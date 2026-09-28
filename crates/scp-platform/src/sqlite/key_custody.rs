//! Persistent [`KeyCustody`] implementation backed by [`SqliteStorage`].
//!
//! Uses the same software cryptography as
//! [`InMemoryKeyCustody`](crate::testing::InMemoryKeyCustody) but persists all
//! key material to an encrypted `SQLite` database via [`SqliteStorage`]. Keys
//! survive process restarts — encryption-at-rest is provided by `SQLCipher`.
//!
//! Requires both `sqlite` and `software_platform` features.
//!
//! See spec section 17.6 (`SQLite` storage) and ADR-006 (platform adapters).

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};

use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use scp_crypto::p256::P256SigningKey;
use tokio::sync::Mutex;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};
use zeroize::Zeroizing;

use super::SqliteStorage;
use crate::error::PlatformError;
use crate::pseudonym_keys::PseudonymKeys;
use crate::traits::{
    CustodyType, KeyCustody, KeyHandle, KeyType, PseudonymKeypair, PublicKey, SharedSecret,
    Signature, Storage,
};

/// Storage key prefix for persisted key material.
const KEY_PREFIX: &str = "custody/keys/";

/// Storage key for the next handle counter.
const COUNTER_KEY: &str = "custody/next_id";

/// Key type discriminant for Ed25519 keys.
const KEY_TYPE_ED25519: u8 = 0;

/// Key type discriminant for X25519 keys.
const KEY_TYPE_X25519: u8 = 1;

/// Key type discriminant for P-256 signing keys ([`KeyType::P256Signing`]).
const KEY_TYPE_P256_SIGNING: u8 = 2;

/// Key type discriminant for P-256 HPKE keys ([`KeyType::HpkeP256`]).
const KEY_TYPE_P256_HPKE: u8 = 3;

/// Role byte for an operational key ([`KeyCustody::generate_keypair`]).
const ROLE_OPERATIONAL: u8 = 0;

/// Role byte for an identity key ([`KeyCustody::generate_identity_keypair`],
/// [`KeyCustody::import_ed25519_signing_key`]), the only derivation source.
const ROLE_IDENTITY: u8 = 1;

/// Length of a persisted key row: `[key_type, role, private_key(32)]`.
const ROW_LEN: usize = 34;

const fn type_byte(key_type: KeyType) -> u8 {
    match key_type {
        KeyType::Ed25519 => KEY_TYPE_ED25519,
        KeyType::X25519 => KEY_TYPE_X25519,
        KeyType::P256Signing => KEY_TYPE_P256_SIGNING,
        KeyType::HpkeP256 => KEY_TYPE_P256_HPKE,
    }
}

/// The error for using a key of type `actual` where `expected` is required.
const fn wrong_type(actual: KeyType, expected: KeyType) -> PlatformError {
    PlatformError::WrongKeyType { expected, actual }
}

/// Consolidated in-memory key store protected by a single mutex.
///
/// Eliminates TOCTOU gaps and lock-ordering deadlock risks that arise from
/// three independent mutexes (`key_types`, `ed25519_keys`, `x25519_keys`).
struct SqliteKeyStore {
    /// Key type lookup, indexed by handle ID.
    key_types: HashMap<u64, KeyType>,
    /// In-memory cache of Ed25519 signing keys, indexed by handle ID.
    ed25519_keys: HashMap<u64, SigningKey>,
    /// In-memory cache of X25519 static secrets, indexed by handle ID.
    x25519_keys: HashMap<u64, StaticSecret>,
    /// P-256 signing and HPKE keys, indexed by handle ID; `key_types` says
    /// which.
    p256_keys: HashMap<u64, P256SigningKey>,
    /// Derived P-256 pseudonym keys, each owned by its identity (§9.10.4,
    /// §9.15), typed [`KeyType::P256Signing`] in `key_types`. Never
    /// persisted, because they re-derive from the identity key.
    pseudonyms: PseudonymKeys,
    /// Handles in the identity role, the only pseudonym-derivation sources.
    identity_ids: HashSet<u64>,
}

impl SqliteKeyStore {
    /// The Ed25519 seed of a pseudonym-derivation source, after the role and
    /// (until S12) curve check.
    fn derive_source(&self, key_id: u64) -> Result<Zeroizing<[u8; 32]>, PlatformError> {
        let key_type = self
            .key_types
            .get(&key_id)
            .copied()
            .ok_or(PlatformError::KeyNotFound)?;
        crate::traits::require_derive_source(self.identity_ids.contains(&key_id), key_type)?;
        let signing_key = self
            .ed25519_keys
            .get(&key_id)
            .ok_or(PlatformError::KeyNotFound)?;
        Ok(Zeroizing::new(signing_key.to_bytes()))
    }

    /// The P-256 key behind `key_id`: a stored key or a derived pseudonym.
    fn p256_key(&self, key_id: u64) -> Result<&P256SigningKey, PlatformError> {
        self.p256_keys
            .get(&key_id)
            .or_else(|| self.pseudonyms.get(key_id))
            .ok_or(PlatformError::KeyNotFound)
    }
}

/// Persistent [`KeyCustody`] backed by [`SqliteStorage`] with `SQLCipher` encryption.
///
/// On construction, loads all previously persisted keys into an in-memory cache
/// for fast access. New keys are written through to `SQLite` immediately. The
/// `SQLCipher` layer provides encryption at rest — private key material is never
/// stored in plaintext on disk.
///
/// # Key Storage Format
///
/// Each key is stored under `custody/keys/{handle_id}` as a 34-byte blob:
/// `[key_type_byte || role_byte || 32_bytes_private_key]`, where the type
/// byte is 0 (Ed25519), 1 (X25519), 2 (P-256 signing) or 3 (P-256 HPKE) and
/// the role byte is 0 (operational) or 1 (identity, the only
/// pseudonym-derivation source). A P-256 scalar that is zero or not below
/// `n`, and any other length, type or role, fails the load. The handle counter is persisted
/// at `custody/next_id` as an 8-byte little-endian u64 to ensure handle
/// uniqueness across restarts.
///
/// Pseudonym-derived keys are NOT persisted — they are deterministically
/// re-derivable from the identity key and are only held in the in-memory cache
/// for the lifetime of the process.
pub struct SqliteKeyCustody {
    /// The underlying encrypted `SQLite` storage.
    storage: SqliteStorage,
    /// Consolidated in-memory key store. A single mutex protects all key maps
    /// to eliminate TOCTOU gaps between type lookup and key access, and to
    /// prevent lock-ordering deadlocks.
    store: Mutex<SqliteKeyStore>,
    /// Monotonically increasing handle counter.
    next_id: AtomicU64,
}

impl SqliteKeyCustody {
    /// Opens or creates a persistent key custody backed by the given
    /// [`SqliteStorage`].
    ///
    /// Loads all previously persisted keys into memory. The `storage` parameter
    /// should be an already-opened, encrypted `SQLite` database (the same one
    /// used for general node storage, or a dedicated one for keys).
    ///
    /// # Errors
    ///
    /// Returns [`PlatformError::StorageError`] if the storage cannot be read
    /// or if persisted key data is corrupted.
    pub async fn new(storage: SqliteStorage) -> Result<Self, PlatformError> {
        let mut ed25519_keys = HashMap::new();
        let mut x25519_keys = HashMap::new();
        let mut p256_keys = HashMap::new();
        let mut key_types = HashMap::new();
        let mut identity_ids = HashSet::new();
        let mut max_id: u64 = 0;

        // Load the persisted handle counter. An absent counter is a fresh
        // store; a counter of any other length is corruption, never zero.
        let persisted_next_id = match storage.retrieve(COUNTER_KEY).await? {
            None => 0,
            Some(data) => {
                let buf: [u8; 8] = data.as_slice().try_into().map_err(|_| {
                    PlatformError::StorageError(format!(
                        "handle counter has invalid length {} (expected 8)",
                        data.len()
                    ))
                })?;
                u64::from_le_bytes(buf)
            }
        };

        // Load all persisted keys.
        let keys = storage.list_keys(KEY_PREFIX).await?;
        for key_path in &keys {
            let id_str = key_path
                .strip_prefix(KEY_PREFIX)
                .ok_or_else(|| PlatformError::StorageError("invalid key path".to_owned()))?;
            let id: u64 = id_str.parse().map_err(|e| {
                PlatformError::StorageError(format!("invalid key handle ID '{id_str}': {e}"))
            })?;

            if id > max_id {
                max_id = id;
            }

            // The row holds the private key: wrap it before anything else so
            // every exit path (including the length and type errors below)
            // wipes it.
            let data = Zeroizing::new(storage.retrieve(key_path).await?.ok_or_else(|| {
                PlatformError::StorageError(format!("key {id} listed but not found"))
            })?);

            if data.len() != ROW_LEN {
                return Err(PlatformError::StorageError(format!(
                    "key {id} has invalid length {} (expected {ROW_LEN})",
                    data.len()
                )));
            }

            let key_type_byte = data[0];
            match data[1] {
                ROLE_OPERATIONAL => {}
                ROLE_IDENTITY => {
                    identity_ids.insert(id);
                }
                other => {
                    return Err(PlatformError::StorageError(format!(
                        "key {id} has unknown role {other}"
                    )));
                }
            }
            let mut key_bytes = Zeroizing::new([0u8; 32]);
            key_bytes.copy_from_slice(&data[2..ROW_LEN]);

            match key_type_byte {
                KEY_TYPE_ED25519 => {
                    let signing_key = SigningKey::from_bytes(&key_bytes);
                    ed25519_keys.insert(id, signing_key);
                    key_types.insert(id, KeyType::Ed25519);
                }
                KEY_TYPE_X25519 => {
                    let secret = StaticSecret::from(*key_bytes);
                    x25519_keys.insert(id, secret);
                    key_types.insert(id, KeyType::X25519);
                }
                KEY_TYPE_P256_SIGNING | KEY_TYPE_P256_HPKE => {
                    let key = crate::traits::p256_key_from_stored(&key_bytes)
                        .map_err(|e| PlatformError::StorageError(format!("key {id}: {e}")))?;
                    p256_keys.insert(id, key);
                    let key_type = if key_type_byte == KEY_TYPE_P256_SIGNING {
                        KeyType::P256Signing
                    } else {
                        KeyType::HpkeP256
                    };
                    key_types.insert(id, key_type);
                }
                other => {
                    // key_bytes is Zeroizing — automatically zeroed on drop
                    return Err(PlatformError::StorageError(format!(
                        "key {id} has unknown type {other}"
                    )));
                }
            }
            // key_bytes automatically zeroed on drop via Zeroizing
        }

        // Start counter from the greater of: persisted counter or max observed ID + 1.
        let next_id = persisted_next_id.max(max_id + 1).max(1);

        Ok(Self {
            storage,
            store: Mutex::new(SqliteKeyStore {
                key_types,
                ed25519_keys,
                x25519_keys,
                p256_keys,
                pseudonyms: PseudonymKeys::default(),
                identity_ids,
            }),
            next_id: AtomicU64::new(next_id),
        })
    }

    /// Allocates the next key handle ID and persists the counter.
    async fn next_handle(&self) -> Result<KeyHandle, PlatformError> {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let counter_bytes = (id + 1).to_le_bytes();
        self.storage.store(COUNTER_KEY, &counter_bytes).await?;
        Ok(KeyHandle::new(id))
    }

    /// Persists a key to `SQLite` storage as `[key_type || role ||
    /// private_key]`.
    async fn persist_key(
        &self,
        id: u64,
        private_key: &[u8; 32],
        key_type: u8,
        identity: bool,
    ) -> Result<(), PlatformError> {
        let mut blob = Zeroizing::new([0u8; ROW_LEN]);
        blob[0] = key_type;
        blob[1] = if identity {
            ROLE_IDENTITY
        } else {
            ROLE_OPERATIONAL
        };
        blob[2..ROW_LEN].copy_from_slice(private_key);
        let key_path = format!("{KEY_PREFIX}{id}");
        self.storage.store(&key_path, blob.as_ref()).await
        // blob automatically zeroed on drop via Zeroizing
    }

    /// Removes a key from `SQLite` storage.
    async fn remove_persisted_key(&self, id: u64) -> Result<(), PlatformError> {
        let key_path = format!("{KEY_PREFIX}{id}");
        self.storage.delete(&key_path).await
    }

    /// Mints and persists a key of `key_type`, in the identity role when
    /// `identity`.
    async fn generate(
        &self,
        key_type: KeyType,
        identity: bool,
    ) -> Result<KeyHandle, PlatformError> {
        let p256_key = match key_type {
            KeyType::P256Signing | KeyType::HpkeP256 => {
                Some(crate::traits::generate_p256_os_rng()?)
            }
            KeyType::Ed25519 | KeyType::X25519 => None,
        };
        let key_bytes = p256_key.as_ref().map_or_else(
            || {
                let mut key_bytes = Zeroizing::new([0u8; 32]);
                rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, key_bytes.as_mut());
                key_bytes
            },
            P256SigningKey::to_scalar_bytes,
        );
        let handle = self.next_handle().await?;

        // Persist to storage before adding to cache.
        self.persist_key(handle.id(), &key_bytes, type_byte(key_type), identity)
            .await?;

        let mut store = self.store.lock().await;
        match (key_type, p256_key) {
            (KeyType::Ed25519, _) => {
                let signing_key = SigningKey::from_bytes(&key_bytes);
                store.ed25519_keys.insert(handle.id(), signing_key);
            }
            (KeyType::X25519, _) => {
                let secret = StaticSecret::from(*key_bytes);
                store.x25519_keys.insert(handle.id(), secret);
            }
            (KeyType::P256Signing | KeyType::HpkeP256, Some(key)) => {
                store.p256_keys.insert(handle.id(), key);
            }
            (KeyType::P256Signing | KeyType::HpkeP256, None) => {
                return Err(PlatformError::CustodyError(
                    "P-256 key generation produced no key".into(),
                ));
            }
        }
        store.key_types.insert(handle.id(), key_type);
        if identity {
            store.identity_ids.insert(handle.id());
        }
        drop(store);

        Ok(handle)
    }

    /// Returns the stored key type for a handle, or an error if not found.
    fn lookup_type(store: &SqliteKeyStore, handle: KeyHandle) -> Result<KeyType, PlatformError> {
        store
            .key_types
            .get(&handle.id())
            .copied()
            .ok_or(PlatformError::KeyNotFound)
    }

    /// The §9.10.4 P-256 pseudonym of identity `key_id` in `context_id` at
    /// `epoch` (`None` for v1). A re-derive returns the handle already in the
    /// slot; the store lock is held throughout, so a concurrent destroy of the
    /// identity lands wholly before or after. Pseudonyms are cached only,
    /// never persisted: they re-derive from the identity key.
    async fn derive_p256_pseudonym(
        &self,
        key_id: u64,
        context_id: &[u8],
        epoch: Option<u64>,
    ) -> Result<PseudonymKeypair, PlatformError> {
        let mut store = self.store.lock().await;
        // Software custody (§9.10.4.A): the ikm is the identity private
        // seed, never the public key. Only an identity key derives, and
        // until S12 (§9.10.4.A native interim) it is Ed25519, so its
        // 32-byte seed is the ikm.
        let ikm = store.derive_source(key_id)?;
        if let Some((handle, public_key)) = store.pseudonyms.existing(key_id, context_id, epoch) {
            drop(store);
            return PseudonymKeypair::new(&public_key, KeyHandle::new(handle));
        }
        let pseudonym_key =
            scp_crypto::pseudonym::derive_pseudonym_keypair(&ikm, context_id, epoch)
                .map_err(|e| PlatformError::CustodyError(format!("pseudonym derivation: {e}")))?;
        let public_key = pseudonym_key.public_key().to_compressed();

        let handle = KeyHandle::new(self.next_id.fetch_add(1, Ordering::Relaxed));
        store
            .pseudonyms
            .insert(key_id, context_id, epoch, handle.id(), pseudonym_key);
        store.key_types.insert(handle.id(), KeyType::P256Signing);
        drop(store);

        PseudonymKeypair::new(&public_key, handle)
    }
}

// Trait uses RPITIT with explicit `+ Send` bound; async fn in trait
// does not guarantee Send futures, so manual impl Future is required.
#[allow(clippy::manual_async_fn, clippy::significant_drop_tightening)]
impl KeyCustody for SqliteKeyCustody {
    fn generate_keypair(
        &self,
        key_type: KeyType,
    ) -> impl Future<Output = Result<KeyHandle, PlatformError>> + Send {
        self.generate(key_type, false)
    }

    fn generate_identity_keypair(
        &self,
    ) -> impl Future<Output = Result<KeyHandle, PlatformError>> + Send {
        self.generate(KeyType::Ed25519, true)
    }

    fn sign(
        &self,
        key: &KeyHandle,
        data: &[u8],
    ) -> impl Future<Output = Result<Signature, PlatformError>> + Send {
        let key_id = key.id();
        async move {
            let store = self.store.lock().await;
            let kt = Self::lookup_type(&store, KeyHandle::new(key_id))?;

            match kt {
                KeyType::Ed25519 => {}
                KeyType::P256Signing => {
                    return crate::traits::sign_p256_digest(store.p256_key(key_id)?, data);
                }
                KeyType::X25519 => return Err(wrong_type(kt, KeyType::Ed25519)),
                KeyType::HpkeP256 => return Err(wrong_type(kt, KeyType::P256Signing)),
            }

            let signing_key = store
                .ed25519_keys
                .get(&key_id)
                .ok_or(PlatformError::KeyNotFound)?;
            let signature = signing_key.sign(data);
            drop(store);
            Ok(Signature::new(signature.to_bytes().to_vec()))
        }
    }

    fn public_key(
        &self,
        key: &KeyHandle,
    ) -> impl Future<Output = Result<PublicKey, PlatformError>> + Send {
        let key_id = key.id();
        async move {
            let store = self.store.lock().await;
            let kt = Self::lookup_type(&store, KeyHandle::new(key_id))?;

            match kt {
                KeyType::Ed25519 => {
                    let signing_key = store
                        .ed25519_keys
                        .get(&key_id)
                        .ok_or(PlatformError::KeyNotFound)?;
                    let verifying_key: VerifyingKey = signing_key.verifying_key();
                    Ok(PublicKey::new(verifying_key.to_bytes().to_vec()))
                }
                KeyType::X25519 => {
                    let secret = store
                        .x25519_keys
                        .get(&key_id)
                        .ok_or(PlatformError::KeyNotFound)?;
                    let public = X25519PublicKey::from(secret);
                    Ok(PublicKey::new(public.to_bytes().to_vec()))
                }
                KeyType::P256Signing => Ok(PublicKey::new(
                    store
                        .p256_key(key_id)?
                        .public_key()
                        .to_compressed()
                        .to_vec(),
                )),
                KeyType::HpkeP256 => Ok(PublicKey::new(
                    store
                        .p256_key(key_id)?
                        .public_key()
                        .to_uncompressed()
                        .to_vec(),
                )),
            }
        }
    }

    fn destroy_key(
        &self,
        key: &KeyHandle,
    ) -> impl Future<Output = Result<(), PlatformError>> + Send {
        let key_id = key.id();
        async move {
            let mut store = self.store.lock().await;
            let kt = Self::lookup_type(&store, KeyHandle::new(key_id))?;

            match kt {
                KeyType::Ed25519 => {
                    store.ed25519_keys.remove(&key_id);
                    // Every pseudonym derived from this identity goes with it
                    // (§9.15), under the same lock a derive holds.
                    for pseudonym in store.pseudonyms.remove_identity(key_id) {
                        store.key_types.remove(&pseudonym);
                    }
                }
                KeyType::X25519 => {
                    store.x25519_keys.remove(&key_id);
                }
                KeyType::P256Signing | KeyType::HpkeP256 => {
                    if store.pseudonyms.remove(key_id) {
                        // Never persisted, so there is no stored row to remove.
                        store.key_types.remove(&key_id);
                        return Ok(());
                    }
                    store.p256_keys.remove(&key_id);
                }
            }
            store.key_types.remove(&key_id);
            store.identity_ids.remove(&key_id);
            drop(store);

            // Remove from persistent storage.
            self.remove_persisted_key(key_id).await?;

            Ok(())
        }
    }

    fn dh_agree(
        &self,
        key: &KeyHandle,
        peer_public: &[u8],
    ) -> impl Future<Output = Result<SharedSecret, PlatformError>> + Send {
        let key_id = key.id();
        let peer_public = peer_public.to_vec();
        async move {
            let store = self.store.lock().await;
            let kt = Self::lookup_type(&store, KeyHandle::new(key_id))?;

            match kt {
                KeyType::X25519 => {}
                KeyType::HpkeP256 => {
                    return crate::traits::p256_dh_agree(store.p256_key(key_id)?, &peer_public);
                }
                KeyType::Ed25519 => return Err(wrong_type(kt, KeyType::X25519)),
                KeyType::P256Signing => return Err(wrong_type(kt, KeyType::HpkeP256)),
            }
            let peer = crate::traits::x25519_peer(&peer_public)?;

            let secret = store
                .x25519_keys
                .get(&key_id)
                .ok_or(PlatformError::KeyNotFound)?;
            let peer_key = X25519PublicKey::from(peer);
            let shared = secret.diffie_hellman(&peer_key);
            drop(store);
            let shared_bytes = Zeroizing::new(shared.to_bytes());
            Ok(SharedSecret::new(*shared_bytes))
        }
    }

    fn derive_pseudonym(
        &self,
        key: &KeyHandle,
        context_id: &[u8],
    ) -> impl Future<Output = Result<PseudonymKeypair, PlatformError>> + Send {
        let key_id = key.id();
        let context_id = context_id.to_vec();
        async move { self.derive_p256_pseudonym(key_id, &context_id, None).await }
    }

    fn derive_rotatable_pseudonym(
        &self,
        key: &KeyHandle,
        context_id: &[u8],
        pseudonym_epoch: u64,
    ) -> impl Future<Output = Result<PseudonymKeypair, PlatformError>> + Send {
        let key_id = key.id();
        let context_id = context_id.to_vec();
        async move {
            self.derive_p256_pseudonym(key_id, &context_id, Some(pseudonym_epoch))
                .await
        }
    }

    fn ed25519_to_x25519_agree(
        &self,
        ed25519_handle: &KeyHandle,
        peer_x25519_public: &[u8; 32],
    ) -> impl Future<Output = Result<SharedSecret, PlatformError>> + Send {
        let key_id = ed25519_handle.id();
        let peer = *peer_x25519_public;
        async move {
            let store = self.store.lock().await;
            let kt = Self::lookup_type(&store, KeyHandle::new(key_id))?;

            if kt != KeyType::Ed25519 {
                return Err(wrong_type(kt, KeyType::Ed25519));
            }

            let signing_key = store
                .ed25519_keys
                .get(&key_id)
                .ok_or(PlatformError::KeyNotFound)?;
            let result = crate::traits::x25519_agree_from_ed25519(signing_key, &peer);
            drop(store);
            Ok(result)
        }
    }

    fn custody_type(&self, _key: &KeyHandle) -> CustodyType {
        CustodyType::Software
    }

    fn generate_ephemeral_ed25519_seed(
        &self,
    ) -> impl Future<Output = Result<Zeroizing<[u8; 32]>, PlatformError>> + Send {
        async move {
            // Software custody: draw 32 bytes from OsRng. The bytes are
            // returned to the caller in a Zeroizing wrapper and never
            // persisted in this custody — the caller hands them to a
            // `PreRotationCustody` per spec §9.7.4.1 §1, §5(f).
            let mut seed = Zeroizing::new([0u8; 32]);
            rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, seed.as_mut());
            Ok(seed)
        }
    }

    fn import_ed25519_signing_key(
        &self,
        seed: &Zeroizing<[u8; 32]>,
    ) -> impl Future<Output = Result<KeyHandle, PlatformError>> + Send {
        async move {
            let handle = self.next_handle().await?;
            let key_bytes = Zeroizing::new(**seed);
            // The imported key is the migrated identity's new `#0`.
            self.persist_key(handle.id(), &key_bytes, KEY_TYPE_ED25519, true)
                .await?;

            let mut store = self.store.lock().await;
            let signing_key = SigningKey::from_bytes(&key_bytes);
            store.ed25519_keys.insert(handle.id(), signing_key);
            store.key_types.insert(handle.id(), KeyType::Ed25519);
            store.identity_ids.insert(handle.id());

            Ok(handle)
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use std::path::Path;

    /// Creates a temporary `SqliteKeyCustody` for testing.
    async fn temp_custody(dir: &Path) -> SqliteKeyCustody {
        let key = [0x42u8; 32];
        let storage = SqliteStorage::new(dir, &key).unwrap();
        SqliteKeyCustody::new(storage).await.unwrap()
    }

    #[tokio::test]
    async fn generate_and_retrieve_ed25519_key() {
        let dir = tempfile::tempdir().unwrap();
        let custody = temp_custody(dir.path()).await;

        let handle = custody.generate_keypair(KeyType::Ed25519).await.unwrap();
        let pubkey = custody.public_key(&handle).await.unwrap();
        assert_eq!(pubkey.as_bytes().len(), 32);
    }

    #[tokio::test]
    async fn generate_and_retrieve_x25519_key() {
        let dir = tempfile::tempdir().unwrap();
        let custody = temp_custody(dir.path()).await;

        let handle = custody.generate_keypair(KeyType::X25519).await.unwrap();
        let pubkey = custody.public_key(&handle).await.unwrap();
        assert_eq!(pubkey.as_bytes().len(), 32);
    }

    #[tokio::test]
    async fn keys_survive_reload() {
        let dir = tempfile::tempdir().unwrap();
        let key = [0x42u8; 32];

        // Generate keys with first instance.
        let handle_ed;
        let handle_x;
        let pubkey_ed;
        let pubkey_x;
        {
            let storage = SqliteStorage::new(dir.path(), &key).unwrap();
            let custody = SqliteKeyCustody::new(storage).await.unwrap();
            handle_ed = custody.generate_keypair(KeyType::Ed25519).await.unwrap();
            handle_x = custody.generate_keypair(KeyType::X25519).await.unwrap();
            pubkey_ed = custody.public_key(&handle_ed).await.unwrap();
            pubkey_x = custody.public_key(&handle_x).await.unwrap();
        }

        // Reload from the same database.
        {
            let storage = SqliteStorage::new(dir.path(), &key).unwrap();
            let custody = SqliteKeyCustody::new(storage).await.unwrap();
            let reloaded_ed = custody.public_key(&handle_ed).await.unwrap();
            let reloaded_x = custody.public_key(&handle_x).await.unwrap();
            assert_eq!(pubkey_ed.as_bytes(), reloaded_ed.as_bytes());
            assert_eq!(pubkey_x.as_bytes(), reloaded_x.as_bytes());
        }
    }

    #[tokio::test]
    async fn sign_produces_valid_signature() {
        use ed25519_dalek::Verifier;

        let dir = tempfile::tempdir().unwrap();
        let custody = temp_custody(dir.path()).await;

        let handle = custody.generate_keypair(KeyType::Ed25519).await.unwrap();
        let data = b"test message";
        let sig = custody.sign(&handle, data).await.unwrap();
        let pubkey = custody.public_key(&handle).await.unwrap();

        let pk_bytes: [u8; 32] = pubkey.as_bytes().try_into().unwrap();
        let verifying_key = VerifyingKey::from_bytes(&pk_bytes).unwrap();
        let sig_bytes: [u8; 64] = sig.as_bytes().try_into().unwrap();
        let signature = ed25519_dalek::Signature::from_bytes(&sig_bytes);
        assert!(verifying_key.verify(data, &signature).is_ok());
    }

    /// C1/C2: the role is persisted. After a reopen the identity key and the
    /// imported key derive, and the operational Ed25519 key is refused by its
    /// role (it still signs). A row with an unknown role, or of the old
    /// 33-byte shape, and a handle counter of the wrong length fail the load.
    #[tokio::test]
    async fn identity_role_persists_and_bad_rows_fail() {
        let dir = tempfile::tempdir().unwrap();
        let custody = temp_custody(dir.path()).await;
        let identity = custody.generate_identity_keypair().await.unwrap();
        let operational = custody.generate_keypair(KeyType::Ed25519).await.unwrap();
        let imported = custody
            .import_ed25519_signing_key(&Zeroizing::new([6u8; 32]))
            .await
            .unwrap();
        drop(custody);

        let custody = temp_custody(dir.path()).await;
        custody.derive_pseudonym(&identity, b"ctx").await.unwrap();
        custody
            .derive_rotatable_pseudonym(&imported, b"ctx", 4)
            .await
            .unwrap();
        assert!(matches!(
            custody.derive_pseudonym(&operational, b"ctx").await,
            Err(PlatformError::WrongKeyType {
                expected: KeyType::Ed25519,
                actual: KeyType::Ed25519
            })
        ));
        custody.sign(&operational, b"data").await.unwrap();

        let row = format!("{KEY_PREFIX}{}", operational.id());
        let mut blob = custody.storage.retrieve(&row).await.unwrap().unwrap();
        assert_eq!((blob.len(), blob[1]), (ROW_LEN, ROLE_OPERATIONAL));
        drop(custody);
        let open = || SqliteStorage::new(dir.path(), &[0x42u8; 32]).unwrap();
        blob[1] = 7;
        // An unknown role byte, then a short row.
        for bad in [blob.clone(), blob[..33].to_vec()] {
            let storage = open();
            storage.store(&row, &bad).await.unwrap();
            match SqliteKeyCustody::new(storage).await {
                Err(PlatformError::StorageError(_)) => {}
                Err(other) => panic!("{other:?}"),
                Ok(_) => panic!("a bad row must fail the load"),
            }
        }
        let storage = open();
        storage.delete(&row).await.unwrap();
        storage.store(COUNTER_KEY, &[1u8; 7]).await.unwrap();
        assert!(matches!(
            SqliteKeyCustody::new(storage).await,
            Err(PlatformError::StorageError(_))
        ));
    }

    /// Pseudonyms are P-256 (§9.10.4): the 33-byte point from the shared
    /// `scp_crypto` recipe over the identity seed, a handle that signs only a
    /// 32-byte digest, and misuse that fails closed. Never persisted.
    #[tokio::test]
    async fn derive_pseudonym_is_p256_and_fails_closed() {
        use scp_crypto::p256::{P256PublicKey, verify_prehash_strict};

        let dir = tempfile::tempdir().unwrap();
        let custody = temp_custody(dir.path()).await;
        let seed = Zeroizing::new([0x24u8; 32]);
        let identity = custody.import_ed25519_signing_key(&seed).await.unwrap();

        for epoch in [None, Some(3)] {
            let pseudo = match epoch {
                None => custody.derive_pseudonym(&identity, b"ctx").await.unwrap(),
                Some(e) => custody
                    .derive_rotatable_pseudonym(&identity, b"ctx", e)
                    .await
                    .unwrap(),
            };
            let expected = scp_crypto::pseudonym::derive_pseudonym_keypair(&seed, b"ctx", epoch)
                .unwrap()
                .public_key()
                .to_compressed();
            assert_eq!(pseudo.public_key().as_bytes(), expected.as_slice());
            assert_eq!(
                pseudo.routing_id(),
                &scp_crypto::pseudonym::pseudonym_routing_id(&expected)
            );

            let digest = [0x77u8; 32];
            let sig = custody.sign(pseudo.key_handle(), &digest).await.unwrap();
            let pk = P256PublicKey::from_sec1(&expected).unwrap();
            verify_prehash_strict(&pk, &digest, sig.as_bytes()).unwrap();
            assert!(matches!(
                custody.sign(pseudo.key_handle(), &[0u8; 31]).await,
                Err(PlatformError::CustodyError(_))
            ));
            assert!(matches!(
                custody.dh_agree(pseudo.key_handle(), &[1u8; 32]).await,
                Err(PlatformError::WrongKeyType {
                    expected: KeyType::HpkeP256,
                    actual: KeyType::P256Signing
                })
            ));
            custody.destroy_key(pseudo.key_handle()).await.unwrap();
            assert!(matches!(
                custody.public_key(pseudo.key_handle()).await,
                Err(PlatformError::KeyNotFound)
            ));
        }
    }

    #[tokio::test]
    async fn destroy_key_removes_from_storage() {
        let dir = tempfile::tempdir().unwrap();
        let key = [0x42u8; 32];

        let handle;
        {
            let storage = SqliteStorage::new(dir.path(), &key).unwrap();
            let custody = SqliteKeyCustody::new(storage).await.unwrap();
            handle = custody.generate_keypair(KeyType::Ed25519).await.unwrap();
            custody.destroy_key(&handle).await.unwrap();
        }

        // Reload — destroyed key should not be present.
        {
            let storage = SqliteStorage::new(dir.path(), &key).unwrap();
            let custody = SqliteKeyCustody::new(storage).await.unwrap();
            assert!(custody.public_key(&handle).await.is_err());
        }
    }

    /// A11: destroying a P-256 key (either type) deletes its row, so it is
    /// gone after a reload while a sibling key survives.
    #[tokio::test]
    async fn destroyed_p256_keys_are_gone_after_reload() {
        let dir = tempfile::tempdir().unwrap();
        let key = [0x42u8; 32];
        let (sign_handle, hpke_handle, kept, kept_pub);
        {
            let storage = SqliteStorage::new(dir.path(), &key).unwrap();
            let custody = SqliteKeyCustody::new(storage).await.unwrap();
            sign_handle = custody
                .generate_keypair(KeyType::P256Signing)
                .await
                .unwrap();
            hpke_handle = custody.generate_keypair(KeyType::HpkeP256).await.unwrap();
            kept = custody
                .generate_keypair(KeyType::P256Signing)
                .await
                .unwrap();
            kept_pub = custody.public_key(&kept).await.unwrap();
            custody.destroy_key(&sign_handle).await.unwrap();
            custody.destroy_key(&hpke_handle).await.unwrap();
            assert!(matches!(
                custody.sign(&sign_handle, &[0u8; 32]).await,
                Err(PlatformError::KeyNotFound)
            ));
        }
        {
            let storage = SqliteStorage::new(dir.path(), &key).unwrap();
            for handle in [sign_handle, hpke_handle] {
                assert!(
                    storage
                        .retrieve(&format!("{KEY_PREFIX}{}", handle.id()))
                        .await
                        .unwrap()
                        .is_none()
                );
            }
            let custody = SqliteKeyCustody::new(storage).await.unwrap();
            assert!(matches!(
                custody.public_key(&sign_handle).await,
                Err(PlatformError::KeyNotFound)
            ));
            assert!(matches!(
                custody.dh_agree(&hpke_handle, &[4u8; 65]).await,
                Err(PlatformError::KeyNotFound)
            ));
            assert_eq!(custody.public_key(&kept).await.unwrap(), kept_pub);
        }
    }

    #[tokio::test]
    async fn dh_agree_works() {
        let dir = tempfile::tempdir().unwrap();
        let custody = temp_custody(dir.path()).await;

        let alice = custody.generate_keypair(KeyType::X25519).await.unwrap();
        let bob = custody.generate_keypair(KeyType::X25519).await.unwrap();

        let alice_pub = custody.public_key(&alice).await.unwrap();
        let bob_pub = custody.public_key(&bob).await.unwrap();

        let alice_bytes: [u8; 32] = alice_pub.as_bytes().try_into().unwrap();
        let bob_bytes: [u8; 32] = bob_pub.as_bytes().try_into().unwrap();

        let secret_ab = custody.dh_agree(&alice, &bob_bytes).await.unwrap();
        let secret_ba = custody.dh_agree(&bob, &alice_bytes).await.unwrap();

        assert_eq!(secret_ab.as_bytes(), secret_ba.as_bytes());
    }

    #[tokio::test]
    async fn handle_counter_survives_restart() {
        let dir = tempfile::tempdir().unwrap();
        let key = [0x42u8; 32];

        let first_handle;
        {
            let storage = SqliteStorage::new(dir.path(), &key).unwrap();
            let custody = SqliteKeyCustody::new(storage).await.unwrap();
            first_handle = custody.generate_keypair(KeyType::Ed25519).await.unwrap();
        }

        // Reload and generate a new key — handle should be higher.
        {
            let storage = SqliteStorage::new(dir.path(), &key).unwrap();
            let custody = SqliteKeyCustody::new(storage).await.unwrap();
            let second_handle = custody.generate_keypair(KeyType::Ed25519).await.unwrap();
            assert!(second_handle.id() > first_handle.id());
        }
    }

    #[tokio::test]
    async fn custody_type_returns_software() {
        let dir = tempfile::tempdir().unwrap();
        let custody = temp_custody(dir.path()).await;
        let handle = custody.generate_keypair(KeyType::Ed25519).await.unwrap();
        assert_eq!(custody.custody_type(&handle), CustodyType::Software);
    }

    /// The P-256 group order `n`, big-endian: the smallest invalid scalar.
    const P256_ORDER: [u8; 32] = [
        0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xBC, 0xE6, 0xFA, 0xAD, 0xA7, 0x17, 0x9E, 0x84, 0xF3, 0xB9, 0xCA, 0xC2, 0xFC, 0x63,
        0x25, 0x51,
    ];

    #[tokio::test]
    async fn p256_keys_survive_reload_with_type_bytes_2_and_3() {
        let dir = tempfile::tempdir().unwrap();
        let key = [0x42u8; 32];
        let (sign_handle, hpke_handle, sign_pub, hpke_pub);
        {
            let storage = SqliteStorage::new(dir.path(), &key).unwrap();
            let custody = SqliteKeyCustody::new(storage).await.unwrap();
            sign_handle = custody
                .generate_keypair(KeyType::P256Signing)
                .await
                .unwrap();
            hpke_handle = custody.generate_keypair(KeyType::HpkeP256).await.unwrap();
            sign_pub = custody.public_key(&sign_handle).await.unwrap();
            hpke_pub = custody.public_key(&hpke_handle).await.unwrap();
            assert_eq!(sign_pub.as_bytes().len(), 33);
            assert_eq!(hpke_pub.as_bytes().len(), 65);
        }
        {
            let storage = SqliteStorage::new(dir.path(), &key).unwrap();
            let sign_row = storage
                .retrieve(&format!("{KEY_PREFIX}{}", sign_handle.id()))
                .await
                .unwrap()
                .unwrap();
            let hpke_row = storage
                .retrieve(&format!("{KEY_PREFIX}{}", hpke_handle.id()))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(sign_row[0], 2);
            assert_eq!(hpke_row[0], 3);

            let custody = SqliteKeyCustody::new(storage).await.unwrap();
            assert_eq!(custody.public_key(&sign_handle).await.unwrap(), sign_pub);
            assert_eq!(custody.public_key(&hpke_handle).await.unwrap(), hpke_pub);

            // 64 distinct digests: about half have a high raw RFC 6979 s,
            // so every one verifying strictly shows low-s normalisation.
            let pk = scp_crypto::p256::P256PublicKey::from_sec1(sign_pub.as_bytes()).unwrap();
            for i in 0..64u8 {
                let digest = [i; 32];
                let sig = custody.sign(&sign_handle, &digest).await.unwrap();
                scp_crypto::p256::verify_prehash_strict(&pk, &digest, sig.as_bytes()).unwrap();
            }

            let peer = P256SigningKey::from_scalar_bytes(&[5u8; 32]).unwrap();
            let own = scp_crypto::p256::P256PublicKey::from_sec1(hpke_pub.as_bytes()).unwrap();
            let shared = custody
                .dh_agree(&hpke_handle, &peer.public_key().to_uncompressed())
                .await
                .unwrap();
            assert_eq!(
                shared.as_bytes(),
                &*scp_crypto::p256::ecdh_p256(&peer, &own)
            );
        }
    }

    #[tokio::test]
    async fn load_rejects_zero_or_out_of_range_p256_scalar() {
        for type_byte in [KEY_TYPE_P256_SIGNING, KEY_TYPE_P256_HPKE] {
            for scalar in [[0u8; 32], P256_ORDER, [0xFFu8; 32]] {
                let dir = tempfile::tempdir().unwrap();
                let key = [0x42u8; 32];
                let storage = SqliteStorage::new(dir.path(), &key).unwrap();
                let mut blob = vec![type_byte];
                blob.extend_from_slice(&scalar);
                storage
                    .store(&format!("{KEY_PREFIX}7"), &blob)
                    .await
                    .unwrap();
                assert!(matches!(
                    SqliteKeyCustody::new(storage).await,
                    Err(PlatformError::StorageError(_))
                ));
            }
        }
    }

    #[tokio::test]
    async fn identity_destroy_removes_its_pseudonyms() {
        let dir = tempfile::tempdir().unwrap();
        crate::pseudonym_keys::tests::check_identity_owns_pseudonyms(
            &temp_custody(dir.path()).await,
        )
        .await
        .unwrap();
    }
}
