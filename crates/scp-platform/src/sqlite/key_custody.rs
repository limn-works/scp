//! Persistent [`KeyCustody`] implementation backed by [`SqliteStorage`].
//!
//! Uses the same software cryptography as
//! [`InMemoryKeyCustody`](crate::testing::InMemoryKeyCustody) but persists all
//! key material to an encrypted `SQLite` database via [`SqliteStorage`]. Keys
//! survive process restarts — `SQLCipher` encrypts every database page, and
//! this custody seals each key entry a second time under its own wrapping key.
//!
//! Requires both `sqlite` and `software_platform` features.
//!
//! # Two layers, and what each one defends
//!
//! `SQLCipher` encrypts and HMACs every page under the database key, so a
//! reader who lacks that key learns nothing and a writer who lacks it cannot
//! alter a stored byte undetected. On top of that, each key entry is sealed
//! with AES-256-GCM under a **separate** wrapping key the caller supplies to
//! [`SqliteKeyCustody::new`], with the `key_type` discriminant and the handle
//! ID bound as Additional Authenticated Data, which closes GitHub issue #2299,
//! the unauthenticated `key_type` byte.
//!
//! The second layer changes the outcome only when the wrapping key and the
//! database key are independent secrets. That is what
//! [`kdf::derive_custody_entry_key`](crate::kdf::derive_custody_entry_key) is
//! for: a caller holding one root secret derives a wrapping key that is
//! unrelated to the `SQLCipher` PRAGMA key derived from the same root, so a
//! leak of the database key alone yields neither the private keys nor the
//! ability to forge an entry. Passing the database key itself as the wrapping
//! key collapses the two layers onto one secret and buys nothing.
//!
//! With `key_type` bound as AAD, an altered discriminant makes
//! the shared `custody_aead::open` helper fail its tag check rather
//! than handing the same 32 bytes to the other algorithm — an Ed25519 seed
//! cannot be retrieved as an X25519 static secret, or the reverse.
//!
//! See spec section 17.6 (`SQLite` storage) and ADR-006 (platform adapters).

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};

use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use tokio::sync::Mutex;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};
use zeroize::Zeroizing;

use super::SqliteStorage;
use crate::custody_aead;
use crate::error::PlatformError;
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

/// Length in bytes of one persisted key entry: `key_type` (1) plus the sealed
/// nonce, ciphertext, and tag (60).
const ENTRY_LEN: usize = 1 + custody_aead::SEALED_LEN;

/// Length in bytes of the entry layout this custody wrote before it sealed
/// entries: `key_type` (1) plus the raw 32-byte private key.
///
/// Named so [`SqliteKeyCustody::new`] can tell a caller that their database
/// predates the per-entry AEAD, instead of reporting a bare length mismatch.
const UNSEALED_ENTRY_LEN: usize = 1 + 32;

/// Builds the Additional Authenticated Data for the entry at `id`.
///
/// Binding `key_type` stops an altered discriminant from feeding the same 32
/// bytes to the other algorithm. Binding the handle ID stops a row copied from
/// `custody/keys/{a}` to `custody/keys/{b}` from opening under the new name.
/// The handle ID is a stable row name here — unlike `FileKeyCustody`'s
/// positional entry index, which `destroy_key` shifts — so binding it costs no
/// re-encryption.
const fn entry_aad(key_type: u8, id: u64) -> [u8; 9] {
    let id_bytes = id.to_le_bytes();
    [
        key_type,
        id_bytes[0],
        id_bytes[1],
        id_bytes[2],
        id_bytes[3],
        id_bytes[4],
        id_bytes[5],
        id_bytes[6],
        id_bytes[7],
    ]
}

/// Consolidated in-memory key store protected by a single mutex.
///
/// Eliminates TOCTOU gaps and lock-ordering deadlock risks that arise from
/// three independent mutexes (`key_types`, `ed25519_keys`, `x25519_keys`).
struct SqliteKeyStore {
    /// Key type lookup, indexed by handle ID.
    key_types: HashMap<u64, u8>,
    /// In-memory cache of Ed25519 signing keys, indexed by handle ID.
    ed25519_keys: HashMap<u64, SigningKey>,
    /// In-memory cache of X25519 static secrets, indexed by handle ID.
    x25519_keys: HashMap<u64, StaticSecret>,
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
/// Each key is stored under `custody/keys/{handle_id}` as a 61-byte blob:
/// `[key_type_byte || nonce(12) || ciphertext(32) || tag(16)]`. The
/// `key_type` byte is in the clear so the loader knows which algorithm
/// consumes the entry, and it is also bound as Additional Authenticated Data
/// together with the handle ID. The handle counter is persisted at
/// `custody/next_id` as an 8-byte little-endian u64 to ensure handle
/// uniqueness across restarts.
///
/// **A database written before the per-entry sealing landed is unreadable.**
/// Those entries were 33 bytes — `[key_type_byte || 32_bytes_private_key]` —
/// with no AEAD of their own. [`SqliteKeyCustody::new`] rejects a 33-byte entry
/// by name rather than reporting a bare length mismatch. SCP is pre-release and
/// `CLAUDE.md` forbids migration code, so this is a **stated breaking change**:
/// an existing custody database must be discarded and its keys regenerated. No
/// shipped release wrote a 33-byte entry that a supported upgrade path must
/// carry forward.
///
/// Pseudonym-derived keys are NOT persisted — they are deterministically
/// re-derivable from the identity key and are only held in the in-memory cache
/// for the lifetime of the process.
pub struct SqliteKeyCustody {
    /// The underlying encrypted `SQLite` storage.
    storage: SqliteStorage,
    /// AES-256-GCM wrapping key for the per-entry seal. Distinct from the
    /// `SQLCipher` database key, so a leak of one does not yield the other.
    entry_key: Zeroizing<[u8; 32]>,
    /// Consolidated in-memory key store. A single mutex protects all key maps
    /// to eliminate TOCTOU gaps between type lookup and key access, and to
    /// prevent lock-ordering deadlocks.
    store: Mutex<SqliteKeyStore>,
    /// Monotonically increasing handle counter.
    next_id: AtomicU64,
}

impl SqliteKeyCustody {
    /// Opens or creates a persistent key custody backed by the given
    /// [`SqliteStorage`], sealing each key entry under `entry_key`.
    ///
    /// Loads all previously persisted keys into memory. The `storage` parameter
    /// should be an already-opened, encrypted `SQLite` database (the same one
    /// used for general node storage, or a dedicated one for keys).
    ///
    /// `entry_key` is the AES-256-GCM wrapping key for the per-entry seal.
    /// Supply key material that is independent of the `SQLCipher` database
    /// key — a caller holding one root secret gets an independent wrapping key
    /// from
    /// [`kdf::derive_custody_entry_key`](crate::kdf::derive_custody_entry_key).
    /// Passing the database key itself compiles and works, and leaves both
    /// layers resting on one secret.
    ///
    /// # Errors
    ///
    /// Returns [`PlatformError::StorageError`] if the storage cannot be read
    /// or if persisted key data is corrupted, and
    /// [`PlatformError::CustodyError`] if an entry does not open under
    /// `entry_key` — which covers a wrong wrapping key, an altered `key_type`
    /// byte, a row copied from another handle ID, and a database written
    /// before the per-entry sealing landed.
    pub async fn new(
        storage: SqliteStorage,
        entry_key: Zeroizing<[u8; 32]>,
    ) -> Result<Self, PlatformError> {
        let mut ed25519_keys = HashMap::new();
        let mut x25519_keys = HashMap::new();
        let mut key_types = HashMap::new();
        let mut max_id: u64 = 0;

        // Load persisted handle counter.
        let persisted_next_id = storage.retrieve(COUNTER_KEY).await?.map_or(0, |data| {
            if data.len() == 8 {
                let mut buf = [0u8; 8];
                buf.copy_from_slice(&data);
                u64::from_le_bytes(buf)
            } else {
                0
            }
        });

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

            let data = storage.retrieve(key_path).await?.ok_or_else(|| {
                PlatformError::StorageError(format!("key {id} listed but not found"))
            })?;

            if data.len() == UNSEALED_ENTRY_LEN {
                return Err(PlatformError::CustodyError(format!(
                    "key {id} is {UNSEALED_ENTRY_LEN} bytes, the layout this custody \
                     wrote before it sealed entries under a per-entry AEAD with the \
                     key_type byte bound as AAD (GitHub issue #2299, the \
                     unauthenticated key_type byte). This build reads \
                     {ENTRY_LEN}-byte sealed entries only, and no migration path exists \
                     — regenerate the keys."
                )));
            }
            if data.len() != ENTRY_LEN {
                return Err(PlatformError::StorageError(format!(
                    "key {id} has invalid length {} (expected {ENTRY_LEN})",
                    data.len()
                )));
            }

            let key_type_byte = data[0];

            // Reject an unknown discriminant before decrypting. The AAD carries
            // this byte, so an unknown value would otherwise fail the tag check
            // and report itself as tampering rather than as an unknown type.
            if key_type_byte != KEY_TYPE_ED25519 && key_type_byte != KEY_TYPE_X25519 {
                return Err(PlatformError::StorageError(format!(
                    "key {id} has unknown type {key_type_byte}"
                )));
            }

            let key_bytes = custody_aead::open(
                &entry_key,
                &data[1..ENTRY_LEN],
                &entry_aad(key_type_byte, id),
            )?;

            if key_type_byte == KEY_TYPE_ED25519 {
                let signing_key = SigningKey::from_bytes(&key_bytes);
                ed25519_keys.insert(id, signing_key);
                key_types.insert(id, KEY_TYPE_ED25519);
            } else {
                let secret = StaticSecret::from(*key_bytes);
                x25519_keys.insert(id, secret);
                key_types.insert(id, KEY_TYPE_X25519);
            }
            // key_bytes automatically zeroed on drop via Zeroizing
        }

        // Start counter from the greater of: persisted counter or max observed ID + 1.
        let next_id = persisted_next_id.max(max_id + 1).max(1);

        Ok(Self {
            storage,
            entry_key,
            store: Mutex::new(SqliteKeyStore {
                key_types,
                ed25519_keys,
                x25519_keys,
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

    /// Persists a key to `SQLite` storage as `[key_type || sealed_entry]`,
    /// binding `key_type` and `id` as Additional Authenticated Data.
    async fn persist_key(
        &self,
        id: u64,
        private_key: &[u8; 32],
        key_type: u8,
    ) -> Result<(), PlatformError> {
        let sealed = custody_aead::seal(&self.entry_key, private_key, &entry_aad(key_type, id))?;
        let mut blob = [0u8; ENTRY_LEN];
        blob[0] = key_type;
        blob[1..].copy_from_slice(&sealed);
        let key_path = format!("{KEY_PREFIX}{id}");
        // `blob` carries ciphertext, not key material, so it needs no zeroizing.
        self.storage.store(&key_path, &blob).await
    }

    /// Removes a key from `SQLite` storage.
    async fn remove_persisted_key(&self, id: u64) -> Result<(), PlatformError> {
        let key_path = format!("{KEY_PREFIX}{id}");
        self.storage.delete(&key_path).await
    }

    /// Returns the stored key type for a handle, or an error if not found.
    fn lookup_type(store: &SqliteKeyStore, handle: KeyHandle) -> Result<u8, PlatformError> {
        store
            .key_types
            .get(&handle.id())
            .copied()
            .ok_or(PlatformError::KeyNotFound)
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
        async move {
            let handle = self.next_handle().await?;
            let mut key_bytes = Zeroizing::new([0u8; 32]);
            rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, key_bytes.as_mut());

            let type_byte = match key_type {
                KeyType::Ed25519 => KEY_TYPE_ED25519,
                KeyType::X25519 => KEY_TYPE_X25519,
            };

            // Persist to storage before adding to cache.
            self.persist_key(handle.id(), &key_bytes, type_byte).await?;

            let mut store = self.store.lock().await;
            match key_type {
                KeyType::Ed25519 => {
                    let signing_key = SigningKey::from_bytes(&key_bytes);
                    store.ed25519_keys.insert(handle.id(), signing_key);
                    store.key_types.insert(handle.id(), KEY_TYPE_ED25519);
                }
                KeyType::X25519 => {
                    let secret = StaticSecret::from(*key_bytes);
                    store.x25519_keys.insert(handle.id(), secret);
                    store.key_types.insert(handle.id(), KEY_TYPE_X25519);
                }
            }

            Ok(handle)
        }
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

            if kt != KEY_TYPE_ED25519 {
                return Err(PlatformError::WrongKeyType {
                    expected: KeyType::Ed25519,
                    actual: KeyType::X25519,
                });
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
                KEY_TYPE_ED25519 => {
                    let signing_key = store
                        .ed25519_keys
                        .get(&key_id)
                        .ok_or(PlatformError::KeyNotFound)?;
                    let verifying_key: VerifyingKey = signing_key.verifying_key();
                    Ok(PublicKey::new(verifying_key.to_bytes().to_vec()))
                }
                KEY_TYPE_X25519 => {
                    let secret = store
                        .x25519_keys
                        .get(&key_id)
                        .ok_or(PlatformError::KeyNotFound)?;
                    let public = X25519PublicKey::from(secret);
                    Ok(PublicKey::new(public.to_bytes().to_vec()))
                }
                _ => Err(PlatformError::KeyNotFound),
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
                KEY_TYPE_ED25519 => {
                    store.ed25519_keys.remove(&key_id);
                }
                KEY_TYPE_X25519 => {
                    store.x25519_keys.remove(&key_id);
                }
                _ => {}
            }
            store.key_types.remove(&key_id);
            drop(store);

            // Remove from persistent storage.
            self.remove_persisted_key(key_id).await?;

            Ok(())
        }
    }

    fn dh_agree(
        &self,
        key: &KeyHandle,
        peer_public: &[u8; 32],
    ) -> impl Future<Output = Result<SharedSecret, PlatformError>> + Send {
        let key_id = key.id();
        let peer = *peer_public;
        async move {
            let store = self.store.lock().await;
            let kt = Self::lookup_type(&store, KeyHandle::new(key_id))?;

            if kt != KEY_TYPE_X25519 {
                return Err(PlatformError::WrongKeyType {
                    expected: KeyType::X25519,
                    actual: KeyType::Ed25519,
                });
            }

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
        async move {
            let mut store = self.store.lock().await;
            let kt = Self::lookup_type(&store, KeyHandle::new(key_id))?;

            if kt != KEY_TYPE_ED25519 {
                return Err(PlatformError::WrongKeyType {
                    expected: KeyType::Ed25519,
                    actual: KeyType::X25519,
                });
            }

            let signing_key = store
                .ed25519_keys
                .get(&key_id)
                .ok_or(PlatformError::KeyNotFound)?;

            // Software custody: pseudonym keypair = Ed25519_keygen(HMAC-SHA256(
            //   pseudonym_secret, context_id || "scp-pseudonym")), where the
            // pseudonym_secret is derived from the private seed via HKDF (§9.10.4.A),
            // NOT the public key, to prevent membership enumeration attacks.
            let pseudonym_signing_key =
                scp_crypto::pseudonym::derive_pseudonym_keypair(signing_key, &context_id, None);
            let pseudonym_verifying_key = pseudonym_signing_key.verifying_key();

            // Store the derived signing key in the cache only (not persisted —
            // pseudonyms are deterministically re-derivable from the identity key).
            let handle = KeyHandle::new(self.next_id.fetch_add(1, Ordering::Relaxed));
            store
                .ed25519_keys
                .insert(handle.id(), pseudonym_signing_key);
            store.key_types.insert(handle.id(), KEY_TYPE_ED25519);

            Ok(PseudonymKeypair {
                public_key: PublicKey::new(pseudonym_verifying_key.to_bytes().to_vec()),
                key_handle: handle,
            })
        }
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
            let mut store = self.store.lock().await;
            let kt = Self::lookup_type(&store, KeyHandle::new(key_id))?;

            if kt != KEY_TYPE_ED25519 {
                return Err(PlatformError::WrongKeyType {
                    expected: KeyType::Ed25519,
                    actual: KeyType::X25519,
                });
            }

            let signing_key = store
                .ed25519_keys
                .get(&key_id)
                .ok_or(PlatformError::KeyNotFound)?;

            // Software custody: rotatable pseudonym keypair = Ed25519_keygen(
            //   HMAC-SHA256(pseudonym_secret, context_id || epoch_BE
            //   || "scp-pseudonym-v2")). The pseudonym_secret is derived from the
            // private seed via HKDF (§9.10.4.A), NOT the public key, to prevent
            // membership enumeration attacks. epoch_BE breaks long-term correlation.
            let pseudonym_signing_key = scp_crypto::pseudonym::derive_pseudonym_keypair(
                signing_key,
                &context_id,
                Some(pseudonym_epoch),
            );
            let pseudonym_verifying_key = pseudonym_signing_key.verifying_key();

            let handle = KeyHandle::new(self.next_id.fetch_add(1, Ordering::Relaxed));
            store
                .ed25519_keys
                .insert(handle.id(), pseudonym_signing_key);
            store.key_types.insert(handle.id(), KEY_TYPE_ED25519);

            Ok(PseudonymKeypair {
                public_key: PublicKey::new(pseudonym_verifying_key.to_bytes().to_vec()),
                key_handle: handle,
            })
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

            if kt != KEY_TYPE_ED25519 {
                return Err(PlatformError::WrongKeyType {
                    expected: KeyType::Ed25519,
                    actual: KeyType::X25519,
                });
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
            self.persist_key(handle.id(), &key_bytes, KEY_TYPE_ED25519)
                .await?;

            let mut store = self.store.lock().await;
            let signing_key = SigningKey::from_bytes(&key_bytes);
            store.ed25519_keys.insert(handle.id(), signing_key);
            store.key_types.insert(handle.id(), KEY_TYPE_ED25519);

            Ok(handle)
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use std::path::Path;

    /// Wrapping key for the per-entry seal in tests. Distinct from the
    /// `SQLCipher` database key so the two layers stay independent, exactly as
    /// production callers derive them.
    const ENTRY_KEY: [u8; 32] = [0x9Du8; 32];

    /// Creates a temporary `SqliteKeyCustody` for testing.
    async fn temp_custody(dir: &Path) -> SqliteKeyCustody {
        let key = [0x42u8; 32];
        let storage = SqliteStorage::new(dir, &key).unwrap();
        SqliteKeyCustody::new(storage, Zeroizing::new(ENTRY_KEY))
            .await
            .unwrap()
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
            let custody = SqliteKeyCustody::new(storage, Zeroizing::new(ENTRY_KEY))
                .await
                .unwrap();
            handle_ed = custody.generate_keypair(KeyType::Ed25519).await.unwrap();
            handle_x = custody.generate_keypair(KeyType::X25519).await.unwrap();
            pubkey_ed = custody.public_key(&handle_ed).await.unwrap();
            pubkey_x = custody.public_key(&handle_x).await.unwrap();
        }

        // Reload from the same database.
        {
            let storage = SqliteStorage::new(dir.path(), &key).unwrap();
            let custody = SqliteKeyCustody::new(storage, Zeroizing::new(ENTRY_KEY))
                .await
                .unwrap();
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

    #[tokio::test]
    async fn destroy_key_removes_from_storage() {
        let dir = tempfile::tempdir().unwrap();
        let key = [0x42u8; 32];

        let handle;
        {
            let storage = SqliteStorage::new(dir.path(), &key).unwrap();
            let custody = SqliteKeyCustody::new(storage, Zeroizing::new(ENTRY_KEY))
                .await
                .unwrap();
            handle = custody.generate_keypair(KeyType::Ed25519).await.unwrap();
            custody.destroy_key(&handle).await.unwrap();
        }

        // Reload — destroyed key should not be present.
        {
            let storage = SqliteStorage::new(dir.path(), &key).unwrap();
            let custody = SqliteKeyCustody::new(storage, Zeroizing::new(ENTRY_KEY))
                .await
                .unwrap();
            assert!(custody.public_key(&handle).await.is_err());
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
            let custody = SqliteKeyCustody::new(storage, Zeroizing::new(ENTRY_KEY))
                .await
                .unwrap();
            first_handle = custody.generate_keypair(KeyType::Ed25519).await.unwrap();
        }

        // Reload and generate a new key — handle should be higher.
        {
            let storage = SqliteStorage::new(dir.path(), &key).unwrap();
            let custody = SqliteKeyCustody::new(storage, Zeroizing::new(ENTRY_KEY))
                .await
                .unwrap();
            let second_handle = custody.generate_keypair(KeyType::Ed25519).await.unwrap();
            assert!(second_handle.id() > first_handle.id());
        }
    }

    /// GitHub issue #2299, the unauthenticated `key_type` byte: an Ed25519
    /// seed MUST NOT be retrievable as an
    /// X25519 static secret.
    ///
    /// The stored `key_type` byte decides which algorithm consumes the 32
    /// bytes, so it is bound as AAD. Rewriting it to the X25519 discriminant
    /// must fail the AEAD tag check on load. Before the binding, the same seed
    /// loaded as an X25519 `StaticSecret` and `dh_agree` returned a shared
    /// secret derived from an Ed25519 signing seed.
    #[tokio::test]
    async fn ed25519_seed_is_not_retrievable_as_x25519() {
        let dir = tempfile::tempdir().unwrap();
        let db_key = [0x42u8; 32];

        // Store one Ed25519 seed and record its storage path.
        let handle_id;
        {
            let storage = SqliteStorage::new(dir.path(), &db_key).unwrap();
            let custody = SqliteKeyCustody::new(storage, Zeroizing::new(ENTRY_KEY))
                .await
                .unwrap();
            let handle = custody.generate_keypair(KeyType::Ed25519).await.unwrap();
            handle_id = handle.id();
            custody.storage.close();
        }

        // Rewrite the plaintext `key_type` byte to the X25519 discriminant,
        // leaving the sealed remainder untouched — the flip an attacker with
        // write access to the decrypted row would make.
        let path = format!("{KEY_PREFIX}{handle_id}");
        {
            let storage = SqliteStorage::new(dir.path(), &db_key).unwrap();
            let mut blob = storage.retrieve(&path).await.unwrap().unwrap();
            assert_eq!(blob[0], KEY_TYPE_ED25519, "entry must start as Ed25519");
            blob[0] = KEY_TYPE_X25519;
            storage.store(&path, &blob).await.unwrap();
            storage.close();
        }

        // Loading must fail rather than surface the seed as an X25519 secret.
        let storage = SqliteStorage::new(dir.path(), &db_key).unwrap();
        let result = SqliteKeyCustody::new(storage, Zeroizing::new(ENTRY_KEY)).await;
        match result {
            Err(PlatformError::CustodyError(msg)) => {
                assert!(
                    msg.contains("decryption failed"),
                    "a flipped key_type byte must fail the AEAD tag check: {msg}"
                );
            }
            Err(other) => panic!("expected a decryption failure, got {other:?}"),
            Ok(_) => panic!("a flipped key_type byte must not load"),
        }
    }

    /// The reverse direction: an X25519 static secret MUST NOT be retrievable
    /// as an Ed25519 seed.
    #[tokio::test]
    async fn x25519_secret_is_not_retrievable_as_ed25519() {
        let dir = tempfile::tempdir().unwrap();
        let db_key = [0x42u8; 32];

        let handle_id;
        {
            let storage = SqliteStorage::new(dir.path(), &db_key).unwrap();
            let custody = SqliteKeyCustody::new(storage, Zeroizing::new(ENTRY_KEY))
                .await
                .unwrap();
            let handle = custody.generate_keypair(KeyType::X25519).await.unwrap();
            handle_id = handle.id();
            custody.storage.close();
        }

        let path = format!("{KEY_PREFIX}{handle_id}");
        {
            let storage = SqliteStorage::new(dir.path(), &db_key).unwrap();
            let mut blob = storage.retrieve(&path).await.unwrap().unwrap();
            assert_eq!(blob[0], KEY_TYPE_X25519, "entry must start as X25519");
            blob[0] = KEY_TYPE_ED25519;
            storage.store(&path, &blob).await.unwrap();
            storage.close();
        }

        let storage = SqliteStorage::new(dir.path(), &db_key).unwrap();
        assert!(
            SqliteKeyCustody::new(storage, Zeroizing::new(ENTRY_KEY))
                .await
                .is_err(),
            "a flipped key_type byte must not load in either direction"
        );
    }

    /// The handle ID is bound as AAD, so an entry copied from one handle's row
    /// to another's must not open under the new name.
    #[tokio::test]
    async fn entry_copied_to_another_handle_does_not_open() {
        let dir = tempfile::tempdir().unwrap();
        let db_key = [0x42u8; 32];

        let (first_id, second_id) = {
            let storage = SqliteStorage::new(dir.path(), &db_key).unwrap();
            let custody = SqliteKeyCustody::new(storage, Zeroizing::new(ENTRY_KEY))
                .await
                .unwrap();
            let a = custody.generate_keypair(KeyType::Ed25519).await.unwrap();
            let b = custody.generate_keypair(KeyType::Ed25519).await.unwrap();
            custody.storage.close();
            (a.id(), b.id())
        };

        {
            let storage = SqliteStorage::new(dir.path(), &db_key).unwrap();
            let first = storage
                .retrieve(&format!("{KEY_PREFIX}{first_id}"))
                .await
                .unwrap()
                .unwrap();
            storage
                .store(&format!("{KEY_PREFIX}{second_id}"), &first)
                .await
                .unwrap();
            storage.close();
        }

        let storage = SqliteStorage::new(dir.path(), &db_key).unwrap();
        assert!(
            SqliteKeyCustody::new(storage, Zeroizing::new(ENTRY_KEY))
                .await
                .is_err(),
            "an entry relocated to another handle ID must fail its tag check"
        );
    }

    /// A wrapping key other than the one the entries were sealed under must
    /// fail to open them, so the per-entry seal rests on its own secret rather
    /// than on the `SQLCipher` database key alone.
    #[tokio::test]
    async fn wrong_entry_key_does_not_open_the_custody() {
        let dir = tempfile::tempdir().unwrap();
        let db_key = [0x42u8; 32];

        {
            let storage = SqliteStorage::new(dir.path(), &db_key).unwrap();
            let custody = SqliteKeyCustody::new(storage, Zeroizing::new(ENTRY_KEY))
                .await
                .unwrap();
            custody.generate_keypair(KeyType::Ed25519).await.unwrap();
            custody.storage.close();
        }

        let storage = SqliteStorage::new(dir.path(), &db_key).unwrap();
        assert!(
            SqliteKeyCustody::new(storage, Zeroizing::new([0xEEu8; 32]))
                .await
                .is_err(),
            "the correct SQLCipher key alone must not open sealed entries"
        );
    }

    /// A database written before the per-entry sealing landed carries 33-byte
    /// entries. `new` must name that layout rather than report a bare length
    /// mismatch, because no migration path reads it.
    #[tokio::test]
    async fn pre_aead_entry_layout_is_rejected_by_name() {
        let dir = tempfile::tempdir().unwrap();
        let db_key = [0x42u8; 32];

        {
            let storage = SqliteStorage::new(dir.path(), &db_key).unwrap();
            // The old layout: key_type byte followed by the raw private key.
            let mut blob = [0u8; UNSEALED_ENTRY_LEN];
            blob[0] = KEY_TYPE_ED25519;
            blob[1..].copy_from_slice(&[0x77u8; 32]);
            storage
                .store(&format!("{KEY_PREFIX}1"), &blob)
                .await
                .unwrap();
            storage.close();
        }

        let storage = SqliteStorage::new(dir.path(), &db_key).unwrap();
        match SqliteKeyCustody::new(storage, Zeroizing::new(ENTRY_KEY)).await {
            Err(PlatformError::CustodyError(msg)) => {
                assert!(
                    msg.contains("regenerate the keys"),
                    "the error must tell the operator what to do: {msg}"
                );
                assert!(
                    msg.contains("2299"),
                    "the error must cite the issue that changed the layout: {msg}"
                );
            }
            Err(other) => panic!("expected a named layout error, got {other:?}"),
            Ok(_) => panic!("a 33-byte entry must not load"),
        }
    }

    /// An entry whose discriminant is neither Ed25519 nor X25519 must be named
    /// as an unknown type. The discriminant is AAD, so decrypting first would
    /// report an unknown byte as tampering and hide its real cause.
    #[tokio::test]
    async fn unknown_key_type_byte_is_named_rather_than_reported_as_tampering() {
        let dir = tempfile::tempdir().unwrap();
        let db_key = [0x42u8; 32];

        let handle_id;
        {
            let storage = SqliteStorage::new(dir.path(), &db_key).unwrap();
            let custody = SqliteKeyCustody::new(storage, Zeroizing::new(ENTRY_KEY))
                .await
                .unwrap();
            handle_id = custody
                .generate_keypair(KeyType::Ed25519)
                .await
                .unwrap()
                .id();
            custody.storage.close();
        }

        let path = format!("{KEY_PREFIX}{handle_id}");
        {
            let storage = SqliteStorage::new(dir.path(), &db_key).unwrap();
            let mut blob = storage.retrieve(&path).await.unwrap().unwrap();
            blob[0] = 0x7F;
            storage.store(&path, &blob).await.unwrap();
            storage.close();
        }

        let storage = SqliteStorage::new(dir.path(), &db_key).unwrap();
        match SqliteKeyCustody::new(storage, Zeroizing::new(ENTRY_KEY)).await {
            Err(PlatformError::StorageError(msg)) => {
                assert!(
                    msg.contains("unknown type 127"),
                    "the error must name the unknown discriminant: {msg}"
                );
            }
            Err(other) => panic!("expected an unknown-type error, got {other:?}"),
            Ok(_) => panic!("an unknown key_type byte must not load"),
        }
    }

    /// The sealed entry must not contain the private key bytes verbatim, so the
    /// per-entry AEAD — not only `SQLCipher` — is what protects them.
    #[tokio::test]
    async fn stored_entry_does_not_contain_the_raw_seed() {
        let dir = tempfile::tempdir().unwrap();
        let db_key = [0x42u8; 32];
        let seed = Zeroizing::new([0x5Cu8; 32]);

        let handle_id;
        {
            let storage = SqliteStorage::new(dir.path(), &db_key).unwrap();
            let custody = SqliteKeyCustody::new(storage, Zeroizing::new(ENTRY_KEY))
                .await
                .unwrap();
            handle_id = custody
                .import_ed25519_signing_key(&seed)
                .await
                .unwrap()
                .id();
            custody.storage.close();
        }

        let storage = SqliteStorage::new(dir.path(), &db_key).unwrap();
        let blob = storage
            .retrieve(&format!("{KEY_PREFIX}{handle_id}"))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(blob.len(), ENTRY_LEN, "entry must be the sealed layout");
        assert!(
            !blob.windows(32).any(|w| w == &seed[..]),
            "the sealed entry must not contain the raw seed"
        );
    }

    #[tokio::test]
    async fn custody_type_returns_software() {
        let dir = tempfile::tempdir().unwrap();
        let custody = temp_custody(dir.path()).await;
        let handle = custody.generate_keypair(KeyType::Ed25519).await.unwrap();
        assert_eq!(custody.custody_type(&handle), CustodyType::Software);
    }
}
