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

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};

use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use tokio::sync::Mutex;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};
use zeroize::Zeroizing;

use super::SqliteStorage;
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
/// Each key is stored under `custody/keys/{handle_id}` as a 33-byte blob:
/// `[key_type_byte || 32_bytes_private_key]`. The handle counter is persisted
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

            if data.len() != 33 {
                return Err(PlatformError::StorageError(format!(
                    "key {id} has invalid length {} (expected 33)",
                    data.len()
                )));
            }

            let key_type_byte = data[0];
            let mut key_bytes = Zeroizing::new([0u8; 32]);
            key_bytes.copy_from_slice(&data[1..33]);

            match key_type_byte {
                KEY_TYPE_ED25519 => {
                    let signing_key = SigningKey::from_bytes(&key_bytes);
                    ed25519_keys.insert(id, signing_key);
                    key_types.insert(id, KEY_TYPE_ED25519);
                }
                KEY_TYPE_X25519 => {
                    let secret = StaticSecret::from(*key_bytes);
                    x25519_keys.insert(id, secret);
                    key_types.insert(id, KEY_TYPE_X25519);
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

    /// Persists a key to `SQLite` storage as `[key_type || private_key]`.
    async fn persist_key(
        &self,
        id: u64,
        private_key: &[u8; 32],
        key_type: u8,
    ) -> Result<(), PlatformError> {
        let mut blob = Zeroizing::new([0u8; 33]);
        blob[0] = key_type;
        blob[1..33].copy_from_slice(private_key);
        let key_path = format!("{KEY_PREFIX}{id}");
        self.storage.store(&key_path, blob.as_ref()).await
        // blob automatically zeroed on drop via Zeroizing
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

            // HMAC-SHA256(ed25519_public_key_bytes, context_id || "scp-pseudonym")
            // ADR-027 amendment: uses verifying (public) key bytes.
            let verifying_key = signing_key.verifying_key();
            let mut mac =
                <Hmac<Sha256> as Mac>::new_from_slice(verifying_key.to_bytes().as_slice())
                    .map_err(|e| PlatformError::CustodyError(e.to_string()))?;
            mac.update(&context_id);
            mac.update(b"scp-pseudonym");
            let hmac_output = mac.finalize().into_bytes();

            let mut seed = Zeroizing::new([0u8; 32]);
            seed.copy_from_slice(&hmac_output[..32]);
            let pseudonym_signing_key = SigningKey::from_bytes(&seed);
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

            // HMAC-SHA256(ed25519_public_key_bytes, context_id || epoch_BE || "scp-pseudonym-v2")
            let verifying_key = signing_key.verifying_key();
            let mut mac =
                <Hmac<Sha256> as Mac>::new_from_slice(verifying_key.to_bytes().as_slice())
                    .map_err(|e| PlatformError::CustodyError(e.to_string()))?;
            mac.update(&context_id);
            mac.update(&pseudonym_epoch.to_be_bytes());
            mac.update(b"scp-pseudonym-v2");
            let hmac_output = mac.finalize().into_bytes();

            let mut seed = Zeroizing::new([0u8; 32]);
            seed.copy_from_slice(&hmac_output[..32]);
            let pseudonym_signing_key = SigningKey::from_bytes(&seed);
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
}
