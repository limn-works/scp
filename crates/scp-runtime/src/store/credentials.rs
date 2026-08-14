//! Bridge credential storage operations for `ProtocolRepository`.
//!
//! Durable persistence for bridge connector credentials (OAuth tokens, API
//! keys, webhook secrets) and their per-bridge root credential keys, following
//! the key convention from spec section 17.3:
//!
//! ```text
//! bridge-credential/{bridge_id}/{credential_type_hash}   -> StoredValue<BridgeCredential>
//! bridge-credential-key/{bridge_id}                       -> StoredValue<[u8; 32]>
//! ```
//!
//! These are the persistent substrate behind
//! [`ProtocolRepositoryCredentialStore`](crate::bridge::credentials::ProtocolRepositoryCredentialStore),
//! the real durable [`BridgeCredentialStore`](crate::bridge::credentials::BridgeCredentialStore)
//! backend selected at the FFI bridge construction boundary (ADR-062 §Decision 5,
//! SCP-CAPINJECT-009). The stored `BridgeCredential.encrypted_data` is already
//! AES-256-GCM ciphertext (encrypted under a key derived from the per-bridge
//! `bridge_credential_key`); the underlying `EncryptedStorage` backend encrypts
//! it a second time at rest (`SQLCipher` / `EncryptingAdapter`), so credentials
//! are double-encrypted defense-in-depth (spec §12.11.2).
//!
//! The `credential_type` is hashed into a fixed-length, key-convention-safe
//! component (SHA-256 of its canonical `Display` form) so that a
//! `CredentialType::Custom(name)` value with arbitrary bytes can never break
//! the `{namespace}/{entity_id}/{sub_key}` key grammar or inject a path
//! separator. The full `CredentialType` is preserved verbatim inside the stored
//! `BridgeCredential` value, so `list` reconstructs the exact types by reading
//! the values rather than parsing them back out of the key.
//!
//! See spec sections 17.3, 17.4, and 12.11. See SCP-CAPINJECT-009.

use scp_platform::traits::Storage;
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

use crate::bridge::credentials::{BridgeCredential, CredentialType};

use super::{ProtocolRepository, StoreError};

// ---------------------------------------------------------------------------
// Key helpers
// ---------------------------------------------------------------------------

/// Derives the key-convention-safe sub-key component for a credential type.
///
/// Format: lowercase hex of `SHA-256(Display(credential_type))`. Hashing keeps
/// the component fixed-length and free of the forbidden `/` separator even for
/// `CredentialType::Custom(arbitrary)`; the value itself carries the exact
/// `credential_type` so no reverse mapping from the key is needed.
fn credential_type_key_component(credential_type: &CredentialType) -> String {
    let digest = Sha256::digest(credential_type.to_string().as_bytes());
    hex::encode(digest)
}

/// Builds the storage key for a single bridge credential.
///
/// Format: `bridge-credential/{bridge_id}/{credential_type_hash}`
/// See spec section 17.3.
fn bridge_credential_key(
    bridge_id: &str,
    credential_type: &CredentialType,
) -> Result<String, StoreError> {
    let bid = super::sanitize_key_component(bridge_id)?;
    let ct = credential_type_key_component(credential_type);
    Ok(format!("bridge-credential/{bid}/{ct}"))
}

/// Builds the prefix for listing/deleting all credentials for a bridge.
///
/// Format: `bridge-credential/{bridge_id}/`
fn bridge_credentials_prefix(bridge_id: &str) -> Result<String, StoreError> {
    let bid = super::sanitize_key_component(bridge_id)?;
    Ok(format!("bridge-credential/{bid}/"))
}

/// Builds the storage key for a bridge's root credential key.
///
/// Format: `bridge-credential-key/{bridge_id}`
/// See spec section 17.3.
fn bridge_credential_root_key(bridge_id: &str) -> Result<String, StoreError> {
    let bid = super::sanitize_key_component(bridge_id)?;
    Ok(format!("bridge-credential-key/{bid}"))
}

// ---------------------------------------------------------------------------
// ProtocolRepository — bridge credential methods
// ---------------------------------------------------------------------------

impl<S: Storage> ProtocolRepository<S> {
    /// Persists a single bridge credential.
    ///
    /// The `credential.encrypted_data` is already AES-256-GCM ciphertext; the
    /// `StoredValue` envelope is written through the `EncryptedStorage` backend
    /// (encrypted a second time at rest). Overwrites any existing credential of
    /// the same `(bridge_id, credential_type)`.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::SerializationFailed`] if serialization fails.
    /// Returns [`StoreError::Storage`] if the underlying storage write fails.
    pub(crate) async fn store_bridge_credential(
        &self,
        credential: &BridgeCredential,
    ) -> Result<(), StoreError> {
        let key = bridge_credential_key(&credential.bridge_id, &credential.credential_type)?;
        self.store_value(&key, credential).await
    }

    /// Loads a single bridge credential.
    ///
    /// Returns `None` if no credential of the given type exists for the bridge.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Storage`] if the underlying storage read fails.
    /// Returns [`StoreError::DeserializationFailed`] if the stored value is
    /// corrupt.
    pub(crate) async fn load_bridge_credential(
        &self,
        bridge_id: &str,
        credential_type: &CredentialType,
    ) -> Result<Option<BridgeCredential>, StoreError> {
        let key = bridge_credential_key(bridge_id, credential_type)?;
        self.load_value(&key).await
    }

    /// Lists the credential types persisted for a bridge.
    ///
    /// Prefix-scans `bridge-credential/{bridge_id}/` and reads each stored
    /// value's exact `credential_type`. Returns the types without exposing any
    /// credential ciphertext.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Storage`] if the underlying storage read fails.
    /// Returns [`StoreError::DeserializationFailed`] if a stored value is
    /// corrupt.
    pub(crate) async fn list_bridge_credential_types(
        &self,
        bridge_id: &str,
    ) -> Result<Vec<CredentialType>, StoreError> {
        let prefix = bridge_credentials_prefix(bridge_id)?;
        let keys = self.storage().list_keys(&prefix).await?;
        let mut types = Vec::with_capacity(keys.len());
        for key in keys {
            if let Some(cred) = self.load_value::<BridgeCredential>(&key).await? {
                types.push(cred.credential_type);
            }
        }
        Ok(types)
    }

    /// Deletes every credential (but not the root key) for a bridge.
    ///
    /// Uses the `delete_prefix` atomic sweep. Callers that also need the root
    /// credential key destroyed must additionally call
    /// [`delete_bridge_credential_root_key`](Self::delete_bridge_credential_root_key).
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Storage`] if the underlying delete fails.
    pub(crate) async fn delete_bridge_credentials(
        &self,
        bridge_id: &str,
    ) -> Result<(), StoreError> {
        let prefix = bridge_credentials_prefix(bridge_id)?;
        self.storage().delete_prefix(&prefix).await?;
        Ok(())
    }

    /// Persists a bridge's root credential key, zeroizing the serialized buffer
    /// after the write.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::SerializationFailed`] if serialization fails.
    /// Returns [`StoreError::Storage`] if the underlying storage write fails.
    pub(crate) async fn store_bridge_credential_root_key(
        &self,
        bridge_id: &str,
        key: &[u8; 32],
    ) -> Result<(), StoreError> {
        let storage_key = bridge_credential_root_key(bridge_id)?;
        // Wrap the `Vec` copy of the raw root key in `Zeroizing` so the heap
        // buffer is scrubbed on drop — `store_value_zeroize` only scrubs the
        // *serialized* envelope, not this intermediate. The root key is the
        // single secret gating all credential decryption for the bridge.
        let raw = Zeroizing::new(key.to_vec());
        self.store_value_zeroize(&storage_key, &*raw).await
    }

    /// Loads a bridge's root credential key, wrapped in [`Zeroizing`].
    ///
    /// Returns `None` if no key is stored for the bridge.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Storage`] if the underlying storage read fails.
    /// Returns [`StoreError::DeserializationFailed`] if the stored value is
    /// corrupt or not exactly 32 bytes.
    pub(crate) async fn load_bridge_credential_root_key(
        &self,
        bridge_id: &str,
    ) -> Result<Option<Zeroizing<[u8; 32]>>, StoreError> {
        let storage_key = bridge_credential_root_key(bridge_id)?;
        let Some(bytes): Option<Vec<u8>> = self.load_value(&storage_key).await? else {
            return Ok(None);
        };
        let mut bytes = Zeroizing::new(bytes);
        let len = bytes.len();
        let array: [u8; 32] = bytes.as_slice().try_into().map_err(|_| {
            StoreError::DeserializationFailed(format!(
                "bridge credential root key for '{bridge_id}' is {len} bytes, expected 32"
            ))
        })?;
        bytes.zeroize();
        Ok(Some(Zeroizing::new(array)))
    }

    /// Deletes a bridge's root credential key.
    ///
    /// This tears down the *stored custody copy* of the root key, so
    /// [`load_bridge_credential_root_key`](Self::load_bridge_credential_root_key)
    /// returns `None` afterward. It does NOT by itself prevent decryption of an
    /// existing credential record: retrieval derives its AES key from a
    /// caller-supplied `bridge_credential_key`, not this stored copy. Full
    /// revocation therefore also deletes the credential records
    /// ([`delete_bridge_credentials`](Self::delete_bridge_credentials)).
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Storage`] if the underlying delete fails.
    pub(crate) async fn delete_bridge_credential_root_key(
        &self,
        bridge_id: &str,
    ) -> Result<(), StoreError> {
        let storage_key = bridge_credential_root_key(bridge_id)?;
        self.storage().delete(&storage_key).await?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use std::sync::atomic::{AtomicU64, Ordering};

    use scp_platform::sqlite::SqliteStorage;

    use super::*;
    use crate::bridge::credentials::{
        credential_aad, decrypt_credential, derive_credential_key, encrypt_credential,
        generate_bridge_credential_key,
    };

    /// Deterministic 32-byte `SQLCipher` key for the on-disk test database.
    const DB_KEY: &[u8; 32] = b"sqlcipher-db-key-32-bytes-long!!";

    static UNIQUE: AtomicU64 = AtomicU64::new(0);

    /// Allocates a unique, empty temp directory for an on-disk `SQLite` database.
    fn unique_temp_dir() -> std::path::PathBuf {
        let n = UNIQUE.fetch_add(1, Ordering::Relaxed);
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!(
            "scp-cred-restart-{}-{n}-{nanos}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// AC4: a real durable credential store persists a bridge token across a
    /// full store teardown + on-disk reopen — proving it is NOT RAM-only.
    ///
    /// Opens a real on-disk `SqliteStorage`, writes an encrypted bridge
    /// credential + its root key through `ProtocolRepository`, DROPS the store
    /// (and its `Arc<SqliteStorage>`, releasing the advisory lock), reopens the
    /// database at the same path/key, and reads the value back — asserting the
    /// ciphertext bytes are byte-identical and the token decrypts end-to-end.
    #[tokio::test]
    async fn bridge_credential_survives_store_drop_and_reopen() {
        let dir = unique_temp_dir();

        let bridge_id = "bridge-restart-001";
        let created_at = 1_700_000_000;
        let root_key = generate_bridge_credential_key();
        let derived = derive_credential_key(&root_key, bridge_id).unwrap();
        let aad = credential_aad(&CredentialType::OAuthAccessToken, created_at);
        let ciphertext = encrypt_credential(&derived, b"oauth-access-token-persist", &aad).unwrap();
        let credential = BridgeCredential {
            encrypted_data: ciphertext.clone(),
            credential_type: CredentialType::OAuthAccessToken,
            created_at,
            expires_at: None,
            bridge_id: bridge_id.to_owned(),
        };

        // --- Session 1: write, then drop the store entirely. ---
        {
            let storage = std::sync::Arc::new(SqliteStorage::new(&dir, DB_KEY).unwrap());
            let repo = ProtocolRepository::new(storage);
            repo.store_bridge_credential_root_key(bridge_id, &root_key)
                .await
                .unwrap();
            repo.store_bridge_credential(&credential).await.unwrap();
            // `repo` (and the `Arc<SqliteStorage>` it owns) drops here,
            // releasing the advisory lock so session 2 can reopen.
        }

        // --- Session 2: reopen the SAME on-disk database and read back. ---
        {
            let storage = std::sync::Arc::new(SqliteStorage::new(&dir, DB_KEY).unwrap());
            let repo = ProtocolRepository::new(storage);

            let loaded = repo
                .load_bridge_credential(bridge_id, &CredentialType::OAuthAccessToken)
                .await
                .unwrap()
                .expect("credential must survive store drop + on-disk reopen");
            assert_eq!(
                loaded.encrypted_data, ciphertext,
                "persisted ciphertext must be byte-identical after restart"
            );
            assert_eq!(loaded.bridge_id, bridge_id);
            assert_eq!(loaded.credential_type, CredentialType::OAuthAccessToken);

            let root = repo
                .load_bridge_credential_root_key(bridge_id)
                .await
                .unwrap()
                .expect("root key must survive restart");
            assert_eq!(
                *root, *root_key,
                "root key must be byte-identical after restart"
            );

            // The reconstructed store still decrypts the token end-to-end
            // (rebuilding the SAME AAD from the loaded type + created_at).
            let re_derived = derive_credential_key(&root, bridge_id).unwrap();
            let re_aad = credential_aad(&loaded.credential_type, loaded.created_at);
            let plaintext =
                decrypt_credential(&re_derived, &loaded.encrypted_data, &re_aad).unwrap();
            assert_eq!(plaintext.as_slice(), b"oauth-access-token-persist");

            let types = repo.list_bridge_credential_types(bridge_id).await.unwrap();
            assert_eq!(types, vec![CredentialType::OAuthAccessToken]);
        }

        let _ = std::fs::remove_dir_all(&dir);
    }
}
