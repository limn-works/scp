//! Wrapping key storage operations for `ProtocolStore`.
//!
//! Persists X25519 wrapping keypairs per context per DID, following the key
//! convention from spec section 17.3:
//!
//! ```text
//! wrapping_key/{context_id}/{did}/public
//! wrapping_key/{context_id}/{did}/secret
//! ```
//!
//! The wrapping keypair is stable across MLS epoch advances and rotates only
//! on identity key rotation (§9.12) or suspected compromise. See §9.16.1.

use scp_platform::traits::Storage;
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use super::{ProtocolStore, StoreError};

// ---------------------------------------------------------------------------
// Key helpers
// ---------------------------------------------------------------------------

/// Builds the storage key for a wrapping public key.
///
/// Format: `wrapping_key/{context_id}/{did}/public`
fn wrapping_public_key_path(context_id: &str, did: &str) -> Result<String, StoreError> {
    let ctx = super::sanitize_key_component(context_id)?;
    let d = super::sanitize_key_component(did)?;
    Ok(format!("wrapping_key/{ctx}/{d}/public"))
}

/// Builds the storage key for a wrapping secret key.
///
/// Format: `wrapping_key/{context_id}/{did}/secret`
fn wrapping_secret_key_path(context_id: &str, did: &str) -> Result<String, StoreError> {
    let ctx = super::sanitize_key_component(context_id)?;
    let d = super::sanitize_key_component(did)?;
    Ok(format!("wrapping_key/{ctx}/{d}/secret"))
}

// ---------------------------------------------------------------------------
// Stored types
// ---------------------------------------------------------------------------

/// Stored wrapping public key (32 bytes X25519).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredWrappingPublicKey {
    /// Raw 32-byte X25519 public key.
    #[serde(with = "serde_bytes")]
    pub key: Vec<u8>,
}

/// Stored wrapping secret key (32 bytes X25519).
///
/// Implements `Zeroize` and `Drop` for defense-in-depth key material cleanup.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Zeroize)]
pub struct StoredWrappingSecretKey {
    /// Raw 32-byte X25519 secret key.
    #[serde(with = "serde_bytes")]
    pub key: Vec<u8>,
}

impl Drop for StoredWrappingSecretKey {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

impl std::fmt::Debug for StoredWrappingSecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StoredWrappingSecretKey")
            .field("key", &"[REDACTED]")
            .finish()
    }
}

// ---------------------------------------------------------------------------
// ProtocolStore methods
// ---------------------------------------------------------------------------

impl<S: Storage> ProtocolStore<S> {
    /// Stores a wrapping keypair for a member in a context.
    ///
    /// Both the public and secret key are stored under separate keys.
    /// The secret key buffer is zeroized after writing for defense-in-depth.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] if serialization or storage fails.
    pub async fn store_wrapping_keypair(
        &self,
        context_id: &str,
        did: &str,
        public_key: &[u8; 32],
        secret_key: &[u8; 32],
    ) -> Result<(), StoreError> {
        let pub_path = wrapping_public_key_path(context_id, did)?;
        let sec_path = wrapping_secret_key_path(context_id, did)?;

        let pub_value = StoredWrappingPublicKey {
            key: public_key.to_vec(),
        };
        let sec_value = StoredWrappingSecretKey {
            key: secret_key.to_vec(),
        };

        self.store_value(&pub_path, &pub_value).await?;
        self.store_value_zeroize(&sec_path, &sec_value).await?;

        Ok(())
    }

    /// Loads the wrapping public key for a member in a context.
    ///
    /// Returns `None` if no wrapping key is stored.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] if deserialization fails.
    pub async fn load_wrapping_public_key(
        &self,
        context_id: &str,
        did: &str,
    ) -> Result<Option<[u8; 32]>, StoreError> {
        let path = wrapping_public_key_path(context_id, did)?;
        let stored: Option<StoredWrappingPublicKey> = self.load_value(&path).await?;
        match stored {
            None => Ok(None),
            Some(v) => {
                let arr: [u8; 32] = v.key.as_slice().try_into().map_err(|_| {
                    StoreError::DeserializationFailed(format!(
                        "wrapping public key must be 32 bytes, got {}",
                        v.key.len()
                    ))
                })?;
                Ok(Some(arr))
            }
        }
    }

    /// Loads the wrapping secret key for a member in a context.
    ///
    /// Returns `None` if no wrapping key is stored.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] if deserialization fails.
    pub async fn load_wrapping_secret_key(
        &self,
        context_id: &str,
        did: &str,
    ) -> Result<Option<[u8; 32]>, StoreError> {
        let path = wrapping_secret_key_path(context_id, did)?;
        let stored: Option<StoredWrappingSecretKey> = self.load_value(&path).await?;
        match stored {
            None => Ok(None),
            Some(v) => {
                let arr: [u8; 32] = v.key.as_slice().try_into().map_err(|_| {
                    StoreError::DeserializationFailed(format!(
                        "wrapping secret key must be 32 bytes, got {}",
                        v.key.len()
                    ))
                })?;
                Ok(Some(arr))
            }
        }
    }

    /// Deletes the wrapping keypair for a member in a context.
    ///
    /// Used during identity key rotation (§9.12) to remove the old keypair
    /// before storing the new one.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] if the delete operation fails.
    pub async fn delete_wrapping_keypair(
        &self,
        context_id: &str,
        did: &str,
    ) -> Result<(), StoreError> {
        let pub_path = wrapping_public_key_path(context_id, did)?;
        let sec_path = wrapping_secret_key_path(context_id, did)?;

        self.storage.delete(&pub_path).await?;
        self.storage.delete(&sec_path).await?;

        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use scp_platform::testing::InMemoryStorage;

    use super::*;

    fn test_store() -> ProtocolStore<InMemoryStorage> {
        ProtocolStore::new_for_testing(InMemoryStorage::new())
    }

    #[tokio::test]
    async fn store_and_load_wrapping_keypair() {
        let store = test_store();
        let pubkey = [42u8; 32];
        let secret = [99u8; 32];

        store
            .store_wrapping_keypair("ctx-1", "did:dht:alice", &pubkey, &secret)
            .await
            .unwrap();

        let loaded_pub = store
            .load_wrapping_public_key("ctx-1", "did:dht:alice")
            .await
            .unwrap();
        assert_eq!(loaded_pub, Some(pubkey));

        let loaded_sec = store
            .load_wrapping_secret_key("ctx-1", "did:dht:alice")
            .await
            .unwrap();
        assert_eq!(loaded_sec, Some(secret));
    }

    #[tokio::test]
    async fn load_returns_none_when_not_stored() {
        let store = test_store();

        let loaded = store
            .load_wrapping_public_key("ctx-1", "did:dht:nobody")
            .await
            .unwrap();
        assert_eq!(loaded, None);
    }

    #[tokio::test]
    async fn delete_wrapping_keypair_removes_both_keys() {
        let store = test_store();
        let pubkey = [1u8; 32];
        let secret = [2u8; 32];

        store
            .store_wrapping_keypair("ctx-1", "did:dht:alice", &pubkey, &secret)
            .await
            .unwrap();

        store
            .delete_wrapping_keypair("ctx-1", "did:dht:alice")
            .await
            .unwrap();

        assert_eq!(
            store
                .load_wrapping_public_key("ctx-1", "did:dht:alice")
                .await
                .unwrap(),
            None
        );
        assert_eq!(
            store
                .load_wrapping_secret_key("ctx-1", "did:dht:alice")
                .await
                .unwrap(),
            None
        );
    }

    #[tokio::test]
    async fn different_contexts_are_isolated() {
        let store = test_store();
        let key1 = [10u8; 32];
        let key2 = [20u8; 32];
        let sec1 = [11u8; 32];
        let sec2 = [21u8; 32];

        store
            .store_wrapping_keypair("ctx-1", "did:dht:alice", &key1, &sec1)
            .await
            .unwrap();
        store
            .store_wrapping_keypair("ctx-2", "did:dht:alice", &key2, &sec2)
            .await
            .unwrap();

        let loaded1 = store
            .load_wrapping_public_key("ctx-1", "did:dht:alice")
            .await
            .unwrap();
        let loaded2 = store
            .load_wrapping_public_key("ctx-2", "did:dht:alice")
            .await
            .unwrap();
        assert_eq!(loaded1, Some(key1));
        assert_eq!(loaded2, Some(key2));
    }

    #[test]
    fn stored_wrapping_secret_key_debug_redacts() {
        let key = StoredWrappingSecretKey { key: vec![1; 32] };
        let debug = format!("{key:?}");
        assert!(debug.contains("REDACTED"));
    }
}
