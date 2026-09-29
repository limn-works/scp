//! Wrapping key storage operations for `ProtocolRepository`.
//!
//! Persists an identity's DHKEM(P-256) wrapping keypair (spec 09 §9.16.1),
//! one per identity, under the key from spec 17 §17.3:
//!
//! ```text
//! wrapping_key/{did}
//! ```
//!
//! Only the 32-byte scalar is stored, in one write; the public point is
//! derived on load by [`WrappingKeyPair::from_secret`]. A store therefore
//! cannot be torn between two halves, and a loaded pair cannot disagree with
//! itself. A stored value that is not a scalar in `[1, n − 1]` fails to load
//! with [`StoreError::InvalidKeyMaterial`].
//!
//! The keypair is stable across MLS epoch advances and rotates only on
//! identity key rotation (§9.12) or suspected compromise.

use scp_platform::traits::Storage;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

use super::{ProtocolRepository, StoreError};
use crate::crypto::wrapping::WrappingKeyPair;

/// Builds the storage key for an identity's wrapping scalar.
///
/// Format: `wrapping_key/{did}`
fn wrapping_key_path(did: &str) -> Result<String, StoreError> {
    let d = super::sanitize_key_component(did)?;
    Ok(format!("wrapping_key/{d}"))
}

/// Stored wrapping secret key (32-byte P-256 scalar).
///
/// Implements `Zeroize` and `Drop` for defense-in-depth key material cleanup.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Zeroize)]
pub struct StoredWrappingSecretKey {
    /// Raw 32-byte P-256 scalar.
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

impl<S: Storage> ProtocolRepository<S> {
    /// Stores `pair`'s scalar as the wrapping key of `did`, replacing any
    /// stored one. The serialized buffer is zeroized after the write.
    ///
    /// # Errors
    ///
    /// [`StoreError`] if `did` is not a valid key component, or if
    /// serialization or storage fails.
    pub async fn store_wrapping_key(
        &self,
        did: &str,
        pair: &WrappingKeyPair,
    ) -> Result<(), StoreError> {
        let path = wrapping_key_path(did)?;
        let value = StoredWrappingSecretKey {
            key: pair.secret().to_vec(),
        };
        self.store_value_zeroize(&path, &value).await
    }

    /// Loads the wrapping keypair of `did`, deriving its public point from the
    /// stored scalar. Returns `None` if none is stored.
    ///
    /// # Errors
    ///
    /// [`StoreError::InvalidKeyMaterial`] if the stored value is not a
    /// 32-byte P-256 scalar in `[1, n − 1]`; another [`StoreError`] if
    /// deserialization fails.
    pub async fn load_wrapping_key(
        &self,
        did: &str,
    ) -> Result<Option<WrappingKeyPair>, StoreError> {
        let path = wrapping_key_path(did)?;
        let stored: Option<StoredWrappingSecretKey> = self.load_value(&path).await?;
        let Some(v) = stored else {
            return Ok(None);
        };
        let secret: Zeroizing<[u8; 32]> =
            Zeroizing::new(v.key.as_slice().try_into().map_err(|_| {
                StoreError::InvalidKeyMaterial(format!(
                    "stored wrapping secret key must be 32 bytes, got {}",
                    v.key.len()
                ))
            })?);
        WrappingKeyPair::from_secret(secret)
            .map(Some)
            .map_err(|e| StoreError::InvalidKeyMaterial(format!("stored wrapping secret key: {e}")))
    }

    /// Deletes the wrapping key of `did`. Used on identity key rotation
    /// (§9.12) before the new key is stored.
    ///
    /// # Errors
    ///
    /// [`StoreError`] if the delete fails.
    pub async fn delete_wrapping_key(&self, did: &str) -> Result<(), StoreError> {
        let path = wrapping_key_path(did)?;
        self.storage.delete(&path).await?;
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use scp_platform::in_memory::InMemoryStorage;

    use super::*;

    fn test_store() -> ProtocolRepository<InMemoryStorage> {
        ProtocolRepository::new_for_testing(InMemoryStorage::new())
    }

    /// A stored pair loads back with the same scalar and the same point, and
    /// the store wrote exactly one entry: the scalar under `wrapping_key/{did}`.
    #[tokio::test]
    async fn store_and_load_round_trips_through_one_scalar_entry() {
        let store = test_store();
        let pair = WrappingKeyPair::generate();

        store
            .store_wrapping_key("did:dht:alice", &pair)
            .await
            .unwrap();

        let loaded = store
            .load_wrapping_key("did:dht:alice")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(loaded.public(), pair.public());
        assert_eq!(**loaded.secret(), **pair.secret());

        let path = wrapping_key_path("did:dht:alice").unwrap();
        assert_eq!(path, "wrapping_key/did:dht:alice");
        let raw: StoredWrappingSecretKey = store.load_value(&path).await.unwrap().unwrap();
        assert_eq!(raw.key.as_slice(), pair.secret().as_slice());
    }

    /// A stored value that is not a valid P-256 scalar (wrong length, zero,
    /// or at least the group order) fails to load with `InvalidKeyMaterial`.
    #[tokio::test]
    async fn load_rejects_invalid_stored_secret_key() {
        let store = test_store();
        for (case, key) in [
            ("16 bytes", vec![1u8; 16]),
            ("zero scalar", vec![0u8; 32]),
            ("all-ones scalar", vec![0xFFu8; 32]),
        ] {
            let path = wrapping_key_path("did:dht:alice").unwrap();
            store
                .store_value_zeroize(&path, &StoredWrappingSecretKey { key })
                .await
                .unwrap();
            let err = store.load_wrapping_key("did:dht:alice").await.unwrap_err();
            assert!(
                matches!(err, StoreError::InvalidKeyMaterial(_)),
                "{case}: {err:?}"
            );
        }
    }

    #[tokio::test]
    async fn load_returns_none_when_not_stored() {
        let store = test_store();
        assert!(
            store
                .load_wrapping_key("did:dht:nobody")
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn delete_wrapping_key_removes_it() {
        let store = test_store();
        store
            .store_wrapping_key("did:dht:alice", &WrappingKeyPair::generate())
            .await
            .unwrap();
        store.delete_wrapping_key("did:dht:alice").await.unwrap();
        assert!(
            store
                .load_wrapping_key("did:dht:alice")
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn different_identities_are_isolated() {
        let store = test_store();
        let alice = WrappingKeyPair::generate();
        let bob = WrappingKeyPair::generate();
        store
            .store_wrapping_key("did:dht:alice", &alice)
            .await
            .unwrap();
        store.store_wrapping_key("did:dht:bob", &bob).await.unwrap();
        let got_alice = store
            .load_wrapping_key("did:dht:alice")
            .await
            .unwrap()
            .unwrap();
        let got_bob = store
            .load_wrapping_key("did:dht:bob")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(got_alice.public(), alice.public());
        assert_eq!(got_bob.public(), bob.public());
    }

    #[test]
    fn stored_wrapping_secret_key_debug_redacts() {
        let key = StoredWrappingSecretKey { key: vec![1; 32] };
        let debug = format!("{key:?}");
        assert!(debug.contains("REDACTED"));
    }
}
