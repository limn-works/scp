//! Wrapping key storage operations for `ProtocolRepository`.
//!
//! Persists DHKEM(P-256) wrapping keypairs (§9.16.1) per context per DID:
//! the 65-byte uncompressed point and its 32-byte scalar. Following the key
//! convention from spec section 17.3:
//!
//! ```text
//! wrapping_key/{context_id}/{did}/public
//! wrapping_key/{context_id}/{did}/secret
//! ```
//!
//! The wrapping keypair is stable across MLS epoch advances and rotates only
//! on identity key rotation (§9.12) or suspected compromise. See §9.16.1.
//!
//! A pair is checked on the way in and each half on the way out (C19(d)):
//! [`ProtocolRepository::store_wrapping_keypair`] refuses a secret whose
//! `scalar · G` is not the public key, and the loads refuse a stored public
//! key that is not a valid P-256 point (§9.5) or a stored secret that is not a
//! valid scalar, each with a typed [`StoreError`].

use scp_platform::traits::Storage;
use scp_protocol::crypto::hpke::p256 as hpke;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

use super::{ProtocolRepository, StoreError};

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

/// Stored wrapping public key (65-byte uncompressed P-256 point).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredWrappingPublicKey {
    /// Raw 65-byte uncompressed P-256 point.
    #[serde(with = "serde_bytes")]
    pub key: Vec<u8>,
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

// ---------------------------------------------------------------------------
// ProtocolRepository methods
// ---------------------------------------------------------------------------

impl<S: Storage> ProtocolRepository<S> {
    /// Stores a wrapping keypair for a member in a context.
    ///
    /// Both the public and secret key are stored under separate keys.
    /// The secret key buffer is zeroized after writing for defense-in-depth.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::InvalidKeyMaterial`] if `secret_key · G` is not
    /// `public_key` (including an invalid point or scalar); nothing is written
    /// then. Returns another [`StoreError`] if serialization or storage fails.
    pub async fn store_wrapping_keypair(
        &self,
        context_id: &str,
        did: &str,
        public_key: &[u8; 65],
        secret_key: &[u8; 32],
    ) -> Result<(), StoreError> {
        scp_crypto::p256::check_keypair(secret_key, public_key)
            .map_err(|e| StoreError::InvalidKeyMaterial(format!("wrapping keypair: {e}")))?;
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
    /// Returns [`StoreError::InvalidKeyMaterial`] if the stored key is not a
    /// valid 65-byte uncompressed P-256 point (§9.5); another [`StoreError`]
    /// if deserialization fails.
    pub async fn load_wrapping_public_key(
        &self,
        context_id: &str,
        did: &str,
    ) -> Result<Option<[u8; 65]>, StoreError> {
        let path = wrapping_public_key_path(context_id, did)?;
        let stored: Option<StoredWrappingPublicKey> = self.load_value(&path).await?;
        stored
            .map(|v| {
                hpke::validate_uncompressed_point(&v.key).map_err(|e| {
                    StoreError::InvalidKeyMaterial(format!("stored wrapping public key: {e}"))
                })
            })
            .transpose()
    }

    /// Loads the wrapping secret key for a member in a context.
    ///
    /// Returns `None` if no wrapping key is stored.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::InvalidKeyMaterial`] if the stored secret is not
    /// a valid 32-byte P-256 scalar; another [`StoreError`] if
    /// deserialization fails.
    pub async fn load_wrapping_secret_key(
        &self,
        context_id: &str,
        did: &str,
    ) -> Result<Option<Zeroizing<[u8; 32]>>, StoreError> {
        let path = wrapping_secret_key_path(context_id, did)?;
        let stored: Option<StoredWrappingSecretKey> = self.load_value(&path).await?;
        let Some(v) = stored else {
            return Ok(None);
        };
        let arr: Zeroizing<[u8; 32]> =
            Zeroizing::new(v.key.as_slice().try_into().map_err(|_| {
                StoreError::InvalidKeyMaterial(format!(
                    "stored wrapping secret key must be 32 bytes, got {}",
                    v.key.len()
                ))
            })?);
        scp_crypto::p256::P256SigningKey::from_scalar_bytes(&arr).map_err(|e| {
            StoreError::InvalidKeyMaterial(format!("stored wrapping secret key: {e}"))
        })?;
        Ok(Some(arr))
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
    use scp_platform::in_memory::InMemoryStorage;

    use super::*;

    fn test_store() -> ProtocolRepository<InMemoryStorage> {
        ProtocolRepository::new_for_testing(InMemoryStorage::new())
    }

    /// A fresh DHKEM(P-256) wrapping pair: the 65-byte point and its scalar.
    fn pair() -> ([u8; 65], [u8; 32]) {
        let (public, secret) = scp_protocol::crypto::sender_keys::generate_wrapping_keypair();
        (public, *secret)
    }

    #[tokio::test]
    async fn store_and_load_wrapping_keypair() {
        let store = test_store();
        let (pubkey, secret) = pair();

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
            .unwrap()
            .unwrap();
        assert_eq!(*loaded_sec, secret);
    }

    /// A pair whose scalar does not produce the public key is refused with
    /// `InvalidKeyMaterial` and nothing is written (C19(d)).
    #[tokio::test]
    async fn store_rejects_mismatched_pair() {
        let store = test_store();
        let (pubkey, _) = pair();
        let (_, other_secret) = pair();
        let err = store
            .store_wrapping_keypair("ctx-1", "did:dht:alice", &pubkey, &other_secret)
            .await
            .unwrap_err();
        assert!(matches!(err, StoreError::InvalidKeyMaterial(_)), "{err:?}");
        assert_eq!(
            store
                .load_wrapping_public_key("ctx-1", "did:dht:alice")
                .await
                .unwrap(),
            None,
            "nothing is written on a refused pair"
        );
    }

    /// A stored public key that is not a valid 65-byte P-256 point fails to
    /// load with `InvalidKeyMaterial`, never loading as a key: a 32-byte
    /// (X25519-length) key, a `0x02` prefix and an off-curve point.
    #[tokio::test]
    async fn load_rejects_invalid_stored_public_key() {
        let store = test_store();
        let (pubkey, _) = pair();
        let mut prefix02 = pubkey.to_vec();
        prefix02[0] = 0x02;
        let mut off_curve = vec![0u8; 65];
        off_curve[0] = 0x04;
        off_curve[64] = 0x01;
        for (case, key) in [
            ("32 bytes", vec![42u8; 32]),
            ("0x02 prefix", prefix02),
            ("off curve", off_curve),
        ] {
            let path = wrapping_public_key_path("ctx-1", "did:dht:alice").unwrap();
            store
                .store_value(&path, &StoredWrappingPublicKey { key })
                .await
                .unwrap();
            let err = store
                .load_wrapping_public_key("ctx-1", "did:dht:alice")
                .await
                .unwrap_err();
            assert!(
                matches!(err, StoreError::InvalidKeyMaterial(_)),
                "{case}: {err:?}"
            );
        }
    }

    /// A stored secret that is not a valid P-256 scalar (wrong length, zero,
    /// or at least the group order) fails to load with `InvalidKeyMaterial`.
    #[tokio::test]
    async fn load_rejects_invalid_stored_secret_key() {
        let store = test_store();
        for (case, key) in [
            ("16 bytes", vec![1u8; 16]),
            ("zero scalar", vec![0u8; 32]),
            ("all-ones scalar", vec![0xFFu8; 32]),
        ] {
            let path = wrapping_secret_key_path("ctx-1", "did:dht:alice").unwrap();
            store
                .store_value_zeroize(&path, &StoredWrappingSecretKey { key })
                .await
                .unwrap();
            let err = store
                .load_wrapping_secret_key("ctx-1", "did:dht:alice")
                .await
                .unwrap_err();
            assert!(
                matches!(err, StoreError::InvalidKeyMaterial(_)),
                "{case}: {err:?}"
            );
        }
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
        let (pubkey, secret) = pair();

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
                .unwrap()
                .map(|k| *k),
            None
        );
    }

    #[tokio::test]
    async fn different_contexts_are_isolated() {
        let store = test_store();
        let (key1, sec1) = pair();
        let (key2, sec2) = pair();

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
