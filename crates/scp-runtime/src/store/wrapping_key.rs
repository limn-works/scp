//! Durable storage of an identity's DHKEM(P-256) wrapping keypair.
//!
//! One keypair per identity (spec 09 §9.16.1), stored under the key from
//! spec 17 §17.3:
//!
//! ```text
//! wrapping_key/{did}
//! ```
//!
//! The supervisor is the only reader and writer: it loads the pair when an
//! identity's first actor is built and, when none is stored, generates one and
//! stores it once. The functions take the supervisor's storage view
//! ([`OpenMlsStorageAdapter`]), which is the same `Storage` handle the rest of
//! the node persists through, and encode the value with the shared
//! [`scp_platform::store_value`] envelope, so the bytes match what
//! `ProtocolRepository` writes for any other key.
//!
//! Only the 32-byte scalar is stored, in one write; the public point is
//! derived on load by [`WrappingKeyPair::from_secret`]. A store therefore
//! cannot be torn between two halves, and a loaded pair cannot disagree with
//! itself. A stored value that is not a scalar in `[1, n − 1]` fails the load
//! with [`ContextError::CryptoFailed`]; nothing is regenerated over it.

use scp_did::DID;
use scp_protocol::context::ContextError;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

use crate::crypto::mls::storage_adapter::OpenMlsStorageAdapter;
use crate::crypto::wrapping::WrappingKeyPair;

/// Builds the storage key for an identity's wrapping scalar.
///
/// Format: `wrapping_key/{did}`
fn wrapping_key_path(did: &DID) -> Result<String, ContextError> {
    let d = scp_platform::store_value::sanitize_key_component(&did.0)
        .map_err(|e| ContextError::PersistenceFailed(format!("wrapping key path: {e}")))?;
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

/// Stores `pair`'s scalar as the wrapping key of `did`, replacing any stored
/// one. The serialized buffer is zeroized after the write.
///
/// # Errors
///
/// [`ContextError::PersistenceFailed`] if `did` is not a valid key component,
/// or if serialization or the storage write fails.
pub(crate) async fn store_wrapping_key(
    storage: &dyn OpenMlsStorageAdapter,
    did: &DID,
    pair: &WrappingKeyPair,
) -> Result<(), ContextError> {
    let path = wrapping_key_path(did)?;
    let value = StoredWrappingSecretKey {
        key: pair.secret().to_vec(),
    };
    let mut bytes = scp_platform::store_value::to_stored_value_bytes(&value)
        .map_err(|e| ContextError::PersistenceFailed(format!("wrapping key encode: {e}")))?;
    let result = storage
        .store(&path, &bytes)
        .await
        .map_err(|e| ContextError::PersistenceFailed(format!("wrapping key write: {e}")));
    bytes.zeroize();
    result
}

/// Loads the wrapping keypair of `did`, deriving its public point from the
/// stored scalar. Returns `None` if none is stored.
///
/// # Errors
///
/// - [`ContextError::PersistenceFailed`] if the storage read fails or the
///   stored bytes are not a well-formed envelope.
/// - [`ContextError::CryptoFailed`] if the stored value is not a 32-byte
///   P-256 scalar in `[1, n − 1]`.
pub(crate) async fn load_wrapping_key(
    storage: &dyn OpenMlsStorageAdapter,
    did: &DID,
) -> Result<Option<WrappingKeyPair>, ContextError> {
    let path = wrapping_key_path(did)?;
    let Some(mut bytes) = storage
        .retrieve(&path)
        .await
        .map_err(|e| ContextError::PersistenceFailed(format!("wrapping key read: {e}")))?
    else {
        return Ok(None);
    };
    let decoded: Result<StoredWrappingSecretKey, _> =
        scp_platform::store_value::from_stored_value_bytes(&bytes);
    bytes.zeroize();
    let stored = decoded
        .map_err(|e| ContextError::PersistenceFailed(format!("wrapping key decode: {e}")))?;
    let secret: Zeroizing<[u8; 32]> =
        Zeroizing::new(stored.key.as_slice().try_into().map_err(|_| {
            ContextError::CryptoFailed(format!(
                "stored wrapping secret key must be 32 bytes, got {}",
                stored.key.len()
            ))
        })?);
    WrappingKeyPair::from_secret(secret)
        .map(Some)
        .map_err(|e| ContextError::CryptoFailed(format!("stored wrapping secret key: {e}")))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use std::sync::Arc;

    use scp_platform::in_memory::InMemoryStorage;

    use super::*;
    use crate::crypto::mls::storage_adapter::SpawnBlockingStorageAdapter;

    fn adapter() -> SpawnBlockingStorageAdapter<InMemoryStorage> {
        SpawnBlockingStorageAdapter::new(Arc::new(InMemoryStorage::new()))
    }

    fn did(s: &str) -> DID {
        DID(s.to_owned())
    }

    async fn write_raw(storage: &dyn OpenMlsStorageAdapter, d: &DID, key: Vec<u8>) {
        let bytes =
            scp_platform::store_value::to_stored_value_bytes(&StoredWrappingSecretKey { key })
                .unwrap();
        storage
            .store(&wrapping_key_path(d).unwrap(), &bytes)
            .await
            .unwrap();
    }

    /// A stored pair loads back with the same scalar and the same point, and
    /// the store wrote exactly one entry: the scalar under `wrapping_key/{did}`,
    /// in the shared `StoredValue` envelope.
    #[tokio::test]
    async fn store_and_load_round_trips_through_one_scalar_entry() {
        let storage = adapter();
        let alice = did("did:dht:alice");
        let pair = WrappingKeyPair::generate();

        store_wrapping_key(&storage, &alice, &pair).await.unwrap();

        let loaded = load_wrapping_key(&storage, &alice).await.unwrap().unwrap();
        assert_eq!(loaded.public(), pair.public());
        assert_eq!(**loaded.secret(), **pair.secret());

        let path = wrapping_key_path(&alice).unwrap();
        assert_eq!(path, "wrapping_key/did:dht:alice");
        let raw = storage.retrieve(&path).await.unwrap().unwrap();
        let stored: StoredWrappingSecretKey =
            scp_platform::store_value::from_stored_value_bytes(&raw).unwrap();
        assert_eq!(stored.key.as_slice(), pair.secret().as_slice());
    }

    /// A stored value that is not a valid P-256 scalar (wrong length, zero,
    /// or at least the group order) fails to load with `CryptoFailed`, and
    /// bytes that are not an envelope fail with `PersistenceFailed`.
    #[tokio::test]
    async fn load_rejects_invalid_stored_secret_key() {
        let storage = adapter();
        let alice = did("did:dht:alice");
        for (case, key) in [
            ("16 bytes", vec![1u8; 16]),
            ("zero scalar", vec![0u8; 32]),
            ("all-ones scalar", vec![0xFFu8; 32]),
        ] {
            write_raw(&storage, &alice, key).await;
            let err = load_wrapping_key(&storage, &alice).await.unwrap_err();
            assert!(
                matches!(err, ContextError::CryptoFailed(_)),
                "{case}: {err:?}"
            );
        }
        storage
            .store(&wrapping_key_path(&alice).unwrap(), b"not msgpack")
            .await
            .unwrap();
        let err = load_wrapping_key(&storage, &alice).await.unwrap_err();
        assert!(matches!(err, ContextError::PersistenceFailed(_)), "{err:?}");
    }

    #[tokio::test]
    async fn load_returns_none_when_not_stored() {
        let storage = adapter();
        assert!(
            load_wrapping_key(&storage, &did("did:dht:nobody"))
                .await
                .unwrap()
                .is_none()
        );
    }

    /// A DID that is not a valid key component is refused before any I/O.
    #[tokio::test]
    async fn path_traversal_did_is_refused() {
        let storage = adapter();
        let evil = did("../identity/victim");
        let err = load_wrapping_key(&storage, &evil).await.unwrap_err();
        assert!(matches!(err, ContextError::PersistenceFailed(_)), "{err:?}");
        let err = store_wrapping_key(&storage, &evil, &WrappingKeyPair::generate())
            .await
            .unwrap_err();
        assert!(matches!(err, ContextError::PersistenceFailed(_)), "{err:?}");
    }

    #[tokio::test]
    async fn different_identities_are_isolated() {
        let storage = adapter();
        let alice = WrappingKeyPair::generate();
        let bob = WrappingKeyPair::generate();
        store_wrapping_key(&storage, &did("did:dht:alice"), &alice)
            .await
            .unwrap();
        store_wrapping_key(&storage, &did("did:dht:bob"), &bob)
            .await
            .unwrap();
        let got_alice = load_wrapping_key(&storage, &did("did:dht:alice"))
            .await
            .unwrap()
            .unwrap();
        let got_bob = load_wrapping_key(&storage, &did("did:dht:bob"))
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
