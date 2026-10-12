//! Durable record of an identity's DHKEM(P-256) wrapping key handle.
//!
//! One wrapping key per identity (spec 09 §9.16.1). The private key lives in
//! the identity's `KeyCustody`; this record holds only the custody's opaque
//! handle and the 65-byte public point, under the key from spec 17 §17.3:
//!
//! ```text
//! wrapping_key/{did}
//! ```
//!
//! The supervisor is the only reader and writer: it reads the record when an
//! identity's first actor is built and, when none is stored, generates a key
//! in custody and stores its record once. The functions take the supervisor's
//! storage view ([`OpenMlsStorageAdapter`]), which is the same `Storage`
//! handle the rest of the node persists through, and encode the value with the
//! shared [`scp_platform::store_value`] envelope, so the bytes match what
//! `ProtocolRepository` writes for any other key.
//!
//! The record is written in one store. A record whose version is not
//! [`RECORD_VERSION`], whose public point is not 65 bytes, or that is not a
//! record at all (an old 32-byte scalar) fails the load with
//! [`ContextError::CryptoFailed`]; nothing is regenerated over it.

use scp_did::DID;
use scp_platform::traits::KeyHandle;
use scp_protocol::context::ContextError;
use serde::{Deserialize, Serialize};

use crate::crypto::mls::storage_adapter::OpenMlsStorageAdapter;

/// The only record version this build reads and writes.
const RECORD_VERSION: u8 = 1;

/// Builds the storage key for an identity's wrapping key record.
///
/// Format: `wrapping_key/{did}`
fn wrapping_key_path(did: &DID) -> Result<String, ContextError> {
    let d = scp_platform::store_value::sanitize_key_component(&did.0)
        .map_err(|e| ContextError::PersistenceFailed(format!("wrapping key path: {e}")))?;
    Ok(format!("wrapping_key/{d}"))
}

/// The stored wrapping key: the custody handle of the private key and its
/// 65-byte uncompressed public point. It carries no key material and no
/// identity; the storage key names the identity.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct StoredWrappingKeyHandle {
    /// The record version, [`RECORD_VERSION`].
    pub v: u8,
    /// The custody handle of the private key.
    pub handle: KeyHandle,
    /// The 65-byte uncompressed public point.
    #[serde(with = "serde_bytes")]
    pub public: Vec<u8>,
}

/// A loaded wrapping key record whose shape has been checked. `Debug` prints
/// only the public point; the handle stays out of logs.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct WrappingKeyRecord {
    /// The custody handle of the private key.
    pub handle: KeyHandle,
    /// The 65-byte uncompressed public point.
    pub public: [u8; 65],
}

impl std::fmt::Debug for WrappingKeyRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WrappingKeyRecord")
            .field("public", &hex::encode(self.public))
            .finish_non_exhaustive()
    }
}

/// Stores `handle` and `public` as the wrapping key record of `did`,
/// replacing any stored one.
///
/// # Errors
///
/// [`ContextError::PersistenceFailed`] if `did` is not a valid key component,
/// or if serialization or the storage write fails.
pub(crate) async fn store_wrapping_key_handle(
    storage: &dyn OpenMlsStorageAdapter,
    did: &DID,
    handle: &KeyHandle,
    public: &[u8; 65],
) -> Result<(), ContextError> {
    let path = wrapping_key_path(did)?;
    let value = StoredWrappingKeyHandle {
        v: RECORD_VERSION,
        handle: *handle,
        public: public.to_vec(),
    };
    let bytes = scp_platform::store_value::to_stored_value_bytes(&value)
        .map_err(|e| ContextError::PersistenceFailed(format!("wrapping key encode: {e}")))?;
    storage
        .store(&path, &bytes)
        .await
        .map_err(|e| ContextError::PersistenceFailed(format!("wrapping key write: {e}")))
}

/// Loads the wrapping key record of `did`. Returns `None` if none is stored.
///
/// # Errors
///
/// - [`ContextError::PersistenceFailed`] if `did` is not a valid key
///   component or the storage read fails.
/// - [`ContextError::CryptoFailed`] if the stored bytes are not a version-1
///   record with a 65-byte public point, including bytes that are no record
///   at all and the old 32-byte scalar record.
pub(crate) async fn load_wrapping_key_handle(
    storage: &dyn OpenMlsStorageAdapter,
    did: &DID,
) -> Result<Option<WrappingKeyRecord>, ContextError> {
    let path = wrapping_key_path(did)?;
    let Some(bytes) = storage
        .retrieve(&path)
        .await
        .map_err(|e| ContextError::PersistenceFailed(format!("wrapping key read: {e}")))?
    else {
        return Ok(None);
    };
    let stored: StoredWrappingKeyHandle =
        scp_platform::store_value::from_stored_value_bytes(&bytes).map_err(|e| {
            ContextError::CryptoFailed(format!("stored wrapping key is not a handle record: {e}"))
        })?;
    if stored.v != RECORD_VERSION {
        return Err(ContextError::CryptoFailed(format!(
            "stored wrapping key record version {} is not {RECORD_VERSION}",
            stored.v
        )));
    }
    let public: [u8; 65] = stored.public.as_slice().try_into().map_err(|_| {
        ContextError::CryptoFailed(format!(
            "stored wrapping public key must be 65 bytes, got {}",
            stored.public.len()
        ))
    })?;
    Ok(Some(WrappingKeyRecord {
        handle: stored.handle,
        public,
    }))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use std::sync::Arc;

    use scp_platform::in_memory::InMemoryStorage;
    use scp_platform::traits::Storage as _;

    use super::*;
    use crate::crypto::mls::storage_adapter::SpawnBlockingStorageAdapter;

    fn adapter() -> SpawnBlockingStorageAdapter<InMemoryStorage> {
        SpawnBlockingStorageAdapter::new(Arc::new(InMemoryStorage::new()))
    }

    fn did(s: &str) -> DID {
        DID(s.to_owned())
    }

    fn public(fill: u8) -> [u8; 65] {
        let mut p = [fill; 65];
        p[0] = 0x04;
        p
    }

    async fn write_raw<T: Serialize + Sync>(
        storage: &dyn OpenMlsStorageAdapter,
        d: &DID,
        value: &T,
    ) {
        let bytes = scp_platform::store_value::to_stored_value_bytes(value).unwrap();
        storage
            .store(&wrapping_key_path(d).unwrap(), &bytes)
            .await
            .unwrap();
    }

    /// A stored record loads back with the same handle and public point, and
    /// the store wrote exactly one entry: the version-1 handle record under
    /// `wrapping_key/{did}`, in the shared `StoredValue` envelope, with no
    /// key material in it.
    #[tokio::test]
    async fn store_and_load_round_trips_through_one_handle_entry() {
        let storage = adapter();
        let alice = did("did:dht:alice");
        let handle = KeyHandle::new(7);

        store_wrapping_key_handle(&storage, &alice, &handle, &public(0x11))
            .await
            .unwrap();

        let loaded = load_wrapping_key_handle(&storage, &alice)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            loaded,
            WrappingKeyRecord {
                handle,
                public: public(0x11)
            }
        );

        let path = wrapping_key_path(&alice).unwrap();
        assert_eq!(path, "wrapping_key/did:dht:alice");
        let raw = storage.retrieve(&path).await.unwrap().unwrap();
        let stored: StoredWrappingKeyHandle =
            scp_platform::store_value::from_stored_value_bytes(&raw).unwrap();
        assert!(
            stored
                == StoredWrappingKeyHandle {
                    v: RECORD_VERSION,
                    handle,
                    public: public(0x11).to_vec(),
                }
        );
        let entries = storage.inner().list_keys("").await.unwrap();
        assert_eq!(entries, vec![path], "exactly one entry is written");
    }

    /// The scalar record of earlier builds, a record of another version, a
    /// public point that is not 65 bytes, and bytes that are no record all
    /// fail with `CryptoFailed`.
    #[tokio::test]
    async fn load_rejects_records_that_are_not_version_1_handles() {
        #[derive(Serialize)]
        struct OldScalarRecord {
            #[serde(with = "serde_bytes")]
            key: Vec<u8>,
        }
        let storage = adapter();
        let alice = did("did:dht:alice");

        write_raw(&storage, &alice, &OldScalarRecord { key: vec![1; 32] }).await;
        let err = load_wrapping_key_handle(&storage, &alice)
            .await
            .unwrap_err();
        assert!(
            matches!(err, ContextError::CryptoFailed(_)),
            "old scalar: {err:?}"
        );

        for (case, record) in [
            (
                "version 2",
                StoredWrappingKeyHandle {
                    v: 2,
                    handle: KeyHandle::new(1),
                    public: public(0x22).to_vec(),
                },
            ),
            (
                "64-byte public",
                StoredWrappingKeyHandle {
                    v: RECORD_VERSION,
                    handle: KeyHandle::new(1),
                    public: vec![4; 64],
                },
            ),
        ] {
            write_raw(&storage, &alice, &record).await;
            let err = load_wrapping_key_handle(&storage, &alice)
                .await
                .unwrap_err();
            assert!(
                matches!(err, ContextError::CryptoFailed(_)),
                "{case}: {err:?}"
            );
        }

        storage
            .store(&wrapping_key_path(&alice).unwrap(), b"not msgpack")
            .await
            .unwrap();
        let err = load_wrapping_key_handle(&storage, &alice)
            .await
            .unwrap_err();
        assert!(matches!(err, ContextError::CryptoFailed(_)), "{err:?}");
    }

    #[tokio::test]
    async fn load_returns_none_when_not_stored() {
        let storage = adapter();
        assert!(
            load_wrapping_key_handle(&storage, &did("did:dht:nobody"))
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
        let err = load_wrapping_key_handle(&storage, &evil).await.unwrap_err();
        assert!(matches!(err, ContextError::PersistenceFailed(_)), "{err:?}");
        let err = store_wrapping_key_handle(&storage, &evil, &KeyHandle::new(1), &public(1))
            .await
            .unwrap_err();
        assert!(matches!(err, ContextError::PersistenceFailed(_)), "{err:?}");
        assert!(storage.inner().list_keys("").await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn different_identities_are_isolated() {
        let storage = adapter();
        store_wrapping_key_handle(
            &storage,
            &did("did:dht:alice"),
            &KeyHandle::new(1),
            &public(1),
        )
        .await
        .unwrap();
        store_wrapping_key_handle(
            &storage,
            &did("did:dht:bob"),
            &KeyHandle::new(2),
            &public(2),
        )
        .await
        .unwrap();
        let got_alice = load_wrapping_key_handle(&storage, &did("did:dht:alice"))
            .await
            .unwrap()
            .unwrap();
        let got_bob = load_wrapping_key_handle(&storage, &did("did:dht:bob"))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            (got_alice.handle, got_alice.public),
            (KeyHandle::new(1), public(1))
        );
        assert_eq!(
            (got_bob.handle, got_bob.public),
            (KeyHandle::new(2), public(2))
        );
    }

    /// `Debug` prints the public point and not the handle.
    #[test]
    fn record_debug_hides_the_handle() {
        let record = WrappingKeyRecord {
            handle: KeyHandle::new(0xDEAD_BEEF),
            public: public(0x33),
        };
        let debug = format!("{record:?}");
        assert!(debug.contains(&hex::encode(public(0x33))), "{debug}");
        assert!(!debug.contains("handle"), "{debug}");
        assert!(!debug.contains(&0xDEAD_BEEF_u64.to_string()), "{debug}");
    }
}
