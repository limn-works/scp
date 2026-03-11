//! TOFU (Trust On First Use) storage operations for `ProtocolStore`.
//!
//! Provides typed persistence for [`TofuRecord`] values under the
//! `tofu/{did}` key namespace. Wraps the raw byte-level `store_tofu_record`
//! / `load_tofu_record` methods from `store::identity` with
//! `MessagePack` serialization of the strongly-typed [`TofuRecord`].
//!
//! # Key Convention
//!
//! ```text
//! tofu/{did}
//! ```
//!
//! See spec section 17.3 and §9.11 (Key Continuity Verification).

use scp_identity::DID;
use scp_platform::traits::Storage;

use crate::crypto::tofu::TofuRecord;

use super::{ProtocolStore, StoreError};

impl<S: Storage> ProtocolStore<S> {
    /// Stores a typed [`TofuRecord`] for a DID.
    ///
    /// Serializes the record via `MessagePack` wrapped in a `StoredValue`
    /// version envelope and writes it under `tofu/{did}`.
    ///
    /// See spec section 9.11.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::SerializationFailed`] if serialization fails.
    /// Returns [`StoreError::Storage`] if the underlying storage write fails.
    pub async fn store_typed_tofu_record(
        &self,
        did: &DID,
        record: &TofuRecord,
    ) -> Result<(), StoreError> {
        let key = super::identity::tofu_key_for_store(did)?;
        self.store_value(&key, record).await
    }

    /// Loads a typed [`TofuRecord`] for a DID.
    ///
    /// Returns `None` if no TOFU record exists for the given DID.
    ///
    /// See spec section 9.11.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::DeserializationFailed`] if deserialization fails.
    /// Returns [`StoreError::Storage`] if the underlying storage read fails.
    pub async fn load_typed_tofu_record(
        &self,
        did: &DID,
    ) -> Result<Option<TofuRecord>, StoreError> {
        let key = super::identity::tofu_key_for_store(did)?;
        self.load_value(&key).await
    }

    /// Deletes the TOFU record for a DID.
    ///
    /// Used when the user explicitly resets trust for a contact.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Storage`] if the underlying storage operation fails.
    pub async fn delete_tofu_record(&self, did: &DID) -> Result<(), StoreError> {
        let key = super::identity::tofu_key_for_store(did)?;
        self.storage.delete(&key).await?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use scp_platform::testing::InMemoryStorage;

    use crate::crypto::tofu::{ObservedKeys, create_tofu_record};
    use crate::store::ProtocolStore;

    fn test_did() -> scp_identity::DID {
        scp_identity::DID::from("did:dht:z6MkTofuTest")
    }

    fn make_store() -> ProtocolStore<InMemoryStorage> {
        ProtocolStore::new_for_testing(InMemoryStorage::new())
    }

    fn sample_keys() -> ObservedKeys {
        ObservedKeys {
            identity_key: [1u8; 32],
            active_key: [2u8; 32],
            agent_key: Some([3u8; 32]),
        }
    }

    #[tokio::test]
    async fn store_and_load_typed_tofu_record_roundtrip() {
        let store = make_store();
        let did = test_did();
        let record = create_tofu_record(&sample_keys(), 1000);

        store.store_typed_tofu_record(&did, &record).await.unwrap();
        let loaded = store.load_typed_tofu_record(&did).await.unwrap();
        assert_eq!(loaded, Some(record));
    }

    #[tokio::test]
    async fn load_typed_tofu_record_returns_none_for_missing() {
        let store = make_store();
        let did = test_did();

        let loaded = store.load_typed_tofu_record(&did).await.unwrap();
        assert!(loaded.is_none());
    }

    #[tokio::test]
    async fn delete_tofu_record_removes_stored_data() {
        let store = make_store();
        let did = test_did();
        let record = create_tofu_record(&sample_keys(), 1000);

        store.store_typed_tofu_record(&did, &record).await.unwrap();
        assert!(store.load_typed_tofu_record(&did).await.unwrap().is_some());

        store.delete_tofu_record(&did).await.unwrap();
        assert!(store.load_typed_tofu_record(&did).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn overwrite_tofu_record() {
        let store = make_store();
        let did = test_did();

        let record_v1 = create_tofu_record(&sample_keys(), 1000);
        store
            .store_typed_tofu_record(&did, &record_v1)
            .await
            .unwrap();

        let new_keys = ObservedKeys {
            identity_key: [10u8; 32],
            active_key: [20u8; 32],
            agent_key: None,
        };
        let record_v2 = create_tofu_record(&new_keys, 2000);
        store
            .store_typed_tofu_record(&did, &record_v2)
            .await
            .unwrap();

        let loaded = store.load_typed_tofu_record(&did).await.unwrap();
        assert_eq!(loaded, Some(record_v2));
    }
}
