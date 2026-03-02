//! Identity storage operations for `ProtocolStore`.
//!
//! Implements identity state CRUD following the key convention from
//! spec section 17.3:
//!
//! ```text
//! identity/{did}/document
//! identity/{did}/active_signing_key
//! identity/{did}/private_state/{seq:020d}
//! ```
//!
//! See spec sections 17.3 and 17.4.

use scp_platform::traits::Storage;

use scp_identity::DID;

use super::{ProtocolStore, StoreError};

// ---------------------------------------------------------------------------
// Key helpers
// ---------------------------------------------------------------------------

/// Builds the storage key for an identity document.
///
/// Format: `identity/{did}/document`
/// See spec section 17.3.
fn identity_document_key(did: &DID) -> Result<String, super::StoreError> {
    let did_str = super::sanitize_key_component(did.as_ref())?;
    Ok(format!("identity/{did_str}/document"))
}

/// Builds the storage key for the active signing key handle.
///
/// Format: `identity/{did}/active_signing_key`
/// See spec section 17.3.
fn active_signing_key_key(did: &DID) -> Result<String, super::StoreError> {
    let did_str = super::sanitize_key_component(did.as_ref())?;
    Ok(format!("identity/{did_str}/active_signing_key"))
}

/// Builds the storage key for identity private state at a sequence number.
///
/// Format: `identity/{did}/private_state/{seq:020d}`
/// Uses 20-digit zero-padding for lexicographic ordering.
/// See spec section 17.3.
fn identity_private_state_key(did: &DID, seq: u64) -> Result<String, super::StoreError> {
    let did_str = super::sanitize_key_component(did.as_ref())?;
    Ok(format!("identity/{did_str}/private_state/{seq:020}"))
}

/// Builds the prefix for listing all identity keys.
///
/// Format: `identity/{did}/`
fn identity_prefix(did: &DID) -> Result<String, super::StoreError> {
    let did_str = super::sanitize_key_component(did.as_ref())?;
    Ok(format!("identity/{did_str}/"))
}

// ---------------------------------------------------------------------------
// ProtocolStore — identity methods
// ---------------------------------------------------------------------------

impl<S: Storage> ProtocolStore<S> {
    /// Stores an identity's DID document.
    ///
    /// Serializes the document bytes under `identity/{did}/document` wrapped
    /// in a `StoredValue` version envelope.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::SerializationFailed`] if serialization fails.
    /// Returns [`StoreError::Storage`] if the underlying storage write fails.
    pub async fn store_identity_document(&self, did: &DID, doc: &[u8]) -> Result<(), StoreError> {
        let key = identity_document_key(did)?;
        self.store_value(&key, &doc.to_vec()).await
    }

    /// Loads an identity's DID document.
    ///
    /// Returns `None` if no document exists for the given DID.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::DeserializationFailed`] if deserialization fails.
    /// Returns [`StoreError::Storage`] if the underlying storage read fails.
    pub async fn load_identity_document(&self, did: &DID) -> Result<Option<Vec<u8>>, StoreError> {
        let key = identity_document_key(did)?;
        self.load_value(&key).await
    }

    /// Stores the active signing key handle for an identity.
    ///
    /// The key handle is serialized as bytes under
    /// `identity/{did}/active_signing_key`.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::SerializationFailed`] if serialization fails.
    /// Returns [`StoreError::Storage`] if the underlying storage write fails.
    pub async fn store_active_signing_key(
        &self,
        did: &DID,
        key_data: &[u8],
    ) -> Result<(), StoreError> {
        let key = active_signing_key_key(did)?;
        self.store_value(&key, &key_data.to_vec()).await
    }

    /// Loads the active signing key handle for an identity.
    ///
    /// Returns `None` if no signing key is stored for the given DID.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::DeserializationFailed`] if deserialization fails.
    /// Returns [`StoreError::Storage`] if the underlying storage read fails.
    pub async fn load_active_signing_key(&self, did: &DID) -> Result<Option<Vec<u8>>, StoreError> {
        let key = active_signing_key_key(did)?;
        self.load_value(&key).await
    }

    /// Stores identity private state at a given sequence number.
    ///
    /// Uses 20-digit zero-padded sequence numbers for lexicographic ordering.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::SerializationFailed`] if serialization fails.
    /// Returns [`StoreError::Storage`] if the underlying storage write fails.
    pub async fn store_identity_private_state(
        &self,
        did: &DID,
        seq: u64,
        state: &[u8],
    ) -> Result<(), StoreError> {
        let key = identity_private_state_key(did, seq)?;
        self.store_value(&key, &state.to_vec()).await
    }

    /// Loads identity private state at a given sequence number.
    ///
    /// Returns `None` if no state exists at the given sequence.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::DeserializationFailed`] if deserialization fails.
    /// Returns [`StoreError::Storage`] if the underlying storage read fails.
    pub async fn load_identity_private_state(
        &self,
        did: &DID,
        seq: u64,
    ) -> Result<Option<Vec<u8>>, StoreError> {
        let key = identity_private_state_key(did, seq)?;
        self.load_value(&key).await
    }

    /// Deletes all stored state for an identity.
    ///
    /// Removes all keys under `identity/{did}/` including document,
    /// signing key, and private state entries. Returns the number of
    /// keys deleted.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Storage`] if the underlying storage operation fails.
    pub async fn delete_identity(&self, did: &DID) -> Result<u64, StoreError> {
        let prefix = identity_prefix(did)?;
        Ok(self.storage.delete_prefix(&prefix).await?)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use scp_platform::testing::InMemoryStorage;

    use super::*;

    fn test_did() -> DID {
        DID::from("did:dht:z6MkTestIdentity")
    }

    fn make_store() -> ProtocolStore<InMemoryStorage> {
        ProtocolStore::new(InMemoryStorage::new())
    }

    #[tokio::test]
    async fn store_and_load_identity_document_roundtrip() {
        let store = make_store();
        let did = test_did();
        let doc = b"mock-did-document-bytes".to_vec();

        store.store_identity_document(&did, &doc).await.unwrap();
        let loaded = store.load_identity_document(&did).await.unwrap();
        assert_eq!(loaded, Some(doc));
    }

    #[tokio::test]
    async fn load_identity_document_returns_none_for_missing() {
        let store = make_store();
        let did = test_did();

        let loaded = store.load_identity_document(&did).await.unwrap();
        assert!(loaded.is_none());
    }

    #[tokio::test]
    async fn store_and_load_active_signing_key_roundtrip() {
        let store = make_store();
        let did = test_did();
        let key_data = vec![0xAB, 0xCD, 0xEF];

        store
            .store_active_signing_key(&did, &key_data)
            .await
            .unwrap();
        let loaded = store.load_active_signing_key(&did).await.unwrap();
        assert_eq!(loaded, Some(key_data));
    }

    #[tokio::test]
    async fn store_and_load_identity_private_state_roundtrip() {
        let store = make_store();
        let did = test_did();
        let state = b"private-state-data".to_vec();

        store
            .store_identity_private_state(&did, 42, &state)
            .await
            .unwrap();
        let loaded = store.load_identity_private_state(&did, 42).await.unwrap();
        assert_eq!(loaded, Some(state));
    }

    #[tokio::test]
    async fn load_identity_private_state_returns_none_for_missing_seq() {
        let store = make_store();
        let did = test_did();

        store
            .store_identity_private_state(&did, 1, b"data")
            .await
            .unwrap();
        let loaded = store.load_identity_private_state(&did, 99).await.unwrap();
        assert!(loaded.is_none());
    }

    #[tokio::test]
    async fn delete_identity_removes_all_state() {
        let store = make_store();
        let did = test_did();

        store.store_identity_document(&did, b"doc").await.unwrap();
        store.store_active_signing_key(&did, b"key").await.unwrap();
        store
            .store_identity_private_state(&did, 0, b"state")
            .await
            .unwrap();

        let deleted = store.delete_identity(&did).await.unwrap();
        assert!(deleted >= 3);

        assert!(store.load_identity_document(&did).await.unwrap().is_none());
        assert!(store.load_active_signing_key(&did).await.unwrap().is_none());
        assert!(
            store
                .load_identity_private_state(&did, 0)
                .await
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn identity_document_key_follows_convention() {
        let did = DID::from("did:dht:z6MkTest");
        assert_eq!(
            identity_document_key(&did).unwrap(),
            "identity/did:dht:z6MkTest/document"
        );
    }

    #[test]
    fn active_signing_key_key_follows_convention() {
        let did = DID::from("did:dht:z6MkTest");
        assert_eq!(
            active_signing_key_key(&did).unwrap(),
            "identity/did:dht:z6MkTest/active_signing_key"
        );
    }

    #[test]
    fn identity_private_state_key_uses_zero_padding() {
        let did = DID::from("did:dht:z6MkTest");
        assert_eq!(
            identity_private_state_key(&did, 42).unwrap(),
            "identity/did:dht:z6MkTest/private_state/00000000000000000042"
        );
    }
}
