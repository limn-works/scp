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
use serde::{Deserialize, Serialize};

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

/// Builds the storage key for a cached DID document.
///
/// Format: `did_cache/{did}`
/// See spec section 17.3.
fn did_cache_key(did: &DID) -> Result<String, super::StoreError> {
    let did_str = super::sanitize_key_component(did.as_ref())?;
    Ok(format!("did_cache/{did_str}"))
}

/// Builds the storage key for a TOFU record.
///
/// Format: `tofu/{did}`
/// See spec section 17.3.
fn tofu_key(did: &DID) -> Result<String, super::StoreError> {
    let did_str = super::sanitize_key_component(did.as_ref())?;
    Ok(format!("tofu/{did_str}"))
}

/// Public-within-store accessor for the TOFU key builder.
///
/// Used by `store::tofu` to avoid duplicating the key convention.
pub(super) fn tofu_key_for_store(did: &DID) -> Result<String, super::StoreError> {
    tofu_key(did)
}

// ---------------------------------------------------------------------------
// DID cache entry
// ---------------------------------------------------------------------------

/// A cached DID document with an expiration timestamp.
///
/// Stored under `did_cache/{did}`. The `expires_at` field is checked
/// on load: if the current time exceeds it, the entry is treated as
/// expired and `None` is returned.
///
/// See spec section 17.4 and SCP-PERSIST-014.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct CachedDidDocument {
    /// The raw DID document bytes.
    doc: Vec<u8>,
    /// Unix timestamp (seconds) when this cache entry expires.
    expires_at: u64,
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
        self.store_value_zeroize(&key, &key_data.to_vec()).await
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
        self.store_value_zeroize(&key, &state.to_vec()).await
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

    // -----------------------------------------------------------------------
    // DID cache methods (SCP-PERSIST-014)
    // -----------------------------------------------------------------------

    /// Caches a DID document with an expiration timestamp.
    ///
    /// Stores the document bytes and expiry under `did_cache/{did}`.
    /// Overwrites any existing cached entry for the same DID.
    ///
    /// See spec section 17.4. See SCP-PERSIST-014.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::SerializationFailed`] if serialization fails.
    /// Returns [`StoreError::Storage`] if the underlying storage write fails.
    pub async fn cache_did_document(
        &self,
        did: &DID,
        doc: &[u8],
        expires_at: u64,
    ) -> Result<(), StoreError> {
        let key = did_cache_key(did)?;
        let entry = CachedDidDocument {
            doc: doc.to_vec(),
            expires_at,
        };
        self.store_value(&key, &entry).await
    }

    /// Loads a cached DID document if it has not expired.
    ///
    /// Returns `None` if no cache entry exists or if `now >= expires_at`.
    /// The caller provides the current time for testability.
    ///
    /// See spec section 17.4. See SCP-PERSIST-014.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::DeserializationFailed`] if deserialization fails.
    /// Returns [`StoreError::Storage`] if the underlying storage read fails.
    pub async fn load_cached_did_document(
        &self,
        did: &DID,
        now: u64,
    ) -> Result<Option<Vec<u8>>, StoreError> {
        let key = did_cache_key(did)?;
        let entry: Option<CachedDidDocument> = self.load_value(&key).await?;
        match entry {
            Some(cached) if now < cached.expires_at => Ok(Some(cached.doc)),
            _ => Ok(None),
        }
    }

    // -----------------------------------------------------------------------
    // TOFU record methods (SCP-PERSIST-014)
    // -----------------------------------------------------------------------

    /// Stores a Trust-On-First-Use (TOFU) record for a DID.
    ///
    /// Serializes the record bytes under `tofu/{did}` wrapped in a
    /// `StoredValue` version envelope.
    ///
    /// See spec section 17.4. See SCP-PERSIST-014.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::SerializationFailed`] if serialization fails.
    /// Returns [`StoreError::Storage`] if the underlying storage write fails.
    pub async fn store_tofu_record(&self, did: &DID, record: &[u8]) -> Result<(), StoreError> {
        let key = tofu_key(did)?;
        self.store_value(&key, &record.to_vec()).await
    }

    /// Loads a TOFU record for a DID.
    ///
    /// Returns `None` if no TOFU record exists for the given DID.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::DeserializationFailed`] if deserialization fails.
    /// Returns [`StoreError::Storage`] if the underlying storage read fails.
    pub async fn load_tofu_record(&self, did: &DID) -> Result<Option<Vec<u8>>, StoreError> {
        let key = tofu_key(did)?;
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

    // -------------------------------------------------------------------
    // DID cache (SCP-PERSIST-014)
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn cache_and_load_did_document_roundtrip() {
        let store = make_store();
        let did = test_did();
        let doc = b"cached-did-document-bytes".to_vec();

        store
            .cache_did_document(&did, &doc, 2_000_000_000)
            .await
            .unwrap();
        // now < expires_at, so document should be returned.
        let loaded = store
            .load_cached_did_document(&did, 1_500_000_000)
            .await
            .unwrap();
        assert_eq!(loaded, Some(doc));
    }

    #[tokio::test]
    async fn cached_did_document_returns_none_when_expired() {
        let store = make_store();
        let did = test_did();

        store
            .cache_did_document(&did, b"doc", 1_000_000_000)
            .await
            .unwrap();
        // now >= expires_at, so None.
        let loaded = store
            .load_cached_did_document(&did, 1_000_000_000)
            .await
            .unwrap();
        assert!(loaded.is_none());

        let loaded = store
            .load_cached_did_document(&did, 1_500_000_000)
            .await
            .unwrap();
        assert!(loaded.is_none());
    }

    #[tokio::test]
    async fn cached_did_document_returns_none_for_missing() {
        let store = make_store();
        let did = test_did();

        let loaded = store
            .load_cached_did_document(&did, 1_000_000_000)
            .await
            .unwrap();
        assert!(loaded.is_none());
    }

    #[tokio::test]
    async fn cache_did_document_overwrites_with_later_expiry() {
        let store = make_store();
        let did = test_did();

        store
            .cache_did_document(&did, b"doc-v1", 1_000_000_000)
            .await
            .unwrap();
        store
            .cache_did_document(&did, b"doc-v2", 3_000_000_000)
            .await
            .unwrap();

        let loaded = store
            .load_cached_did_document(&did, 2_000_000_000)
            .await
            .unwrap();
        assert_eq!(loaded, Some(b"doc-v2".to_vec()));
    }

    // -------------------------------------------------------------------
    // TOFU records (SCP-PERSIST-014)
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn store_and_load_tofu_record_roundtrip() {
        let store = make_store();
        let did = test_did();
        let record = b"tofu-binding-data".to_vec();

        store.store_tofu_record(&did, &record).await.unwrap();
        let loaded = store.load_tofu_record(&did).await.unwrap();
        assert_eq!(loaded, Some(record));
    }

    #[tokio::test]
    async fn load_tofu_record_returns_none_for_missing() {
        let store = make_store();
        let did = test_did();

        let loaded = store.load_tofu_record(&did).await.unwrap();
        assert!(loaded.is_none());
    }

    // -------------------------------------------------------------------
    // Key convention tests
    // -------------------------------------------------------------------

    #[test]
    fn did_cache_key_follows_convention() {
        let did = DID::from("did:dht:z6MkTest");
        assert_eq!(did_cache_key(&did).unwrap(), "did_cache/did:dht:z6MkTest");
    }

    #[test]
    fn tofu_key_follows_convention() {
        let did = DID::from("did:dht:z6MkTest");
        assert_eq!(tofu_key(&did).unwrap(), "tofu/did:dht:z6MkTest");
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
