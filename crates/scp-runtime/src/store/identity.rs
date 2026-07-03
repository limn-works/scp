//! Identity storage operations for `ProtocolRepository`.
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

use scp_did::DID;

use scp_protocol::identity::block_list::{BlockListEvent, BlockListState};

use super::{ProtocolRepository, StoreError};

// ---------------------------------------------------------------------------
// Key helpers
// ---------------------------------------------------------------------------

/// Builds the storage key for an identity document.
///
/// Format: `identity/{did}/document`
/// See spec section 17.3.
///
/// Delegates to the shared `store_value` key builder so this path and the
/// standalone `Identity::create` persistence path address the identical slot.
fn identity_document_key(did: &DID) -> Result<String, super::StoreError> {
    Ok(scp_platform::store_value::identity_document_key(
        did.as_ref(),
    )?)
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

/// Builds the storage key for the block list event log.
///
/// Format: `identity/{did}/block_list_events`
/// See spec §3.7.1.
fn block_list_events_key(did: &DID) -> Result<String, super::StoreError> {
    let did_str = super::sanitize_key_component(did.as_ref())?;
    Ok(format!("identity/{did_str}/block_list_events"))
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
// ProtocolRepository — identity methods
// ---------------------------------------------------------------------------

impl<S: Storage> ProtocolRepository<S> {
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

    // -----------------------------------------------------------------------
    // Block list methods (SCP-CAC-001, spec §3.7.1)
    // -----------------------------------------------------------------------

    /// Appends a block list event to the identity's event log.
    ///
    /// Events are persisted as an append-only log under identity private
    /// state. Current block list state is derived by replaying the log.
    ///
    /// See spec §3.7.1.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::SerializationFailed`] if serialization fails.
    /// Returns [`StoreError::Storage`] if the underlying storage write fails.
    pub async fn append_block_list_event(
        &self,
        did: &DID,
        event: &BlockListEvent,
    ) -> Result<(), StoreError> {
        let key = block_list_events_key(did)?;
        let mut events: Vec<BlockListEvent> = self.load_value(&key).await?.unwrap_or_default();
        events.push(event.clone());
        self.store_value(&key, &events).await
    }

    /// Loads the full block list event log for an identity.
    ///
    /// Returns an empty `Vec` if no events have been recorded.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::DeserializationFailed`] if deserialization fails.
    /// Returns [`StoreError::Storage`] if the underlying storage read fails.
    pub async fn load_block_list_events(
        &self,
        did: &DID,
    ) -> Result<Vec<BlockListEvent>, StoreError> {
        let key = block_list_events_key(did)?;
        Ok(self.load_value(&key).await?.unwrap_or_default())
    }

    /// Returns all globally blocked DIDs for an identity (Tier 2).
    ///
    /// Derives state by replaying the identity's block list event log.
    ///
    /// See spec §3.7.1.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] if the event log cannot be loaded.
    pub async fn get_global_block_list(&self, did: &DID) -> Result<Vec<DID>, StoreError> {
        let events = self.load_block_list_events(did).await?;
        let state = BlockListState::from_events(&events);
        Ok(state.global_block_list())
    }

    /// Returns whether a target DID is globally blocked by a blocker (Tier 2).
    ///
    /// Derives state by replaying the blocker's block list event log.
    ///
    /// See spec §3.7.1.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] if the event log cannot be loaded.
    pub async fn is_globally_blocked(
        &self,
        blocker: &DID,
        target: &DID,
    ) -> Result<bool, StoreError> {
        let events = self.load_block_list_events(blocker).await?;
        let state = BlockListState::from_events(&events);
        Ok(state.is_globally_blocked(target))
    }

    /// Returns all DIDs blocked in a specific context by an identity (Tier 1).
    ///
    /// Derives state by replaying the identity's block list event log
    /// and filtering for the given context.
    ///
    /// See spec §3.7.1.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] if the event log cannot be loaded.
    pub async fn get_context_block_list(
        &self,
        did: &DID,
        context_id: &str,
    ) -> Result<Vec<DID>, StoreError> {
        let events = self.load_block_list_events(did).await?;
        let state = BlockListState::from_events(&events);
        Ok(state.context_block_list(context_id))
    }

    /// Returns whether a target DID is blocked in a specific context (Tier 1).
    ///
    /// Derives state by replaying the blocker's block list event log
    /// and checking the given context.
    ///
    /// See spec §3.7.1.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] if the event log cannot be loaded.
    pub async fn is_blocked_in_context(
        &self,
        blocker: &DID,
        target: &DID,
        context_id: &str,
    ) -> Result<bool, StoreError> {
        let events = self.load_block_list_events(blocker).await?;
        let state = BlockListState::from_events(&events);
        Ok(state.is_blocked_in_context(target, context_id))
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

    fn make_store() -> ProtocolRepository<InMemoryStorage> {
        ProtocolRepository::new_for_testing(InMemoryStorage::new())
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

    #[test]
    fn block_list_events_key_follows_convention() {
        let did = DID::from("did:dht:z6MkTest");
        assert_eq!(
            block_list_events_key(&did).unwrap(),
            "identity/did:dht:z6MkTest/block_list_events"
        );
    }

    // -------------------------------------------------------------------
    // Block list persistence (SCP-CAC-001, spec §3.7.1)
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn append_and_load_block_list_events_roundtrip() {
        let store = make_store();
        let did = test_did();

        store
            .append_block_list_event(
                &did,
                &BlockListEvent::BlockDID {
                    target_did: DID::from("did:dht:z6MkDave"),
                    timestamp: 1000,
                },
            )
            .await
            .unwrap();

        store
            .append_block_list_event(
                &did,
                &BlockListEvent::BlockDIDInContext {
                    target_did: DID::from("did:dht:z6MkEve"),
                    context_id: "ctx-1".to_owned(),
                    timestamp: 2000,
                },
            )
            .await
            .unwrap();

        let events = store.load_block_list_events(&did).await.unwrap();
        assert_eq!(events.len(), 2);
    }

    #[tokio::test]
    async fn load_block_list_events_returns_empty_for_missing() {
        let store = make_store();
        let did = test_did();
        let events = store.load_block_list_events(&did).await.unwrap();
        assert!(events.is_empty());
    }

    #[tokio::test]
    async fn get_global_block_list_derives_from_events() {
        let store = make_store();
        let did = test_did();
        let dave = DID::from("did:dht:z6MkDave");
        let eve = DID::from("did:dht:z6MkEve");

        store
            .append_block_list_event(
                &did,
                &BlockListEvent::BlockDID {
                    target_did: dave.clone(),
                    timestamp: 1000,
                },
            )
            .await
            .unwrap();
        store
            .append_block_list_event(
                &did,
                &BlockListEvent::BlockDID {
                    target_did: eve.clone(),
                    timestamp: 2000,
                },
            )
            .await
            .unwrap();

        let mut blocked = store.get_global_block_list(&did).await.unwrap();
        blocked.sort();
        assert_eq!(blocked.len(), 2);
        assert!(blocked.contains(&dave));
        assert!(blocked.contains(&eve));
    }

    #[tokio::test]
    async fn is_globally_blocked_returns_correct_state() {
        let store = make_store();
        let did = test_did();
        let dave = DID::from("did:dht:z6MkDave");
        let eve = DID::from("did:dht:z6MkEve");

        store
            .append_block_list_event(
                &did,
                &BlockListEvent::BlockDID {
                    target_did: dave.clone(),
                    timestamp: 1000,
                },
            )
            .await
            .unwrap();

        assert!(store.is_globally_blocked(&did, &dave).await.unwrap());
        assert!(!store.is_globally_blocked(&did, &eve).await.unwrap());
    }

    #[tokio::test]
    async fn global_block_then_unblock_lifecycle() {
        let store = make_store();
        let did = test_did();
        let dave = DID::from("did:dht:z6MkDave");

        store
            .append_block_list_event(
                &did,
                &BlockListEvent::BlockDID {
                    target_did: dave.clone(),
                    timestamp: 1000,
                },
            )
            .await
            .unwrap();
        assert!(store.is_globally_blocked(&did, &dave).await.unwrap());

        store
            .append_block_list_event(
                &did,
                &BlockListEvent::UnblockDID {
                    target_did: dave.clone(),
                    timestamp: 2000,
                },
            )
            .await
            .unwrap();
        assert!(!store.is_globally_blocked(&did, &dave).await.unwrap());
        assert!(store.get_global_block_list(&did).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn get_context_block_list_derives_from_events() {
        let store = make_store();
        let did = test_did();
        let dave = DID::from("did:dht:z6MkDave");

        store
            .append_block_list_event(
                &did,
                &BlockListEvent::BlockDIDInContext {
                    target_did: dave.clone(),
                    context_id: "ctx-1".to_owned(),
                    timestamp: 1000,
                },
            )
            .await
            .unwrap();

        let blocked = store.get_context_block_list(&did, "ctx-1").await.unwrap();
        assert_eq!(blocked, vec![dave.clone()]);

        // Different context returns empty.
        let blocked = store.get_context_block_list(&did, "ctx-2").await.unwrap();
        assert!(blocked.is_empty());
    }

    #[tokio::test]
    async fn is_blocked_in_context_returns_correct_state() {
        let store = make_store();
        let did = test_did();
        let dave = DID::from("did:dht:z6MkDave");

        store
            .append_block_list_event(
                &did,
                &BlockListEvent::BlockDIDInContext {
                    target_did: dave.clone(),
                    context_id: "ctx-1".to_owned(),
                    timestamp: 1000,
                },
            )
            .await
            .unwrap();

        assert!(
            store
                .is_blocked_in_context(&did, &dave, "ctx-1")
                .await
                .unwrap()
        );
        assert!(
            !store
                .is_blocked_in_context(&did, &dave, "ctx-2")
                .await
                .unwrap()
        );
    }

    #[tokio::test]
    async fn context_block_then_unblock_lifecycle() {
        let store = make_store();
        let did = test_did();
        let dave = DID::from("did:dht:z6MkDave");

        store
            .append_block_list_event(
                &did,
                &BlockListEvent::BlockDIDInContext {
                    target_did: dave.clone(),
                    context_id: "ctx-1".to_owned(),
                    timestamp: 1000,
                },
            )
            .await
            .unwrap();
        assert!(
            store
                .is_blocked_in_context(&did, &dave, "ctx-1")
                .await
                .unwrap()
        );

        store
            .append_block_list_event(
                &did,
                &BlockListEvent::UnblockDIDInContext {
                    target_did: dave.clone(),
                    context_id: "ctx-1".to_owned(),
                    timestamp: 2000,
                },
            )
            .await
            .unwrap();
        assert!(
            !store
                .is_blocked_in_context(&did, &dave, "ctx-1")
                .await
                .unwrap()
        );
    }

    #[tokio::test]
    async fn delete_identity_removes_block_list_events() {
        let store = make_store();
        let did = test_did();

        store
            .append_block_list_event(
                &did,
                &BlockListEvent::BlockDID {
                    target_did: DID::from("did:dht:z6MkDave"),
                    timestamp: 1000,
                },
            )
            .await
            .unwrap();

        store.delete_identity(&did).await.unwrap();

        let events = store.load_block_list_events(&did).await.unwrap();
        assert!(events.is_empty());
    }

    #[tokio::test]
    async fn block_list_commutativity_via_store() {
        // Verify that appending events in different orders produces the
        // same derived state when queried through ProtocolRepository.
        let store_a = make_store();
        let store_b = make_store();
        let did = test_did();
        let dave = DID::from("did:dht:z6MkDave");
        let eve = DID::from("did:dht:z6MkEve");

        // Store A: block Dave then Eve
        store_a
            .append_block_list_event(
                &did,
                &BlockListEvent::BlockDID {
                    target_did: dave.clone(),
                    timestamp: 1000,
                },
            )
            .await
            .unwrap();
        store_a
            .append_block_list_event(
                &did,
                &BlockListEvent::BlockDID {
                    target_did: eve.clone(),
                    timestamp: 2000,
                },
            )
            .await
            .unwrap();

        // Store B: block Eve then Dave
        store_b
            .append_block_list_event(
                &did,
                &BlockListEvent::BlockDID {
                    target_did: eve.clone(),
                    timestamp: 2000,
                },
            )
            .await
            .unwrap();
        store_b
            .append_block_list_event(
                &did,
                &BlockListEvent::BlockDID {
                    target_did: dave.clone(),
                    timestamp: 1000,
                },
            )
            .await
            .unwrap();

        let mut list_a = store_a.get_global_block_list(&did).await.unwrap();
        let mut list_b = store_b.get_global_block_list(&did).await.unwrap();
        list_a.sort();
        list_b.sort();
        assert_eq!(list_a, list_b);
    }
}
