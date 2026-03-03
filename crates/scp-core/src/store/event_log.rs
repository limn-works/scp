//! Event log storage operations for `ProtocolStore`.
//!
//! Implements event log persistence following the key convention from
//! spec section 17.3:
//!
//! ```text
//! context/{context_id}/event/{seq:020d}
//! context/{context_id}/event_meta/count
//! context/{context_id}/event_meta/root
//! context/{context_id}/event_tree/{level}/{index}
//! ```
//!
//! Event sequence numbers use 20-digit zero-padding for lexicographic
//! ordering, enabling efficient range queries via `list_keys`.
//!
//! See spec sections 17.3, 17.4, and ADR-011.

use scp_platform::traits::Storage;

use super::{ProtocolStore, StoreError};

// ---------------------------------------------------------------------------
// Key helpers
// ---------------------------------------------------------------------------

/// Builds the storage key for an event hash at a given sequence number.
///
/// Format: `context/{context_id}/event/{seq:020d}`
/// Uses 20-digit zero-padding for lexicographic ordering.
/// See spec section 17.3.
fn event_key(context_id: &str, seq: u64) -> Result<String, StoreError> {
    let ctx = super::sanitize_key_component(context_id)?;
    Ok(format!("context/{ctx}/event/{seq:020}"))
}

/// Builds the prefix for listing all events in a context.
///
/// Format: `context/{context_id}/event/`
fn event_prefix(context_id: &str) -> Result<String, StoreError> {
    let ctx = super::sanitize_key_component(context_id)?;
    Ok(format!("context/{ctx}/event/"))
}

/// Builds the storage key for the event count metadata.
///
/// Format: `context/{context_id}/event_meta/count`
/// See spec section 17.3.
fn event_count_key(context_id: &str) -> Result<String, StoreError> {
    let ctx = super::sanitize_key_component(context_id)?;
    Ok(format!("context/{ctx}/event_meta/count"))
}

/// Builds the storage key for the Merkle root of the event log.
///
/// Format: `context/{context_id}/event_meta/root`
/// See spec section 17.3.
fn event_root_key(context_id: &str) -> Result<String, StoreError> {
    let ctx = super::sanitize_key_component(context_id)?;
    Ok(format!("context/{ctx}/event_meta/root"))
}

/// Builds the storage key for a Merkle tree node.
///
/// Format: `context/{context_id}/event_tree/{level}/{index}`
/// See spec section 17.3 and ADR-011.
fn event_tree_node_key(context_id: &str, level: u32, index: u64) -> Result<String, StoreError> {
    let ctx = super::sanitize_key_component(context_id)?;
    Ok(format!("context/{ctx}/event_tree/{level}/{index}"))
}

// ---------------------------------------------------------------------------
// ProtocolStore — event log methods (core: SCP-PERSIST-010)
// ---------------------------------------------------------------------------

impl<S: Storage> ProtocolStore<S> {
    /// Appends an event hash to the event log at the given sequence number.
    ///
    /// Stores the 32-byte SHA-256 event hash under
    /// `context/{context_id}/event/{seq:020d}` and updates the event
    /// count metadata at `context/{context_id}/event_meta/count`.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::SerializationFailed`] if serialization fails.
    /// Returns [`StoreError::Storage`] if the underlying storage write fails.
    pub async fn append_event(
        &self,
        context_id: &str,
        seq: u64,
        event_hash: &[u8; 32],
    ) -> Result<(), StoreError> {
        let key = event_key(context_id, seq)?;
        self.store_value(&key, &event_hash.to_vec()).await?;

        // Update event count: new count = seq + 1 (sequences are 0-based).
        let count_key = event_count_key(context_id)?;
        let new_count = seq + 1;
        self.store_value(&count_key, &new_count).await
    }

    /// Loads the event hash at a given sequence number.
    ///
    /// Returns `None` if no event exists at the given sequence.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::DeserializationFailed`] if deserialization fails.
    /// Returns [`StoreError::Storage`] if the underlying storage read fails.
    pub async fn load_event(
        &self,
        context_id: &str,
        seq: u64,
    ) -> Result<Option<Vec<u8>>, StoreError> {
        let key = event_key(context_id, seq)?;
        self.load_value(&key).await
    }

    /// Loads event hashes for a range of sequence numbers `[start, end)`.
    ///
    /// Returns hashes in sequence order. Uses `list_keys` with the event
    /// prefix and filters by sequence bounds. Missing sequences within
    /// the range are silently skipped.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Storage`] if the underlying storage operation fails.
    /// Returns [`StoreError::DeserializationFailed`] if any event hash fails
    /// to deserialize.
    pub async fn load_event_range(
        &self,
        context_id: &str,
        start: u64,
        end: u64,
    ) -> Result<Vec<Vec<u8>>, StoreError> {
        let prefix = event_prefix(context_id)?;
        let keys = self.storage.list_keys(&prefix).await?;

        let start_suffix = format!("{start:020}");
        let end_suffix = format!("{end:020}");

        let mut results = Vec::new();
        for key in keys {
            if let Some(seq_str) = key.strip_prefix(&prefix)
                && seq_str >= start_suffix.as_str()
                && seq_str < end_suffix.as_str()
                && let Some(data) = self.load_value::<Vec<u8>>(&key).await?
            {
                results.push(data);
            }
        }
        Ok(results)
    }

    /// Returns the total number of events appended to the context's log.
    ///
    /// Reads from the `event_meta/count` metadata key. Returns 0 if no
    /// events have been appended.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Storage`] if the underlying storage read fails.
    pub async fn event_count(&self, context_id: &str) -> Result<u64, StoreError> {
        let key = event_count_key(context_id)?;
        let count: Option<u64> = self.load_value(&key).await?;
        Ok(count.unwrap_or(0))
    }

    // -----------------------------------------------------------------------
    // Event log Merkle tree methods (SCP-PERSIST-017)
    // -----------------------------------------------------------------------

    /// Stores the Merkle root hash for the context's event log.
    ///
    /// Persists the 32-byte root hash under
    /// `context/{context_id}/event_meta/root`.
    ///
    /// See ADR-011 on the verifiable event log Merkle tree.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::SerializationFailed`] if serialization fails.
    /// Returns [`StoreError::Storage`] if the underlying storage write fails.
    pub async fn store_event_root(
        &self,
        context_id: &str,
        root: &[u8; 32],
    ) -> Result<(), StoreError> {
        let key = event_root_key(context_id)?;
        self.store_value(&key, &root.to_vec()).await
    }

    /// Loads the Merkle root hash for the context's event log.
    ///
    /// Returns `None` if no root has been stored.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::DeserializationFailed`] if deserialization fails.
    /// Returns [`StoreError::Storage`] if the underlying storage read fails.
    pub async fn load_event_root(&self, context_id: &str) -> Result<Option<[u8; 32]>, StoreError> {
        let key = event_root_key(context_id)?;
        let data: Option<Vec<u8>> = self.load_value(&key).await?;
        match data {
            Some(bytes) => {
                let arr: [u8; 32] = bytes.try_into().map_err(|_| {
                    StoreError::DeserializationFailed(
                        "event root must be exactly 32 bytes".to_owned(),
                    )
                })?;
                Ok(Some(arr))
            }
            None => Ok(None),
        }
    }

    /// Stores a Merkle tree node hash at the given level and index.
    ///
    /// Persists the 32-byte hash under
    /// `context/{context_id}/event_tree/{level}/{index}`.
    ///
    /// See ADR-011 on the verifiable event log Merkle tree.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::SerializationFailed`] if serialization fails.
    /// Returns [`StoreError::Storage`] if the underlying storage write fails.
    pub async fn store_event_tree_node(
        &self,
        context_id: &str,
        level: u32,
        index: u64,
        hash: &[u8; 32],
    ) -> Result<(), StoreError> {
        let key = event_tree_node_key(context_id, level, index)?;
        self.store_value(&key, &hash.to_vec()).await
    }

    /// Loads a Merkle tree node hash at the given level and index.
    ///
    /// Returns `None` if no node exists at the given position.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::DeserializationFailed`] if deserialization fails.
    /// Returns [`StoreError::Storage`] if the underlying storage read fails.
    pub async fn load_event_tree_node(
        &self,
        context_id: &str,
        level: u32,
        index: u64,
    ) -> Result<Option<[u8; 32]>, StoreError> {
        let key = event_tree_node_key(context_id, level, index)?;
        let data: Option<Vec<u8>> = self.load_value(&key).await?;
        match data {
            Some(bytes) => {
                let arr: [u8; 32] = bytes.try_into().map_err(|_| {
                    StoreError::DeserializationFailed(
                        "tree node hash must be exactly 32 bytes".to_owned(),
                    )
                })?;
                Ok(Some(arr))
            }
            None => Ok(None),
        }
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

    fn make_store() -> ProtocolStore<InMemoryStorage> {
        ProtocolStore::new(InMemoryStorage::new())
    }

    fn test_hash(byte: u8) -> [u8; 32] {
        let mut h = [0u8; 32];
        h[0] = byte;
        h
    }

    // -------------------------------------------------------------------
    // Event log core methods (SCP-PERSIST-010)
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn append_and_load_event_roundtrip() {
        let store = make_store();
        let hash = test_hash(0xAB);

        store.append_event("ctx-1", 0, &hash).await.unwrap();
        let loaded = store.load_event("ctx-1", 0).await.unwrap();
        assert_eq!(loaded, Some(hash.to_vec()));
    }

    #[tokio::test]
    async fn load_event_returns_none_for_missing_sequence() {
        let store = make_store();
        let loaded = store.load_event("ctx-1", 99).await.unwrap();
        assert!(loaded.is_none());
    }

    #[tokio::test]
    async fn event_count_tracks_appended_events() {
        let store = make_store();

        assert_eq!(store.event_count("ctx-1").await.unwrap(), 0);

        store.append_event("ctx-1", 0, &test_hash(1)).await.unwrap();
        assert_eq!(store.event_count("ctx-1").await.unwrap(), 1);

        store.append_event("ctx-1", 1, &test_hash(2)).await.unwrap();
        assert_eq!(store.event_count("ctx-1").await.unwrap(), 2);

        store.append_event("ctx-1", 2, &test_hash(3)).await.unwrap();
        assert_eq!(store.event_count("ctx-1").await.unwrap(), 3);
    }

    #[tokio::test]
    async fn load_event_range_returns_correct_ordered_subset() {
        let store = make_store();

        for i in 0u8..10 {
            let mut hash = [0u8; 32];
            hash[0] = i;
            store
                .append_event("ctx-1", u64::from(i), &hash)
                .await
                .unwrap();
        }

        let range = store.load_event_range("ctx-1", 3, 7).await.unwrap();
        assert_eq!(range.len(), 4);

        // Verify sequence order and correct values.
        for (idx, data) in range.iter().enumerate() {
            let expected = u8::try_from(3 + idx).unwrap();
            assert_eq!(data[0], expected);
        }
    }

    #[tokio::test]
    async fn load_event_range_empty_for_no_match() {
        let store = make_store();

        store.append_event("ctx-1", 0, &test_hash(1)).await.unwrap();

        let range = store.load_event_range("ctx-1", 5, 10).await.unwrap();
        assert!(range.is_empty());
    }

    #[tokio::test]
    async fn event_key_uses_20_digit_zero_padding() {
        let key = event_key("ctx-1", 42).unwrap();
        assert_eq!(key, "context/ctx-1/event/00000000000000000042");
    }

    // -------------------------------------------------------------------
    // Merkle tree methods (SCP-PERSIST-017)
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn store_and_load_event_root_roundtrip() {
        let store = make_store();
        let root = test_hash(0xFF);

        store.store_event_root("ctx-1", &root).await.unwrap();
        let loaded = store.load_event_root("ctx-1").await.unwrap();
        assert_eq!(loaded, Some(root));
    }

    #[tokio::test]
    async fn load_event_root_returns_none_for_missing() {
        let store = make_store();
        let loaded = store.load_event_root("ctx-1").await.unwrap();
        assert!(loaded.is_none());
    }

    #[tokio::test]
    async fn store_and_load_event_tree_node_roundtrip() {
        let store = make_store();
        let hash = test_hash(0xCC);

        store
            .store_event_tree_node("ctx-1", 2, 5, &hash)
            .await
            .unwrap();
        let loaded = store.load_event_tree_node("ctx-1", 2, 5).await.unwrap();
        assert_eq!(loaded, Some(hash));
    }

    #[tokio::test]
    async fn load_event_tree_node_returns_none_for_missing() {
        let store = make_store();
        let loaded = store.load_event_tree_node("ctx-1", 0, 0).await.unwrap();
        assert!(loaded.is_none());
    }

    // -------------------------------------------------------------------
    // Key convention tests
    // -------------------------------------------------------------------

    #[test]
    fn event_key_follows_convention() {
        assert_eq!(
            event_key("ctx-123", 0).unwrap(),
            "context/ctx-123/event/00000000000000000000"
        );
        assert_eq!(
            event_key("ctx-123", 42).unwrap(),
            "context/ctx-123/event/00000000000000000042"
        );
    }

    #[test]
    fn event_count_key_follows_convention() {
        assert_eq!(
            event_count_key("ctx-123").unwrap(),
            "context/ctx-123/event_meta/count"
        );
    }

    #[test]
    fn event_root_key_follows_convention() {
        assert_eq!(
            event_root_key("ctx-123").unwrap(),
            "context/ctx-123/event_meta/root"
        );
    }

    #[test]
    fn event_tree_node_key_follows_convention() {
        assert_eq!(
            event_tree_node_key("ctx-123", 2, 5).unwrap(),
            "context/ctx-123/event_tree/2/5"
        );
    }
}
