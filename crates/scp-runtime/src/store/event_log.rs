//! Event log storage operations for `ProtocolRepository`.
//!
//! Implements event log persistence following the key convention from
//! spec section 17.3:
//!
//! ```text
//! context/{context_id}/event/{seq:020d}               -- 32-byte event hash
//! context/{context_id}/event_meta/count               -- u64 event count
//! context/{context_id}/event_meta/root                -- 32-byte Merkle root
//! context/{context_id}/event_tree/{level}/{index}     -- Merkle tree nodes
//! context/{context_id}/event_data/{seq:020d}          -- MessagePack-serialized Event payload
//! context/{context_id}/merkle_event_log/{seq:020d}    -- per-entry MerkleEventLogProvider (#710)
//! ```
//!
//! Event sequence numbers use 20-digit zero-padding for lexicographic
//! ordering, enabling efficient range queries via `list_keys`.
//!
//! The `event_data/` key space stores full serialized event payloads alongside
//! the Merkle tree leaf hashes. This enables `query_events` to return real
//! event data instead of just Merkle summaries. See GitHub issue #303.
//!
//! The `merkle_event_log/{seq:020d}` key space stores individual
//! `EventLogEntry` values for the `MerkleEventLogProvider`, enabling O(1)
//! append persistence. Restore loads all entries by prefix scan.
//! See GitHub issues #636, #710.
//!
//! See spec sections 17.3, 17.4, and ADR-011.

use scp_platform::traits::Storage;

use super::{ProtocolRepository, StoreError};

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
/// Format: `context/{context_id}/event_tree/{level:05}/{index:020}`
/// Uses zero-padding for consistency with event key conventions.
/// See spec section 17.3 and ADR-011.
fn event_tree_node_key(context_id: &str, level: u32, index: u64) -> Result<String, StoreError> {
    let ctx = super::sanitize_key_component(context_id)?;
    Ok(format!("context/{ctx}/event_tree/{level:05}/{index:020}"))
}

/// Builds the storage key for an event data payload at a given sequence number.
///
/// Format: `context/{context_id}/event_data/{seq:020d}`
/// Uses 20-digit zero-padding for lexicographic ordering, matching the
/// event hash key convention.
/// See spec section 17.3 and GitHub issue #303.
fn event_data_key(context_id: &str, seq: u64) -> Result<String, StoreError> {
    let ctx = super::sanitize_key_component(context_id)?;
    Ok(format!("context/{ctx}/event_data/{seq:020}"))
}

/// Builds the prefix for listing all event data payloads in a context.
///
/// Format: `context/{context_id}/event_data/`
fn event_data_prefix(context_id: &str) -> Result<String, StoreError> {
    let ctx = super::sanitize_key_component(context_id)?;
    Ok(format!("context/{ctx}/event_data/"))
}

/// Builds the storage key for a single `MerkleEventLogProvider` entry.
///
/// Format: `context/{context_id}/merkle_event_log/{seq:020d}`
/// Uses 20-digit zero-padding for lexicographic ordering, matching
/// the `event/{seq:020d}` convention.
/// See GitHub issues #636, #710.
fn merkle_event_log_entry_key(context_id: &str, seq: usize) -> Result<String, StoreError> {
    let ctx = super::sanitize_key_component(context_id)?;
    Ok(format!("context/{ctx}/merkle_event_log/{seq:020}"))
}

/// Builds the prefix for listing all `MerkleEventLogProvider` entries.
///
/// Format: `context/{context_id}/merkle_event_log/`
fn merkle_event_log_prefix(context_id: &str) -> Result<String, StoreError> {
    let ctx = super::sanitize_key_component(context_id)?;
    Ok(format!("context/{ctx}/merkle_event_log/"))
}

// ---------------------------------------------------------------------------
// EventQueryFilter — filter criteria for query_events (GitHub issue #303)
// ---------------------------------------------------------------------------

/// Filter criteria for querying stored events.
///
/// All fields are optional. When `None`, the filter does not constrain
/// that dimension. Multiple filters are `ANDed` together.
#[derive(Debug, Clone, Default)]
pub struct EventQueryFilter {
    /// Match events with this exact event type (e.g., `"OutletInvoked"`).
    pub event_type: Option<String>,
    /// Match events from this specific actor DID.
    pub actor_did: Option<String>,
    /// Only events at or after this sequence number (inclusive).
    pub sequence_start: Option<u64>,
    /// Only events before this sequence number (exclusive).
    pub sequence_end: Option<u64>,
    /// Only events at or after this Unix timestamp (seconds, inclusive).
    pub timestamp_start: Option<u64>,
    /// Only events before this Unix timestamp (seconds, exclusive).
    pub timestamp_end: Option<u64>,
    /// Maximum number of events to return.
    pub limit: Option<usize>,
}

impl EventQueryFilter {
    /// Returns `true` if any filter field requires deserializing the event
    /// payload to check (i.e., `event_type`, `actor_did`, or timestamp filters).
    const fn needs_deserialized_check(&self) -> bool {
        self.event_type.is_some()
            || self.actor_did.is_some()
            || self.timestamp_start.is_some()
            || self.timestamp_end.is_some()
    }

    /// Returns `true` if the given deserialized event matches all active
    /// filter criteria.
    fn matches(&self, event: &scp_event_log::Event) -> bool {
        if let Some(ref et) = self.event_type {
            let event_type_str = format!("{:?}", event.event_type);
            if event_type_str != *et {
                return false;
            }
        }
        if let Some(ref actor) = self.actor_did
            && event.actor_did.0 != *actor
        {
            return false;
        }
        if let Some(ts_start) = self.timestamp_start
            && event.timestamp < ts_start
        {
            return false;
        }
        if let Some(ts_end) = self.timestamp_end
            && event.timestamp >= ts_end
        {
            return false;
        }
        true
    }
}

// ---------------------------------------------------------------------------
// ProtocolRepository — event log methods (core: SCP-PERSIST-010)
// ---------------------------------------------------------------------------

impl<S: Storage> ProtocolRepository<S> {
    /// Appends an event hash to the event log at the given sequence number.
    ///
    /// Stores the 32-byte SHA-256 event hash under
    /// `context/{context_id}/event/{seq:020d}` and updates the event
    /// count metadata at `context/{context_id}/event_meta/count`.
    ///
    /// Enforces strict append-only monotonicity: `seq` must equal the
    /// current event count (i.e., the next expected sequence number).
    /// Out-of-order or duplicate appends are rejected.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::SerializationFailed`] if `seq` does not equal
    /// the current event count (monotonicity violation), or if serialization
    /// fails.
    /// Returns [`StoreError::Storage`] if the underlying storage write fails.
    ///
    /// # Consistency note
    ///
    /// The event count is maintained as a separate metadata key and is
    /// updated after the event write. If `append_event` fails between the
    /// event write and the count update, the count can drift behind the
    /// actual number of stored events. Callers that detect this condition
    /// should treat it as a data integrity issue.
    pub async fn append_event(
        &self,
        context_id: &str,
        seq: u64,
        event_hash: &[u8; 32],
    ) -> Result<(), StoreError> {
        // Enforce strict monotonicity: seq must be exactly the current count.
        let current_count = self.event_count(context_id).await?;
        if seq != current_count {
            return Err(StoreError::SerializationFailed(format!(
                "non-monotonic event append: seq={seq}, expected={current_count}"
            )));
        }

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
    /// # Performance
    ///
    /// The thin `Storage` trait only provides `list_keys(prefix)` which
    /// returns all keys under the prefix (O(N) in total events). This
    /// method terminates early once keys exceed `end_suffix` (keys are
    /// sorted lexicographically), avoiding unnecessary I/O for events
    /// beyond the requested range. Storage backends that support native
    /// range queries should be preferred for large event logs.
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
            if let Some(seq_str) = key.strip_prefix(&prefix) {
                // Keys are sorted lexicographically; once we pass end_suffix
                // no further keys can be in range — terminate early.
                if seq_str >= end_suffix.as_str() {
                    break;
                }
                if seq_str >= start_suffix.as_str()
                    && let Some(data) = self.load_value::<Vec<u8>>(&key).await?
                {
                    results.push(data);
                }
            }
        }
        Ok(results)
    }

    /// Returns the total number of events appended to the context's log.
    ///
    /// Reads from the `event_meta/count` metadata key. Returns 0 if no
    /// events have been appended.
    ///
    /// # Consistency
    ///
    /// The count is maintained as a separate metadata key, updated after
    /// each event write in `append_event`. If `append_event` fails between
    /// the event write and the count update, the count can fall behind the
    /// actual number of stored events. Callers that detect a mismatch
    /// (e.g., an event exists at `seq == count`) should treat it as a data
    /// integrity issue requiring recovery.
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
    // Event data payload methods (GitHub issue #303)
    // -----------------------------------------------------------------------

    /// Stores a serialized event payload at the given sequence number.
    ///
    /// Persists the `MessagePack`-serialized `Event` bytes under
    /// `context/{context_id}/event_data/{seq:020d}`. This stores the full
    /// event payload alongside the Merkle tree leaf hash (which is stored
    /// separately via [`append_event`](Self::append_event)).
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::SerializationFailed`] if serialization fails.
    /// Returns [`StoreError::Storage`] if the underlying storage write fails.
    pub async fn store_event_data(
        &self,
        context_id: &str,
        seq: u64,
        event_bytes: &[u8],
    ) -> Result<(), StoreError> {
        let key = event_data_key(context_id, seq)?;
        self.store_value(&key, &event_bytes.to_vec()).await
    }

    /// Loads a serialized event payload at the given sequence number.
    ///
    /// Returns `None` if no event data exists at the given sequence (e.g.,
    /// for events that were hash-only before payload persistence was added).
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::DeserializationFailed`] if deserialization fails.
    /// Returns [`StoreError::Storage`] if the underlying storage read fails.
    pub async fn load_event_data(
        &self,
        context_id: &str,
        seq: u64,
    ) -> Result<Option<Vec<u8>>, StoreError> {
        let key = event_data_key(context_id, seq)?;
        self.load_value(&key).await
    }

    /// Loads serialized event payloads for a range of sequence numbers `[start, end)`.
    ///
    /// Returns `(sequence, payload_bytes)` pairs in sequence order. Missing
    /// sequences within the range are silently skipped (backward compatibility
    /// for events that were hash-only before payload persistence was added).
    ///
    /// # Performance
    ///
    /// Uses `list_keys` with the event data prefix and filters by sequence
    /// bounds. Terminates early once keys exceed `end_suffix`.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Storage`] if the underlying storage operation fails.
    /// Returns [`StoreError::DeserializationFailed`] if any payload fails
    /// to deserialize.
    pub async fn load_event_data_range(
        &self,
        context_id: &str,
        start: u64,
        end: u64,
    ) -> Result<Vec<(u64, Vec<u8>)>, StoreError> {
        let prefix = event_data_prefix(context_id)?;
        let keys = self.storage.list_keys(&prefix).await?;

        let start_suffix = format!("{start:020}");
        let end_suffix = format!("{end:020}");

        let mut results = Vec::new();
        for key in keys {
            if let Some(seq_str) = key.strip_prefix(&prefix) {
                // Keys are sorted lexicographically; once we pass end_suffix
                // no further keys can be in range -- terminate early.
                if seq_str >= end_suffix.as_str() {
                    break;
                }
                if seq_str >= start_suffix.as_str()
                    && let Some(data) = self.load_value::<Vec<u8>>(&key).await?
                {
                    // Parse the sequence number from the key suffix.
                    if let Ok(seq) = seq_str.parse::<u64>() {
                        results.push((seq, data));
                    }
                }
            }
        }
        Ok(results)
    }

    /// Appends both an event hash and its full serialized payload atomically.
    ///
    /// This is the combined operation for persisting a complete event record:
    /// the 32-byte SHA-256 hash goes to `context/{context_id}/event/{seq:020d}`
    /// (for Merkle tree verification) and the full `MessagePack`-serialized
    /// `Event` goes to `context/{context_id}/event_data/{seq:020d}` (for
    /// later query and replay).
    ///
    /// Enforces strict append-only monotonicity: `seq` must equal the
    /// current event count.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::SerializationFailed`] if `seq` does not equal
    /// the current event count (monotonicity violation).
    /// Returns [`StoreError::Storage`] if the underlying storage write fails.
    pub async fn append_event_full(
        &self,
        context_id: &str,
        seq: u64,
        event_hash: &[u8; 32],
        event_bytes: &[u8],
    ) -> Result<(), StoreError> {
        // Delegate hash storage (with monotonicity enforcement) to append_event.
        self.append_event(context_id, seq, event_hash).await?;
        // Store the full event payload alongside.
        self.store_event_data(context_id, seq, event_bytes).await
    }

    /// Queries stored event data with optional filters.
    ///
    /// Loads event payloads from the `event_data/` key space, deserializes
    /// them, and applies the provided filter criteria. Returns matching
    /// events in sequence order.
    ///
    /// # Filter fields
    ///
    /// - `event_type`: Match events with this exact event type name.
    /// - `actor_did`: Match events from this specific actor DID.
    /// - `sequence_start`: Only events at or after this sequence (inclusive).
    /// - `sequence_end`: Only events before this sequence (exclusive).
    /// - `timestamp_start`: Only events at or after this timestamp.
    /// - `timestamp_end`: Only events before this timestamp.
    /// - `limit`: Maximum number of events to return.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Storage`] if the underlying storage operation fails.
    /// Returns [`StoreError::DeserializationFailed`] if stored data is corrupt.
    pub async fn query_events(
        &self,
        context_id: &str,
        filter: &EventQueryFilter,
    ) -> Result<Vec<Vec<u8>>, StoreError> {
        let count = self.event_count(context_id).await?;
        if count == 0 {
            return Ok(Vec::new());
        }

        let start = filter.sequence_start.unwrap_or(0);
        let end = filter.sequence_end.unwrap_or(count);

        let range = self.load_event_data_range(context_id, start, end).await?;

        let mut results = Vec::new();
        for (_seq, data) in range {
            // Apply post-load filters by attempting deserialization.
            // If deserialization fails for filter checking, include the raw
            // bytes anyway (the caller may handle partial data).
            if filter.needs_deserialized_check() {
                if let Ok(event) = rmp_serde::from_slice::<scp_event_log::Event>(&data) {
                    if !filter.matches(&event) {
                        continue;
                    }
                }
                // If deserialization fails, skip the event (corrupt data).
                else {
                    continue;
                }
            }

            results.push(data);

            if let Some(limit) = filter.limit
                && results.len() >= limit
            {
                break;
            }
        }

        Ok(results)
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

    // -----------------------------------------------------------------------
    // MerkleEventLogProvider persistence methods (#636)
    // -----------------------------------------------------------------------

    /// Stores a single `MerkleEventLogProvider` entry at the given sequence.
    ///
    /// Persists one `EventLogEntry` under
    /// `context/{context_id}/merkle_event_log/{seq:020d}`. O(1) per append.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::SerializationFailed`] if serialization fails.
    /// Returns [`StoreError::Storage`] if the underlying storage write fails.
    pub async fn store_merkle_event_log_entry(
        &self,
        context_id: &str,
        seq: usize,
        entry: &crate::context::providers::event_log::EventLogEntry,
    ) -> Result<(), StoreError> {
        let key = merkle_event_log_entry_key(context_id, seq)?;
        self.store_value(&key, entry).await
    }

    /// Stores all `MerkleEventLogProvider` entries for a context, replacing
    /// any previously stored entries.
    ///
    /// Deletes existing per-entry keys via prefix delete, then writes each
    /// entry under its own key. Used by bulk operations (prune, import).
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::SerializationFailed`] if serialization fails.
    /// Returns [`StoreError::Storage`] if the underlying storage write fails.
    pub async fn store_merkle_event_log_entries(
        &self,
        context_id: &str,
        entries: &[crate::context::providers::event_log::EventLogEntry],
    ) -> Result<(), StoreError> {
        // Delete all existing keys under this prefix (per-entry + legacy blob).
        let prefix = merkle_event_log_prefix(context_id)?;
        self.storage.delete_prefix(&prefix).await?;

        // Write each entry under its own key.
        for (i, entry) in entries.iter().enumerate() {
            self.store_merkle_event_log_entry(context_id, i, entry)
                .await?;
        }
        Ok(())
    }

    /// Loads the persisted `MerkleEventLogProvider` entries for a context.
    ///
    /// Loads per-entry keys via prefix scan (`merkle_event_log/`).
    /// Returns `None` if no entries have been persisted.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::DeserializationFailed`] if deserialization fails.
    /// Returns [`StoreError::Storage`] if the underlying storage read fails.
    pub async fn load_merkle_event_log_entries(
        &self,
        context_id: &str,
    ) -> Result<Option<Vec<crate::context::providers::event_log::EventLogEntry>>, StoreError> {
        let prefix = merkle_event_log_prefix(context_id)?;
        let keys = self.storage.list_keys(&prefix).await?;

        if keys.is_empty() {
            return Ok(None);
        }

        // Per-entry format (#710): load each entry individually.
        // Keys are returned in lexicographic order (= sequence order due
        // to zero-padding).
        let mut entries = Vec::with_capacity(keys.len());
        for key in &keys {
            let entry: crate::context::providers::event_log::EventLogEntry =
                self.load_value(key).await?.ok_or_else(|| {
                    StoreError::DeserializationFailed(format!(
                        "merkle event log entry missing after list_keys: {key}"
                    ))
                })?;
            entries.push(entry);
        }
        Ok(Some(entries))
    }

    /// Deletes the persisted `MerkleEventLogProvider` entries for a context.
    ///
    /// Removes all per-entry keys via prefix delete.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Storage`] if the underlying storage delete fails.
    pub async fn delete_merkle_event_log_entries(
        &self,
        context_id: &str,
    ) -> Result<(), StoreError> {
        let prefix = merkle_event_log_prefix(context_id)?;
        self.storage.delete_prefix(&prefix).await?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::cast_possible_truncation
)]
mod tests {
    use scp_platform::testing::InMemoryStorage;

    use super::*;

    fn make_store() -> ProtocolRepository<InMemoryStorage> {
        ProtocolRepository::new_for_testing(InMemoryStorage::new())
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

    #[tokio::test]
    async fn append_event_rejects_out_of_order_sequence() {
        let store = make_store();

        store.append_event("ctx-1", 0, &test_hash(1)).await.unwrap();

        // Attempting to append at seq=5 when count is 1 should fail.
        let result = store.append_event("ctx-1", 5, &test_hash(2)).await;
        assert!(result.is_err());
        assert_eq!(store.event_count("ctx-1").await.unwrap(), 1);
    }

    #[tokio::test]
    async fn append_event_rejects_duplicate_sequence() {
        let store = make_store();

        store.append_event("ctx-1", 0, &test_hash(1)).await.unwrap();
        store.append_event("ctx-1", 1, &test_hash(2)).await.unwrap();

        // Attempting to re-append at seq=0 should fail (duplicate).
        let result = store.append_event("ctx-1", 0, &test_hash(3)).await;
        assert!(result.is_err());
        assert_eq!(store.event_count("ctx-1").await.unwrap(), 2);
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
    // Event data payload methods (GitHub issue #303)
    // -------------------------------------------------------------------

    fn make_test_event(
        seq: u64,
        event_type: scp_event_log::EventType,
        actor: &str,
    ) -> scp_event_log::Event {
        scp_event_log::Event {
            event_type,
            actor_did: scp_event_log::DID(actor.to_owned()),
            timestamp: 1_700_000_000 + seq,
            sequence: seq,
            payload: scp_event_log::EventPayload {
                data: vec![seq as u8; 4],
            },
            prev_hash: [0u8; 32],
            signature: Vec::new(),
        }
    }

    fn serialize_event(event: &scp_event_log::Event) -> Vec<u8> {
        rmp_serde::to_vec(event).unwrap()
    }

    #[tokio::test]
    async fn store_and_load_event_data_roundtrip() {
        let store = make_store();
        let event = make_test_event(
            0,
            scp_event_log::EventType::OutletInvoked,
            "did:dht:z6MkTest",
        );
        let bytes = serialize_event(&event);

        store.store_event_data("ctx-1", 0, &bytes).await.unwrap();
        let loaded = store.load_event_data("ctx-1", 0).await.unwrap();
        assert_eq!(loaded, Some(bytes));
    }

    #[tokio::test]
    async fn load_event_data_returns_none_for_missing_sequence() {
        let store = make_store();
        let loaded = store.load_event_data("ctx-1", 99).await.unwrap();
        assert!(loaded.is_none());
    }

    #[tokio::test]
    async fn load_event_data_range_returns_correct_ordered_subset() {
        let store = make_store();

        for i in 0u64..10 {
            let event =
                make_test_event(i, scp_event_log::EventType::MessageSent, "did:dht:z6MkTest");
            let bytes = serialize_event(&event);
            store.store_event_data("ctx-1", i, &bytes).await.unwrap();
        }

        let range = store.load_event_data_range("ctx-1", 3, 7).await.unwrap();
        assert_eq!(range.len(), 4);

        // Verify sequence order.
        for (idx, (seq, _data)) in range.iter().enumerate() {
            assert_eq!(*seq, 3 + idx as u64);
        }
    }

    #[tokio::test]
    async fn load_event_data_range_empty_for_no_match() {
        let store = make_store();
        let event = make_test_event(
            0,
            scp_event_log::EventType::ContextCreated,
            "did:dht:z6MkTest",
        );
        let bytes = serialize_event(&event);
        store.store_event_data("ctx-1", 0, &bytes).await.unwrap();

        let range = store.load_event_data_range("ctx-1", 5, 10).await.unwrap();
        assert!(range.is_empty());
    }

    #[tokio::test]
    async fn append_event_full_stores_both_hash_and_payload() {
        let store = make_store();
        let hash = test_hash(0xAB);
        let event = make_test_event(
            0,
            scp_event_log::EventType::OutletInvoked,
            "did:dht:z6MkTest",
        );
        let bytes = serialize_event(&event);

        store
            .append_event_full("ctx-1", 0, &hash, &bytes)
            .await
            .unwrap();

        // Verify hash was stored.
        let loaded_hash = store.load_event("ctx-1", 0).await.unwrap();
        assert_eq!(loaded_hash, Some(hash.to_vec()));

        // Verify payload was stored.
        let loaded_data = store.load_event_data("ctx-1", 0).await.unwrap();
        assert_eq!(loaded_data, Some(bytes));

        // Verify event count was updated.
        assert_eq!(store.event_count("ctx-1").await.unwrap(), 1);
    }

    #[tokio::test]
    async fn query_events_with_no_filter_returns_all() {
        let store = make_store();

        for i in 0u64..3 {
            let event =
                make_test_event(i, scp_event_log::EventType::MessageSent, "did:dht:z6MkTest");
            let bytes = serialize_event(&event);
            store
                .append_event_full("ctx-1", i, &test_hash(i as u8), &bytes)
                .await
                .unwrap();
        }

        let filter = EventQueryFilter::default();
        let results = store.query_events("ctx-1", &filter).await.unwrap();
        assert_eq!(results.len(), 3);
    }

    #[tokio::test]
    async fn query_events_filters_by_event_type() {
        let store = make_store();

        let e0 = make_test_event(0, scp_event_log::EventType::MessageSent, "did:dht:z6MkA");
        let e1 = make_test_event(1, scp_event_log::EventType::OutletInvoked, "did:dht:z6MkB");
        let e2 = make_test_event(2, scp_event_log::EventType::MessageSent, "did:dht:z6MkC");
        store
            .append_event_full("ctx-1", 0, &test_hash(0), &serialize_event(&e0))
            .await
            .unwrap();
        store
            .append_event_full("ctx-1", 1, &test_hash(1), &serialize_event(&e1))
            .await
            .unwrap();
        store
            .append_event_full("ctx-1", 2, &test_hash(2), &serialize_event(&e2))
            .await
            .unwrap();

        let filter = EventQueryFilter {
            event_type: Some("MessageSent".to_owned()),
            ..Default::default()
        };
        let results = store.query_events("ctx-1", &filter).await.unwrap();
        assert_eq!(results.len(), 2);
    }

    #[tokio::test]
    async fn query_events_filters_by_actor_did() {
        let store = make_store();

        let e0 = make_test_event(0, scp_event_log::EventType::MessageSent, "did:dht:z6MkA");
        let e1 = make_test_event(1, scp_event_log::EventType::MessageSent, "did:dht:z6MkB");
        store
            .append_event_full("ctx-1", 0, &test_hash(0), &serialize_event(&e0))
            .await
            .unwrap();
        store
            .append_event_full("ctx-1", 1, &test_hash(1), &serialize_event(&e1))
            .await
            .unwrap();

        let filter = EventQueryFilter {
            actor_did: Some("did:dht:z6MkA".to_owned()),
            ..Default::default()
        };
        let results = store.query_events("ctx-1", &filter).await.unwrap();
        assert_eq!(results.len(), 1);
    }

    #[tokio::test]
    async fn query_events_filters_by_sequence_range() {
        let store = make_store();

        for i in 0u64..5 {
            let event =
                make_test_event(i, scp_event_log::EventType::MessageSent, "did:dht:z6MkTest");
            store
                .append_event_full("ctx-1", i, &test_hash(i as u8), &serialize_event(&event))
                .await
                .unwrap();
        }

        let filter = EventQueryFilter {
            sequence_start: Some(2),
            sequence_end: Some(4),
            ..Default::default()
        };
        let results = store.query_events("ctx-1", &filter).await.unwrap();
        assert_eq!(results.len(), 2);
    }

    #[tokio::test]
    async fn query_events_filters_by_timestamp_range() {
        let store = make_store();

        for i in 0u64..5 {
            let event =
                make_test_event(i, scp_event_log::EventType::MessageSent, "did:dht:z6MkTest");
            store
                .append_event_full("ctx-1", i, &test_hash(i as u8), &serialize_event(&event))
                .await
                .unwrap();
        }

        // Events have timestamps 1_700_000_000, ..., 1_700_000_004
        let filter = EventQueryFilter {
            timestamp_start: Some(1_700_000_002),
            timestamp_end: Some(1_700_000_004),
            ..Default::default()
        };
        let results = store.query_events("ctx-1", &filter).await.unwrap();
        assert_eq!(results.len(), 2);
    }

    #[tokio::test]
    async fn query_events_respects_limit() {
        let store = make_store();

        for i in 0u64..10 {
            let event =
                make_test_event(i, scp_event_log::EventType::MessageSent, "did:dht:z6MkTest");
            store
                .append_event_full("ctx-1", i, &test_hash(i as u8), &serialize_event(&event))
                .await
                .unwrap();
        }

        let filter = EventQueryFilter {
            limit: Some(3),
            ..Default::default()
        };
        let results = store.query_events("ctx-1", &filter).await.unwrap();
        assert_eq!(results.len(), 3);
    }

    #[tokio::test]
    async fn backward_compatibility_hash_only_events() {
        let store = make_store();

        // Simulate a hash-only event (no payload stored).
        store.append_event("ctx-1", 0, &test_hash(1)).await.unwrap();

        // load_event_data should return None for hash-only events.
        let loaded = store.load_event_data("ctx-1", 0).await.unwrap();
        assert!(loaded.is_none());

        // query_events should return empty for hash-only contexts.
        let filter = EventQueryFilter::default();
        let results = store.query_events("ctx-1", &filter).await.unwrap();
        assert!(results.is_empty());
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
            "context/ctx-123/event_tree/00002/00000000000000000005"
        );
    }

    #[test]
    fn event_data_key_follows_convention() {
        assert_eq!(
            event_data_key("ctx-123", 0).unwrap(),
            "context/ctx-123/event_data/00000000000000000000"
        );
        assert_eq!(
            event_data_key("ctx-123", 42).unwrap(),
            "context/ctx-123/event_data/00000000000000000042"
        );
    }

    #[test]
    fn event_data_prefix_follows_convention() {
        assert_eq!(
            event_data_prefix("ctx-123").unwrap(),
            "context/ctx-123/event_data/"
        );
    }

    // -------------------------------------------------------------------
    // Merkle event log persistence tests (#636)
    // -------------------------------------------------------------------

    #[test]
    fn merkle_event_log_entry_key_follows_convention() {
        assert_eq!(
            merkle_event_log_entry_key("ctx-123", 0).unwrap(),
            "context/ctx-123/merkle_event_log/00000000000000000000"
        );
        assert_eq!(
            merkle_event_log_entry_key("ctx-123", 42).unwrap(),
            "context/ctx-123/merkle_event_log/00000000000000000042"
        );
    }

    #[test]
    fn merkle_event_log_prefix_follows_convention() {
        assert_eq!(
            merkle_event_log_prefix("ctx-123").unwrap(),
            "context/ctx-123/merkle_event_log/"
        );
    }

    #[tokio::test]
    async fn store_and_load_single_merkle_event_log_entry() {
        use crate::context::providers::event_log::EventLogEntry;

        let store = make_store();
        let entry = EventLogEntry {
            event: "ContextCreated".to_owned(),
            actor_did: String::new(),
            timestamp: 1_700_000_000,
            prev_hash: [0u8; 32],
            hash: [1u8; 32],
            payload: None,
        };

        store
            .store_merkle_event_log_entry("ctx-1", 0, &entry)
            .await
            .unwrap();

        let loaded = store
            .load_merkle_event_log_entries("ctx-1")
            .await
            .unwrap()
            .unwrap();

        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].event, "ContextCreated");
    }

    #[tokio::test]
    async fn store_and_load_merkle_event_log_entries_roundtrip() {
        use crate::context::providers::event_log::EventLogEntry;

        let store = make_store();
        let entries = vec![
            EventLogEntry {
                event: "ContextCreated".to_owned(),
                actor_did: String::new(),
                timestamp: 1_700_000_000,
                prev_hash: [0u8; 32],
                hash: [1u8; 32],
                payload: None,
            },
            EventLogEntry {
                event: "MemberJoined".to_owned(),
                actor_did: String::new(),
                timestamp: 1_700_000_001,
                prev_hash: [1u8; 32],
                hash: [2u8; 32],
                payload: None,
            },
        ];

        store
            .store_merkle_event_log_entries("ctx-1", &entries)
            .await
            .unwrap();

        let loaded = store
            .load_merkle_event_log_entries("ctx-1")
            .await
            .unwrap()
            .unwrap();

        assert_eq!(loaded.len(), 2);
        assert_eq!(loaded[0].event, "ContextCreated");
        assert_eq!(loaded[1].event, "MemberJoined");
    }

    #[tokio::test]
    async fn load_merkle_event_log_entries_returns_none_for_missing() {
        let store = make_store();
        let loaded = store
            .load_merkle_event_log_entries("nonexistent")
            .await
            .unwrap();
        assert!(loaded.is_none());
    }

    #[tokio::test]
    async fn delete_merkle_event_log_entries() {
        use crate::context::providers::event_log::EventLogEntry;

        let store = make_store();
        let entries = vec![EventLogEntry {
            event: "ContextCreated".to_owned(),
            actor_did: String::new(),
            timestamp: 1_700_000_000,
            prev_hash: [0u8; 32],
            hash: [1u8; 32],
            payload: None,
        }];

        store
            .store_merkle_event_log_entries("ctx-del", &entries)
            .await
            .unwrap();

        assert!(
            store
                .load_merkle_event_log_entries("ctx-del")
                .await
                .unwrap()
                .is_some()
        );

        store
            .delete_merkle_event_log_entries("ctx-del")
            .await
            .unwrap();

        assert!(
            store
                .load_merkle_event_log_entries("ctx-del")
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn bulk_store_replaces_existing_per_entry_keys() {
        use crate::context::providers::event_log::EventLogEntry;

        let store = make_store();

        // Store 5 entries individually.
        for i in 0..5u8 {
            let entry = EventLogEntry {
                event: format!("Event{i}"),
                actor_did: String::new(),
                timestamp: u64::from(i),
                prev_hash: [i; 32],
                hash: [i + 1; 32],
                payload: None,
            };
            store
                .store_merkle_event_log_entry("ctx-bulk", usize::from(i), &entry)
                .await
                .unwrap();
        }

        // Bulk-store only 2 entries (simulating prune).
        let pruned = vec![
            EventLogEntry {
                event: "Event3".to_owned(),
                actor_did: String::new(),
                timestamp: 3,
                prev_hash: [3; 32],
                hash: [4; 32],
                payload: None,
            },
            EventLogEntry {
                event: "Event4".to_owned(),
                actor_did: String::new(),
                timestamp: 4,
                prev_hash: [4; 32],
                hash: [5; 32],
                payload: None,
            },
        ];
        store
            .store_merkle_event_log_entries("ctx-bulk", &pruned)
            .await
            .unwrap();

        let loaded = store
            .load_merkle_event_log_entries("ctx-bulk")
            .await
            .unwrap()
            .unwrap();

        // Should only have the 2 entries, not 5.
        assert_eq!(loaded.len(), 2);
        assert_eq!(loaded[0].event, "Event3");
        assert_eq!(loaded[1].event, "Event4");
    }
}
