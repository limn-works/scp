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
//! context/{context_id}/merkle_event_log/head          -- current generation and log length
//! context/{context_id}/merkle_event_log/g{gen:020d}/{base_seq:020d}
//!                                                     -- one unit: Vec<Event>, MerkleEventLogProvider
//! ```
//!
//! Event sequence numbers use 20-digit zero-padding for lexicographic
//! ordering, enabling efficient range queries via `list_keys`.
//!
//! The `event_data/` key space stores full serialized event payloads alongside
//! the Merkle tree leaf hashes. This enables `query_events` to return real
//! event data instead of just Merkle summaries. See GitHub issue #303.
//!
//! The `merkle_event_log/` key space stores the `MerkleEventLogProvider` log as
//! units of `scp_event_log::Event` under the generation that
//! `merkle_event_log/head` names (spec section 17.3, "Merkle event log
//! entries"). An append puts one unit and then `head`. A replace writes a new
//! generation and then puts `head`, so every write needs only a single-key put
//! to be atomic.
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

/// Builds the prefix for every `MerkleEventLogProvider` key of a context.
///
/// Format: `context/{context_id}/merkle_event_log/`
fn merkle_event_log_prefix(context_id: &str) -> Result<String, StoreError> {
    let ctx = super::sanitize_key_component(context_id)?;
    Ok(format!("context/{ctx}/merkle_event_log/"))
}

/// Builds the key that names the current generation and length of a
/// context's `MerkleEventLogProvider` log.
///
/// Format: `context/{context_id}/merkle_event_log/head`
/// See spec section 17.3, "Merkle event log entries".
pub(super) fn merkle_event_log_head_key(context_id: &str) -> Result<String, StoreError> {
    let ctx = super::sanitize_key_component(context_id)?;
    Ok(format!("context/{ctx}/merkle_event_log/head"))
}

/// Builds the prefix of every unit in one generation of a context's
/// `MerkleEventLogProvider` log.
///
/// Format: `context/{context_id}/merkle_event_log/g{gen:020d}/`
fn merkle_event_log_generation_prefix(
    context_id: &str,
    generation: u64,
) -> Result<String, StoreError> {
    let ctx = super::sanitize_key_component(context_id)?;
    Ok(format!("context/{ctx}/merkle_event_log/g{generation:020}/"))
}

/// Builds the key of the unit whose first entry has sequence `base_seq`.
///
/// Format: `context/{context_id}/merkle_event_log/g{gen:020d}/{base_seq:020d}`
/// Uses 20-digit zero-padding so key order is generation order, then
/// sequence order.
fn merkle_event_log_unit_key(
    context_id: &str,
    generation: u64,
    base_seq: u64,
) -> Result<String, StoreError> {
    let ctx = super::sanitize_key_component(context_id)?;
    Ok(format!(
        "context/{ctx}/merkle_event_log/g{generation:020}/{base_seq:020}"
    ))
}

/// The most entries a replace writes into one unit. A replace of `n` entries
/// makes `ceil(n / 256)` unit puts plus the `head` put, and this bound caps
/// the size of each stored value.
const MERKLE_EVENT_LOG_REPLACE_UNIT_ENTRIES: usize = 256;

/// The value of `merkle_event_log/head`: the generation that holds the live
/// log and the log's total entry count (spec section 17.3, "Merkle event log
/// entries"). A unit at or beyond `len` is left from an append that crashed
/// before its `head` put, or is another writer's append in flight; a load
/// ignores it and the next append at `len` overwrites it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
struct MerkleEventLogHead {
    /// The generation whose units form the live log.
    generation: u64,
    /// The number of entries in the live log.
    len: u64,
}

/// Converts an entry count to `u64`, the type of every stored sequence.
fn entry_count(n: usize) -> Result<u64, StoreError> {
    u64::try_from(n)
        .map_err(|_| StoreError::SerializationFailed("event log length exceeds u64".to_owned()))
}

/// Parses a generation directory name `g{gen:020d}`, accepting only the
/// canonical 20-digit form.
fn parse_generation_dir(name: &str) -> Option<u64> {
    let digits = name.strip_prefix('g')?;
    digits
        .parse()
        .ok()
        .filter(|generation: &u64| format!("{generation:020}") == digits)
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

    /// Stores one unit of `MerkleEventLogProvider` entries: `entries[0]` has
    /// sequence `base_seq` and the rest follow it in order.
    ///
    /// Puts the unit under the generation that `merkle_event_log/head` names,
    /// then puts `head` with its length raised by the unit's entry count. A
    /// failure between the two puts leaves a unit at the old length, which a
    /// load ignores, so storage holds either every entry of the unit or none
    /// of them. When no `head` exists, the unit becomes a whole new log
    /// through [`Self::replace_merkle_event_log_entries`] (spec section 17.3,
    /// "Merkle event log entries").
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::SerializationFailed`] if `entries` is empty,
    /// serialization fails, or the length would overflow.
    /// Returns [`StoreError::EventLogUnitMisaligned`] if `base_seq` differs
    /// from the stored log's length (0 when no `head` exists).
    /// Returns [`StoreError::Storage`] if a storage read or write fails.
    pub(crate) async fn store_merkle_event_log_unit(
        &self,
        context_id: &str,
        base_seq: u64,
        entries: &[scp_event_log::Event],
    ) -> Result<(), StoreError> {
        if entries.is_empty() {
            return Err(StoreError::SerializationFailed(
                "an event log unit holds at least one entry".to_owned(),
            ));
        }
        let head_key = merkle_event_log_head_key(context_id)?;
        let Some(head) = self.load_value::<MerkleEventLogHead>(&head_key).await? else {
            if base_seq != 0 {
                return Err(StoreError::EventLogUnitMisaligned {
                    base_seq,
                    expected: 0,
                });
            }
            return self
                .replace_merkle_event_log_entries(context_id, entries)
                .await;
        };
        if base_seq != head.len {
            return Err(StoreError::EventLogUnitMisaligned {
                base_seq,
                expected: head.len,
            });
        }
        let len = head
            .len
            .checked_add(entry_count(entries.len())?)
            .ok_or_else(|| {
                StoreError::SerializationFailed("event log length overflowed".to_owned())
            })?;
        let key = merkle_event_log_unit_key(context_id, head.generation, base_seq)?;
        self.store_value(&key, &entries).await?;
        // Commit point: from here on, a load includes the unit.
        self.store_value(
            &head_key,
            &MerkleEventLogHead {
                generation: head.generation,
                len,
            },
        )
        .await
    }

    /// Replaces a context's whole `MerkleEventLogProvider` log with `entries`.
    ///
    /// Deletes any keys left under generation `gen + 1` (generation 0 when no
    /// `head` exists), writes `entries` as units under that generation, and
    /// then puts `head` naming that generation and `entries.len()`. The
    /// `head` put is the commit point: an error before it leaves the old log
    /// loadable, and once it lands the new log is loadable. Deleting the old
    /// generation afterwards is best-effort, because
    /// [`Self::load_merkle_event_log_entries`] deletes every generation below
    /// `head`'s. Used by prune, import, and init.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::SerializationFailed`] if serialization fails or
    /// the generation number would overflow.
    /// Returns [`StoreError::Storage`] if a storage read or write before the
    /// commit point fails.
    pub(crate) async fn replace_merkle_event_log_entries(
        &self,
        context_id: &str,
        entries: &[scp_event_log::Event],
    ) -> Result<(), StoreError> {
        let head_key = merkle_event_log_head_key(context_id)?;
        let old_generation = self
            .load_value::<MerkleEventLogHead>(&head_key)
            .await?
            .map(|head| head.generation);
        let generation = match old_generation {
            None => 0,
            Some(old) => old.checked_add(1).ok_or_else(|| {
                StoreError::SerializationFailed("event log generation number overflowed".to_owned())
            })?,
        };

        // A replace that failed before its head put can have left units
        // under this generation; none of them may join the new log.
        let generation_prefix = merkle_event_log_generation_prefix(context_id, generation)?;
        self.storage.delete_prefix(&generation_prefix).await?;

        let mut base_seq: u64 = 0;
        for unit in entries.chunks(MERKLE_EVENT_LOG_REPLACE_UNIT_ENTRIES) {
            let key = merkle_event_log_unit_key(context_id, generation, base_seq)?;
            self.store_value(&key, &unit).await?;
            base_seq = base_seq
                .checked_add(entry_count(unit.len())?)
                .ok_or_else(|| {
                    StoreError::SerializationFailed("event log sequence overflowed".to_owned())
                })?;
        }

        // Commit point: from here on, a load reads the new generation.
        self.store_value(
            &head_key,
            &MerkleEventLogHead {
                generation,
                len: base_seq,
            },
        )
        .await?;

        if let Some(old) = old_generation {
            let old_prefix = merkle_event_log_generation_prefix(context_id, old)?;
            if let Err(e) = self.storage.delete_prefix(&old_prefix).await {
                tracing::warn!(
                    context_id,
                    generation = old,
                    error = %e,
                    "deleting the replaced event log generation failed; the next load deletes it"
                );
            }
        }
        Ok(())
    }

    /// Loads a context's `MerkleEventLogProvider` log.
    ///
    /// Reads `merkle_event_log/head`, then the units under the generation it
    /// names in key order, up to the length it records. Returns `None` when
    /// no `head` exists, and then deletes nothing. Deletes, best-effort, every
    /// generation below `head`'s, which a replace or a destroy left behind.
    /// Ignores, and never deletes, a unit at or beyond the recorded length:
    /// an append that failed before its `head` put left it, or another
    /// writer's append is in flight, and the next append at that length
    /// overwrites it. A generation above `head`'s can be a replace still in
    /// flight, so load leaves it in place.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::EventLogUnitMisaligned`] if a unit's `base_seq`
    /// differs from the number of entries in the units before it (a gap or an
    /// overlap).
    /// Returns [`StoreError::EventLogLengthMismatch`] if the units below the
    /// recorded length do not hold exactly that many entries, for example
    /// because a tail unit is missing.
    /// Returns [`StoreError::DeserializationFailed`] if a unit key does not
    /// parse, a unit is empty, or deserialization fails.
    /// Returns [`StoreError::Storage`] if a storage read fails.
    pub async fn load_merkle_event_log_entries(
        &self,
        context_id: &str,
    ) -> Result<Option<Vec<scp_event_log::Event>>, StoreError> {
        let head_key = merkle_event_log_head_key(context_id)?;
        let Some(head) = self.load_value::<MerkleEventLogHead>(&head_key).await? else {
            return Ok(None);
        };
        let prefix = merkle_event_log_prefix(context_id)?;
        let live_prefix = merkle_event_log_generation_prefix(context_id, head.generation)?;

        let mut keys = self.storage.list_keys(&prefix).await?;
        keys.sort_unstable();

        let mut unit_keys = Vec::new();
        let mut stale_generations = std::collections::BTreeSet::new();
        for key in keys {
            if key.starts_with(&live_prefix) {
                unit_keys.push(key);
                continue;
            }
            let rest = key.get(prefix.len()..).unwrap_or_default();
            if let Some((dir, _)) = rest.split_once('/')
                && parse_generation_dir(dir).is_some_and(|generation| generation < head.generation)
            {
                stale_generations.insert(format!("{prefix}{dir}/"));
            }
        }

        let mut entries: Vec<scp_event_log::Event> = Vec::new();
        for key in unit_keys {
            let suffix = key.get(live_prefix.len()..).unwrap_or_default();
            let base_seq: u64 = suffix
                .parse()
                .ok()
                .filter(|seq: &u64| format!("{seq:020}") == suffix)
                .ok_or_else(|| {
                    StoreError::DeserializationFailed(format!(
                        "event log unit key does not end in a 20-digit sequence: {key}"
                    ))
                })?;
            // A unit at or beyond `len` is not part of the log: an append
            // whose `head` put failed, or one still in flight, left it. Load
            // ignores it and never deletes it; the next append at `len`
            // overwrites it, and a replace's generation cleanup removes it.
            if base_seq >= head.len {
                continue;
            }
            let expected = entry_count(entries.len())?;
            if base_seq != expected {
                return Err(StoreError::EventLogUnitMisaligned { base_seq, expected });
            }
            let unit: Vec<scp_event_log::Event> =
                self.load_value(&key).await?.ok_or_else(|| {
                    StoreError::DeserializationFailed(format!(
                        "event log unit missing after list_keys: {key}"
                    ))
                })?;
            if unit.is_empty() {
                return Err(StoreError::DeserializationFailed(format!(
                    "event log unit holds no entries: {key}"
                )));
            }
            entries.extend(unit);
        }
        let loaded = entry_count(entries.len())?;
        if loaded != head.len {
            return Err(StoreError::EventLogLengthMismatch {
                head_len: head.len,
                loaded,
            });
        }
        self.delete_stale_event_log_generations(context_id, &stale_generations)
            .await;
        Ok(Some(entries))
    }

    /// Deletes a context's `MerkleEventLogProvider` log.
    ///
    /// Deletes `merkle_event_log/head` first, which removes the log, and then
    /// deletes every generation best-effort. A generation this call left
    /// behind never joins a later log: the next replace deletes the
    /// generation it writes before writing it, and a load deletes the
    /// generations below `head`'s.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Storage`] if deleting `head` fails.
    pub async fn delete_merkle_event_log_entries(
        &self,
        context_id: &str,
    ) -> Result<(), StoreError> {
        let head_key = merkle_event_log_head_key(context_id)?;
        self.storage.delete(&head_key).await?;
        let prefix = merkle_event_log_prefix(context_id)?;
        if let Err(e) = self.storage.delete_prefix(&prefix).await {
            tracing::warn!(
                context_id,
                error = %e,
                "deleting the destroyed event log's generations failed; a later replace or load deletes them"
            );
        }
        Ok(())
    }

    /// Deletes, best-effort, the generations below `head`'s.
    async fn delete_stale_event_log_generations(
        &self,
        context_id: &str,
        stale_generations: &std::collections::BTreeSet<String>,
    ) {
        for stale in stale_generations {
            if let Err(e) = self.storage.delete_prefix(stale).await {
                tracing::warn!(
                    context_id,
                    prefix = %stale,
                    error = %e,
                    "deleting a stale event log generation failed; the next load retries"
                );
            }
        }
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
    use scp_platform::in_memory::InMemoryStorage;

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
            actor_did: scp_did::DID(actor.to_owned()),
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
    // Merkle event log persistence tests (spec section 17.3, "Merkle event
    // log entries")
    // -------------------------------------------------------------------

    type FaultyRepository = ProtocolRepository<
        std::sync::Arc<crate::context::supervisor::faulty_storage::FaultyStorage>,
    >;

    fn make_faulty_store() -> (
        FaultyRepository,
        std::sync::Arc<crate::context::supervisor::faulty_storage::FaultyStorage>,
    ) {
        let faulty = std::sync::Arc::new(
            crate::context::supervisor::faulty_storage::FaultyStorage::new(std::sync::Arc::new(
                InMemoryStorage::new(),
            )),
        );
        (
            ProtocolRepository::new_for_testing(std::sync::Arc::clone(&faulty)),
            faulty,
        )
    }

    /// `n` events with sequences `first..first + n`, each with a distinct
    /// timestamp.
    fn merkle_events(first: u64, n: u64) -> Vec<scp_event_log::Event> {
        (first..first + n)
            .map(|seq| make_test_event(seq, scp_event_log::EventType::MessageSent, ""))
            .collect()
    }

    /// Byte-exact identity of a log, since `Event` has no `PartialEq`.
    fn log_bytes(entries: &[scp_event_log::Event]) -> Vec<u8> {
        rmp_serde::to_vec(entries).unwrap()
    }

    #[test]
    fn merkle_event_log_keys_follow_convention() {
        assert_eq!(
            merkle_event_log_prefix("ctx-123").unwrap(),
            "context/ctx-123/merkle_event_log/"
        );
        assert_eq!(
            merkle_event_log_head_key("ctx-123").unwrap(),
            "context/ctx-123/merkle_event_log/head"
        );
        assert_eq!(
            merkle_event_log_generation_prefix("ctx-123", 7).unwrap(),
            "context/ctx-123/merkle_event_log/g00000000000000000007/"
        );
        assert_eq!(
            merkle_event_log_unit_key("ctx-123", 7, 42).unwrap(),
            "context/ctx-123/merkle_event_log/g00000000000000000007/00000000000000000042"
        );
    }

    #[tokio::test]
    async fn first_unit_without_head_starts_a_log() {
        let store = make_store();
        let entries = merkle_events(0, 1);
        store
            .store_merkle_event_log_unit("ctx-1", 0, &entries)
            .await
            .unwrap();
        let loaded = store
            .load_merkle_event_log_entries("ctx-1")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(log_bytes(&loaded), log_bytes(&entries));
        assert_eq!(
            store
                .load_value::<MerkleEventLogHead>("context/ctx-1/merkle_event_log/head")
                .await
                .unwrap(),
            Some(MerkleEventLogHead {
                generation: 0,
                len: 1
            })
        );
    }

    #[tokio::test]
    async fn unit_without_head_must_start_at_zero() {
        let store = make_store();
        let err = store
            .store_merkle_event_log_unit("ctx-1", 3, &merkle_events(3, 1))
            .await
            .unwrap_err();
        assert!(
            matches!(
                err,
                StoreError::EventLogUnitMisaligned {
                    base_seq: 3,
                    expected: 0
                }
            ),
            "got {err:?}"
        );
        assert!(
            store
                .load_merkle_event_log_entries("ctx-1")
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn empty_unit_is_rejected() {
        let store = make_store();
        let err = store
            .store_merkle_event_log_unit("ctx-1", 0, &[])
            .await
            .unwrap_err();
        assert!(
            matches!(err, StoreError::SerializationFailed(_)),
            "got {err:?}"
        );
    }

    #[tokio::test]
    async fn units_and_replace_roundtrip_in_order() {
        let store = make_store();
        let mut expected = merkle_events(0, 2);
        store
            .replace_merkle_event_log_entries("ctx-1", &expected)
            .await
            .unwrap();
        let unit = merkle_events(2, 3);
        store
            .store_merkle_event_log_unit("ctx-1", 2, &unit)
            .await
            .unwrap();
        let single = merkle_events(5, 1);
        store
            .store_merkle_event_log_unit("ctx-1", 5, &single)
            .await
            .unwrap();
        expected.extend(unit);
        expected.extend(single);
        let loaded = store
            .load_merkle_event_log_entries("ctx-1")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(log_bytes(&loaded), log_bytes(&expected));
    }

    #[tokio::test]
    async fn replace_spans_several_units_and_drops_the_old_generation() {
        let store = make_store();
        store
            .replace_merkle_event_log_entries("ctx-1", &merkle_events(0, 5))
            .await
            .unwrap();
        let big = merkle_events(
            0,
            u64::try_from(2 * MERKLE_EVENT_LOG_REPLACE_UNIT_ENTRIES + 3).unwrap(),
        );
        store
            .replace_merkle_event_log_entries("ctx-1", &big)
            .await
            .unwrap();

        let loaded = store
            .load_merkle_event_log_entries("ctx-1")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(log_bytes(&loaded), log_bytes(&big));

        let mut keys = store
            .storage
            .list_keys("context/ctx-1/merkle_event_log/")
            .await
            .unwrap();
        keys.sort();
        assert_eq!(
            keys,
            vec![
                "context/ctx-1/merkle_event_log/g00000000000000000001/00000000000000000000",
                "context/ctx-1/merkle_event_log/g00000000000000000001/00000000000000000256",
                "context/ctx-1/merkle_event_log/g00000000000000000001/00000000000000000512",
                "context/ctx-1/merkle_event_log/head",
            ]
        );
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
        let store = make_store();
        store
            .replace_merkle_event_log_entries("ctx-del", &merkle_events(0, 3))
            .await
            .unwrap();
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
        assert!(
            store
                .storage
                .list_keys("context/ctx-del/merkle_event_log/")
                .await
                .unwrap()
                .is_empty()
        );
    }

    /// A destroy whose generation delete fails still removes the log, because
    /// it deletes `head` first; the next replace into that generation does
    /// not pick up the leftover units.
    #[tokio::test]
    async fn delete_with_failed_generation_delete_still_removes_the_log() {
        let (store, faulty) = make_faulty_store();
        store
            .replace_merkle_event_log_entries("ctx-del", &merkle_events(0, 3))
            .await
            .unwrap();
        faulty.fail_delete_prefix_calls("context/ctx-del/merkle_event_log/");
        store
            .delete_merkle_event_log_entries("ctx-del")
            .await
            .unwrap();
        faulty.clear_fail();
        assert!(
            store
                .load_merkle_event_log_entries("ctx-del")
                .await
                .unwrap()
                .is_none()
        );
        let new = merkle_events(0, 1);
        store
            .replace_merkle_event_log_entries("ctx-del", &new)
            .await
            .unwrap();
        let loaded = store
            .load_merkle_event_log_entries("ctx-del")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(log_bytes(&loaded), log_bytes(&new));
    }

    /// A replace whose put fails at any point leaves exactly the old log or
    /// exactly the new one loadable, never a mix or a prefix.
    #[tokio::test]
    async fn replace_failing_at_any_put_loads_old_or_new() {
        let old = merkle_events(100, 5);
        let new = merkle_events(
            0,
            u64::try_from(2 * MERKLE_EVENT_LOG_REPLACE_UNIT_ENTRIES + 3).unwrap(),
        );
        let (mut saw_old, mut saw_new) = (false, false);
        // Three unit puts and the head put; N = 5 lets every put succeed.
        for n in 1..=5 {
            let (store, faulty) = make_faulty_store();
            store
                .replace_merkle_event_log_entries("ctx-1", &old)
                .await
                .unwrap();
            faulty.fail_nth_store(n);
            let result = store.replace_merkle_event_log_entries("ctx-1", &new).await;
            faulty.clear_fail();
            let loaded = store
                .load_merkle_event_log_entries("ctx-1")
                .await
                .unwrap()
                .unwrap();
            if log_bytes(&loaded) == log_bytes(&old) {
                assert!(
                    result.is_err(),
                    "N={n}: an Ok replace must load the new log"
                );
                saw_old = true;
            } else {
                assert_eq!(
                    log_bytes(&loaded),
                    log_bytes(&new),
                    "N={n}: a failed replace loaded {} entries, neither the old log nor the new one",
                    loaded.len()
                );
                saw_new = true;
            }
        }
        assert!(saw_old && saw_new, "the sweep must reach both outcomes");
    }

    /// The old generation's delete runs after the head put, so its failure
    /// does not undo the replace: the new log loads, and that load deletes
    /// the old generation.
    #[tokio::test]
    async fn failed_old_generation_delete_after_head_put_loads_new_log() {
        let (store, faulty) = make_faulty_store();
        let old = merkle_events(100, 4);
        let new = merkle_events(0, 2);
        store
            .replace_merkle_event_log_entries("ctx-1", &old)
            .await
            .unwrap();
        faulty.fail_delete_prefix_calls("context/ctx-1/merkle_event_log/g00000000000000000000/");
        store
            .replace_merkle_event_log_entries("ctx-1", &new)
            .await
            .unwrap();
        let loaded = store
            .load_merkle_event_log_entries("ctx-1")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(log_bytes(&loaded), log_bytes(&new));

        faulty.clear_fail();
        let loaded = store
            .load_merkle_event_log_entries("ctx-1")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(log_bytes(&loaded), log_bytes(&new));
        let keys = store
            .storage
            .list_keys("context/ctx-1/merkle_event_log/g00000000000000000000/")
            .await
            .unwrap();
        assert!(
            keys.is_empty(),
            "the load deletes the replaced generation: {keys:?}"
        );
    }

    /// A k-entry unit whose persist fails leaves none of its entries visible.
    #[tokio::test]
    async fn failed_unit_persist_leaves_none_of_its_entries() {
        let base = merkle_events(0, 2);
        let unit = merkle_events(2, 3);
        let mut with_unit = base.clone();
        with_unit.extend(unit.iter().cloned());
        // The first `store` after arming is the unit's first put.
        for n in 1..=u64::try_from(unit.len()).unwrap() {
            let (store, faulty) = make_faulty_store();
            store
                .replace_merkle_event_log_entries("ctx-1", &base)
                .await
                .unwrap();
            faulty.fail_nth_store(n);
            let result = store.store_merkle_event_log_unit("ctx-1", 2, &unit).await;
            faulty.clear_fail();
            let loaded = store
                .load_merkle_event_log_entries("ctx-1")
                .await
                .unwrap()
                .unwrap();
            if result.is_err() {
                assert_eq!(
                    log_bytes(&loaded),
                    log_bytes(&base),
                    "N={n}: a failed unit persist left {} of its {} entries visible",
                    loaded.len() - base.len(),
                    unit.len()
                );
            } else {
                assert_eq!(log_bytes(&loaded), log_bytes(&with_unit), "N={n}");
            }
        }
        // N = 1 always fails the unit's put.
        let (store, faulty) = make_faulty_store();
        store
            .replace_merkle_event_log_entries("ctx-1", &base)
            .await
            .unwrap();
        faulty.fail_nth_store(1);
        assert!(
            store
                .store_merkle_event_log_unit("ctx-1", 2, &unit)
                .await
                .is_err()
        );
    }

    /// Writes `head` and the given `(generation, base_seq, n)` units
    /// directly, bypassing the write methods, to model a stored log those
    /// methods cannot produce.
    async fn write_raw_log(
        store: &ProtocolRepository<InMemoryStorage>,
        head: MerkleEventLogHead,
        units: &[(u64, u64, u64)],
    ) {
        store
            .store_value("context/ctx-1/merkle_event_log/head", &head)
            .await
            .unwrap();
        for &(generation, base_seq, n) in units {
            store
                .store_value(
                    &merkle_event_log_unit_key("ctx-1", generation, base_seq).unwrap(),
                    &merkle_events(base_seq, n),
                )
                .await
                .unwrap();
        }
    }

    #[tokio::test]
    async fn gap_between_units_is_a_typed_error() {
        let store = make_store();
        let head = MerkleEventLogHead {
            generation: 0,
            len: 6,
        };
        write_raw_log(&store, head, &[(0, 0, 2), (0, 5, 1)]).await;
        let err = store
            .load_merkle_event_log_entries("ctx-1")
            .await
            .unwrap_err();
        assert!(
            matches!(
                err,
                StoreError::EventLogUnitMisaligned {
                    base_seq: 5,
                    expected: 2
                }
            ),
            "got {err:?}"
        );
    }

    #[tokio::test]
    async fn overlap_between_units_is_a_typed_error() {
        let store = make_store();
        let head = MerkleEventLogHead {
            generation: 0,
            len: 4,
        };
        write_raw_log(&store, head, &[(0, 0, 3), (0, 1, 1)]).await;
        let err = store
            .load_merkle_event_log_entries("ctx-1")
            .await
            .unwrap_err();
        assert!(
            matches!(
                err,
                StoreError::EventLogUnitMisaligned {
                    base_seq: 1,
                    expected: 3
                }
            ),
            "got {err:?}"
        );
    }

    /// A unit whose `base_seq` is not the stored log's length is refused
    /// before anything is written.
    #[tokio::test]
    async fn unit_must_start_at_the_head_length() {
        let store = make_store();
        let base = merkle_events(0, 3);
        store
            .replace_merkle_event_log_entries("ctx-1", &base)
            .await
            .unwrap();
        for base_seq in [1, 5] {
            let err = store
                .store_merkle_event_log_unit("ctx-1", base_seq, &merkle_events(base_seq, 1))
                .await
                .unwrap_err();
            assert!(
                matches!(
                    err,
                    StoreError::EventLogUnitMisaligned { base_seq: b, expected: 3 } if b == base_seq
                ),
                "base_seq {base_seq}: got {err:?}"
            );
        }
        let loaded = store
            .load_merkle_event_log_entries("ctx-1")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(log_bytes(&loaded), log_bytes(&base));
        assert!(
            store
                .storage
                .list_keys("context/ctx-1/merkle_event_log/g00000000000000000000/")
                .await
                .unwrap()
                .iter()
                .all(|key| key.ends_with("/00000000000000000000")),
            "a refused unit writes no key"
        );
    }

    /// A log whose last unit is gone loads as a typed error, never as the
    /// shorter log.
    #[tokio::test]
    async fn missing_tail_unit_is_a_length_mismatch() {
        let store = make_store();
        let entries = merkle_events(
            0,
            u64::try_from(MERKLE_EVENT_LOG_REPLACE_UNIT_ENTRIES + 4).unwrap(),
        );
        store
            .replace_merkle_event_log_entries("ctx-1", &entries)
            .await
            .unwrap();
        store
            .storage
            .delete(&merkle_event_log_unit_key("ctx-1", 0, 256).unwrap())
            .await
            .unwrap();
        let err = store
            .load_merkle_event_log_entries("ctx-1")
            .await
            .unwrap_err();
        assert!(
            matches!(
                err,
                StoreError::EventLogLengthMismatch {
                    head_len: 260,
                    loaded: 256
                }
            ),
            "got {err:?}"
        );
    }

    /// A unit at or beyond the head's length, which an append that failed
    /// before its `head` put leaves, is ignored and left in place: another
    /// writer may be mid-append. The next append at the head's length
    /// overwrites it, and the log then loads with that append's entries.
    #[tokio::test]
    async fn unit_beyond_the_head_length_is_ignored_and_kept() {
        let store = make_store();
        let base = merkle_events(0, 2);
        store
            .replace_merkle_event_log_entries("ctx-1", &base)
            .await
            .unwrap();
        let orphan = merkle_event_log_unit_key("ctx-1", 0, 2).unwrap();
        store
            .store_value(&orphan, &merkle_events(2, 1))
            .await
            .unwrap();
        let loaded = store
            .load_merkle_event_log_entries("ctx-1")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(log_bytes(&loaded), log_bytes(&base));
        assert!(
            store.storage.exists(&orphan).await.unwrap(),
            "the load leaves the unit beyond the head's length in place"
        );

        // The next append at the head's length overwrites the orphan.
        let mut next = merkle_events(2, 1);
        next[0].timestamp += 1;
        store
            .store_merkle_event_log_unit("ctx-1", 2, &next)
            .await
            .unwrap();
        let loaded = store
            .load_merkle_event_log_entries("ctx-1")
            .await
            .unwrap()
            .unwrap();
        let mut expected = base.clone();
        expected.extend(next);
        assert_eq!(log_bytes(&loaded), log_bytes(&expected));
    }

    /// Load deletes a generation below the head's and leaves one above it,
    /// which can be a replace still in flight.
    #[tokio::test]
    async fn load_deletes_only_generations_below_the_head() {
        let store = make_store();
        let head = MerkleEventLogHead {
            generation: 5,
            len: 1,
        };
        write_raw_log(&store, head, &[(4, 0, 2), (5, 0, 1), (6, 0, 3)]).await;
        let loaded = store
            .load_merkle_event_log_entries("ctx-1")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(log_bytes(&loaded), log_bytes(&merkle_events(0, 1)));
        assert!(
            !store
                .storage
                .exists(&merkle_event_log_unit_key("ctx-1", 4, 0).unwrap())
                .await
                .unwrap(),
            "a generation below the head's is deleted"
        );
        assert!(
            store
                .storage
                .exists(&merkle_event_log_unit_key("ctx-1", 6, 0).unwrap())
                .await
                .unwrap(),
            "a generation above the head's stays in place"
        );
    }

    /// On `FilesystemStorage`, a temp file that a crashed put left under the
    /// live generation is not a unit: the log loads, and the temp file is not
    /// read as a misaligned or undecodable unit.
    #[tokio::test]
    async fn log_loads_with_a_leftover_temp_file_in_its_generation() {
        let dir = std::env::temp_dir().join(format!(
            "scp-event-log-tmp-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let store = ProtocolRepository::new_for_testing(
            scp_platform::filesystem::FilesystemStorage::new(&dir).unwrap(),
        );
        let entries = merkle_events(0, 2);
        store
            .replace_merkle_event_log_entries("ctx-1", &entries)
            .await
            .unwrap();
        let generation_dir = dir
            .join("context")
            .join("ctx-1")
            .join("merkle_event_log")
            .join("g00000000000000000000");
        std::fs::write(generation_dir.join(".tmp.1.2.3"), b"half-written").unwrap();

        let loaded = store.load_merkle_event_log_entries("ctx-1").await;
        std::fs::remove_dir_all(&dir).unwrap();
        assert_eq!(log_bytes(&loaded.unwrap().unwrap()), log_bytes(&entries));
    }

    /// A unit key that does not end in a canonical 20-digit sequence is a
    /// typed error, not a silently skipped unit.
    #[tokio::test]
    async fn non_canonical_unit_key_is_a_typed_error() {
        let store = make_store();
        store
            .replace_merkle_event_log_entries("ctx-1", &merkle_events(0, 1))
            .await
            .unwrap();
        store
            .store_value(
                "context/ctx-1/merkle_event_log/g00000000000000000000/1",
                &merkle_events(1, 1),
            )
            .await
            .unwrap();
        let err = store
            .load_merkle_event_log_entries("ctx-1")
            .await
            .unwrap_err();
        assert!(
            matches!(err, StoreError::DeserializationFailed(_)),
            "got {err:?}"
        );
    }
}
