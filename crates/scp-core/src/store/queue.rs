//! Client-side outbound queue storage for `ProtocolStore`.
//!
//! When the SDK detects disconnection (all relay WebSocket connections lost),
//! outbound messages are queued locally rather than dropped. Messages are
//! serialized to their inner envelope form (signed, padded, NOT MLS-encrypted)
//! and stored under `queue/{context_id}/{seq:020d}`. MLS encryption is applied
//! at drain time using the then-current epoch.
//!
//! # Bounds
//!
//! - **Per-context:** 1,000 messages. When full, the oldest messages are dropped
//!   with a `QueueOverflow` event emitted.
//! - **Global:** 10,000 messages total across all contexts. Same overflow behavior.
//!
//! # TTL Expiry
//!
//! On reconnection, entries older than the context's `blob_ttl` (or 7 days if no
//! TTL is set) are discarded -- they would expire on relays before delivery anyway.
//!
//! See spec section 23.2. See GitHub issue #583.

use scp_platform::traits::Storage;
use serde::{Deserialize, Serialize};

use super::{ProtocolStore, StoreError};

// ---------------------------------------------------------------------------
// Constants (spec section 23.2)
// ---------------------------------------------------------------------------

/// Maximum number of queued messages per context.
pub const MAX_QUEUE_PER_CONTEXT: u64 = 1_000;

/// Maximum number of queued messages across all contexts.
pub const MAX_QUEUE_GLOBAL: u64 = 10_000;

/// Default TTL for queue entries when the context has no `blob_ttl`: 7 days.
pub const DEFAULT_QUEUE_TTL_SECS: u64 = 7 * 24 * 3600;

// ---------------------------------------------------------------------------
// QueueEntry
// ---------------------------------------------------------------------------

/// A queued outbound message entry.
///
/// Stores the inner envelope bytes (signed, padded, NOT MLS-encrypted) along
/// with the timestamp when the message was queued. MLS encryption is deferred
/// to drain time (spec section 23.2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QueueEntry {
    /// The serialized inner envelope bytes (signed, padded).
    #[serde(with = "serde_bytes")]
    pub inner_envelope: Vec<u8>,
    /// Unix timestamp (seconds) when this message was queued.
    pub queued_at: u64,
    /// Content-addressable hash for multi-device queue deduplication (spec
    /// section 23.8). SHA-256 of the inner envelope bytes.
    pub content_hash: [u8; 32],
}

// ---------------------------------------------------------------------------
// QueueOverflowInfo
// ---------------------------------------------------------------------------

/// Information about a queue overflow event, emitted to the application layer
/// when messages are dropped due to queue bounds.
///
/// See spec section 23.2.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QueueOverflowInfo {
    /// The context where the overflow occurred.
    pub context_id: String,
    /// Number of messages dropped.
    pub messages_dropped: u64,
    /// Whether the overflow was due to the per-context bound or the global bound.
    pub overflow_kind: OverflowKind,
}

/// Whether a queue overflow was caused by the per-context bound or the global bound.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum OverflowKind {
    /// Per-context limit exceeded (1,000 messages).
    PerContext,
    /// Global limit exceeded (10,000 messages total).
    Global,
}

impl std::fmt::Display for OverflowKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PerContext => write!(f, "per-context ({MAX_QUEUE_PER_CONTEXT})"),
            Self::Global => write!(f, "global ({MAX_QUEUE_GLOBAL})"),
        }
    }
}

// ---------------------------------------------------------------------------
// Key helpers
// ---------------------------------------------------------------------------

/// Builds the storage key for a queue entry.
///
/// Format: `queue/{context_id}/{seq:020d}`
/// Uses 20-digit zero-padding for lexicographic ordering.
/// See spec section 23.2.
fn queue_entry_key(context_id: &str, seq: u64) -> Result<String, StoreError> {
    let ctx = super::sanitize_key_component(context_id)?;
    Ok(format!("queue/{ctx}/{seq:020}"))
}

/// Builds the prefix for listing all queue entries in a context.
///
/// Format: `queue/{context_id}/`
fn queue_context_prefix(context_id: &str) -> Result<String, StoreError> {
    let ctx = super::sanitize_key_component(context_id)?;
    Ok(format!("queue/{ctx}/"))
}

/// Builds the storage key for the per-context queue sequence counter.
///
/// Format: `queue/{context_id}/_seq`
/// The underscore (`0x5F`) sorts after digits (`0x30`-`0x39`), so this
/// metadata key sorts after all zero-padded sequence number entries.
fn queue_seq_key(context_id: &str) -> Result<String, StoreError> {
    let ctx = super::sanitize_key_component(context_id)?;
    Ok(format!("queue/{ctx}/_seq"))
}

/// Prefix for listing all queue entries across all contexts.
const QUEUE_GLOBAL_PREFIX: &str = "queue/";

/// Storage key for the global queue count.
const QUEUE_GLOBAL_COUNT_KEY: &str = "_meta/queue_global_count";

// ---------------------------------------------------------------------------
// ProtocolStore — outbound queue methods (spec §23.2, issue #583)
// ---------------------------------------------------------------------------

impl<S: Storage> ProtocolStore<S> {
    /// Enqueues an outbound message for a context.
    ///
    /// The `inner_envelope` bytes must be the fully constructed inner envelope
    /// (signed, padded) but NOT MLS-encrypted. MLS encryption is applied at
    /// drain time using the then-current epoch (spec section 23.2).
    ///
    /// Returns `Ok(None)` on success, or `Ok(Some(QueueOverflowInfo))` if
    /// messages were dropped to stay within bounds. The oldest messages in the
    /// context are dropped first.
    ///
    /// # Arguments
    ///
    /// * `context_id` — The context to queue the message for.
    /// * `inner_envelope` — Serialized inner envelope bytes (signed, padded).
    /// * `queued_at` — Unix timestamp (seconds) when this message was composed.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::SerializationFailed`] if serialization fails.
    /// Returns [`StoreError::Storage`] if the underlying storage write fails.
    pub async fn enqueue_message(
        &self,
        context_id: &str,
        inner_envelope: &[u8],
        queued_at: u64,
    ) -> Result<Option<QueueOverflowInfo>, StoreError> {
        // Compute content hash for multi-device dedup (§23.8).
        let content_hash = {
            use sha2::{Digest, Sha256};
            let mut hasher = Sha256::new();
            hasher.update(inner_envelope);
            let result = hasher.finalize();
            let mut hash = [0u8; 32];
            hash.copy_from_slice(&result);
            hash
        };

        let entry = QueueEntry {
            inner_envelope: inner_envelope.to_vec(),
            queued_at,
            content_hash,
        };

        // Read the global count BEFORE storing the entry to avoid the
        // fallback scan (which lists keys) double-counting the new entry.
        let old_global_count = self.queue_global_count().await?;

        // Allocate the next sequence number for this context.
        let seq = self.next_queue_seq(context_id).await?;

        // Store the entry.
        let key = queue_entry_key(context_id, seq)?;
        self.store_value(&key, &entry).await?;

        // Persist the incremented global count.
        let new_global_count = old_global_count + 1;
        self.store_value(QUEUE_GLOBAL_COUNT_KEY, &new_global_count)
            .await?;

        // Enforce per-context bound.
        let mut per_ctx_overflow = None;
        let ctx_count = self.queue_context_count(context_id).await?;
        if ctx_count > MAX_QUEUE_PER_CONTEXT {
            per_ctx_overflow = Some(
                self.enforce_per_context_bound(context_id, ctx_count)
                    .await?,
            );
        }

        // Always check the global bound — per-context enforcement may not
        // have removed enough to satisfy the global cap.  Re-read the global
        // count because `enforce_per_context_bound` updates it.
        let current_global = self.queue_global_count().await?;
        if current_global > MAX_QUEUE_GLOBAL {
            let overflow = self.enforce_global_bound(context_id).await?;
            return Ok(Some(overflow));
        }

        Ok(per_ctx_overflow)
    }

    /// Dequeues all messages for a context in queue order.
    ///
    /// Returns the queue entries sorted by sequence number (oldest first).
    /// Entries are removed from storage after retrieval.
    ///
    /// This is called during Phase 6 of the reconnection protocol (spec
    /// section 23.3). Each entry's inner envelope should be MLS-encrypted
    /// with the current epoch's key schedule before sending.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Storage`] if the underlying storage operation fails.
    /// Returns [`StoreError::DeserializationFailed`] if any entry fails to
    /// deserialize.
    pub async fn dequeue_messages(&self, context_id: &str) -> Result<Vec<QueueEntry>, StoreError> {
        let prefix = queue_context_prefix(context_id)?;
        let keys = self.storage.list_keys(&prefix).await?;

        let mut entries = Vec::new();
        let mut keys_to_delete = Vec::new();

        for key in &keys {
            // Skip metadata keys (e.g., `_seq`).
            if key.ends_with("/_seq") {
                continue;
            }
            if let Some(entry) = self.load_value::<QueueEntry>(key).await? {
                entries.push(entry);
                keys_to_delete.push(key.clone());
            }
        }

        // Delete all dequeued entries and the sequence counter.
        for key in &keys_to_delete {
            self.storage.delete(key).await?;
        }

        // Update global count.
        let removed = u64::try_from(keys_to_delete.len()).unwrap_or(u64::MAX);
        let global_count = self.queue_global_count().await?;
        let new_global = global_count.saturating_sub(removed);
        self.store_value(QUEUE_GLOBAL_COUNT_KEY, &new_global)
            .await?;

        // Reset the per-context sequence counter.
        let seq_key = queue_seq_key(context_id)?;
        self.storage.delete(&seq_key).await?;

        Ok(entries)
    }

    /// Prunes expired queue entries for a context based on TTL.
    ///
    /// Entries older than `max_age_secs` (relative to `now`) are discarded.
    /// Per spec section 23.2: "On reconnection, entries older than the context's
    /// `blob_ttl` (or 7 days if no TTL) are discarded."
    ///
    /// Returns the number of entries pruned.
    ///
    /// # Arguments
    ///
    /// * `context_id` — The context to prune.
    /// * `now` — Current Unix timestamp (seconds).
    /// * `max_age_secs` — Maximum age in seconds. Entries with
    ///   `queued_at + max_age_secs < now` are pruned. Pass the context's
    ///   `blob_ttl` or [`DEFAULT_QUEUE_TTL_SECS`] if no TTL is set.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Storage`] if the underlying storage operation fails.
    pub async fn prune_expired_queue(
        &self,
        context_id: &str,
        now: u64,
        max_age_secs: u64,
    ) -> Result<u64, StoreError> {
        let prefix = queue_context_prefix(context_id)?;
        let keys = self.storage.list_keys(&prefix).await?;

        let mut pruned = 0u64;
        for key in &keys {
            // Skip metadata keys.
            if key.ends_with("/_seq") {
                continue;
            }
            if let Some(entry) = self.load_value::<QueueEntry>(key).await? {
                // Check if the entry has expired.
                if entry.queued_at.saturating_add(max_age_secs) < now {
                    self.storage.delete(key).await?;
                    pruned += 1;
                }
            }
        }

        // Update global count.
        if pruned > 0 {
            let global_count = self.queue_global_count().await?;
            let new_global = global_count.saturating_sub(pruned);
            self.store_value(QUEUE_GLOBAL_COUNT_KEY, &new_global)
                .await?;
        }

        Ok(pruned)
    }

    /// Returns the number of queued messages for a specific context.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Storage`] if the underlying storage operation fails.
    pub async fn queue_context_count(&self, context_id: &str) -> Result<u64, StoreError> {
        let prefix = queue_context_prefix(context_id)?;
        let keys = self.storage.list_keys(&prefix).await?;
        // Exclude metadata keys (e.g., `_seq`).
        let count = keys.iter().filter(|k| !k.ends_with("/_seq")).count();
        Ok(u64::try_from(count).unwrap_or(u64::MAX))
    }

    /// Returns the total number of queued messages across all contexts.
    ///
    /// Uses the cached global count for O(1) lookups. Falls back to a full
    /// scan if the count is missing (e.g., after migration from a version
    /// that did not track the global count).
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Storage`] if the underlying storage operation fails.
    pub async fn queue_global_count(&self) -> Result<u64, StoreError> {
        let count: Option<u64> = self.load_value(QUEUE_GLOBAL_COUNT_KEY).await?;
        if let Some(c) = count {
            Ok(c)
        } else {
            // Fallback: scan all queue keys for migration compatibility.
            let keys = self.storage.list_keys(QUEUE_GLOBAL_PREFIX).await?;
            let total = keys.iter().filter(|k| !k.ends_with("/_seq")).count();
            let total_u64 = u64::try_from(total).unwrap_or(u64::MAX);
            // Cache the count so future lookups are O(1).
            self.store_value(QUEUE_GLOBAL_COUNT_KEY, &total_u64).await?;
            Ok(total_u64)
        }
    }

    /// Returns all context IDs that have queued messages.
    ///
    /// Scans the `queue/` key prefix and extracts unique context IDs.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Storage`] if the underlying storage operation fails.
    pub async fn queue_context_ids(&self) -> Result<Vec<String>, StoreError> {
        let keys = self.storage.list_keys(QUEUE_GLOBAL_PREFIX).await?;
        let mut context_ids = std::collections::BTreeSet::new();
        for key in &keys {
            // Keys have format: queue/{context_id}/{...}
            if let Some(rest) = key.strip_prefix(QUEUE_GLOBAL_PREFIX)
                && let Some(ctx_id) = rest.split('/').next()
            {
                context_ids.insert(ctx_id.to_owned());
            }
        }
        Ok(context_ids.into_iter().collect())
    }

    // -----------------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------------

    /// Allocates the next sequence number for a context's queue.
    ///
    /// Reads and increments the per-context sequence counter stored under
    /// `queue/{context_id}/_seq`. Returns the allocated sequence number.
    async fn next_queue_seq(&self, context_id: &str) -> Result<u64, StoreError> {
        let key = queue_seq_key(context_id)?;
        let current: Option<u64> = self.load_value(&key).await?;
        let seq = current.unwrap_or(0);
        self.store_value(&key, &(seq + 1)).await?;
        Ok(seq)
    }

    /// Enforces the per-context queue bound by removing the oldest entries.
    ///
    /// Removes entries until the context count is at or below
    /// [`MAX_QUEUE_PER_CONTEXT`]. Returns overflow info describing how many
    /// messages were dropped.
    async fn enforce_per_context_bound(
        &self,
        context_id: &str,
        current_count: u64,
    ) -> Result<QueueOverflowInfo, StoreError> {
        let excess = current_count.saturating_sub(MAX_QUEUE_PER_CONTEXT);
        let prefix = queue_context_prefix(context_id)?;
        let keys = self.storage.list_keys(&prefix).await?;

        // Keys are sorted lexicographically (oldest first due to zero-padding).
        let mut dropped = 0u64;
        for key in &keys {
            if dropped >= excess {
                break;
            }
            // Skip metadata keys.
            if key.ends_with("/_seq") {
                continue;
            }
            self.storage.delete(key).await?;
            dropped += 1;
        }

        // Update global count.
        let global_count = self.queue_global_count().await?;
        let new_global = global_count.saturating_sub(dropped);
        self.store_value(QUEUE_GLOBAL_COUNT_KEY, &new_global)
            .await?;

        Ok(QueueOverflowInfo {
            context_id: context_id.to_owned(),
            messages_dropped: dropped,
            overflow_kind: OverflowKind::PerContext,
        })
    }

    /// Enforces the global queue bound by removing the oldest entries across
    /// all contexts, ordered by `queued_at` timestamp (spec §23.2).
    ///
    /// Removes entries (oldest first across all contexts) until the global
    /// count is at or below [`MAX_QUEUE_GLOBAL`]. The `triggering_context_id`
    /// is used in the returned overflow info.
    async fn enforce_global_bound(
        &self,
        triggering_context_id: &str,
    ) -> Result<QueueOverflowInfo, StoreError> {
        let global_count = self.queue_global_count().await?;
        let excess = global_count.saturating_sub(MAX_QUEUE_GLOBAL);

        // List all queue keys globally.
        let all_keys = self.storage.list_keys(QUEUE_GLOBAL_PREFIX).await?;

        // Load entries with their keys so we can sort by queued_at (oldest
        // first), not by lexicographic key order (which sorts by context ID).
        let mut candidates: Vec<(String, u64)> = Vec::new();
        for key in &all_keys {
            if key.ends_with("/_seq") {
                continue;
            }
            if let Some(entry) = self.load_value::<QueueEntry>(key).await? {
                candidates.push((key.clone(), entry.queued_at));
            }
        }

        // Sort by queued_at ascending — oldest entries first.
        candidates.sort_by_key(|(_key, queued_at)| *queued_at);

        let mut dropped = 0u64;
        for (key, _queued_at) in &candidates {
            if dropped >= excess {
                break;
            }
            self.storage.delete(key).await?;
            dropped += 1;
        }

        // Update global count.
        let new_global = global_count.saturating_sub(dropped);
        self.store_value(QUEUE_GLOBAL_COUNT_KEY, &new_global)
            .await?;

        Ok(QueueOverflowInfo {
            context_id: triggering_context_id.to_owned(),
            messages_dropped: dropped,
            overflow_kind: OverflowKind::Global,
        })
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

    fn test_envelope(id: u8) -> Vec<u8> {
        vec![id; 64]
    }

    // -------------------------------------------------------------------
    // Key convention tests
    // -------------------------------------------------------------------

    #[test]
    fn queue_entry_key_follows_spec_convention() {
        let key = queue_entry_key("ctx-1", 0).unwrap();
        assert_eq!(key, "queue/ctx-1/00000000000000000000");

        let key = queue_entry_key("ctx-1", 42).unwrap();
        assert_eq!(key, "queue/ctx-1/00000000000000000042");
    }

    #[test]
    fn queue_entry_key_rejects_traversal() {
        assert!(queue_entry_key("../evil", 0).is_err());
        assert!(queue_entry_key("evil\\path", 0).is_err());
        assert!(queue_entry_key("evil\0id", 0).is_err());
    }

    #[test]
    fn queue_context_prefix_follows_convention() {
        let prefix = queue_context_prefix("ctx-123").unwrap();
        assert_eq!(prefix, "queue/ctx-123/");
    }

    // -------------------------------------------------------------------
    // Enqueue and dequeue
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn enqueue_and_dequeue_single_message() {
        let store = make_store();
        let envelope = test_envelope(0xAA);

        let overflow = store
            .enqueue_message("ctx-1", &envelope, 1_000_000)
            .await
            .unwrap();
        assert!(overflow.is_none());

        let entries = store.dequeue_messages("ctx-1").await.unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].inner_envelope, envelope);
        assert_eq!(entries[0].queued_at, 1_000_000);
    }

    #[tokio::test]
    async fn dequeue_preserves_queue_order() {
        let store = make_store();

        for i in 0u8..5 {
            store
                .enqueue_message("ctx-1", &test_envelope(i), 1_000_000 + u64::from(i))
                .await
                .unwrap();
        }

        let entries = store.dequeue_messages("ctx-1").await.unwrap();
        assert_eq!(entries.len(), 5);
        for (i, entry) in entries.iter().enumerate() {
            let expected_byte = u8::try_from(i).unwrap();
            assert_eq!(entry.inner_envelope, test_envelope(expected_byte));
            assert_eq!(entry.queued_at, 1_000_000 + i as u64);
        }
    }

    #[tokio::test]
    async fn dequeue_removes_entries_from_storage() {
        let store = make_store();

        store
            .enqueue_message("ctx-1", &test_envelope(1), 1_000_000)
            .await
            .unwrap();
        store
            .enqueue_message("ctx-1", &test_envelope(2), 1_000_001)
            .await
            .unwrap();

        let entries = store.dequeue_messages("ctx-1").await.unwrap();
        assert_eq!(entries.len(), 2);

        // Second dequeue should return empty.
        let entries = store.dequeue_messages("ctx-1").await.unwrap();
        assert!(entries.is_empty());
    }

    #[tokio::test]
    async fn dequeue_updates_global_count() {
        let store = make_store();

        store
            .enqueue_message("ctx-1", &test_envelope(1), 1_000_000)
            .await
            .unwrap();
        store
            .enqueue_message("ctx-2", &test_envelope(2), 1_000_001)
            .await
            .unwrap();

        assert_eq!(store.queue_global_count().await.unwrap(), 2);

        store.dequeue_messages("ctx-1").await.unwrap();
        assert_eq!(store.queue_global_count().await.unwrap(), 1);

        store.dequeue_messages("ctx-2").await.unwrap();
        assert_eq!(store.queue_global_count().await.unwrap(), 0);
    }

    #[tokio::test]
    async fn dequeue_empty_context_returns_empty() {
        let store = make_store();
        let entries = store.dequeue_messages("nonexistent").await.unwrap();
        assert!(entries.is_empty());
    }

    // -------------------------------------------------------------------
    // Context isolation
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn queues_are_context_scoped() {
        let store = make_store();

        store
            .enqueue_message("ctx-1", &test_envelope(0xAA), 1_000_000)
            .await
            .unwrap();
        store
            .enqueue_message("ctx-2", &test_envelope(0xBB), 1_000_001)
            .await
            .unwrap();

        let entries_1 = store.dequeue_messages("ctx-1").await.unwrap();
        assert_eq!(entries_1.len(), 1);
        assert_eq!(entries_1[0].inner_envelope, test_envelope(0xAA));

        let entries_2 = store.dequeue_messages("ctx-2").await.unwrap();
        assert_eq!(entries_2.len(), 1);
        assert_eq!(entries_2[0].inner_envelope, test_envelope(0xBB));
    }

    // -------------------------------------------------------------------
    // Content hash (multi-device dedup)
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn content_hash_is_sha256_of_inner_envelope() {
        use sha2::{Digest, Sha256};

        let store = make_store();
        let envelope = test_envelope(0xCC);

        store
            .enqueue_message("ctx-1", &envelope, 1_000_000)
            .await
            .unwrap();

        let entries = store.dequeue_messages("ctx-1").await.unwrap();
        assert_eq!(entries.len(), 1);

        // Verify the content hash matches SHA-256 of the envelope.
        let mut hasher = Sha256::new();
        hasher.update(&envelope);
        let expected: [u8; 32] = hasher.finalize().into();
        assert_eq!(entries[0].content_hash, expected);
    }

    // -------------------------------------------------------------------
    // Queue counting
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn queue_context_count_tracks_entries() {
        let store = make_store();

        assert_eq!(store.queue_context_count("ctx-1").await.unwrap(), 0);

        store
            .enqueue_message("ctx-1", &test_envelope(1), 1_000_000)
            .await
            .unwrap();
        assert_eq!(store.queue_context_count("ctx-1").await.unwrap(), 1);

        store
            .enqueue_message("ctx-1", &test_envelope(2), 1_000_001)
            .await
            .unwrap();
        assert_eq!(store.queue_context_count("ctx-1").await.unwrap(), 2);
    }

    #[tokio::test]
    async fn queue_global_count_tracks_all_contexts() {
        let store = make_store();

        assert_eq!(store.queue_global_count().await.unwrap(), 0);

        store
            .enqueue_message("ctx-1", &test_envelope(1), 1_000_000)
            .await
            .unwrap();
        store
            .enqueue_message("ctx-2", &test_envelope(2), 1_000_001)
            .await
            .unwrap();
        store
            .enqueue_message("ctx-1", &test_envelope(3), 1_000_002)
            .await
            .unwrap();

        assert_eq!(store.queue_global_count().await.unwrap(), 3);
    }

    // -------------------------------------------------------------------
    // Queue context IDs
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn queue_context_ids_returns_all_contexts_with_queued_messages() {
        let store = make_store();

        store
            .enqueue_message("ctx-alpha", &test_envelope(1), 1_000_000)
            .await
            .unwrap();
        store
            .enqueue_message("ctx-beta", &test_envelope(2), 1_000_001)
            .await
            .unwrap();
        store
            .enqueue_message("ctx-alpha", &test_envelope(3), 1_000_002)
            .await
            .unwrap();

        let ids = store.queue_context_ids().await.unwrap();
        assert_eq!(ids.len(), 2);
        assert!(ids.contains(&"ctx-alpha".to_owned()));
        assert!(ids.contains(&"ctx-beta".to_owned()));
    }

    // -------------------------------------------------------------------
    // TTL-based expiry
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn prune_expired_queue_removes_stale_entries() {
        let store = make_store();

        // Queue 3 messages at different times.
        store
            .enqueue_message("ctx-1", &test_envelope(1), 100)
            .await
            .unwrap();
        store
            .enqueue_message("ctx-1", &test_envelope(2), 200)
            .await
            .unwrap();
        store
            .enqueue_message("ctx-1", &test_envelope(3), 500)
            .await
            .unwrap();

        // Prune entries older than 200 seconds at now=400.
        // Entry 1: queued_at=100, 100+200=300 < 400 -> expired
        // Entry 2: queued_at=200, 200+200=400 >= 400 -> NOT expired (boundary)
        // Entry 3: queued_at=500, 500+200=700 >= 400 -> NOT expired
        let pruned = store.prune_expired_queue("ctx-1", 400, 200).await.unwrap();
        assert_eq!(pruned, 1);

        let entries = store.dequeue_messages("ctx-1").await.unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].queued_at, 200);
        assert_eq!(entries[1].queued_at, 500);
    }

    #[tokio::test]
    async fn prune_expired_queue_updates_global_count() {
        let store = make_store();

        store
            .enqueue_message("ctx-1", &test_envelope(1), 100)
            .await
            .unwrap();
        store
            .enqueue_message("ctx-2", &test_envelope(2), 200)
            .await
            .unwrap();

        assert_eq!(store.queue_global_count().await.unwrap(), 2);

        let pruned = store.prune_expired_queue("ctx-1", 500, 100).await.unwrap();
        assert_eq!(pruned, 1);
        assert_eq!(store.queue_global_count().await.unwrap(), 1);
    }

    #[tokio::test]
    async fn prune_expired_queue_no_expiry_returns_zero() {
        let store = make_store();

        store
            .enqueue_message("ctx-1", &test_envelope(1), 1_000_000)
            .await
            .unwrap();

        // Nothing expired at a time shortly after queueing with a generous TTL.
        let pruned = store
            .prune_expired_queue("ctx-1", 1_000_100, DEFAULT_QUEUE_TTL_SECS)
            .await
            .unwrap();
        assert_eq!(pruned, 0);
    }

    #[tokio::test]
    async fn prune_empty_context_returns_zero() {
        let store = make_store();
        let pruned = store
            .prune_expired_queue("nonexistent", 1_000_000, 100)
            .await
            .unwrap();
        assert_eq!(pruned, 0);
    }

    // -------------------------------------------------------------------
    // Per-context bound enforcement
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn per_context_bound_drops_oldest_on_overflow() {
        let store = make_store();

        // Fill to capacity.
        for i in 0..MAX_QUEUE_PER_CONTEXT {
            let byte = u8::try_from(i % 256).unwrap_or(0);
            store
                .enqueue_message("ctx-1", &test_envelope(byte), 1_000_000 + i)
                .await
                .unwrap();
        }
        assert_eq!(
            store.queue_context_count("ctx-1").await.unwrap(),
            MAX_QUEUE_PER_CONTEXT
        );

        // One more should trigger overflow.
        let overflow = store
            .enqueue_message("ctx-1", &test_envelope(0xFF), 2_000_000)
            .await
            .unwrap();
        assert!(overflow.is_some());
        let info = overflow.unwrap();
        assert_eq!(info.overflow_kind, OverflowKind::PerContext);
        assert_eq!(info.messages_dropped, 1);
        assert_eq!(info.context_id, "ctx-1");

        // Count should be back to the limit.
        assert_eq!(
            store.queue_context_count("ctx-1").await.unwrap(),
            MAX_QUEUE_PER_CONTEXT
        );
    }

    // -------------------------------------------------------------------
    // Global bound enforcement
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn global_bound_enforcement() {
        let store = make_store();

        // Fill 10 contexts with 10 messages each = 100 messages total.
        // This is well below the global limit, just testing tracking.
        for ctx in 0..10u64 {
            for msg in 0..10u64 {
                store
                    .enqueue_message(
                        &format!("ctx-{ctx}"),
                        &test_envelope(u8::try_from(ctx * 10 + msg).unwrap_or(0)),
                        1_000_000 + ctx * 100 + msg,
                    )
                    .await
                    .unwrap();
            }
        }
        assert_eq!(store.queue_global_count().await.unwrap(), 100);
    }

    /// Regression test for issue #709: global bound eviction must use
    /// `queued_at` timestamp ordering, NOT lexicographic context ID ordering.
    ///
    /// Uses `enforce_global_bound` directly to test eviction ordering in
    /// isolation without needing to fill the full 10,000 entry global
    /// capacity.
    ///
    /// Scenario: context "zzz" has the OLDEST messages and context "aaa" has
    /// the NEWEST. If eviction were lexicographic, "aaa" entries would be
    /// evicted first despite being newer. The correct behavior is to evict
    /// "zzz" entries first because they have the oldest timestamps.
    #[tokio::test]
    async fn global_bound_evicts_by_timestamp_not_context_id_order() {
        let store = make_store();

        // Enqueue 3 entries in "zzz" context with OLD timestamps.
        for i in 0u64..3 {
            let byte = u8::try_from(i).unwrap();
            store
                .enqueue_message("zzz-old", &test_envelope(byte), 100 + i)
                .await
                .unwrap();
        }

        // Enqueue 3 entries in "aaa" context with NEW timestamps.
        for i in 0u64..3 {
            let byte = u8::try_from(i + 10).unwrap();
            store
                .enqueue_message("aaa-new", &test_envelope(byte), 900 + i)
                .await
                .unwrap();
        }

        assert_eq!(store.queue_global_count().await.unwrap(), 6);

        // Artificially set the global count to MAX_QUEUE_GLOBAL + 2 to
        // simulate an over-limit scenario. This lets us test
        // `enforce_global_bound` without needing 10,000 real entries.
        store
            .store_value(QUEUE_GLOBAL_COUNT_KEY, &(MAX_QUEUE_GLOBAL + 2))
            .await
            .unwrap();

        // Enforce global bound. This should evict the 2 oldest entries
        // by timestamp (from "zzz-old"), NOT the alphabetically-first
        // entries (from "aaa-new").
        let overflow = store.enforce_global_bound("trigger").await.unwrap();
        assert_eq!(overflow.messages_dropped, 2);
        assert_eq!(overflow.overflow_kind, OverflowKind::Global);

        // "zzz-old" should have lost 2 entries (oldest timestamps: 100, 101).
        assert_eq!(
            store.queue_context_count("zzz-old").await.unwrap(),
            1,
            "zzz-old (oldest timestamps) should have lost 2 entries"
        );

        // "aaa-new" should retain all 3 entries (newer timestamps).
        assert_eq!(
            store.queue_context_count("aaa-new").await.unwrap(),
            3,
            "aaa-new (newer timestamps) should retain all entries"
        );
    }

    /// Regression test for issue #709: both per-context and global bounds
    /// must be enforced consistently. Per-context overflow must NOT skip
    /// global bound enforcement.
    ///
    /// Uses `queue_global_count` manipulation to test the combined overflow
    /// path without needing 10,000+ real entries.
    ///
    /// Scenario: enqueue messages into a context that overflows its per-context
    /// limit while the global count also exceeds its limit. Both bounds must
    /// be enforced.
    #[tokio::test]
    async fn both_per_context_and_global_bounds_enforced() {
        let store = make_store();

        // Fill "ctx-target" to capacity (MAX_QUEUE_PER_CONTEXT).
        for i in 0..MAX_QUEUE_PER_CONTEXT {
            let byte = u8::try_from(i % 256).unwrap_or(0);
            store
                .enqueue_message("ctx-target", &test_envelope(byte), 1_000 + i)
                .await
                .unwrap();
        }

        // Add some entries to another context with older timestamps.
        for i in 0u64..5 {
            let byte = u8::try_from(i + 50).unwrap();
            store
                .enqueue_message("ctx-other", &test_envelope(byte), 1 + i)
                .await
                .unwrap();
        }

        // Total real entries: 1000 + 5 = 1005.
        assert_eq!(store.queue_global_count().await.unwrap(), 1005);

        // Artificially inflate the global count to MAX_QUEUE_GLOBAL + 5.
        // After enqueue (+1) and per-context enforcement (-1), the global
        // count is still above MAX_QUEUE_GLOBAL, so enforce_global_bound
        // must actually run.  Without the +5 headroom the count lands
        // exactly at MAX_QUEUE_GLOBAL and the `>` check is never true.
        store
            .store_value(QUEUE_GLOBAL_COUNT_KEY, &(MAX_QUEUE_GLOBAL + 5))
            .await
            .unwrap();

        // Enqueue one more to "ctx-target", triggering per-context overflow
        // (1001 > 1000). After per-context enforcement removes 1, the
        // global count should ALSO be checked and enforced.
        let overflow = store
            .enqueue_message("ctx-target", &test_envelope(0xFF), 500_000)
            .await
            .unwrap();

        // Some overflow should have been reported.
        assert!(overflow.is_some(), "overflow must be reported");

        // Per-context bound should be enforced on ctx-target.
        assert_eq!(
            store.queue_context_count("ctx-target").await.unwrap(),
            MAX_QUEUE_PER_CONTEXT,
            "per-context bound must be enforced on ctx-target"
        );

        // Global bound should ALSO be enforced: the global count should not
        // exceed MAX_QUEUE_GLOBAL. Without the fix (early return on
        // per-context overflow), global enforcement would be skipped.
        let global = store.queue_global_count().await.unwrap();
        assert!(
            global <= MAX_QUEUE_GLOBAL,
            "global bound must be enforced even when per-context overflow triggers; got {global}"
        );
    }

    // -------------------------------------------------------------------
    // QueueEntry serialization
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn queue_entry_serialization_roundtrip() {
        let entry = QueueEntry {
            inner_envelope: vec![1, 2, 3, 4],
            queued_at: 1_700_000_000,
            content_hash: [0xAA; 32],
        };
        let bytes = ProtocolStore::<InMemoryStorage>::serialize(&entry).unwrap();
        let decoded: QueueEntry = ProtocolStore::<InMemoryStorage>::deserialize(&bytes).unwrap();
        assert_eq!(decoded, entry);
    }

    // -------------------------------------------------------------------
    // OverflowKind display
    // -------------------------------------------------------------------

    #[test]
    fn overflow_kind_display() {
        assert!(
            OverflowKind::PerContext
                .to_string()
                .contains(&MAX_QUEUE_PER_CONTEXT.to_string())
        );
        assert!(
            OverflowKind::Global
                .to_string()
                .contains(&MAX_QUEUE_GLOBAL.to_string())
        );
    }

    // -------------------------------------------------------------------
    // Default queue TTL constant
    // -------------------------------------------------------------------

    #[test]
    fn default_queue_ttl_is_seven_days() {
        assert_eq!(DEFAULT_QUEUE_TTL_SECS, 604_800);
    }
}
