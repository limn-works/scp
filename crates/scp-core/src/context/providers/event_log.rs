//! Production [`ContextEventLogProvider`] with Merkle-chained event integrity.
//!
//! [`MerkleEventLogProvider`] maintains a per-context append-only event log
//! where each entry is chained to its predecessor via SHA-256 hashing. This
//! provides tamper-evident event ordering: any modification to a historical
//! event invalidates all subsequent entries in the chain.
//!
//! # Persistence (#636, #710)
//!
//! When constructed with [`MerkleEventLogProvider::with_persistence`], the
//! provider persists event log entries to a [`EventLogPersistence`] backend
//! after each append operation and loads them during
//! [`restore_event_log`](MerkleEventLogProvider::restore_event_log). This
//! ensures events survive process restarts.
//!
//! As of #710, each entry is persisted individually (O(1) per append)
//! rather than re-serializing the entire entry list (O(n)). Bulk
//! operations (prune, import) rewrite all entries.
//!
//! # Structure
//!
//! Each event entry stores:
//! - The event name (e.g., `"ContextCreated"`, `"MemberJoined"`)
//! - A timestamp (seconds since UNIX epoch)
//! - The SHA-256 hash of the previous entry (or all-zeros for the first entry)
//! - Its own SHA-256 hash (computed over the concatenation of the above fields)
//!
//! # Thread Safety
//!
//! Interior state is protected by `std::sync::Mutex` because the
//! [`ContextEventLogProvider`] trait methods are synchronous.
//!
//! See ADR-008 (context creation), spec section 9.9 (event log).

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::context::builder::{ContextCreationError, ContextEventLogProvider};

/// A single entry in a Merkle-chained event log.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventLogEntry {
    /// The event name (e.g., `"ContextCreated"`, `"MemberJoined"`).
    pub event: String,
    /// Seconds since UNIX epoch when the event was appended.
    pub timestamp: u64,
    /// SHA-256 hash of the previous entry (all zeros for the first entry).
    pub prev_hash: [u8; 32],
    /// SHA-256 hash of this entry (computed over event + timestamp + `prev_hash`).
    pub hash: [u8; 32],
}

/// Per-context Merkle-chained event log.
#[derive(Debug, Default)]
struct ContextLog {
    /// The ordered list of event entries.
    entries: Vec<EventLogEntry>,
}

impl ContextLog {
    /// Appends a new event to the log, chaining it to the previous entry.
    fn append(&mut self, event: &str) -> EventLogEntry {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let prev_hash = self.entries.last().map_or([0u8; 32], |e| e.hash);

        let hash = compute_entry_hash(event, timestamp, &prev_hash);

        let entry = EventLogEntry {
            event: event.to_owned(),
            timestamp,
            prev_hash,
            hash,
        };

        self.entries.push(entry.clone());
        entry
    }
}

/// Computes the SHA-256 hash for an event log entry.
///
/// Hash input: `"SCP-EXPORT-ENTRY-V1:" || event_bytes || timestamp_be_bytes || prev_hash`
///
/// Uses big-endian for the timestamp to match codebase convention, and a
/// domain separator to prevent cross-protocol hash confusion.
fn compute_entry_hash(event: &str, timestamp: u64, prev_hash: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"SCP-EXPORT-ENTRY-V1:");
    hasher.update(event.as_bytes());
    hasher.update(timestamp.to_be_bytes());
    hasher.update(prev_hash);
    let result = hasher.finalize();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result);
    hash
}

// ---------------------------------------------------------------------------
// EventLogPersistence trait (#636)
// ---------------------------------------------------------------------------

/// Persistence adapter for `MerkleEventLogProvider` event log entries.
///
/// Mirrors the [`ContextPersistence`](crate::context::manager::ContextPersistence)
/// pattern: synchronous trait methods, bridged to async `ProtocolStore` via
/// `tokio::task::block_in_place` in production.
///
/// All methods use `context_id` as a hex string (matching `ProtocolStore` key
/// conventions).
///
/// # Per-entry storage (#710)
///
/// Each entry is stored under its own key (`merkle_event_log/{seq:020d}`)
/// rather than as a single serialized blob. This makes `append_event` O(1)
/// instead of O(n) per persist. Bulk operations (prune, import) use
/// [`persist_entries`](Self::persist_entries) which rewrites all keys.
///
/// See GitHub issues #636, #710.
pub trait EventLogPersistence: Send + Sync {
    /// Persists a single event log entry at the given sequence index.
    ///
    /// Called after each append operation. O(1) serialization + I/O.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying storage write fails.
    fn persist_entry(
        &self,
        context_id: &str,
        seq: usize,
        entry: &EventLogEntry,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>>;

    /// Persists all event log entries for a context, replacing any
    /// previously stored entries.
    ///
    /// Called after bulk operations (prune, import) that rewrite the full
    /// entry set. Deletes existing per-entry keys before writing.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying storage write fails.
    fn persist_entries(
        &self,
        context_id: &str,
        entries: &[EventLogEntry],
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>>;

    /// Loads previously persisted event log entries for a context.
    ///
    /// Loads per-entry keys by prefix scan. Falls back to the legacy
    /// single-blob format (`merkle_event_log/entries`) for backward
    /// compatibility with pre-#710 data.
    ///
    /// Returns `None` if no entries have been persisted.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying storage read fails.
    fn load_entries(
        &self,
        context_id: &str,
    ) -> Result<Option<Vec<EventLogEntry>>, Box<dyn std::error::Error + Send + Sync>>;

    /// Deletes persisted event log entries for a context.
    ///
    /// Called on `destroy_event_log`. Removes all per-entry keys by prefix.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying storage delete fails.
    fn delete_entries(
        &self,
        context_id: &str,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>>;
}

// ---------------------------------------------------------------------------
// MerkleEventLogProvider
// ---------------------------------------------------------------------------

/// Production [`ContextEventLogProvider`] with Merkle-chained integrity.
///
/// Each context gets its own event log. Events are appended in order, with
/// each entry chaining to its predecessor via SHA-256 hashing.
///
/// # Persistence
///
/// When constructed with [`with_persistence`](Self::with_persistence), the
/// provider persists event log entries to the given backend after each
/// mutation and loads them via [`restore_event_log`](Self::restore_event_log).
///
/// # Construction
///
/// ```rust,ignore
/// // Without persistence (in-memory only):
/// let event_log = MerkleEventLogProvider::new();
///
/// // With persistence (survives process restart):
/// let event_log = MerkleEventLogProvider::with_persistence(
///     Arc::new(persistence_bridge),
/// );
/// ```
pub struct MerkleEventLogProvider {
    /// Per-context event logs, keyed by context ID bytes.
    logs: Mutex<HashMap<[u8; 32], ContextLog>>,
    /// Optional persistence backend for surviving process restarts (#636).
    persistence: Option<std::sync::Arc<dyn EventLogPersistence>>,
}

#[allow(clippy::significant_drop_tightening)]
impl MerkleEventLogProvider {
    /// Creates a new empty event log provider (in-memory only).
    #[must_use]
    pub fn new() -> Self {
        Self {
            logs: Mutex::new(HashMap::new()),
            persistence: None,
        }
    }

    /// Creates a new event log provider with persistence support.
    ///
    /// Events are persisted to the given backend after each append, and
    /// can be restored via [`restore_event_log`](Self::restore_event_log).
    #[must_use]
    pub fn with_persistence(persistence: std::sync::Arc<dyn EventLogPersistence>) -> Self {
        Self {
            logs: Mutex::new(HashMap::new()),
            persistence: Some(persistence),
        }
    }

    /// Returns the event log entries for a context, if one exists.
    ///
    /// Useful for auditing and verification. Returns `None` if no log
    /// has been initialized for the given context.
    #[must_use]
    pub fn entries(&self, context_id: &[u8; 32]) -> Option<Vec<EventLogEntry>> {
        let logs = self
            .logs
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        logs.get(context_id).map(|log| log.entries.clone())
    }

    /// Returns the Merkle root hash (the hash of the last entry) for a
    /// context's event log.
    ///
    /// Returns all zeros if the log is empty. Returns `None` if no log
    /// exists for the context.
    #[must_use]
    pub fn merkle_root(&self, context_id: &[u8; 32]) -> Option<[u8; 32]> {
        let logs = self
            .logs
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let log = logs.get(context_id)?;
        Some(log.entries.last().map_or([0u8; 32], |e| e.hash))
    }

    /// Serializes the event log entries for a context into `MessagePack` bytes.
    ///
    /// Used by [`ContextExport`](crate::context::export_import::ContextExport)
    /// to include the full event log in a portable export.
    ///
    /// # Errors
    ///
    /// Returns [`ContextCreationError::EventLogFailed`] if no log exists for
    /// the context or serialization fails.
    pub fn export_event_log_entries(
        &self,
        context_id: &[u8; 32],
    ) -> Result<Vec<u8>, ContextCreationError> {
        let entries = self.entries(context_id).ok_or_else(|| {
            ContextCreationError::EventLogFailed(format!(
                "no event log for context {}",
                hex::encode(context_id)
            ))
        })?;
        rmp_serde::to_vec_named(&entries).map_err(|e| {
            ContextCreationError::EventLogFailed(format!(
                "failed to serialize event log entries: {e}"
            ))
        })
    }

    /// Imports serialized event log entries (`MessagePack`) into this provider,
    /// replacing any existing log for the context.
    ///
    /// The imported entries are verified for Merkle chain integrity before
    /// being accepted.
    ///
    /// # Errors
    ///
    /// Returns [`ContextCreationError::EventLogFailed`] if deserialization
    /// fails or the Merkle chain is broken.
    pub fn import_event_log_entries(
        &self,
        context_id: &[u8; 32],
        data: &[u8],
    ) -> Result<(), ContextCreationError> {
        let entries: Vec<EventLogEntry> = rmp_serde::from_slice(data).map_err(|e| {
            ContextCreationError::EventLogFailed(format!(
                "failed to deserialize event log entries: {e}"
            ))
        })?;

        verify_chain_integrity(&entries)?;

        // Persist the imported entries (bulk rewrite).
        self.persist_entries_best_effort(context_id, &entries);

        let mut logs = self
            .logs
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let log = ContextLog { entries };
        logs.insert(*context_id, log);
        Ok(())
    }

    /// Verifies the Merkle chain integrity of a context's event log.
    ///
    /// Returns `true` if every entry's `prev_hash` matches the preceding
    /// entry's `hash`, and each entry's `hash` is correctly computed.
    /// Returns `false` if any chain link is broken.
    ///
    /// The first entry's `prev_hash` is accepted unconditionally because the
    /// log may have been pruned — the predecessor it references may no longer
    /// exist.
    ///
    /// Returns `true` for empty logs and contexts that do not exist.
    #[must_use]
    pub fn verify_chain(&self, context_id: &[u8; 32]) -> bool {
        let logs = self
            .logs
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let Some(log) = logs.get(context_id) else {
            return true;
        };

        for (i, entry) in log.entries.iter().enumerate() {
            // Skip prev_hash linkage check for the first entry: if the log
            // was pruned, entries[0].prev_hash references a discarded
            // predecessor and cannot be validated.
            if i > 0 && entry.prev_hash != log.entries[i - 1].hash {
                return false;
            }

            // Check self-hash correctness.
            let expected_hash = compute_entry_hash(&entry.event, entry.timestamp, &entry.prev_hash);
            if entry.hash != expected_hash {
                return false;
            }
        }
        true
    }

    /// Restores a context's event log from persisted storage.
    ///
    /// Loads the entries from the persistence backend, verifies Merkle chain
    /// integrity, and populates the in-memory log. Called during
    /// `ContextManager::restore_context`.
    ///
    /// If no persistence backend is configured or no entries are found,
    /// the log is initialized empty.
    ///
    /// # Errors
    ///
    /// Returns [`ContextCreationError::EventLogFailed`] if the persisted
    /// entries fail Merkle chain verification (data corruption).
    pub fn restore_event_log(&self, context_id: &[u8; 32]) -> Result<(), ContextCreationError> {
        let context_id_hex = hex::encode(context_id);

        let entries = self
            .persistence
            .as_ref()
            .map_or_else(Vec::new, |persistence| {
                match persistence.load_entries(&context_id_hex) {
                    Ok(Some(entries)) => entries,
                    Ok(None) => Vec::new(),
                    Err(e) => {
                        tracing::warn!(
                            context_id = %context_id_hex,
                            error = %e,
                            "failed to load persisted event log entries; \
                             initializing empty log"
                        );
                        Vec::new()
                    }
                }
            });

        // Verify chain integrity if entries were loaded.
        if !entries.is_empty() {
            verify_chain_integrity(&entries)?;
        }

        let mut logs = self
            .logs
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        logs.insert(*context_id, ContextLog { entries });
        Ok(())
    }

    /// Prunes event log entries, keeping only the most recent `keep_last_n`.
    ///
    /// The pruned log maintains Merkle chain integrity: the first remaining
    /// entry's `prev_hash` will reference the (now-discarded) predecessor,
    /// which is expected behavior for a checkpoint-based truncation.
    ///
    /// Persists the pruned entries if a persistence backend is configured.
    ///
    /// # Returns
    ///
    /// The number of entries removed, or `None` if no log exists for
    /// the context.
    pub fn prune_event_log(&self, context_id: &[u8; 32], keep_last_n: usize) -> Option<usize> {
        let mut logs = self
            .logs
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let log = logs.get_mut(context_id)?;

        let total = log.entries.len();
        if total <= keep_last_n {
            return Some(0);
        }

        let remove_count = total - keep_last_n;
        log.entries.drain(..remove_count);

        // Persist the pruned state (bulk rewrite with renumbered keys).
        let entries_snapshot = log.entries.clone();
        drop(logs);
        self.persist_entries_best_effort(context_id, &entries_snapshot);

        Some(remove_count)
    }

    /// Best-effort O(1) persistence of a single entry at a given sequence.
    ///
    /// Used by `append_event` to persist only the newly appended entry.
    fn persist_entry_best_effort(&self, context_id: &[u8; 32], seq: usize, entry: &EventLogEntry) {
        if let Some(ref persistence) = self.persistence {
            let context_id_hex = hex::encode(context_id);
            if let Err(e) = persistence.persist_entry(&context_id_hex, seq, entry) {
                tracing::warn!(
                    context_id = %context_id_hex,
                    error = %e,
                    "failed to persist event log entry (best-effort)"
                );
            }
        }
    }

    /// Best-effort bulk persistence: replaces all stored entries.
    ///
    /// Used by prune and import operations that rewrite the full entry set.
    fn persist_entries_best_effort(&self, context_id: &[u8; 32], entries: &[EventLogEntry]) {
        if let Some(ref persistence) = self.persistence {
            let context_id_hex = hex::encode(context_id);
            if let Err(e) = persistence.persist_entries(&context_id_hex, entries) {
                tracing::warn!(
                    context_id = %context_id_hex,
                    error = %e,
                    "failed to persist event log entries (best-effort)"
                );
            }
        }
    }

    /// Best-effort persistence deletion.
    fn delete_persisted_best_effort(&self, context_id: &[u8; 32]) {
        if let Some(ref persistence) = self.persistence {
            let context_id_hex = hex::encode(context_id);
            if let Err(e) = persistence.delete_entries(&context_id_hex) {
                tracing::warn!(
                    context_id = %context_id_hex,
                    error = %e,
                    "failed to delete persisted event log entries (best-effort)"
                );
            }
        }
    }
}

impl Default for MerkleEventLogProvider {
    fn default() -> Self {
        Self::new()
    }
}

// Nursery lint — false-positives on lock guards across block boundaries.
#[allow(clippy::significant_drop_tightening)]
impl ContextEventLogProvider for MerkleEventLogProvider {
    fn init_event_log(&self, context_id: &[u8; 32]) -> Result<(), ContextCreationError> {
        let mut logs = self
            .logs
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        logs.insert(*context_id, ContextLog::default());

        // Persist the empty entry set to establish the context in storage
        // (clears any stale per-entry keys from a previous incarnation).
        drop(logs);
        self.persist_entries_best_effort(context_id, &[]);

        Ok(())
    }

    fn append_event(&self, context_id: &[u8; 32], event: &str) -> Result<(), ContextCreationError> {
        let mut logs = self
            .logs
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let log = logs.get_mut(context_id).ok_or_else(|| {
            ContextCreationError::EventLogFailed(format!(
                "no event log for context {}",
                hex::encode(context_id)
            ))
        })?;
        let entry = log.append(event);
        let seq = log.entries.len() - 1;

        // O(1) persist: only the newly appended entry (#710).
        drop(logs);
        self.persist_entry_best_effort(context_id, seq, &entry);

        Ok(())
    }

    fn destroy_event_log(&self, context_id: &[u8; 32]) -> Result<(), ContextCreationError> {
        let mut logs = self
            .logs
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        logs.remove(context_id);

        // Remove persisted entries.
        drop(logs);
        self.delete_persisted_best_effort(context_id);

        Ok(())
    }

    fn export_event_log_data(
        &self,
        context_id: &[u8; 32],
    ) -> Result<Vec<u8>, crate::context::ContextError> {
        self.export_event_log_entries(context_id)
            .map_err(|e| crate::context::ContextError::EventLogFailed(e.to_string()))
    }

    fn import_event_log_data(
        &self,
        context_id: &[u8; 32],
        data: &[u8],
    ) -> Result<(), crate::context::ContextError> {
        self.import_event_log_entries(context_id, data)
            .map_err(|e| crate::context::ContextError::EventLogFailed(e.to_string()))
    }

    fn event_log_merkle_root(
        &self,
        context_id: &[u8; 32],
    ) -> Result<[u8; 32], crate::context::ContextError> {
        self.merkle_root(context_id).ok_or_else(|| {
            crate::context::ContextError::EventLogFailed(format!(
                "no event log for context {}",
                hex::encode(context_id)
            ))
        })
    }
}

// ---------------------------------------------------------------------------
// Chain verification helper
// ---------------------------------------------------------------------------

/// Verifies Merkle chain integrity for a list of entries.
///
/// The first entry's `prev_hash` is accepted unconditionally because the log
/// may have been pruned — the predecessor it references may no longer exist.
/// Subsequent entries must chain correctly to their immediate predecessor.
///
/// # Errors
///
/// Returns [`ContextCreationError::EventLogFailed`] if any chain link is
/// broken (`prev_hash` mismatch or hash mismatch).
fn verify_chain_integrity(entries: &[EventLogEntry]) -> Result<(), ContextCreationError> {
    for (i, entry) in entries.iter().enumerate() {
        // Skip prev_hash linkage check for the first entry: if the log was
        // pruned, entries[0].prev_hash references a discarded predecessor
        // and cannot be validated.
        if i > 0 && entry.prev_hash != entries[i - 1].hash {
            return Err(ContextCreationError::EventLogFailed(format!(
                "Merkle chain broken at entry {i}: prev_hash mismatch"
            )));
        }
        let expected_hash = compute_entry_hash(&entry.event, entry.timestamp, &entry.prev_hash);
        if entry.hash != expected_hash {
            return Err(ContextCreationError::EventLogFailed(format!(
                "Merkle chain broken at entry {i}: hash mismatch"
            )));
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::significant_drop_tightening
)]
mod tests {
    use super::*;

    #[test]
    fn init_creates_empty_log() {
        let provider = MerkleEventLogProvider::new();
        let ctx_id = [1u8; 32];

        provider.init_event_log(&ctx_id).unwrap();

        let entries = provider.entries(&ctx_id).unwrap();
        assert!(entries.is_empty());
    }

    #[test]
    fn append_adds_entry_with_merkle_chain() {
        let provider = MerkleEventLogProvider::new();
        let ctx_id = [2u8; 32];

        provider.init_event_log(&ctx_id).unwrap();
        provider.append_event(&ctx_id, "ContextCreated").unwrap();
        provider.append_event(&ctx_id, "MemberJoined").unwrap();

        let entries = provider.entries(&ctx_id).unwrap();
        assert_eq!(entries.len(), 2);

        // First entry's prev_hash should be all zeros.
        assert_eq!(entries[0].prev_hash, [0u8; 32]);
        assert_eq!(entries[0].event, "ContextCreated");

        // Second entry's prev_hash should equal first entry's hash.
        assert_eq!(entries[1].prev_hash, entries[0].hash);
        assert_eq!(entries[1].event, "MemberJoined");

        // Chain should verify.
        assert!(provider.verify_chain(&ctx_id));
    }

    #[test]
    fn append_fails_for_uninitialized_context() {
        let provider = MerkleEventLogProvider::new();
        let ctx_id = [3u8; 32];

        let result = provider.append_event(&ctx_id, "SomeEvent");
        assert!(result.is_err());
    }

    #[test]
    fn destroy_removes_log() {
        let provider = MerkleEventLogProvider::new();
        let ctx_id = [4u8; 32];

        provider.init_event_log(&ctx_id).unwrap();
        provider.append_event(&ctx_id, "ContextCreated").unwrap();

        provider.destroy_event_log(&ctx_id).unwrap();

        assert!(provider.entries(&ctx_id).is_none());
    }

    #[test]
    fn verify_chain_detects_tampering() {
        let provider = MerkleEventLogProvider::new();
        let ctx_id = [5u8; 32];

        provider.init_event_log(&ctx_id).unwrap();
        provider.append_event(&ctx_id, "Event1").unwrap();
        provider.append_event(&ctx_id, "Event2").unwrap();
        provider.append_event(&ctx_id, "Event3").unwrap();

        assert!(provider.verify_chain(&ctx_id));

        // Tamper with the second entry's hash.
        {
            let mut logs = provider.logs.lock().unwrap();
            let log = logs.get_mut(&ctx_id).unwrap();
            log.entries[1].hash = [0xff; 32];
        }

        // Chain should now fail verification.
        assert!(!provider.verify_chain(&ctx_id));
    }

    #[test]
    fn verify_chain_empty_and_nonexistent() {
        let provider = MerkleEventLogProvider::new();
        let ctx_id = [6u8; 32];

        // Nonexistent context verifies trivially.
        assert!(provider.verify_chain(&ctx_id));

        // Empty log verifies.
        provider.init_event_log(&ctx_id).unwrap();
        assert!(provider.verify_chain(&ctx_id));
    }

    #[test]
    fn entry_hashes_are_deterministic() {
        let hash1 = compute_entry_hash("test", 1000, &[0u8; 32]);
        let hash2 = compute_entry_hash("test", 1000, &[0u8; 32]);
        assert_eq!(hash1, hash2);

        // Different input produces different hash.
        let hash3 = compute_entry_hash("other", 1000, &[0u8; 32]);
        assert_ne!(hash1, hash3);
    }

    #[test]
    fn append_context_event_delegates_to_append_event() {
        let provider = MerkleEventLogProvider::new();
        let ctx_id = [7u8; 32];

        provider.init_event_log(&ctx_id).unwrap();
        // append_context_event is the default trait method that delegates to append_event.
        provider
            .append_context_event(&ctx_id, "MemberLeft")
            .unwrap();

        let entries = provider.entries(&ctx_id).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].event, "MemberLeft");
    }

    // -----------------------------------------------------------------------
    // Persistence tests (#636)
    // -----------------------------------------------------------------------

    /// In-memory `EventLogPersistence` for testing.
    struct MockEventLogPersistence {
        store: Mutex<HashMap<String, Vec<EventLogEntry>>>,
    }

    impl MockEventLogPersistence {
        fn new() -> Self {
            Self {
                store: Mutex::new(HashMap::new()),
            }
        }
    }

    impl EventLogPersistence for MockEventLogPersistence {
        fn persist_entry(
            &self,
            context_id: &str,
            seq: usize,
            entry: &EventLogEntry,
        ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
            let mut store = self.store.lock().unwrap();
            let entries = store.entry(context_id.to_owned()).or_default();
            if seq >= entries.len() {
                entries.resize(
                    seq + 1,
                    EventLogEntry {
                        event: String::new(),
                        timestamp: 0,
                        prev_hash: [0u8; 32],
                        hash: [0u8; 32],
                    },
                );
            }
            entries[seq] = entry.clone();
            Ok(())
        }

        fn persist_entries(
            &self,
            context_id: &str,
            entries: &[EventLogEntry],
        ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
            self.store
                .lock()
                .unwrap()
                .insert(context_id.to_owned(), entries.to_vec());
            Ok(())
        }

        fn load_entries(
            &self,
            context_id: &str,
        ) -> Result<Option<Vec<EventLogEntry>>, Box<dyn std::error::Error + Send + Sync>> {
            Ok(self.store.lock().unwrap().get(context_id).cloned())
        }

        fn delete_entries(
            &self,
            context_id: &str,
        ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
            self.store.lock().unwrap().remove(context_id);
            Ok(())
        }
    }

    #[test]
    fn persistence_on_append() {
        let persistence = std::sync::Arc::new(MockEventLogPersistence::new());
        let provider = MerkleEventLogProvider::with_persistence(persistence.clone());
        let ctx_id = [10u8; 32];
        let ctx_hex = hex::encode(ctx_id);

        provider.init_event_log(&ctx_id).unwrap();
        provider.append_event(&ctx_id, "ContextCreated").unwrap();
        provider.append_event(&ctx_id, "MemberJoined").unwrap();

        // Entries should be persisted.
        let persisted = persistence.load_entries(&ctx_hex).unwrap().unwrap();
        assert_eq!(persisted.len(), 2);
        assert_eq!(persisted[0].event, "ContextCreated");
        assert_eq!(persisted[1].event, "MemberJoined");
    }

    #[test]
    fn restore_from_persistence() {
        let persistence = std::sync::Arc::new(MockEventLogPersistence::new());
        let ctx_id = [11u8; 32];
        let ctx_hex = hex::encode(ctx_id);

        // Phase 1: append events and persist.
        {
            let provider = MerkleEventLogProvider::with_persistence(persistence.clone());
            provider.init_event_log(&ctx_id).unwrap();
            provider.append_event(&ctx_id, "ContextCreated").unwrap();
            provider.append_event(&ctx_id, "MemberJoined").unwrap();
            provider.append_event(&ctx_id, "MessageSent").unwrap();

            // Verify persisted.
            assert_eq!(
                persistence.load_entries(&ctx_hex).unwrap().unwrap().len(),
                3
            );
        }

        // Phase 2: create a new provider (simulating restart), restore.
        {
            let provider = MerkleEventLogProvider::with_persistence(persistence);
            provider.restore_event_log(&ctx_id).unwrap();

            let entries = provider.entries(&ctx_id).unwrap();
            assert_eq!(entries.len(), 3);
            assert_eq!(entries[0].event, "ContextCreated");
            assert_eq!(entries[1].event, "MemberJoined");
            assert_eq!(entries[2].event, "MessageSent");

            // Chain integrity should hold.
            assert!(provider.verify_chain(&ctx_id));

            // Appending after restore should chain correctly.
            provider.append_event(&ctx_id, "MemberLeft").unwrap();
            let entries = provider.entries(&ctx_id).unwrap();
            assert_eq!(entries.len(), 4);
            assert_eq!(entries[3].prev_hash, entries[2].hash);
            assert!(provider.verify_chain(&ctx_id));
        }
    }

    #[test]
    fn restore_empty_when_no_persistence() {
        let provider = MerkleEventLogProvider::new();
        let ctx_id = [12u8; 32];

        // restore_event_log without persistence creates empty log.
        provider.restore_event_log(&ctx_id).unwrap();
        let entries = provider.entries(&ctx_id).unwrap();
        assert!(entries.is_empty());
    }

    #[test]
    fn destroy_cleans_persistence() {
        let persistence = std::sync::Arc::new(MockEventLogPersistence::new());
        let provider = MerkleEventLogProvider::with_persistence(persistence.clone());
        let ctx_id = [13u8; 32];
        let ctx_hex = hex::encode(ctx_id);

        provider.init_event_log(&ctx_id).unwrap();
        provider.append_event(&ctx_id, "ContextCreated").unwrap();

        assert!(persistence.load_entries(&ctx_hex).unwrap().is_some());

        provider.destroy_event_log(&ctx_id).unwrap();

        // Persistence should be cleaned.
        assert!(persistence.load_entries(&ctx_hex).unwrap().is_none());
        assert!(provider.entries(&ctx_id).is_none());
    }

    #[test]
    fn prune_keeps_last_n_entries() {
        let persistence = std::sync::Arc::new(MockEventLogPersistence::new());
        let provider = MerkleEventLogProvider::with_persistence(persistence.clone());
        let ctx_id = [14u8; 32];
        let ctx_hex = hex::encode(ctx_id);

        provider.init_event_log(&ctx_id).unwrap();
        for i in 0..10 {
            provider
                .append_event(&ctx_id, &format!("Event{i}"))
                .unwrap();
        }

        assert_eq!(provider.entries(&ctx_id).unwrap().len(), 10);

        let removed = provider.prune_event_log(&ctx_id, 3).unwrap();
        assert_eq!(removed, 7);

        let entries = provider.entries(&ctx_id).unwrap();
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].event, "Event7");
        assert_eq!(entries[1].event, "Event8");
        assert_eq!(entries[2].event, "Event9");

        // Pruned state should be persisted.
        let persisted = persistence.load_entries(&ctx_hex).unwrap().unwrap();
        assert_eq!(persisted.len(), 3);
    }

    #[test]
    fn prune_noop_when_fewer_than_keep() {
        let provider = MerkleEventLogProvider::new();
        let ctx_id = [15u8; 32];

        provider.init_event_log(&ctx_id).unwrap();
        provider.append_event(&ctx_id, "Event0").unwrap();
        provider.append_event(&ctx_id, "Event1").unwrap();

        let removed = provider.prune_event_log(&ctx_id, 5).unwrap();
        assert_eq!(removed, 0);
        assert_eq!(provider.entries(&ctx_id).unwrap().len(), 2);
    }

    #[test]
    fn prune_nonexistent_context_returns_none() {
        let provider = MerkleEventLogProvider::new();
        let ctx_id = [16u8; 32];

        assert!(provider.prune_event_log(&ctx_id, 5).is_none());
    }

    #[test]
    fn restore_after_prune() {
        let persistence = std::sync::Arc::new(MockEventLogPersistence::new());
        let ctx_id = [18u8; 32];

        // Phase 1: create entries, prune, verify persisted state.
        {
            let provider = MerkleEventLogProvider::with_persistence(persistence.clone());
            provider.init_event_log(&ctx_id).unwrap();
            for i in 0..10 {
                provider
                    .append_event(&ctx_id, &format!("Event{i}"))
                    .unwrap();
            }

            // Prune to keep only the last 3 entries.
            let removed = provider.prune_event_log(&ctx_id, 3).unwrap();
            assert_eq!(removed, 7);

            // First remaining entry's prev_hash should NOT be [0u8; 32]
            // because it references a pruned predecessor.
            let entries = provider.entries(&ctx_id).unwrap();
            assert_eq!(entries.len(), 3);
            assert_ne!(entries[0].prev_hash, [0u8; 32]);

            // Chain should still verify after prune.
            assert!(provider.verify_chain(&ctx_id));
        }

        // Phase 2: restore from persistence (simulating process restart).
        {
            let provider = MerkleEventLogProvider::with_persistence(persistence);
            provider.restore_event_log(&ctx_id).unwrap();

            let entries = provider.entries(&ctx_id).unwrap();
            assert_eq!(entries.len(), 3);
            assert_eq!(entries[0].event, "Event7");
            assert_eq!(entries[1].event, "Event8");
            assert_eq!(entries[2].event, "Event9");

            // Chain integrity must pass after restore of pruned log.
            assert!(provider.verify_chain(&ctx_id));

            // Appending after restore should chain correctly.
            provider.append_event(&ctx_id, "Event10").unwrap();
            let entries = provider.entries(&ctx_id).unwrap();
            assert_eq!(entries.len(), 4);
            assert_eq!(entries[3].prev_hash, entries[2].hash);
            assert!(provider.verify_chain(&ctx_id));
        }
    }

    #[test]
    fn import_persists_entries() {
        let persistence = std::sync::Arc::new(MockEventLogPersistence::new());
        let provider = MerkleEventLogProvider::with_persistence(persistence.clone());
        let ctx_id = [17u8; 32];
        let ctx_hex = hex::encode(ctx_id);

        // Build entries via another provider (no persistence) to get valid chain.
        let source = MerkleEventLogProvider::new();
        source.init_event_log(&ctx_id).unwrap();
        source.append_event(&ctx_id, "Imported1").unwrap();
        source.append_event(&ctx_id, "Imported2").unwrap();
        let exported = source.export_event_log_entries(&ctx_id).unwrap();

        // Import into the persistent provider.
        provider
            .import_event_log_entries(&ctx_id, &exported)
            .unwrap();

        // Should be persisted.
        let persisted = persistence.load_entries(&ctx_hex).unwrap().unwrap();
        assert_eq!(persisted.len(), 2);
        assert_eq!(persisted[0].event, "Imported1");
    }
}
