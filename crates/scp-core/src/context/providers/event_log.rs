//! Production [`ContextEventLogProvider`] with Merkle-chained event integrity.
//!
//! [`MerkleEventLogProvider`] maintains a per-context append-only event log
//! where each entry is chained to its predecessor via SHA-256 hashing. This
//! provides tamper-evident event ordering: any modification to a historical
//! event invalidates all subsequent entries in the chain.
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
/// Hash input: `event_bytes || timestamp_le_bytes || prev_hash`
fn compute_entry_hash(event: &str, timestamp: u64, prev_hash: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(event.as_bytes());
    hasher.update(timestamp.to_le_bytes());
    hasher.update(prev_hash);
    let result = hasher.finalize();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result);
    hash
}

/// Production [`ContextEventLogProvider`] with Merkle-chained integrity.
///
/// Each context gets its own event log. Events are appended in order, with
/// each entry chaining to its predecessor via SHA-256 hashing.
///
/// # Construction
///
/// ```rust,ignore
/// let event_log = MerkleEventLogProvider::new();
/// let manager = ContextManager::new(
///     Box::new(crypto),
///     Box::new(transport),
///     Box::new(event_log),
/// );
/// ```
pub struct MerkleEventLogProvider {
    /// Per-context event logs, keyed by context ID bytes.
    logs: Mutex<HashMap<[u8; 32], ContextLog>>,
}

#[allow(clippy::significant_drop_tightening)]
impl MerkleEventLogProvider {
    /// Creates a new empty event log provider.
    #[must_use]
    pub fn new() -> Self {
        Self {
            logs: Mutex::new(HashMap::new()),
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

        // Verify Merkle chain integrity before accepting.
        for (i, entry) in entries.iter().enumerate() {
            let expected_prev = if i == 0 {
                [0u8; 32]
            } else {
                entries[i - 1].hash
            };
            if entry.prev_hash != expected_prev {
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
            // Check prev_hash linkage.
            let expected_prev = if i == 0 {
                [0u8; 32]
            } else {
                log.entries[i - 1].hash
            };
            if entry.prev_hash != expected_prev {
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
        log.append(event);
        Ok(())
    }

    fn destroy_event_log(&self, context_id: &[u8; 32]) -> Result<(), ContextCreationError> {
        let mut logs = self
            .logs
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        logs.remove(context_id);
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
}
