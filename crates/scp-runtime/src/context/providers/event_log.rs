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
use subtle::ConstantTimeEq;

use crate::context::builder::ContextEventLogProvider;
use scp_protocol::context::builder::ContextCreationError;

/// A single entry in a Merkle-chained event log.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventLogEntry {
    /// The event name (e.g., `"ContextCreated"`, `"MemberJoined"`).
    pub event: String,
    /// The DID of the actor who produced this event (the sender for messages,
    /// the proposer for governance, the joiner for membership events).
    ///
    /// Added as part of #1594 to enable full-history consequence evaluation.
    /// Defaults to empty string for backward compatibility with entries
    /// serialized before `actor_did` was added.
    #[serde(default)]
    pub actor_did: String,
    /// Seconds since UNIX epoch when the event was appended.
    pub timestamp: u64,
    /// SHA-256 hash of the previous entry (all zeros for the first entry).
    pub prev_hash: [u8; 32],
    /// SHA-256 hash of this entry (domain-separated SHA-256 over event +
    /// `actor_did` + timestamp + `prev_hash` + optional `payload`).
    pub hash: [u8; 32],
    /// Optional structured payload for this event.
    ///
    /// Used by governance actions to carry target DID and other structured
    /// data that consequence triggers and participation records need. The
    /// payload is included in the Merkle hash to ensure tamper evidence.
    ///
    /// Defaults to `None` for backward compatibility with entries serialized
    /// before this field was added.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payload: Option<serde_json::Value>,
}

/// Per-context Merkle-chained event log.
#[derive(Debug, Default)]
struct ContextLog {
    /// The ordered list of event entries.
    entries: Vec<EventLogEntry>,
}

impl ContextLog {
    /// Appends a new event to the log, chaining it to the previous entry.
    fn append(
        &mut self,
        event: &str,
        actor_did: &str,
        payload: Option<&serde_json::Value>,
    ) -> EventLogEntry {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let prev_hash = self.entries.last().map_or([0u8; 32], |e| e.hash);

        let hash = compute_entry_hash(event, actor_did, timestamp, &prev_hash, payload);

        let entry = EventLogEntry {
            event: event.to_owned(),
            actor_did: actor_did.to_owned(),
            timestamp,
            prev_hash,
            hash,
            payload: payload.cloned(),
        };

        self.entries.push(entry.clone());
        entry
    }
}

/// Computes the SHA-256 hash for an event log entry.
///
/// Hash input: `"SCP-EXPORT-ENTRY:" || len(event) || event || len(actor_did)
///   || actor_did || timestamp || prev_hash [|| len(payload_json) || payload_json]`
///
/// Uses big-endian u32 length prefixes before variable-length fields to
/// prevent length-extension ambiguity (e.g., event="AB" + actor="CD" vs
/// event="ABC" + actor="D" producing the same hash).
///
/// When `payload` is `Some`, the canonical JSON representation is appended
/// with a length prefix. When `None`, no additional bytes are hashed,
/// preserving backward compatibility with entries created before payloads
/// were introduced.
/// Public alias for [`compute_entry_hash`] for test/mock use.
#[must_use]
pub fn entry_hash(
    event: &str,
    actor_did: &str,
    timestamp: u64,
    prev_hash: &[u8; 32],
    payload: Option<&serde_json::Value>,
) -> [u8; 32] {
    compute_entry_hash(event, actor_did, timestamp, prev_hash, payload)
}

fn compute_entry_hash(
    event: &str,
    actor_did: &str,
    timestamp: u64,
    prev_hash: &[u8; 32],
    payload: Option<&serde_json::Value>,
) -> [u8; 32] {
    // Event names and DID strings are always well under u32::MAX bytes.
    // Saturating conversion is used to satisfy clippy::cast_possible_truncation.
    let event_len = u32::try_from(event.len()).unwrap_or(u32::MAX);
    let actor_len = u32::try_from(actor_did.len()).unwrap_or(u32::MAX);
    let mut hasher = Sha256::new();
    hasher.update(b"SCP-EXPORT-ENTRY:");
    hasher.update(event_len.to_be_bytes());
    hasher.update(event.as_bytes());
    hasher.update(actor_len.to_be_bytes());
    hasher.update(actor_did.as_bytes());
    hasher.update(timestamp.to_be_bytes());
    hasher.update(prev_hash);
    // Payload is included in the hash when present.
    // Absent payloads contribute no bytes, preserving backward compat.
    if let Some(val) = payload {
        let json_bytes = serde_json::to_vec(val).unwrap_or_default();
        let payload_len = u32::try_from(json_bytes.len()).unwrap_or(u32::MAX);
        hasher.update(payload_len.to_be_bytes());
        hasher.update(&json_bytes);
    }
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
/// pattern: synchronous trait methods, bridged to async `ProtocolRepository` via
/// `tokio::task::block_in_place` in production.
///
/// All methods use `context_id` as a hex string (matching `ProtocolRepository` key
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
    /// Loads per-entry keys by prefix scan.
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
            if i > 0 && !bool::from(entry.prev_hash.ct_eq(&log.entries[i - 1].hash)) {
                return false;
            }

            // Check self-hash correctness.
            let expected = compute_entry_hash(
                &entry.event,
                &entry.actor_did,
                entry.timestamp,
                &entry.prev_hash,
                entry.payload.as_ref(),
            );
            if !bool::from(entry.hash.ct_eq(&expected)) {
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

    /// Prunes event log entries before a checkpoint boundary based on a
    /// [`PruningPolicy`](scp_protocol::context::governance::PruningPolicy).
    ///
    /// Called after creating a governance checkpoint (#1474). If the policy
    /// has time-based pruning configured, entries older than
    /// `now - retention_secs` (clamped to 30-day minimum) and before the
    /// checkpoint boundary (`checkpoint_event_count`) are removed.
    ///
    /// If only size-based pruning is configured, entries beyond
    /// `max_event_count` are removed (keeping the most recent).
    ///
    /// Structural events (governance, membership) are retained
    /// `structural_retention_multiplier / 10000` times longer than
    /// operational events per ADR-030 §2c.
    ///
    /// # Returns
    ///
    /// The number of entries removed, or `None` if no log exists for
    /// the context.
    pub fn prune_before_checkpoint(
        &self,
        context_id: &[u8; 32],
        checkpoint_event_count: u64,
        policy: &scp_protocol::context::governance::PruningPolicy,
    ) -> Option<usize> {
        use std::time::{SystemTime, UNIX_EPOCH};

        /// Minimum retention: 30 days (protocol floor per ADR-030 §2a).
        const MIN_RETENTION_SECS: u64 = 2_592_000;

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let mut logs = self
            .logs
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let log = logs.get_mut(context_id)?;

        let total = log.entries.len();
        if total == 0 {
            return Some(0);
        }

        // Cannot prune beyond the checkpoint boundary (entries at or after
        // the checkpoint are still live).
        #[allow(clippy::cast_possible_truncation)]
        let checkpoint_bound = (checkpoint_event_count as usize).min(total);

        let mut prune_count = 0usize;

        // Time-based and size-based pruning evaluate independently;
        // we take the maximum of the two so that both policies are honored.
        if let Some(ref time_policy) = policy.time_based {
            let retention = time_policy.retention_secs.max(MIN_RETENTION_SECS);

            let mut time_prune = 0usize;
            for entry in log.entries.iter().take(checkpoint_bound) {
                let is_structural = is_structural_event_name(&entry.event);
                // Apply structural retention multiplier: structural events are
                // retained longer. Uses integer arithmetic (basis points) to
                // avoid f64 precision loss on u64 values.
                let effective_retention = if is_structural {
                    let multiplier_bp =
                        u128::from(policy.event_type_retention.structural_retention_multiplier);
                    #[allow(clippy::cast_possible_truncation)]
                    let r = (u128::from(retention) * multiplier_bp / 10_000) as u64;
                    r.max(retention)
                } else {
                    retention
                };

                if entry.timestamp < now.saturating_sub(effective_retention) {
                    time_prune += 1;
                } else {
                    // Entries are ordered by time; once we find a
                    // retained entry, all subsequent are also retained.
                    break;
                }
            }
            prune_count = prune_count.max(time_prune);
        }

        if let Some(ref size_policy) = policy.size_based {
            // Size-based: keep at most `max_event_count` entries.
            #[allow(clippy::cast_possible_truncation)]
            let max_count = size_policy.max_event_count as usize;
            if total > max_count {
                let size_prune = (total - max_count).min(checkpoint_bound);
                prune_count = prune_count.max(size_prune);
            }
        }

        if prune_count == 0 {
            return Some(0);
        }

        tracing::info!(
            context_id = %hex::encode(context_id),
            pruned = prune_count,
            remaining = total - prune_count,
            "pruned event log entries after checkpoint"
        );

        log.entries.drain(..prune_count);

        // Persist the pruned state (bulk rewrite with renumbered keys).
        let entries_snapshot = log.entries.clone();
        drop(logs);
        self.persist_entries_best_effort(context_id, &entries_snapshot);

        Some(prune_count)
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

/// Returns `true` if the event name represents a structural event
/// (governance, membership) that should be retained longer than
/// operational events per ADR-030 §2c.
///
/// Mirrors the `is_structural_event` function in `scp-event-log/src/pruning.rs`
/// but operates on event name strings rather than `EventType` enum values.
fn is_structural_event_name(event: &str) -> bool {
    matches!(
        event,
        "ContextCreated"
            | "MemberJoined"
            | "MemberLeft"
            | "RoleAssigned"
            | "GovernanceAction"
            | "GovernanceActionProposed"
            | "GovernanceActionApproved"
            | "GovernanceActionExecuted"
            | "GovernanceActionRejected"
            | "GovernanceActionWithdrawn"
            | "ContextClosing"
            | "ContextClosed"
            | "ContextExpired"
            | "MemberBlocked"
            | "ConsistencyCheckpoint"
            | "PruningPolicyModified"
    )
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

    fn append_event(
        &self,
        context_id: &[u8; 32],
        event: &str,
        actor_did: &str,
        payload: Option<&serde_json::Value>,
    ) -> Result<(), ContextCreationError> {
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
        let entry = log.append(event, actor_did, payload);
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

    fn event_log_entries(
        &self,
        context_id: &[u8; 32],
    ) -> Result<Option<Vec<EventLogEntry>>, scp_protocol::context::ContextError> {
        Ok(self.entries(context_id))
    }

    fn export_event_log_data(
        &self,
        context_id: &[u8; 32],
    ) -> Result<Vec<u8>, scp_protocol::context::ContextError> {
        self.export_event_log_entries(context_id)
            .map_err(|e| scp_protocol::context::ContextError::EventLogFailed(e.to_string()))
    }

    fn import_event_log_data(
        &self,
        context_id: &[u8; 32],
        data: &[u8],
    ) -> Result<(), scp_protocol::context::ContextError> {
        self.import_event_log_entries(context_id, data)
            .map_err(|e| scp_protocol::context::ContextError::EventLogFailed(e.to_string()))
    }

    fn event_log_merkle_root(
        &self,
        context_id: &[u8; 32],
    ) -> Result<[u8; 32], scp_protocol::context::ContextError> {
        self.merkle_root(context_id).ok_or_else(|| {
            scp_protocol::context::ContextError::EventLogFailed(format!(
                "no event log for context {}",
                hex::encode(context_id)
            ))
        })
    }

    fn prune_before_checkpoint(
        &self,
        context_id: &[u8; 32],
        checkpoint_event_count: u64,
        policy: &scp_protocol::context::governance::PruningPolicy,
    ) -> Option<usize> {
        // Delegate to the concrete method on MerkleEventLogProvider.
        Self::prune_before_checkpoint(self, context_id, checkpoint_event_count, policy)
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
        if i > 0 && !bool::from(entry.prev_hash.ct_eq(&entries[i - 1].hash)) {
            return Err(ContextCreationError::EventLogFailed(format!(
                "Merkle chain broken at entry {i}: prev_hash mismatch"
            )));
        }
        // Verify self-hash correctness.
        let expected = compute_entry_hash(
            &entry.event,
            &entry.actor_did,
            entry.timestamp,
            &entry.prev_hash,
            entry.payload.as_ref(),
        );
        if !bool::from(entry.hash.ct_eq(&expected)) {
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
        provider
            .append_event(&ctx_id, "ContextCreated", "", None)
            .unwrap();
        provider
            .append_event(&ctx_id, "MemberJoined", "", None)
            .unwrap();

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

        let result = provider.append_event(&ctx_id, "SomeEvent", "", None);
        assert!(result.is_err());
    }

    #[test]
    fn destroy_removes_log() {
        let provider = MerkleEventLogProvider::new();
        let ctx_id = [4u8; 32];

        provider.init_event_log(&ctx_id).unwrap();
        provider
            .append_event(&ctx_id, "ContextCreated", "", None)
            .unwrap();

        provider.destroy_event_log(&ctx_id).unwrap();

        assert!(provider.entries(&ctx_id).is_none());
    }

    #[test]
    fn verify_chain_detects_tampering() {
        let provider = MerkleEventLogProvider::new();
        let ctx_id = [5u8; 32];

        provider.init_event_log(&ctx_id).unwrap();
        provider.append_event(&ctx_id, "Event1", "", None).unwrap();
        provider.append_event(&ctx_id, "Event2", "", None).unwrap();
        provider.append_event(&ctx_id, "Event3", "", None).unwrap();

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
        let hash1 = compute_entry_hash("test", "did:key:z123", 1000, &[0u8; 32], None);
        let hash2 = compute_entry_hash("test", "did:key:z123", 1000, &[0u8; 32], None);
        assert_eq!(hash1, hash2);

        // Different input produces different hash.
        let hash3 = compute_entry_hash("other", "did:key:z123", 1000, &[0u8; 32], None);
        assert_ne!(hash1, hash3);

        // Different actor_did produces different hash.
        let hash4 = compute_entry_hash("test", "did:key:z456", 1000, &[0u8; 32], None);
        assert_ne!(hash1, hash4);
    }

    #[test]
    fn append_context_event_delegates_to_append_event() {
        let provider = MerkleEventLogProvider::new();
        let ctx_id = [7u8; 32];

        provider.init_event_log(&ctx_id).unwrap();
        // append_context_event is the default trait method that delegates to append_event.
        provider
            .append_context_event(&ctx_id, "MemberLeft", "")
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
                        actor_did: String::new(),
                        timestamp: 0,
                        prev_hash: [0u8; 32],
                        hash: [0u8; 32],
                        payload: None,
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
        provider
            .append_event(&ctx_id, "ContextCreated", "", None)
            .unwrap();
        provider
            .append_event(&ctx_id, "MemberJoined", "", None)
            .unwrap();

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
            provider
                .append_event(&ctx_id, "ContextCreated", "", None)
                .unwrap();
            provider
                .append_event(&ctx_id, "MemberJoined", "", None)
                .unwrap();
            provider
                .append_event(&ctx_id, "MessageSent", "", None)
                .unwrap();

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
            provider
                .append_event(&ctx_id, "MemberLeft", "", None)
                .unwrap();
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
        provider
            .append_event(&ctx_id, "ContextCreated", "", None)
            .unwrap();

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
                .append_event(&ctx_id, &format!("Event{i}"), "", None)
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
        provider.append_event(&ctx_id, "Event0", "", None).unwrap();
        provider.append_event(&ctx_id, "Event1", "", None).unwrap();

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
                    .append_event(&ctx_id, &format!("Event{i}"), "", None)
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
            provider.append_event(&ctx_id, "Event10", "", None).unwrap();
            let entries = provider.entries(&ctx_id).unwrap();
            assert_eq!(entries.len(), 4);
            assert_eq!(entries[3].prev_hash, entries[2].hash);
            assert!(provider.verify_chain(&ctx_id));
        }
    }

    #[test]
    fn event_log_entries_via_dyn_dispatch() {
        use crate::context::builder::ContextEventLogProvider;

        let provider = MerkleEventLogProvider::new();
        let ctx_id = [19u8; 32];

        provider.init_event_log(&ctx_id).unwrap();
        provider
            .append_event(&ctx_id, "ContextCreated", "", None)
            .unwrap();
        provider
            .append_event(&ctx_id, "MemberJoined", "", None)
            .unwrap();

        // Call event_log_entries through dyn dispatch.
        let boxed: Box<dyn ContextEventLogProvider> = Box::new(provider);
        let entries = boxed.event_log_entries(&ctx_id).unwrap().unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].event, "ContextCreated");
        assert_eq!(entries[1].event, "MemberJoined");
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
        source.append_event(&ctx_id, "Imported1", "", None).unwrap();
        source.append_event(&ctx_id, "Imported2", "", None).unwrap();
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

    // -----------------------------------------------------------------------
    // Hash computation unit tests (#1594, #33-41)
    // -----------------------------------------------------------------------

    /// Changing `actor_did` with all other fields constant changes the hash.
    #[test]
    fn compute_entry_hash_actor_did_changes_hash() {
        let h1 = compute_entry_hash("MessageSent", "did:key:alice", 1000, &[0u8; 32], None);
        let h2 = compute_entry_hash("MessageSent", "did:key:bob", 1000, &[0u8; 32], None);
        assert_ne!(h1, h2, "different actor_did must produce different hash");
    }

    /// Changing event name with all other fields constant changes the hash.
    #[test]
    fn compute_entry_hash_event_changes_hash() {
        let h1 = compute_entry_hash("MessageSent", "did:key:alice", 1000, &[0u8; 32], None);
        let h2 = compute_entry_hash("MemberJoined", "did:key:alice", 1000, &[0u8; 32], None);
        assert_ne!(h1, h2, "different event must produce different hash");
    }

    /// Changing timestamp with all other fields constant changes the hash.
    #[test]
    fn compute_entry_hash_timestamp_changes_hash() {
        let h1 = compute_entry_hash("MessageSent", "did:key:alice", 1000, &[0u8; 32], None);
        let h2 = compute_entry_hash("MessageSent", "did:key:alice", 1001, &[0u8; 32], None);
        assert_ne!(h1, h2, "different timestamp must produce different hash");
    }

    /// Changing `prev_hash` with all other fields constant changes the hash.
    #[test]
    fn compute_entry_hash_prev_hash_changes_hash() {
        let h1 = compute_entry_hash("MessageSent", "did:key:alice", 1000, &[0u8; 32], None);
        let h2 = compute_entry_hash("MessageSent", "did:key:alice", 1000, &[1u8; 32], None);
        assert_ne!(h1, h2, "different prev_hash must produce different hash");
    }

    /// Chain verification succeeds for a valid 3-entry chain.
    #[test]
    fn chain_verification_succeeds_for_valid_chain() {
        let provider = MerkleEventLogProvider::new();
        let ctx_id = [20u8; 32];
        provider.init_event_log(&ctx_id).unwrap();
        provider
            .append_event(&ctx_id, "Event1", "did:key:alice", None)
            .unwrap();
        provider
            .append_event(&ctx_id, "Event2", "did:key:bob", None)
            .unwrap();
        provider
            .append_event(&ctx_id, "Event3", "did:key:carol", None)
            .unwrap();
        assert!(
            provider.verify_chain(&ctx_id),
            "valid 3-entry chain must verify"
        );
    }

    /// Chain verification fails when `actor_did` in an entry is tampered.
    #[test]
    fn chain_verification_fails_for_tampered_actor_did() {
        let provider = MerkleEventLogProvider::new();
        let ctx_id = [21u8; 32];
        provider.init_event_log(&ctx_id).unwrap();
        provider
            .append_event(&ctx_id, "Event1", "did:key:alice", None)
            .unwrap();
        provider
            .append_event(&ctx_id, "Event2", "did:key:bob", None)
            .unwrap();

        {
            let mut logs = provider.logs.lock().unwrap();
            let log = logs.get_mut(&ctx_id).unwrap();
            log.entries[1].actor_did = "did:key:mallory".to_owned();
        }

        assert!(
            !provider.verify_chain(&ctx_id),
            "tampered actor_did must fail chain verification"
        );
    }

    /// Chain verification fails when event name in an entry is tampered.
    #[test]
    fn chain_verification_fails_for_tampered_event() {
        let provider = MerkleEventLogProvider::new();
        let ctx_id = [22u8; 32];
        provider.init_event_log(&ctx_id).unwrap();
        provider
            .append_event(&ctx_id, "Event1", "did:key:alice", None)
            .unwrap();
        provider
            .append_event(&ctx_id, "Event2", "did:key:bob", None)
            .unwrap();

        {
            let mut logs = provider.logs.lock().unwrap();
            let log = logs.get_mut(&ctx_id).unwrap();
            log.entries[1].event = "TamperedEvent".to_owned();
        }

        assert!(
            !provider.verify_chain(&ctx_id),
            "tampered event name must fail chain verification"
        );
    }

    /// Chain verification fails when hash field is tampered.
    #[test]
    fn chain_verification_fails_for_tampered_hash() {
        let provider = MerkleEventLogProvider::new();
        let ctx_id = [23u8; 32];
        provider.init_event_log(&ctx_id).unwrap();
        provider
            .append_event(&ctx_id, "Event1", "did:key:alice", None)
            .unwrap();
        provider
            .append_event(&ctx_id, "Event2", "did:key:bob", None)
            .unwrap();
        provider
            .append_event(&ctx_id, "Event3", "did:key:carol", None)
            .unwrap();

        {
            let mut logs = provider.logs.lock().unwrap();
            let log = logs.get_mut(&ctx_id).unwrap();
            log.entries[0].hash = [0xAA; 32]; // tamper first entry's hash
        }

        assert!(
            !provider.verify_chain(&ctx_id),
            "tampered hash must fail chain verification"
        );
    }

    /// Domain separator "SCP-EXPORT-ENTRY:" and length prefixes are
    /// present in hash computation. Verified by computing the hash manually
    /// and comparing.
    #[test]
    fn domain_separator_present_in_hash() {
        use sha2::{Digest, Sha256};

        let event = "TestEvent";
        let actor_did = "did:key:test";
        let timestamp: u64 = 12345;
        let prev_hash = [0u8; 32];

        // Compute with the function.
        let hash = compute_entry_hash(event, actor_did, timestamp, &prev_hash, None);

        // Compute manually WITH domain separator and length prefixes.
        let event_len = u32::try_from(event.len()).unwrap();
        let actor_len = u32::try_from(actor_did.len()).unwrap();
        let mut hasher = Sha256::new();
        hasher.update(b"SCP-EXPORT-ENTRY:");
        hasher.update(event_len.to_be_bytes());
        hasher.update(event.as_bytes());
        hasher.update(actor_len.to_be_bytes());
        hasher.update(actor_did.as_bytes());
        hasher.update(timestamp.to_be_bytes());
        hasher.update(prev_hash);
        let expected: [u8; 32] = hasher.finalize().into();
        assert_eq!(
            hash, expected,
            "hash must match manual computation with domain separator and length prefixes"
        );

        // Compute manually WITHOUT domain separator — must NOT match.
        let mut hasher_no_sep = Sha256::new();
        hasher_no_sep.update(event.as_bytes());
        hasher_no_sep.update(actor_did.as_bytes());
        hasher_no_sep.update(timestamp.to_be_bytes());
        hasher_no_sep.update(prev_hash);
        let wrong: [u8; 32] = hasher_no_sep.finalize().into();
        assert_ne!(hash, wrong, "hash without domain separator must differ");
    }

    // -----------------------------------------------------------------------
    // Structured payload tests (H11-H12)
    // -----------------------------------------------------------------------

    /// Payload is included in the Merkle hash: same entry with different
    /// payloads must produce different hashes.
    #[test]
    fn test_payload_in_hash() {
        let h_none = compute_entry_hash(
            "GovernanceActionExecuted",
            "did:key:admin",
            1000,
            &[0u8; 32],
            None,
        );
        let payload_a = serde_json::json!({"target_did": "did:key:alice"});
        let payload_b = serde_json::json!({"target_did": "did:key:bob"});
        let h_a = compute_entry_hash(
            "GovernanceActionExecuted",
            "did:key:admin",
            1000,
            &[0u8; 32],
            Some(&payload_a),
        );
        let h_b = compute_entry_hash(
            "GovernanceActionExecuted",
            "did:key:admin",
            1000,
            &[0u8; 32],
            Some(&payload_b),
        );

        assert_ne!(h_none, h_a, "payload must change the hash");
        assert_ne!(h_none, h_b, "payload must change the hash");
        assert_ne!(h_a, h_b, "different payloads must produce different hashes");

        // Same payload produces same hash (deterministic).
        let h_a2 = compute_entry_hash(
            "GovernanceActionExecuted",
            "did:key:admin",
            1000,
            &[0u8; 32],
            Some(&payload_a),
        );
        assert_eq!(h_a, h_a2, "same payload must produce same hash");
    }

    /// Entries without payload are backward compatible: hash matches the
    /// pre-payload computation.
    #[test]
    fn test_backward_compat_no_payload() {
        // Hash with None payload must equal hash without payload (the old
        // computation that didn't have the payload parameter at all).
        use sha2::{Digest, Sha256};

        let event = "MessageSent";
        let actor_did = "did:key:alice";
        let timestamp: u64 = 5000;
        let prev_hash = [0u8; 32];

        let hash = compute_entry_hash(event, actor_did, timestamp, &prev_hash, None);

        // Manual computation matching the pre-payload hash algorithm.
        let event_len = u32::try_from(event.len()).unwrap();
        let actor_len = u32::try_from(actor_did.len()).unwrap();
        let mut hasher = Sha256::new();
        hasher.update(b"SCP-EXPORT-ENTRY:");
        hasher.update(event_len.to_be_bytes());
        hasher.update(event.as_bytes());
        hasher.update(actor_len.to_be_bytes());
        hasher.update(actor_did.as_bytes());
        hasher.update(timestamp.to_be_bytes());
        hasher.update(prev_hash);
        // No payload bytes — backward compatible.
        let expected: [u8; 32] = hasher.finalize().into();

        assert_eq!(
            hash, expected,
            "None payload must produce the same hash as the pre-payload algorithm"
        );
    }

    /// `MerkleEventLogProvider` stores and returns payload through append/read.
    #[test]
    fn test_payload_roundtrip_through_provider() {
        let provider = MerkleEventLogProvider::new();
        let ctx_id = [88u8; 32];
        provider.init_event_log(&ctx_id).unwrap();

        // Append without payload.
        provider
            .append_event(&ctx_id, "MessageSent", "did:key:alice", None)
            .unwrap();

        // Append with payload.
        let payload = serde_json::json!({"target_did": "did:key:bob"});
        provider
            .append_event(
                &ctx_id,
                "GovernanceActionExecuted",
                "did:key:admin",
                Some(&payload),
            )
            .unwrap();

        let entries = provider.event_log_entries(&ctx_id).unwrap().unwrap();
        assert_eq!(entries.len(), 2);

        // First entry has no payload.
        assert!(entries[0].payload.is_none());

        // Second entry has the payload.
        assert_eq!(entries[1].payload, Some(payload));

        // Chain still verifies.
        assert!(provider.verify_chain(&ctx_id));
    }
}
