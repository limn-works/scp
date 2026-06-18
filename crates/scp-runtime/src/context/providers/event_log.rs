//! Production [`ContextEventLogProvider`] backed by [`scp_event_log::EventLog`].
//!
//! [`MerkleEventLogProvider`] maintains a per-context append-only Merkle tree
//! using the canonical [`scp_event_log`] substrate — the same RFC 6962 tree
//! (`tree::append_unsigned_event`, `tree::root`) the WASM bridge and the FFI
//! UCAN-state log use. This is the native↔WASM event-log unification: both
//! implementations now route every leaf through the identical preimage
//! (`SHA-256(0x00 ‖ rmp_serde(Event))`), so their Merkle roots converge and
//! §9.9.3 equivocation detection cannot false-positive on encoding drift.
//!
//! # Persistence (#636, #710)
//!
//! When constructed with [`MerkleEventLogProvider::with_persistence`], the
//! provider persists [`scp_event_log::Event`] values to an
//! [`EventLogPersistence`] backend after each append operation and loads them
//! during [`restore_event_log`](MerkleEventLogProvider::restore_event_log).
//! This ensures events survive process restarts. Each event is persisted
//! individually (O(1) per append); bulk operations (prune, import) rewrite all
//! events.
//!
//! # Integrity model
//!
//! Tamper evidence comes from the substrate Merkle tree, not a side hash
//! chain: each [`scp_event_log::Event`] carries a `prev_hash` link verified by
//! [`scp_event_log::tree::append_unsigned_event`], and the Merkle root
//! ([`scp_event_log::tree::root`]) commits to the full leaf sequence. Events
//! are appended with an empty signature (`signature: vec![]`): the runtime
//! does not hold a per-event signing key at the provider boundary, matching the
//! WASM `append_unsigned_event` security model documented in
//! `.docs/lessons/unsigned-event-mcp-bridge.md`.
//!
//! # Thread Safety
//!
//! Interior state is protected by `std::sync::Mutex` because the
//! [`ContextEventLogProvider`] trait methods are synchronous.
//!
//! See ADR-008 (context creation), spec section 9.9 (event log), and the
//! ADR-011 native↔WASM unification amendment in `.docs/adrs/phase-2.md`.

use std::collections::HashMap;
#[allow(
    clippy::disallowed_types,
    reason = "sync `ContextEventLogProvider` trait upstream; `tokio::sync::Mutex` is not usable at a sync trait boundary. Deleted in commits 4-12 of ADR-049 (actor refactor) per plan §Commit ladder; see `~/.claude/plans/generic-moseying-lightning.md`."
)]
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use scp_event_log::{DID, Event, EventLog, EventPayload, EventType};

use crate::context::builder::ContextEventLogProvider;
use scp_protocol::context::builder::ContextCreationError;

/// Per-context event log wrapping the canonical [`scp_event_log::EventLog`].
struct ContextLog {
    /// The RFC 6962 Merkle tree of events for this context.
    log: EventLog,
}

impl ContextLog {
    /// Creates a new empty per-context log keyed by the hex context id.
    fn new(context_id: &[u8; 32]) -> Self {
        Self {
            log: EventLog::new(hex::encode(context_id)),
        }
    }

    /// Appends a new typed event, computing the sequence + `prev_hash` chain
    /// link and delegating to [`scp_event_log::tree::append_unsigned_event`].
    ///
    /// Mirrors the WASM bridge's `append_log_event`
    /// (`crates/scp-ffi/wasm/src/manager.rs`): the event carries an empty
    /// signature, and sequence/`prev_hash` are derived from the current log
    /// state so `append_unsigned_event`'s validation always passes.
    fn append(
        &mut self,
        event_type: EventType,
        actor_did: &str,
        payload: EventPayload,
    ) -> Result<Event, ContextCreationError> {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let sequence = scp_event_log::tree::event_count(&self.log);
        let leaves = self.log.leaves();
        let prev_hash = if leaves.is_empty() {
            scp_event_log::tree::GENESIS_PREV_HASH
        } else {
            leaves[leaves.len() - 1]
        };

        let event = Event {
            event_type,
            actor_did: DID::from(actor_did.to_owned()),
            timestamp,
            sequence,
            payload,
            prev_hash,
            signature: Vec::new(),
        };

        scp_event_log::tree::append_unsigned_event(&mut self.log, &event).map_err(|e| {
            ContextCreationError::EventLogFailed(format!("event log append failed: {e}"))
        })?;

        Ok(event)
    }
}

// ---------------------------------------------------------------------------
// EventLogPersistence trait (#636)
// ---------------------------------------------------------------------------

/// Persistence adapter for `MerkleEventLogProvider` events.
///
/// Mirrors the [`ContextPersistence`](crate::context::persistence::ContextPersistence)
/// pattern: synchronous trait methods, bridged to async `ProtocolRepository` via
/// `tokio::task::block_in_place` in production.
///
/// All methods use `context_id` as a hex string (matching `ProtocolRepository` key
/// conventions).
///
/// # Per-event storage (#710)
///
/// Each event is stored under its own key (`merkle_event_log/{seq:020d}`)
/// rather than as a single serialized blob. This makes `append_event` O(1)
/// instead of O(n) per persist. Bulk operations (prune, import) use
/// [`persist_entries`](Self::persist_entries) which rewrites all keys.
///
/// See GitHub issues #636, #710.
pub trait EventLogPersistence: Send + Sync {
    /// Persists a single event at the given sequence index.
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
        entry: &Event,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>>;

    /// Persists all events for a context, replacing any previously stored
    /// events.
    ///
    /// Called after bulk operations (prune, import) that rewrite the full
    /// event set. Deletes existing per-event keys before writing.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying storage write fails.
    fn persist_entries(
        &self,
        context_id: &str,
        entries: &[Event],
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>>;

    /// Loads previously persisted events for a context.
    ///
    /// Loads per-event keys by prefix scan.
    /// Returns `None` if no events have been persisted.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying storage read fails.
    fn load_entries(
        &self,
        context_id: &str,
    ) -> Result<Option<Vec<Event>>, Box<dyn std::error::Error + Send + Sync>>;

    /// Deletes persisted events for a context.
    ///
    /// Called on `destroy_event_log`. Removes all per-event keys by prefix.
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

/// Production [`ContextEventLogProvider`] backed by [`scp_event_log::EventLog`].
///
/// Each context gets its own Merkle tree. Events are appended in order, each
/// chaining to its predecessor via the substrate's `prev_hash` link and
/// committed to by the RFC 6962 Merkle root.
///
/// # Persistence
///
/// When constructed with [`with_persistence`](Self::with_persistence), the
/// provider persists events to the given backend after each mutation and loads
/// them via [`restore_event_log`](Self::restore_event_log).
pub struct MerkleEventLogProvider {
    /// Per-context event logs, keyed by context ID bytes.
    #[allow(
        clippy::disallowed_types,
        reason = "sync `ContextEventLogProvider` trait upstream; `tokio::sync::Mutex` is not usable at a sync trait boundary. The actor refactor replaces this provider with an async trait — deleted in commits 4-12 of ADR-049 (actor refactor) per plan §Commit ladder; see `~/.claude/plans/generic-moseying-lightning.md`."
    )]
    logs: Mutex<HashMap<[u8; 32], ContextLog>>,
    /// Optional persistence backend for surviving process restarts (#636).
    persistence: Option<std::sync::Arc<dyn EventLogPersistence>>,
}

#[allow(clippy::significant_drop_tightening)]
#[allow(
    clippy::disallowed_types,
    reason = "sync `ContextEventLogProvider` trait upstream; `tokio::sync::Mutex` is not usable at a sync trait boundary. Deleted in commits 4-12 of ADR-049 (actor refactor) per plan §Commit ladder; see `~/.claude/plans/generic-moseying-lightning.md`."
)]
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

    /// Returns the events for a context, if a log exists.
    ///
    /// Useful for auditing and verification. Returns `None` if no log
    /// has been initialized for the given context.
    #[must_use]
    pub fn entries(&self, context_id: &[u8; 32]) -> Option<Vec<Event>> {
        let logs = self
            .logs
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        logs.get(context_id).map(|log| log.log.events().to_vec())
    }

    /// Runs `f` with read access to a context's canonical [`EventLog`].
    ///
    /// This is the proof seam: `prove_event_inclusion` /
    /// `prove_event_consistency` (in `queries_helpers`) construct Merkle proofs
    /// directly against the provider's tree, so there is no second tree to keep
    /// in sync. Returns `None` if no log exists for the context.
    #[must_use]
    pub fn with_log<T>(&self, context_id: &[u8; 32], f: impl FnOnce(&EventLog) -> T) -> Option<T> {
        let logs = self
            .logs
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        logs.get(context_id).map(|cl| f(&cl.log))
    }

    /// Returns the Merkle root hash for a context's event log.
    ///
    /// Returns `SHA-256("")` (the empty-tree root) if the log is empty.
    /// Returns `None` if no log exists for the context.
    #[must_use]
    pub fn merkle_root(&self, context_id: &[u8; 32]) -> Option<[u8; 32]> {
        let logs = self
            .logs
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let log = logs.get(context_id)?;
        Some(scp_event_log::tree::root(&log.log))
    }

    /// Serializes the events for a context into `MessagePack` bytes.
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
            ContextCreationError::EventLogFailed(format!("failed to serialize event log: {e}"))
        })
    }

    /// Imports serialized events (`MessagePack`) into this provider, replacing
    /// any existing log for the context.
    ///
    /// The imported events are verified for hash-chain + Merkle integrity by
    /// replaying them through [`scp_event_log::tree::append_unsigned_event`]
    /// before being accepted.
    ///
    /// # Errors
    ///
    /// Returns [`ContextCreationError::EventLogFailed`] if deserialization
    /// fails or the hash chain is broken.
    pub fn import_event_log_entries(
        &self,
        context_id: &[u8; 32],
        data: &[u8],
    ) -> Result<(), ContextCreationError> {
        let entries: Vec<Event> = rmp_serde::from_slice(data).map_err(|e| {
            ContextCreationError::EventLogFailed(format!("failed to deserialize event log: {e}"))
        })?;

        let log = rebuild_log_from_events(context_id, &entries)?;

        // Persist the imported events (bulk rewrite).
        self.persist_entries_best_effort(context_id, &entries);

        let mut logs = self
            .logs
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        logs.insert(*context_id, ContextLog { log });
        Ok(())
    }

    /// Restores a context's event log from persisted storage.
    ///
    /// Loads the events from the persistence backend, replays them through the
    /// Merkle tree (verifying chain integrity), and populates the in-memory
    /// log. Called during `ContextManager::restore_context`.
    ///
    /// If no persistence backend is configured or no events are found, the log
    /// is initialized empty.
    ///
    /// # Errors
    ///
    /// Returns [`ContextCreationError::EventLogFailed`] if the persisted
    /// events fail hash-chain verification (data corruption).
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
                            "failed to load persisted event log; initializing empty log"
                        );
                        Vec::new()
                    }
                }
            });

        let log = rebuild_log_from_events(context_id, &entries)?;

        let mut logs = self
            .logs
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        logs.insert(*context_id, ContextLog { log });
        Ok(())
    }

    /// Prunes event log entries before a checkpoint boundary based on a
    /// [`PruningPolicy`](scp_protocol::context::governance::PruningPolicy).
    ///
    /// Called after creating a governance checkpoint (#1474). If the policy
    /// has time-based pruning configured, events older than
    /// `now - retention_secs` (clamped to 30-day minimum) and before the
    /// checkpoint boundary (`checkpoint_event_count`) are removed.
    ///
    /// If only size-based pruning is configured, events beyond
    /// `max_event_count` are removed (keeping the most recent).
    ///
    /// Structural events (governance, membership, lifecycle) are retained
    /// `structural_retention_multiplier / 10000` times longer than
    /// operational events per ADR-030 §2c, classified by the canonical typed
    /// [`scp_event_log::pruning::is_structural_event`].
    ///
    /// The retained tail is reconstructed by re-chaining its events as a fresh
    /// [`scp_event_log::EventLog`] (see [`truncate_log_keeping_tail`]): the
    /// first retained event re-anchors to `GENESIS_PREV_HASH` and each
    /// subsequent event re-chains to the new running head. The pruned
    /// predecessors are gone, so every tail leaf hash (and the resulting root)
    /// CHANGES — this matches the `TruncatedEventLog` semantics where a pruned
    /// log's first entry references a discarded predecessor. Pre-prune proofs
    /// against the OLD root are no longer valid against the re-chained tail;
    /// proofs are re-derived from the new tail or generated against the
    /// retained checkpoint root.
    ///
    /// # Returns
    ///
    /// The number of events removed, or `None` if no log exists for the
    /// context.
    pub fn prune_before_checkpoint(
        &self,
        context_id: &[u8; 32],
        checkpoint_event_count: u64,
        policy: &scp_protocol::context::governance::PruningPolicy,
    ) -> Option<usize> {
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
        let context_log = logs.get_mut(context_id)?;

        let events = context_log.log.events();
        let total = events.len();
        if total == 0 {
            return Some(0);
        }

        // Cannot prune beyond the checkpoint boundary (events at or after the
        // checkpoint are still live).
        #[allow(clippy::cast_possible_truncation)]
        let checkpoint_bound = (checkpoint_event_count as usize).min(total);

        let mut prune_count = 0usize;

        // Time-based and size-based pruning evaluate independently; we take the
        // maximum of the two so that both policies are honored.
        if let Some(ref time_policy) = policy.time_based {
            let retention = time_policy.retention_secs.max(MIN_RETENTION_SECS);

            let mut time_prune = 0usize;
            for event in events.iter().take(checkpoint_bound) {
                let is_structural = scp_event_log::pruning::is_structural_event(&event.event_type);
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

                if event.timestamp < now.saturating_sub(effective_retention) {
                    time_prune += 1;
                } else {
                    // Events are ordered by time; once we find a retained
                    // event, all subsequent are also retained.
                    break;
                }
            }
            prune_count = prune_count.max(time_prune);
        }

        if let Some(ref size_policy) = policy.size_based {
            // Size-based: keep at most `max_event_count` events.
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

        // Reconstruct the retained tail via the canonical substrate truncation
        // so leaf hashes (and proof paths) survive the prune unchanged.
        let pruned_log = match truncate_log_keeping_tail(&context_log.log, prune_count) {
            Ok(log) => log,
            Err(e) => {
                tracing::warn!(
                    context_id = %hex::encode(context_id),
                    error = %e,
                    "event log truncation failed; skipping prune"
                );
                return Some(0);
            }
        };

        tracing::info!(
            context_id = %hex::encode(context_id),
            pruned = prune_count,
            remaining = total - prune_count,
            "pruned event log entries after checkpoint"
        );

        context_log.log = pruned_log;

        // Persist the pruned state (bulk rewrite with renumbered keys).
        let entries_snapshot = context_log.log.events().to_vec();
        drop(logs);
        self.persist_entries_best_effort(context_id, &entries_snapshot);

        Some(prune_count)
    }

    /// Best-effort O(1) persistence of a single event at a given sequence.
    ///
    /// Used by `append_event` to persist only the newly appended event.
    fn persist_entry_best_effort(&self, context_id: &[u8; 32], seq: usize, entry: &Event) {
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

    /// Best-effort bulk persistence: replaces all stored events.
    ///
    /// Used by prune and import operations that rewrite the full event set.
    fn persist_entries_best_effort(&self, context_id: &[u8; 32], entries: &[Event]) {
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

/// Replays a slice of events into a fresh [`EventLog`], verifying the hash
/// chain via [`scp_event_log::tree::append_unsigned_event`].
///
/// Each event's `sequence`/`prev_hash` must already match its position in the
/// sequence; otherwise `append_unsigned_event` rejects it. Used by import and
/// restore so a tampered or reordered persisted log fails closed.
fn rebuild_log_from_events(
    context_id: &[u8; 32],
    entries: &[Event],
) -> Result<EventLog, ContextCreationError> {
    let mut log = EventLog::new(hex::encode(context_id));
    for event in entries {
        scp_event_log::tree::append_unsigned_event(&mut log, event).map_err(|e| {
            ContextCreationError::EventLogFailed(format!(
                "event log chain broken at sequence {}: {e}",
                event.sequence
            ))
        })?;
    }
    Ok(log)
}

/// Drops the first `prune_count` events, returning a new [`EventLog`]
/// containing only the tail.
///
/// Uses [`scp_event_log::checkpoint::TruncatedEventLog::from_log_and_checkpoint`]
/// to validate the prune boundary, then rebuilds a standalone, append-capable
/// `EventLog` from the retained tail events. The tail is RE-CHAINED: the first
/// retained event re-anchors to `GENESIS_PREV_HASH` (its real predecessor was
/// pruned) and each subsequent event re-chains to the new running head. Every
/// non-`prev_hash` field (timestamp, type, payload, signature) is preserved,
/// but because the chaining changes, every tail leaf hash and the resulting
/// Merkle root differ from the pre-prune tree.
fn truncate_log_keeping_tail(
    log: &EventLog,
    prune_count: usize,
) -> Result<EventLog, scp_event_log::EventLogError> {
    use scp_event_log::checkpoint::{ConsistencyCheckpoint, TruncatedEventLog};

    let prune_boundary = prune_count as u64;
    // A synthetic checkpoint marking the prune boundary. `from_log_and_checkpoint`
    // only reads `event_count`; the remaining fields are not consulted, so a
    // zero-valued root/signature is acceptable here.
    let checkpoint = ConsistencyCheckpoint {
        context_id: log.context_id().to_owned(),
        sender_did: DID::from(String::new()),
        event_count: prune_boundary,
        merkle_root: scp_event_log::tree::root(log),
        epoch: None,
        timestamp: 0,
        signature: Vec::new(),
    };

    let truncated = TruncatedEventLog::from_log_and_checkpoint(log, checkpoint)?;

    // Rebuild a standalone EventLog from the retained tail events so the
    // provider continues to own a full (event-backed) log it can append to.
    let mut tail = EventLog::new(log.context_id().to_owned());
    for event in log.events().iter().skip(prune_count) {
        // The tail event's recorded prev_hash references its (now-pruned)
        // predecessor, so re-chain against the tail's own running head while
        // preserving every other field (timestamp, payload, signature). The
        // first retained event re-anchors to GENESIS, matching the
        // checkpoint-truncation semantics (a pruned log's first entry
        // references a discarded predecessor).
        let sequence = scp_event_log::tree::event_count(&tail);
        let leaves = tail.leaves();
        let prev_hash = if leaves.is_empty() {
            scp_event_log::tree::GENESIS_PREV_HASH
        } else {
            leaves[leaves.len() - 1]
        };
        let rechained = Event {
            event_type: event.event_type,
            actor_did: event.actor_did.clone(),
            timestamp: event.timestamp,
            sequence,
            payload: event.payload.clone(),
            prev_hash,
            signature: event.signature.clone(),
        };
        scp_event_log::tree::append_unsigned_event(&mut tail, &rechained)?;
    }
    // `truncated` is consulted only to validate the boundary; the rebuilt
    // `tail` is the authoritative retained log.
    debug_assert_eq!(truncated.tail_event_count(), tail.events().len() as u64);
    Ok(tail)
}

// Nursery lint — false-positives on lock guards across block boundaries.
#[allow(clippy::significant_drop_tightening)]
impl ContextEventLogProvider for MerkleEventLogProvider {
    fn init_event_log(&self, context_id: &[u8; 32]) -> Result<(), ContextCreationError> {
        let mut logs = self
            .logs
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        logs.insert(*context_id, ContextLog::new(context_id));

        // Persist the empty event set to establish the context in storage
        // (clears any stale per-event keys from a previous incarnation).
        drop(logs);
        self.persist_entries_best_effort(context_id, &[]);

        Ok(())
    }

    fn append_event(
        &self,
        context_id: &[u8; 32],
        event_type: EventType,
        actor_did: &str,
        payload: EventPayload,
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
        let event = log.append(event_type, actor_did, payload)?;
        #[allow(clippy::cast_possible_truncation)]
        let seq = event.sequence as usize;

        // O(1) persist: only the newly appended event (#710).
        drop(logs);
        self.persist_entry_best_effort(context_id, seq, &event);

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
    ) -> Result<Option<Vec<Event>>, scp_protocol::context::ContextError> {
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

    fn prove_event_inclusion(
        &self,
        context_id: &[u8; 32],
        leaf_index: u64,
    ) -> Result<scp_event_log::proof::InclusionProof, scp_protocol::context::ContextError> {
        // Build the proof directly against the provider's own canonical tree
        // via `with_log` — no replay, no second tree (the proof seam).
        self.with_log(context_id, |log| {
            scp_event_log::proof::prove_inclusion(log, leaf_index)
                .map_err(|e| scp_protocol::context::ContextError::EventLogFailed(e.to_string()))
        })
        .unwrap_or_else(|| {
            Err(scp_protocol::context::ContextError::EventLogFailed(
                format!("no event log for context {}", hex::encode(context_id)),
            ))
        })
    }

    fn prove_event_consistency(
        &self,
        context_id: &[u8; 32],
        old_size: u64,
    ) -> Result<scp_event_log::proof::ConsistencyProof, scp_protocol::context::ContextError> {
        self.with_log(context_id, |log| {
            let current_size = scp_event_log::tree::event_count(log);
            scp_event_log::proof::prove_consistency(log, old_size, current_size)
                .map_err(|e| scp_protocol::context::ContextError::EventLogFailed(e.to_string()))
        })
        .unwrap_or_else(|| {
            Err(scp_protocol::context::ContextError::EventLogFailed(
                format!("no event log for context {}", hex::encode(context_id)),
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

    fn payload_bytes(data: &[u8]) -> EventPayload {
        EventPayload {
            data: data.to_vec(),
        }
    }

    #[test]
    fn init_creates_empty_log() {
        let provider = MerkleEventLogProvider::new();
        let ctx_id = [1u8; 32];

        provider.init_event_log(&ctx_id).unwrap();

        let entries = provider.entries(&ctx_id).unwrap();
        assert!(entries.is_empty());
    }

    #[test]
    fn append_adds_event_with_hash_chain() {
        let provider = MerkleEventLogProvider::new();
        let ctx_id = [2u8; 32];

        provider.init_event_log(&ctx_id).unwrap();
        provider
            .append_event(
                &ctx_id,
                EventType::ContextCreated,
                "",
                EventPayload::default(),
            )
            .unwrap();
        provider
            .append_event(
                &ctx_id,
                EventType::MemberJoined,
                "",
                EventPayload::default(),
            )
            .unwrap();

        let entries = provider.entries(&ctx_id).unwrap();
        assert_eq!(entries.len(), 2);

        // First event's prev_hash is the genesis sentinel.
        assert_eq!(entries[0].prev_hash, scp_event_log::tree::GENESIS_PREV_HASH);
        assert_eq!(entries[0].event_type, EventType::ContextCreated);
        assert_eq!(entries[0].sequence, 0);

        // Second event's prev_hash equals the first leaf hash.
        let first_leaf = provider.with_log(&ctx_id, |log| log.leaves()[0]).unwrap();
        assert_eq!(entries[1].prev_hash, first_leaf);
        assert_eq!(entries[1].event_type, EventType::MemberJoined);
        assert_eq!(entries[1].sequence, 1);
    }

    #[test]
    fn append_fails_for_uninitialized_context() {
        let provider = MerkleEventLogProvider::new();
        let ctx_id = [3u8; 32];

        let result =
            provider.append_event(&ctx_id, EventType::MessageSent, "", EventPayload::default());
        assert!(result.is_err());
    }

    #[test]
    fn destroy_removes_log() {
        let provider = MerkleEventLogProvider::new();
        let ctx_id = [4u8; 32];

        provider.init_event_log(&ctx_id).unwrap();
        provider
            .append_event(
                &ctx_id,
                EventType::ContextCreated,
                "",
                EventPayload::default(),
            )
            .unwrap();

        provider.destroy_event_log(&ctx_id).unwrap();

        assert!(provider.entries(&ctx_id).is_none());
    }

    #[test]
    fn merkle_root_changes_on_append() {
        let provider = MerkleEventLogProvider::new();
        let ctx_id = [5u8; 32];

        provider.init_event_log(&ctx_id).unwrap();
        let empty_root = provider.merkle_root(&ctx_id).unwrap();
        provider
            .append_event(
                &ctx_id,
                EventType::MessageSent,
                "did:key:a",
                EventPayload::default(),
            )
            .unwrap();
        let one_root = provider.merkle_root(&ctx_id).unwrap();
        assert_ne!(empty_root, one_root);
    }

    #[test]
    fn export_import_roundtrip_preserves_root() {
        let source = MerkleEventLogProvider::new();
        let ctx_id = [6u8; 32];
        source.init_event_log(&ctx_id).unwrap();
        source
            .append_event(
                &ctx_id,
                EventType::ContextCreated,
                "did:key:a",
                EventPayload::default(),
            )
            .unwrap();
        source
            .append_event(
                &ctx_id,
                EventType::GovernanceActionExecuted,
                "did:key:admin",
                payload_bytes(b"some-payload"),
            )
            .unwrap();
        let exported = source.export_event_log_entries(&ctx_id).unwrap();
        let source_root = source.merkle_root(&ctx_id).unwrap();

        let dest = MerkleEventLogProvider::new();
        dest.import_event_log_entries(&ctx_id, &exported).unwrap();
        let dest_root = dest.merkle_root(&ctx_id).unwrap();

        assert_eq!(source_root, dest_root, "import must preserve Merkle root");
        assert_eq!(dest.entries(&ctx_id).unwrap().len(), 2);
    }

    #[test]
    fn import_rejects_tampered_chain() {
        let source = MerkleEventLogProvider::new();
        let ctx_id = [7u8; 32];
        source.init_event_log(&ctx_id).unwrap();
        source
            .append_event(
                &ctx_id,
                EventType::ContextCreated,
                "",
                EventPayload::default(),
            )
            .unwrap();
        source
            .append_event(
                &ctx_id,
                EventType::MemberJoined,
                "",
                EventPayload::default(),
            )
            .unwrap();
        let mut entries = source.entries(&ctx_id).unwrap();

        // Tamper: corrupt the second event's prev_hash chain link.
        entries[1].prev_hash = [0xFF; 32];
        let tampered = rmp_serde::to_vec_named(&entries).unwrap();

        let dest = MerkleEventLogProvider::new();
        let result = dest.import_event_log_entries(&ctx_id, &tampered);
        assert!(result.is_err(), "tampered chain must be rejected on import");
    }

    // -----------------------------------------------------------------------
    // Persistence tests (#636)
    // -----------------------------------------------------------------------

    /// In-memory `EventLogPersistence` for testing.
    struct MockEventLogPersistence {
        #[allow(
            clippy::disallowed_types,
            reason = "Test-only mock state; actor refactor does not migrate test scaffolding. See ADR-049 §'Disallowed types / methods via clippy.toml'."
        )]
        store: Mutex<HashMap<String, Vec<Event>>>,
    }

    #[allow(
        clippy::disallowed_types,
        reason = "Test-only mock state; actor refactor does not migrate test scaffolding. See ADR-049 §'Disallowed types / methods via clippy.toml' and plan §Commit ladder in `~/.claude/plans/generic-moseying-lightning.md`."
    )]
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
            entry: &Event,
        ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
            let mut store = self.store.lock().unwrap();
            let entries = store.entry(context_id.to_owned()).or_default();
            if seq >= entries.len() {
                while entries.len() <= seq {
                    entries.push(Event {
                        event_type: EventType::MessageSent,
                        actor_did: DID::from(String::new()),
                        timestamp: 0,
                        sequence: entries.len() as u64,
                        payload: EventPayload::default(),
                        prev_hash: [0u8; 32],
                        signature: Vec::new(),
                    });
                }
            }
            entries[seq] = entry.clone();
            Ok(())
        }

        fn persist_entries(
            &self,
            context_id: &str,
            entries: &[Event],
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
        ) -> Result<Option<Vec<Event>>, Box<dyn std::error::Error + Send + Sync>> {
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
            .append_event(
                &ctx_id,
                EventType::ContextCreated,
                "",
                EventPayload::default(),
            )
            .unwrap();
        provider
            .append_event(
                &ctx_id,
                EventType::MemberJoined,
                "",
                EventPayload::default(),
            )
            .unwrap();

        let persisted = persistence.load_entries(&ctx_hex).unwrap().unwrap();
        assert_eq!(persisted.len(), 2);
        assert_eq!(persisted[0].event_type, EventType::ContextCreated);
        assert_eq!(persisted[1].event_type, EventType::MemberJoined);
    }

    #[test]
    fn restore_from_persistence() {
        let persistence = std::sync::Arc::new(MockEventLogPersistence::new());
        let ctx_id = [11u8; 32];
        let ctx_hex = hex::encode(ctx_id);

        {
            let provider = MerkleEventLogProvider::with_persistence(persistence.clone());
            provider.init_event_log(&ctx_id).unwrap();
            provider
                .append_event(
                    &ctx_id,
                    EventType::ContextCreated,
                    "",
                    EventPayload::default(),
                )
                .unwrap();
            provider
                .append_event(
                    &ctx_id,
                    EventType::MemberJoined,
                    "",
                    EventPayload::default(),
                )
                .unwrap();
            provider
                .append_event(&ctx_id, EventType::MessageSent, "", EventPayload::default())
                .unwrap();

            assert_eq!(
                persistence.load_entries(&ctx_hex).unwrap().unwrap().len(),
                3
            );
        }

        {
            let provider = MerkleEventLogProvider::with_persistence(persistence);
            provider.restore_event_log(&ctx_id).unwrap();

            let entries = provider.entries(&ctx_id).unwrap();
            assert_eq!(entries.len(), 3);
            assert_eq!(entries[0].event_type, EventType::ContextCreated);
            assert_eq!(entries[2].event_type, EventType::MessageSent);

            // Appending after restore chains correctly.
            provider
                .append_event(&ctx_id, EventType::MemberLeft, "", EventPayload::default())
                .unwrap();
            let entries = provider.entries(&ctx_id).unwrap();
            assert_eq!(entries.len(), 4);
            assert_eq!(entries[3].sequence, 3);
        }
    }

    #[test]
    fn restore_empty_when_no_persistence() {
        let provider = MerkleEventLogProvider::new();
        let ctx_id = [12u8; 32];

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
            .append_event(
                &ctx_id,
                EventType::ContextCreated,
                "",
                EventPayload::default(),
            )
            .unwrap();

        assert!(persistence.load_entries(&ctx_hex).unwrap().is_some());

        provider.destroy_event_log(&ctx_id).unwrap();

        assert!(persistence.load_entries(&ctx_hex).unwrap().is_none());
        assert!(provider.entries(&ctx_id).is_none());
    }

    #[test]
    fn event_log_entries_via_dyn_dispatch() {
        use crate::context::builder::ContextEventLogProvider;

        let provider = MerkleEventLogProvider::new();
        let ctx_id = [19u8; 32];

        provider.init_event_log(&ctx_id).unwrap();
        provider
            .append_event(
                &ctx_id,
                EventType::ContextCreated,
                "",
                EventPayload::default(),
            )
            .unwrap();
        provider
            .append_event(
                &ctx_id,
                EventType::MemberJoined,
                "",
                EventPayload::default(),
            )
            .unwrap();

        let boxed: Box<dyn ContextEventLogProvider> = Box::new(provider);
        let entries = boxed.event_log_entries(&ctx_id).unwrap().unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].event_type, EventType::ContextCreated);
        assert_eq!(entries[1].event_type, EventType::MemberJoined);
    }

    #[test]
    fn append_context_event_delegates_to_append_event() {
        use crate::context::builder::ContextEventLogProvider;

        let provider = MerkleEventLogProvider::new();
        let ctx_id = [7u8; 32];

        provider.init_event_log(&ctx_id).unwrap();
        provider
            .append_context_event(&ctx_id, EventType::MemberLeft, "")
            .unwrap();

        let entries = provider.entries(&ctx_id).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].event_type, EventType::MemberLeft);
    }
}
