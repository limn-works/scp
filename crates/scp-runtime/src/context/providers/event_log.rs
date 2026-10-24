//! Production [`ContextEventLogProvider`] backed by [`scp_event_log::EventLog`].
//!
//! [`MerkleEventLogProvider`] maintains a per-context append-only Merkle tree
//! using the canonical [`scp_event_log`] substrate — the same RFC 6962 tree
//! (`tree::append_unsigned_event`, `tree::root`) the FFI
//! UCAN-state log uses. This is the event-log typed-event unification: every
//! honest member now routes every leaf through the identical preimage
//! (`SHA-256(0x00 ‖ rmp_serde(Event))`), so their Merkle roots converge and
//! §9.9.3 equivocation detection cannot false-positive on encoding drift.
//!
//! # Persistence
//!
//! When constructed with [`MerkleEventLogProvider::with_persistence`], the
//! provider persists [`scp_event_log::Event`] values to an
//! [`EventLogPersistence`] backend after each append operation and loads them
//! during [`restore_event_log`](MerkleEventLogProvider::restore_event_log).
//! This ensures events survive process restarts. An append persists one unit
//! (O(1) per append); bulk operations (init, prune, import) replace the whole
//! stored log in one commit. A per-context write gate serializes the writes to
//! one context, so storage receives them in the order memory applied them.
//!
//! # Integrity model
//!
//! Tamper evidence comes from the substrate Merkle tree, not a side hash
//! chain: each [`scp_event_log::Event`] carries a `prev_hash` link verified by
//! [`scp_event_log::tree::append_unsigned_event`], and the Merkle root
//! ([`scp_event_log::tree::root`]) commits to the full leaf sequence. Events
//! are appended with an empty signature (`signature: vec![]`): the runtime
//! does not hold a per-event signing key at the provider boundary, matching the
//! `append_unsigned_event` security model documented in
//! `.docs/lessons/unsigned-event-mcp-bridge.md`.
//!
//! # Thread Safety
//!
//! The in-memory Merkle tree is protected by a `std::sync::Mutex`. Under ADR-049
//! Decision 7 the persistence-touching `ContextEventLogProvider` methods are
//! `async` (they `.await` the async `EventLogPersistence` backend), but every
//! lock is scoped and dropped BEFORE any `.await`, so the guard never crosses a
//! suspension point — a `std::sync::Mutex` is correct and a `tokio::sync::Mutex`
//! would add unnecessary overhead. The pure in-memory read methods stay
//! synchronous (see the trait's async-discipline note).
//!
//! See ADR-008 (context creation), spec section 9.9 (event log), and the
//! ADR-011 typed-event unification amendment in `.docs/adrs/phase-2.md`.

use std::collections::HashMap;
#[allow(
    clippy::disallowed_types,
    reason = "`std::sync::Mutex` guards only synchronous in-memory Merkle-tree operations; every lock is scoped and dropped BEFORE any `.await` on the async `EventLogPersistence` backend (ADR-049 Decision 7), so the guard is never held across a suspension point and a `tokio::sync::Mutex` would add unnecessary overhead."
)]
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use scp_did::DID;
use scp_event_log::{Event, EventLog, EventPayload, EventType};

use crate::context::builder::{ContextEventLogProvider, EventLogRestore};
use scp_protocol::context::builder::ContextCreationError;

/// Per-context event log wrapping the canonical [`scp_event_log::EventLog`].
struct ContextLog {
    /// The RFC 6962 Merkle tree of events for this context.
    log: EventLog,
    /// Set when a unit persist or a replace failed, so the stored log may
    /// differ from `log`. While it is set, the next write replaces the whole
    /// stored log with `log`, and only a replace that succeeds clears it
    /// (spec section 17.3, "Merkle event log entries"). Read and written only
    /// under the context's write gate.
    storage_diverged: bool,
}

impl ContextLog {
    /// Creates a new empty per-context log keyed by the hex context id.
    fn new(context_id: &[u8; 32]) -> Self {
        Self::from_log(EventLog::new(hex::encode(context_id)))
    }

    /// Wraps a log whose stored copy matches it.
    const fn from_log(log: EventLog) -> Self {
        Self {
            log,
            storage_diverged: false,
        }
    }

    /// Appends a new typed event, computing the sequence + `prev_hash` chain
    /// link and delegating to [`scp_event_log::tree::append_unsigned_event`].
    ///
    /// The event carries an empty signature, and sequence/`prev_hash` are
    /// derived from the current log state so `append_unsigned_event`'s
    /// validation always passes.
    fn append(
        &mut self,
        event_type: EventType,
        actor_did: &str,
        payload: EventPayload,
        timestamp: u64,
    ) -> Result<Event, ContextCreationError> {
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
/// pattern: `#[async_trait]` methods that `.await` the async `ProtocolRepository`
/// directly (ADR-049 Decision 7). Held as `Arc<dyn EventLogPersistence>` inside the
/// provider, which is reachable from `ActorDeps` (moved into `tokio::spawn`), so the
/// futures must be **Send** — plain `#[async_trait]`, not `?Send`.
///
/// All methods use `context_id` as a hex string (matching `ProtocolRepository` key
/// conventions).
///
/// # Atomicity
///
/// Each method either takes full effect or none (spec section 17.3, "Merkle
/// event log entries"). [`persist_unit`](Self::persist_unit) stores a unit of
/// one or more events in one write, and [`replace`](Self::replace) swaps the
/// whole stored log at one commit point, so a failure never leaves a prefix of
/// a unit or of a replacement log loadable.
#[async_trait::async_trait]
pub trait EventLogPersistence: Send + Sync {
    /// Persists one unit of events: `entries[0]` has sequence `base_seq` and
    /// the rest follow it in order.
    ///
    /// Called after each append. After an error, a load returns either every
    /// entry of the unit or none of them.
    ///
    /// # Errors
    ///
    /// Returns an error if `entries` is empty, if `base_seq` cannot start a
    /// unit of the stored log, or if the underlying storage write fails.
    async fn persist_unit(
        &self,
        context_id: &str,
        base_seq: u64,
        entries: &[Event],
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>>;

    /// Replaces a context's whole stored log with `entries`.
    ///
    /// Called by init, prune, and import. After an error, a load returns
    /// either exactly the old log or exactly `entries`.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying storage write fails before the
    /// replacement commits.
    async fn replace(
        &self,
        context_id: &str,
        entries: &[Event],
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>>;

    /// Loads a context's stored log.
    ///
    /// Returns `None` when storage holds no log for the context: no `head`
    /// key, whatever units remain. Otherwise reads the units of the
    /// generation `head` names, in key order, up to the length `head` records
    /// (spec section 17.3, "Merkle event log entries").
    ///
    /// # Errors
    ///
    /// Returns an error, and never a truncated log, when the stored log is
    /// unreadable. The storage-backed implementation returns
    /// [`StoreError::EventLogUnitMisaligned`](crate::store::StoreError::EventLogUnitMisaligned)
    /// for a gap or an overlap between units,
    /// [`StoreError::EventLogLengthMismatch`](crate::store::StoreError::EventLogLengthMismatch)
    /// when the units do not hold the length `head` records,
    /// [`StoreError::DeserializationFailed`](crate::store::StoreError::DeserializationFailed)
    /// for an empty unit, a unit key that does not parse, or an undecodable
    /// value, and [`StoreError::Storage`](crate::store::StoreError::Storage)
    /// when a storage read fails.
    async fn load_entries(
        &self,
        context_id: &str,
    ) -> Result<Option<Vec<Event>>, Box<dyn std::error::Error + Send + Sync>>;

    /// Deletes persisted events for a context.
    ///
    /// Called on `destroy_event_log`. After it returns `Ok`, a load returns
    /// `None`.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying storage delete fails.
    async fn delete_entries(
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
        reason = "`std::sync::Mutex` guards only synchronous in-memory Merkle-tree operations; every lock is scoped and dropped BEFORE any `.await` on the async `EventLogPersistence` backend (ADR-049 Decision 7), so the guard is never held across a suspension point and a `tokio::sync::Mutex` would add unnecessary overhead."
    )]
    logs: Mutex<HashMap<[u8; 32], ContextLog>>,
    /// Per-context write gates. Each write to a context holds its gate's one
    /// permit from the in-memory change through the persist, so writes to one
    /// context never interleave and storage applies them in memory's order.
    /// [`MerkleEventLogProvider::release_write_gate`] removes a gate only
    /// when no writer holds or waits on it.
    write_gates: dashmap::DashMap<[u8; 32], WriteGate>,
    /// Optional persistence backend for surviving process restarts (#636).
    persistence: Option<std::sync::Arc<dyn EventLogPersistence>>,
}

/// A context's write gate: a semaphore with one permit. A writer that holds
/// or awaits the permit holds a clone of the `Arc`, which
/// [`MerkleEventLogProvider::release_write_gate`] counts.
type WriteGate = std::sync::Arc<tokio::sync::Semaphore>;

#[allow(clippy::significant_drop_tightening)]
#[allow(
    clippy::disallowed_types,
    reason = "`std::sync::Mutex` guards only synchronous in-memory Merkle-tree operations; every lock is scoped and dropped BEFORE any `.await` on the async `EventLogPersistence` backend (ADR-049 Decision 7), so the guard is never held across a suspension point and a `tokio::sync::Mutex` would add unnecessary overhead."
)]
impl MerkleEventLogProvider {
    /// Creates a new empty event log provider (in-memory only).
    #[must_use]
    pub fn new() -> Self {
        Self {
            logs: Mutex::new(HashMap::new()),
            write_gates: dashmap::DashMap::new(),
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
            write_gates: dashmap::DashMap::new(),
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
    pub async fn import_event_log_entries(
        &self,
        context_id: &[u8; 32],
        data: &[u8],
    ) -> Result<(), ContextCreationError> {
        let entries: Vec<Event> = rmp_serde::from_slice(data).map_err(|e| {
            ContextCreationError::EventLogFailed(format!("failed to deserialize event log: {e}"))
        })?;

        let log = rebuild_log_from_events(context_id, &entries)?;

        let _write = self.lock_write_gate(context_id).await?;
        // Persist the imported events (one replace).
        let stored = self.replace_best_effort(context_id, &entries).await;

        let mut logs = self
            .logs
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        logs.insert(
            *context_id,
            ContextLog {
                log,
                storage_diverged: !stored,
            },
        );
        Ok(())
    }

    /// Restores a context's event log from persisted storage, failing closed.
    ///
    /// Loads the events from the persistence backend, replays them through the
    /// Merkle tree (verifying chain integrity), and populates the in-memory
    /// log. Called during `Supervisor::restore_context`.
    ///
    /// Starts an empty log and returns [`EventLogRestore::Absent`] only when no
    /// persistence backend is configured or the backend holds no log for the
    /// context (spec section 17.3, "Merkle event log entries").
    ///
    /// # Errors
    ///
    /// Returns [`ContextCreationError::EventLogFailed`] if loading the stored
    /// log fails or its events fail hash-chain verification. The in-memory
    /// log and the stored log are then unchanged, so a later append cannot
    /// overwrite stored units. When the context then has no log in memory, the
    /// restore also releases the context's write gate, so a failed restore
    /// leaves no gate behind.
    pub async fn restore_event_log(
        &self,
        context_id: &[u8; 32],
    ) -> Result<EventLogRestore, ContextCreationError> {
        let write = self.lock_write_gate(context_id).await?;
        match self.load_log_for_restore(context_id).await {
            Ok((log, restore)) => {
                let mut logs = self
                    .logs
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                logs.insert(*context_id, ContextLog::from_log(log));
                Ok(restore)
            }
            Err(e) => {
                drop(write);
                let has_log = self
                    .logs
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .contains_key(context_id);
                if !has_log {
                    self.release_write_gate(context_id);
                }
                Err(e)
            }
        }
    }

    /// Loads and verifies a context's stored log for [`Self::restore_event_log`],
    /// or starts an empty log when storage holds none. The caller holds the
    /// context's write gate.
    async fn load_log_for_restore(
        &self,
        context_id: &[u8; 32],
    ) -> Result<(EventLog, EventLogRestore), ContextCreationError> {
        let context_id_hex = hex::encode(context_id);
        let stored = match self.persistence.as_ref() {
            None => None,
            Some(persistence) => persistence
                .load_entries(&context_id_hex)
                .await
                .map_err(|e| {
                    ContextCreationError::EventLogFailed(format!(
                        "loading the stored event log of context {context_id_hex} failed: {e}"
                    ))
                })?,
        };
        Ok(match stored {
            Some(entries) => (
                rebuild_log_from_events(context_id, &entries)?,
                EventLogRestore::Loaded {
                    entries: entries.len(),
                },
            ),
            None => (EventLog::new(context_id_hex), EventLogRestore::Absent),
        })
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
    pub async fn prune_before_checkpoint(
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

        let _write = match self.lock_write_gate(context_id).await {
            Ok(permit) => permit,
            Err(e) => {
                tracing::error!(
                    context_id = %hex::encode(context_id),
                    error = %e,
                    "event log prune could not take the write gate; skipping prune"
                );
                return None;
            }
        };

        let (prune_count, entries_snapshot) = {
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
                    let is_structural =
                        scp_event_log::pruning::is_structural_event(&event.event_type);
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

            // Reconstruct the retained tail via the canonical substrate truncation.
            // The tail is RE-CHAINED to a fresh genesis (see
            // `truncate_log_keeping_tail`): the first retained event re-anchors to
            // `GENESIS_PREV_HASH`, so every tail leaf hash and the resulting Merkle
            // root CHANGE. Pre-prune proofs against the OLD root are intentionally
            // invalidated, matching RFC 6962 log truncation semantics.
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

            // Persist the pruned state (one replace with renumbered sequences).
            let entries_snapshot = context_log.log.events().to_vec();
            (prune_count, entries_snapshot)
        };
        let stored = self
            .replace_best_effort(context_id, &entries_snapshot)
            .await;
        self.set_storage_diverged(context_id, !stored);

        Some(prune_count)
    }

    /// Returns the write gate for a context, creating it on first use.
    fn write_gate(&self, context_id: &[u8; 32]) -> WriteGate {
        // The shard guard drops at the end of this statement, before any
        // caller awaits the gate.
        std::sync::Arc::clone(
            self.write_gates
                .entry(*context_id)
                .or_insert_with(|| std::sync::Arc::new(tokio::sync::Semaphore::new(1)))
                .value(),
        )
    }

    /// Waits for and takes a context's write gate. The returned permit holds
    /// a clone of the gate until it drops.
    ///
    /// # Errors
    ///
    /// Returns [`ContextCreationError::EventLogFailed`] if the gate's
    /// semaphore is closed. No code closes it, so this error marks a bug.
    async fn lock_write_gate(
        &self,
        context_id: &[u8; 32],
    ) -> Result<tokio::sync::OwnedSemaphorePermit, ContextCreationError> {
        self.write_gate(context_id)
            .acquire_owned()
            .await
            .map_err(|e| {
                ContextCreationError::EventLogFailed(format!(
                    "event log write gate for context {} is closed: {e}",
                    hex::encode(context_id)
                ))
            })
    }

    /// Removes a context's write gate when no writer holds or waits on it.
    ///
    /// Every path that removes a context's log from this provider must call
    /// this after its own permit drops; otherwise the gate stays in
    /// `write_gates` for the life of the provider. `destroy_event_log` is
    /// one such path; a restore that fails while the context has no log in
    /// memory is another.
    ///
    /// Every writer clones the gate inside [`Self::write_gate`] under the
    /// map's shard lock, and `remove_if` reads the clone count under that same
    /// lock. A count of 1 (the map's own reference) therefore means no writer
    /// holds the gate and none can take it before the removal. A gate that a
    /// waiter still holds stays in the map, so a later writer reuses it rather
    /// than creating a second gate for the context.
    fn release_write_gate(&self, context_id: &[u8; 32]) {
        self.write_gates.remove_if(context_id, |_, gate| {
            std::sync::Arc::strong_count(gate) == 1
        });
    }

    /// Best-effort persistence of one unit that starts at `base_seq`.
    ///
    /// Used by `append_event` to persist only the newly appended event.
    /// Returns whether the stored log now matches memory: `true` after a
    /// successful persist or when no backend is configured.
    async fn persist_unit_best_effort(
        &self,
        context_id: &[u8; 32],
        base_seq: u64,
        entries: &[Event],
    ) -> bool {
        let Some(ref persistence) = self.persistence else {
            return true;
        };
        let context_id_hex = hex::encode(context_id);
        match persistence
            .persist_unit(&context_id_hex, base_seq, entries)
            .await
        {
            Ok(()) => true,
            Err(e) => {
                tracing::warn!(
                    context_id = %context_id_hex,
                    error = %e,
                    "failed to persist event log unit; the next write replaces the stored log"
                );
                false
            }
        }
    }

    /// Best-effort replace of the whole stored log.
    ///
    /// Used by init, prune, import, and an append over a diverged stored log.
    /// Returns whether the stored log now matches memory: `true` after a
    /// successful replace or when no backend is configured.
    async fn replace_best_effort(&self, context_id: &[u8; 32], entries: &[Event]) -> bool {
        let Some(ref persistence) = self.persistence else {
            return true;
        };
        let context_id_hex = hex::encode(context_id);
        match persistence.replace(&context_id_hex, entries).await {
            Ok(()) => true,
            Err(e) => {
                tracing::warn!(
                    context_id = %context_id_hex,
                    error = %e,
                    "failed to replace persisted event log; the next write replaces it again"
                );
                false
            }
        }
    }

    /// Records whether a context's stored log may differ from memory after a
    /// write. The caller holds the context's write gate.
    fn set_storage_diverged(&self, context_id: &[u8; 32], diverged: bool) {
        let mut logs = self
            .logs
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(log) = logs.get_mut(context_id) {
            log.storage_diverged = diverged;
        }
    }

    /// Best-effort persistence deletion.
    async fn delete_persisted_best_effort(&self, context_id: &[u8; 32]) {
        if let Some(ref persistence) = self.persistence {
            let context_id_hex = hex::encode(context_id);
            if let Err(e) = persistence.delete_entries(&context_id_hex).await {
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
/// Rebuilds a standalone, append-capable `EventLog` from the retained tail
/// events after validating the prune boundary lies within the event set. The
/// tail is RE-CHAINED: the first
/// retained event re-anchors to `GENESIS_PREV_HASH` (its real predecessor was
/// pruned) and each subsequent event re-chains to the new running head. Every
/// non-`prev_hash` field (timestamp, type, payload, signature) is preserved,
/// but because the chaining changes, every tail leaf hash and the resulting
/// Merkle root differ from the pre-prune tree.
fn truncate_log_keeping_tail(
    log: &EventLog,
    prune_count: usize,
) -> Result<EventLog, scp_event_log::EventLogError> {
    // The prune boundary must lie within the existing event set; the caller
    // (`prune_before_checkpoint`) clamps `prune_count` to the log length, but
    // assert the invariant here so a future caller cannot silently over-prune.
    debug_assert!(
        prune_count <= log.events().len(),
        "prune_count ({prune_count}) exceeds event count ({})",
        log.events().len()
    );

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
    Ok(tail)
}

// Nursery lint — false-positives on lock guards across block boundaries.
#[async_trait::async_trait]
#[allow(clippy::significant_drop_tightening)]
impl ContextEventLogProvider for MerkleEventLogProvider {
    async fn init_event_log(&self, context_id: &[u8; 32]) -> Result<(), ContextCreationError> {
        let _write = self.lock_write_gate(context_id).await?;
        {
            let mut logs = self
                .logs
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            logs.insert(*context_id, ContextLog::new(context_id));
        }

        // Persist the empty event set to establish the context in storage
        // (replaces any stored log from a previous incarnation).
        let stored = self.replace_best_effort(context_id, &[]).await;
        self.set_storage_diverged(context_id, !stored);

        Ok(())
    }

    async fn append_event(
        &self,
        context_id: &[u8; 32],
        event_type: EventType,
        actor_did: &str,
        payload: EventPayload,
        timestamp_secs: u64,
    ) -> Result<(), ContextCreationError> {
        // §5.4.5 `chunks_billed` wire-invariant (C1) — enforced at the
        // event-log APPEND boundary so ANY malformed streaming
        // `OutletInvokedEvent`, from any source, is durably wire-rejected
        // ("refused at log-insert time, not accepted-and-flagged"). The
        // appender holds only the event (opaque `payload` bytes), NOT the
        // chunk sequence or `cancel_ack_seq`, so it enforces the
        // event-LOCAL bound `chunks_billed <= stream_chunk_count`
        // (`verify_outlet_invoked_event_local`); the tighter
        // manifest-derived equality is enforced upstream at chunk-emission
        // time by the dispatch pump's gate. Only payloads that DECODE as an
        // `OutletInvokedEvent` are checked: the `OutletInvoked`
        // discriminator is also carried by the unary saga's join-record
        // payload (a distinct JSON shape lacking the required event fields),
        // which does not decode here and is passed through untouched. This
        // keeps the `scp-event-log` crate runtime-independent — the invariant
        // lives in `scp-runtime`, the crate only owns the error variant.
        if event_type == EventType::OutletInvoked
            && let Ok(invoked) = serde_json::from_slice::<
                scp_protocol::context::outlets::lifecycle::OutletInvokedEvent,
            >(&payload.data)
        {
            crate::context::outlets::stream::verify_outlet_invoked_event_local(&invoked).map_err(
                |err| {
                    let log_err =
                        crate::context::outlets::stream::chunks_billed_error_to_event_log_error(
                            err,
                        );
                    ContextCreationError::EventLogFailed(log_err.to_string())
                },
            )?;
        }

        let _write = self.lock_write_gate(context_id).await?;
        let (event, diverged_log) = {
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
            let event = log.append(event_type, actor_did, payload, timestamp_secs)?;
            // A diverged stored log cannot take one more unit: it may lack
            // earlier entries or hold a replaced log, so it gets the whole
            // in-memory log instead.
            let diverged_log = log.storage_diverged.then(|| log.log.events().to_vec());
            (event, diverged_log)
        };

        let stored = match diverged_log {
            // O(1) persist: a one-entry unit holding only the new event.
            None => {
                self.persist_unit_best_effort(
                    context_id,
                    event.sequence,
                    std::slice::from_ref(&event),
                )
                .await
            }
            Some(entries) => self.replace_best_effort(context_id, &entries).await,
        };
        self.set_storage_diverged(context_id, !stored);

        Ok(())
    }

    async fn destroy_event_log(&self, context_id: &[u8; 32]) -> Result<(), ContextCreationError> {
        {
            let _write = self.lock_write_gate(context_id).await?;
            {
                let mut logs = self
                    .logs
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                logs.remove(context_id);
            }

            // Remove persisted entries.
            self.delete_persisted_best_effort(context_id).await;
        }
        // The permit above dropped, so this provider's own clone of the gate
        // no longer counts.
        self.release_write_gate(context_id);

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

    async fn import_event_log_data(
        &self,
        context_id: &[u8; 32],
        data: &[u8],
    ) -> Result<(), scp_protocol::context::ContextError> {
        self.import_event_log_entries(context_id, data)
            .await
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

    fn event_log_summary(
        &self,
        context_id: &[u8; 32],
    ) -> Result<(usize, [u8; 32]), scp_protocol::context::ContextError> {
        // One lock acquisition for both values, so a concurrent append is
        // either in the count and the root or in neither.
        self.with_log(context_id, |log| {
            (log.events().len(), scp_event_log::tree::root(log))
        })
        .ok_or_else(|| {
            scp_protocol::context::ContextError::EventLogFailed(format!(
                "no event log for context {}",
                hex::encode(context_id)
            ))
        })
    }

    async fn restore_event_log(
        &self,
        context_id: &[u8; 32],
    ) -> Result<EventLogRestore, ContextCreationError> {
        // Delegate to the INHERENT method, which loads persisted entries
        // (`persistence.load_entries`) and replays them via
        // `rebuild_log_from_events`. Without this override, production restart
        // (`Supervisor::restore_context` → `restore_event_log_fail_closed`)
        // dispatches through the `dyn ContextEventLogProvider` trait object and
        // hits the trait DEFAULT (`init_event_log` = empty log), so the
        // persisted Merkle history is silently dropped and inclusion /
        // consistency proofs over pre-restart events fail.
        //
        // The fully-qualified `Self::restore_event_log(self, ..)` path resolves
        // to the INHERENT method (inherent methods take precedence over trait
        // methods in path syntax — same as the sibling `prune_before_checkpoint`
        // override just below); the bare `self.restore_event_log(context_id)`
        // method-call form would resolve back to THIS trait method and recurse
        // infinitely.
        Self::restore_event_log(self, context_id).await
    }

    async fn prune_before_checkpoint(
        &self,
        context_id: &[u8; 32],
        checkpoint_event_count: u64,
        policy: &scp_protocol::context::governance::PruningPolicy,
    ) -> Option<usize> {
        // Delegate to the concrete method on MerkleEventLogProvider.
        Self::prune_before_checkpoint(self, context_id, checkpoint_event_count, policy).await
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

    #[tokio::test]
    async fn init_creates_empty_log() {
        let provider = MerkleEventLogProvider::new();
        let ctx_id = [1u8; 32];

        provider.init_event_log(&ctx_id).await.unwrap();

        let entries = provider.entries(&ctx_id).unwrap();
        assert!(entries.is_empty());
    }

    /// Builds a JSON-encoded `OutletInvokedEvent` payload with the given
    /// chunk/billed counts (the encoding the saga append path uses:
    /// `serde_json::to_vec`), so the provider's append-boundary check can
    /// decode and enforce the §5.4.5 wire-invariant.
    fn outlet_invoked_payload(stream_chunk_count: u32, chunks_billed: u32) -> EventPayload {
        use scp_protocol::context::outlets::OutletStatus;
        use scp_protocol::context::outlets::lifecycle::OutletInvokedEvent;
        use scp_protocol::context::outlets::stream::StreamTerminalStatus;
        let event = OutletInvokedEvent {
            request_id: "00000000000000000000000000000001".to_owned(),
            outlet_id: "outlet-x".to_owned(),
            invoker_did: scp_did::DID("did:dht:z6MkInvoker".to_owned()),
            status: OutletStatus::Success,
            execution_time_ms: 5,
            input_hash: "0".repeat(64),
            output_hash: None,
            cost: None,
            stream_chunk_count,
            chunks_billed,
            stream_manifest_hash: [0x11; 32],
            stream_terminal_status: StreamTerminalStatus::Ok,
            cancel_ack_seq: None,
            audit_anomaly: None,
        };
        EventPayload {
            data: serde_json::to_vec(&event).unwrap(),
        }
    }

    /// §5.4.5 C1: a well-formed streaming `OutletInvokedEvent`
    /// (`chunks_billed <= stream_chunk_count`) appends; a tampered one
    /// (`chunks_billed > stream_chunk_count`) is wire-rejected at
    /// `append_event` with the `ChunksBilledMismatch` error surfaced.
    #[tokio::test]
    async fn append_rejects_outlet_invoked_chunks_billed_over_count() {
        let provider = MerkleEventLogProvider::new();
        let ctx_id = [7u8; 32];
        provider.init_event_log(&ctx_id).await.unwrap();

        // Well-formed: 3 billed of 5 total chunks — appends.
        provider
            .append_event(
                &ctx_id,
                EventType::OutletInvoked,
                "did:dht:z6MkInvoker",
                outlet_invoked_payload(5, 3),
                1_700_000_000,
            )
            .await
            .expect("well-formed OutletInvokedEvent must append");
        assert_eq!(provider.entries(&ctx_id).unwrap().len(), 1);

        // Tampered: 6 billed of 5 total — impossible; must be rejected and
        // NOT appended.
        let err = provider
            .append_event(
                &ctx_id,
                EventType::OutletInvoked,
                "did:dht:z6MkInvoker",
                outlet_invoked_payload(5, 6),
                1_700_000_000,
            )
            .await
            .expect_err("chunks_billed > stream_chunk_count must be rejected");
        let msg = err.to_string();
        assert!(
            msg.contains("chunks_billed mismatch"),
            "error must surface the §5.4.5 ChunksBilledMismatch: {msg}"
        );
        assert!(
            msg.contains("recorded=6") && msg.contains("reference=5"),
            "error must carry recorded/reference counts: {msg}"
        );
        // The rejected event did NOT land — the log still has exactly one.
        assert_eq!(
            provider.entries(&ctx_id).unwrap().len(),
            1,
            "wire-rejected event must not be appended"
        );

        // Boundary: chunks_billed == stream_chunk_count is admissible.
        provider
            .append_event(
                &ctx_id,
                EventType::OutletInvoked,
                "did:dht:z6MkInvoker",
                outlet_invoked_payload(4, 4),
                1_700_000_000,
            )
            .await
            .expect("chunks_billed == stream_chunk_count must append");
        assert_eq!(provider.entries(&ctx_id).unwrap().len(), 2);
    }

    /// Builds an `OutletStreamChunk` carrying a `Data` payload at `seq`.
    fn stream_data_chunk(seq: u64) -> scp_protocol::context::outlets::stream::OutletStreamChunk {
        scp_protocol::context::outlets::stream::OutletStreamChunk {
            request_id: [0x33; 16],
            sequence: seq,
            payload: scp_protocol::context::outlets::stream::ChunkPayload::Data {
                value: serde_json::json!({ "v": seq }),
            },
            sig: [0u8; 64],
        }
    }

    /// Builds an `OutletStreamChunk` carrying a non-billable `Progress`
    /// payload at `seq`.
    fn stream_progress_chunk(
        seq: u64,
    ) -> scp_protocol::context::outlets::stream::OutletStreamChunk {
        scp_protocol::context::outlets::stream::OutletStreamChunk {
            request_id: [0x33; 16],
            sequence: seq,
            payload: scp_protocol::context::outlets::stream::ChunkPayload::Progress {
                pct: 5_000,
                note: None,
            },
            sig: [0u8; 64],
        }
    }

    /// Builds an `OutletStreamChunk` carrying a terminal `End` payload at
    /// `seq`.
    fn stream_end_chunk(seq: u64) -> scp_protocol::context::outlets::stream::OutletStreamChunk {
        use scp_protocol::provenance::{DataProvenance, DiscoveryMethod, SourceType};
        scp_protocol::context::outlets::stream::OutletStreamChunk {
            request_id: [0x33; 16],
            sequence: seq,
            payload: scp_protocol::context::outlets::stream::ChunkPayload::End {
                aggregate: serde_json::Value::Null,
                provenance: DataProvenance {
                    source_context: "ctx-test".to_owned(),
                    source_type: SourceType::Persistent,
                    counterparties: Vec::new(),
                    purpose: None,
                    discovery_method: DiscoveryMethod::OutOfBand,
                    age: std::time::Duration::from_secs(0),
                    memory_scope: scp_protocol::context::params::MemoryScope::Full,
                    chain_depth: 0,
                    chain_path: None,
                    payment_amount: None,
                    payment_adapter: None,
                    payment_receipt_id: None,
                },
                execution_time_ms: 0,
            },
            sig: [0u8; 64],
        }
    }

    /// Builds an `OutletInvokedEvent` for the manifest-verified append path.
    #[allow(clippy::too_many_arguments)]
    fn manifest_invoked_event(
        stream_chunk_count: u32,
        chunks_billed: u32,
        stream_manifest_hash: [u8; 32],
        cancel_ack_seq: Option<u64>,
    ) -> scp_protocol::context::outlets::lifecycle::OutletInvokedEvent {
        use scp_protocol::context::outlets::OutletStatus;
        use scp_protocol::context::outlets::lifecycle::OutletInvokedEvent;
        use scp_protocol::context::outlets::stream::StreamTerminalStatus;
        OutletInvokedEvent {
            request_id: "00000000000000000000000000000001".to_owned(),
            outlet_id: "outlet-x".to_owned(),
            invoker_did: scp_did::DID("did:dht:z6MkInvoker".to_owned()),
            status: OutletStatus::Success,
            execution_time_ms: 5,
            input_hash: "0".repeat(64),
            output_hash: None,
            cost: None,
            stream_chunk_count,
            chunks_billed,
            stream_manifest_hash,
            stream_terminal_status: StreamTerminalStatus::Ok,
            cancel_ack_seq,
            audit_anomaly: None,
        }
    }

    /// **034 AC22** — `append_outlet_invoked_verified` re-derives the FULL
    /// §5.4.5:566 manifest-derived `chunks_billed` reference from the retained
    /// chunk `Sequence` and wire-rejects an event whose recorded `chunks_billed`
    /// diverges, appending NO event; a corrected event then appends.
    ///
    /// Fixture: 10 chunks = 8 `Data` (seq 0..8) + `Progress`@8 + `End`@9, with
    /// `cancel_ack_seq = Some(5)` ⇒ billable `Data` with `seq <= 5` = 6.
    #[tokio::test]
    async fn append_outlet_invoked_verified_rejects_wrong_chunks_billed_034_ac22() {
        let provider = MerkleEventLogProvider::new();
        let ctx_id = [22u8; 32];
        provider.init_event_log(&ctx_id).await.unwrap();

        // 8 Data (seq 0..8) + Progress@8 + End@9 = 10 chunks total.
        let mut chunks: Vec<_> = (0..8).map(stream_data_chunk).collect();
        chunks.push(stream_progress_chunk(8));
        chunks.push(stream_end_chunk(9));
        assert_eq!(chunks.len(), 10);
        let root = scp_protocol::context::outlets::stream::compute_chunk_manifest_root(&chunks)
            .expect("manifest root");

        // WRONG chunks_billed = 8; the manifest-derived reference is 6.
        let bad_event = manifest_invoked_event(10, 8, root, Some(5));
        let err = provider
            .append_outlet_invoked_verified(
                &ctx_id,
                &bad_event,
                &chunks,
                "did:dht:z6MkInvoker",
                1_700_000_000,
            )
            .await
            .expect_err("recorded chunks_billed=8 diverges from manifest reference=6");
        let msg = err.to_string();
        assert!(
            msg.contains("chunks_billed mismatch"),
            "error must surface the §5.4.5 ChunksBilledMismatch: {msg}"
        );
        assert!(
            msg.contains("recorded=8") && msg.contains("reference=6"),
            "error must carry recorded=8 / reference=6: {msg}"
        );
        // No event was appended — the log has no entries.
        assert!(
            provider.entries(&ctx_id).unwrap().is_empty(),
            "wire-rejected event must not be appended"
        );

        // Corrected chunks_billed = 6 (the manifest reference) now appends.
        let good_event = manifest_invoked_event(10, 6, root, Some(5));
        provider
            .append_outlet_invoked_verified(
                &ctx_id,
                &good_event,
                &chunks,
                "did:dht:z6MkInvoker",
                1_700_000_000,
            )
            .await
            .expect("corrected event whose chunks_billed==manifest reference must append");
        assert_eq!(
            provider.entries(&ctx_id).unwrap().len(),
            1,
            "corrected event appended exactly once"
        );
    }

    /// **034 AC21** — the `chunks_billed <= stream_chunk_count` invariant holds
    /// for a correctly-built streaming event AND the FULL manifest verification
    /// accepts it (the positive path of AC22): billable count (6) never exceeds
    /// the total chunk count (10), and the manifest root + leaf count match.
    #[tokio::test]
    async fn append_outlet_invoked_verified_accepts_well_formed_event_034_ac21() {
        let provider = MerkleEventLogProvider::new();
        let ctx_id = [21u8; 32];
        provider.init_event_log(&ctx_id).await.unwrap();

        let mut chunks: Vec<_> = (0..8).map(stream_data_chunk).collect();
        chunks.push(stream_progress_chunk(8));
        chunks.push(stream_end_chunk(9));
        let root = scp_protocol::context::outlets::stream::compute_chunk_manifest_root(&chunks)
            .expect("manifest root");

        let event = manifest_invoked_event(10, 6, root, Some(5));
        // Invariant: billable subset never exceeds the total.
        assert!(
            event.chunks_billed <= event.stream_chunk_count,
            "chunks_billed (6) must be <= stream_chunk_count (10)"
        );
        provider
            .append_outlet_invoked_verified(
                &ctx_id,
                &event,
                &chunks,
                "did:dht:z6MkInvoker",
                1_700_000_000,
            )
            .await
            .expect("well-formed manifest-consistent event must append");
        assert_eq!(provider.entries(&ctx_id).unwrap().len(), 1);
    }

    /// §5.4.5 C1: the unary saga's `OutletInvoked` join-record payload (a
    /// distinct JSON shape lacking the streaming event fields) is passed
    /// through untouched — the append-boundary check only fires on payloads
    /// that decode as an `OutletInvokedEvent`.
    #[tokio::test]
    async fn append_passes_through_saga_outlet_invoked_join_payload() {
        let provider = MerkleEventLogProvider::new();
        let ctx_id = [8u8; 32];
        provider.init_event_log(&ctx_id).await.unwrap();

        // Mirrors the saga.rs join payload: no request_id/status/etc., so it
        // does NOT decode as an OutletInvokedEvent and is not checked.
        let saga_payload = serde_json::json!({
            "saga_id": "saga-1",
            "outlet_invoked_event_id": "evt-1",
            "caller_context_id": "aa",
            "outlet_registration_id": "reg-1",
            "chain_depth": 2,
            "timestamp_ms": 1_700_000_000_000_u64,
        });
        provider
            .append_event(
                &ctx_id,
                EventType::OutletInvoked,
                "did:dht:z6MkCaller",
                EventPayload {
                    data: serde_json::to_vec(&saga_payload).unwrap(),
                },
                1_700_000_000,
            )
            .await
            .expect("saga join-record payload must pass through untouched");
        assert_eq!(provider.entries(&ctx_id).unwrap().len(), 1);
    }

    #[tokio::test]
    async fn append_adds_event_with_hash_chain() {
        let provider = MerkleEventLogProvider::new();
        let ctx_id = [2u8; 32];

        provider.init_event_log(&ctx_id).await.unwrap();
        provider
            .append_event(
                &ctx_id,
                EventType::ContextCreated,
                "",
                EventPayload::default(),
                1_700_000_000,
            )
            .await
            .unwrap();
        provider
            .append_event(
                &ctx_id,
                EventType::MemberJoined,
                "",
                EventPayload::default(),
                1_700_000_000,
            )
            .await
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

    #[tokio::test]
    async fn append_fails_for_uninitialized_context() {
        let provider = MerkleEventLogProvider::new();
        let ctx_id = [3u8; 32];

        let result = provider
            .append_event(
                &ctx_id,
                EventType::MessageSent,
                "",
                EventPayload::default(),
                1_700_000_000,
            )
            .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn destroy_removes_log() {
        let provider = MerkleEventLogProvider::new();
        let ctx_id = [4u8; 32];

        provider.init_event_log(&ctx_id).await.unwrap();
        provider
            .append_event(
                &ctx_id,
                EventType::ContextCreated,
                "",
                EventPayload::default(),
                1_700_000_000,
            )
            .await
            .unwrap();

        provider.destroy_event_log(&ctx_id).await.unwrap();

        assert!(provider.entries(&ctx_id).is_none());
    }

    #[tokio::test]
    async fn merkle_root_changes_on_append() {
        let provider = MerkleEventLogProvider::new();
        let ctx_id = [5u8; 32];

        provider.init_event_log(&ctx_id).await.unwrap();
        let empty_root = provider.merkle_root(&ctx_id).unwrap();
        provider
            .append_event(
                &ctx_id,
                EventType::MessageSent,
                "did:key:a",
                EventPayload::default(),
                1_700_000_000,
            )
            .await
            .unwrap();
        let one_root = provider.merkle_root(&ctx_id).unwrap();
        assert_ne!(empty_root, one_root);
    }

    /// `event_log_summary` refuses a context that has no log instead of
    /// reporting the empty-tree root for it, reports `(0, SHA-256(""))` only
    /// for a log that exists and is empty, and returns the count and root of
    /// one tree once entries exist.
    #[tokio::test]
    async fn event_log_summary_distinguishes_missing_from_empty() {
        let provider = MerkleEventLogProvider::new();
        let ctx_id = [23u8; 32];

        let missing = provider.event_log_summary(&ctx_id);
        assert!(
            matches!(
                missing,
                Err(scp_protocol::context::ContextError::EventLogFailed(_))
            ),
            "a context with no event log must be an error, not an empty log: {missing:?}"
        );

        provider.init_event_log(&ctx_id).await.unwrap();
        let empty_root = scp_event_log::tree::root(&EventLog::new(String::new()));
        assert_eq!(
            provider.event_log_summary(&ctx_id).unwrap(),
            (0, empty_root)
        );

        for event_type in [EventType::ContextCreated, EventType::MessageSent] {
            provider
                .append_event(
                    &ctx_id,
                    event_type,
                    "",
                    EventPayload::default(),
                    1_700_000_000,
                )
                .await
                .unwrap();
        }
        assert_eq!(
            provider.event_log_summary(&ctx_id).unwrap(),
            (2, provider.merkle_root(&ctx_id).unwrap())
        );
    }

    #[tokio::test]
    async fn export_import_roundtrip_preserves_root() {
        let source = MerkleEventLogProvider::new();
        let ctx_id = [6u8; 32];
        source.init_event_log(&ctx_id).await.unwrap();
        source
            .append_event(
                &ctx_id,
                EventType::ContextCreated,
                "did:key:a",
                EventPayload::default(),
                1_700_000_000,
            )
            .await
            .unwrap();
        source
            .append_event(
                &ctx_id,
                EventType::GovernanceActionExecuted,
                "did:key:admin",
                payload_bytes(b"some-payload"),
                1_700_000_000,
            )
            .await
            .unwrap();
        let exported = source.export_event_log_entries(&ctx_id).unwrap();
        let source_root = source.merkle_root(&ctx_id).unwrap();

        let dest = MerkleEventLogProvider::new();
        dest.import_event_log_entries(&ctx_id, &exported)
            .await
            .unwrap();
        let dest_root = dest.merkle_root(&ctx_id).unwrap();

        assert_eq!(source_root, dest_root, "import must preserve Merkle root");
        assert_eq!(dest.entries(&ctx_id).unwrap().len(), 2);
    }

    #[tokio::test]
    async fn import_rejects_tampered_chain() {
        let source = MerkleEventLogProvider::new();
        let ctx_id = [7u8; 32];
        source.init_event_log(&ctx_id).await.unwrap();
        source
            .append_event(
                &ctx_id,
                EventType::ContextCreated,
                "",
                EventPayload::default(),
                1_700_000_000,
            )
            .await
            .unwrap();
        source
            .append_event(
                &ctx_id,
                EventType::MemberJoined,
                "",
                EventPayload::default(),
                1_700_000_000,
            )
            .await
            .unwrap();
        let mut entries = source.entries(&ctx_id).unwrap();

        // Tamper: corrupt the second event's prev_hash chain link.
        entries[1].prev_hash = [0xFF; 32];
        let tampered = rmp_serde::to_vec_named(&entries).unwrap();

        let dest = MerkleEventLogProvider::new();
        let result = dest.import_event_log_entries(&ctx_id, &tampered).await;
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

    #[async_trait::async_trait]
    impl EventLogPersistence for MockEventLogPersistence {
        async fn persist_unit(
            &self,
            context_id: &str,
            base_seq: u64,
            entries: &[Event],
        ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
            let base = usize::try_from(base_seq)?;
            let mut store = self.store.lock().unwrap();
            let stored = store.entry(context_id.to_owned()).or_default();
            if base != stored.len() {
                return Err(format!(
                    "unit at {base} does not follow {} stored entries",
                    stored.len()
                )
                .into());
            }
            stored.extend_from_slice(entries);
            Ok(())
        }

        async fn replace(
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

        async fn load_entries(
            &self,
            context_id: &str,
        ) -> Result<Option<Vec<Event>>, Box<dyn std::error::Error + Send + Sync>> {
            Ok(self.store.lock().unwrap().get(context_id).cloned())
        }

        async fn delete_entries(
            &self,
            context_id: &str,
        ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
            self.store.lock().unwrap().remove(context_id);
            Ok(())
        }
    }

    #[tokio::test]
    async fn persistence_on_append() {
        let persistence = std::sync::Arc::new(MockEventLogPersistence::new());
        let provider = MerkleEventLogProvider::with_persistence(persistence.clone());
        let ctx_id = [10u8; 32];
        let ctx_hex = hex::encode(ctx_id);

        provider.init_event_log(&ctx_id).await.unwrap();
        provider
            .append_event(
                &ctx_id,
                EventType::ContextCreated,
                "",
                EventPayload::default(),
                1_700_000_000,
            )
            .await
            .unwrap();
        provider
            .append_event(
                &ctx_id,
                EventType::MemberJoined,
                "",
                EventPayload::default(),
                1_700_000_000,
            )
            .await
            .unwrap();

        let persisted = persistence.load_entries(&ctx_hex).await.unwrap().unwrap();
        assert_eq!(persisted.len(), 2);
        assert_eq!(persisted[0].event_type, EventType::ContextCreated);
        assert_eq!(persisted[1].event_type, EventType::MemberJoined);
    }

    #[tokio::test]
    async fn restore_from_persistence() {
        let persistence = std::sync::Arc::new(MockEventLogPersistence::new());
        let ctx_id = [11u8; 32];
        let ctx_hex = hex::encode(ctx_id);

        {
            let provider = MerkleEventLogProvider::with_persistence(persistence.clone());
            provider.init_event_log(&ctx_id).await.unwrap();
            provider
                .append_event(
                    &ctx_id,
                    EventType::ContextCreated,
                    "",
                    EventPayload::default(),
                    1_700_000_000,
                )
                .await
                .unwrap();
            provider
                .append_event(
                    &ctx_id,
                    EventType::MemberJoined,
                    "",
                    EventPayload::default(),
                    1_700_000_000,
                )
                .await
                .unwrap();
            provider
                .append_event(
                    &ctx_id,
                    EventType::MessageSent,
                    "",
                    EventPayload::default(),
                    1_700_000_000,
                )
                .await
                .unwrap();

            assert_eq!(
                persistence
                    .load_entries(&ctx_hex)
                    .await
                    .unwrap()
                    .unwrap()
                    .len(),
                3
            );
        }

        {
            let provider = MerkleEventLogProvider::with_persistence(persistence);
            provider.restore_event_log(&ctx_id).await.unwrap();

            let entries = provider.entries(&ctx_id).unwrap();
            assert_eq!(entries.len(), 3);
            assert_eq!(entries[0].event_type, EventType::ContextCreated);
            assert_eq!(entries[2].event_type, EventType::MessageSent);

            // Appending after restore chains correctly.
            provider
                .append_event(
                    &ctx_id,
                    EventType::MemberLeft,
                    "",
                    EventPayload::default(),
                    1_700_000_000,
                )
                .await
                .unwrap();
            let entries = provider.entries(&ctx_id).unwrap();
            assert_eq!(entries.len(), 4);
            assert_eq!(entries[3].sequence, 3);
        }
    }

    /// Regression test for the process-restart data-continuity bug: the
    /// production restart path (`Supervisor::restore_context` →
    /// `restore_event_log_fail_closed`) dispatches through a
    /// `&dyn ContextEventLogProvider` trait object. Before this fix, the
    /// `impl ContextEventLogProvider for MerkleEventLogProvider` block did NOT
    /// override `restore_event_log`, so the trait DEFAULT ran
    /// (`init_event_log` = EMPTY log) and the persisted Merkle history was
    /// silently dropped on every restart — inclusion/consistency proofs over
    /// pre-restart events would then fail.
    ///
    /// This test MUST call `restore_event_log` THROUGH the trait object
    /// (`&dyn ContextEventLogProvider`), not the inherent method: calling the
    /// inherent method directly (as `restore_from_persistence` does) would pass
    /// even with the bug present, because the inherent method always replayed
    /// correctly. Only trait-object dispatch exercises the override.
    #[tokio::test]
    async fn restore_via_trait_object_replays_persisted_log() {
        use crate::context::builder::ContextEventLogProvider;

        let persistence = std::sync::Arc::new(MockEventLogPersistence::new());
        let ctx_id = [21u8; 32];

        // Pre-restart incarnation: append N events, capture the Merkle root and
        // entry count that a correct restart must reproduce.
        let (pre_restart_root, pre_restart_len) = {
            let provider = MerkleEventLogProvider::with_persistence(persistence.clone());
            provider.init_event_log(&ctx_id).await.unwrap();
            provider
                .append_event(
                    &ctx_id,
                    EventType::ContextCreated,
                    "did:key:a",
                    EventPayload::default(),
                    1_700_000_000,
                )
                .await
                .unwrap();
            provider
                .append_event(
                    &ctx_id,
                    EventType::MemberJoined,
                    "did:key:b",
                    payload_bytes(b"join"),
                    1_700_000_001,
                )
                .await
                .unwrap();
            provider
                .append_event(
                    &ctx_id,
                    EventType::MessageSent,
                    "did:key:a",
                    payload_bytes(b"hello"),
                    1_700_000_002,
                )
                .await
                .unwrap();

            let root = provider.merkle_root(&ctx_id).unwrap();
            let len = provider.entries(&ctx_id).unwrap().len();
            (root, len)
        };
        assert_eq!(pre_restart_len, 3);

        // Simulate process restart: a FRESH provider over the SAME persistence
        // backend, restored via TRAIT-OBJECT dispatch (the production path).
        let restored = MerkleEventLogProvider::with_persistence(persistence);
        {
            let via_trait: &dyn ContextEventLogProvider = &restored;
            via_trait.restore_event_log(&ctx_id).await.unwrap();
        }

        // The rebuilt in-memory log must match the persisted history exactly:
        // same entry count AND same Merkle root. Under the bug (empty-init
        // default) the count would be 0 and the root the empty-tree root.
        let restored_entries = restored.entries(&ctx_id).unwrap();
        assert_eq!(
            restored_entries.len(),
            pre_restart_len,
            "trait-object restore must replay all persisted entries"
        );
        assert_eq!(restored_entries[0].event_type, EventType::ContextCreated);
        assert_eq!(restored_entries[2].event_type, EventType::MessageSent);
        assert_eq!(
            restored.merkle_root(&ctx_id).unwrap(),
            pre_restart_root,
            "trait-object restore must reproduce the pre-restart Merkle root"
        );

        // The restored log is append-capable and chains from the replayed tail.
        let via_trait: &dyn ContextEventLogProvider = &restored;
        via_trait
            .append_event(
                &ctx_id,
                EventType::MemberLeft,
                "did:key:b",
                EventPayload::default(),
                1_700_000_003,
            )
            .await
            .unwrap();
        let after_append = restored.entries(&ctx_id).unwrap();
        assert_eq!(after_append.len(), 4);
        assert_eq!(after_append[3].sequence, 3);
    }

    #[tokio::test]
    async fn restore_empty_when_no_persistence() {
        let provider = MerkleEventLogProvider::new();
        let ctx_id = [12u8; 32];

        provider.restore_event_log(&ctx_id).await.unwrap();
        let entries = provider.entries(&ctx_id).unwrap();
        assert!(entries.is_empty());
    }

    #[tokio::test]
    async fn destroy_cleans_persistence() {
        let persistence = std::sync::Arc::new(MockEventLogPersistence::new());
        let provider = MerkleEventLogProvider::with_persistence(persistence.clone());
        let ctx_id = [13u8; 32];
        let ctx_hex = hex::encode(ctx_id);

        provider.init_event_log(&ctx_id).await.unwrap();
        provider
            .append_event(
                &ctx_id,
                EventType::ContextCreated,
                "",
                EventPayload::default(),
                1_700_000_000,
            )
            .await
            .unwrap();

        assert!(persistence.load_entries(&ctx_hex).await.unwrap().is_some());

        provider.destroy_event_log(&ctx_id).await.unwrap();

        assert!(persistence.load_entries(&ctx_hex).await.unwrap().is_none());
        assert!(provider.entries(&ctx_id).is_none());
    }

    // -----------------------------------------------------------------------
    // Write gate and atomic storage (spec section 17.3, "Merkle event log
    // entries")
    // -----------------------------------------------------------------------

    /// Persistence that counts calls in flight and parks each call until the
    /// test adds a permit to `park`.
    struct ParkingPersistence {
        park: tokio::sync::Semaphore,
        in_flight: std::sync::atomic::AtomicUsize,
        max_in_flight: std::sync::atomic::AtomicUsize,
    }

    impl ParkingPersistence {
        const fn new() -> Self {
            Self {
                park: tokio::sync::Semaphore::const_new(0),
                in_flight: std::sync::atomic::AtomicUsize::new(0),
                max_in_flight: std::sync::atomic::AtomicUsize::new(0),
            }
        }

        async fn enter_and_park(&self) {
            use std::sync::atomic::Ordering;
            let now = self.in_flight.fetch_add(1, Ordering::SeqCst) + 1;
            self.max_in_flight.fetch_max(now, Ordering::SeqCst);
            self.park.acquire().await.unwrap().forget();
            self.in_flight.fetch_sub(1, Ordering::SeqCst);
        }

        fn in_flight(&self) -> usize {
            self.in_flight.load(std::sync::atomic::Ordering::SeqCst)
        }
    }

    #[async_trait::async_trait]
    impl EventLogPersistence for ParkingPersistence {
        async fn persist_unit(
            &self,
            _context_id: &str,
            _base_seq: u64,
            _entries: &[Event],
        ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
            self.enter_and_park().await;
            Ok(())
        }

        async fn replace(
            &self,
            _context_id: &str,
            _entries: &[Event],
        ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
            self.enter_and_park().await;
            Ok(())
        }

        async fn load_entries(
            &self,
            _context_id: &str,
        ) -> Result<Option<Vec<Event>>, Box<dyn std::error::Error + Send + Sync>> {
            Ok(None)
        }

        async fn delete_entries(
            &self,
            _context_id: &str,
        ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
            self.enter_and_park().await;
            Ok(())
        }
    }

    /// Lets every runnable task on the current-thread runtime run until it
    /// blocks.
    async fn settle() {
        for _ in 0..64 {
            tokio::task::yield_now().await;
        }
    }

    /// A destroy that releases the write gate while another writer waits on
    /// it must not let a later writer take a second gate: at most one write to
    /// a context is ever in its persist call.
    #[tokio::test(flavor = "current_thread")]
    async fn write_gate_admits_one_writer_across_destroy() {
        let persistence = std::sync::Arc::new(ParkingPersistence::new());
        let provider = std::sync::Arc::new(MerkleEventLogProvider::with_persistence(
            persistence.clone(),
        ));
        let ctx_id = [30u8; 32];

        persistence.park.add_permits(1);
        provider.init_event_log(&ctx_id).await.unwrap();
        persistence
            .max_in_flight
            .store(0, std::sync::atomic::Ordering::SeqCst);

        let append = |provider: std::sync::Arc<MerkleEventLogProvider>| async move {
            provider
                .append_event(
                    &ctx_id,
                    EventType::MessageSent,
                    "",
                    EventPayload::default(),
                    1_700_000_000,
                )
                .await
        };

        // A holds the gate, parked in its persist.
        let a = tokio::spawn(append(provider.clone()));
        settle().await;
        assert_eq!(persistence.in_flight(), 1, "A parks in persist_unit");

        // D (destroy) and E (init) wait on the gate, in that order.
        let d = tokio::spawn({
            let provider = provider.clone();
            async move { provider.destroy_event_log(&ctx_id).await }
        });
        settle().await;
        let e = tokio::spawn({
            let provider = provider.clone();
            async move { provider.init_event_log(&ctx_id).await }
        });
        settle().await;

        // A finishes; D takes the gate and parks in delete_entries.
        persistence.park.add_permits(1);
        settle().await;
        assert!(a.is_finished(), "A finished");
        assert_eq!(persistence.in_flight(), 1, "D parks in delete_entries");

        // D finishes and releases the gate while E still waits on it; E takes
        // the gate and parks in replace.
        persistence.park.add_permits(1);
        settle().await;
        assert!(d.is_finished(), "D finished");
        assert_eq!(persistence.in_flight(), 1, "E parks in replace");

        // F must queue behind E on the same gate.
        let f = tokio::spawn(append(provider.clone()));
        settle().await;
        let max = persistence
            .max_in_flight
            .load(std::sync::atomic::Ordering::SeqCst);

        persistence.park.add_permits(16);
        a.await.unwrap().unwrap();
        d.await.unwrap().unwrap();
        e.await.unwrap().unwrap();
        f.await.unwrap().unwrap();

        assert_eq!(
            max, 1,
            "two writes to one context were in persistence at once: the write gate admitted two holders"
        );
        assert_eq!(provider.entries(&ctx_id).unwrap().len(), 1);
    }

    /// A destroy with no waiting writer removes the context's gate, so gates
    /// do not accumulate for destroyed contexts.
    #[tokio::test]
    async fn destroy_releases_an_idle_write_gate() {
        let provider = MerkleEventLogProvider::with_persistence(std::sync::Arc::new(
            MockEventLogPersistence::new(),
        ));
        let ctx_id = [31u8; 32];
        provider.init_event_log(&ctx_id).await.unwrap();
        assert_eq!(provider.write_gates.len(), 1);
        provider.destroy_event_log(&ctx_id).await.unwrap();
        assert!(provider.write_gates.is_empty());
    }

    type Faulty = crate::context::supervisor::faulty_storage::FaultyStorage;

    fn faulty_provider(faulty: &std::sync::Arc<Faulty>) -> MerkleEventLogProvider {
        let repo = std::sync::Arc::new(crate::store::ProtocolRepository::new_for_testing(
            std::sync::Arc::clone(faulty),
        ));
        MerkleEventLogProvider::with_persistence(std::sync::Arc::new(
            crate::store::context::ProtocolRepositoryEventLogBridge::new(repo),
        ))
    }

    fn log_bytes(entries: &[Event]) -> Vec<u8> {
        rmp_serde::to_vec(entries).unwrap()
    }

    #[derive(Clone, Copy, Debug)]
    enum ReplaceOp {
        Prune,
        Import,
        InitOverExisting,
    }

    /// Asserts that the stored log itself, read through the bridge's
    /// `load_entries`, is a whole log: `old` or `new`.
    async fn assert_stored_log_is_old_or_new(
        faulty: &std::sync::Arc<Faulty>,
        ctx_id: &[u8; 32],
        old: &[Event],
        new: &[Event],
        case: &str,
    ) {
        let bridge =
            crate::store::context::ProtocolRepositoryEventLogBridge::new(std::sync::Arc::new(
                crate::store::ProtocolRepository::new_for_testing(std::sync::Arc::clone(faulty)),
            ));
        let stored = bridge
            .load_entries(&hex::encode(ctx_id))
            .await
            .unwrap_or_else(|e| panic!("{case}: the stored log does not load: {e}"))
            .unwrap_or_else(|| panic!("{case}: storage holds no log"));
        assert!(
            log_bytes(&stored) == log_bytes(old) || log_bytes(&stored) == log_bytes(new),
            "{case}: storage holds {} entries, neither the old log ({}) nor the new one ({})",
            stored.len(),
            old.len(),
            new.len()
        );
    }

    /// Prune, import, and init over an existing log each replace the stored
    /// log. For a crash at every put N, a fresh provider restores exactly the
    /// old log or exactly the new one.
    #[tokio::test]
    async fn replace_crashing_at_any_put_restores_old_or_new_log() {
        let ctx_id = [32u8; 32];

        // Import source: a log long enough to need several stored units.
        let source = MerkleEventLogProvider::new();
        source.init_event_log(&ctx_id).await.unwrap();
        for i in 0..300u64 {
            source
                .append_event(
                    &ctx_id,
                    EventType::MessageSent,
                    "",
                    payload_bytes(&i.to_be_bytes()),
                    1_700_000_000 + i,
                )
                .await
                .unwrap();
        }
        let import_data = source.export_event_log_entries(&ctx_id).unwrap();

        let prune_policy = scp_protocol::context::governance::PruningPolicy {
            size_based: Some(scp_protocol::context::governance::SizeBasedPolicy {
                max_event_count: 2,
                max_storage_bytes: u64::MAX,
            }),
            ..Default::default()
        };

        for op in [
            ReplaceOp::Prune,
            ReplaceOp::Import,
            ReplaceOp::InitOverExisting,
        ] {
            let mut saw_old = false;
            let mut saw_new = false;
            // Prune puts 2 keys, import 3, init 1; N = 4 lets every put land.
            for n in 1..=4u64 {
                let faulty = std::sync::Arc::new(Faulty::new(std::sync::Arc::new(
                    scp_platform::in_memory::InMemoryStorage::new(),
                )));
                let provider = faulty_provider(&faulty);
                provider.init_event_log(&ctx_id).await.unwrap();
                append_n(&provider, &ctx_id, 0xA0, 5).await;
                let old = provider.entries(&ctx_id).unwrap();

                faulty.fail_nth_store(n);
                match op {
                    ReplaceOp::Prune => {
                        assert_eq!(
                            provider
                                .prune_before_checkpoint(&ctx_id, 5, &prune_policy)
                                .await,
                            Some(3)
                        );
                    }
                    ReplaceOp::Import => provider
                        .import_event_log_entries(&ctx_id, &import_data)
                        .await
                        .unwrap(),
                    ReplaceOp::InitOverExisting => provider.init_event_log(&ctx_id).await.unwrap(),
                }
                faulty.clear_fail();
                let new = provider.entries(&ctx_id).unwrap();

                assert_stored_log_is_old_or_new(
                    &faulty,
                    &ctx_id,
                    &old,
                    &new,
                    &format!("{op:?} N={n}"),
                )
                .await;

                let restored = faulty_provider(&faulty);
                restored
                    .restore_event_log(&ctx_id)
                    .await
                    .unwrap_or_else(|e| {
                        panic!("{op:?} N={n}: restore rejected the stored log: {e}")
                    });
                let got = restored.entries(&ctx_id).unwrap();
                if log_bytes(&got) == log_bytes(&old) {
                    saw_old = true;
                } else {
                    assert_eq!(
                        log_bytes(&got),
                        log_bytes(&new),
                        "{op:?} N={n}: restored {} entries, neither the old log ({}) nor the new one ({})",
                        got.len(),
                        old.len(),
                        new.len()
                    );
                    saw_new = true;
                }
            }
            assert!(
                saw_old && saw_new,
                "{op:?}: the sweep must reach both outcomes"
            );
        }
    }

    /// Every key and value under `prefix`, for comparing storage before and
    /// after an operation that must not write.
    async fn storage_snapshot(
        storage: &impl scp_platform::traits::Storage,
        prefix: &str,
    ) -> Vec<(String, Option<Vec<u8>>)> {
        let mut snapshot = Vec::new();
        for key in storage.list_keys(prefix).await.unwrap() {
            let value = storage.retrieve(&key).await.unwrap();
            snapshot.push((key, value));
        }
        snapshot
    }

    /// A restore over a stored log that does not load fails, installs no
    /// in-memory log, and leaves every stored key as it was.
    #[tokio::test]
    async fn restore_over_an_unreadable_log_fails_and_leaves_storage_unchanged() {
        use scp_platform::traits::Storage;

        let ctx_id = [33u8; 32];
        let ctx_hex = hex::encode(ctx_id);
        let repo = std::sync::Arc::new(crate::store::ProtocolRepository::new_for_testing(
            scp_platform::in_memory::InMemoryStorage::new(),
        ));
        let persistence = std::sync::Arc::new(
            crate::store::context::ProtocolRepositoryEventLogBridge::new(std::sync::Arc::clone(
                &repo,
            )),
        );
        let writer = MerkleEventLogProvider::with_persistence(persistence.clone());
        writer.init_event_log(&ctx_id).await.unwrap();
        for i in 0..3u8 {
            writer
                .append_event(
                    &ctx_id,
                    EventType::MemberJoined,
                    "",
                    payload_bytes(&[i]),
                    1_700_000_000,
                )
                .await
                .unwrap();
        }
        // Remove the middle unit: the stored log now has a gap.
        let prefix = format!("context/{ctx_hex}/merkle_event_log/");
        let middle = repo
            .storage()
            .list_keys(&prefix)
            .await
            .unwrap()
            .into_iter()
            .find(|key| key.ends_with("/00000000000000000001"))
            .unwrap();
        repo.storage().delete(&middle).await.unwrap();
        let before = storage_snapshot(repo.storage(), &prefix).await;

        let restored = MerkleEventLogProvider::with_persistence(persistence);
        let err = restored.restore_event_log(&ctx_id).await.unwrap_err();
        assert!(
            err.to_string().contains("misaligned"),
            "restore returns the typed load error: {err}"
        );
        assert!(
            restored.entries(&ctx_id).is_none(),
            "a failed restore installs no log"
        );
        assert!(
            !restored.write_gates.contains_key(&ctx_id),
            "a failed restore leaves no write gate behind"
        );
        assert!(
            restored
                .append_event(
                    &ctx_id,
                    EventType::MemberJoined,
                    "",
                    EventPayload::default(),
                    1_700_000_000,
                )
                .await
                .is_err(),
            "an append after a failed restore has no log to extend"
        );
        assert_eq!(
            storage_snapshot(repo.storage(), &prefix).await,
            before,
            "a failed restore leaves the stored units unchanged"
        );
    }

    /// A restore over storage that holds no log starts an empty log and says
    /// so; one over a stored log says how many entries it replayed.
    #[tokio::test]
    async fn restore_reports_absent_or_loaded() {
        let ctx_id = [34u8; 32];
        let persistence = std::sync::Arc::new(MockEventLogPersistence::new());
        let provider = MerkleEventLogProvider::with_persistence(persistence.clone());
        assert_eq!(
            provider.restore_event_log(&ctx_id).await.unwrap(),
            EventLogRestore::Absent
        );
        assert_eq!(provider.entries(&ctx_id).unwrap().len(), 0);
        for _ in 0..2 {
            provider
                .append_event(
                    &ctx_id,
                    EventType::MemberJoined,
                    "",
                    EventPayload::default(),
                    1_700_000_000,
                )
                .await
                .unwrap();
        }
        let restored = MerkleEventLogProvider::with_persistence(persistence);
        assert_eq!(
            restored.restore_event_log(&ctx_id).await.unwrap(),
            EventLogRestore::Loaded { entries: 2 }
        );
    }

    async fn append_n(provider: &MerkleEventLogProvider, ctx_id: &[u8; 32], tag: u8, n: u8) {
        for i in 0..n {
            provider
                .append_event(
                    ctx_id,
                    EventType::MemberJoined,
                    "",
                    payload_bytes(&[tag, i]),
                    1_600_000_000 + u64::from(i),
                )
                .await
                .unwrap();
        }
    }

    /// Asserts that a fresh provider over `faulty` restores exactly the
    /// in-memory log of `provider`.
    async fn assert_reload_matches(
        faulty: &std::sync::Arc<Faulty>,
        provider: &MerkleEventLogProvider,
        ctx_id: &[u8; 32],
        case: &str,
    ) {
        let in_memory = provider.entries(ctx_id).unwrap();
        let restored = faulty_provider(faulty);
        restored
            .restore_event_log(ctx_id)
            .await
            .unwrap_or_else(|e| panic!("{case}: restore failed: {e}"));
        let got = restored.entries(ctx_id).unwrap();
        assert_eq!(
            log_bytes(&got),
            log_bytes(&in_memory),
            "{case}: reloaded {} entries, memory holds {}",
            got.len(),
            in_memory.len()
        );
    }

    /// After a failed prune replace, the next append replaces the whole
    /// stored log, so a reload gives exactly the in-memory log.
    #[tokio::test]
    async fn append_after_failed_prune_replace_restores_memory() {
        let ctx_id = [35u8; 32];
        let faulty = std::sync::Arc::new(Faulty::new(std::sync::Arc::new(
            scp_platform::in_memory::InMemoryStorage::new(),
        )));
        let provider = faulty_provider(&faulty);
        provider.init_event_log(&ctx_id).await.unwrap();
        append_n(&provider, &ctx_id, 0xA0, 5).await;
        let policy = scp_protocol::context::governance::PruningPolicy {
            size_based: Some(scp_protocol::context::governance::SizeBasedPolicy {
                max_event_count: 2,
                max_storage_bytes: u64::MAX,
            }),
            ..Default::default()
        };
        faulty.fail_nth_store(1);
        assert_eq!(
            provider.prune_before_checkpoint(&ctx_id, 5, &policy).await,
            Some(3)
        );
        faulty.clear_fail();
        append_n(&provider, &ctx_id, 0xB0, 1).await;
        assert_reload_matches(&faulty, &provider, &ctx_id, "prune").await;
    }

    /// After a failed import replace, the next append replaces the whole
    /// stored log, so a reload gives exactly the in-memory log.
    #[tokio::test]
    async fn append_after_failed_import_restores_memory() {
        let ctx_id = [36u8; 32];
        let source = MerkleEventLogProvider::new();
        source.init_event_log(&ctx_id).await.unwrap();
        append_n(&source, &ctx_id, 0xC0, 4).await;
        let import_data = source.export_event_log_entries(&ctx_id).unwrap();

        let faulty = std::sync::Arc::new(Faulty::new(std::sync::Arc::new(
            scp_platform::in_memory::InMemoryStorage::new(),
        )));
        let provider = faulty_provider(&faulty);
        provider.init_event_log(&ctx_id).await.unwrap();
        append_n(&provider, &ctx_id, 0xA0, 2).await;
        faulty.fail_nth_store(1);
        provider
            .import_event_log_entries(&ctx_id, &import_data)
            .await
            .unwrap();
        faulty.clear_fail();
        append_n(&provider, &ctx_id, 0xB0, 1).await;
        assert_reload_matches(&faulty, &provider, &ctx_id, "import").await;
    }

    /// A failed persist of the first unit, with no stored `head`, is
    /// followed by appends that succeed; a reload gives the full log.
    #[tokio::test]
    async fn appends_after_failed_first_unit_restore_the_full_log() {
        let ctx_id = [37u8; 32];
        let faulty = std::sync::Arc::new(Faulty::new(std::sync::Arc::new(
            scp_platform::in_memory::InMemoryStorage::new(),
        )));
        let provider = faulty_provider(&faulty);
        // No stored log: the restore starts an empty log and writes no head.
        assert_eq!(
            provider.restore_event_log(&ctx_id).await.unwrap(),
            EventLogRestore::Absent
        );
        faulty.fail_nth_store(1);
        append_n(&provider, &ctx_id, 0xA0, 1).await;
        faulty.clear_fail();
        append_n(&provider, &ctx_id, 0xB0, 2).await;
        assert_eq!(provider.entries(&ctx_id).unwrap().len(), 3);
        assert_reload_matches(&faulty, &provider, &ctx_id, "first unit").await;
    }

    #[tokio::test]
    async fn event_log_entries_via_dyn_dispatch() {
        use crate::context::builder::ContextEventLogProvider;

        let provider = MerkleEventLogProvider::new();
        let ctx_id = [19u8; 32];

        provider.init_event_log(&ctx_id).await.unwrap();
        provider
            .append_event(
                &ctx_id,
                EventType::ContextCreated,
                "",
                EventPayload::default(),
                1_700_000_000,
            )
            .await
            .unwrap();
        provider
            .append_event(
                &ctx_id,
                EventType::MemberJoined,
                "",
                EventPayload::default(),
                1_700_000_000,
            )
            .await
            .unwrap();

        let boxed: Box<dyn ContextEventLogProvider> = Box::new(provider);
        let entries = boxed.event_log_entries(&ctx_id).unwrap().unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].event_type, EventType::ContextCreated);
        assert_eq!(entries[1].event_type, EventType::MemberJoined);
    }

    #[tokio::test]
    async fn append_context_event_delegates_to_append_event() {
        use crate::context::builder::ContextEventLogProvider;

        let provider = MerkleEventLogProvider::new();
        let ctx_id = [7u8; 32];

        provider.init_event_log(&ctx_id).await.unwrap();
        provider
            .append_context_event(&ctx_id, EventType::MemberLeft, "", 1_700_000_000)
            .await
            .unwrap();

        let entries = provider.entries(&ctx_id).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].event_type, EventType::MemberLeft);
    }
}
