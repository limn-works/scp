//! Block list storage for identity private state.
//!
//! Implements block list event log and state derivation per spec §3.7.1.
//! Two granularities:
//!
//! - **Global block list (Tier 2):** DIDs blocked across all shared contexts.
//! - **Per-context block list (Tier 1):** DIDs blocked in a specific context.
//!
//! Block lists are append-only event logs with commutative operations.
//! Current state is derived by replaying the event log. Multi-device sync
//! is conflict-free because all operations are commutative — two devices
//! can independently add blocks and the union is correct.
//!
//! See spec §3.7.1, §9.16.3, ADR-038.

use std::collections::{HashMap, HashSet};

use serde::{Deserialize, Serialize};

use scp_identity::DID;

// ---------------------------------------------------------------------------
// BlockListEvent
// ---------------------------------------------------------------------------

/// An event in the block list append-only log.
///
/// Four variants cover global (Tier 2) and per-context (Tier 1) blocking.
/// All operations are commutative — ordering between independent events
/// does not affect the derived state. Only the relative ordering of
/// block/unblock pairs for the same (target, context) matters.
///
/// See spec §3.7.1.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum BlockListEvent {
    /// Add a DID to the global block list (Tier 2, cross-context).
    BlockDID {
        /// The DID being blocked.
        target_did: DID,
        /// Unix timestamp (milliseconds) when the block was issued.
        timestamp: u64,
    },

    /// Remove a DID from the global block list (Tier 2).
    UnblockDID {
        /// The DID being unblocked.
        target_did: DID,
        /// Unix timestamp (milliseconds) when the unblock was issued.
        timestamp: u64,
    },

    /// Add a DID to a per-context block list (Tier 1, single context).
    BlockDIDInContext {
        /// The DID being blocked in this context.
        target_did: DID,
        /// The context in which the block applies.
        context_id: String,
        /// Unix timestamp (milliseconds) when the block was issued.
        timestamp: u64,
    },

    /// Remove a DID from a per-context block list (Tier 1).
    UnblockDIDInContext {
        /// The DID being unblocked in this context.
        target_did: DID,
        /// The context from which the block is removed.
        context_id: String,
        /// Unix timestamp (milliseconds) when the unblock was issued.
        timestamp: u64,
    },
}

// ---------------------------------------------------------------------------
// BlockListState — derived from event log replay
// ---------------------------------------------------------------------------

/// Materialized block list state derived from replaying an event log.
///
/// This is not stored directly — it is computed from the append-only
/// event log. Implementations MAY cache this for query performance,
/// but the event log is the authoritative record.
///
/// See spec §3.7.1.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BlockListState {
    /// DIDs on the global block list (Tier 2).
    global: HashSet<DID>,

    /// Per-context block lists (Tier 1). Key is `context_id`.
    per_context: HashMap<String, HashSet<DID>>,
}

impl BlockListState {
    /// Creates a new empty block list state.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Derives block list state by replaying an ordered event log.
    ///
    /// Events are applied in order. For each (target, context) pair,
    /// the last event wins: `BlockDID` followed by `UnblockDID` for the
    /// same target results in an unblocked state.
    ///
    /// Independent operations are commutative: `BlockDID(X)` then
    /// `BlockDID(Y)` produces the same state as `BlockDID(Y)` then
    /// `BlockDID(X)`.
    #[must_use]
    pub fn from_events(events: &[BlockListEvent]) -> Self {
        let mut state = Self::new();
        for event in events {
            state.apply(event);
        }
        state
    }

    /// Applies a single event to the current state.
    pub fn apply(&mut self, event: &BlockListEvent) {
        match event {
            BlockListEvent::BlockDID {
                target_did,
                timestamp: _,
            } => {
                self.global.insert(target_did.clone());
            }
            BlockListEvent::UnblockDID {
                target_did,
                timestamp: _,
            } => {
                self.global.remove(target_did);
            }
            BlockListEvent::BlockDIDInContext {
                target_did,
                context_id,
                timestamp: _,
            } => {
                self.per_context
                    .entry(context_id.clone())
                    .or_default()
                    .insert(target_did.clone());
            }
            BlockListEvent::UnblockDIDInContext {
                target_did,
                context_id,
                timestamp: _,
            } => {
                if let Some(set) = self.per_context.get_mut(context_id) {
                    set.remove(target_did);
                    if set.is_empty() {
                        self.per_context.remove(context_id);
                    }
                }
            }
        }
    }

    /// Returns all globally blocked DIDs (Tier 2).
    #[must_use]
    pub fn global_block_list(&self) -> Vec<DID> {
        self.global.iter().cloned().collect()
    }

    /// Returns whether a DID is globally blocked.
    #[must_use]
    pub fn is_globally_blocked(&self, target: &DID) -> bool {
        self.global.contains(target)
    }

    /// Returns all DIDs blocked in a specific context (Tier 1).
    #[must_use]
    pub fn context_block_list(&self, context_id: &str) -> Vec<DID> {
        self.per_context
            .get(context_id)
            .map(|set| set.iter().cloned().collect())
            .unwrap_or_default()
    }

    /// Returns whether a DID is blocked in a specific context (Tier 1).
    #[must_use]
    pub fn is_blocked_in_context(&self, target: &DID, context_id: &str) -> bool {
        self.per_context
            .get(context_id)
            .is_some_and(|set| set.contains(target))
    }

    /// Returns all context IDs where the given DID is blocked (Tier 1).
    ///
    /// Used by the blocking orchestrator to check whether a per-context
    /// block has already been executed for a global block propagation.
    #[must_use]
    pub fn contexts_blocking(&self, target: &DID) -> Vec<String> {
        self.per_context
            .iter()
            .filter(|(_, set)| set.contains(target))
            .map(|(ctx_id, _)| ctx_id.clone())
            .collect()
    }
}
