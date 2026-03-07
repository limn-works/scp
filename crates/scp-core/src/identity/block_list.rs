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
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn did(s: &str) -> DID {
        DID::from(s)
    }

    // -----------------------------------------------------------------------
    // AC-11: Serialization round-trip tests
    // -----------------------------------------------------------------------

    #[test]
    fn block_did_event_roundtrip_serialization() {
        let event = BlockListEvent::BlockDID {
            target_did: did("did:dht:z6MkTarget"),
            timestamp: 1_700_000_000_000,
        };
        let bytes = rmp_serde::to_vec(&event).unwrap();
        let decoded: BlockListEvent = rmp_serde::from_slice(&bytes).unwrap();
        assert_eq!(decoded, event);
    }

    #[test]
    fn unblock_did_event_roundtrip_serialization() {
        let event = BlockListEvent::UnblockDID {
            target_did: did("did:dht:z6MkTarget"),
            timestamp: 1_700_000_001_000,
        };
        let bytes = rmp_serde::to_vec(&event).unwrap();
        let decoded: BlockListEvent = rmp_serde::from_slice(&bytes).unwrap();
        assert_eq!(decoded, event);
    }

    #[test]
    fn block_did_in_context_event_roundtrip_serialization() {
        let event = BlockListEvent::BlockDIDInContext {
            target_did: did("did:dht:z6MkTarget"),
            context_id: "ctx-123".to_owned(),
            timestamp: 1_700_000_002_000,
        };
        let bytes = rmp_serde::to_vec(&event).unwrap();
        let decoded: BlockListEvent = rmp_serde::from_slice(&bytes).unwrap();
        assert_eq!(decoded, event);
    }

    #[test]
    fn unblock_did_in_context_event_roundtrip_serialization() {
        let event = BlockListEvent::UnblockDIDInContext {
            target_did: did("did:dht:z6MkTarget"),
            context_id: "ctx-123".to_owned(),
            timestamp: 1_700_000_003_000,
        };
        let bytes = rmp_serde::to_vec(&event).unwrap();
        let decoded: BlockListEvent = rmp_serde::from_slice(&bytes).unwrap();
        assert_eq!(decoded, event);
    }

    #[test]
    fn all_variants_json_roundtrip() {
        let events = vec![
            BlockListEvent::BlockDID {
                target_did: did("did:dht:z6MkA"),
                timestamp: 100,
            },
            BlockListEvent::UnblockDID {
                target_did: did("did:dht:z6MkA"),
                timestamp: 200,
            },
            BlockListEvent::BlockDIDInContext {
                target_did: did("did:dht:z6MkB"),
                context_id: "ctx-1".to_owned(),
                timestamp: 300,
            },
            BlockListEvent::UnblockDIDInContext {
                target_did: did("did:dht:z6MkB"),
                context_id: "ctx-1".to_owned(),
                timestamp: 400,
            },
        ];
        let json = serde_json::to_string(&events).unwrap();
        let decoded: Vec<BlockListEvent> = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded, events);
    }

    // -----------------------------------------------------------------------
    // AC-6: State derived from event log replay
    // -----------------------------------------------------------------------

    #[test]
    fn empty_event_log_produces_empty_state() {
        let state = BlockListState::from_events(&[]);
        assert!(state.global_block_list().is_empty());
        assert!(!state.is_globally_blocked(&did("did:dht:anyone")));
    }

    // -----------------------------------------------------------------------
    // AC-2, AC-3: Global block list
    // -----------------------------------------------------------------------

    #[test]
    fn block_did_adds_to_global_list() {
        let events = vec![BlockListEvent::BlockDID {
            target_did: did("did:dht:z6MkDave"),
            timestamp: 1000,
        }];
        let state = BlockListState::from_events(&events);
        assert!(state.is_globally_blocked(&did("did:dht:z6MkDave")));
        assert_eq!(state.global_block_list().len(), 1);
    }

    // -----------------------------------------------------------------------
    // AC-7: Block followed by unblock = unblocked
    // -----------------------------------------------------------------------

    #[test]
    fn block_then_unblock_results_in_unblocked() {
        let events = vec![
            BlockListEvent::BlockDID {
                target_did: did("did:dht:z6MkDave"),
                timestamp: 1000,
            },
            BlockListEvent::UnblockDID {
                target_did: did("did:dht:z6MkDave"),
                timestamp: 2000,
            },
        ];
        let state = BlockListState::from_events(&events);
        assert!(!state.is_globally_blocked(&did("did:dht:z6MkDave")));
        assert!(state.global_block_list().is_empty());
    }

    #[test]
    fn unblock_then_block_results_in_blocked() {
        let events = vec![
            BlockListEvent::UnblockDID {
                target_did: did("did:dht:z6MkDave"),
                timestamp: 1000,
            },
            BlockListEvent::BlockDID {
                target_did: did("did:dht:z6MkDave"),
                timestamp: 2000,
            },
        ];
        let state = BlockListState::from_events(&events);
        assert!(state.is_globally_blocked(&did("did:dht:z6MkDave")));
    }

    // -----------------------------------------------------------------------
    // AC-8: Commutativity of independent operations
    // -----------------------------------------------------------------------

    #[test]
    fn block_operations_are_commutative_for_different_targets() {
        let order_a = vec![
            BlockListEvent::BlockDID {
                target_did: did("did:dht:z6MkX"),
                timestamp: 1000,
            },
            BlockListEvent::BlockDID {
                target_did: did("did:dht:z6MkY"),
                timestamp: 2000,
            },
        ];
        let order_b = vec![
            BlockListEvent::BlockDID {
                target_did: did("did:dht:z6MkY"),
                timestamp: 2000,
            },
            BlockListEvent::BlockDID {
                target_did: did("did:dht:z6MkX"),
                timestamp: 1000,
            },
        ];

        let state_a = BlockListState::from_events(&order_a);
        let state_b = BlockListState::from_events(&order_b);

        // Both states have the same globally blocked DIDs.
        let mut list_a = state_a.global_block_list();
        let mut list_b = state_b.global_block_list();
        list_a.sort();
        list_b.sort();
        assert_eq!(list_a, list_b);
        assert!(state_a.is_globally_blocked(&did("did:dht:z6MkX")));
        assert!(state_a.is_globally_blocked(&did("did:dht:z6MkY")));
        assert!(state_b.is_globally_blocked(&did("did:dht:z6MkX")));
        assert!(state_b.is_globally_blocked(&did("did:dht:z6MkY")));
    }

    #[test]
    fn per_context_block_operations_are_commutative_for_different_targets() {
        let ctx = "ctx-1";
        let order_a = vec![
            BlockListEvent::BlockDIDInContext {
                target_did: did("did:dht:z6MkX"),
                context_id: ctx.to_owned(),
                timestamp: 1000,
            },
            BlockListEvent::BlockDIDInContext {
                target_did: did("did:dht:z6MkY"),
                context_id: ctx.to_owned(),
                timestamp: 2000,
            },
        ];
        let order_b = vec![
            BlockListEvent::BlockDIDInContext {
                target_did: did("did:dht:z6MkY"),
                context_id: ctx.to_owned(),
                timestamp: 2000,
            },
            BlockListEvent::BlockDIDInContext {
                target_did: did("did:dht:z6MkX"),
                context_id: ctx.to_owned(),
                timestamp: 1000,
            },
        ];

        let state_a = BlockListState::from_events(&order_a);
        let state_b = BlockListState::from_events(&order_b);

        let mut list_a = state_a.context_block_list(ctx);
        let mut list_b = state_b.context_block_list(ctx);
        list_a.sort();
        list_b.sort();
        assert_eq!(list_a, list_b);
    }

    #[test]
    fn cross_granularity_commutativity() {
        // Blocking X globally and Y in context produces the same state
        // regardless of order.
        let order_a = vec![
            BlockListEvent::BlockDID {
                target_did: did("did:dht:z6MkX"),
                timestamp: 1000,
            },
            BlockListEvent::BlockDIDInContext {
                target_did: did("did:dht:z6MkY"),
                context_id: "ctx-1".to_owned(),
                timestamp: 2000,
            },
        ];
        let order_b = vec![
            BlockListEvent::BlockDIDInContext {
                target_did: did("did:dht:z6MkY"),
                context_id: "ctx-1".to_owned(),
                timestamp: 2000,
            },
            BlockListEvent::BlockDID {
                target_did: did("did:dht:z6MkX"),
                timestamp: 1000,
            },
        ];

        let state_a = BlockListState::from_events(&order_a);
        let state_b = BlockListState::from_events(&order_b);

        assert_eq!(
            state_a.is_globally_blocked(&did("did:dht:z6MkX")),
            state_b.is_globally_blocked(&did("did:dht:z6MkX"))
        );
        assert_eq!(
            state_a.is_blocked_in_context(&did("did:dht:z6MkY"), "ctx-1"),
            state_b.is_blocked_in_context(&did("did:dht:z6MkY"), "ctx-1")
        );
    }

    // -----------------------------------------------------------------------
    // AC-4, AC-5: Per-context block list
    // -----------------------------------------------------------------------

    #[test]
    fn block_did_in_context_scoped_to_context() {
        let events = vec![BlockListEvent::BlockDIDInContext {
            target_did: did("did:dht:z6MkDave"),
            context_id: "ctx-1".to_owned(),
            timestamp: 1000,
        }];
        let state = BlockListState::from_events(&events);

        assert!(state.is_blocked_in_context(&did("did:dht:z6MkDave"), "ctx-1"));
        assert!(!state.is_blocked_in_context(&did("did:dht:z6MkDave"), "ctx-2"));
        assert!(!state.is_globally_blocked(&did("did:dht:z6MkDave")));
        assert_eq!(state.context_block_list("ctx-1").len(), 1);
        assert!(state.context_block_list("ctx-2").is_empty());
    }

    #[test]
    fn block_then_unblock_in_context_results_in_unblocked() {
        let events = vec![
            BlockListEvent::BlockDIDInContext {
                target_did: did("did:dht:z6MkDave"),
                context_id: "ctx-1".to_owned(),
                timestamp: 1000,
            },
            BlockListEvent::UnblockDIDInContext {
                target_did: did("did:dht:z6MkDave"),
                context_id: "ctx-1".to_owned(),
                timestamp: 2000,
            },
        ];
        let state = BlockListState::from_events(&events);
        assert!(!state.is_blocked_in_context(&did("did:dht:z6MkDave"), "ctx-1"));
        assert!(state.context_block_list("ctx-1").is_empty());
    }

    // -----------------------------------------------------------------------
    // AC-12: Block/unblock lifecycle (combined scenarios)
    // -----------------------------------------------------------------------

    #[test]
    fn complex_lifecycle_global_and_per_context() {
        let events = vec![
            // Block Dave globally
            BlockListEvent::BlockDID {
                target_did: did("did:dht:z6MkDave"),
                timestamp: 1000,
            },
            // Block Eve in ctx-1
            BlockListEvent::BlockDIDInContext {
                target_did: did("did:dht:z6MkEve"),
                context_id: "ctx-1".to_owned(),
                timestamp: 2000,
            },
            // Block Eve in ctx-2
            BlockListEvent::BlockDIDInContext {
                target_did: did("did:dht:z6MkEve"),
                context_id: "ctx-2".to_owned(),
                timestamp: 3000,
            },
            // Unblock Dave globally
            BlockListEvent::UnblockDID {
                target_did: did("did:dht:z6MkDave"),
                timestamp: 4000,
            },
            // Unblock Eve in ctx-1 only
            BlockListEvent::UnblockDIDInContext {
                target_did: did("did:dht:z6MkEve"),
                context_id: "ctx-1".to_owned(),
                timestamp: 5000,
            },
            // Re-block Dave globally
            BlockListEvent::BlockDID {
                target_did: did("did:dht:z6MkDave"),
                timestamp: 6000,
            },
        ];

        let state = BlockListState::from_events(&events);

        // Dave is globally blocked again (re-blocked after unblock).
        assert!(state.is_globally_blocked(&did("did:dht:z6MkDave")));

        // Eve is NOT globally blocked.
        assert!(!state.is_globally_blocked(&did("did:dht:z6MkEve")));

        // Eve is unblocked in ctx-1 but still blocked in ctx-2.
        assert!(!state.is_blocked_in_context(&did("did:dht:z6MkEve"), "ctx-1"));
        assert!(state.is_blocked_in_context(&did("did:dht:z6MkEve"), "ctx-2"));

        // Global list has only Dave.
        assert_eq!(state.global_block_list(), vec![did("did:dht:z6MkDave")]);

        // ctx-1 is empty, ctx-2 has Eve.
        assert!(state.context_block_list("ctx-1").is_empty());
        assert_eq!(
            state.context_block_list("ctx-2"),
            vec![did("did:dht:z6MkEve")]
        );
    }

    #[test]
    fn duplicate_block_events_are_idempotent() {
        let events = vec![
            BlockListEvent::BlockDID {
                target_did: did("did:dht:z6MkDave"),
                timestamp: 1000,
            },
            BlockListEvent::BlockDID {
                target_did: did("did:dht:z6MkDave"),
                timestamp: 2000,
            },
        ];
        let state = BlockListState::from_events(&events);
        assert!(state.is_globally_blocked(&did("did:dht:z6MkDave")));
        assert_eq!(state.global_block_list().len(), 1);
    }

    #[test]
    fn unblock_without_prior_block_is_no_op() {
        let events = vec![BlockListEvent::UnblockDID {
            target_did: did("did:dht:z6MkDave"),
            timestamp: 1000,
        }];
        let state = BlockListState::from_events(&events);
        assert!(!state.is_globally_blocked(&did("did:dht:z6MkDave")));
        assert!(state.global_block_list().is_empty());
    }

    #[test]
    fn unblock_in_context_without_prior_block_is_no_op() {
        let events = vec![BlockListEvent::UnblockDIDInContext {
            target_did: did("did:dht:z6MkDave"),
            context_id: "ctx-1".to_owned(),
            timestamp: 1000,
        }];
        let state = BlockListState::from_events(&events);
        assert!(!state.is_blocked_in_context(&did("did:dht:z6MkDave"), "ctx-1"));
    }

    #[test]
    fn multiple_targets_in_same_context() {
        let events = vec![
            BlockListEvent::BlockDIDInContext {
                target_did: did("did:dht:z6MkA"),
                context_id: "ctx-1".to_owned(),
                timestamp: 1000,
            },
            BlockListEvent::BlockDIDInContext {
                target_did: did("did:dht:z6MkB"),
                context_id: "ctx-1".to_owned(),
                timestamp: 2000,
            },
            BlockListEvent::BlockDIDInContext {
                target_did: did("did:dht:z6MkC"),
                context_id: "ctx-1".to_owned(),
                timestamp: 3000,
            },
        ];
        let state = BlockListState::from_events(&events);
        let mut list = state.context_block_list("ctx-1");
        list.sort();
        assert_eq!(list.len(), 3);
        assert!(state.is_blocked_in_context(&did("did:dht:z6MkA"), "ctx-1"));
        assert!(state.is_blocked_in_context(&did("did:dht:z6MkB"), "ctx-1"));
        assert!(state.is_blocked_in_context(&did("did:dht:z6MkC"), "ctx-1"));
    }
}
