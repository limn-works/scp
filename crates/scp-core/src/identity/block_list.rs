//! Block list storage for identity private state.
//!
//! Implements block list event log and state derivation per spec §3.7.1,
//! blocking (§9.16.3), and unblocking with forward-only restoration (§9.16.8).
//!
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
//! Unblocking (§9.16.8) reverses key distribution denial (Layer 1) but does
//! NOT restore historical access. The blocker does NOT rotate their sender key
//! on unblock — the current key remains valid. Historical gap is permanent.
//!
//! **Tier stacking:** If governance (Tier 3) has also revoked the target's
//! access, the identity-level unblock does NOT restore access. Both must be
//! independently reversed. See [`is_effectively_blocked`].
//!
//! See spec §3.7.1, §9.16.3, §9.16.8, ADR-038.

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

    /// Returns whether a DID is blocked at the identity level in any
    /// applicable tier (Tier 1 in the given context, or Tier 2 globally).
    ///
    /// **Does NOT check governance (Tier 3).** Use [`is_effectively_blocked`]
    /// for the full tier-stacking check that includes governance revocation.
    #[must_use]
    pub fn is_identity_blocked(&self, target: &DID, context_id: &str) -> bool {
        self.is_globally_blocked(target) || self.is_blocked_in_context(target, context_id)
    }

    // -----------------------------------------------------------------------
    // Blocking convenience methods (SCP-CAC-002)
    // -----------------------------------------------------------------------

    /// Blocks a DID in a specific context (Tier 1).
    ///
    /// Records a [`BlockDIDInContext`] event and updates the materialized
    /// state. Idempotent — blocking an already-blocked DID is a no-op
    /// on state (the event is still recorded for log completeness).
    pub fn block_did_in_context(&mut self, target_did: DID, context_id: String, timestamp: u64) {
        let event = BlockListEvent::BlockDIDInContext {
            target_did,
            context_id,
            timestamp,
        };
        self.apply(&event);
    }

    /// Blocks a DID globally across all contexts (Tier 2).
    ///
    /// Records a [`BlockDID`] event. **Does NOT automatically propagate
    /// to per-context lists** — the caller (SDK orchestration layer) is
    /// responsible for enumerating shared contexts and executing the
    /// per-context block protocol.
    pub fn block_did_global(&mut self, target_did: DID, timestamp: u64) {
        let event = BlockListEvent::BlockDID {
            target_did,
            timestamp,
        };
        self.apply(&event);
    }

    // -----------------------------------------------------------------------
    // Unblocking operations (SCP-CAC-003, §9.16.8)
    // -----------------------------------------------------------------------

    /// Unblocks a DID in a specific context (Tier 1).
    ///
    /// Removes the target from the per-context block list and records an
    /// [`UnblockDIDInContext`] event.
    ///
    /// **Forward-only restoration (§9.16.8):**
    /// - The blocker does NOT rotate their sender key — the current key
    ///   remains valid.
    /// - On next `SenderKeyRequest` from the previously-blocked party, the
    ///   blocker's SDK checks the updated block list and responds with the
    ///   current sender key.
    /// - Historical gap is permanent: content encrypted during the block
    ///   period used sender key epochs the blocked party never received.
    /// - Access keys destroyed during the block (Layer 3) are NOT restored
    ///   for historical content.
    pub fn unblock_did_in_context(
        &mut self,
        target_did: DID,
        context_id: String,
        timestamp: u64,
    ) -> UnblockResult {
        let was_blocked = self
            .per_context
            .get(&context_id)
            .is_some_and(|set| set.contains(&target_did));

        let event = BlockListEvent::UnblockDIDInContext {
            target_did: target_did.clone(),
            context_id: context_id.clone(),
            timestamp,
        };
        self.apply(&event);

        UnblockResult {
            target_did,
            was_blocked,
            contexts_unblocked: if was_blocked {
                vec![context_id]
            } else {
                vec![]
            },
        }
    }

    /// Unblocks a DID globally (Tier 2).
    ///
    /// Removes the target from the global block list AND from all
    /// per-context block lists where the target appears. Records an
    /// [`UnblockDID`] event.
    ///
    /// **Forward-only restoration (§9.16.8):** Same guarantees as
    /// [`unblock_did_in_context`](Self::unblock_did_in_context) — no
    /// sender key rotation, no historical access restoration.
    ///
    /// **Tier stacking:** This only reverses the identity-level block
    /// (Tiers 1 and 2). If governance (Tier 3) has also revoked the
    /// target's access, the governance revocation remains active. Use
    /// [`is_effectively_blocked`] to check the combined state of all tiers.
    pub fn unblock_did_global(&mut self, target_did: DID, timestamp: u64) -> UnblockResult {
        let was_globally_blocked = self.global.contains(&target_did);

        // Collect all contexts where this DID was blocked.
        let contexts_unblocked: Vec<String> = self
            .per_context
            .iter()
            .filter(|(_, blocked_set)| blocked_set.contains(&target_did))
            .map(|(ctx_id, _)| ctx_id.clone())
            .collect();

        let event = BlockListEvent::UnblockDID {
            target_did: target_did.clone(),
            timestamp,
        };
        self.apply(&event);

        // Global unblock also clears per-context entries.
        for ctx_id in &contexts_unblocked {
            if let Some(set) = self.per_context.get_mut(ctx_id) {
                set.remove(&target_did);
                if set.is_empty() {
                    self.per_context.remove(ctx_id);
                }
            }
        }

        UnblockResult {
            target_did,
            was_blocked: was_globally_blocked || !contexts_unblocked.is_empty(),
            contexts_unblocked,
        }
    }
}

// ---------------------------------------------------------------------------
// Unblock result (§9.16.8)
// ---------------------------------------------------------------------------

/// Result of an unblock operation (§9.16.8).
///
/// Contains metadata about what changed, enabling the caller to take
/// appropriate action (e.g., persisting updated block lists, NOT rotating
/// sender keys — unblock intentionally does not rotate).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnblockResult {
    /// The DID that was unblocked.
    pub target_did: DID,
    /// Whether the target was actually blocked before the unblock operation.
    /// `false` if the target was not on any block list (unblock was a no-op).
    pub was_blocked: bool,
    /// Context IDs where the target was removed from per-context block lists.
    pub contexts_unblocked: Vec<String>,
}

// ---------------------------------------------------------------------------
// Tier stacking (§3.6, §9.16.8)
// ---------------------------------------------------------------------------

/// Checks whether a target DID is effectively blocked considering all three
/// tiers.
///
/// **Tier stacking rule (§9.16.8):** The target's effective access is the
/// most restrictive of all active tiers. If ANY tier blocks access, the
/// target is effectively blocked.
///
/// - `block_list`: The blocker's [`BlockListState`].
/// - `target`: The DID to check.
/// - `context_id`: The context in which to check.
/// - `governance_revoked`: Whether governance (Tier 3) has revoked the
///   target's read or write access. The caller queries this from the
///   context's `write_revoked_members` set.
#[must_use]
pub fn is_effectively_blocked(
    block_list: &BlockListState,
    target: &DID,
    context_id: &str,
    governance_revoked: bool,
) -> bool {
    governance_revoked || block_list.is_identity_blocked(target, context_id)
}

/// Checks whether a target DID's access can be restored (all tiers clear).
///
/// After an identity-level unblock, the target's access is only actually
/// restored if governance (Tier 3) has NOT also revoked access.
#[must_use]
pub fn is_access_restored(
    block_list: &BlockListState,
    target: &DID,
    context_id: &str,
    governance_revoked: bool,
) -> bool {
    !is_effectively_blocked(block_list, target, context_id, governance_revoked)
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

    // -----------------------------------------------------------------------
    // SCP-CAC-003: Unblocking with forward-only restoration
    // -----------------------------------------------------------------------

    #[test]
    fn unblock_did_in_context_removes_target() {
        let mut state = BlockListState::new();
        let target = did("did:dht:z6MkDave");
        let ctx = "ctx-1".to_owned();

        state.block_did_in_context(target.clone(), ctx.clone(), 1000);
        assert!(state.is_blocked_in_context(&target, &ctx));

        let result = state.unblock_did_in_context(target.clone(), ctx.clone(), 2000);
        assert!(!state.is_blocked_in_context(&target, &ctx));
        assert!(result.was_blocked);
        assert_eq!(result.target_did, target);
        assert_eq!(result.contexts_unblocked, vec![ctx]);
    }

    #[test]
    fn unblock_did_in_context_noop_if_not_blocked() {
        let mut state = BlockListState::new();
        let result =
            state.unblock_did_in_context(did("did:dht:z6MkDave"), "ctx-1".to_owned(), 1000);
        assert!(!result.was_blocked);
        assert!(result.contexts_unblocked.is_empty());
    }

    #[test]
    fn unblock_did_global_removes_from_global_and_all_contexts() {
        let mut state = BlockListState::new();
        let target = did("did:dht:z6MkDave");

        state.block_did_global(target.clone(), 1000);
        state.block_did_in_context(target.clone(), "ctx-1".to_owned(), 1001);
        state.block_did_in_context(target.clone(), "ctx-2".to_owned(), 1002);

        assert!(state.is_globally_blocked(&target));
        assert!(state.is_blocked_in_context(&target, "ctx-1"));
        assert!(state.is_blocked_in_context(&target, "ctx-2"));

        let result = state.unblock_did_global(target.clone(), 2000);

        assert!(!state.is_globally_blocked(&target));
        assert!(!state.is_blocked_in_context(&target, "ctx-1"));
        assert!(!state.is_blocked_in_context(&target, "ctx-2"));
        assert!(result.was_blocked);
        assert_eq!(result.contexts_unblocked.len(), 2);
    }

    #[test]
    fn unblock_did_global_noop_if_not_blocked() {
        let mut state = BlockListState::new();
        let result = state.unblock_did_global(did("did:dht:z6MkDave"), 1000);
        assert!(!result.was_blocked);
        assert!(result.contexts_unblocked.is_empty());
    }

    #[test]
    fn after_unblock_target_not_on_block_list() {
        let mut state = BlockListState::new();
        let target = did("did:dht:z6MkDave");
        let ctx = "ctx-1".to_owned();

        state.block_did_in_context(target.clone(), ctx.clone(), 1000);
        assert!(state.is_identity_blocked(&target, &ctx));

        state.unblock_did_in_context(target.clone(), ctx.clone(), 2000);
        assert!(!state.is_identity_blocked(&target, &ctx));
    }

    #[test]
    fn forward_only_restoration_block_unblock_cycle() {
        let mut state = BlockListState::new();
        let target = did("did:dht:z6MkDave");
        let ctx = "ctx-1".to_owned();

        state.block_did_in_context(target.clone(), ctx.clone(), 1000);
        state.unblock_did_in_context(target.clone(), ctx.clone(), 2000);
        state.block_did_in_context(target.clone(), ctx.clone(), 3000);
        assert!(state.is_blocked_in_context(&target, &ctx));
    }

    #[test]
    fn unblock_result_has_no_key_rotation_fields() {
        let mut state = BlockListState::new();
        let target = did("did:dht:z6MkDave");

        state.block_did_in_context(target.clone(), "ctx-1".to_owned(), 1000);
        let result = state.unblock_did_in_context(target, "ctx-1".to_owned(), 2000);

        // UnblockResult intentionally has no key rotation fields.
        assert!(result.was_blocked);
        assert_eq!(result.contexts_unblocked.len(), 1);
    }

    // -----------------------------------------------------------------------
    // Tier stacking tests (§3.6, §9.16.8)
    // -----------------------------------------------------------------------

    #[test]
    fn tier_stacking_governance_blocks_after_identity_unblock() {
        let mut state = BlockListState::new();
        let target = did("did:dht:z6MkDave");
        let ctx = "ctx-1";

        state.block_did_in_context(target.clone(), ctx.to_owned(), 1000);
        let governance_revoked = true;

        assert!(is_effectively_blocked(
            &state,
            &target,
            ctx,
            governance_revoked
        ));
        assert!(!is_access_restored(
            &state,
            &target,
            ctx,
            governance_revoked
        ));

        state.unblock_did_in_context(target.clone(), ctx.to_owned(), 2000);

        // Identity tier clear, but governance still blocks.
        assert!(!state.is_identity_blocked(&target, ctx));
        assert!(is_effectively_blocked(
            &state,
            &target,
            ctx,
            governance_revoked
        ));
        assert!(!is_access_restored(
            &state,
            &target,
            ctx,
            governance_revoked
        ));
    }

    #[test]
    fn tier_stacking_access_restored_when_all_tiers_clear() {
        let mut state = BlockListState::new();
        let target = did("did:dht:z6MkDave");
        let ctx = "ctx-1";

        state.block_did_in_context(target.clone(), ctx.to_owned(), 1000);
        state.unblock_did_in_context(target.clone(), ctx.to_owned(), 2000);

        // Identity cleared, governance not revoked → fully restored.
        assert!(is_access_restored(&state, &target, ctx, false));
        // Identity cleared but governance revoked → not restored.
        assert!(!is_access_restored(&state, &target, ctx, true));
    }

    #[test]
    fn tier_stacking_governance_only_revocation() {
        let state = BlockListState::new();
        let target = did("did:dht:z6MkDave");
        assert!(is_effectively_blocked(&state, &target, "ctx-1", true));
        assert!(!is_access_restored(&state, &target, "ctx-1", true));
    }

    #[test]
    fn tier_stacking_identity_only_revocation() {
        let mut state = BlockListState::new();
        let target = did("did:dht:z6MkDave");
        let ctx = "ctx-1";

        state.block_did_in_context(target.clone(), ctx.to_owned(), 1000);
        assert!(is_effectively_blocked(&state, &target, ctx, false));

        state.unblock_did_in_context(target.clone(), ctx.to_owned(), 2000);
        assert!(is_access_restored(&state, &target, ctx, false));
    }

    #[test]
    fn is_identity_blocked_checks_both_tiers() {
        let mut state = BlockListState::new();
        let target = did("did:dht:z6MkDave");

        assert!(!state.is_identity_blocked(&target, "ctx-1"));

        state.block_did_in_context(target.clone(), "ctx-1".to_owned(), 1000);
        assert!(state.is_identity_blocked(&target, "ctx-1"));
        assert!(!state.is_identity_blocked(&target, "ctx-2"));

        state.block_did_global(target.clone(), 1001);
        assert!(state.is_identity_blocked(&target, "ctx-1"));
        assert!(state.is_identity_blocked(&target, "ctx-2"));
    }

    #[test]
    fn global_unblock_does_not_affect_other_targets() {
        let mut state = BlockListState::new();
        let dave = did("did:dht:z6MkDave");
        let eve = did("did:dht:z6MkEve");

        state.block_did_global(dave.clone(), 1000);
        state.block_did_global(eve.clone(), 1001);
        state.unblock_did_global(dave.clone(), 2000);

        assert!(!state.is_globally_blocked(&dave));
        assert!(state.is_globally_blocked(&eve));
    }

    #[test]
    fn context_unblock_does_not_affect_other_contexts() {
        let mut state = BlockListState::new();
        let target = did("did:dht:z6MkDave");

        state.block_did_in_context(target.clone(), "ctx-1".to_owned(), 1000);
        state.block_did_in_context(target.clone(), "ctx-2".to_owned(), 1001);
        state.unblock_did_in_context(target.clone(), "ctx-1".to_owned(), 2000);

        assert!(!state.is_blocked_in_context(&target, "ctx-1"));
        assert!(state.is_blocked_in_context(&target, "ctx-2"));
    }

    #[test]
    fn global_unblock_clears_per_context_for_target_only() {
        let mut state = BlockListState::new();
        let dave = did("did:dht:z6MkDave");
        let eve = did("did:dht:z6MkEve");

        state.block_did_in_context(dave.clone(), "ctx-1".to_owned(), 1000);
        state.block_did_in_context(eve.clone(), "ctx-1".to_owned(), 1001);
        state.block_did_global(dave.clone(), 1002);
        state.unblock_did_global(dave.clone(), 2000);

        assert!(!state.is_globally_blocked(&dave));
        assert!(!state.is_blocked_in_context(&dave, "ctx-1"));
        assert!(state.is_blocked_in_context(&eve, "ctx-1"));
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
