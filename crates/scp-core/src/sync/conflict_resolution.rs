//! Offline conflict resolution for concurrent governance changes (SCP-124).
//!
//! When two or more admins are simultaneously offline and propose conflicting
//! governance modifications, the protocol must resolve the conflict
//! deterministically without relying on synchronized clocks.
//!
//! # Conflict resolution principles (ADR-029 section 5)
//!
//! 1. The Merkle event log order is authoritative (section 9.14).
//! 2. MLS epoch boundaries are synchronization points (section 9.8.3).
//! 3. No synchronized clock dependency -- ordering is determined by Merkle
//!    tree leaf indices, not wall-clock time.
//!
//! # Resolution strategies
//!
//! - **Metadata conflicts:** Last-writer-wins, where "last" is determined by
//!   Merkle tree leaf index (lower index = earlier = wins).
//! - **Governance conflicts:** The proposal with the lower event log sequence
//!   number wins. The losing proposal is invalidated.
//! - **Simultaneous commit (same sequence):** The context enters a governance
//!   freeze state requiring explicit resolution (ADR-031 section 7).
//! - **Deadlock:** Detected when the governance model requires votes from
//!   permanently unavailable DIDs (ADR-031 section 10).
//!
//! See ADR-029 in `.docs/adrs/phase-6.md` and ADR-031 section 7.

use serde::{Deserialize, Serialize};

use super::ContextId;
use crate::context::governance::{GovernanceAction, GovernanceModelConfig, ProposalId};
use crate::identity::DID;

// ---------------------------------------------------------------------------
// MerkleRoot type alias
// ---------------------------------------------------------------------------

/// A Merkle root hash (SHA-256, 32 bytes).
///
/// Used as the authoritative state reference for conflict resolution.
pub type MerkleRoot = [u8; 32];

// ---------------------------------------------------------------------------
// ConflictType
// ---------------------------------------------------------------------------

/// Classification of concurrent offline conflicts.
///
/// Different conflict types require different resolution strategies.
/// See ADR-029 section 5 for the full conflict taxonomy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConflictType {
    /// Two concurrent metadata changes to the same field (e.g., context
    /// settings). Resolved via last-writer-wins by Merkle position.
    MetadataConflict,
    /// Two concurrent governance proposals that are incompatible (e.g.,
    /// conflicting role changes, mutual removal). Resolved by Merkle log
    /// order or governance freeze if simultaneous.
    GovernanceConflict,
    /// Two concurrent role changes targeting the same DID with different
    /// target roles. Resolved by Merkle log order.
    RoleConflict,
    /// Two concurrent membership changes that are incompatible (e.g.,
    /// remove + role change for the same DID). Resolved by Merkle log order.
    MembershipConflict,
}

// ---------------------------------------------------------------------------
// ConflictResolutionStrategy
// ---------------------------------------------------------------------------

/// The resolution strategy applied to resolve a conflict.
///
/// Each variant records which strategy was used and the outcome. All
/// strategies are deterministic and clock-independent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConflictResolutionStrategy {
    /// Last-writer-wins based on Merkle tree leaf index. The operation with
    /// the lower leaf index (committed first) wins.
    LastWriterWins {
        /// Leaf index of the winning operation.
        winner_leaf_index: u64,
        /// Leaf index of the losing operation.
        loser_leaf_index: u64,
    },
    /// Ordered by Merkle log position. The proposal committed first wins.
    MerkleOrdered {
        /// Proposal ID of the winner.
        winner_proposal_id: ProposalId,
        /// Proposal ID of the loser (invalidated).
        loser_proposal_id: ProposalId,
    },
    /// Governance freeze: both proposals landed at the same sequence number.
    /// The context is frozen for new governance actions until explicit
    /// resolution (ADR-031 section 7).
    GovernanceFreeze {
        /// Proposal IDs that caused the freeze.
        conflicting_proposals: Vec<ProposalId>,
    },
    /// Both operations were compatible and merged without conflict.
    Merged,
}

// ---------------------------------------------------------------------------
// MetadataOp
// ---------------------------------------------------------------------------

/// A metadata operation from an offline member.
///
/// Captures a change to context metadata along with its Merkle tree leaf
/// index for deterministic ordering. The leaf index is assigned when the
/// operation is committed to the event log.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetadataOp {
    /// The DID of the member who proposed this change.
    pub author_did: DID,
    /// The metadata field being changed (e.g., "description", "ttl").
    pub field: String,
    /// The new value for the field (serialized).
    #[serde(with = "serde_bytes")]
    pub value: Vec<u8>,
    /// Merkle tree leaf index where this operation was committed.
    /// Lower index = earlier in the log = committed first.
    pub leaf_index: u64,
}

// ---------------------------------------------------------------------------
// OfflineConflict
// ---------------------------------------------------------------------------

/// Captures two conflicting operations with their Merkle positions.
///
/// This is the input to conflict resolution. The two operations were
/// committed by different members while both were offline, and their
/// effects are incompatible.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OfflineConflict {
    /// The context where the conflict occurred.
    pub context_id: ContextId,
    /// Classification of the conflict.
    pub conflict_type: ConflictType,
    /// Merkle tree leaf index of the first operation.
    pub leaf_index_a: u64,
    /// Merkle tree leaf index of the second operation.
    pub leaf_index_b: u64,
    /// Proposal ID of the first operation (if governance/role/membership).
    pub proposal_id_a: Option<ProposalId>,
    /// Proposal ID of the second operation (if governance/role/membership).
    pub proposal_id_b: Option<ProposalId>,
}

// ---------------------------------------------------------------------------
// GovernanceProposalSnapshot
// ---------------------------------------------------------------------------

/// A lightweight snapshot of a governance proposal for conflict detection.
///
/// Contains only the fields needed for conflict resolution -- not the full
/// [`GovernanceProposal`] with its vote tracking.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GovernanceProposalSnapshot {
    /// Unique proposal identifier.
    pub proposal_id: ProposalId,
    /// The DID of the proposer.
    pub proposer_did: DID,
    /// The governance action being proposed.
    pub action: GovernanceAction,
    /// Merkle tree leaf index where this proposal was committed.
    pub leaf_index: u64,
}

// ---------------------------------------------------------------------------
// ForkSnapshot
// ---------------------------------------------------------------------------

/// A minimal snapshot of context state at a specific Merkle root.
///
/// Used as input to `fork_context` when a governance deadlock requires
/// creating a new context branch.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForkSnapshot {
    /// The context identifier.
    pub context_id: ContextId,
    /// Current members and their roles.
    pub members: Vec<(DID, String)>,
    /// The governance model configuration.
    pub governance_config: GovernanceModelConfig,
    /// Merkle root at the snapshot point.
    pub merkle_root: MerkleRoot,
    /// Number of events in the log at snapshot time.
    pub event_count: u64,
}

// ---------------------------------------------------------------------------
// ContextFork
// ---------------------------------------------------------------------------

/// The result of forking a context due to irreconcilable governance deadlock.
///
/// Per ADR-031 section 7, the context is not forked automatically. Instead,
/// it is frozen until an admin resolves the conflict. If no resolution is
/// reached within the voting window, both proposals are invalidated and the
/// freeze is lifted. `ContextFork` represents the metadata for a new context
/// branch if the participants choose to fork.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContextFork {
    /// The original context ID that was forked.
    pub original_context_id: ContextId,
    /// The new context ID for the fork.
    pub forked_context_id: ContextId,
    /// Merkle root at the fork point (last consistent state).
    pub fork_point: MerkleRoot,
    /// Number of events in the log at the fork point.
    pub fork_event_count: u64,
    /// Members included in the forked context.
    pub members: Vec<(DID, String)>,
    /// The governance model for the forked context.
    pub governance_config: GovernanceModelConfig,
}

// ---------------------------------------------------------------------------
// ConflictResolutionError
// ---------------------------------------------------------------------------

/// Errors produced by conflict resolution operations.
#[derive(Debug, thiserror::Error)]
pub enum ConflictResolutionError {
    /// The two operations are not actually conflicting.
    #[error("operations are not conflicting: {reason}")]
    NotConflicting {
        /// Explanation of why the operations are compatible.
        reason: String,
    },

    /// The proposals reference different contexts.
    #[error("proposals reference different contexts: {context_a} vs {context_b}")]
    ContextMismatch {
        /// Context ID of the first proposal.
        context_a: ContextId,
        /// Context ID of the second proposal.
        context_b: ContextId,
    },

    /// No proposals provided for governance conflict resolution.
    #[error("no proposals provided for conflict resolution")]
    EmptyProposals,

    /// Fork point not found in the event log.
    #[error("fork point not found: merkle root does not match any known state")]
    ForkPointNotFound,
}

// ---------------------------------------------------------------------------
// Conflict detection helpers
// ---------------------------------------------------------------------------

/// Checks whether two governance actions are conflicting.
///
/// Two actions conflict if they target the same entity with incompatible
/// changes. See ADR-031 section 7 for the conflict taxonomy.
///
/// # Examples of conflicts
///
/// - Two `ChangeRole` actions for the same DID with different target roles.
/// - Two `ModifyCeiling` actions with different ceiling sets.
/// - A `RemoveMember` and a `ChangeRole` targeting the same DID.
/// - Two `RemoveMember` actions targeting each other's proposers (mutual removal).
#[must_use]
pub fn actions_conflict(
    a: &GovernanceAction,
    a_proposer: &DID,
    b: &GovernanceAction,
    b_proposer: &DID,
) -> bool {
    match (a, b) {
        // Two role changes for the same DID with different roles.
        (
            GovernanceAction::ChangeRole {
                did: did_a,
                new_role: role_a,
            },
            GovernanceAction::ChangeRole {
                did: did_b,
                new_role: role_b,
            },
        ) => did_a == did_b && role_a != role_b,

        // Two ceiling modifications with different sets.
        (GovernanceAction::ModifyCeiling { .. }, GovernanceAction::ModifyCeiling { .. }) => {
            // Any two concurrent ceiling modifications conflict — the sets
            // may or may not differ, but concurrent modification is unsafe.
            true
        }

        // Remove + role change for the same DID.
        (
            GovernanceAction::RemoveMember {
                did: remove_did, ..
            },
            GovernanceAction::ChangeRole {
                did: change_did, ..
            },
        )
        | (
            GovernanceAction::ChangeRole {
                did: change_did, ..
            },
            GovernanceAction::RemoveMember {
                did: remove_did, ..
            },
        ) => remove_did == change_did,

        // Mutual removal: each proposer removes the other.
        (
            GovernanceAction::RemoveMember { did: did_a, .. },
            GovernanceAction::RemoveMember { did: did_b, .. },
        ) => did_a == b_proposer && did_b == a_proposer,

        // All other action pairs are non-conflicting.
        _ => false,
    }
}

// ---------------------------------------------------------------------------
// Metadata conflict resolution
// ---------------------------------------------------------------------------

/// Resolves a metadata conflict using last-writer-wins by Merkle position.
///
/// When two offline members concurrently modify the same metadata field,
/// the operation committed first to the Merkle event log wins. "First"
/// means lower leaf index — determined by the log's append order, not by
/// wall-clock time.
///
/// This satisfies the §9.8.3 requirement: no synchronized clock dependency.
///
/// # Returns
///
/// - `LastWriterWins` with the winner and loser leaf indices.
/// - `Merged` if the operations modify different fields (no conflict).
///
/// See ADR-029 section 5c.
#[must_use]
pub fn resolve_metadata_conflict(a: &MetadataOp, b: &MetadataOp) -> ConflictResolutionStrategy {
    // Different fields — no conflict, merge both.
    if a.field != b.field {
        return ConflictResolutionStrategy::Merged;
    }

    // Same field — lower leaf index wins.
    if a.leaf_index <= b.leaf_index {
        ConflictResolutionStrategy::LastWriterWins {
            winner_leaf_index: a.leaf_index,
            loser_leaf_index: b.leaf_index,
        }
    } else {
        ConflictResolutionStrategy::LastWriterWins {
            winner_leaf_index: b.leaf_index,
            loser_leaf_index: a.leaf_index,
        }
    }
}

// ---------------------------------------------------------------------------
// Governance conflict resolution
// ---------------------------------------------------------------------------

/// Resolves conflicting governance proposals deterministically.
///
/// When two or more admins are offline and propose conflicting governance
/// actions, the conflict is resolved by Merkle log order:
///
/// - The proposal with the lower leaf index (committed first) wins.
/// - The losing proposal is invalidated with reason "Conflicting proposal
///   {`winner_id`} committed first".
/// - If two proposals have the same leaf index (simultaneous commit), the
///   context enters a governance freeze (ADR-031 section 7).
///
/// No synchronized clock dependency (§9.8.3).
///
/// # Errors
///
/// Returns [`ConflictResolutionError::EmptyProposals`] if the slice is empty.
/// Returns [`ConflictResolutionError::NotConflicting`] if no pair of
/// proposals actually conflicts.
///
/// See ADR-029 section 5c and ADR-031 section 7.
pub fn resolve_governance_conflict(
    proposals: &[GovernanceProposalSnapshot],
) -> Result<ConflictResolutionStrategy, ConflictResolutionError> {
    if proposals.is_empty() {
        return Err(ConflictResolutionError::EmptyProposals);
    }

    if proposals.len() == 1 {
        return Err(ConflictResolutionError::NotConflicting {
            reason: "only one proposal provided".to_owned(),
        });
    }

    // Find all conflicting pairs.
    let mut conflicting_pairs: Vec<(usize, usize)> = Vec::new();
    for i in 0..proposals.len() {
        for j in (i + 1)..proposals.len() {
            if actions_conflict(
                &proposals[i].action,
                &proposals[i].proposer_did,
                &proposals[j].action,
                &proposals[j].proposer_did,
            ) {
                conflicting_pairs.push((i, j));
            }
        }
    }

    if conflicting_pairs.is_empty() {
        return Err(ConflictResolutionError::NotConflicting {
            reason: "no conflicting action pairs found".to_owned(),
        });
    }

    // Check for simultaneous commits (same leaf index) among any conflicting pair.
    let simultaneous: Vec<ProposalId> = conflicting_pairs
        .iter()
        .filter(|(i, j)| proposals[*i].leaf_index == proposals[*j].leaf_index)
        .flat_map(|(i, j)| vec![proposals[*i].proposal_id, proposals[*j].proposal_id])
        .collect();

    if !simultaneous.is_empty() {
        // Deduplicate proposal IDs.
        let mut deduped = simultaneous;
        deduped.sort_unstable();
        deduped.dedup();
        return Ok(ConflictResolutionStrategy::GovernanceFreeze {
            conflicting_proposals: deduped,
        });
    }

    // All conflicting pairs have different leaf indices.
    // Resolve by finding the pair with the smallest gap and using
    // the lower leaf index as winner.
    //
    // For simplicity (and per ADR-031 section 7), we resolve the first
    // conflicting pair — the proposal with the lower leaf index wins.
    let (i, j) = conflicting_pairs[0];
    let (winner, loser) = if proposals[i].leaf_index < proposals[j].leaf_index {
        (&proposals[i], &proposals[j])
    } else {
        (&proposals[j], &proposals[i])
    };

    Ok(ConflictResolutionStrategy::MerkleOrdered {
        winner_proposal_id: winner.proposal_id,
        loser_proposal_id: loser.proposal_id,
    })
}

// ---------------------------------------------------------------------------
// Deadlock detection
// ---------------------------------------------------------------------------

/// Detects whether a set of governance proposals constitutes a deadlock.
///
/// A deadlock occurs when conflicting proposals have the same Merkle leaf
/// index (simultaneous commit), making it impossible to determine a winner
/// by log order alone. The context enters a governance freeze state
/// requiring explicit resolution.
///
/// This also detects mutual-removal deadlocks: two proposals that each
/// remove the other's proposer, creating a circular dependency that cannot
/// be resolved by simple ordering.
///
/// See ADR-031 sections 7 and 10.
#[must_use]
pub fn detect_deadlock(proposals: &[GovernanceProposalSnapshot]) -> bool {
    if proposals.len() < 2 {
        return false;
    }

    for i in 0..proposals.len() {
        for j in (i + 1)..proposals.len() {
            if !actions_conflict(
                &proposals[i].action,
                &proposals[i].proposer_did,
                &proposals[j].action,
                &proposals[j].proposer_did,
            ) {
                continue;
            }

            // Same leaf index = simultaneous commit = deadlock.
            if proposals[i].leaf_index == proposals[j].leaf_index {
                return true;
            }

            // Mutual removal: each proposer removes the other. Even with
            // different leaf indices, this is a logical deadlock because
            // executing the first removal invalidates the authority of
            // the second proposer.
            if is_mutual_removal(
                &proposals[i].action,
                &proposals[i].proposer_did,
                &proposals[j].action,
                &proposals[j].proposer_did,
            ) {
                return true;
            }
        }
    }

    false
}

/// Checks whether two actions constitute mutual removal (each proposer
/// removes the other).
fn is_mutual_removal(
    a: &GovernanceAction,
    a_proposer: &DID,
    b: &GovernanceAction,
    b_proposer: &DID,
) -> bool {
    matches!(
        (a, b),
        (
            GovernanceAction::RemoveMember { did: did_a, .. },
            GovernanceAction::RemoveMember { did: did_b, .. },
        ) if did_a == b_proposer && did_b == a_proposer
    )
}

// ---------------------------------------------------------------------------
// Context fork
// ---------------------------------------------------------------------------

/// Creates a context fork from a snapshot at a given fork point.
///
/// When a governance deadlock cannot be resolved (no resolution reached
/// within the voting window, or participants choose to split), this
/// function generates the metadata for a new context branch.
///
/// The forked context:
/// - Starts from the last consistent state (the fork point).
/// - Inherits all members and the governance configuration.
/// - Gets a new deterministic context ID derived from the original ID
///   and the fork point Merkle root.
///
/// Per ADR-031 section 7, context fork is not automatic. It is an explicit
/// action taken when deadlock resolution fails.
///
/// # Errors
///
/// Returns [`ConflictResolutionError::ForkPointNotFound`] if the provided
/// Merkle root does not match the snapshot's root (sanity check).
pub fn fork_context(
    original: &ForkSnapshot,
    fork_point: &MerkleRoot,
) -> Result<ContextFork, ConflictResolutionError> {
    // Sanity check: the fork point must match the snapshot's Merkle root.
    if original.merkle_root != *fork_point {
        return Err(ConflictResolutionError::ForkPointNotFound);
    }

    // Generate a deterministic forked context ID from the original ID and
    // the fork point. This ensures all members compute the same fork ID.
    let forked_id = generate_fork_id(&original.context_id, fork_point);

    Ok(ContextFork {
        original_context_id: original.context_id.clone(),
        forked_context_id: forked_id,
        fork_point: *fork_point,
        fork_event_count: original.event_count,
        members: original.members.clone(),
        governance_config: original.governance_config.clone(),
    })
}

/// Generates a deterministic context ID for a fork.
///
/// The fork ID is derived from `SHA-256(original_id || "fork" || merkle_root)`
/// encoded as a hex string prefixed with "fork-". This ensures all members
/// independently compute the same fork ID.
fn generate_fork_id(original_context_id: &str, fork_point: &MerkleRoot) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(original_context_id.as_bytes());
    hasher.update(b"fork");
    hasher.update(fork_point);
    let hash = hasher.finalize();
    let hex: String = hash[..16].iter().fold(String::with_capacity(32), |mut s, b| {
        use std::fmt::Write;
        let _ = write!(s, "{b:02x}");
        s
    });
    format!("fork-{hex}")
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
)]
mod tests {
    use super::*;

    // Helper: create a DID from a string.
    fn did(s: &str) -> DID {
        DID(s.to_owned())
    }

    // Helper: create a proposal ID from a byte.
    fn proposal_id(b: u8) -> ProposalId {
        let mut id = [0u8; 32];
        id[0] = b;
        id
    }

    // Helper: create a MetadataOp.
    fn metadata_op(author: &str, field: &str, value: &[u8], leaf_index: u64) -> MetadataOp {
        MetadataOp {
            author_did: did(author),
            field: field.to_owned(),
            value: value.to_vec(),
            leaf_index,
        }
    }

    // Helper: create a GovernanceProposalSnapshot.
    fn gov_proposal(
        id_byte: u8,
        proposer: &str,
        action: GovernanceAction,
        leaf_index: u64,
    ) -> GovernanceProposalSnapshot {
        GovernanceProposalSnapshot {
            proposal_id: proposal_id(id_byte),
            proposer_did: did(proposer),
            action,
            leaf_index,
        }
    }

    // -----------------------------------------------------------------------
    // ConflictType serialization
    // -----------------------------------------------------------------------

    #[test]
    fn conflict_type_variants_are_serializable() {
        let variants = vec![
            ConflictType::MetadataConflict,
            ConflictType::GovernanceConflict,
            ConflictType::RoleConflict,
            ConflictType::MembershipConflict,
        ];
        for variant in &variants {
            let json = serde_json::to_string(variant);
            assert!(json.is_ok(), "failed to serialize {variant:?}");
        }
    }

    // -----------------------------------------------------------------------
    // actions_conflict
    // -----------------------------------------------------------------------

    #[test]
    fn conflicting_role_changes_same_did_different_roles() {
        let a = GovernanceAction::ChangeRole {
            did: did("did:dht:alice"),
            new_role: "admin".to_owned(),
        };
        let b = GovernanceAction::ChangeRole {
            did: did("did:dht:alice"),
            new_role: "member".to_owned(),
        };
        assert!(actions_conflict(
            &a,
            &did("did:dht:bob"),
            &b,
            &did("did:dht:carol"),
        ));
    }

    #[test]
    fn non_conflicting_role_changes_same_did_same_role() {
        let a = GovernanceAction::ChangeRole {
            did: did("did:dht:alice"),
            new_role: "admin".to_owned(),
        };
        let b = GovernanceAction::ChangeRole {
            did: did("did:dht:alice"),
            new_role: "admin".to_owned(),
        };
        assert!(!actions_conflict(
            &a,
            &did("did:dht:bob"),
            &b,
            &did("did:dht:carol"),
        ));
    }

    #[test]
    fn non_conflicting_role_changes_different_dids() {
        let a = GovernanceAction::ChangeRole {
            did: did("did:dht:alice"),
            new_role: "admin".to_owned(),
        };
        let b = GovernanceAction::ChangeRole {
            did: did("did:dht:bob"),
            new_role: "member".to_owned(),
        };
        assert!(!actions_conflict(
            &a,
            &did("did:dht:carol"),
            &b,
            &did("did:dht:dave"),
        ));
    }

    #[test]
    fn conflicting_ceiling_modifications() {
        let a = GovernanceAction::ModifyCeiling {
            new_ceiling: vec![],
        };
        let b = GovernanceAction::ModifyCeiling {
            new_ceiling: vec![],
        };
        assert!(actions_conflict(
            &a,
            &did("did:dht:alice"),
            &b,
            &did("did:dht:bob"),
        ));
    }

    #[test]
    fn conflicting_remove_and_role_change_same_did() {
        let remove = GovernanceAction::RemoveMember {
            did: did("did:dht:alice"),
            reason: None,
        };
        let change = GovernanceAction::ChangeRole {
            did: did("did:dht:alice"),
            new_role: "admin".to_owned(),
        };
        assert!(actions_conflict(
            &remove,
            &did("did:dht:bob"),
            &change,
            &did("did:dht:carol"),
        ));
        // Commutative.
        assert!(actions_conflict(
            &change,
            &did("did:dht:carol"),
            &remove,
            &did("did:dht:bob"),
        ));
    }

    #[test]
    fn conflicting_mutual_removal() {
        let a = GovernanceAction::RemoveMember {
            did: did("did:dht:bob"),
            reason: None,
        };
        let b = GovernanceAction::RemoveMember {
            did: did("did:dht:alice"),
            reason: None,
        };
        assert!(actions_conflict(
            &a,
            &did("did:dht:alice"),
            &b,
            &did("did:dht:bob"),
        ));
    }

    #[test]
    fn non_conflicting_removals_of_different_members() {
        let a = GovernanceAction::RemoveMember {
            did: did("did:dht:carol"),
            reason: None,
        };
        let b = GovernanceAction::RemoveMember {
            did: did("did:dht:dave"),
            reason: None,
        };
        assert!(!actions_conflict(
            &a,
            &did("did:dht:alice"),
            &b,
            &did("did:dht:bob"),
        ));
    }

    #[test]
    fn non_conflicting_unrelated_actions() {
        let a = GovernanceAction::CloseContext {
            reason: Some("done".to_owned()),
        };
        let b = GovernanceAction::ExtendTtl {
            additional_secs: 3600,
        };
        assert!(!actions_conflict(
            &a,
            &did("did:dht:alice"),
            &b,
            &did("did:dht:bob"),
        ));
    }

    // -----------------------------------------------------------------------
    // resolve_metadata_conflict
    // -----------------------------------------------------------------------

    #[test]
    fn metadata_conflict_different_fields_merges() {
        let a = metadata_op("did:dht:alice", "description", b"hello", 5);
        let b = metadata_op("did:dht:bob", "ttl", b"3600", 3);
        assert_eq!(
            resolve_metadata_conflict(&a, &b),
            ConflictResolutionStrategy::Merged,
        );
    }

    #[test]
    fn metadata_conflict_same_field_lower_index_wins() {
        let a = metadata_op("did:dht:alice", "description", b"first", 3);
        let b = metadata_op("did:dht:bob", "description", b"second", 7);
        assert_eq!(
            resolve_metadata_conflict(&a, &b),
            ConflictResolutionStrategy::LastWriterWins {
                winner_leaf_index: 3,
                loser_leaf_index: 7,
            },
        );
    }

    #[test]
    fn metadata_conflict_reversed_order_still_lower_wins() {
        let a = metadata_op("did:dht:alice", "description", b"second", 10);
        let b = metadata_op("did:dht:bob", "description", b"first", 2);
        assert_eq!(
            resolve_metadata_conflict(&a, &b),
            ConflictResolutionStrategy::LastWriterWins {
                winner_leaf_index: 2,
                loser_leaf_index: 10,
            },
        );
    }

    #[test]
    fn metadata_conflict_same_index_first_arg_wins() {
        // When indices are equal, a wins (a.leaf_index <= b.leaf_index).
        let a = metadata_op("did:dht:alice", "description", b"tied-a", 5);
        let b = metadata_op("did:dht:bob", "description", b"tied-b", 5);
        assert_eq!(
            resolve_metadata_conflict(&a, &b),
            ConflictResolutionStrategy::LastWriterWins {
                winner_leaf_index: 5,
                loser_leaf_index: 5,
            },
        );
    }

    // -----------------------------------------------------------------------
    // resolve_governance_conflict
    // -----------------------------------------------------------------------

    #[test]
    fn governance_conflict_empty_proposals_errors() {
        let result = resolve_governance_conflict(&[]);
        assert!(matches!(
            result,
            Err(ConflictResolutionError::EmptyProposals)
        ));
    }

    #[test]
    fn governance_conflict_single_proposal_errors() {
        let p = gov_proposal(
            1,
            "did:dht:alice",
            GovernanceAction::ChangeRole {
                did: did("did:dht:bob"),
                new_role: "admin".to_owned(),
            },
            5,
        );
        let result = resolve_governance_conflict(&[p]);
        assert!(matches!(
            result,
            Err(ConflictResolutionError::NotConflicting { .. })
        ));
    }

    #[test]
    fn governance_conflict_non_conflicting_proposals_errors() {
        let p1 = gov_proposal(
            1,
            "did:dht:alice",
            GovernanceAction::ChangeRole {
                did: did("did:dht:bob"),
                new_role: "admin".to_owned(),
            },
            5,
        );
        let p2 = gov_proposal(
            2,
            "did:dht:carol",
            GovernanceAction::ChangeRole {
                did: did("did:dht:dave"),
                new_role: "member".to_owned(),
            },
            7,
        );
        let result = resolve_governance_conflict(&[p1, p2]);
        assert!(matches!(
            result,
            Err(ConflictResolutionError::NotConflicting { .. })
        ));
    }

    #[test]
    fn governance_conflict_lower_leaf_index_wins() {
        let p1 = gov_proposal(
            1,
            "did:dht:alice",
            GovernanceAction::ChangeRole {
                did: did("did:dht:target"),
                new_role: "admin".to_owned(),
            },
            3,
        );
        let p2 = gov_proposal(
            2,
            "did:dht:bob",
            GovernanceAction::ChangeRole {
                did: did("did:dht:target"),
                new_role: "observer".to_owned(),
            },
            7,
        );
        let result = resolve_governance_conflict(&[p1, p2]);
        assert!(result.is_ok());
        assert_eq!(
            result.ok(),
            Some(ConflictResolutionStrategy::MerkleOrdered {
                winner_proposal_id: proposal_id(1),
                loser_proposal_id: proposal_id(2),
            }),
        );
    }

    #[test]
    fn governance_conflict_order_independent() {
        // Same proposals in reversed order should produce the same winner.
        let p1 = gov_proposal(
            1,
            "did:dht:alice",
            GovernanceAction::ChangeRole {
                did: did("did:dht:target"),
                new_role: "admin".to_owned(),
            },
            3,
        );
        let p2 = gov_proposal(
            2,
            "did:dht:bob",
            GovernanceAction::ChangeRole {
                did: did("did:dht:target"),
                new_role: "observer".to_owned(),
            },
            7,
        );
        let result_ab = resolve_governance_conflict(&[p1.clone(), p2.clone()]);
        let result_ba = resolve_governance_conflict(&[p2, p1]);
        assert_eq!(result_ab.ok(), result_ba.ok());
    }

    #[test]
    fn governance_conflict_same_leaf_index_triggers_freeze() {
        let p1 = gov_proposal(
            1,
            "did:dht:alice",
            GovernanceAction::ChangeRole {
                did: did("did:dht:target"),
                new_role: "admin".to_owned(),
            },
            5,
        );
        let p2 = gov_proposal(
            2,
            "did:dht:bob",
            GovernanceAction::ChangeRole {
                did: did("did:dht:target"),
                new_role: "observer".to_owned(),
            },
            5,
        );
        let result = resolve_governance_conflict(&[p1, p2]);
        assert!(result.is_ok());
        match result.ok() {
            Some(ConflictResolutionStrategy::GovernanceFreeze {
                conflicting_proposals,
            }) => {
                assert_eq!(conflicting_proposals.len(), 2);
                assert!(conflicting_proposals.contains(&proposal_id(1)));
                assert!(conflicting_proposals.contains(&proposal_id(2)));
            }
            other => panic!("expected GovernanceFreeze, got {other:?}"),
        }
    }

    #[test]
    fn governance_conflict_mutual_removal_resolved_by_order() {
        let p1 = gov_proposal(
            1,
            "did:dht:alice",
            GovernanceAction::RemoveMember {
                did: did("did:dht:bob"),
                reason: None,
            },
            3,
        );
        let p2 = gov_proposal(
            2,
            "did:dht:bob",
            GovernanceAction::RemoveMember {
                did: did("did:dht:alice"),
                reason: None,
            },
            7,
        );
        let result = resolve_governance_conflict(&[p1, p2]);
        assert!(result.is_ok());
        assert_eq!(
            result.ok(),
            Some(ConflictResolutionStrategy::MerkleOrdered {
                winner_proposal_id: proposal_id(1),
                loser_proposal_id: proposal_id(2),
            }),
        );
    }

    #[test]
    fn governance_conflict_three_proposals_first_conflicting_pair_resolved() {
        // Three proposals: p1 and p3 conflict (same DID, different roles).
        // p2 is unrelated.
        let p1 = gov_proposal(
            1,
            "did:dht:alice",
            GovernanceAction::ChangeRole {
                did: did("did:dht:target"),
                new_role: "admin".to_owned(),
            },
            2,
        );
        let p2 = gov_proposal(
            2,
            "did:dht:bob",
            GovernanceAction::CloseContext {
                reason: Some("unrelated".to_owned()),
            },
            5,
        );
        let p3 = gov_proposal(
            3,
            "did:dht:carol",
            GovernanceAction::ChangeRole {
                did: did("did:dht:target"),
                new_role: "observer".to_owned(),
            },
            8,
        );
        let result = resolve_governance_conflict(&[p1, p2, p3]);
        assert!(result.is_ok());
        assert_eq!(
            result.ok(),
            Some(ConflictResolutionStrategy::MerkleOrdered {
                winner_proposal_id: proposal_id(1),
                loser_proposal_id: proposal_id(3),
            }),
        );
    }

    // -----------------------------------------------------------------------
    // detect_deadlock
    // -----------------------------------------------------------------------

    #[test]
    fn no_deadlock_with_single_proposal() {
        let p = gov_proposal(
            1,
            "did:dht:alice",
            GovernanceAction::ChangeRole {
                did: did("did:dht:bob"),
                new_role: "admin".to_owned(),
            },
            5,
        );
        assert!(!detect_deadlock(&[p]));
    }

    #[test]
    fn no_deadlock_with_non_conflicting_proposals() {
        let p1 = gov_proposal(
            1,
            "did:dht:alice",
            GovernanceAction::ChangeRole {
                did: did("did:dht:bob"),
                new_role: "admin".to_owned(),
            },
            3,
        );
        let p2 = gov_proposal(
            2,
            "did:dht:carol",
            GovernanceAction::ChangeRole {
                did: did("did:dht:dave"),
                new_role: "member".to_owned(),
            },
            7,
        );
        assert!(!detect_deadlock(&[p1, p2]));
    }

    #[test]
    fn no_deadlock_with_different_leaf_indices_non_mutual() {
        // Conflicting but not simultaneous and not mutual removal.
        let p1 = gov_proposal(
            1,
            "did:dht:alice",
            GovernanceAction::ChangeRole {
                did: did("did:dht:target"),
                new_role: "admin".to_owned(),
            },
            3,
        );
        let p2 = gov_proposal(
            2,
            "did:dht:bob",
            GovernanceAction::ChangeRole {
                did: did("did:dht:target"),
                new_role: "observer".to_owned(),
            },
            7,
        );
        assert!(!detect_deadlock(&[p1, p2]));
    }

    #[test]
    fn deadlock_with_same_leaf_index() {
        let p1 = gov_proposal(
            1,
            "did:dht:alice",
            GovernanceAction::ChangeRole {
                did: did("did:dht:target"),
                new_role: "admin".to_owned(),
            },
            5,
        );
        let p2 = gov_proposal(
            2,
            "did:dht:bob",
            GovernanceAction::ChangeRole {
                did: did("did:dht:target"),
                new_role: "observer".to_owned(),
            },
            5,
        );
        assert!(detect_deadlock(&[p1, p2]));
    }

    #[test]
    fn deadlock_with_mutual_removal_even_different_indices() {
        let p1 = gov_proposal(
            1,
            "did:dht:alice",
            GovernanceAction::RemoveMember {
                did: did("did:dht:bob"),
                reason: None,
            },
            3,
        );
        let p2 = gov_proposal(
            2,
            "did:dht:bob",
            GovernanceAction::RemoveMember {
                did: did("did:dht:alice"),
                reason: None,
            },
            7,
        );
        assert!(detect_deadlock(&[p1, p2]));
    }

    #[test]
    fn no_deadlock_empty_proposals() {
        assert!(!detect_deadlock(&[]));
    }

    // -----------------------------------------------------------------------
    // fork_context
    // -----------------------------------------------------------------------

    #[test]
    fn fork_context_succeeds_with_matching_root() {
        let root = [42u8; 32];
        let snapshot = ForkSnapshot {
            context_id: "ctx-original".to_owned(),
            members: vec![
                (did("did:dht:alice"), "admin".to_owned()),
                (did("did:dht:bob"), "member".to_owned()),
            ],
            governance_config: GovernanceModelConfig::SingleAdmin {
                admin_did: did("did:dht:alice"),
            },
            merkle_root: root,
            event_count: 100,
        };

        let result = fork_context(&snapshot, &root);
        assert!(result.is_ok());
        let fork = result.ok();
        assert!(fork.is_some());
        let fork = fork.as_ref();
        assert_eq!(
            fork.map(|f| f.original_context_id.as_str()),
            Some("ctx-original"),
        );
        assert_eq!(fork.map(|f| f.fork_point), Some(root));
        assert_eq!(fork.map(|f| f.fork_event_count), Some(100));
        assert_eq!(fork.map(|f| f.members.len()), Some(2));
        // Fork ID should start with "fork-".
        assert!(
            fork.is_some_and(|f| f.forked_context_id.starts_with("fork-"))
        );
    }

    #[test]
    fn fork_context_fails_with_mismatched_root() {
        let snapshot = ForkSnapshot {
            context_id: "ctx-original".to_owned(),
            members: vec![],
            governance_config: GovernanceModelConfig::SingleAdmin {
                admin_did: did("did:dht:alice"),
            },
            merkle_root: [1u8; 32],
            event_count: 50,
        };

        let different_root = [2u8; 32];
        let result = fork_context(&snapshot, &different_root);
        assert!(matches!(
            result,
            Err(ConflictResolutionError::ForkPointNotFound)
        ));
    }

    #[test]
    fn fork_id_is_deterministic() {
        let root = [99u8; 32];
        let snapshot = ForkSnapshot {
            context_id: "ctx-1".to_owned(),
            members: vec![],
            governance_config: GovernanceModelConfig::SingleAdmin {
                admin_did: did("did:dht:alice"),
            },
            merkle_root: root,
            event_count: 10,
        };

        let fork1 = fork_context(&snapshot, &root);
        let fork2 = fork_context(&snapshot, &root);
        assert!(fork1.is_ok());
        assert!(fork2.is_ok());
        assert_eq!(
            fork1.as_ref().ok().map(|f| &f.forked_context_id),
            fork2.as_ref().ok().map(|f| &f.forked_context_id),
        );
    }

    // -----------------------------------------------------------------------
    // ConflictResolutionStrategy serialization
    // -----------------------------------------------------------------------

    #[test]
    fn resolution_strategies_are_serializable() {
        let strategies = vec![
            ConflictResolutionStrategy::LastWriterWins {
                winner_leaf_index: 3,
                loser_leaf_index: 7,
            },
            ConflictResolutionStrategy::MerkleOrdered {
                winner_proposal_id: proposal_id(1),
                loser_proposal_id: proposal_id(2),
            },
            ConflictResolutionStrategy::GovernanceFreeze {
                conflicting_proposals: vec![proposal_id(1), proposal_id(2)],
            },
            ConflictResolutionStrategy::Merged,
        ];
        for strategy in &strategies {
            let json = serde_json::to_string(strategy);
            assert!(json.is_ok(), "failed to serialize {strategy:?}");
        }
    }

    // -----------------------------------------------------------------------
    // OfflineConflict struct
    // -----------------------------------------------------------------------

    #[test]
    fn offline_conflict_is_serializable() {
        let conflict = OfflineConflict {
            context_id: "ctx-1".to_owned(),
            conflict_type: ConflictType::GovernanceConflict,
            leaf_index_a: 3,
            leaf_index_b: 7,
            proposal_id_a: Some(proposal_id(1)),
            proposal_id_b: Some(proposal_id(2)),
        };
        let json = serde_json::to_string(&conflict);
        assert!(json.is_ok());
        let deserialized: Result<OfflineConflict, _> =
            serde_json::from_str(json.as_deref().unwrap_or(""));
        assert!(deserialized.is_ok());
    }

    // -----------------------------------------------------------------------
    // No clock dependency verification
    // -----------------------------------------------------------------------

    #[test]
    fn resolution_uses_leaf_index_not_timestamp() {
        // Two metadata ops where the "later" timestamp has the lower leaf index.
        // The lower leaf index should still win, proving no clock dependency.
        let early_clock_late_log = metadata_op("did:dht:alice", "title", b"early-clock", 10);
        let late_clock_early_log = metadata_op("did:dht:bob", "title", b"late-clock", 2);

        let result = resolve_metadata_conflict(&early_clock_late_log, &late_clock_early_log);
        assert_eq!(
            result,
            ConflictResolutionStrategy::LastWriterWins {
                winner_leaf_index: 2,
                loser_leaf_index: 10,
            },
        );
    }

    #[test]
    fn governance_resolution_uses_leaf_index_not_timestamp() {
        // Proposal p2 was "created later" (higher leaf index) but should lose.
        let p1 = gov_proposal(
            1,
            "did:dht:alice",
            GovernanceAction::ModifyCeiling {
                new_ceiling: vec![],
            },
            2,
        );
        let p2 = gov_proposal(
            2,
            "did:dht:bob",
            GovernanceAction::ModifyCeiling {
                new_ceiling: vec![],
            },
            100,
        );
        let result = resolve_governance_conflict(&[p1, p2]);
        assert!(result.is_ok());
        assert_eq!(
            result.ok(),
            Some(ConflictResolutionStrategy::MerkleOrdered {
                winner_proposal_id: proposal_id(1),
                loser_proposal_id: proposal_id(2),
            }),
        );
    }

    // -----------------------------------------------------------------------
    // ContextFork
    // -----------------------------------------------------------------------

    #[test]
    fn context_fork_is_serializable() {
        let fork = ContextFork {
            original_context_id: "ctx-1".to_owned(),
            forked_context_id: "fork-abc123".to_owned(),
            fork_point: [0u8; 32],
            fork_event_count: 50,
            members: vec![(did("did:dht:alice"), "admin".to_owned())],
            governance_config: GovernanceModelConfig::SingleAdmin {
                admin_did: did("did:dht:alice"),
            },
        };
        let json = serde_json::to_string(&fork);
        assert!(json.is_ok());
    }
}
