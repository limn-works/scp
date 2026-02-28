//! Governance-MLS epoch coordination (SCP-133, ADR-031 section 8).
//!
//! Governance proposals and votes are MLS application messages. They do **not**
//! trigger MLS epoch advances on their own. However, governance actions that
//! result in membership changes (`AddMember`, `RemoveMember`) DO trigger MLS
//! operations (add/remove), which advance the epoch.
//!
//! The lifecycle when a membership-affecting proposal is approved:
//!
//! 1. Proposal approved (governance decision).
//! 2. [`ContextManager`](super::super::manager::ContextManager) executes the
//!    membership change via MLS `add_member()`/`remove_member()`.
//! 3. MLS Commit advances the epoch.
//! 4. `GovernanceActionExecuted` event appended to event log.
//!
//! Pending proposals are NOT invalidated by epoch advances. A proposal created
//! at epoch E is valid at epoch E+N -- the proposal references a governance
//! action, not epoch-specific state. The sole exception is group state reset
//! (ADR-029 Tier 3), which invalidates pending proposals.
//!
//! This module provides:
//!
//! - [`MlsImpact`] -- Classification of governance actions by MLS effect.
//! - [`classify_action`] -- Determine the MLS impact of a governance action.
//! - [`MlsOperation`] -- MLS operations triggered by approved governance actions.
//! - [`generate_mls_operations`] -- Produce MLS operations from an approved
//!   proposal.
//! - [`EpochCoordinator`] -- Coordinates governance approval with MLS commits.
//! - [`ConsistencyCheck`] / [`check_consistency`] -- Verify governance and MLS
//!   state agreement.

use serde::{Deserialize, Serialize};

use crate::identity::DID;

use super::{
    GovernanceAction, GovernanceContext, GovernanceError, GovernanceProposal, ProposalStatus,
};

// ---------------------------------------------------------------------------
// MlsImpact -- classification of governance actions
// ---------------------------------------------------------------------------

/// Classification of a governance action's impact on MLS group state.
///
/// Membership-affecting actions require MLS operations (add/remove) and trigger
/// epoch advances. Non-membership actions are purely governance-level and skip
/// MLS coordination entirely. See ADR-031 section 8.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MlsImpact {
    /// The action affects MLS group membership. An MLS add or remove proposal
    /// and Commit are required, advancing the epoch.
    MembershipChange,

    /// The action does not affect MLS group membership. No MLS operations are
    /// needed; the governance decision is applied without epoch advance.
    NoMlsChange,
}

/// Classify a [`GovernanceAction`] by its MLS impact.
///
/// Only `AddMember` and `RemoveMember` require MLS group operations. All other
/// governance actions (role changes, settings changes, tool registration, etc.)
/// operate at the governance layer without touching MLS state.
///
/// # Examples
///
/// ```rust
/// use scp_core::context::governance::mls_integration::{classify_action, MlsImpact};
/// use scp_core::context::governance::GovernanceAction;
/// use scp_core::identity::DID;
///
/// let add = GovernanceAction::AddMember {
///     did: DID::from("did:dht:z6MkTest"),
///     role: "member".to_owned(),
/// };
/// assert_eq!(classify_action(&add), MlsImpact::MembershipChange);
///
/// let close = GovernanceAction::CloseContext { reason: None };
/// assert_eq!(classify_action(&close), MlsImpact::NoMlsChange);
/// ```
#[must_use]
pub const fn classify_action(action: &GovernanceAction) -> MlsImpact {
    match action {
        GovernanceAction::AddMember { .. } | GovernanceAction::RemoveMember { .. } => {
            MlsImpact::MembershipChange
        }
        GovernanceAction::ChangeRole { .. }
        | GovernanceAction::RegisterTool { .. }
        | GovernanceAction::RemoveTool { .. }
        | GovernanceAction::ModifyCeiling { .. }
        | GovernanceAction::CloseContext { .. }
        | GovernanceAction::ExtendTtl { .. }
        | GovernanceAction::TransferAdmin { .. }
        | GovernanceAction::CreateChildContext { .. } => MlsImpact::NoMlsChange,
    }
}

// ---------------------------------------------------------------------------
// MlsOperation -- operations generated for approved proposals
// ---------------------------------------------------------------------------

/// An MLS operation that must be executed after a governance proposal is
/// approved and the action affects membership.
///
/// The [`ContextManager`](super::super::manager::ContextManager) consumes
/// these operations and translates them into concrete MLS API calls
/// (`add_member`, `remove_member`) which produce Commits and advance the epoch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum MlsOperation {
    /// Add a member to the MLS group. The `ContextManager` must obtain the
    /// member's `KeyPackage` and call `add_member()` on the `ScpMlsGroup`.
    AddMember {
        /// DID of the member to add.
        did: DID,
        /// Role assigned to the new member (for UCAN token minting).
        role: String,
    },

    /// Remove a member from the MLS group. The `ContextManager` must resolve
    /// the member's leaf index and call `remove_member()` on the `ScpMlsGroup`.
    RemoveMember {
        /// DID of the member to remove.
        did: DID,
        /// Optional reason for removal (included in governance event).
        reason: Option<String>,
    },
}

/// Generate MLS operations from an approved governance proposal.
///
/// Returns `Ok(Some(operation))` for membership-affecting proposals and
/// `Ok(None)` for non-membership proposals. Returns an error if the proposal
/// is not in `Approved` status.
///
/// The caller ([`ContextManager`](super::super::manager::ContextManager)) is
/// responsible for executing the returned operation against the `ScpMlsGroup`.
///
/// # Errors
///
/// Returns [`GovernanceError::ProposalNotPending`] if the proposal is not
/// approved (the status field describes the actual status).
pub fn generate_mls_operations(
    proposal: &GovernanceProposal,
) -> Result<Option<MlsOperation>, GovernanceError> {
    if proposal.status != ProposalStatus::Approved {
        return Err(GovernanceError::ProposalNotPending {
            status: format!("{:?}", proposal.status),
        });
    }

    let operation = match &proposal.action {
        GovernanceAction::AddMember { did, role } => Some(MlsOperation::AddMember {
            did: did.clone(),
            role: role.clone(),
        }),
        GovernanceAction::RemoveMember { did, reason } => Some(MlsOperation::RemoveMember {
            did: did.clone(),
            reason: reason.clone(),
        }),
        // All other actions do not affect MLS membership.
        _ => None,
    };

    Ok(operation)
}

// ---------------------------------------------------------------------------
// EpochCoordinator -- tracks governance-MLS epoch coordination
// ---------------------------------------------------------------------------

/// Tracks the coordination between governance proposal approval and MLS epoch
/// advances.
///
/// When a membership-affecting proposal is approved, the coordinator records
/// the governance epoch at which approval occurred and the MLS epoch that
/// results from executing the MLS operation. This creates an auditable link
/// between governance decisions and MLS state transitions.
///
/// # Concurrency
///
/// The coordinator is intentionally not `Arc<Mutex<_>>` -- it does not hold
/// locks across async boundaries. The [`ContextManager`] serializes governance
/// and MLS operations through its own lock, calling into the coordinator
/// synchronously within that scope. This avoids deadlock between governance
/// and MLS state machines.
#[derive(Debug)]
pub struct EpochCoordinator {
    /// Completed coordination records. Each entry records a governance proposal
    /// that triggered an MLS epoch advance.
    records: Vec<CoordinationRecord>,
}

/// A record of a governance proposal that triggered an MLS epoch advance.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoordinationRecord {
    /// The governance proposal ID that was approved.
    pub proposal_id: [u8; 32],
    /// The MLS epoch before the operation was executed.
    pub epoch_before: u64,
    /// The MLS epoch after the operation was committed.
    pub epoch_after: u64,
    /// The MLS operation that was executed.
    pub operation: MlsOperation,
    /// Unix timestamp (seconds) when the coordination completed.
    pub coordinated_at: u64,
}

impl EpochCoordinator {
    /// Creates a new, empty coordinator.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            records: Vec::new(),
        }
    }

    /// Record a completed governance-MLS coordination.
    ///
    /// Called by the `ContextManager` after successfully executing an MLS
    /// operation triggered by an approved governance proposal.
    ///
    /// # Errors
    ///
    /// Returns [`GovernanceError::InvalidConfig`] if `epoch_after` is not
    /// greater than `epoch_before` (MLS commits always advance the epoch).
    pub fn record_coordination(
        &mut self,
        proposal_id: [u8; 32],
        epoch_before: u64,
        epoch_after: u64,
        operation: MlsOperation,
        timestamp: u64,
    ) -> Result<(), GovernanceError> {
        if epoch_after <= epoch_before {
            return Err(GovernanceError::InvalidConfig(
                "epoch_after must be greater than epoch_before after MLS commit".to_owned(),
            ));
        }

        self.records.push(CoordinationRecord {
            proposal_id,
            epoch_before,
            epoch_after,
            operation,
            coordinated_at: timestamp,
        });

        Ok(())
    }

    /// Returns all coordination records.
    #[must_use]
    pub fn records(&self) -> &[CoordinationRecord] {
        &self.records
    }

    /// Returns the most recent coordination record, if any.
    #[must_use]
    pub fn last_record(&self) -> Option<&CoordinationRecord> {
        self.records.last()
    }

    /// Returns the number of coordination records.
    #[must_use]
    pub const fn record_count(&self) -> usize {
        self.records.len()
    }
}

impl Default for EpochCoordinator {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// ConsistencyCheck -- verify governance and MLS state agreement
// ---------------------------------------------------------------------------

/// Result of a consistency check between governance state and MLS state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConsistencyCheck {
    /// Governance state and MLS state are consistent.
    Consistent,

    /// A member exists in governance state but not in the MLS group.
    MemberMissingFromMls {
        /// The DID present in governance but absent from MLS.
        did: DID,
    },

    /// A member exists in the MLS group but not in governance state.
    MemberMissingFromGovernance {
        /// The DID present in MLS but absent from governance.
        did: DID,
    },

    /// The MLS epoch is behind the expected value based on completed
    /// coordination records.
    EpochMismatch {
        /// The expected MLS epoch.
        expected: u64,
        /// The actual MLS epoch.
        actual: u64,
    },
}

/// Check consistency between governance state and MLS group state.
///
/// Compares the member lists from governance and MLS to detect divergence.
/// Returns a list of inconsistencies found. An empty list means the states
/// are consistent.
///
/// This check is advisory -- the `ContextManager` uses it to detect and log
/// divergence but does not automatically reconcile. Reconciliation requires
/// governance action (re-proposing failed membership changes).
///
/// # Arguments
///
/// * `governance_members` -- DIDs from the governance context's member list.
/// * `mls_members` -- DIDs extracted from the MLS group's leaf nodes.
/// * `expected_epoch` -- The expected MLS epoch (from the latest coordination
///   record or governance context).
/// * `actual_epoch` -- The actual MLS epoch from the group.
#[must_use]
pub fn check_consistency(
    governance_members: &[DID],
    mls_members: &[DID],
    expected_epoch: Option<u64>,
    actual_epoch: Option<u64>,
) -> Vec<ConsistencyCheck> {
    let mut issues = Vec::new();

    // Check for members in governance but not in MLS.
    for did in governance_members {
        if !mls_members.contains(did) {
            issues.push(ConsistencyCheck::MemberMissingFromMls { did: did.clone() });
        }
    }

    // Check for members in MLS but not in governance.
    for did in mls_members {
        if !governance_members.contains(did) {
            issues.push(ConsistencyCheck::MemberMissingFromGovernance { did: did.clone() });
        }
    }

    // Check epoch consistency if both are known.
    if let (Some(expected), Some(actual)) = (expected_epoch, actual_epoch)
        && expected != actual {
            issues.push(ConsistencyCheck::EpochMismatch { expected, actual });
        }

    issues
}

/// Determine whether a governance proposal requires MLS coordination.
///
/// This is a convenience function that combines [`classify_action`] with
/// a status check: only `Approved` proposals with `MembershipChange` impact
/// require MLS coordination.
#[must_use]
pub fn requires_mls_coordination(proposal: &GovernanceProposal) -> bool {
    proposal.status == ProposalStatus::Approved
        && classify_action(&proposal.action) == MlsImpact::MembershipChange
}

/// Invalidate pending proposals after a group state reset (ADR-029 Tier 3).
///
/// When an MLS group undergoes a full state reset, all pending proposals are
/// invalidated because the member's relationship to the group has fundamentally
/// changed. This function filters a list of proposals and returns the IDs of
/// proposals that should be invalidated.
///
/// The caller is responsible for updating the proposal status to
/// `Invalidated { reason }` in the governance engine.
///
/// # Arguments
///
/// * `proposals` -- All proposals to check.
/// * `reset_epoch` -- The MLS epoch at which the reset occurred. Proposals
///   created at or before this epoch are invalidated.
#[must_use]
pub fn proposals_invalidated_by_reset(
    proposals: &[GovernanceProposal],
    reset_epoch: u64,
) -> Vec<[u8; 32]> {
    proposals
        .iter()
        .filter(|p| {
            p.status == ProposalStatus::Pending
                && p.created_at_epoch
                    .is_none_or(|epoch| epoch <= reset_epoch)
        })
        .map(|p| p.proposal_id)
        .collect()
}

/// Validate that the governance context's current epoch is compatible with
/// an approved proposal's creation epoch.
///
/// Pending proposals are NOT invalidated by normal epoch advances (ADR-031
/// section 8). This function confirms that a proposal created at epoch E is
/// still valid at epoch E+N. Returns `true` if valid.
///
/// The only case where this returns `false` is if the group has undergone a
/// full reset (epoch dropped below the proposal's creation epoch), which
/// should not happen under normal operation.
#[must_use]
pub const fn is_proposal_epoch_valid(proposal: &GovernanceProposal, context: &GovernanceContext) -> bool {
    match (proposal.created_at_epoch, context.current_epoch) {
        // Both epochs known: proposal is valid if current >= created.
        (Some(created), Some(current)) => current >= created,
        // If either epoch is unknown, the proposal is considered valid
        // (epoch tracking may not be enabled for broadcast contexts).
        _ => true,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::context::governance::{
        GovernanceAction, GovernanceProposal, ProposalStatus, SignedVote, VoteType,
    };
    use crate::context::params::{Capability, ContextParams, ToolRegistration};
    use crate::identity::DID;

    fn alice() -> DID {
        DID::from("did:dht:z6MkAlice")
    }

    fn bob() -> DID {
        DID::from("did:dht:z6MkBob")
    }

    fn carol() -> DID {
        DID::from("did:dht:z6MkCarol")
    }

    /// Create a test governance context with standard members.
    fn test_governance_context() -> GovernanceContext {
        GovernanceContext {
            context_id: "ctx-mls-test".to_owned(),
            members: vec![
                (alice(), "admin".to_owned()),
                (bob(), "member".to_owned()),
                (carol(), "member".to_owned()),
            ],
            admin_dids: vec![alice()],
            current_epoch: Some(5),
            now: 1_700_000_000,
        }
    }

    /// Create a test approved proposal for the given action.
    fn approved_proposal(action: GovernanceAction, epoch: Option<u64>) -> GovernanceProposal {
        GovernanceProposal {
            proposal_id: [1u8; 32],
            context_id: "ctx-mls-test".to_owned(),
            proposer_did: alice(),
            action,
            status: ProposalStatus::Approved,
            created_at: 1_700_000_000,
            voting_deadline: 1_700_086_400,
            approvals: vec![SignedVote {
                voter_did: alice(),
                vote: VoteType::Approve,
                timestamp: 1_700_000_000,
                signature: Vec::new(),
            }],
            rejections: Vec::new(),
            created_at_epoch: epoch,
        }
    }

    /// Create a test pending proposal for the given action.
    fn pending_proposal(action: GovernanceAction, epoch: Option<u64>) -> GovernanceProposal {
        GovernanceProposal {
            proposal_id: [2u8; 32],
            context_id: "ctx-mls-test".to_owned(),
            proposer_did: alice(),
            action,
            status: ProposalStatus::Pending,
            created_at: 1_700_000_000,
            voting_deadline: 1_700_086_400,
            approvals: Vec::new(),
            rejections: Vec::new(),
            created_at_epoch: epoch,
        }
    }

    // -----------------------------------------------------------------------
    // classify_action tests
    // -----------------------------------------------------------------------

    #[test]
    fn classify_add_member_is_membership_change() {
        let action = GovernanceAction::AddMember {
            did: bob(),
            role: "member".to_owned(),
        };
        assert_eq!(classify_action(&action), MlsImpact::MembershipChange);
    }

    #[test]
    fn classify_remove_member_is_membership_change() {
        let action = GovernanceAction::RemoveMember {
            did: bob(),
            reason: Some("inactive".to_owned()),
        };
        assert_eq!(classify_action(&action), MlsImpact::MembershipChange);
    }

    #[test]
    fn classify_change_role_is_no_mls_change() {
        let action = GovernanceAction::ChangeRole {
            did: bob(),
            new_role: "observer".to_owned(),
        };
        assert_eq!(classify_action(&action), MlsImpact::NoMlsChange);
    }

    #[test]
    fn classify_register_tool_is_no_mls_change() {
        let action = GovernanceAction::RegisterTool {
            registration: ToolRegistration {
                name: "search".to_owned(),
            },
        };
        assert_eq!(classify_action(&action), MlsImpact::NoMlsChange);
    }

    #[test]
    fn classify_remove_tool_is_no_mls_change() {
        let action = GovernanceAction::RemoveTool {
            tool_id: "search".to_owned(),
        };
        assert_eq!(classify_action(&action), MlsImpact::NoMlsChange);
    }

    #[test]
    fn classify_modify_ceiling_is_no_mls_change() {
        let action = GovernanceAction::ModifyCeiling {
            new_ceiling: vec![Capability::MessagesRead],
        };
        assert_eq!(classify_action(&action), MlsImpact::NoMlsChange);
    }

    #[test]
    fn classify_close_context_is_no_mls_change() {
        let action = GovernanceAction::CloseContext {
            reason: Some("done".to_owned()),
        };
        assert_eq!(classify_action(&action), MlsImpact::NoMlsChange);
    }

    #[test]
    fn classify_extend_ttl_is_no_mls_change() {
        let action = GovernanceAction::ExtendTtl {
            additional_secs: 3600,
        };
        assert_eq!(classify_action(&action), MlsImpact::NoMlsChange);
    }

    #[test]
    fn classify_transfer_admin_is_no_mls_change() {
        let action = GovernanceAction::TransferAdmin { new_admin: bob() };
        assert_eq!(classify_action(&action), MlsImpact::NoMlsChange);
    }

    #[test]
    fn classify_create_child_context_is_no_mls_change() {
        let action = GovernanceAction::CreateChildContext {
            params: Box::new(ContextParams::default()),
        };
        assert_eq!(classify_action(&action), MlsImpact::NoMlsChange);
    }

    // -----------------------------------------------------------------------
    // generate_mls_operations tests
    // -----------------------------------------------------------------------

    #[test]
    fn generate_mls_ops_for_add_member() {
        let action = GovernanceAction::AddMember {
            did: bob(),
            role: "member".to_owned(),
        };
        let proposal = approved_proposal(action, Some(5));

        let result = generate_mls_operations(&proposal).expect("generate");
        assert_eq!(
            result,
            Some(MlsOperation::AddMember {
                did: bob(),
                role: "member".to_owned(),
            })
        );
    }

    #[test]
    fn generate_mls_ops_for_remove_member() {
        let action = GovernanceAction::RemoveMember {
            did: bob(),
            reason: Some("inactive".to_owned()),
        };
        let proposal = approved_proposal(action, Some(5));

        let result = generate_mls_operations(&proposal).expect("generate");
        assert_eq!(
            result,
            Some(MlsOperation::RemoveMember {
                did: bob(),
                reason: Some("inactive".to_owned()),
            })
        );
    }

    #[test]
    fn generate_mls_ops_for_non_membership_returns_none() {
        let action = GovernanceAction::ChangeRole {
            did: bob(),
            new_role: "observer".to_owned(),
        };
        let proposal = approved_proposal(action, Some(5));

        let result = generate_mls_operations(&proposal).expect("generate");
        assert!(result.is_none());
    }

    #[test]
    fn generate_mls_ops_for_settings_change_returns_none() {
        let action = GovernanceAction::ExtendTtl {
            additional_secs: 3600,
        };
        let proposal = approved_proposal(action, Some(5));

        let result = generate_mls_operations(&proposal).expect("generate");
        assert!(result.is_none());
    }

    #[test]
    fn generate_mls_ops_rejects_pending_proposal() {
        let action = GovernanceAction::AddMember {
            did: bob(),
            role: "member".to_owned(),
        };
        let proposal = pending_proposal(action, Some(5));

        let result = generate_mls_operations(&proposal);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            GovernanceError::ProposalNotPending { .. }
        ));
    }

    #[test]
    fn generate_mls_ops_rejects_expired_proposal() {
        let action = GovernanceAction::AddMember {
            did: bob(),
            role: "member".to_owned(),
        };
        let mut proposal = pending_proposal(action, Some(5));
        proposal.status = ProposalStatus::Expired;

        let result = generate_mls_operations(&proposal);
        assert!(result.is_err());
    }

    // -----------------------------------------------------------------------
    // EpochCoordinator tests
    // -----------------------------------------------------------------------

    #[test]
    fn epoch_coordinator_records_coordination() {
        let mut coordinator = EpochCoordinator::new();

        let result = coordinator.record_coordination(
            [1u8; 32],
            5,
            6,
            MlsOperation::AddMember {
                did: bob(),
                role: "member".to_owned(),
            },
            1_700_000_100,
        );

        assert!(result.is_ok());
        assert_eq!(coordinator.record_count(), 1);

        let record = coordinator.last_record().expect("should have record");
        assert_eq!(record.proposal_id, [1u8; 32]);
        assert_eq!(record.epoch_before, 5);
        assert_eq!(record.epoch_after, 6);
        assert_eq!(record.coordinated_at, 1_700_000_100);
    }

    #[test]
    fn epoch_coordinator_rejects_non_advancing_epoch() {
        let mut coordinator = EpochCoordinator::new();

        // epoch_after == epoch_before should fail.
        let result = coordinator.record_coordination(
            [1u8; 32],
            5,
            5,
            MlsOperation::AddMember {
                did: bob(),
                role: "member".to_owned(),
            },
            1_700_000_100,
        );

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            GovernanceError::InvalidConfig(_)
        ));
    }

    #[test]
    fn epoch_coordinator_rejects_decreasing_epoch() {
        let mut coordinator = EpochCoordinator::new();

        // epoch_after < epoch_before should fail.
        let result = coordinator.record_coordination(
            [1u8; 32],
            5,
            3,
            MlsOperation::RemoveMember {
                did: bob(),
                reason: None,
            },
            1_700_000_100,
        );

        assert!(result.is_err());
    }

    #[test]
    fn epoch_coordinator_tracks_multiple_records() {
        let mut coordinator = EpochCoordinator::new();

        coordinator
            .record_coordination(
                [1u8; 32],
                5,
                6,
                MlsOperation::AddMember {
                    did: bob(),
                    role: "member".to_owned(),
                },
                1_700_000_100,
            )
            .expect("first");

        coordinator
            .record_coordination(
                [2u8; 32],
                6,
                7,
                MlsOperation::RemoveMember {
                    did: carol(),
                    reason: Some("left".to_owned()),
                },
                1_700_000_200,
            )
            .expect("second");

        assert_eq!(coordinator.record_count(), 2);
        assert_eq!(coordinator.records().len(), 2);

        let last = coordinator.last_record().expect("should have record");
        assert_eq!(last.proposal_id, [2u8; 32]);
        assert_eq!(last.epoch_after, 7);
    }

    #[test]
    fn epoch_coordinator_empty_has_no_records() {
        let coordinator = EpochCoordinator::new();
        assert_eq!(coordinator.record_count(), 0);
        assert!(coordinator.last_record().is_none());
        assert!(coordinator.records().is_empty());
    }

    #[test]
    fn epoch_coordinator_default_is_empty() {
        let coordinator = EpochCoordinator::default();
        assert_eq!(coordinator.record_count(), 0);
    }

    // -----------------------------------------------------------------------
    // check_consistency tests
    // -----------------------------------------------------------------------

    #[test]
    fn consistency_check_all_consistent() {
        let gov_members = vec![alice(), bob(), carol()];
        let mls_members = vec![alice(), bob(), carol()];

        let issues = check_consistency(&gov_members, &mls_members, Some(5), Some(5));
        assert!(issues.is_empty());
    }

    #[test]
    fn consistency_check_member_missing_from_mls() {
        let gov_members = vec![alice(), bob(), carol()];
        let mls_members = vec![alice(), bob()]; // carol missing from MLS

        let issues = check_consistency(&gov_members, &mls_members, Some(5), Some(5));
        assert_eq!(issues.len(), 1);
        assert_eq!(
            issues[0],
            ConsistencyCheck::MemberMissingFromMls { did: carol() }
        );
    }

    #[test]
    fn consistency_check_member_missing_from_governance() {
        let gov_members = vec![alice(), bob()];
        let mls_members = vec![alice(), bob(), carol()]; // carol in MLS but not governance

        let issues = check_consistency(&gov_members, &mls_members, Some(5), Some(5));
        assert_eq!(issues.len(), 1);
        assert_eq!(
            issues[0],
            ConsistencyCheck::MemberMissingFromGovernance { did: carol() }
        );
    }

    #[test]
    fn consistency_check_epoch_mismatch() {
        let gov_members = vec![alice(), bob()];
        let mls_members = vec![alice(), bob()];

        let issues = check_consistency(&gov_members, &mls_members, Some(5), Some(7));
        assert_eq!(issues.len(), 1);
        assert_eq!(
            issues[0],
            ConsistencyCheck::EpochMismatch {
                expected: 5,
                actual: 7
            }
        );
    }

    #[test]
    fn consistency_check_multiple_issues() {
        let gov_members = vec![alice(), bob()];
        let mls_members = vec![alice(), carol()]; // bob missing from MLS, carol missing from gov

        let issues = check_consistency(&gov_members, &mls_members, Some(5), Some(8));
        assert_eq!(issues.len(), 3); // bob missing from MLS, carol missing from gov, epoch mismatch
    }

    #[test]
    fn consistency_check_no_epoch_tracking() {
        let gov_members = vec![alice()];
        let mls_members = vec![alice()];

        // No epoch info available -- should not report epoch issues.
        let issues = check_consistency(&gov_members, &mls_members, None, None);
        assert!(issues.is_empty());
    }

    #[test]
    fn consistency_check_partial_epoch_info() {
        let gov_members = vec![alice()];
        let mls_members = vec![alice()];

        // Only one side has epoch info -- should not report epoch issues.
        let issues_a = check_consistency(&gov_members, &mls_members, Some(5), None);
        assert!(issues_a.is_empty());

        let issues_b = check_consistency(&gov_members, &mls_members, None, Some(5));
        assert!(issues_b.is_empty());
    }

    // -----------------------------------------------------------------------
    // requires_mls_coordination tests
    // -----------------------------------------------------------------------

    #[test]
    fn approved_add_member_requires_mls_coordination() {
        let action = GovernanceAction::AddMember {
            did: bob(),
            role: "member".to_owned(),
        };
        let proposal = approved_proposal(action, Some(5));
        assert!(requires_mls_coordination(&proposal));
    }

    #[test]
    fn approved_remove_member_requires_mls_coordination() {
        let action = GovernanceAction::RemoveMember {
            did: bob(),
            reason: None,
        };
        let proposal = approved_proposal(action, Some(5));
        assert!(requires_mls_coordination(&proposal));
    }

    #[test]
    fn approved_change_role_does_not_require_mls_coordination() {
        let action = GovernanceAction::ChangeRole {
            did: bob(),
            new_role: "observer".to_owned(),
        };
        let proposal = approved_proposal(action, Some(5));
        assert!(!requires_mls_coordination(&proposal));
    }

    #[test]
    fn pending_add_member_does_not_require_mls_coordination() {
        let action = GovernanceAction::AddMember {
            did: bob(),
            role: "member".to_owned(),
        };
        let proposal = pending_proposal(action, Some(5));
        assert!(!requires_mls_coordination(&proposal));
    }

    #[test]
    fn approved_close_context_does_not_require_mls_coordination() {
        let action = GovernanceAction::CloseContext {
            reason: Some("done".to_owned()),
        };
        let proposal = approved_proposal(action, Some(5));
        assert!(!requires_mls_coordination(&proposal));
    }

    #[test]
    fn approved_extend_ttl_does_not_require_mls_coordination() {
        let action = GovernanceAction::ExtendTtl {
            additional_secs: 7200,
        };
        let proposal = approved_proposal(action, Some(5));
        assert!(!requires_mls_coordination(&proposal));
    }

    // -----------------------------------------------------------------------
    // proposals_invalidated_by_reset tests
    // -----------------------------------------------------------------------

    #[test]
    fn reset_invalidates_pending_proposals_at_or_before_epoch() {
        let proposals = vec![
            pending_proposal(
                GovernanceAction::AddMember {
                    did: bob(),
                    role: "member".to_owned(),
                },
                Some(3),
            ),
            pending_proposal(
                GovernanceAction::ChangeRole {
                    did: carol(),
                    new_role: "admin".to_owned(),
                },
                Some(5),
            ),
        ];

        let invalidated = proposals_invalidated_by_reset(&proposals, 5);
        assert_eq!(invalidated.len(), 2);
    }

    #[test]
    fn reset_does_not_invalidate_proposals_after_epoch() {
        let proposals = vec![pending_proposal(
            GovernanceAction::AddMember {
                did: bob(),
                role: "member".to_owned(),
            },
            Some(10),
        )];

        let invalidated = proposals_invalidated_by_reset(&proposals, 5);
        assert!(invalidated.is_empty());
    }

    #[test]
    fn reset_does_not_invalidate_approved_proposals() {
        let proposals = vec![approved_proposal(
            GovernanceAction::RemoveMember {
                did: bob(),
                reason: None,
            },
            Some(3),
        )];

        let invalidated = proposals_invalidated_by_reset(&proposals, 5);
        assert!(invalidated.is_empty());
    }

    #[test]
    fn reset_invalidates_pending_proposals_without_epoch() {
        let proposals = vec![pending_proposal(
            GovernanceAction::AddMember {
                did: bob(),
                role: "member".to_owned(),
            },
            None, // No epoch info -- conservatively invalidated.
        )];

        let invalidated = proposals_invalidated_by_reset(&proposals, 5);
        assert_eq!(invalidated.len(), 1);
    }

    #[test]
    fn reset_with_empty_proposals_returns_empty() {
        let invalidated = proposals_invalidated_by_reset(&[], 5);
        assert!(invalidated.is_empty());
    }

    // -----------------------------------------------------------------------
    // is_proposal_epoch_valid tests
    // -----------------------------------------------------------------------

    #[test]
    fn proposal_valid_at_same_epoch() {
        let proposal = pending_proposal(GovernanceAction::CloseContext { reason: None }, Some(5));
        let ctx = test_governance_context();
        assert!(is_proposal_epoch_valid(&proposal, &ctx));
    }

    #[test]
    fn proposal_valid_at_later_epoch() {
        let proposal = pending_proposal(GovernanceAction::CloseContext { reason: None }, Some(3));
        let ctx = test_governance_context(); // epoch 5
        assert!(is_proposal_epoch_valid(&proposal, &ctx));
    }

    #[test]
    fn proposal_invalid_at_earlier_epoch() {
        let proposal = pending_proposal(
            GovernanceAction::CloseContext { reason: None },
            Some(10), // Created at epoch 10.
        );
        let ctx = test_governance_context(); // Current epoch 5.
        assert!(!is_proposal_epoch_valid(&proposal, &ctx));
    }

    #[test]
    fn proposal_valid_when_no_epoch_info() {
        let proposal = pending_proposal(GovernanceAction::CloseContext { reason: None }, None);
        let mut ctx = test_governance_context();
        ctx.current_epoch = None;
        assert!(is_proposal_epoch_valid(&proposal, &ctx));
    }

    #[test]
    fn proposal_valid_when_proposal_has_no_epoch() {
        let proposal = pending_proposal(GovernanceAction::CloseContext { reason: None }, None);
        let ctx = test_governance_context();
        assert!(is_proposal_epoch_valid(&proposal, &ctx));
    }

    #[test]
    fn proposal_valid_when_context_has_no_epoch() {
        let proposal = pending_proposal(GovernanceAction::CloseContext { reason: None }, Some(5));
        let mut ctx = test_governance_context();
        ctx.current_epoch = None;
        assert!(is_proposal_epoch_valid(&proposal, &ctx));
    }

    // -----------------------------------------------------------------------
    // MlsOperation serialization
    // -----------------------------------------------------------------------

    #[test]
    fn mls_operation_serialization_roundtrip() {
        let operations = vec![
            MlsOperation::AddMember {
                did: bob(),
                role: "member".to_owned(),
            },
            MlsOperation::RemoveMember {
                did: carol(),
                reason: Some("left voluntarily".to_owned()),
            },
            MlsOperation::RemoveMember {
                did: bob(),
                reason: None,
            },
        ];

        for op in &operations {
            let json = serde_json::to_string(op).expect("serialize");
            let deserialized: MlsOperation = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(&deserialized, op);
        }
    }

    // -----------------------------------------------------------------------
    // CoordinationRecord serialization
    // -----------------------------------------------------------------------

    #[test]
    fn coordination_record_serialization_roundtrip() {
        let record = CoordinationRecord {
            proposal_id: [0xab; 32],
            epoch_before: 5,
            epoch_after: 6,
            operation: MlsOperation::AddMember {
                did: bob(),
                role: "member".to_owned(),
            },
            coordinated_at: 1_700_000_100,
        };

        let json = serde_json::to_string(&record).expect("serialize");
        let deserialized: CoordinationRecord = serde_json::from_str(&json).expect("deserialize");

        assert_eq!(deserialized.proposal_id, record.proposal_id);
        assert_eq!(deserialized.epoch_before, record.epoch_before);
        assert_eq!(deserialized.epoch_after, record.epoch_after);
        assert_eq!(deserialized.operation, record.operation);
        assert_eq!(deserialized.coordinated_at, record.coordinated_at);
    }

    // -----------------------------------------------------------------------
    // MlsImpact serialization
    // -----------------------------------------------------------------------

    #[test]
    fn mls_impact_serialization_roundtrip() {
        for impact in &[MlsImpact::MembershipChange, MlsImpact::NoMlsChange] {
            let json = serde_json::to_string(impact).expect("serialize");
            let deserialized: MlsImpact = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(&deserialized, impact);
        }
    }

    // -----------------------------------------------------------------------
    // Concurrency safety compile-time checks
    // -----------------------------------------------------------------------

    #[test]
    fn epoch_coordinator_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<EpochCoordinator>();
    }

    #[test]
    fn coordination_record_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<CoordinationRecord>();
    }

    // -----------------------------------------------------------------------
    // Integration: full governance-MLS coordination flow
    // -----------------------------------------------------------------------

    #[test]
    fn full_coordination_flow_add_member() {
        // Simulate the complete flow: governance approval -> MLS operation
        // generation -> epoch coordination recording -> consistency check.

        // Step 1: Governance proposal is approved.
        let action = GovernanceAction::AddMember {
            did: DID::from("did:dht:z6MkDave"),
            role: "member".to_owned(),
        };
        let proposal = approved_proposal(action, Some(5));

        // Step 2: Check if MLS coordination is required.
        assert!(requires_mls_coordination(&proposal));

        // Step 3: Generate MLS operations.
        let mls_op = generate_mls_operations(&proposal)
            .expect("generate")
            .expect("should have operation");

        assert_eq!(
            mls_op,
            MlsOperation::AddMember {
                did: DID::from("did:dht:z6MkDave"),
                role: "member".to_owned(),
            }
        );

        // Step 4: (ContextManager would execute MLS operation here.)
        // Simulate: epoch advances from 5 to 6.

        // Step 5: Record the coordination.
        let mut coordinator = EpochCoordinator::new();
        coordinator
            .record_coordination(proposal.proposal_id, 5, 6, mls_op, 1_700_000_100)
            .expect("record");

        // Step 6: Verify consistency after the operation.
        let gov_members = vec![alice(), bob(), carol(), DID::from("did:dht:z6MkDave")];
        let mls_members = vec![alice(), bob(), carol(), DID::from("did:dht:z6MkDave")];

        let issues = check_consistency(&gov_members, &mls_members, Some(6), Some(6));
        assert!(
            issues.is_empty(),
            "state should be consistent after coordination"
        );
    }

    #[test]
    fn full_coordination_flow_remove_member() {
        // Simulate remove member flow.

        let action = GovernanceAction::RemoveMember {
            did: bob(),
            reason: Some("violation".to_owned()),
        };
        let proposal = approved_proposal(action, Some(5));

        assert!(requires_mls_coordination(&proposal));

        let mls_op = generate_mls_operations(&proposal)
            .expect("generate")
            .expect("should have operation");

        assert_eq!(
            mls_op,
            MlsOperation::RemoveMember {
                did: bob(),
                reason: Some("violation".to_owned()),
            }
        );

        // Simulate epoch advance.
        let mut coordinator = EpochCoordinator::new();
        coordinator
            .record_coordination(proposal.proposal_id, 5, 6, mls_op, 1_700_000_200)
            .expect("record");

        // After removal, bob should not be in either list.
        let gov_members = vec![alice(), carol()];
        let mls_members = vec![alice(), carol()];

        let issues = check_consistency(&gov_members, &mls_members, Some(6), Some(6));
        assert!(issues.is_empty());
    }

    #[test]
    fn full_flow_non_membership_skips_mls() {
        // Non-membership changes should bypass MLS entirely.

        let action = GovernanceAction::ChangeRole {
            did: bob(),
            new_role: "observer".to_owned(),
        };
        let proposal = approved_proposal(action, Some(5));

        // Should not require MLS coordination.
        assert!(!requires_mls_coordination(&proposal));

        // Should generate no MLS operations.
        let mls_op = generate_mls_operations(&proposal).expect("generate");
        assert!(mls_op.is_none());

        // MLS state unchanged -- epoch stays the same.
        let gov_members = vec![alice(), bob(), carol()];
        let mls_members = vec![alice(), bob(), carol()];
        let issues = check_consistency(&gov_members, &mls_members, Some(5), Some(5));
        assert!(issues.is_empty());
    }

    // -----------------------------------------------------------------------
    // Concurrent governance and MLS operations
    // -----------------------------------------------------------------------

    #[test]
    fn concurrent_proposals_do_not_deadlock() {
        // Verify that processing multiple proposals sequentially through the
        // coordinator does not cause issues. The EpochCoordinator is not
        // behind a lock -- the ContextManager serializes access.

        let mut coordinator = EpochCoordinator::new();

        // Two membership changes processed sequentially.
        coordinator
            .record_coordination(
                [1u8; 32],
                5,
                6,
                MlsOperation::AddMember {
                    did: DID::from("did:dht:z6MkDave"),
                    role: "member".to_owned(),
                },
                1_700_000_100,
            )
            .expect("first coordination");

        coordinator
            .record_coordination(
                [2u8; 32],
                6,
                7,
                MlsOperation::RemoveMember {
                    did: bob(),
                    reason: None,
                },
                1_700_000_200,
            )
            .expect("second coordination");

        assert_eq!(coordinator.record_count(), 2);

        // Verify monotonic epoch progression.
        let records = coordinator.records();
        assert!(records[1].epoch_before >= records[0].epoch_after);
    }

    #[test]
    fn non_membership_and_membership_proposals_coexist() {
        // Verify that a non-membership proposal followed by a membership
        // proposal works correctly.

        let role_change = GovernanceAction::ChangeRole {
            did: bob(),
            new_role: "observer".to_owned(),
        };
        let role_proposal = approved_proposal(role_change, Some(5));

        let add_member = GovernanceAction::AddMember {
            did: DID::from("did:dht:z6MkDave"),
            role: "member".to_owned(),
        };
        let mut add_proposal = approved_proposal(add_member, Some(5));
        add_proposal.proposal_id = [3u8; 32]; // Distinct ID.

        // Role change does not need MLS coordination.
        assert!(!requires_mls_coordination(&role_proposal));
        assert!(
            generate_mls_operations(&role_proposal)
                .expect("generate")
                .is_none()
        );

        // Add member does need MLS coordination.
        assert!(requires_mls_coordination(&add_proposal));
        assert!(
            generate_mls_operations(&add_proposal)
                .expect("generate")
                .is_some()
        );

        // Only the membership change is recorded in the coordinator.
        let mut coordinator = EpochCoordinator::new();
        let mls_op = generate_mls_operations(&add_proposal)
            .expect("generate")
            .expect("op");
        coordinator
            .record_coordination(add_proposal.proposal_id, 5, 6, mls_op, 1_700_000_300)
            .expect("record");

        assert_eq!(coordinator.record_count(), 1);
    }
}
