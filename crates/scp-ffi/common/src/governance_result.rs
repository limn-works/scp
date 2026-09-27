//! One name per governance outcome, shared by every FFI bridge.
//!
//! `PyO3`, napi-rs, and `UniFFI` each hand a caller a string naming what a
//! governance execution did. Each bridge used to build that string itself, and
//! they diverged: two wrote an exhaustive match over
//! [`GovernanceActionResult`], while napi-rs wrote `format!("{result:?}")`,
//! whose payload-carrying variants render as a Rust debug dump
//! (`MigrationProposed(MigrationProposedResult { .. })`) that no SDK enum
//! matches. Every bridge now calls [`governance_action_result_name`], so one
//! outcome carries one name on every bridge.
//!
//! [`governance_action_result_name`] matches every variant with no wildcard
//! arm, so adding a variant to [`GovernanceActionResult`] stops this crate from
//! compiling until someone names it. A wildcard arm here would instead ship a
//! new outcome under an old name.
//!
//! `governance_propose` returns that same enum in a JSON field, and all three
//! bridges rendered that field with `format!("{r:?}")` after `governance_execute`
//! stopped doing so. [`governance_propose_response`] builds that whole JSON
//! body, so both entry points hand a caller one name for one outcome.

use scp_core::context::ContextState;
use scp_core::context::governance::{ProposalId, ProposalStatus};
use scp_core::context::state::GovernanceActionResult;

/// Returns whichever name a caller reads for `result`.
///
/// Each name matches its Rust variant name exactly, which is what Python,
/// Swift, and TypeScript SDK enums store as their values.
#[must_use]
pub const fn governance_action_result_name(result: &GovernanceActionResult) -> &'static str {
    match result {
        GovernanceActionResult::MemberAdded { .. } => "MemberAdded",
        GovernanceActionResult::MemberRemoved => "MemberRemoved",
        GovernanceActionResult::RoleChanged => "RoleChanged",
        GovernanceActionResult::OutletRegistered => "OutletRegistered",
        GovernanceActionResult::OutletRemoved => "OutletRemoved",
        GovernanceActionResult::CeilingModified => "CeilingModified",
        GovernanceActionResult::ContextClosed => "ContextClosed",
        GovernanceActionResult::TtlExtended => "TtlExtended",
        GovernanceActionResult::PruningPolicyModified => "PruningPolicyModified",
        GovernanceActionResult::AdminTransferred => "AdminTransferred",
        GovernanceActionResult::SignerAdded => "SignerAdded",
        GovernanceActionResult::SignerRemoved => "SignerRemoved",
        GovernanceActionResult::ThresholdModified => "ThresholdModified",
        GovernanceActionResult::ChildContextCreated => "ChildContextCreated",
        GovernanceActionResult::OutletInterfaceEstablished => "OutletInterfaceEstablished",
        GovernanceActionResult::MemberReset => "MemberReset",
        GovernanceActionResult::ConflictResolved => "ConflictResolved",
        GovernanceActionResult::ContextPromoted => "ContextPromoted",
        GovernanceActionResult::MemberSuspended(_) => "MemberSuspended",
        GovernanceActionResult::AccessRevoked(_) => "AccessRevoked",
        GovernanceActionResult::AccessRestored(_) => "AccessRestored",
        GovernanceActionResult::ContentKeysRotated(_) => "ContentKeysRotated",
        GovernanceActionResult::GovernanceReconfigured(_) => "GovernanceReconfigured",
        GovernanceActionResult::SubscriberBanned(_) => "SubscriberBanned",
        GovernanceActionResult::SubscriberUnbanned { .. } => "SubscriberUnbanned",
        GovernanceActionResult::Executed => "Executed",
        GovernanceActionResult::MigrationProposed(_) => "MigrationProposed",
        GovernanceActionResult::MigrationCancelled => "MigrationCancelled",
        GovernanceActionResult::ContextTombstoned => "ContextTombstoned",
    }
}

/// Returns the lifecycle state a bridge's context handle moves to after a
/// governance action produced `result`, or `None` when the action leaves that
/// state alone (spec §5.11A).
///
/// `governance_execute` and an auto-executing `governance_propose` both run
/// the action, so every bridge applies this answer on both paths. Each bridge
/// used to write this match only in `governance_execute`, so a `single_admin`
/// proposal that executed a migration reported `MigrationProposed` while the
/// handle still read `Active`.
///
/// Every variant is named with no wildcard arm, so a new outcome stops this
/// crate from compiling until someone decides whether it moves the handle.
#[must_use]
pub const fn handle_state_after(result: &GovernanceActionResult) -> Option<ContextState> {
    match result {
        GovernanceActionResult::MigrationProposed(_) => Some(ContextState::MigratingOut),
        GovernanceActionResult::MigrationCancelled => Some(ContextState::Active),
        GovernanceActionResult::ContextTombstoned => Some(ContextState::Tombstoned),
        GovernanceActionResult::MemberAdded { .. }
        | GovernanceActionResult::MemberRemoved
        | GovernanceActionResult::RoleChanged
        | GovernanceActionResult::OutletRegistered
        | GovernanceActionResult::OutletRemoved
        | GovernanceActionResult::CeilingModified
        | GovernanceActionResult::ContextClosed
        | GovernanceActionResult::TtlExtended
        | GovernanceActionResult::PruningPolicyModified
        | GovernanceActionResult::AdminTransferred
        | GovernanceActionResult::SignerAdded
        | GovernanceActionResult::SignerRemoved
        | GovernanceActionResult::ThresholdModified
        | GovernanceActionResult::ChildContextCreated
        | GovernanceActionResult::OutletInterfaceEstablished
        | GovernanceActionResult::MemberReset
        | GovernanceActionResult::ConflictResolved
        | GovernanceActionResult::ContextPromoted
        | GovernanceActionResult::MemberSuspended(_)
        | GovernanceActionResult::AccessRevoked(_)
        | GovernanceActionResult::AccessRestored(_)
        | GovernanceActionResult::ContentKeysRotated(_)
        | GovernanceActionResult::GovernanceReconfigured(_)
        | GovernanceActionResult::SubscriberBanned(_)
        | GovernanceActionResult::SubscriberUnbanned { .. }
        | GovernanceActionResult::Executed => None,
    }
}

/// Builds the JSON body every bridge answers `governance_propose` with.
///
/// `PyO3`, napi-rs, and `UniFFI` each answer `governance_propose` with
/// `{proposal_id, status, execution_result}`, and each used to build that
/// object itself. All three rendered `execution_result` as
/// `format!("{r:?}")`, so a payload-carrying variant reached a caller as a
/// Rust debug dump — `MemberAdded { welcome_bytes: [..], commit_bytes: [..] }`
/// — that no SDK enum names. A `single_admin` context auto-approves and
/// auto-executes a proposal, which makes `execution_result` the field that
/// caller reads, so the debug dump was what an `AddMember` proposal returned.
/// Routing all three bridges through this one function gives
/// `execution_result` the same name [`governance_action_result_name`] gives
/// `governance_execute`.
///
/// `status` keeps its `Debug` rendering. `ProposalStatus::Rejected` and
/// `ProposalStatus::Invalidated` each carry the reason a proposal did not
/// pass, no SDK declares an enum over those names, and dropping the payload
/// would delete the reason. Every bridge rendered `status` identically before
/// this function existed, so moving that rendering here changes no answer.
///
/// # Arguments
///
/// * `proposal_id` -- Identifier of the proposal the engine created.
/// * `status` -- Lifecycle status the proposal holds after creation.
/// * `execution_result` -- What the action did, `Some` when a single-admin
///   proposal auto-executed and `None` while a multi-admin proposal awaits
///   votes.
#[must_use]
pub fn governance_propose_response(
    proposal_id: &ProposalId,
    status: &ProposalStatus,
    execution_result: Option<&GovernanceActionResult>,
) -> String {
    serde_json::json!({
        "proposal_id": hex::encode(proposal_id),
        "status": format!("{status:?}"),
        "execution_result": execution_result.map(governance_action_result_name),
    })
    .to_string()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use scp_core::context::governance::RejectionReason;
    use scp_core::context::membership::RedactedBytes;

    use super::*;

    /// Each name a bridge hands a caller is exactly its Rust variant name, so
    /// an SDK enum whose values mirror those variant names parses every one.
    #[test]
    fn payload_carrying_variants_report_a_bare_variant_name() {
        assert_eq!(
            governance_action_result_name(&GovernanceActionResult::MigrationCancelled),
            "MigrationCancelled"
        );
        assert_eq!(
            governance_action_result_name(&GovernanceActionResult::ContextTombstoned),
            "ContextTombstoned"
        );
        assert_eq!(
            governance_action_result_name(&GovernanceActionResult::Executed),
            "Executed"
        );
    }

    /// A `single_admin` context auto-approves and auto-executes an
    /// `AddMember` proposal, so `governance_propose` is where a caller reads
    /// `MemberAdded`. Every bridge rendered that variant with
    /// `format!("{r:?}")` until [`governance_propose_response`] existed, which
    /// handed a caller `MemberAdded { welcome_bytes: [3 bytes, REDACTED],
    /// commit_bytes: [2 bytes, REDACTED] }` — a string Python's
    /// `GovernanceActionResult`, Swift's enum, and TypeScript's
    /// `GOVERNANCE_ACTION_RESULTS` all reject.
    #[test]
    fn propose_response_names_a_payload_carrying_outcome() {
        let response = governance_propose_response(
            &[0xAB; 32],
            &ProposalStatus::Approved,
            Some(&GovernanceActionResult::MemberAdded {
                welcome_bytes: RedactedBytes(vec![1, 2, 3]),
                commit_bytes: RedactedBytes(vec![4, 5]),
            }),
        );
        let parsed: serde_json::Value =
            serde_json::from_str(&response).expect("the response must be JSON");
        assert_eq!(
            parsed["execution_result"].as_str(),
            Some("MemberAdded"),
            "a propose response must name its outcome; got {response}"
        );
        assert_eq!(parsed["status"].as_str(), Some("Approved"));
        assert_eq!(
            parsed["proposal_id"].as_str(),
            Some("ab".repeat(32).as_str())
        );
    }

    /// A multi-admin proposal awaits votes, so a caller reads a JSON `null`
    /// rather than a name. An SDK reads that difference to decide whether a
    /// governance action already ran.
    #[test]
    fn propose_response_reports_a_pending_proposal_as_null() {
        let response = governance_propose_response(&[0; 32], &ProposalStatus::Pending, None);
        let parsed: serde_json::Value =
            serde_json::from_str(&response).expect("the response must be JSON");
        assert!(
            parsed["execution_result"].is_null(),
            "a pending proposal executed nothing; got {response}"
        );
        assert_eq!(parsed["status"].as_str(), Some("Pending"));
    }

    /// `ProposalStatus::Rejected` and `ProposalStatus::Invalidated` each carry
    /// the reason a proposal did not pass, and no SDK declares an enum over
    /// status names, so `status` keeps the `Debug` rendering every bridge
    /// already produced. This holds that rendering fixed, because dropping the
    /// payload would delete the reason a caller reads.
    #[test]
    fn propose_response_keeps_the_reason_a_rejection_carries() {
        let response = governance_propose_response(
            &[0; 32],
            &ProposalStatus::Rejected {
                reason: RejectionReason::ApprovalImpossible,
            },
            None,
        );
        let parsed: serde_json::Value =
            serde_json::from_str(&response).expect("the response must be JSON");
        assert_eq!(
            parsed["status"].as_str(),
            Some("Rejected { reason: ApprovalImpossible }"),
            "a rejected proposal must still report why; got {response}"
        );
    }

    /// A name never carries debug punctuation. `format!("{result:?}")` — what
    /// one bridge did before this module existed — renders
    /// `MemberAdded { welcome_bytes: …, commit_bytes: … }`, which no SDK enum
    /// matches, so this asserts what that rendering would violate.
    #[test]
    fn a_name_carries_no_debug_punctuation() {
        for result in [
            GovernanceActionResult::MemberRemoved,
            GovernanceActionResult::RoleChanged,
            GovernanceActionResult::MigrationCancelled,
        ] {
            let name = governance_action_result_name(&result);
            assert!(
                !name.contains('{') && !name.contains('(') && !name.contains(' '),
                "governance outcome name must be a bare variant name, got {name}"
            );
        }
    }

    /// A migration or tombstone moves the handle whichever entry point ran
    /// the action; every other outcome leaves the handle alone.
    #[test]
    fn migration_and_tombstone_outcomes_move_the_handle_state() {
        let proposed = GovernanceActionResult::MigrationProposed(
            scp_core::context::state::MigrationProposedResult {
                destination_context_id: "dest".to_owned(),
                grace_period_end: 1,
            },
        );
        assert_eq!(
            handle_state_after(&proposed),
            Some(ContextState::MigratingOut)
        );
        assert_eq!(
            handle_state_after(&GovernanceActionResult::MigrationCancelled),
            Some(ContextState::Active)
        );
        assert_eq!(
            handle_state_after(&GovernanceActionResult::ContextTombstoned),
            Some(ContextState::Tombstoned)
        );
        for result in [
            GovernanceActionResult::MemberRemoved,
            GovernanceActionResult::ContextClosed,
            GovernanceActionResult::Executed,
        ] {
            assert_eq!(handle_state_after(&result), None, "{result:?}");
        }
    }
}
