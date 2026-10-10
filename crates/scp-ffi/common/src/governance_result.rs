//! One wire name per governance outcome, shared by every FFI bridge.
//!
//! `PyO3`, napi-rs, and `UniFFI` each hand a caller a string naming what a
//! governance action did. Napi-rs `governance_execute` and all three bridges'
//! `governance_propose` built that string with `format!("{r:?}")`, so a
//! payload-carrying variant reached an SDK as a Rust `Debug` dump such as
//! `MemberSuspended(SuspendMemberResult { did: DID("did:dht:…"), .. })`, which
//! no SDK enum parses. Every bridge now calls [`governance_action_result_name`]
//! and [`governance_propose_response`] instead.
//!
//! [`governance_action_result_name`] matches every [`GovernanceActionResult`]
//! variant with no wildcard arm, so a new variant stops this crate from
//! compiling until someone gives it a name. Each name equals its Rust variant
//! name, which is what Python's `GovernanceActionResult`
//! (`bindings/python/scp_sdk/governance.py`), Swift's `GovernanceActionResult`
//! (`bindings/swift/Sources/SCP/Governance.swift`), and TypeScript's
//! `GovernanceActionResult` union (`bindings/typescript/src/types.ts`) store as
//! their values; Kotlin passes a bridge's string through unchanged.

use scp_core::context::governance::{ProposalId, ProposalStatus};
use scp_core::context::state::GovernanceActionResult;

/// Returns a caller-facing wire name for `result`.
///
/// Each name equals its Rust variant name and carries no payload, because a
/// payload belongs to a typed accessor and never to an outcome name.
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

/// Builds a JSON body `{proposal_id, status, execution_result}` that every
/// bridge returns from `governance_propose`.
///
/// A `single_admin` context auto-approves and auto-executes a proposal, so a
/// caller of such a context reads which action ran from `execution_result`
/// and never calls `governance_execute`. `execution_result` therefore carries
/// [`governance_action_result_name`]'s name, or JSON `null` while a proposal
/// awaits votes.
///
/// `status` keeps `ProposalStatus`'s `Debug` rendering, which every bridge
/// already produced: `ProposalStatus::Rejected` and
/// `ProposalStatus::Invalidated` carry a reason that a bare name would drop,
/// and no SDK parses `status` into an enum today.
///
/// # Arguments
///
/// * `proposal_id` -- Identifier of a proposal that a governance engine created.
/// * `status` -- Lifecycle status that proposal holds after creation.
/// * `execution_result` -- What an auto-executed action did, or `None` while a
///   multi-admin proposal awaits votes.
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
    use scp_core::context::broadcast::GovernanceBanResult;
    use scp_core::context::governance::{AccessScope, RejectionReason};
    use scp_core::context::membership::RedactedBytes;
    use scp_core::context::state::{
        ContentKeysRotatedResult, GovernanceReconfiguredResult, MigrationProposedResult,
        RestoreAccessResult, RevokeResult, SuspendMemberResult,
    };
    use scp_did::DID;

    use super::*;

    fn did() -> DID {
        DID("did:dht:zTestMember".to_owned())
    }

    /// One value of every `GovernanceActionResult` variant, paired with a wire
    /// name that SDK enums parse. A variant added to `GovernanceActionResult`
    /// fails compilation in `governance_action_result_name` first; a test
    /// author then adds its row here.
    fn every_variant() -> Vec<(GovernanceActionResult, &'static str)> {
        vec![
            (
                GovernanceActionResult::MemberAdded {
                    welcome_bytes: RedactedBytes(vec![1, 2, 3]),
                    commit_bytes: RedactedBytes(vec![4, 5]),
                },
                "MemberAdded",
            ),
            (GovernanceActionResult::MemberRemoved, "MemberRemoved"),
            (GovernanceActionResult::RoleChanged, "RoleChanged"),
            (GovernanceActionResult::OutletRegistered, "OutletRegistered"),
            (GovernanceActionResult::OutletRemoved, "OutletRemoved"),
            (GovernanceActionResult::CeilingModified, "CeilingModified"),
            (GovernanceActionResult::ContextClosed, "ContextClosed"),
            (GovernanceActionResult::TtlExtended, "TtlExtended"),
            (
                GovernanceActionResult::PruningPolicyModified,
                "PruningPolicyModified",
            ),
            (GovernanceActionResult::AdminTransferred, "AdminTransferred"),
            (GovernanceActionResult::SignerAdded, "SignerAdded"),
            (GovernanceActionResult::SignerRemoved, "SignerRemoved"),
            (
                GovernanceActionResult::ThresholdModified,
                "ThresholdModified",
            ),
            (
                GovernanceActionResult::ChildContextCreated,
                "ChildContextCreated",
            ),
            (
                GovernanceActionResult::OutletInterfaceEstablished,
                "OutletInterfaceEstablished",
            ),
            (GovernanceActionResult::MemberReset, "MemberReset"),
            (GovernanceActionResult::ConflictResolved, "ConflictResolved"),
            (GovernanceActionResult::ContextPromoted, "ContextPromoted"),
            (
                GovernanceActionResult::MemberSuspended(SuspendMemberResult {
                    did: did(),
                    capabilities: Vec::new(),
                }),
                "MemberSuspended",
            ),
            (
                GovernanceActionResult::AccessRevoked(RevokeResult {
                    did: did(),
                    access: AccessScope::Both,
                    rotated_author_count: 2,
                }),
                "AccessRevoked",
            ),
            (
                GovernanceActionResult::AccessRestored(RestoreAccessResult {
                    did: did(),
                    capabilities: Vec::new(),
                }),
                "AccessRestored",
            ),
            (
                GovernanceActionResult::ContentKeysRotated(ContentKeysRotatedResult {
                    reason: Some("compromise".to_owned()),
                }),
                "ContentKeysRotated",
            ),
            (
                GovernanceActionResult::GovernanceReconfigured(GovernanceReconfiguredResult {
                    changes_applied: 1,
                }),
                "GovernanceReconfigured",
            ),
            (
                GovernanceActionResult::SubscriberBanned(GovernanceBanResult {
                    banned_did: "did:dht:zBanned".to_owned(),
                    rotated_authors: Vec::new(),
                    scope: AccessScope::Read,
                }),
                "SubscriberBanned",
            ),
            (
                GovernanceActionResult::SubscriberUnbanned { did: did() },
                "SubscriberUnbanned",
            ),
            (GovernanceActionResult::Executed, "Executed"),
            (
                GovernanceActionResult::MigrationProposed(MigrationProposedResult {
                    destination_context_id: "dest".to_owned(),
                    grace_period_end: 1,
                }),
                "MigrationProposed",
            ),
            (
                GovernanceActionResult::MigrationCancelled,
                "MigrationCancelled",
            ),
            (
                GovernanceActionResult::ContextTombstoned,
                "ContextTombstoned",
            ),
        ]
    }

    /// Pins all 29 wire names. A rename here breaks every SDK parser, so a
    /// changed row needs a matching SDK change in one pull request.
    #[test]
    fn every_variant_has_its_pinned_wire_name() {
        let rows = every_variant();
        assert_eq!(rows.len(), 29, "GovernanceActionResult has 29 variants");
        for (result, expected) in &rows {
            assert_eq!(
                governance_action_result_name(result),
                *expected,
                "wrong wire name for {result:?}"
            );
        }
    }

    /// No two variants share a name, so an SDK can map each name back to one
    /// outcome.
    #[test]
    fn wire_names_are_distinct() {
        let names: std::collections::HashSet<&str> = every_variant()
            .iter()
            .map(|(r, _)| governance_action_result_name(r))
            .collect();
        assert_eq!(names.len(), 29);
    }

    /// A wire name differs from `Debug` output for every payload-carrying
    /// variant, which is what a bridge sent before this module existed.
    #[test]
    fn wire_name_is_not_debug_output_for_payload_variants() {
        for (result, name) in every_variant() {
            let debug = format!("{result:?}");
            if debug != name {
                assert!(
                    !name.contains(['{', '(', ' ']),
                    "wire name {name} carries Debug punctuation"
                );
            }
        }
    }

    /// A `single_admin` propose response names its auto-executed outcome.
    #[test]
    fn propose_response_names_a_payload_carrying_outcome() {
        let response = governance_propose_response(
            &[0xAB; 32],
            &ProposalStatus::Approved,
            Some(&GovernanceActionResult::MemberSuspended(
                SuspendMemberResult {
                    did: did(),
                    capabilities: Vec::new(),
                },
            )),
        );
        let parsed: serde_json::Value = serde_json::from_str(&response).unwrap();
        assert_eq!(parsed["execution_result"].as_str(), Some("MemberSuspended"));
        assert_eq!(parsed["status"].as_str(), Some("Approved"));
        assert_eq!(
            parsed["proposal_id"].as_str(),
            Some("ab".repeat(32).as_str())
        );
    }

    /// A proposal awaiting votes executed nothing, so `execution_result` is
    /// JSON `null`.
    #[test]
    fn propose_response_reports_a_pending_proposal_as_null() {
        let response = governance_propose_response(&[0; 32], &ProposalStatus::Pending, None);
        let parsed: serde_json::Value = serde_json::from_str(&response).unwrap();
        assert!(parsed["execution_result"].is_null(), "got {response}");
        assert_eq!(parsed["status"].as_str(), Some("Pending"));
    }

    /// `status` keeps a rejection's reason.
    #[test]
    fn propose_response_keeps_a_rejection_reason() {
        let response = governance_propose_response(
            &[0; 32],
            &ProposalStatus::Rejected {
                reason: RejectionReason::ApprovalImpossible,
            },
            None,
        );
        let parsed: serde_json::Value = serde_json::from_str(&response).unwrap();
        assert_eq!(
            parsed["status"].as_str(),
            Some("Rejected { reason: ApprovalImpossible }")
        );
    }
}
