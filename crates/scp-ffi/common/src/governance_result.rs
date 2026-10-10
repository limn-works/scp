//! One wire name per governance outcome and proposal status, shared by every
//! FFI bridge.
//!
//! `PyO3`, napi-rs, and `UniFFI` each hand a caller strings naming what a
//! governance action did, which state a proposal holds, and how a checkpoint
//! is attested. Bridges built those strings with `format!("{r:?}")`, so a
//! payload-carrying variant reached an SDK as a Rust `Debug` dump such as
//! `MemberSuspended(SuspendMemberResult { did: DID("did:dht:…"), .. })` or
//! `Rejected { reason: AdminRejected }`, which no SDK enum parses. Every bridge
//! now calls this module's functions instead.
//!
//! Each name function matches every variant with no wildcard arm, so a new
//! variant stops this crate from compiling until someone gives it a name. Each
//! name equals its Rust variant name, which is what Python's
//! `GovernanceActionResult` (`bindings/python/scp_sdk/governance.py`), Swift's
//! `GovernanceActionResult` (`bindings/swift/Sources/SCP/Governance.swift`),
//! and TypeScript's `GovernanceActionResult` union
//! (`bindings/typescript/src/types.ts`) store as their values; Kotlin passes a
//! bridge's string through unchanged.

use scp_core::context::governance::{
    CheckpointAttestationStatus, ContextCheckpoint, ProposalId, ProposalStatus, RejectionReason,
};
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

/// Returns a caller-facing wire name for `status`, without its payload.
///
/// A rejection's or invalidation's reason travels in a separate field that
/// [`insert_proposal_status`] writes, so a name never carries `Debug`
/// punctuation.
#[must_use]
pub const fn proposal_status_name(status: &ProposalStatus) -> &'static str {
    match status {
        ProposalStatus::Pending => "Pending",
        ProposalStatus::Approved => "Approved",
        ProposalStatus::Rejected { .. } => "Rejected",
        ProposalStatus::Expired => "Expired",
        ProposalStatus::Cancelled => "Cancelled",
        ProposalStatus::Invalidated { .. } => "Invalidated",
    }
}

/// Returns a caller-facing wire name for why a proposal was rejected.
#[must_use]
pub const fn rejection_reason_name(reason: &RejectionReason) -> &'static str {
    match reason {
        RejectionReason::AdminRejected => "AdminRejected",
        RejectionReason::MajorityRejected => "MajorityRejected",
        RejectionReason::UnanimityBroken { .. } => "UnanimityBroken",
        RejectionReason::ApprovalImpossible => "ApprovalImpossible",
        RejectionReason::InsufficientParticipation => "InsufficientParticipation",
    }
}

/// Writes `status`'s fields into a JSON object.
///
/// - `status`: [`proposal_status_name`], always present.
/// - `reason`: present only for `Rejected` ([`rejection_reason_name`]) and
///   `Invalidated` (its free-text reason).
/// - `rejector`: present only for `Rejected` with
///   `RejectionReason::UnanimityBroken`, naming a voter who broke unanimity.
///
/// An absent key means its value does not exist, so a caller never confuses
/// a missing reason with a reason spelled `"none"`.
pub fn insert_proposal_status(
    map: &mut serde_json::Map<String, serde_json::Value>,
    status: &ProposalStatus,
) {
    map.insert(
        "status".to_owned(),
        serde_json::Value::from(proposal_status_name(status)),
    );
    match status {
        ProposalStatus::Rejected { reason } => {
            map.insert(
                "reason".to_owned(),
                serde_json::Value::from(rejection_reason_name(reason)),
            );
            match reason {
                RejectionReason::UnanimityBroken { rejector } => {
                    map.insert(
                        "rejector".to_owned(),
                        serde_json::Value::from(rejector.as_ref()),
                    );
                }
                RejectionReason::AdminRejected
                | RejectionReason::MajorityRejected
                | RejectionReason::ApprovalImpossible
                | RejectionReason::InsufficientParticipation => {}
            }
        }
        ProposalStatus::Invalidated { reason } => {
            map.insert(
                "reason".to_owned(),
                serde_json::Value::from(reason.as_str()),
            );
        }
        ProposalStatus::Pending
        | ProposalStatus::Approved
        | ProposalStatus::Expired
        | ProposalStatus::Cancelled => {}
    }
}

/// Builds a JSON body `{status, reason?, rejector?}` that every bridge returns
/// from `governance_approve`, `governance_reject`, and `governance_withdraw`.
///
/// [`insert_proposal_status`] defines each field.
#[must_use]
pub fn proposal_status_response(status: &ProposalStatus) -> String {
    let mut map = serde_json::Map::new();
    insert_proposal_status(&mut map, status);
    serde_json::Value::Object(map).to_string()
}

/// Builds a JSON body `{proposal_id, status, reason?, rejector?,
/// execution_result}` that every bridge returns from `governance_propose`.
///
/// A `single_admin` context auto-approves and auto-executes a proposal, so a
/// caller of such a context reads which action ran from `execution_result`
/// and never calls `governance_execute`. `execution_result` therefore carries
/// [`governance_action_result_name`]'s name, or JSON `null` while a proposal
/// awaits votes. [`insert_proposal_status`] defines `status`, `reason`, and
/// `rejector`.
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
    let mut map = serde_json::Map::new();
    map.insert(
        "proposal_id".to_owned(),
        serde_json::Value::from(hex::encode(proposal_id)),
    );
    insert_proposal_status(&mut map, status);
    map.insert(
        "execution_result".to_owned(),
        execution_result.map_or(serde_json::Value::Null, |r| {
            serde_json::Value::from(governance_action_result_name(r))
        }),
    );
    serde_json::Value::Object(map).to_string()
}

/// Returns a caller-facing wire name for a checkpoint's attestation status.
#[must_use]
pub const fn checkpoint_attestation_status_name(
    status: &CheckpointAttestationStatus,
) -> &'static str {
    match status {
        CheckpointAttestationStatus::FullyAttested => "FullyAttested",
        CheckpointAttestationStatus::PartiallyAttested => "PartiallyAttested",
    }
}

/// Builds a JSON body `{attestation_status, checkpoint}` that every bridge
/// returns from `add_checkpoint_cosignature`.
///
/// # Errors
///
/// Returns `serde_json::Error` when `checkpoint` fails to serialize. A bridge
/// maps it to a typed `SCP-CTX-2063` error and never substitutes JSON `null`
/// for a checkpoint it could not encode.
pub fn checkpoint_cosignature_response(
    checkpoint: &ContextCheckpoint,
    status: &CheckpointAttestationStatus,
) -> Result<String, serde_json::Error> {
    let checkpoint = serde_json::to_value(checkpoint)?;
    Ok(serde_json::json!({
        "attestation_status": checkpoint_attestation_status_name(status),
        "checkpoint": checkpoint,
    })
    .to_string())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use scp_core::context::broadcast::GovernanceBanResult;
    use scp_core::context::governance::AccessScope;
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

    /// A rejection travels as a bare `status` name plus a `reason` field, so
    /// nothing a `Debug` dump carried is lost and no `Debug` punctuation
    /// reaches an SDK.
    #[test]
    fn propose_response_splits_a_rejection_into_status_and_reason() {
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
            Some("Rejected"),
            "got {response}"
        );
        assert_eq!(parsed["reason"].as_str(), Some("ApprovalImpossible"));
        assert!(parsed.get("rejector").is_none(), "got {response}");
    }

    /// One row per status: a value, its pinned `status` name, and the
    /// `reason` and `rejector` fields its response must carry.
    type StatusRow = (
        ProposalStatus,
        &'static str,
        Option<&'static str>,
        Option<&'static str>,
    );

    fn every_status() -> Vec<StatusRow> {
        let rejected = |reason| ProposalStatus::Rejected { reason };
        vec![
            (ProposalStatus::Pending, "Pending", None, None),
            (ProposalStatus::Approved, "Approved", None, None),
            (
                rejected(RejectionReason::AdminRejected),
                "Rejected",
                Some("AdminRejected"),
                None,
            ),
            (
                rejected(RejectionReason::MajorityRejected),
                "Rejected",
                Some("MajorityRejected"),
                None,
            ),
            (
                rejected(RejectionReason::UnanimityBroken { rejector: did() }),
                "Rejected",
                Some("UnanimityBroken"),
                Some("did:dht:zTestMember"),
            ),
            (
                rejected(RejectionReason::ApprovalImpossible),
                "Rejected",
                Some("ApprovalImpossible"),
                None,
            ),
            (
                rejected(RejectionReason::InsufficientParticipation),
                "Rejected",
                Some("InsufficientParticipation"),
                None,
            ),
            (ProposalStatus::Expired, "Expired", None, None),
            (ProposalStatus::Cancelled, "Cancelled", None, None),
            (
                ProposalStatus::Invalidated {
                    reason: "proposer removed".to_owned(),
                },
                "Invalidated",
                Some("proposer removed"),
                None,
            ),
        ]
    }

    /// Pins every body that approve, reject, and withdraw return. For a
    /// payload-carrying status, `status` differs from `format!("{status:?}")`,
    /// which every bridge sent before.
    #[test]
    fn proposal_status_response_pins_every_status() {
        for (status, name, reason, rejector) in every_status() {
            let response = proposal_status_response(&status);
            let parsed: serde_json::Value = serde_json::from_str(&response).unwrap();
            assert_eq!(parsed["status"].as_str(), Some(name), "got {response}");
            assert_eq!(
                parsed.get("reason").and_then(serde_json::Value::as_str),
                reason,
                "got {response}"
            );
            assert_eq!(
                parsed.get("rejector").and_then(serde_json::Value::as_str),
                rejector,
                "got {response}"
            );
            if reason.is_some() {
                let debug = format!("{status:?}");
                assert_ne!(parsed["status"].as_str(), Some(debug.as_str()));
            }
        }
    }

    #[test]
    fn checkpoint_attestation_status_names_are_pinned() {
        assert_eq!(
            checkpoint_attestation_status_name(&CheckpointAttestationStatus::FullyAttested),
            "FullyAttested"
        );
        assert_eq!(
            checkpoint_attestation_status_name(&CheckpointAttestationStatus::PartiallyAttested),
            "PartiallyAttested"
        );
    }

    /// `add_checkpoint_cosignature`'s body carries the status name and the
    /// checkpoint as a JSON object that decodes to an equal checkpoint.
    #[test]
    fn checkpoint_cosignature_response_round_trips_the_checkpoint() {
        let checkpoint = ContextCheckpoint {
            checkpoint_seq: 7,
            merkle_root: [1; 32],
            event_count: 8,
            last_event_hash: [2; 32],
            state_snapshot_hash: [3; 32],
            created_at: 9,
            creator_did: did(),
            creator_signature: vec![4; 64],
            cosignatures: Vec::new(),
            attestation_status: CheckpointAttestationStatus::PartiallyAttested,
        };
        let response = checkpoint_cosignature_response(
            &checkpoint,
            &CheckpointAttestationStatus::PartiallyAttested,
        )
        .unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&response).unwrap();
        assert_eq!(
            parsed["attestation_status"].as_str(),
            Some("PartiallyAttested")
        );
        let back: ContextCheckpoint = serde_json::from_value(parsed["checkpoint"].clone()).unwrap();
        assert_eq!(back, checkpoint);
    }
}
