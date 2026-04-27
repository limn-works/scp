#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! B6 governance integration tests.
//!
//! Covers governance subsystem APIs NOT already tested in
//! `scp-core/tests/governance_integration.rs` — serde roundtrips, vote
//! signing/verification, engine-level lifecycle, conflict detection,
//! deadlock detection, and economic governance actions.

use std::sync::Arc;

use scp_core::context::governance::majority::MajorityVoteEngine;
use scp_core::context::governance::multisig::ThresholdEngine;
use scp_core::context::governance::timeout::{
    DeadlockCondition, DeadlockDetectionState, detect_deadlock,
};
use scp_core::context::governance::unanimity::UnanimityEngine;
use scp_core::context::governance::{
    AccessScope, ConflictResolution, DeadlockJustification, GovernanceAction, GovernanceContext,
    GovernanceEngine, GovernanceError, GovernanceEvent, GovernanceReconfigAction, KeyResolver,
    ProposalStatus, PruningPolicy, SingleAdminEngine, VoteType, actions_conflict, sign_vote,
    verify_vote,
};
use scp_core::context::params::{Capability, ContextParams};
use scp_core::context::tools::OutletSchema;
use scp_core::context::tools::interface::OutletInterface;
use scp_core::economy::types::{Amount, CostSchedule, CurrencyCode, EconomicPolicy};
use scp_identity::DID;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn alice() -> DID {
    DID::from("did:dht:z6MkAlice")
}

fn bob() -> DID {
    DID::from("did:dht:z6MkBob")
}

fn carol() -> DID {
    DID::from("did:dht:z6MkCarol")
}

fn dave() -> DID {
    DID::from("did:dht:z6MkDave")
}

fn sk_for(seed: u8) -> ed25519_dalek::SigningKey {
    ed25519_dalek::SigningKey::from_bytes(&[seed; 32])
}

/// Mock key resolver: Alice=1, Bob=2, Carol=3, Dave=4.
fn mock_resolver() -> KeyResolver {
    Arc::new(|did: &DID| {
        let did_str: &str = did.as_ref();
        match did_str {
            "did:dht:z6MkAlice" => Some(sk_for(1).verifying_key()),
            "did:dht:z6MkBob" => Some(sk_for(2).verifying_key()),
            "did:dht:z6MkCarol" => Some(sk_for(3).verifying_key()),
            "did:dht:z6MkDave" => Some(sk_for(4).verifying_key()),
            _ => None,
        }
    })
}

fn governance_context_for_members(
    ctx_id: &str,
    members: &[(DID, &str)],
    admin_dids: &[DID],
    now: u64,
) -> GovernanceContext {
    GovernanceContext {
        context_id: ctx_id.to_owned(),
        members: members
            .iter()
            .map(|(d, r)| (d.clone(), (*r).to_owned()))
            .collect(),
        admin_dids: admin_dids.to_vec(),
        current_epoch: Some(1),
        now,
    }
}

fn simple_tool_interface() -> OutletInterface {
    OutletInterface {
        source_context: "ctx-src".to_owned(),
        target_context: "ctx-tgt".to_owned(),
        outlet_id: "tool-1".to_owned(),
        rate_limit: None,
        per_caller_rate_limit: None,
        approved_by_source: true,
        approved_by_target: false,
        outbound_policy: None,
        inbound_policy: None,
    }
}

fn simple_economic_policy() -> EconomicPolicy {
    EconomicPolicy {
        locked: false,
        cost_schedule: CostSchedule {
            currency: CurrencyCode::from("USD"),
            per_message: Some(Amount::new(1)),
            per_outlet_call: None,
            per_join: None,
            per_period: None,
            per_byte_stored: None,
        },
        payment_adapters: vec![],
        pricing_formula: None,
        payee: DID::from("did:dht:z6MkPayee"),
    }
}

fn simple_tool_registration() -> scp_core::context::params::OutletRegistration {
    scp_core::context::params::OutletRegistration {
        outlet_id: "search".to_owned(),
        kind: scp_core::context::outlets::OutletKind::Action,
        name: "search".to_owned(),
        description: "Search tool".to_owned(),
        schema: OutletSchema {
            input_schema: serde_json::json!({"type": "object"}),
            output_schema: serde_json::json!({"type": "object"}),
            aggregate_schema: None,
        },
        implementation_hash: [0u8; 32],
        test_vectors: vec![],
        operator_did: DID::from("did:dht:z6MkTestOperator"),
        cost: None,
        registered_at: 0,
        signature: Vec::new(),
        message_catalog: Vec::new(),
    }
}

// ---------------------------------------------------------------------------
// 1. all_governance_action_variants_roundtrip
// ---------------------------------------------------------------------------

/// Builds governance action fixtures covering every variant (plus a
/// few variants with multiple `AccessScope` values) for exhaustive
/// serde round-trip testing. The assertion below pins the fixture
/// count so adding a new variant to the enum without updating this
/// helper breaks the test loudly.
/// Split into a helper to keep the test function within the line limit.
#[allow(clippy::too_many_lines)]
fn all_governance_actions_for_test() -> Vec<GovernanceAction> {
    vec![
        GovernanceAction::AddMember {
            did: bob(),
            role: "member".to_owned(),
        },
        GovernanceAction::RemoveMember {
            did: bob(),
            reason: Some("inactive".to_owned()),
            induced_rotations: Vec::new(),
        },
        GovernanceAction::ChangeRole {
            did: bob(),
            new_role: "observer".to_owned(),
        },
        GovernanceAction::RegisterOutlet {
            registration: Box::new(simple_tool_registration()),
        },
        GovernanceAction::RemoveOutlet {
            outlet_id: "search".to_owned(),
        },
        GovernanceAction::ModifyCeiling {
            new_ceiling: vec![Capability::MessagesRead],
        },
        GovernanceAction::CloseContext {
            reason: Some("done".to_owned()),
        },
        GovernanceAction::ExtendTtl {
            additional_secs: 3600,
        },
        GovernanceAction::TransferAdmin { new_admin: bob() },
        GovernanceAction::CreateChildContext {
            params: Box::new(ContextParams::default()),
        },
        GovernanceAction::RevokeAccess {
            did: bob(),
            access: AccessScope::Read,
        },
        GovernanceAction::RestoreAccess {
            did: bob(),
            capabilities: vec![Capability::MessagesRead],
        },
        GovernanceAction::ModifyPruningPolicy {
            new_policy: PruningPolicy::default(),
        },
        GovernanceAction::AddSigner { did: carol() },
        GovernanceAction::RemoveSigner { did: carol() },
        GovernanceAction::ModifyThreshold { new_threshold: 2 },
        GovernanceAction::EstablishOutletInterface {
            interface: simple_tool_interface(),
        },
        GovernanceAction::ResetMember {
            did: bob(),
            reason: "group state corruption".to_owned(),
        },
        GovernanceAction::ResolveConflict {
            proposal_a: [1u8; 32],
            proposal_b: [2u8; 32],
            resolution: ConflictResolution::AcceptProposal {
                winner_id: [1u8; 32],
            },
        },
        GovernanceAction::PromoteContext,
        GovernanceAction::RevokeAccess {
            did: bob(),
            access: AccessScope::Write,
        },
        GovernanceAction::RestoreAccess {
            did: bob(),
            capabilities: vec![Capability::MessagesWrite],
        },
        GovernanceAction::RotateContentKeys {
            reason: Some("periodic hygiene".to_owned()),
        },
        GovernanceAction::ReconfigureGovernance {
            changes: vec![GovernanceReconfigAction::RemoveInactiveSigner { did: carol() }],
            justification: DeadlockJustification {
                unavailable_dids: vec![carol()],
                missed_windows: vec![(carol(), 5)],
                detected_at: 1_700_000_000,
            },
        },
        GovernanceAction::SetEconomicPolicy {
            policy: simple_economic_policy(),
        },
        GovernanceAction::ApproveSpend {
            spender: bob(),
            amount: Amount::new(1000),
            purpose: "tool costs".to_owned(),
        },
        GovernanceAction::LockEconomicPolicy,
        GovernanceAction::ProposeContextMigration {
            new_context_params: Box::new(ContextParams::default()),
            reason: "protocol upgrade".to_owned(),
            grace_period_secs: 604_800,
            auto_invite: true,
        },
        GovernanceAction::CancelContextMigration,
        GovernanceAction::SuspendCapability {
            did: bob(),
            capabilities: vec![Capability::GovernanceVote],
        },
        GovernanceAction::ModifyHardRateLimit {
            new_config: scp_core::economy::antispam::HardRateLimitConfig::matrix_defaults(),
        },
    ]
}

#[tokio::test]
async fn all_governance_action_variants_roundtrip() {
    let actions = all_governance_actions_for_test();

    // The fixture count is pinned to catch enum growth. When adding
    // a new GovernanceAction variant, extend `all_governance_actions_for_test`
    // and bump this number. Not equal to the raw variant count —
    // Revoke / RestoreAccess appear twice with different AccessScope
    // values to exercise both scopes of the AccessScope enum.
    assert_eq!(
        actions.len(),
        31,
        "fixture must cover every GovernanceAction variant; bump when adding a new variant"
    );

    for action in &actions {
        let json = serde_json::to_string(action).expect("serialize");
        let deserialized: GovernanceAction = serde_json::from_str(&json).expect("deserialize");
        let json2 = serde_json::to_string(&deserialized).expect("re-serialize");
        assert_eq!(json, json2, "round-trip mismatch for {action:?}");
    }
}

// ---------------------------------------------------------------------------
// 2. proposal_id_deterministic
// ---------------------------------------------------------------------------

#[tokio::test]
async fn proposal_id_deterministic() {
    // Two proposals with identical inputs (same context, proposer, action, timestamp)
    // must produce the same proposal ID. We achieve this by creating two engines
    // with the same parameters and proposing the same action at the same time.
    let now = 1_700_000_000;
    let action = GovernanceAction::AddMember {
        did: dave(),
        role: "member".to_owned(),
    };
    let ctx =
        governance_context_for_members("ctx-deterministic", &[(alice(), "admin")], &[alice()], now);

    let mut engine1 = SingleAdminEngine::new(alice(), mock_resolver());
    let mut engine2 = SingleAdminEngine::new(alice(), mock_resolver());

    let (p1, _) = engine1
        .propose(&alice(), action.clone(), &ctx, &sk_for(1))
        .unwrap();
    let (p2, _) = engine2.propose(&alice(), action, &ctx, &sk_for(1)).unwrap();

    assert_eq!(
        p1.proposal_id, p2.proposal_id,
        "same inputs must produce same proposal ID"
    );
}

// ---------------------------------------------------------------------------
// 3. proposal_id_differs_on_input_change
// ---------------------------------------------------------------------------

#[tokio::test]
async fn proposal_id_differs_on_input_change() {
    let now = 1_700_000_000;
    let base_ctx = governance_context_for_members(
        "ctx-diff",
        &[(alice(), "admin"), (bob(), "admin")],
        &[alice(), bob()],
        now,
    );

    // Base proposal.
    let mut engine1 = SingleAdminEngine::new(alice(), mock_resolver());
    let (base, _) = engine1
        .propose(
            &alice(),
            GovernanceAction::AddMember {
                did: dave(),
                role: "member".to_owned(),
            },
            &base_ctx,
            &sk_for(1),
        )
        .unwrap();

    // Different action.
    let mut engine2 = SingleAdminEngine::new(alice(), mock_resolver());
    let (diff_action, _) = engine2
        .propose(
            &alice(),
            GovernanceAction::CloseContext { reason: None },
            &base_ctx,
            &sk_for(1),
        )
        .unwrap();
    assert_ne!(
        base.proposal_id, diff_action.proposal_id,
        "different action -> different ID"
    );

    // Different proposer (Bob is admin in a fresh engine).
    let mut engine3 = SingleAdminEngine::new(bob(), mock_resolver());
    let (diff_proposer, _) = engine3
        .propose(
            &bob(),
            GovernanceAction::AddMember {
                did: dave(),
                role: "member".to_owned(),
            },
            &base_ctx,
            &sk_for(2),
        )
        .unwrap();
    assert_ne!(
        base.proposal_id, diff_proposer.proposal_id,
        "different proposer -> different ID"
    );

    // Different timestamp.
    let diff_ts_ctx = GovernanceContext {
        now: now + 1,
        ..base_ctx.clone()
    };
    let mut engine4 = SingleAdminEngine::new(alice(), mock_resolver());
    let (diff_ts, _) = engine4
        .propose(
            &alice(),
            GovernanceAction::AddMember {
                did: dave(),
                role: "member".to_owned(),
            },
            &diff_ts_ctx,
            &sk_for(1),
        )
        .unwrap();
    assert_ne!(
        base.proposal_id, diff_ts.proposal_id,
        "different timestamp -> different ID"
    );
}

// ---------------------------------------------------------------------------
// 4. vote_sign_verify_roundtrip
// ---------------------------------------------------------------------------

#[tokio::test]
async fn vote_sign_verify_roundtrip() {
    let proposal_id = [42u8; 32];
    let vote = VoteType::Approve;
    let voter_did = "did:dht:z6MkAlice";
    let timestamp = 1_700_000_000u64;
    let signing_key = sk_for(1);

    let signed = sign_vote(&proposal_id, &vote, voter_did, timestamp, &signing_key).unwrap();
    assert_eq!(signed.voter_did, alice());
    assert_eq!(signed.vote, VoteType::Approve);
    assert_eq!(signed.timestamp, timestamp);

    let verifying_key = signing_key.verifying_key();
    verify_vote(&proposal_id, &signed, &verifying_key).unwrap();
}

// ---------------------------------------------------------------------------
// 5. vote_verify_wrong_key_fails
// ---------------------------------------------------------------------------

#[tokio::test]
async fn vote_verify_wrong_key_fails() {
    let proposal_id = [42u8; 32];
    let vote = VoteType::Reject;
    let voter_did = "did:dht:z6MkAlice";
    let timestamp = 1_700_000_000u64;
    let signing_key = sk_for(1);

    let signed = sign_vote(&proposal_id, &vote, voter_did, timestamp, &signing_key).unwrap();

    // Verify with a different key -> must fail.
    let wrong_key = sk_for(2).verifying_key();
    let result = verify_vote(&proposal_id, &signed, &wrong_key);
    assert!(result.is_err(), "verify_vote with wrong key must fail");
    assert!(
        matches!(result.unwrap_err(), GovernanceError::VerificationFailed(_)),
        "expected VerificationFailed error"
    );
}

// ---------------------------------------------------------------------------
// 6. single_admin_auto_approves
// ---------------------------------------------------------------------------

#[tokio::test]
async fn single_admin_auto_approves() {
    let mut engine = SingleAdminEngine::new(alice(), mock_resolver());
    let ctx = governance_context_for_members(
        "ctx-sa-auto",
        &[(alice(), "admin"), (bob(), "member")],
        &[alice()],
        1_700_000_000,
    );

    let (proposal, events) = engine
        .propose(
            &alice(),
            GovernanceAction::AddMember {
                did: dave(),
                role: "member".to_owned(),
            },
            &ctx,
            &sk_for(1),
        )
        .unwrap();

    assert_eq!(proposal.status, ProposalStatus::Approved);
    assert!(
        events.iter().any(|e| matches!(
            e,
            GovernanceEvent::ProposalResolved {
                status: ProposalStatus::Approved,
                ..
            }
        )),
        "expected ProposalResolved(Approved)"
    );
}

// ---------------------------------------------------------------------------
// 7. single_admin_non_admin_rejects
// ---------------------------------------------------------------------------

#[tokio::test]
async fn single_admin_non_admin_rejects() {
    let mut engine = SingleAdminEngine::new(alice(), mock_resolver());
    let ctx = governance_context_for_members(
        "ctx-sa-reject",
        &[(alice(), "admin"), (bob(), "member")],
        &[alice()],
        1_700_000_000,
    );

    let result = engine.propose(
        &bob(),
        GovernanceAction::CloseContext { reason: None },
        &ctx,
        &sk_for(2),
    );

    assert!(result.is_err());
    assert!(
        matches!(result.unwrap_err(), GovernanceError::NotAdmin),
        "expected NotAdmin"
    );
}

// ---------------------------------------------------------------------------
// 8. majority_approval
// ---------------------------------------------------------------------------

#[tokio::test]
async fn majority_approval() {
    let voters = vec![alice(), bob(), carol()];
    let mut engine = MajorityVoteEngine::new(voters, 86_400, 5000, mock_resolver()).unwrap();

    let now = 1_700_000_000;
    let ctx = governance_context_for_members(
        "ctx-maj-approve",
        &[(alice(), "member"), (bob(), "member"), (carol(), "member")],
        &[alice()],
        now,
    );

    // Alice proposes (does NOT auto-approve in Majority model).
    let (proposal, _) = engine
        .propose(
            &alice(),
            GovernanceAction::ChangeRole {
                did: bob(),
                new_role: "observer".to_owned(),
            },
            &ctx,
            &sk_for(1),
        )
        .unwrap();
    assert_eq!(proposal.status, ProposalStatus::Pending);

    // Alice explicitly approves.
    let (status, _) = engine
        .approve(&proposal.proposal_id, &alice(), &ctx, &sk_for(1))
        .unwrap();
    assert_eq!(status, ProposalStatus::Pending);

    // Bob approves -> 2/3 majority.
    let (status, _) = engine
        .approve(&proposal.proposal_id, &bob(), &ctx, &sk_for(2))
        .unwrap();
    assert_eq!(status, ProposalStatus::Approved);
}

// ---------------------------------------------------------------------------
// 9. majority_rejection
// ---------------------------------------------------------------------------

#[tokio::test]
async fn majority_rejection() {
    let voters = vec![alice(), bob(), carol()];
    let mut engine = MajorityVoteEngine::new(voters, 86_400, 5000, mock_resolver()).unwrap();

    let now = 1_700_000_000;
    let ctx = governance_context_for_members(
        "ctx-maj-reject",
        &[(alice(), "member"), (bob(), "member"), (carol(), "member")],
        &[alice()],
        now,
    );

    let (proposal, _) = engine
        .propose(
            &alice(),
            GovernanceAction::CloseContext { reason: None },
            &ctx,
            &sk_for(1),
        )
        .unwrap();

    // Bob and Carol reject -> 2 rejections out of 3 eligible.
    let (_, _) = engine
        .reject(&proposal.proposal_id, &bob(), &ctx, &sk_for(2))
        .unwrap();
    let (status, _) = engine
        .reject(&proposal.proposal_id, &carol(), &ctx, &sk_for(3))
        .unwrap();

    assert!(
        matches!(status, ProposalStatus::Rejected { .. }),
        "expected Rejected, got {status:?}"
    );
}

// ---------------------------------------------------------------------------
// 10. majority_min_participation
// ---------------------------------------------------------------------------

#[tokio::test]
async fn majority_min_participation() {
    // 4 voters, min_participation_bps=7500 (75%). Need 3 votes.
    let voters = vec![alice(), bob(), carol(), dave()];
    let mut engine = MajorityVoteEngine::new(voters, 300, 7500, mock_resolver()).unwrap();

    let now = 1_700_000_000;
    let ctx = governance_context_for_members(
        "ctx-maj-participation",
        &[
            (alice(), "member"),
            (bob(), "member"),
            (carol(), "member"),
            (dave(), "member"),
        ],
        &[alice()],
        now,
    );

    let (proposal, _) = engine
        .propose(
            &alice(),
            GovernanceAction::CloseContext { reason: None },
            &ctx,
            &sk_for(1),
        )
        .unwrap();

    // Only Alice has voted (via propose). After deadline, insufficient participation.
    let expired_ctx = GovernanceContext {
        now: now + 301,
        ..ctx
    };
    let (status, _) = engine.resolve(&proposal.proposal_id, &expired_ctx).unwrap();

    assert!(
        matches!(
            &status,
            ProposalStatus::Rejected {
                reason: scp_core::context::governance::RejectionReason::InsufficientParticipation
            }
        ),
        "expected InsufficientParticipation, got {status:?}"
    );
}

// ---------------------------------------------------------------------------
// 11. threshold_m_of_n
// ---------------------------------------------------------------------------

#[tokio::test]
async fn threshold_m_of_n() {
    // 2-of-3 threshold.
    let signers = vec![alice(), bob(), carol()];
    let mut engine = ThresholdEngine::new(signers, 2, 86_400, mock_resolver()).unwrap();

    let now = 1_700_000_000;
    let ctx = governance_context_for_members(
        "ctx-thresh-2of3",
        &[(alice(), "admin"), (bob(), "admin"), (carol(), "admin")],
        &[alice(), bob(), carol()],
        now,
    );

    let (proposal, _) = engine
        .propose(
            &alice(),
            GovernanceAction::AddMember {
                did: dave(),
                role: "member".to_owned(),
            },
            &ctx,
            &sk_for(1),
        )
        .unwrap();

    // Alice auto-approved on propose (1/2). Bob approves (2/2).
    let (status, _) = engine
        .approve(&proposal.proposal_id, &bob(), &ctx, &sk_for(2))
        .unwrap();

    assert_eq!(status, ProposalStatus::Approved);
}

// ---------------------------------------------------------------------------
// 12. unanimity_all_approve
// ---------------------------------------------------------------------------

#[tokio::test]
async fn unanimity_all_approve() {
    let voters = vec![alice(), bob(), carol()];
    let mut engine = UnanimityEngine::new(voters, 86_400, mock_resolver()).unwrap();

    let now = 1_700_000_000;
    let ctx = governance_context_for_members(
        "ctx-unanimity-approve",
        &[(alice(), "member"), (bob(), "member"), (carol(), "member")],
        &[alice()],
        now,
    );

    let (proposal, _) = engine
        .propose(
            &alice(),
            GovernanceAction::CloseContext {
                reason: Some("test".to_owned()),
            },
            &ctx,
            &sk_for(1),
        )
        .unwrap();
    assert_eq!(proposal.status, ProposalStatus::Pending);

    // Bob approves (2/3).
    let (status, _) = engine
        .approve(&proposal.proposal_id, &bob(), &ctx, &sk_for(2))
        .unwrap();
    assert_eq!(status, ProposalStatus::Pending);

    // Carol approves (3/3 -> unanimous).
    let (status, _) = engine
        .approve(&proposal.proposal_id, &carol(), &ctx, &sk_for(3))
        .unwrap();
    assert_eq!(status, ProposalStatus::Approved);
}

// ---------------------------------------------------------------------------
// 13. unanimity_single_reject
// ---------------------------------------------------------------------------

#[tokio::test]
async fn unanimity_single_reject() {
    let voters = vec![alice(), bob(), carol()];
    let mut engine = UnanimityEngine::new(voters, 86_400, mock_resolver()).unwrap();

    let now = 1_700_000_000;
    let ctx = governance_context_for_members(
        "ctx-unanimity-reject",
        &[(alice(), "member"), (bob(), "member"), (carol(), "member")],
        &[alice()],
        now,
    );

    let (proposal, _) = engine
        .propose(
            &alice(),
            GovernanceAction::CloseContext { reason: None },
            &ctx,
            &sk_for(1),
        )
        .unwrap();

    // Bob rejects -> unanimity broken immediately.
    let (status, _) = engine
        .reject(&proposal.proposal_id, &bob(), &ctx, &sk_for(2))
        .unwrap();

    assert!(
        matches!(status, ProposalStatus::Rejected { .. }),
        "expected Rejected, got {status:?}"
    );
}

// ---------------------------------------------------------------------------
// 14. already_voted_error
// ---------------------------------------------------------------------------

#[tokio::test]
async fn already_voted_error() {
    let signers = vec![alice(), bob(), carol()];
    let mut engine = ThresholdEngine::new(signers, 3, 86_400, mock_resolver()).unwrap();

    let now = 1_700_000_000;
    let ctx = governance_context_for_members(
        "ctx-already-voted",
        &[(alice(), "admin"), (bob(), "admin"), (carol(), "admin")],
        &[alice(), bob(), carol()],
        now,
    );

    let (proposal, _) = engine
        .propose(
            &alice(),
            GovernanceAction::AddMember {
                did: dave(),
                role: "member".to_owned(),
            },
            &ctx,
            &sk_for(1),
        )
        .unwrap();

    // Alice already voted (auto-approval from propose). Voting again should fail.
    let result = engine.approve(&proposal.proposal_id, &alice(), &ctx, &sk_for(1));
    assert!(result.is_err());
    assert!(
        matches!(result.unwrap_err(), GovernanceError::AlreadyVoted),
        "expected AlreadyVoted"
    );
}

// ---------------------------------------------------------------------------
// 15. voting_window_expired
// ---------------------------------------------------------------------------

#[tokio::test]
async fn voting_window_expired() {
    let signers = vec![alice(), bob(), carol()];
    let mut engine = ThresholdEngine::new(signers, 2, 300, mock_resolver()).unwrap();

    let now = 1_700_000_000;
    let ctx = governance_context_for_members(
        "ctx-window-expired",
        &[(alice(), "admin"), (bob(), "admin"), (carol(), "admin")],
        &[alice(), bob(), carol()],
        now,
    );

    let (proposal, _) = engine
        .propose(
            &alice(),
            GovernanceAction::CloseContext { reason: None },
            &ctx,
            &sk_for(1),
        )
        .unwrap();

    // Advance past voting deadline.
    let expired_ctx = GovernanceContext {
        now: now + 301,
        ..ctx
    };

    let result = engine.approve(&proposal.proposal_id, &bob(), &expired_ctx, &sk_for(2));
    assert!(result.is_err());
    assert!(
        matches!(
            result.unwrap_err(),
            GovernanceError::VotingWindowExpired { .. }
        ),
        "expected VotingWindowExpired"
    );
}

// ---------------------------------------------------------------------------
// 16. conflict_detection
// ---------------------------------------------------------------------------

#[tokio::test]
async fn conflict_detection() {
    // Competing ChangeRole for same DID with different roles.
    let action_a = GovernanceAction::ChangeRole {
        did: bob(),
        new_role: "admin".to_owned(),
    };
    let action_b = GovernanceAction::ChangeRole {
        did: bob(),
        new_role: "member".to_owned(),
    };
    assert!(
        actions_conflict(&action_a, &alice(), &action_b, &carol()),
        "competing ChangeRole for same DID should conflict"
    );

    // Mutual RemoveMember.
    let remove_a = GovernanceAction::RemoveMember {
        did: bob(),
        reason: None,
        induced_rotations: Vec::new(),
    };
    let remove_b = GovernanceAction::RemoveMember {
        did: alice(),
        reason: None,
        induced_rotations: Vec::new(),
    };
    assert!(
        actions_conflict(&remove_a, &alice(), &remove_b, &bob()),
        "mutual RemoveMember should conflict"
    );

    // Competing ModifyCeiling.
    let ceiling_a = GovernanceAction::ModifyCeiling {
        new_ceiling: vec![Capability::MessagesRead],
    };
    let ceiling_b = GovernanceAction::ModifyCeiling {
        new_ceiling: vec![Capability::MessagesWrite],
    };
    assert!(
        actions_conflict(&ceiling_a, &alice(), &ceiling_b, &bob()),
        "competing ModifyCeiling should conflict"
    );

    // Revoke (read) vs RestoreAccess (read).
    let revoke = GovernanceAction::RevokeAccess {
        did: bob(),
        access: AccessScope::Read,
    };
    let restore = GovernanceAction::RestoreAccess {
        did: bob(),
        capabilities: vec![Capability::MessagesRead],
    };
    assert!(
        actions_conflict(&revoke, &alice(), &restore, &carol()),
        "Revoke (read) vs RestoreAccess (read) should conflict"
    );

    // Revoke (write) vs RestoreAccess (write).
    let revoke_w = GovernanceAction::RevokeAccess {
        did: bob(),
        access: AccessScope::Write,
    };
    let restore_w = GovernanceAction::RestoreAccess {
        did: bob(),
        capabilities: vec![Capability::MessagesWrite],
    };
    assert!(
        actions_conflict(&revoke_w, &alice(), &restore_w, &carol()),
        "Revoke (write) vs RestoreAccess (write) should conflict"
    );
}

// ---------------------------------------------------------------------------
// 17. non_conflicting_actions
// ---------------------------------------------------------------------------

#[tokio::test]
async fn non_conflicting_actions() {
    // ChangeRole for different DIDs.
    let action_a = GovernanceAction::ChangeRole {
        did: bob(),
        new_role: "admin".to_owned(),
    };
    let action_b = GovernanceAction::ChangeRole {
        did: carol(),
        new_role: "member".to_owned(),
    };
    assert!(
        !actions_conflict(&action_a, &alice(), &action_b, &alice()),
        "ChangeRole for different DIDs should not conflict"
    );

    // AddMember and ChangeRole for different DIDs.
    let add = GovernanceAction::AddMember {
        did: dave(),
        role: "member".to_owned(),
    };
    let change = GovernanceAction::ChangeRole {
        did: bob(),
        new_role: "admin".to_owned(),
    };
    assert!(
        !actions_conflict(&add, &alice(), &change, &carol()),
        "AddMember and ChangeRole for different DIDs should not conflict"
    );

    // CloseContext and ExtendTtl.
    let close = GovernanceAction::CloseContext { reason: None };
    let extend = GovernanceAction::ExtendTtl {
        additional_secs: 3600,
    };
    assert!(
        !actions_conflict(&close, &alice(), &extend, &bob()),
        "CloseContext and ExtendTtl should not conflict"
    );

    // Non-mutual RemoveMember (Alice removes Bob, Carol removes Dave).
    let remove_a = GovernanceAction::RemoveMember {
        did: bob(),
        reason: None,
        induced_rotations: Vec::new(),
    };
    let remove_b = GovernanceAction::RemoveMember {
        did: dave(),
        reason: None,
        induced_rotations: Vec::new(),
    };
    assert!(
        !actions_conflict(&remove_a, &alice(), &remove_b, &carol()),
        "RemoveMember targeting different DIDs (not mutual) should not conflict"
    );
}

// ---------------------------------------------------------------------------
// 18. deadlock_detection
// ---------------------------------------------------------------------------

#[tokio::test]
async fn deadlock_detection() {
    // Threshold: 3-of-3 signers, but only 2 are active members.
    let signers = vec![alice(), bob(), carol()];
    let engine = ThresholdEngine::new(signers, 3, 86_400, mock_resolver()).unwrap();

    let ctx = governance_context_for_members(
        "ctx-deadlock",
        &[(alice(), "admin"), (bob(), "admin")], // carol departed
        &[alice(), bob()],
        1_700_000_000,
    );

    let detection_state = DeadlockDetectionState::default();
    let conditions = detect_deadlock(&engine, &ctx, &detection_state);

    assert_eq!(conditions.len(), 1);
    assert!(
        matches!(
            &conditions[0],
            DeadlockCondition::ThresholdInsufficient {
                threshold: 3,
                active_signers: 2,
                ..
            }
        ),
        "expected ThresholdInsufficient, got {:?}",
        conditions[0]
    );
}

// ---------------------------------------------------------------------------
// 19. governance_event_variants
// ---------------------------------------------------------------------------

#[tokio::test]
async fn governance_event_variants() {
    // Construct each variant and verify pattern matching works.
    let events: Vec<GovernanceEvent> = vec![
        GovernanceEvent::ProposalCreated {
            proposal_id: [1u8; 32],
            proposer_did: alice(),
            action: Box::new(GovernanceAction::CloseContext { reason: None }),
            voting_deadline: 1_700_000_000,
        },
        GovernanceEvent::VoteCast {
            proposal_id: [1u8; 32],
            voter_did: bob(),
            vote: VoteType::Approve,
        },
        GovernanceEvent::VoteWithdrawn {
            proposal_id: [1u8; 32],
            voter_did: bob(),
        },
        GovernanceEvent::ProposalResolved {
            proposal_id: [1u8; 32],
            status: ProposalStatus::Approved,
        },
        GovernanceEvent::DeadlockRecovery {
            justification: DeadlockJustification {
                unavailable_dids: vec![carol()],
                missed_windows: vec![],
                detected_at: 1_700_000_000,
            },
            changes: vec![GovernanceReconfigAction::RemoveInactiveSigner { did: carol() }],
        },
        GovernanceEvent::ConflictDetected {
            proposal_a: [1u8; 32],
            proposal_b: [2u8; 32],
        },
        GovernanceEvent::ConflictResolved {
            winner_id: [1u8; 32],
            loser_id: [2u8; 32],
        },
    ];

    // Verify all 7 event types are represented.
    assert_eq!(events.len(), 7, "must cover all 7 GovernanceEvent variants");

    // Verify each can be serialized.
    for event in &events {
        let json = serde_json::to_string(event).expect("serialize");
        let _: GovernanceEvent = serde_json::from_str(&json).expect("deserialize");
    }
}

// ---------------------------------------------------------------------------
// 20. revocation_scope_variants
// ---------------------------------------------------------------------------

#[tokio::test]
async fn revocation_scope_variants() {
    // Verify the three AccessScope variants for content access actions.
    let read = AccessScope::Read;
    let write = AccessScope::Write;
    let both = AccessScope::Both;

    assert_ne!(read, write);
    assert_ne!(read, both);

    // Revoke with Read scope.
    let action_read = GovernanceAction::RevokeAccess {
        did: bob(),
        access: AccessScope::Read,
    };
    let json_read = serde_json::to_string(&action_read).unwrap();
    let deser_read: GovernanceAction = serde_json::from_str(&json_read).unwrap();
    assert_eq!(
        serde_json::to_string(&deser_read).unwrap(),
        json_read,
        "Read scope roundtrip"
    );

    // Revoke with Write scope.
    let action_write = GovernanceAction::RevokeAccess {
        did: bob(),
        access: AccessScope::Write,
    };
    let json_write = serde_json::to_string(&action_write).unwrap();
    let deser_write: GovernanceAction = serde_json::from_str(&json_write).unwrap();
    assert_eq!(
        serde_json::to_string(&deser_write).unwrap(),
        json_write,
        "Write scope roundtrip"
    );

    // Conflicting scopes on same DID.
    let revoke_both = GovernanceAction::RevokeAccess {
        did: bob(),
        access: AccessScope::Both,
    };
    let revoke_write = GovernanceAction::RevokeAccess {
        did: bob(),
        access: AccessScope::Write,
    };
    assert!(
        actions_conflict(&revoke_both, &alice(), &revoke_write, &carol()),
        "same DID + different scopes should conflict"
    );
}

// ---------------------------------------------------------------------------
// 21. economic_governance_actions
// ---------------------------------------------------------------------------

#[tokio::test]
async fn economic_governance_actions() {
    let mut engine = SingleAdminEngine::new(alice(), mock_resolver());
    let ctx = governance_context_for_members(
        "ctx-econ",
        &[(alice(), "admin"), (bob(), "member")],
        &[alice()],
        1_700_000_000,
    );

    // SetEconomicPolicy.
    let (proposal, _) = engine
        .propose(
            &alice(),
            GovernanceAction::SetEconomicPolicy {
                policy: simple_economic_policy(),
            },
            &ctx,
            &sk_for(1),
        )
        .unwrap();
    assert_eq!(
        proposal.status,
        ProposalStatus::Approved,
        "SetEconomicPolicy should auto-approve for admin"
    );

    // ApproveSpend.
    let ctx2 = GovernanceContext {
        now: ctx.now + 1,
        ..ctx.clone()
    };
    let (proposal, _) = engine
        .propose(
            &alice(),
            GovernanceAction::ApproveSpend {
                spender: bob(),
                amount: Amount::new(500),
                purpose: "computation costs".to_owned(),
            },
            &ctx2,
            &sk_for(1),
        )
        .unwrap();
    assert_eq!(
        proposal.status,
        ProposalStatus::Approved,
        "ApproveSpend should auto-approve for admin"
    );

    // LockEconomicPolicy.
    let ctx3 = GovernanceContext {
        now: ctx.now + 2,
        ..ctx.clone()
    };
    let (proposal, _) = engine
        .propose(
            &alice(),
            GovernanceAction::LockEconomicPolicy,
            &ctx3,
            &sk_for(1),
        )
        .unwrap();
    assert_eq!(
        proposal.status,
        ProposalStatus::Approved,
        "LockEconomicPolicy should auto-approve for admin"
    );
}
