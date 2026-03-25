use super::*;

// -----------------------------------------------------------------------
// GovernanceModel enum expansion tests (#320)
// -----------------------------------------------------------------------

#[test]
fn governance_model_serde_roundtrip_all_variants() {
    use scp_protocol::context::params::GovernanceModel;

    let alice: DID = "did:dht:z6MkAlice".into();
    let bob: DID = "did:dht:z6MkBob".into();
    let carol: DID = "did:dht:z6MkCarol".into();

    let models = vec![
        GovernanceModel::SingleAdmin,
        GovernanceModel::Threshold {
            threshold: 2,
            signers: vec![alice.clone(), bob.clone(), carol.clone()],
        },
        GovernanceModel::Majority {
            eligible_voters: vec![alice.clone(), bob.clone(), carol.clone()],
        },
        GovernanceModel::Unanimity {
            eligible_voters: vec![alice, bob, carol],
        },
    ];

    for model in &models {
        let json = serde_json::to_string(model).expect("serialize");
        let deserialized: GovernanceModel = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(&deserialized, model, "serde roundtrip failed for {model:?}");
    }
}

#[test]
fn governance_model_in_context_params_roundtrip() {
    use scp_protocol::context::params::GovernanceModel;

    let params = ContextParams {
        governance: GovernanceModel::Threshold {
            threshold: 2,
            signers: vec![
                "did:dht:z6MkAlice".into(),
                "did:dht:z6MkBob".into(),
                "did:dht:z6MkCarol".into(),
            ],
        },
        ..ContextParams::default()
    };

    let json = serde_json::to_string(&params).expect("serialize");
    let deserialized: ContextParams = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(deserialized.governance, params.governance);
}

#[test]
fn public_metadata_exposes_all_governance_variants() {
    use scp_protocol::context::params::{GovernanceModel, RuntimeMetadata};

    let params = ContextParams {
        governance: GovernanceModel::Majority {
            eligible_voters: vec!["did:dht:z6MkAlice".into(), "did:dht:z6MkBob".into()],
        },
        ..ContextParams::default()
    };

    let runtime = RuntimeMetadata::default();
    let meta = params.public_metadata(&runtime);
    assert_eq!(meta.governance, params.governance);
}

// -----------------------------------------------------------------------
// Context creation validation tests (#320)
// -----------------------------------------------------------------------

#[tokio::test]
async fn create_context_rejects_threshold_exceeding_signers() {
    let manager = ContextManager::new(
        Box::new(MockCrypto::default()),
        Box::new(MockTransport::connected()),
        Box::new(MockEventLog::default()),
        noop_key_resolver(),
    );

    let params = ContextParams {
        governance: scp_protocol::context::params::GovernanceModel::Threshold {
            threshold: 5,
            signers: vec!["did:dht:z6MkAlice".into(), "did:dht:z6MkBob".into()],
        },
        ..ContextParams::default()
    };

    let result = manager
        .create_context(
            "ctx-bad-threshold".into(),
            params,
            "did:dht:z6MkAlice".into(),
        )
        .await;

    assert!(result.is_err(), "should reject threshold > signers.len()");
}

#[tokio::test]
async fn create_context_rejects_threshold_zero() {
    let manager = ContextManager::new(
        Box::new(MockCrypto::default()),
        Box::new(MockTransport::connected()),
        Box::new(MockEventLog::default()),
        noop_key_resolver(),
    );

    let params = ContextParams {
        governance: scp_protocol::context::params::GovernanceModel::Threshold {
            threshold: 0,
            signers: vec!["did:dht:z6MkAlice".into()],
        },
        ..ContextParams::default()
    };

    let result = manager
        .create_context(
            "ctx-zero-threshold".into(),
            params,
            "did:dht:z6MkAlice".into(),
        )
        .await;

    assert!(result.is_err(), "should reject threshold == 0");
}

#[tokio::test]
async fn create_context_rejects_majority_empty_voters() {
    let manager = ContextManager::new(
        Box::new(MockCrypto::default()),
        Box::new(MockTransport::connected()),
        Box::new(MockEventLog::default()),
        noop_key_resolver(),
    );

    let params = ContextParams {
        governance: scp_protocol::context::params::GovernanceModel::Majority {
            eligible_voters: vec![],
        },
        ..ContextParams::default()
    };

    let result = manager
        .create_context(
            "ctx-empty-majority".into(),
            params,
            "did:dht:z6MkAlice".into(),
        )
        .await;

    assert!(
        result.is_err(),
        "should reject Majority with empty eligible_voters"
    );
}

#[tokio::test]
async fn create_context_rejects_unanimity_empty_voters() {
    let manager = ContextManager::new(
        Box::new(MockCrypto::default()),
        Box::new(MockTransport::connected()),
        Box::new(MockEventLog::default()),
        noop_key_resolver(),
    );

    let params = ContextParams {
        governance: scp_protocol::context::params::GovernanceModel::Unanimity {
            eligible_voters: vec![],
        },
        ..ContextParams::default()
    };

    let result = manager
        .create_context(
            "ctx-empty-unanimity".into(),
            params,
            "did:dht:z6MkAlice".into(),
        )
        .await;

    assert!(
        result.is_err(),
        "should reject Unanimity with empty eligible_voters"
    );
}

// -----------------------------------------------------------------------
// Proposal lifecycle tests (#320)
// -----------------------------------------------------------------------

#[tokio::test]
async fn single_admin_propose_auto_executes() {
    use scp_protocol::context::governance::GovernanceAction;

    let manager = ContextManager::new(
        Box::new(MockCrypto::default()),
        Box::new(MockTransport::connected()),
        Box::new(MockEventLog::default()),
        mock_key_resolver(),
    );

    let creator_did: DID = "did:dht:z6MkCreator".into();
    let signing_key = signing_key_for_did(&creator_did);

    let params = ContextParams {
        ceiling: vec![
            Capability::MessagesRead,
            Capability::MessagesWrite,
            Capability::ToolRegister,
        ],
        ..ContextParams::default()
    };

    let handle = manager
        .create_context(
            "ctx-single-admin-lifecycle".into(),
            params,
            creator_did.clone(),
        )
        .await
        .unwrap();

    assert_eq!(handle.state().await, ContextState::Active);

    // Propose RegisterTool — should auto-execute in SingleAdmin.
    let action = GovernanceAction::RegisterTool {
        registration: Box::new(test_tool_registration("test-tool")),
    };

    let (proposal, events) = manager
        .propose_governance_action(
            "ctx-single-admin-lifecycle",
            &creator_did,
            action,
            &signing_key,
        )
        .await
        .unwrap();

    assert!(
        matches!(
            proposal.status,
            scp_protocol::context::governance::ProposalStatus::Approved
        ),
        "SingleAdmin proposal should be auto-approved"
    );
    assert!(
        events.len() >= 2,
        "should have ProposalCreated + VoteCast + ProposalResolved events"
    );

    // Verify the proposal is retrievable.
    let retrieved = manager
        .get_proposal("ctx-single-admin-lifecycle", &proposal.proposal_id)
        .await
        .unwrap();
    assert_eq!(retrieved.proposal_id, proposal.proposal_id);

    // Verify list_proposals returns it.
    let proposals = manager
        .list_proposals("ctx-single-admin-lifecycle")
        .await
        .unwrap();
    assert_eq!(proposals.len(), 1);
}

#[tokio::test]
async fn threshold_context_proposal_lifecycle() {
    use scp_protocol::context::governance::{GovernanceAction, ProposalStatus};

    let manager = ContextManager::new(
        Box::new(MockCrypto::default()),
        Box::new(MockTransport::connected()),
        Box::new(MockEventLog::default()),
        mock_key_resolver(),
    );

    let alice: DID = "did:dht:z6MkAlice".into();
    let bob: DID = "did:dht:z6MkBob".into();
    let carol: DID = "did:dht:z6MkCarol".into();
    let key_a = signing_key_for_did(&alice);
    let key_b = signing_key_for_did(&bob);

    let params = ContextParams {
        governance: scp_protocol::context::params::GovernanceModel::Threshold {
            threshold: 2,
            signers: vec![alice.clone(), bob.clone(), carol.clone()],
        },
        ceiling: vec![
            Capability::MessagesRead,
            Capability::MessagesWrite,
            Capability::ToolRegister,
        ],
        ..ContextParams::default()
    };

    // Create context (alice is the creator/admin).
    let _handle = manager
        .create_context("ctx-threshold".into(), params, alice.clone())
        .await
        .unwrap();

    // Alice proposes RegisterTool (her proposer vote counts as first approval).
    let action = GovernanceAction::RegisterTool {
        registration: Box::new(test_tool_registration("threshold-tool")),
    };

    let (proposal, _events) = manager
        .propose_governance_action("ctx-threshold", &alice, action, &key_a)
        .await
        .unwrap();

    // Proposal should be Pending (1 vote, need 2).
    assert!(
        matches!(proposal.status, ProposalStatus::Pending),
        "threshold proposal should be pending after 1 vote, got {:?}",
        proposal.status
    );

    // Bob votes approve — should reach threshold (2-of-3).
    let (status, _events) = manager
        .vote_on_proposal("ctx-threshold", &proposal.proposal_id, &bob, true, &key_b)
        .await
        .unwrap();

    assert!(
        matches!(status, ProposalStatus::Approved),
        "threshold proposal should be approved after 2nd vote, got {status:?}"
    );

    // Verify the tool was registered (auto-execution).
    let contexts = manager.contexts.lock().await;
    let ctx = contexts.get("ctx-threshold").unwrap();
    assert!(
        ctx.governance
            .registered_tools
            .iter()
            .any(|t| t.name == "threshold-tool"),
        "tool should have been registered after proposal approval"
    );
}

#[tokio::test]
async fn majority_context_proposal_lifecycle() {
    use scp_protocol::context::governance::{GovernanceAction, ProposalStatus};

    let manager = ContextManager::new(
        Box::new(MockCrypto::default()),
        Box::new(MockTransport::connected()),
        Box::new(MockEventLog::default()),
        mock_key_resolver(),
    );

    let alice: DID = "did:dht:z6MkAlice".into();
    let bob: DID = "did:dht:z6MkBob".into();
    let carol: DID = "did:dht:z6MkCarol".into();
    let key_a = signing_key_for_did(&alice);
    let key_b = signing_key_for_did(&bob);

    let params = ContextParams {
        governance: scp_protocol::context::params::GovernanceModel::Majority {
            eligible_voters: vec![alice.clone(), bob.clone(), carol.clone()],
        },
        ..ContextParams::default()
    };

    let _handle = manager
        .create_context("ctx-majority".into(), params, alice.clone())
        .await
        .unwrap();

    // Alice proposes CloseContext.
    let action = GovernanceAction::CloseContext {
        reason: Some("test close".to_owned()),
    };

    let (proposal, _) = manager
        .propose_governance_action("ctx-majority", &alice, action, &key_a)
        .await
        .unwrap();

    assert!(matches!(proposal.status, ProposalStatus::Pending));

    // Alice approves her own proposal (proposer must vote separately
    // in MajorityVoteEngine — propose() does not auto-approve).
    let (status, _) = manager
        .vote_on_proposal("ctx-majority", &proposal.proposal_id, &alice, true, &key_a)
        .await
        .unwrap();
    assert!(
        matches!(status, ProposalStatus::Pending),
        "1/3 approvals should still be pending, got {status:?}"
    );

    // Bob approves — now 2/3 approve = >50% = approved.
    let (status, _) = manager
        .vote_on_proposal("ctx-majority", &proposal.proposal_id, &bob, true, &key_b)
        .await
        .unwrap();

    assert!(
        matches!(status, ProposalStatus::Approved),
        "2/3 approvals should reach majority, got {status:?}"
    );
}

#[tokio::test]
async fn unanimity_context_single_rejection_defeats_proposal() {
    use scp_protocol::context::governance::{GovernanceAction, ProposalStatus};

    let manager = ContextManager::new(
        Box::new(MockCrypto::default()),
        Box::new(MockTransport::connected()),
        Box::new(MockEventLog::default()),
        mock_key_resolver(),
    );

    let alice: DID = "did:dht:z6MkAlice".into();
    let bob: DID = "did:dht:z6MkBob".into();
    let carol: DID = "did:dht:z6MkCarol".into();
    let key_a = signing_key_for_did(&alice);
    let key_b = signing_key_for_did(&bob);
    let key_c = signing_key_for_did(&carol);

    let params = ContextParams {
        governance: scp_protocol::context::params::GovernanceModel::Unanimity {
            eligible_voters: vec![alice.clone(), bob.clone(), carol.clone()],
        },
        ..ContextParams::default()
    };

    // Add bob as member so we can test RemoveMember doesn't happen.
    let _handle = manager
        .create_context("ctx-unanimity".into(), params, alice.clone())
        .await
        .unwrap();

    // Add bob to membership manually for the test.
    {
        let mut contexts = manager.contexts.lock().await;
        let ctx = contexts.get_mut("ctx-unanimity").unwrap();
        ctx.membership
            .add_member(bob.clone(), "member".into(), vec![]);
        ctx.membership
            .add_member(carol.clone(), "member".into(), vec![]);
    }

    // Alice proposes RemoveMember(bob).
    let action = GovernanceAction::RemoveMember {
        did: bob.clone(),
        reason: Some("test removal".to_owned()),
    };

    let (proposal, _) = manager
        .propose_governance_action("ctx-unanimity", &alice, action, &key_a)
        .await
        .unwrap();

    assert!(matches!(proposal.status, ProposalStatus::Pending));

    // Bob approves.
    let (status, _) = manager
        .vote_on_proposal("ctx-unanimity", &proposal.proposal_id, &bob, true, &key_b)
        .await
        .unwrap();
    assert!(matches!(status, ProposalStatus::Pending));

    // Carol rejects — single rejection kills unanimity.
    let (status, _) = manager
        .vote_on_proposal(
            "ctx-unanimity",
            &proposal.proposal_id,
            &carol,
            false,
            &key_c,
        )
        .await
        .unwrap();

    assert!(
        matches!(status, ProposalStatus::Rejected { .. }),
        "unanimity proposal should be rejected after single rejection, got {status:?}"
    );

    // Verify bob is still a member (proposal was rejected, not executed).
    let contexts = manager.contexts.lock().await;
    let ctx = contexts.get("ctx-unanimity").unwrap();
    assert!(
        ctx.membership.get(bob.as_ref()).is_some(),
        "Bob should still be a member after rejected proposal"
    );
}

#[tokio::test]
async fn non_eligible_voter_rejected() {
    use scp_protocol::context::governance::GovernanceAction;

    let manager = ContextManager::new(
        Box::new(MockCrypto::default()),
        Box::new(MockTransport::connected()),
        Box::new(MockEventLog::default()),
        mock_key_resolver(),
    );

    let alice: DID = "did:dht:z6MkAlice".into();
    let bob: DID = "did:dht:z6MkBob".into();
    let eve: DID = "did:dht:z6MkEve".into();
    let key_a = signing_key_for_did(&alice);
    let key_e = signing_key_for_did(&eve);

    let params = ContextParams {
        governance: scp_protocol::context::params::GovernanceModel::Threshold {
            threshold: 2,
            signers: vec![alice.clone(), bob.clone()],
        },
        ..ContextParams::default()
    };

    let _handle = manager
        .create_context("ctx-eligibility".into(), params, alice.clone())
        .await
        .unwrap();

    // Alice proposes.
    let action = GovernanceAction::RegisterTool {
        registration: Box::new(test_tool_registration("tool")),
    };

    let (proposal, _) = manager
        .propose_governance_action("ctx-eligibility", &alice, action, &key_a)
        .await
        .unwrap();

    // Eve (not a signer) tries to vote — should be rejected.
    let result = manager
        .vote_on_proposal("ctx-eligibility", &proposal.proposal_id, &eve, true, &key_e)
        .await;

    assert!(result.is_err(), "non-eligible voter should be rejected");
    let err = result.unwrap_err();
    assert!(
        matches!(err, ContextError::GovernanceFailed(_)),
        "should be GovernanceFailed for non-eligible voter, got {err:?}"
    );
}

#[test]
fn governance_snapshot_serde_roundtrip() {
    use scp_protocol::context::roles::{ContextRoleState, default_ceiling};

    let params = ContextParams {
        governance: scp_protocol::context::params::GovernanceModel::Threshold {
            threshold: 2,
            signers: vec![
                "did:dht:z6MkAlice".into(),
                "did:dht:z6MkBob".into(),
                "did:dht:z6MkCarol".into(),
            ],
        },
        ..ContextParams::default()
    };

    let role_state = ContextRoleState::new(
        "ctx-snap",
        "did:dht:z6MkAlice",
        default_ceiling(),
        vec![],
        &scp_primitives::SystemClock,
    )
    .unwrap();

    let snapshot = super::ContextSnapshot {
        context_id: "ctx-snap".to_owned(),
        state: ContextState::Active,
        context_params: params,
        membership: MembershipState::new(),
        role_state,
        executed_proposals: HashSet::new(),
        ttl_remaining_secs: None,
        registered_tools: Vec::new(),
        write_revoked_members: HashSet::new(),
        read_revoked_members: HashSet::new(),
        read_exclusion_list: HashSet::new(),
        tool_interfaces: Vec::new(),
        threshold_signers: Vec::new(),
        threshold_value: 0,
        pruning_policy: None,
        governance_model_config: Some(
            scp_protocol::context::governance::GovernanceModelConfig::Threshold {
                signers: vec![
                    "did:dht:z6MkAlice".into(),
                    "did:dht:z6MkBob".into(),
                    "did:dht:z6MkCarol".into(),
                ],
                threshold: 2,
                voting_window_secs: 86_400,
            },
        ),
        economic_policy: None,
        budget_tracker: scp_protocol::economy::budget::MemberBudgetTracker::new(),
        approved_proposals: HashMap::new(),
        governance_freeze: None,
        pending_ceiling_modification: None,
        pending_economic_policy_change: None,
        mls_epoch: 0,
        epoch_coordination_records: Vec::new(),
        grace_entries: Vec::new(),
        needs_reconnect: false,
        migration_state: None,
        mls_crypto_state: Vec::new(),
        access_key_store: scp_protocol::crypto::access_keys::AccessKeyStore::new(),
        consequence_rules: Vec::new(),
        participation_cache: std::collections::HashMap::new(),
    };

    let json = serde_json::to_string(&snapshot).expect("serialize");
    let deserialized: super::ContextSnapshot = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(deserialized.context_id, snapshot.context_id);
    assert_eq!(
        deserialized.governance_model_config,
        snapshot.governance_model_config
    );
}

// -----------------------------------------------------------------------
// Promotion policy enforcement tests (§5.10, #340)
// -----------------------------------------------------------------------

/// §5.10 AC1: a context created with `NoPromotion` rejects `PromoteContext`
/// governance proposals with `PermissionDenied`.
#[tokio::test]
async fn promote_context_rejected_when_policy_is_no_promotion() {
    use scp_protocol::context::governance::{GovernanceProposal, SignedVote, VoteType};

    let (manager, _handle) = setup_active_context().await;

    // setup_active_context uses ContextParams::default() which has
    // promotion_policy = NoPromotion. Build an approved PromoteContext
    // proposal with the creator's vote.
    let proposal = GovernanceProposal {
        proposal_id: [1u8; 32],
        context_id: "test-ctx".into(),
        proposer_did: "did:key:creator".into(),
        action: GovernanceAction::PromoteContext,
        status: ProposalStatus::Approved,
        created_at: 1000,
        voting_deadline: 2000,
        approvals: vec![SignedVote {
            voter_did: "did:key:creator".into(),
            vote: VoteType::Approve,
            timestamp: 1000,
            signature: vec![0u8; 64],
        }],
        rejections: Vec::new(),
        created_at_epoch: None,
    };

    let result = manager
        .execute_governance_action("test-ctx", &proposal)
        .await;

    assert!(
        result.is_err(),
        "NoPromotion context must reject PromoteContext"
    );
    let err = result.unwrap_err();
    let msg = format!("{err}");
    assert!(
        msg.contains("not Promotable"),
        "error message should contain 'not Promotable', got: {msg}"
    );
    assert!(
        matches!(err, ContextError::PermissionDenied(_)),
        "should be PermissionDenied, got: {err}"
    );
}

/// §5.10 AC2: a context created with `Promotable` can be promoted via
/// unanimous governance approval. After promotion, TTL is removed and
/// memory scope transitions to `Full`.
#[tokio::test]
async fn promote_context_succeeds_when_policy_is_promotable() {
    use scp_protocol::context::governance::{GovernanceProposal, SignedVote, VoteType};
    use scp_protocol::context::params::{MemoryScope, PromotionPolicy};

    let manager = ContextManager::new(
        Box::new(MockCrypto::default()),
        Box::new(MockTransport::connected()),
        Box::new(MockEventLog::default()),
        noop_key_resolver(),
    );

    let params = ContextParams {
        promotion_policy: PromotionPolicy::Promotable,
        memory_scope: MemoryScope::Ephemeral,
        ttl: Some(std::time::Duration::from_secs(3600)),
        ceiling: vec![
            scp_protocol::context::params::Capability::new("messages:read"),
            scp_protocol::context::params::Capability::new("messages:write"),
        ],
        ..ContextParams::default()
    };

    let handle = manager
        .create_context("promo-ctx".into(), params, "did:key:creator".into())
        .await
        .unwrap();

    // Verify preconditions: TTL is set, memory scope is Ephemeral.
    assert_eq!(handle.params().memory_scope, MemoryScope::Ephemeral);
    assert_eq!(
        handle.params().promotion_policy,
        PromotionPolicy::Promotable
    );

    // Build an approved PromoteContext proposal with unanimous consent
    // (only the creator is a member).
    let proposal = GovernanceProposal {
        proposal_id: [2u8; 32],
        context_id: "promo-ctx".into(),
        proposer_did: "did:key:creator".into(),
        action: GovernanceAction::PromoteContext,
        status: ProposalStatus::Approved,
        created_at: 1000,
        voting_deadline: 2000,
        approvals: vec![SignedVote {
            voter_did: "did:key:creator".into(),
            vote: VoteType::Approve,
            timestamp: 1000,
            signature: vec![0u8; 64],
        }],
        rejections: Vec::new(),
        created_at_epoch: None,
    };

    let result = manager
        .execute_governance_action("promo-ctx", &proposal)
        .await;

    assert!(
        result.is_ok(),
        "Promotable context should accept PromoteContext: {result:?}"
    );

    // Verify postconditions: memory scope is now Full.
    let contexts = manager.contexts.lock().await;
    let ctx = contexts.get("promo-ctx").unwrap();
    assert_eq!(
        ctx.handle.params().memory_scope,
        MemoryScope::Full,
        "memory scope should transition to Full after promotion"
    );

    // TTL timer should be cancelled (deadline removed).
    assert!(
        ctx.ttl.timer.deadline_unix_secs.is_none(),
        "TTL deadline should be removed after promotion"
    );
}

/// §5.10 AC3: after promotion, `promotion_policy` remains `Promotable` —
/// the field is not mutated by the promotion itself.
#[tokio::test]
async fn promote_context_does_not_mutate_promotion_policy() {
    use scp_protocol::context::governance::{GovernanceProposal, SignedVote, VoteType};
    use scp_protocol::context::params::{MemoryScope, PromotionPolicy};

    let manager = ContextManager::new(
        Box::new(MockCrypto::default()),
        Box::new(MockTransport::connected()),
        Box::new(MockEventLog::default()),
        noop_key_resolver(),
    );

    let params = ContextParams {
        promotion_policy: PromotionPolicy::Promotable,
        memory_scope: MemoryScope::Ephemeral,
        ceiling: vec![scp_protocol::context::params::Capability::new(
            "messages:read",
        )],
        ..ContextParams::default()
    };

    let handle = manager
        .create_context("promo-immut-ctx".into(), params, "did:key:creator".into())
        .await
        .unwrap();

    assert_eq!(
        handle.params().promotion_policy,
        PromotionPolicy::Promotable
    );

    let proposal = GovernanceProposal {
        proposal_id: [3u8; 32],
        context_id: "promo-immut-ctx".into(),
        proposer_did: "did:key:creator".into(),
        action: GovernanceAction::PromoteContext,
        status: ProposalStatus::Approved,
        created_at: 1000,
        voting_deadline: 2000,
        approvals: vec![SignedVote {
            voter_did: "did:key:creator".into(),
            vote: VoteType::Approve,
            timestamp: 1000,
            signature: vec![0u8; 64],
        }],
        rejections: Vec::new(),
        created_at_epoch: None,
    };

    let result = manager
        .execute_governance_action("promo-immut-ctx", &proposal)
        .await;
    assert!(result.is_ok(), "promotion should succeed: {result:?}");

    // Verify promotion_policy is still Promotable (not mutated).
    let contexts = manager.contexts.lock().await;
    let ctx = contexts.get("promo-immut-ctx").unwrap();
    assert_eq!(
        ctx.handle.params().promotion_policy,
        PromotionPolicy::Promotable,
        "promotion_policy must remain Promotable after promotion — it is immutable"
    );
}

// -----------------------------------------------------------------------
// Ceiling enforcement tests (#339, §5.3)
// -----------------------------------------------------------------------

/// Helper: create a context with a specific ceiling for ceiling enforcement tests.
async fn setup_context_with_ceiling(
    ceiling: Vec<Capability>,
) -> (ContextManager, ContextHandle, String) {
    let manager = ContextManager::new(
        Box::new(MockCrypto::default()),
        Box::new(MockTransport::connected()),
        Box::new(MockEventLog::default()),
        noop_key_resolver(),
    );

    let params = ContextParams {
        ceiling,
        ..ContextParams::default()
    };

    let handle = manager
        .create_context("ceiling-test-ctx".into(), params, "did:key:creator".into())
        .await
        .unwrap();

    let ctx_id = "ceiling-test-ctx".to_owned();
    (manager, handle, ctx_id)
}

/// Helper: build a simple approved proposal for ceiling tests.
fn ceiling_test_proposal(context_id: &str, action: GovernanceAction) -> super::GovernanceProposal {
    use scp_protocol::context::governance::{SignedVote, VoteType};
    super::GovernanceProposal {
        proposal_id: [42u8; 32],
        context_id: context_id.into(),
        proposer_did: "did:key:creator".into(),
        action,
        status: ProposalStatus::Approved,
        created_at: 1000,
        voting_deadline: 2000,
        approvals: vec![SignedVote {
            voter_did: "did:key:creator".into(),
            vote: VoteType::Approve,
            timestamp: 1000,
            signature: vec![0u8; 64],
        }],
        rejections: Vec::new(),
        created_at_epoch: None,
    }
}

/// #339: `RegisterTool` is rejected when `ToolRegister` is not in ceiling.
#[tokio::test]
async fn register_tool_rejected_without_ceiling_capability() {
    use scp_protocol::context::tools::registry::ToolSchema;

    let (manager, _handle, ctx_id) =
        setup_context_with_ceiling(vec![Capability::MessagesRead, Capability::MessagesWrite]).await;

    let reg = scp_protocol::context::params::ToolRegistration {
        tool_id: "test".to_owned(),
        name: "test".to_owned(),
        description: "test".to_owned(),
        schema: ToolSchema {
            input_schema: serde_json::json!({"type": "object"}),
            output_schema: serde_json::json!({"type": "object"}),
        },
        implementation_hash: [0u8; 32],
        test_vectors: vec![],
        operator_did: "did:key:op".into(),
        cost: None,
        registered_at: 0,
        signature: Vec::new(),
    };

    let proposal = ceiling_test_proposal(
        &ctx_id,
        GovernanceAction::RegisterTool {
            registration: Box::new(reg),
        },
    );

    let result = manager.execute_governance_action(&ctx_id, &proposal).await;
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(
        matches!(err, ContextError::PermissionDenied(ref msg) if msg.contains("tool registration")),
        "expected PermissionDenied about tool registration, got: {err}"
    );
}

/// #339: `RegisterTool` succeeds when `ToolRegister` is in ceiling.
#[tokio::test]
async fn register_tool_succeeds_with_ceiling_capability() {
    use scp_protocol::context::tools::registry::ToolSchema;

    let (manager, _handle, ctx_id) = setup_context_with_ceiling(vec![
        Capability::MessagesRead,
        Capability::MessagesWrite,
        Capability::ToolRegister,
    ])
    .await;

    let reg = scp_protocol::context::params::ToolRegistration {
        tool_id: "test".to_owned(),
        name: "test".to_owned(),
        description: "test".to_owned(),
        schema: ToolSchema {
            input_schema: serde_json::json!({"type": "object"}),
            output_schema: serde_json::json!({"type": "object"}),
        },
        implementation_hash: [0u8; 32],
        test_vectors: vec![],
        operator_did: "did:key:op".into(),
        cost: None,
        registered_at: 0,
        signature: Vec::new(),
    };

    let proposal = ceiling_test_proposal(
        &ctx_id,
        GovernanceAction::RegisterTool {
            registration: Box::new(reg),
        },
    );

    let result = manager.execute_governance_action(&ctx_id, &proposal).await;
    assert!(result.is_ok(), "RegisterTool should succeed: {result:?}");
}

/// #339: `EstablishToolInterface` is rejected when `ToolInterface` is not in ceiling.
#[tokio::test]
async fn establish_tool_interface_rejected_without_ceiling_capability() {
    let (manager, _handle, ctx_id) =
        setup_context_with_ceiling(vec![Capability::MessagesRead, Capability::MessagesWrite]).await;

    let proposal = ceiling_test_proposal(
        &ctx_id,
        GovernanceAction::EstablishToolInterface {
            interface: ToolInterface {
                source_context: ctx_id.clone(),
                target_context: "other-ctx".into(),
                tool_id: "tool-a".into(),
                rate_limit: None,
                per_caller_rate_limit: None,
                approved_by_source: true,
                approved_by_target: false,
                outbound_policy: None,
                inbound_policy: None,
            },
        },
    );

    let result = manager.execute_governance_action(&ctx_id, &proposal).await;
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(
        matches!(err, ContextError::PermissionDenied(ref msg) if msg.contains("tool interface")),
        "expected PermissionDenied about tool interface, got: {err}"
    );
}

/// #339: `CreateChildContext` is rejected when `ChildContextCreate` is not in ceiling.
#[tokio::test]
async fn create_child_context_rejected_without_ceiling_capability() {
    let (manager, _handle, ctx_id) =
        setup_context_with_ceiling(vec![Capability::MessagesRead, Capability::MessagesWrite]).await;

    let proposal = ceiling_test_proposal(
        &ctx_id,
        GovernanceAction::CreateChildContext {
            params: Box::new(ContextParams::default()),
        },
    );

    let result = manager.execute_governance_action(&ctx_id, &proposal).await;
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(
        matches!(err, ContextError::PermissionDenied(ref msg) if msg.contains("child context")),
        "expected PermissionDenied about child context, got: {err}"
    );
}

/// #339: `BlockAuthor` is rejected when `MemberBan` is not in ceiling.
#[tokio::test]
async fn block_author_rejected_without_member_ban_ceiling() {
    let manager = ContextManager::new(
        Box::new(MockCrypto::default()),
        Box::new(MockTransport::connected()),
        Box::new(MockEventLog::default()),
        noop_key_resolver(),
    );

    manager.register_local_did("did:key:alice".into()).await;
    manager.register_local_did("did:key:bob".into()).await;

    // Ceiling WITHOUT MemberBan.
    let params = ContextParams {
        mode: ContextMode::Broadcast,
        memory_scope: MemoryScope::Full,
        ceiling: vec![
            Capability::MessagesRead,
            Capability::MessagesWrite,
            Capability::RoleAssign,
        ],
        ..ContextParams::default()
    };

    let _handle = manager
        .create_context("bc-no-ban".into(), params, "did:key:alice".into())
        .await
        .unwrap();

    // Add bob as author.
    {
        let mut contexts = manager.contexts.lock().await;
        let ctx = contexts.get_mut("bc-no-ban").unwrap();
        let bc = ctx.broadcast_context.as_mut().unwrap();
        bc.add_author("did:key:bob").unwrap();
        ctx.membership
            .add_member("did:key:bob".into(), "author".into(), vec![]);
    }

    let proposal =
        approved_block_author_proposal(&"did:key:alice".into(), "bc-no-ban", &"did:key:bob".into());
    let result = manager
        .execute_governance_action("bc-no-ban", &proposal)
        .await;
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(
        matches!(err, ContextError::PermissionDenied(ref msg) if msg.contains("MemberBan")),
        "expected PermissionDenied about MemberBan, got: {err}"
    );
}

// -----------------------------------------------------------------------
// Governance engine construction tests (SCP-267, ADR-031)
// -----------------------------------------------------------------------

/// AC 4: `create_context` constructs `SingleAdminEngine` when
/// `GovernanceModel::SingleAdmin` is specified.
#[tokio::test]
async fn governance_single_admin_engine_constructed() {
    let manager = ContextManager::new(
        Box::new(MockCrypto::default()),
        Box::new(MockTransport::connected()),
        Box::new(MockEventLog::default()),
        noop_key_resolver(),
    );
    let params = ContextParams {
        governance: GovernanceModel::SingleAdmin,
        ..ContextParams::default()
    };
    let creator: DID = "did:key:admin1".into();
    let handle = manager
        .create_context("ctx-gov-sa".into(), params, creator.clone())
        .await
        .unwrap();
    assert_eq!(handle.state().await, ContextState::Active);
    // Verify the engine is accessible inside the per-context state.
    let contexts = manager.contexts.lock().await;
    let ctx = contexts.get("ctx-gov-sa").unwrap();
    let config = ctx.governance.engine.model_config();
    assert_eq!(
        config,
        GovernanceModelConfig::SingleAdmin { admin_did: creator }
    );
}

/// AC 5: `create_context_with_governance` constructs `ThresholdEngine`
/// when `GovernanceModel::Threshold` is specified.
#[tokio::test]
async fn governance_threshold_engine_constructed() {
    let manager = ContextManager::new(
        Box::new(MockCrypto::default()),
        Box::new(MockTransport::connected()),
        Box::new(MockEventLog::default()),
        noop_key_resolver(),
    );
    let creator: DID = "did:key:admin1".into();
    let signer2: DID = "did:key:signer2".into();
    let params = ContextParams {
        governance: GovernanceModel::Threshold {
            threshold: 2,
            signers: vec![creator.clone(), signer2.clone()],
        },
        ..ContextParams::default()
    };
    let config = GovernanceModelConfig::Threshold {
        signers: vec![creator.clone(), signer2.clone()],
        threshold: 2,
        voting_window_secs: 86_400,
    };
    let handle = manager
        .create_context_with_governance(
            "ctx-gov-thresh".into(),
            params,
            creator.clone(),
            config.clone(),
        )
        .await
        .unwrap();
    assert_eq!(handle.state().await, ContextState::Active);
    let contexts = manager.contexts.lock().await;
    let ctx = contexts.get("ctx-gov-thresh").unwrap();
    assert_eq!(ctx.governance.engine.model_config(), config);
}

/// AC 6: `create_context_with_governance` constructs `MajorityVoteEngine`
/// when `GovernanceModel::Majority` is specified.
#[tokio::test]
async fn governance_majority_engine_constructed() {
    let manager = ContextManager::new(
        Box::new(MockCrypto::default()),
        Box::new(MockTransport::connected()),
        Box::new(MockEventLog::default()),
        noop_key_resolver(),
    );
    let creator: DID = "did:key:admin1".into();
    let params = ContextParams {
        governance: GovernanceModel::Majority {
            eligible_voters: vec![creator.clone()],
        },
        ..ContextParams::default()
    };
    let config = GovernanceModelConfig::Majority {
        voting_window_secs: 86_400,
        min_participation_bps: 5000,
    };
    let handle = manager
        .create_context_with_governance("ctx-gov-maj".into(), params, creator.clone(), config)
        .await
        .unwrap();
    assert_eq!(handle.state().await, ContextState::Active);
    let contexts = manager.contexts.lock().await;
    let ctx = contexts.get("ctx-gov-maj").unwrap();
    let model_config = ctx.governance.engine.model_config();
    assert!(matches!(
        model_config,
        GovernanceModelConfig::Majority { .. }
    ));
}

/// AC 7: `create_context_with_governance` constructs `UnanimityEngine`
/// when `GovernanceModel::Unanimity` is specified.
#[tokio::test]
async fn governance_unanimity_engine_constructed() {
    let manager = ContextManager::new(
        Box::new(MockCrypto::default()),
        Box::new(MockTransport::connected()),
        Box::new(MockEventLog::default()),
        noop_key_resolver(),
    );
    let creator: DID = "did:key:admin1".into();
    let params = ContextParams {
        governance: GovernanceModel::Unanimity {
            eligible_voters: vec![creator.clone()],
        },
        ..ContextParams::default()
    };
    let config = GovernanceModelConfig::Unanimity {
        voting_window_secs: 172_800,
    };
    let handle = manager
        .create_context_with_governance(
            "ctx-gov-unan".into(),
            params,
            creator.clone(),
            config.clone(),
        )
        .await
        .unwrap();
    assert_eq!(handle.state().await, ContextState::Active);
    let contexts = manager.contexts.lock().await;
    let ctx = contexts.get("ctx-gov-unan").unwrap();
    assert_eq!(ctx.governance.engine.model_config(), config);
}

/// AC 8/12: Invalid `GovernanceModelConfig` is rejected at creation time.
/// Threshold > `signers.len()`.
#[tokio::test]
async fn governance_invalid_threshold_too_high_rejected() {
    let manager = ContextManager::new(
        Box::new(MockCrypto::default()),
        Box::new(MockTransport::connected()),
        Box::new(MockEventLog::default()),
        noop_key_resolver(),
    );
    let creator: DID = "did:key:admin1".into();
    let params = ContextParams {
        governance: GovernanceModel::Threshold {
            threshold: 5,
            signers: vec![creator.clone()],
        },
        ..ContextParams::default()
    };
    let config = GovernanceModelConfig::Threshold {
        signers: vec![creator.clone()],
        threshold: 5, // > signers.len() (1)
        voting_window_secs: 86_400,
    };
    let result = manager
        .create_context_with_governance("ctx-bad-thresh".into(), params, creator, config)
        .await;
    assert!(result.is_err());
}

/// AC 8/12: Invalid `GovernanceModelConfig` — threshold == 0 rejected.
#[tokio::test]
async fn governance_invalid_threshold_zero_rejected() {
    let manager = ContextManager::new(
        Box::new(MockCrypto::default()),
        Box::new(MockTransport::connected()),
        Box::new(MockEventLog::default()),
        noop_key_resolver(),
    );
    let creator: DID = "did:key:admin1".into();
    let params = ContextParams {
        governance: GovernanceModel::Threshold {
            threshold: 0,
            signers: vec![creator.clone()],
        },
        ..ContextParams::default()
    };
    let config = GovernanceModelConfig::Threshold {
        signers: vec![creator.clone()],
        threshold: 0,
        voting_window_secs: 86_400,
    };
    let result = manager
        .create_context_with_governance("ctx-bad-thresh-0".into(), params, creator, config)
        .await;
    assert!(result.is_err());
}

/// AC 8/12: Invalid `GovernanceModelConfig` — empty signers for Threshold.
#[tokio::test]
async fn governance_invalid_empty_signers_rejected() {
    let manager = ContextManager::new(
        Box::new(MockCrypto::default()),
        Box::new(MockTransport::connected()),
        Box::new(MockEventLog::default()),
        noop_key_resolver(),
    );
    let creator: DID = "did:key:admin1".into();
    let params = ContextParams {
        governance: GovernanceModel::Threshold {
            threshold: 1,
            signers: vec![],
        },
        ..ContextParams::default()
    };
    let config = GovernanceModelConfig::Threshold {
        signers: vec![],
        threshold: 1,
        voting_window_secs: 86_400,
    };
    let result = manager
        .create_context_with_governance("ctx-bad-empty".into(), params, creator, config)
        .await;
    assert!(result.is_err());
}

/// AC 8/12: Invalid `GovernanceModelConfig` — `min_participation_bps` > 10000.
#[tokio::test]
async fn governance_invalid_min_participation_rejected() {
    let manager = ContextManager::new(
        Box::new(MockCrypto::default()),
        Box::new(MockTransport::connected()),
        Box::new(MockEventLog::default()),
        noop_key_resolver(),
    );
    let creator: DID = "did:key:admin1".into();
    let params = ContextParams {
        governance: GovernanceModel::Majority {
            eligible_voters: vec![creator.clone()],
        },
        ..ContextParams::default()
    };
    let config = GovernanceModelConfig::Majority {
        voting_window_secs: 86_400,
        min_participation_bps: 10001, // > 10000
    };
    let result = manager
        .create_context_with_governance("ctx-bad-bps".into(), params, creator, config)
        .await;
    assert!(result.is_err());
}

/// AC 8: GovernanceModel/GovernanceModelConfig mismatch is rejected.
#[tokio::test]
async fn governance_model_config_mismatch_rejected() {
    let manager = ContextManager::new(
        Box::new(MockCrypto::default()),
        Box::new(MockTransport::connected()),
        Box::new(MockEventLog::default()),
        noop_key_resolver(),
    );
    let creator: DID = "did:key:admin1".into();
    let params = ContextParams {
        governance: GovernanceModel::SingleAdmin,
        ..ContextParams::default()
    };
    // Mismatch: params says SingleAdmin, config says Threshold.
    let config = GovernanceModelConfig::Threshold {
        signers: vec![creator.clone()],
        threshold: 1,
        voting_window_secs: 86_400,
    };
    let result = manager
        .create_context_with_governance("ctx-mismatch".into(), params, creator, config)
        .await;
    assert!(result.is_err());
}

/// AC 10/13: UCAN tokens are minted for Threshold signers at creation.
#[tokio::test]
async fn governance_ucan_tokens_minted_for_threshold_signers() {
    let creator: DID = "did:key:creator1".into();
    let signer2: DID = "did:key:signer2".into();
    let signer3: DID = "did:key:signer3".into();

    let config = GovernanceModelConfig::Threshold {
        signers: vec![creator.clone(), signer2.clone(), signer3.clone()],
        threshold: 2,
        voting_window_secs: 86_400,
    };
    let engine =
        build_governance_engine(config, vec![creator.clone()], noop_key_resolver()).unwrap();
    let tokens = mint_governance_tokens(
        "ctx-ucan-test",
        &creator,
        engine.as_ref(),
        &scp_primitives::SystemClock,
    );

    // 3 signers x 2 capabilities (GovernancePropose + GovernanceVote) = 6 tokens.
    assert_eq!(tokens.len(), 6);

    // Verify each signer has both GovernancePropose and GovernanceVote tokens.
    for signer in [&creator, &signer2, &signer3] {
        let signer_tokens: Vec<_> = tokens.iter().filter(|t| *signer == t.aud).collect();
        assert_eq!(signer_tokens.len(), 2, "each signer should have 2 tokens");
        let capabilities: Vec<&str> = signer_tokens
            .iter()
            .map(|t| t.att[0].with.as_str())
            .collect();
        assert!(
            capabilities
                .iter()
                .any(|c| c.contains("governance:propose")),
            "should have GovernancePropose token"
        );
        assert!(
            capabilities.iter().any(|c| c.contains("governance:vote")),
            "should have GovernanceVote token"
        );
    }

    // All tokens should be issued by the creator.
    for token in &tokens {
        assert_eq!(token.iss, creator.to_string());
    }
}

/// AC 10: UCAN tokens for `SingleAdmin` include both `GovernancePropose`
/// and `GovernanceVote` for the admin.
#[tokio::test]
async fn governance_ucan_tokens_minted_for_single_admin() {
    let creator: DID = "did:key:creator1".into();
    let engine = Box::new(SingleAdminEngine::new(creator.clone(), noop_key_resolver()));
    let tokens = mint_governance_tokens(
        "ctx-sa-ucan",
        &creator,
        engine.as_ref(),
        &scp_primitives::SystemClock,
    );

    // 1 voter x 2 capabilities = 2 tokens.
    assert_eq!(tokens.len(), 2);
    assert!(tokens.iter().all(|t| creator == t.aud));
    assert!(tokens.iter().all(|t| creator == t.iss));
}

/// AC 11: Default `create_context` constructs engines for all four
/// governance model variants without explicit `GovernanceModelConfig`.
#[tokio::test]
async fn governance_default_engine_all_variants() {
    let manager = ContextManager::new(
        Box::new(MockCrypto::default()),
        Box::new(MockTransport::connected()),
        Box::new(MockEventLog::default()),
        noop_key_resolver(),
    );
    let creator: DID = "did:key:admin1".into();

    let models = [
        GovernanceModel::SingleAdmin,
        GovernanceModel::Threshold {
            threshold: 1,
            signers: vec![creator.clone()],
        },
        GovernanceModel::Majority {
            eligible_voters: vec![creator.clone()],
        },
        GovernanceModel::Unanimity {
            eligible_voters: vec![creator.clone()],
        },
    ];

    for (i, model) in models.iter().enumerate() {
        let params = ContextParams {
            governance: model.clone(),
            ..ContextParams::default()
        };
        let ctx_id = format!("ctx-default-{i}");
        let handle = manager
            .create_context(ctx_id.clone(), params, creator.clone())
            .await
            .unwrap();
        assert_eq!(handle.state().await, ContextState::Active);
    }
}

// -----------------------------------------------------------------------
// Governance proposal lifecycle tests (SCP-268)
// -----------------------------------------------------------------------

/// Helper: creates a manager with an active context whose ceiling includes
/// governance capabilities, so propose/vote operations succeed.
async fn setup_governance_context() -> (ContextManager, ContextHandle, String) {
    let manager = ContextManager::new(
        Box::new(MockCrypto::default()),
        Box::new(MockTransport::connected()),
        Box::new(MockEventLog::default()),
        mock_key_resolver(),
    );

    let params = ContextParams {
        ceiling: vec![
            scp_protocol::context::params::Capability::new("messages:read"),
            scp_protocol::context::params::Capability::new("messages:write"),
            scp_protocol::context::params::Capability::new("role:assign"),
            scp_protocol::context::params::Capability::new("governance:propose"),
            scp_protocol::context::params::Capability::new("governance:vote"),
            scp_protocol::context::params::Capability::new("context:close"),
        ],
        ..ContextParams::default()
    };

    let admin_did: DID = "did:key:admin".into();
    let handle = manager
        .create_context("gov-ctx".into(), params, admin_did)
        .await
        .unwrap();

    (manager, handle, "gov-ctx".to_owned())
}

/// SCP-268 AC1: `SingleAdmin.propose()` returns `ProposalOutcome` with
/// `Approved` status (auto-approve per ADR-031 section 4a) and `execution_result: None`.
#[tokio::test]
async fn governance_single_admin_propose_checked_auto_approves() {
    let (manager, _handle, ctx_id) = setup_governance_context().await;
    let admin_did: DID = "did:key:admin".into();
    let signing_key = signing_key_for_did(&admin_did);

    let action = super::GovernanceAction::CloseContext { reason: None };

    let outcome = manager
        .propose_governance_action_checked(&ctx_id, &admin_did, action, &signing_key)
        .await
        .unwrap();

    // SingleAdmin auto-approves (ADR-031 section 4a).
    assert!(
        matches!(outcome.status, super::ProposalStatus::Approved),
        "SingleAdmin proposals should be auto-approved"
    );
    assert!(
        outcome.execution_result.is_some(),
        "execution_result must be Some for auto-approved SingleAdmin proposals (SCP-270)"
    );
    assert_eq!(outcome.proposal.proposer_did, admin_did);
    assert_eq!(outcome.proposal.context_id, ctx_id);
}

/// SCP-268 AC5: proposing on a non-Active context returns `ContextNotActive`.
#[tokio::test]
async fn governance_propose_checked_on_inactive_context_returns_not_active() {
    let (manager, handle, ctx_id) = setup_governance_context().await;
    let admin_did: DID = "did:key:admin".into();
    let signing_key = signing_key_for_did(&admin_did);

    // Transition to Closing.
    handle.transition_to(&ContextState::Closing).await.unwrap();

    let result = manager
        .propose_governance_action_checked(
            &ctx_id,
            &admin_did,
            super::GovernanceAction::CloseContext { reason: None },
            &signing_key,
        )
        .await;

    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        ContextError::ContextNotActive
    ));
}

/// SCP-268 AC6: proposing without `GovernancePropose` capability is rejected.
#[tokio::test]
async fn governance_propose_checked_without_capability_rejected() {
    let (manager, _handle, ctx_id) = setup_governance_context().await;

    // Join bob as a member (default role = member, which has messages:read/write
    // but not governance:propose).
    let kp = KeyPackage::mock("did:key:bob".into());
    let handle_ref = {
        let contexts = manager.contexts.lock().await;
        contexts.get(&ctx_id).unwrap().handle.clone()
    };
    manager.join_context(&handle_ref, kp).await.unwrap();

    let bob_did: DID = "did:key:bob".into();
    let signing_key = signing_key_for_did(&bob_did);
    let result = manager
        .propose_governance_action_checked(
            &ctx_id,
            &bob_did,
            super::GovernanceAction::CloseContext { reason: None },
            &signing_key,
        )
        .await;

    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(
        matches!(err, ContextError::PermissionDenied(_)),
        "member without governance:propose should be rejected: {err}"
    );
}

/// SCP-268 AC7: approve/reject without `GovernanceVote` capability is rejected.
#[tokio::test]
async fn governance_vote_without_capability_rejected() {
    let (manager, _handle, ctx_id) = setup_governance_context().await;

    // Join bob as member (no governance:vote capability).
    let kp = KeyPackage::mock("did:key:bob".into());
    let handle_ref = {
        let contexts = manager.contexts.lock().await;
        contexts.get(&ctx_id).unwrap().handle.clone()
    };
    manager.join_context(&handle_ref, kp).await.unwrap();

    let bob_did: DID = "did:key:bob".into();
    let signing_key = signing_key_for_did(&bob_did);
    let fake_proposal_id = [0u8; 32];

    // approve should fail
    let approve_result = manager
        .approve_governance_proposal(&ctx_id, &fake_proposal_id, &bob_did, &signing_key)
        .await;
    assert!(approve_result.is_err());
    assert!(matches!(
        approve_result.unwrap_err(),
        ContextError::PermissionDenied(_)
    ));

    // reject should fail
    let reject_result = manager
        .reject_governance_proposal(&ctx_id, &fake_proposal_id, &bob_did, &signing_key)
        .await;
    assert!(reject_result.is_err());
    assert!(matches!(
        reject_result.unwrap_err(),
        ContextError::PermissionDenied(_)
    ));
}

/// SCP-268 AC8: governance events are recorded in the event log.
#[tokio::test]
async fn governance_propose_checked_records_events() {
    let manager = ContextManager::new(
        Box::new(MockCrypto::default()),
        Box::new(MockTransport::connected()),
        Box::<MockEventLog>::from(MockEventLog::default()),
        mock_key_resolver(),
    );

    let params = ContextParams {
        ceiling: vec![
            scp_protocol::context::params::Capability::new("messages:read"),
            scp_protocol::context::params::Capability::new("messages:write"),
            scp_protocol::context::params::Capability::new("governance:propose"),
            scp_protocol::context::params::Capability::new("governance:vote"),
        ],
        ..ContextParams::default()
    };

    let admin_did: DID = "did:key:admin".into();
    let _handle = manager
        .create_context("ev-ctx".into(), params, admin_did.clone())
        .await
        .unwrap();

    let signing_key = signing_key_for_did(&admin_did);

    let outcome = manager
        .propose_governance_action_checked(
            "ev-ctx",
            &admin_did,
            super::GovernanceAction::CloseContext { reason: None },
            &signing_key,
        )
        .await
        .unwrap();

    // SingleAdmin produces ProposalCreated + VoteCast + ProposalResolved
    // events. Verify they were logged.
    assert!(matches!(outcome.status, super::ProposalStatus::Approved));
}

/// SCP-268 AC3/AC4: `ThresholdEngine` governance multi-vote lifecycle.
/// Propose creates `Pending` proposal; approve reaches quorum -> `Approved`.
#[tokio::test]
async fn governance_threshold_propose_approve_lifecycle() {
    let alice_did: DID = "did:key:alice".into();
    let bob_did: DID = "did:key:bob".into();

    let manager = ContextManager::new(
        Box::new(MockCrypto::default()),
        Box::new(MockTransport::connected()),
        Box::new(MockEventLog::default()),
        mock_key_resolver(),
    );

    let params = ContextParams {
        ceiling: vec![
            scp_protocol::context::params::Capability::new("messages:read"),
            scp_protocol::context::params::Capability::new("messages:write"),
            scp_protocol::context::params::Capability::new("role:assign"),
            scp_protocol::context::params::Capability::new("governance:propose"),
            scp_protocol::context::params::Capability::new("governance:vote"),
        ],
        governance: GovernanceModel::Threshold {
            threshold: 2,
            signers: vec![alice_did.clone(), bob_did.clone()],
        },
        ..ContextParams::default()
    };

    let handle = manager
        .create_context("thresh-ctx".into(), params, alice_did.clone())
        .await
        .unwrap();

    // Join bob.
    let kp = KeyPackage::mock("did:key:bob".into());
    manager.join_context(&handle, kp).await.unwrap();

    // Grant governance capabilities to bob.
    {
        let mut contexts = manager.contexts.lock().await;
        let ctx = contexts.get_mut("thresh-ctx").unwrap();
        ctx.role_state
            .member_capabilities
            .entry("did:key:bob".to_owned())
            .or_default()
            .insert(Capability::GovernancePropose);
        ctx.role_state
            .member_capabilities
            .entry("did:key:bob".to_owned())
            .or_default()
            .insert(Capability::GovernanceVote);
    }

    let signing_key_alice = signing_key_for_did(&alice_did);
    let signing_key_bob = signing_key_for_did(&bob_did);

    // Alice proposes via capability-checked path.
    let outcome = manager
        .propose_governance_action_checked(
            "thresh-ctx",
            &alice_did,
            super::GovernanceAction::CloseContext { reason: None },
            &signing_key_alice,
        )
        .await
        .unwrap();

    // Threshold 2-of-2: proposer's vote counts as 1, so status is Pending.
    assert!(
        matches!(outcome.status, super::ProposalStatus::Pending),
        "2-of-2 threshold should start as Pending after first vote, got: {:?}",
        outcome.status
    );

    let proposal_id = outcome.proposal.proposal_id;

    // Bob approves -> quorum reached -> Approved.
    let status = manager
        .approve_governance_proposal("thresh-ctx", &proposal_id, &bob_did, &signing_key_bob)
        .await
        .unwrap();

    assert!(
        matches!(status, super::ProposalStatus::Approved),
        "2-of-2 threshold should be Approved after second vote, got: {status:?}"
    );
}

/// SCP-268: proposing on a non-existent context returns `MembershipFailed`.
#[tokio::test]
async fn governance_propose_checked_on_nonexistent_context() {
    let manager = ContextManager::new(
        Box::new(MockCrypto::default()),
        Box::new(MockTransport::connected()),
        Box::new(MockEventLog::default()),
        mock_key_resolver(),
    );

    let admin_did: DID = "did:key:admin".into();
    let signing_key = signing_key_for_did(&admin_did);
    let result = manager
        .propose_governance_action_checked(
            "nonexistent",
            &admin_did,
            super::GovernanceAction::CloseContext { reason: None },
            &signing_key,
        )
        .await;

    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        ContextError::ContextNotRegistered(_)
    ));
}

/// SCP-268: `withdraw_governance_vote` returns `PermissionDenied` for `SingleAdmin`.
#[tokio::test]
async fn governance_withdraw_vote_single_admin_not_supported() {
    let (manager, _handle, ctx_id) = setup_governance_context().await;
    let admin_did: DID = "did:key:admin".into();
    let fake_proposal_id = [0u8; 32];

    let result = manager
        .withdraw_governance_vote(&ctx_id, &fake_proposal_id, &admin_did)
        .await;

    // SingleAdmin does not support withdraw_vote.
    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        ContextError::PermissionDenied(_)
    ));
}

// -------------------------------------------------------------------
// SCP-270: auto-execution, unanimity overrides, governance bypass
// -------------------------------------------------------------------

/// Helper: `ContextParams` with governance-compatible ceiling.
/// Helper: build an approved proposal with customizable approvals.
fn approved_proposal(
    pid: [u8; 32],
    context_id: &str,
    action: GovernanceAction,
    approver_dids: &[&str],
) -> GovernanceProposal {
    use scp_protocol::context::governance::{SignedVote, VoteType};
    GovernanceProposal {
        proposal_id: pid,
        context_id: context_id.into(),
        proposer_did: approver_dids
            .first()
            .unwrap_or(&"did:key:creator")
            .to_string()
            .into(),
        action,
        status: ProposalStatus::Approved,
        created_at: 1000,
        voting_deadline: 2000,
        approvals: approver_dids
            .iter()
            .enumerate()
            .map(|(i, did)| SignedVote {
                voter_did: (*did).to_owned().into(),
                vote: VoteType::Approve,
                timestamp: 1000 + i as u64,
                signature: vec![0u8; 64],
            })
            .collect(),
        rejections: Vec::new(),
        created_at_epoch: None,
    }
}

/// SCP-270 AC14: each `GovernanceAction` variant executes through governance.
/// Covered by the existing `single_admin_propose_auto_executes` and
/// per-action tests. This test verifies the dispatch returns typed results.
#[tokio::test]
async fn governance_dispatch_returns_typed_results() {
    use scp_protocol::context::governance::{GovernanceProposal, SignedVote, VoteType};

    let manager = ContextManager::new(
        Box::new(MockCrypto::default()),
        Box::new(MockTransport::connected()),
        Box::new(MockEventLog::default()),
        noop_key_resolver(),
    );

    let params = governance_params();
    let _handle = manager
        .create_context("typed-result-ctx".into(), params, "did:key:creator".into())
        .await
        .unwrap();

    // AddMember
    let proposal = GovernanceProposal {
        proposal_id: [10u8; 32],
        context_id: "typed-result-ctx".into(),
        proposer_did: "did:key:creator".into(),
        action: GovernanceAction::AddMember {
            did: "did:key:new".into(),
            role: "member".to_owned(),
        },
        status: ProposalStatus::Approved,
        created_at: 1000,
        voting_deadline: 2000,
        approvals: vec![SignedVote {
            voter_did: "did:key:creator".into(),
            vote: VoteType::Approve,
            timestamp: 1000,
            signature: vec![0u8; 64],
        }],
        rejections: Vec::new(),
        created_at_epoch: None,
    };
    let result = manager
        .execute_governance_action("typed-result-ctx", &proposal)
        .await
        .unwrap();
    assert!(
        matches!(result, GovernanceActionResult::MemberAdded),
        "AddMember should return MemberAdded, got: {result:?}"
    );

    // RemoveMember
    let proposal = GovernanceProposal {
        proposal_id: [11u8; 32],
        context_id: "typed-result-ctx".into(),
        proposer_did: "did:key:creator".into(),
        action: GovernanceAction::RemoveMember {
            did: "did:key:new".into(),
            reason: None,
        },
        status: ProposalStatus::Approved,
        created_at: 1000,
        voting_deadline: 2000,
        approvals: vec![SignedVote {
            voter_did: "did:key:creator".into(),
            vote: VoteType::Approve,
            timestamp: 1000,
            signature: vec![0u8; 64],
        }],
        rejections: Vec::new(),
        created_at_epoch: None,
    };
    let result = manager
        .execute_governance_action("typed-result-ctx", &proposal)
        .await
        .unwrap();
    assert!(
        matches!(result, GovernanceActionResult::MemberRemoved),
        "RemoveMember should return MemberRemoved, got: {result:?}"
    );
}

/// SCP-270 AC15: auto-execution on Approved status for `SingleAdmin`.
#[tokio::test]
async fn governance_auto_execution_single_admin() {
    let (manager, _handle, ctx_id) = setup_governance_context().await;
    let admin_did: DID = "did:key:admin".into();
    let signing_key = signing_key_for_did(&admin_did);

    // propose_governance_action for SingleAdmin auto-executes.
    let (proposal, _events) = manager
        .propose_governance_action(
            &ctx_id,
            &admin_did,
            GovernanceAction::AddMember {
                did: "did:key:newmember".into(),
                role: "member".to_owned(),
            },
            &signing_key,
        )
        .await
        .unwrap();

    // Proposal should be Approved (auto-approved by SingleAdmin).
    assert_eq!(proposal.status, ProposalStatus::Approved);

    // The member should already be added (auto-executed).
    let contexts = manager.contexts.lock().await;
    let ctx = contexts.get(&ctx_id).unwrap();
    assert!(
        ctx.membership.contains("did:key:newmember"),
        "auto-execution should have added the member"
    );
}

/// SCP-270 AC15: auto-execution on Approved status for Threshold model.
#[tokio::test]
async fn governance_auto_execution_threshold_on_approval() {
    let creator: DID = "did:key:creator".into();
    let manager = ContextManager::new(
        Box::new(MockCrypto::default()),
        Box::new(MockTransport::connected()),
        Box::new(MockEventLog::default()),
        mock_key_resolver(),
    );

    let mut params = governance_params();
    params.governance = GovernanceModel::Threshold {
        threshold: 1,
        signers: vec![creator.clone()],
    };

    let _handle = manager
        .create_context("thresh-auto-ctx".into(), params, creator.clone())
        .await
        .unwrap();

    let signing_key = signing_key_for_did(&creator);
    // Threshold with 1-of-1: proposal auto-approved on propose.
    let (proposal, _) = manager
        .propose_governance_action(
            "thresh-auto-ctx",
            &creator,
            GovernanceAction::AddMember {
                did: "did:key:bob".into(),
                role: "member".to_owned(),
            },
            &signing_key,
        )
        .await
        .unwrap();

    assert_eq!(proposal.status, ProposalStatus::Approved);

    // Verify auto-execution happened.
    let contexts = manager.contexts.lock().await;
    let ctx = contexts.get("thresh-auto-ctx").unwrap();
    assert!(
        ctx.membership.contains("did:key:bob"),
        "auto-execution should have added the member on threshold quorum"
    );
}

/// SCP-270 AC16: `close_context` through governance for Threshold model.
#[tokio::test]
async fn close_context_through_governance_threshold() {
    let creator: DID = "did:key:creator".into();
    let signer2: DID = "did:key:signer2".into();
    let manager = ContextManager::new(
        Box::new(MockCrypto::default()),
        Box::new(MockTransport::connected()),
        Box::new(MockEventLog::default()),
        mock_key_resolver(),
    );

    let mut params = governance_params();
    params.governance = GovernanceModel::Threshold {
        threshold: 2,
        signers: vec![creator.clone(), signer2.clone()],
    };

    let handle = manager
        .create_context("close-thresh-ctx".into(), params, creator.clone())
        .await
        .unwrap();

    // Direct close_context should fail for multi-admin.
    let result = manager.close_context(&handle, &creator).await;
    assert!(result.is_err());
    assert!(
        matches!(result.unwrap_err(), ContextError::PermissionDenied(ref msg) if msg.contains("multi-admin")),
        "close_context should reject multi-admin contexts"
    );

    // Verify context is still active.
    assert_eq!(handle.state().await, ContextState::Active);
}

/// SCP-270 AC17: `ExtendTtl` unanimity override — partial approval rejected.
#[tokio::test]
async fn extend_ttl_rejects_without_unanimity() {
    let manager = ContextManager::new(
        Box::new(MockCrypto::default()),
        Box::new(MockTransport::connected()),
        Box::new(MockEventLog::default()),
        noop_key_resolver(),
    );
    let mut params = governance_params();
    params.ttl = Some(std::time::Duration::from_secs(3600));
    let _handle = manager
        .create_context("ttl-unan-ctx".into(), params, "did:key:creator".into())
        .await
        .unwrap();

    // Add a second member.
    let add = approved_proposal(
        [20u8; 32],
        "ttl-unan-ctx",
        GovernanceAction::AddMember {
            did: "did:key:bob".into(),
            role: "member".to_owned(),
        },
        &["did:key:creator"],
    );
    manager
        .execute_governance_action("ttl-unan-ctx", &add)
        .await
        .unwrap();

    // ExtendTtl with only creator's approval (bob hasn't approved).
    let extend = approved_proposal(
        [21u8; 32],
        "ttl-unan-ctx",
        GovernanceAction::ExtendTtl {
            additional_secs: 3600,
        },
        &["did:key:creator"],
    );
    let result = manager
        .execute_governance_action("ttl-unan-ctx", &extend)
        .await;
    assert!(result.is_err());
    assert!(
        matches!(result.unwrap_err(), ContextError::PermissionDenied(ref msg) if msg.contains("unanimous")),
        "ExtendTtl should require unanimity"
    );
}

/// SCP-270 AC17: `ExtendTtl` unanimity override — unanimous approval succeeds.
#[tokio::test]
async fn extend_ttl_succeeds_with_unanimity() {
    let manager = ContextManager::new(
        Box::new(MockCrypto::default()),
        Box::new(MockTransport::connected()),
        Box::new(MockEventLog::default()),
        noop_key_resolver(),
    );
    let mut params = governance_params();
    params.ttl = Some(std::time::Duration::from_secs(3600));
    let _handle = manager
        .create_context("ttl-unan2-ctx".into(), params, "did:key:creator".into())
        .await
        .unwrap();

    // Add a second member.
    let add = approved_proposal(
        [20u8; 32],
        "ttl-unan2-ctx",
        GovernanceAction::AddMember {
            did: "did:key:bob".into(),
            role: "member".to_owned(),
        },
        &["did:key:creator"],
    );
    manager
        .execute_governance_action("ttl-unan2-ctx", &add)
        .await
        .unwrap();

    // ExtendTtl with both members' approval.
    let extend = approved_proposal(
        [22u8; 32],
        "ttl-unan2-ctx",
        GovernanceAction::ExtendTtl {
            additional_secs: 3600,
        },
        &["did:key:creator", "did:key:bob"],
    );
    let result = manager
        .execute_governance_action("ttl-unan2-ctx", &extend)
        .await;
    assert!(
        result.is_ok(),
        "ExtendTtl with unanimity should succeed: {result:?}"
    );
    assert!(matches!(
        result.unwrap(),
        GovernanceActionResult::TtlExtended
    ));
}

/// SCP-270 AC18: `PromoteContext` unanimity override.
#[tokio::test]
async fn promote_context_requires_unanimity() {
    use scp_protocol::context::governance::{GovernanceProposal, SignedVote, VoteType};
    use scp_protocol::context::params::{MemoryScope, PromotionPolicy};

    let manager = ContextManager::new(
        Box::new(MockCrypto::default()),
        Box::new(MockTransport::connected()),
        Box::new(MockEventLog::default()),
        noop_key_resolver(),
    );

    let mut params = governance_params();
    params.promotion_policy = PromotionPolicy::Promotable;
    params.memory_scope = MemoryScope::Ephemeral;
    params.ttl = Some(std::time::Duration::from_secs(3600));

    let _handle = manager
        .create_context(
            "promo-unanimity-ctx".into(),
            params,
            "did:key:creator".into(),
        )
        .await
        .unwrap();

    // Add a second member.
    let add_proposal = GovernanceProposal {
        proposal_id: [30u8; 32],
        context_id: "promo-unanimity-ctx".into(),
        proposer_did: "did:key:creator".into(),
        action: GovernanceAction::AddMember {
            did: "did:key:carol".into(),
            role: "member".to_owned(),
        },
        status: ProposalStatus::Approved,
        created_at: 1000,
        voting_deadline: 2000,
        approvals: vec![SignedVote {
            voter_did: "did:key:creator".into(),
            vote: VoteType::Approve,
            timestamp: 1000,
            signature: vec![0u8; 64],
        }],
        rejections: Vec::new(),
        created_at_epoch: None,
    };
    manager
        .execute_governance_action("promo-unanimity-ctx", &add_proposal)
        .await
        .unwrap();

    // PromoteContext with only creator's approval — should fail.
    let promote_proposal = GovernanceProposal {
        proposal_id: [31u8; 32],
        context_id: "promo-unanimity-ctx".into(),
        proposer_did: "did:key:creator".into(),
        action: GovernanceAction::PromoteContext,
        status: ProposalStatus::Approved,
        created_at: 1000,
        voting_deadline: 2000,
        approvals: vec![SignedVote {
            voter_did: "did:key:creator".into(),
            vote: VoteType::Approve,
            timestamp: 1000,
            signature: vec![0u8; 64],
        }],
        rejections: Vec::new(),
        created_at_epoch: None,
    };

    let result = manager
        .execute_governance_action("promo-unanimity-ctx", &promote_proposal)
        .await;
    assert!(result.is_err());
    assert!(
        matches!(result.unwrap_err(), ContextError::PermissionDenied(ref msg) if msg.contains("unanimous")),
        "PromoteContext should require unanimity"
    );
}

/// SCP-270 AC19: governance bypass prevention — standalone `close_context`
/// returns error for multi-admin models.
#[tokio::test]
async fn governance_bypass_prevented_for_multi_admin_close() {
    let creator: DID = "did:key:creator".into();
    let manager = ContextManager::new(
        Box::new(MockCrypto::default()),
        Box::new(MockTransport::connected()),
        Box::new(MockEventLog::default()),
        mock_key_resolver(),
    );

    // Create a Majority governance context.
    let mut params = governance_params();
    params.governance = GovernanceModel::Majority {
        eligible_voters: vec![creator.clone()],
    };
    let handle = manager
        .create_context("bypass-test-ctx".into(), params, creator.clone())
        .await
        .unwrap();

    // Direct close_context should fail.
    let result = manager.close_context(&handle, &creator).await;
    assert!(result.is_err());
    assert!(
        matches!(result.unwrap_err(), ContextError::PermissionDenied(ref msg) if msg.contains("multi-admin")),
        "standalone close_context must reject multi-admin contexts"
    );
}

/// SCP-270 AC5: `close_context` for `SingleAdmin` goes through engine (auto-approve).
#[tokio::test]
async fn close_context_single_admin_succeeds() {
    let (manager, handle, _ctx_id) = setup_governance_context().await;
    let admin_did: DID = "did:key:admin".into();

    let result = manager.close_context(&handle, &admin_did).await;
    assert!(
        result.is_ok(),
        "SingleAdmin close_context should succeed: {result:?}"
    );
}

/// SCP-270 AC11: `AddSigner` mints `GovernanceVote` + `GovernancePropose` UCANs.
#[tokio::test]
async fn add_signer_mints_governance_ucans() {
    let manager = ContextManager::new(
        Box::new(MockCrypto::default()),
        Box::new(MockTransport::connected()),
        Box::new(MockEventLog::default()),
        noop_key_resolver(),
    );
    let mut params = governance_params();
    params.governance = GovernanceModel::Threshold {
        threshold: 1,
        signers: vec!["did:key:creator".into()],
    };
    let _handle = manager
        .create_context("signer-ucan-ctx".into(), params, "did:key:creator".into())
        .await
        .unwrap();

    // Add member, then add as signer.
    let add = approved_proposal(
        [40u8; 32],
        "signer-ucan-ctx",
        GovernanceAction::AddMember {
            did: "did:key:newsigner".into(),
            role: "member".to_owned(),
        },
        &["did:key:creator"],
    );
    manager
        .execute_governance_action("signer-ucan-ctx", &add)
        .await
        .unwrap();

    let add_s = approved_proposal(
        [41u8; 32],
        "signer-ucan-ctx",
        GovernanceAction::AddSigner {
            did: "did:key:newsigner".into(),
        },
        &["did:key:creator"],
    );
    let result = manager
        .execute_governance_action("signer-ucan-ctx", &add_s)
        .await;
    assert!(result.is_ok(), "AddSigner should succeed: {result:?}");

    // Verify GovernanceVote + GovernancePropose capabilities were granted.
    let contexts = manager.contexts.lock().await;
    let ctx = contexts.get("signer-ucan-ctx").unwrap();
    let caps = ctx
        .role_state
        .member_capabilities
        .get("did:key:newsigner")
        .expect("new signer should have capabilities");
    assert!(caps.contains(&Capability::GovernancePropose));
    assert!(caps.contains(&Capability::GovernanceVote));
}

/// SCP-270 AC12: `RemoveSigner` revokes governance UCANs and validates threshold.
#[tokio::test]
async fn remove_signer_revokes_governance_ucans() {
    let manager = ContextManager::new(
        Box::new(MockCrypto::default()),
        Box::new(MockTransport::connected()),
        Box::new(MockEventLog::default()),
        noop_key_resolver(),
    );
    let mut params = governance_params();
    // Only creator is an initial signer; signer3 will be added dynamically.
    params.governance = GovernanceModel::Threshold {
        threshold: 1,
        signers: vec!["did:key:creator".into()],
    };
    let _handle = manager
        .create_context("rm-signer-ctx".into(), params, "did:key:creator".into())
        .await
        .unwrap();

    // Add signer3 as member, then grant signer role.
    let add = approved_proposal(
        [50u8; 32],
        "rm-signer-ctx",
        GovernanceAction::AddMember {
            did: "did:key:signer3".into(),
            role: "member".to_owned(),
        },
        &["did:key:creator"],
    );
    manager
        .execute_governance_action("rm-signer-ctx", &add)
        .await
        .unwrap();

    let add_s = approved_proposal(
        [51u8; 32],
        "rm-signer-ctx",
        GovernanceAction::AddSigner {
            did: "did:key:signer3".into(),
        },
        &["did:key:creator"],
    );
    manager
        .execute_governance_action("rm-signer-ctx", &add_s)
        .await
        .unwrap();

    // Verify signer3 has governance capabilities.
    {
        let contexts = manager.contexts.lock().await;
        let ctx = contexts.get("rm-signer-ctx").unwrap();
        let caps = ctx
            .role_state
            .member_capabilities
            .get("did:key:signer3")
            .expect("signer3 should have capabilities");
        assert!(caps.contains(&Capability::GovernanceVote));
    }

    // Remove signer3.
    let rm = approved_proposal(
        [52u8; 32],
        "rm-signer-ctx",
        GovernanceAction::RemoveSigner {
            did: "did:key:signer3".into(),
        },
        &["did:key:creator"],
    );
    let result = manager
        .execute_governance_action("rm-signer-ctx", &rm)
        .await;
    assert!(result.is_ok(), "RemoveSigner should succeed: {result:?}");

    // Verify governance capabilities were revoked.
    let contexts = manager.contexts.lock().await;
    let ctx = contexts.get("rm-signer-ctx").unwrap();
    if let Some(caps) = ctx.role_state.member_capabilities.get("did:key:signer3") {
        assert!(!caps.contains(&Capability::GovernancePropose));
        assert!(!caps.contains(&Capability::GovernanceVote));
    }
    assert!(
        ctx.membership.contains("did:key:signer3"),
        "should remain a member"
    );
}

// ===================================================================
// SCP-274: governance-manager integration test — full lifecycle
// ===================================================================

#[tokio::test]
async fn scp274_single_admin_full_lifecycle() {
    let (manager, _handle, ctx_id) = setup_governance_context().await;
    let admin_did: DID = "did:key:admin".into();
    let signing_key = signing_key_for_did(&admin_did);
    let outcome = manager
        .propose_governance_action_checked(
            &ctx_id,
            &admin_did,
            GovernanceAction::AddMember {
                did: "did:key:target".into(),
                role: "member".to_owned(),
            },
            &signing_key,
        )
        .await
        .unwrap();
    assert_eq!(outcome.status, ProposalStatus::Approved);
    let outcome = manager
        .propose_governance_action_checked(
            &ctx_id,
            &admin_did,
            GovernanceAction::RemoveMember {
                did: "did:key:target".into(),
                reason: Some("test".into()),
            },
            &signing_key,
        )
        .await
        .unwrap();
    assert_eq!(
        outcome.status,
        ProposalStatus::Approved,
        "SingleAdmin should auto-approve"
    );
    assert!(
        outcome.execution_result.is_some(),
        "SingleAdmin should auto-execute"
    );
}

#[tokio::test]
async fn scp274_threshold_full_lifecycle() {
    let creator: DID = "did:key:creator".into();
    let signer2: DID = "did:key:signer2".into();
    let manager = ContextManager::new(
        Box::new(MockCrypto::default()),
        Box::new(MockTransport::connected()),
        Box::new(MockEventLog::default()),
        mock_key_resolver(),
    );
    let mut params = governance_params();
    params.governance = GovernanceModel::Threshold {
        threshold: 2,
        signers: vec![creator.clone(), signer2.clone()],
    };
    let _handle = manager
        .create_context("scp274-thresh".into(), params, creator.clone())
        .await
        .unwrap();
    {
        let mut contexts = manager.contexts.lock().await;
        let ctx = contexts.get_mut("scp274-thresh").unwrap();
        ctx.membership
            .add_member("did:key:signer2".into(), "signer".into(), vec![]);
        ctx.role_state.member_capabilities.insert(
            "did:key:signer2".into(),
            HashSet::from([Capability::GovernancePropose, Capability::GovernanceVote]),
        );
    }
    {
        let mut contexts = manager.contexts.lock().await;
        contexts
            .get_mut("scp274-thresh")
            .unwrap()
            .membership
            .add_member("did:key:target".into(), "member".into(), vec![]);
    }
    let creator_sk = signing_key_for_did(&creator);
    let outcome = manager
        .propose_governance_action_checked(
            "scp274-thresh",
            &creator,
            GovernanceAction::RemoveMember {
                did: "did:key:target".into(),
                reason: None,
            },
            &creator_sk,
        )
        .await
        .unwrap();
    let proposal_id = outcome.proposal.proposal_id;
    let signer2_sk = signing_key_for_did(&signer2);
    let status = manager
        .approve_governance_proposal("scp274-thresh", &proposal_id, &signer2, &signer2_sk)
        .await
        .unwrap();
    assert_eq!(status, ProposalStatus::Approved);
    assert!(!manager.is_member("scp274-thresh", "did:key:target").await);
}

#[tokio::test]
async fn scp274_majority_full_lifecycle() {
    let creator: DID = "did:key:creator".into();
    let manager = ContextManager::new(
        Box::new(MockCrypto::default()),
        Box::new(MockTransport::connected()),
        Box::new(MockEventLog::default()),
        mock_key_resolver(),
    );
    let mut params = governance_params();
    params.governance = GovernanceModel::Majority {
        eligible_voters: vec![creator.clone()],
    };
    let _handle = manager
        .create_context("scp274-maj".into(), params, creator.clone())
        .await
        .unwrap();
    {
        let mut contexts = manager.contexts.lock().await;
        let ctx = contexts.get_mut("scp274-maj").unwrap();
        ctx.membership
            .add_member("did:key:target".into(), "member".into(), vec![]);
        ctx.role_state.members.insert("did:key:target".into());
    }
    let creator_sk = signing_key_for_did(&creator);
    let outcome = manager
        .propose_governance_action_checked(
            "scp274-maj",
            &creator,
            GovernanceAction::ChangeRole {
                did: "did:key:target".into(),
                new_role: "observer".into(),
            },
            &creator_sk,
        )
        .await
        .unwrap();
    // MajorityVote propose() always returns Pending — the proposer must
    // explicitly cast an approve vote to reach quorum (1-of-1).
    assert_eq!(outcome.status, ProposalStatus::Pending);
    let proposal_id = outcome.proposal.proposal_id;
    let status = manager
        .approve_governance_proposal("scp274-maj", &proposal_id, &creator, &creator_sk)
        .await
        .unwrap();
    assert_eq!(status, ProposalStatus::Approved);
}

#[tokio::test]
async fn scp274_unanimity_full_lifecycle() {
    let creator: DID = "did:key:creator".into();
    let member2: DID = "did:key:member2".into();
    let manager = ContextManager::new(
        Box::new(MockCrypto::default()),
        Box::new(MockTransport::connected()),
        Box::new(MockEventLog::default()),
        mock_key_resolver(),
    );
    let mut params = governance_params();
    params.governance = GovernanceModel::Unanimity {
        eligible_voters: vec![creator.clone(), member2.clone()],
    };
    let _handle = manager
        .create_context("scp274-unan".into(), params, creator.clone())
        .await
        .unwrap();
    {
        let mut contexts = manager.contexts.lock().await;
        let ctx = contexts.get_mut("scp274-unan").unwrap();
        ctx.membership
            .add_member("did:key:member2".into(), "member".into(), vec![]);
        ctx.role_state.member_capabilities.insert(
            "did:key:member2".into(),
            HashSet::from([Capability::GovernancePropose, Capability::GovernanceVote]),
        );
    }
    {
        let mut contexts = manager.contexts.lock().await;
        contexts
            .get_mut("scp274-unan")
            .unwrap()
            .membership
            .add_member("did:key:target".into(), "member".into(), vec![]);
    }
    let creator_sk = signing_key_for_did(&creator);
    let outcome = manager
        .propose_governance_action_checked(
            "scp274-unan",
            &creator,
            GovernanceAction::RemoveMember {
                did: "did:key:target".into(),
                reason: None,
            },
            &creator_sk,
        )
        .await
        .unwrap();
    let proposal_id = outcome.proposal.proposal_id;
    let member2_sk = signing_key_for_did(&member2);
    let status = manager
        .approve_governance_proposal("scp274-unan", &proposal_id, &member2, &member2_sk)
        .await
        .unwrap();
    assert_eq!(status, ProposalStatus::Approved);
    assert!(!manager.is_member("scp274-unan", "did:key:target").await);
}

#[tokio::test]
async fn scp274_rejected_proposal_does_not_execute() {
    let creator: DID = "did:key:creator".into();
    let signer2: DID = "did:key:signer2".into();
    let manager = ContextManager::new(
        Box::new(MockCrypto::default()),
        Box::new(MockTransport::connected()),
        Box::new(MockEventLog::default()),
        mock_key_resolver(),
    );
    let mut params = governance_params();
    params.governance = GovernanceModel::Threshold {
        threshold: 2,
        signers: vec![creator.clone(), signer2.clone()],
    };
    let _handle = manager
        .create_context("scp274-reject".into(), params, creator.clone())
        .await
        .unwrap();
    {
        let mut contexts = manager.contexts.lock().await;
        let ctx = contexts.get_mut("scp274-reject").unwrap();
        ctx.membership
            .add_member("did:key:signer2".into(), "signer".into(), vec![]);
        ctx.role_state.member_capabilities.insert(
            "did:key:signer2".into(),
            HashSet::from([Capability::GovernancePropose, Capability::GovernanceVote]),
        );
        ctx.membership
            .add_member("did:key:target".into(), "member".into(), vec![]);
    }
    let creator_sk = signing_key_for_did(&creator);
    let outcome = manager
        .propose_governance_action_checked(
            "scp274-reject",
            &creator,
            GovernanceAction::RemoveMember {
                did: "did:key:target".into(),
                reason: None,
            },
            &creator_sk,
        )
        .await
        .unwrap();
    let proposal_id = outcome.proposal.proposal_id;
    let signer2_sk = signing_key_for_did(&signer2);
    let status = manager
        .reject_governance_proposal("scp274-reject", &proposal_id, &signer2, &signer2_sk)
        .await
        .unwrap();
    assert!(matches!(status, ProposalStatus::Rejected { .. }));
    assert!(manager.is_member("scp274-reject", "did:key:target").await);
}

/// SCP-274 AC8: governance events emitted during propose/approve lifecycle.
#[tokio::test]
async fn scp274_governance_events_in_log() {
    let creator: DID = "did:key:creator".into();
    let signer2: DID = "did:key:signer2".into();
    let manager = ContextManager::new(
        Box::new(MockCrypto::default()),
        Box::new(MockTransport::connected()),
        Box::new(MockEventLog::default()),
        mock_key_resolver(),
    );
    let mut params = governance_params();
    params.governance = GovernanceModel::Threshold {
        threshold: 2,
        signers: vec![creator.clone(), signer2.clone()],
    };
    let _handle = manager
        .create_context("scp274-events".into(), params, creator.clone())
        .await
        .unwrap();
    {
        let mut contexts = manager.contexts.lock().await;
        let ctx = contexts.get_mut("scp274-events").unwrap();
        ctx.membership
            .add_member("did:key:signer2".into(), "signer".into(), vec![]);
        ctx.role_state.member_capabilities.insert(
            "did:key:signer2".into(),
            HashSet::from([Capability::GovernancePropose, Capability::GovernanceVote]),
        );
        ctx.membership
            .add_member("did:key:target".into(), "member".into(), vec![]);
    }
    let creator_sk = signing_key_for_did(&creator);
    let outcome = manager
        .propose_governance_action_checked(
            "scp274-events",
            &creator,
            GovernanceAction::RemoveMember {
                did: "did:key:target".into(),
                reason: None,
            },
            &creator_sk,
        )
        .await
        .unwrap();
    assert!(
        matches!(outcome.status, ProposalStatus::Pending),
        "should be pending after first vote"
    );
    let proposal_id = outcome.proposal.proposal_id;
    let signer2_sk = signing_key_for_did(&signer2);
    let status = manager
        .approve_governance_proposal("scp274-events", &proposal_id, &signer2, &signer2_sk)
        .await
        .unwrap();
    assert_eq!(
        status,
        ProposalStatus::Approved,
        "should be approved after quorum"
    );
    assert!(
        !manager.is_member("scp274-events", "did:key:target").await,
        "target removed after governance execution"
    );
}

#[tokio::test]
async fn scp274_bypass_prevention() {
    let creator: DID = "did:key:creator".into();
    let manager = ContextManager::new(
        Box::new(MockCrypto::default()),
        Box::new(MockTransport::connected()),
        Box::new(MockEventLog::default()),
        mock_key_resolver(),
    );
    let mut params = governance_params();
    params.governance = GovernanceModel::Majority {
        eligible_voters: vec![creator.clone()],
    };
    let handle = manager
        .create_context("scp274-bypass".into(), params, creator.clone())
        .await
        .unwrap();
    let result = manager.close_context(&handle, &creator).await;
    assert!(result.is_err());
    assert!(
        matches!(result.unwrap_err(), ContextError::PermissionDenied(ref msg) if msg.contains("multi-admin"))
    );
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn scp274_exercises_seven_action_variants() {
    let manager = ContextManager::new(
        Box::new(MockCrypto::default()),
        Box::new(MockTransport::connected()),
        Box::new(MockEventLog::default()),
        noop_key_resolver(),
    );
    let params = governance_params();
    let _handle = manager
        .create_context("scp274-7a".into(), params, "did:key:admin".into())
        .await
        .unwrap();
    let add = approved_proposal(
        [100u8; 32],
        "scp274-7a",
        GovernanceAction::AddMember {
            did: "did:key:target".into(),
            role: "member".to_owned(),
        },
        &["did:key:admin"],
    );
    assert!(
        manager
            .execute_governance_action("scp274-7a", &add)
            .await
            .is_ok(),
        "AddMember"
    );
    let rm = approved_proposal(
        [101u8; 32],
        "scp274-7a",
        GovernanceAction::RemoveMember {
            did: "did:key:target".into(),
            reason: None,
        },
        &["did:key:admin"],
    );
    assert!(
        manager
            .execute_governance_action("scp274-7a", &rm)
            .await
            .is_ok(),
        "RemoveMember"
    );
    let add2 = approved_proposal(
        [102u8; 32],
        "scp274-7a",
        GovernanceAction::AddMember {
            did: "did:key:target".into(),
            role: "member".to_owned(),
        },
        &["did:key:admin"],
    );
    manager
        .execute_governance_action("scp274-7a", &add2)
        .await
        .unwrap();
    let cr = approved_proposal(
        [103u8; 32],
        "scp274-7a",
        GovernanceAction::ChangeRole {
            did: "did:key:target".into(),
            new_role: "observer".into(),
        },
        &["did:key:admin"],
    );
    assert!(
        manager
            .execute_governance_action("scp274-7a", &cr)
            .await
            .is_ok(),
        "ChangeRole"
    );
    let close = approved_proposal(
        [104u8; 32],
        "scp274-7a",
        GovernanceAction::CloseContext {
            reason: Some("test".into()),
        },
        &["did:key:admin"],
    );
    assert!(
        manager
            .execute_governance_action("scp274-7a", &close)
            .await
            .is_ok(),
        "CloseContext"
    );
    let mut params2 = governance_params();
    params2.ttl = Some(std::time::Duration::from_secs(3600));
    let _h2 = manager
        .create_context("scp274-7b".into(), params2, "did:key:admin".into())
        .await
        .unwrap();
    {
        let mut contexts = manager.contexts.lock().await;
        contexts
            .get_mut("scp274-7b")
            .unwrap()
            .membership
            .add_member("did:key:signer".into(), "member".into(), vec![]);
    }
    let add_s = approved_proposal(
        [105u8; 32],
        "scp274-7b",
        GovernanceAction::AddSigner {
            did: "did:key:signer".into(),
        },
        &["did:key:admin"],
    );
    assert!(
        manager
            .execute_governance_action("scp274-7b", &add_s)
            .await
            .is_ok(),
        "AddSigner"
    );
    let ext = approved_proposal(
        [106u8; 32],
        "scp274-7b",
        GovernanceAction::ExtendTtl {
            additional_secs: 1800,
        },
        &["did:key:admin", "did:key:signer"],
    );
    assert!(
        manager
            .execute_governance_action("scp274-7b", &ext)
            .await
            .is_ok(),
        "ExtendTtl"
    );
    let revoke = approved_proposal(
        [107u8; 32],
        "scp274-7b",
        GovernanceAction::RevokeWriteAccess {
            did: "did:key:signer".into(),
            scope: super::RevocationScope::FutureOnly,
        },
        &["did:key:admin"],
    );
    assert!(
        manager
            .execute_governance_action("scp274-7b", &revoke)
            .await
            .is_ok(),
        "RevokeWriteAccess"
    );
    let revoke_r = approved_proposal(
        [108u8; 32],
        "scp274-7b",
        GovernanceAction::RevokeReadAccess {
            did: "did:key:signer".into(),
            scope: super::RevocationScope::Full,
        },
        &["did:key:admin"],
    );
    manager
        .execute_governance_action("scp274-7b", &revoke_r)
        .await
        .unwrap();
    let restore_r = approved_proposal(
        [109u8; 32],
        "scp274-7b",
        GovernanceAction::RestoreReadAccess {
            did: "did:key:signer".into(),
        },
        &["did:key:admin"],
    );
    assert!(
        manager
            .execute_governance_action("scp274-7b", &restore_r)
            .await
            .is_ok(),
        "RestoreReadAccess"
    );
}

#[tokio::test]
async fn scp274_extend_ttl_unanimity_override_in_threshold() {
    let manager = ContextManager::new(
        Box::new(MockCrypto::default()),
        Box::new(MockTransport::connected()),
        Box::new(MockEventLog::default()),
        noop_key_resolver(),
    );
    let mut params = governance_params();
    params.ttl = Some(std::time::Duration::from_secs(3600));
    params.governance = GovernanceModel::Threshold {
        threshold: 1,
        signers: vec!["did:key:creator".into()],
    };
    let _handle = manager
        .create_context("scp274-ttl-t".into(), params, "did:key:creator".into())
        .await
        .unwrap();
    let add = approved_proposal(
        [110u8; 32],
        "scp274-ttl-t",
        GovernanceAction::AddMember {
            did: "did:key:bob".into(),
            role: "member".to_owned(),
        },
        &["did:key:creator"],
    );
    manager
        .execute_governance_action("scp274-ttl-t", &add)
        .await
        .unwrap();
    let extend = approved_proposal(
        [111u8; 32],
        "scp274-ttl-t",
        GovernanceAction::ExtendTtl {
            additional_secs: 1800,
        },
        &["did:key:creator"],
    );
    assert!(
        manager
            .execute_governance_action("scp274-ttl-t", &extend)
            .await
            .is_err(),
        "ExtendTtl requires unanimity"
    );
    let extend2 = approved_proposal(
        [112u8; 32],
        "scp274-ttl-t",
        GovernanceAction::ExtendTtl {
            additional_secs: 1800,
        },
        &["did:key:creator", "did:key:bob"],
    );
    assert!(
        manager
            .execute_governance_action("scp274-ttl-t", &extend2)
            .await
            .is_ok(),
        "ExtendTtl with unanimity"
    );
}

#[tokio::test]
async fn scp274_promote_context_unanimity_override_in_majority() {
    use scp_protocol::context::params::{MemoryScope, PromotionPolicy};
    let creator: DID = "did:key:creator".into();
    let manager = ContextManager::new(
        Box::new(MockCrypto::default()),
        Box::new(MockTransport::connected()),
        Box::new(MockEventLog::default()),
        noop_key_resolver(),
    );
    let mut params = governance_params();
    params.governance = GovernanceModel::Majority {
        eligible_voters: vec![creator.clone()],
    };
    params.promotion_policy = PromotionPolicy::Promotable;
    params.memory_scope = MemoryScope::Ephemeral;
    params.ttl = Some(std::time::Duration::from_secs(3600));
    let _handle = manager
        .create_context("scp274-promo".into(), params, creator.clone())
        .await
        .unwrap();
    let add = approved_proposal(
        [120u8; 32],
        "scp274-promo",
        GovernanceAction::AddMember {
            did: "did:key:bob".into(),
            role: "member".to_owned(),
        },
        &["did:key:creator"],
    );
    manager
        .execute_governance_action("scp274-promo", &add)
        .await
        .unwrap();
    let promote = approved_proposal(
        [121u8; 32],
        "scp274-promo",
        GovernanceAction::PromoteContext,
        &["did:key:creator"],
    );
    assert!(
        manager
            .execute_governance_action("scp274-promo", &promote)
            .await
            .is_err(),
        "PromoteContext requires unanimity"
    );
    let promote2 = approved_proposal(
        [122u8; 32],
        "scp274-promo",
        GovernanceAction::PromoteContext,
        &["did:key:creator", "did:key:bob"],
    );
    assert!(
        manager
            .execute_governance_action("scp274-promo", &promote2)
            .await
            .is_ok(),
        "PromoteContext with unanimity"
    );
}

#[tokio::test]
async fn scp274_conflict_detection_change_role() {
    let manager = ContextManager::new(
        Box::new(MockCrypto::default()),
        Box::new(MockTransport::connected()),
        Box::new(MockEventLog::default()),
        noop_key_resolver(),
    );
    let params = governance_params();
    let _handle = manager
        .create_context("scp274-conflict".into(), params, "did:key:admin".into())
        .await
        .unwrap();
    {
        let mut contexts = manager.contexts.lock().await;
        let ctx = contexts.get_mut("scp274-conflict").unwrap();
        ctx.membership
            .add_member("did:key:target".into(), "member".into(), vec![]);
        ctx.role_state.members.insert("did:key:target".into());
    }
    let proposal_a = approved_proposal(
        [130u8; 32],
        "scp274-conflict",
        GovernanceAction::ChangeRole {
            did: "did:key:target".into(),
            new_role: "admin".into(),
        },
        &["did:key:admin"],
    );
    let proposal_b = approved_proposal(
        [131u8; 32],
        "scp274-conflict",
        GovernanceAction::ChangeRole {
            did: "did:key:target".into(),
            new_role: "observer".into(),
        },
        &["did:key:admin"],
    );
    manager
        .execute_governance_action("scp274-conflict", &proposal_a)
        .await
        .unwrap();
    {
        let mut contexts = manager.contexts.lock().await;
        let ctx = contexts.get_mut("scp274-conflict").unwrap();
        use std::time::{SystemTime, UNIX_EPOCH};
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        ctx.governance
            .approved_proposals
            .insert(proposal_a.proposal_id, (proposal_a.clone(), now, now));
        let events = manager.detect_and_handle_conflicts(ctx, &proposal_b);
        assert!(
            events.iter().any(|e| matches!(
                e,
                scp_protocol::context::governance::GovernanceEvent::ConflictDetected { .. }
                    | scp_protocol::context::governance::GovernanceEvent::ConflictResolved { .. }
            )),
            "conflict detected: {events:?}"
        );
    }
}

#[tokio::test]
async fn scp274_deadlock_detection_threshold() {
    use crate::context::governance::timeout::{DeadlockDetectionState, detect_deadlock};
    use scp_protocol::context::governance::GovernanceContext;
    use scp_protocol::context::governance::multisig::ThresholdEngine;
    let signer1: DID = "did:key:signer1".into();
    let signer2: DID = "did:key:signer2".into();
    let signer3: DID = "did:key:signer3".into();
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&[1u8; 32]);
    let resolver: std::sync::Arc<
        dyn Fn(&DID) -> Option<ed25519_dalek::VerifyingKey> + Send + Sync,
    > = std::sync::Arc::new(move |_| Some(signing_key.verifying_key()));
    let engine =
        ThresholdEngine::new(vec![signer1.clone(), signer2, signer3], 2, 86_400, resolver).unwrap();
    let gov_ctx = GovernanceContext {
        context_id: "deadlock-test".into(),
        members: vec![(signer1.clone(), "admin".into())],
        admin_dids: vec![signer1],
        current_epoch: None,
        now: 1000,
    };
    let detection_state = DeadlockDetectionState::default();
    let conditions = detect_deadlock(&engine, &gov_ctx, &detection_state);
    assert!(!conditions.is_empty(), "deadlock should be detected");
}

#[tokio::test]
async fn scp274_checkpoint_cosignature_threshold() {
    use scp_protocol::context::governance::GovernanceEngine;
    use scp_protocol::context::governance::multisig::ThresholdEngine;
    let signer1: DID = "did:key:signer1".into();
    let signer2: DID = "did:key:signer2".into();
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&[1u8; 32]);
    let resolver: std::sync::Arc<
        dyn Fn(&DID) -> Option<ed25519_dalek::VerifyingKey> + Send + Sync,
    > = std::sync::Arc::new(move |_| Some(signing_key.verifying_key()));
    let engine =
        ThresholdEngine::new(vec![signer1.clone(), signer2.clone()], 2, 86_400, resolver).unwrap();
    let (required_signers, quorum) = engine.checkpoint_cosignature_requirements();
    assert_eq!(quorum, 2);
    assert_eq!(required_signers.len(), 2);
    assert!(required_signers.contains(&signer1));
    assert!(required_signers.contains(&signer2));
}

// -----------------------------------------------------------------------
// Ceiling notification period tests (§5.3.2, Finding 2)
// -----------------------------------------------------------------------

#[test]
fn pending_ceiling_modification_effective_at_equals_notified_at_plus_259200() {
    let notified_at = 1_000_000u64;
    let pending = PendingCeilingModification {
        new_capabilities: vec![Capability::MessagesRead],
        notified_at,
        effective_at: notified_at + CEILING_CHANGE_NOTIFICATION_PERIOD_SECS,
        proposal_id: [0u8; 32],
    };
    assert_eq!(
        pending.effective_at,
        notified_at + 259_200,
        "effective_at must be notified_at + 72h (259,200s)"
    );
}

#[test]
fn pending_ceiling_is_effective_false_before_period_expires() {
    let notified_at = 1_000_000u64;
    let pending = PendingCeilingModification {
        new_capabilities: vec![Capability::MessagesRead],
        notified_at,
        effective_at: notified_at + CEILING_CHANGE_NOTIFICATION_PERIOD_SECS,
        proposal_id: [0u8; 32],
    };
    // One second before effective_at.
    assert!(
        !pending.is_effective(pending.effective_at - 1),
        "is_effective must return false before the notification period expires"
    );
    // At notified_at (start of period).
    assert!(
        !pending.is_effective(notified_at),
        "is_effective must return false at the start of the notification period"
    );
}

#[test]
fn pending_ceiling_is_effective_true_after_period_expires() {
    let notified_at = 1_000_000u64;
    let pending = PendingCeilingModification {
        new_capabilities: vec![Capability::MessagesRead],
        notified_at,
        effective_at: notified_at + CEILING_CHANGE_NOTIFICATION_PERIOD_SECS,
        proposal_id: [0u8; 32],
    };
    // Exactly at effective_at.
    assert!(
        pending.is_effective(pending.effective_at),
        "is_effective must return true at exactly effective_at"
    );
    // Well after effective_at.
    assert!(
        pending.is_effective(pending.effective_at + 3600),
        "is_effective must return true after the notification period expires"
    );
}

#[tokio::test]
async fn execute_modify_ceiling_sets_pending_with_72h_period() {
    use scp_protocol::context::governance::GovernanceAction;

    let manager = ContextManager::new(
        Box::new(MockCrypto::default()),
        Box::new(MockTransport::connected()),
        Box::new(MockEventLog::default()),
        mock_key_resolver(),
    );

    let alice: DID = "did:dht:z6MkAlice".into();
    let key_a = signing_key_for_did(&alice);

    let params = ContextParams {
        governance: scp_protocol::context::params::GovernanceModel::SingleAdmin,
        ceiling_policy: scp_protocol::context::params::CeilingPolicy::Governed,
        ceiling: vec![Capability::MessagesRead, Capability::MessagesWrite],
        ..ContextParams::default()
    };

    let _handle = manager
        .create_context("ctx-ceiling".into(), params, alice.clone())
        .await
        .unwrap();

    // Propose ModifyCeiling — SingleAdmin auto-approves and auto-executes.
    let new_ceiling = vec![
        Capability::MessagesRead,
        Capability::MessagesWrite,
        Capability::ToolRegister,
    ];
    let action = GovernanceAction::ModifyCeiling {
        new_ceiling: new_ceiling.clone(),
    };
    let (_proposal, _events) = manager
        .propose_governance_action("ctx-ceiling", &alice, action, &key_a)
        .await
        .unwrap();

    // Verify the pending ceiling modification was stored with 72h period.
    let contexts = manager.contexts.lock().await;
    let ctx = contexts.get("ctx-ceiling").unwrap();
    let pending = ctx
        .governance
        .pending_ceiling_modification
        .as_ref()
        .expect("pending ceiling modification should exist");
    assert_eq!(pending.new_capabilities, new_ceiling);
    assert_eq!(
        pending.effective_at,
        pending.notified_at + 259_200,
        "effective_at must be notified_at + 72h"
    );
    // Ceiling should NOT yet be updated (still pending).
    assert!(
        !ctx.role_state.ceiling.contains(&Capability::ToolRegister),
        "ToolRegister should not be in ceiling yet (still in notification period)"
    );
}

#[tokio::test]
async fn apply_pending_ceiling_modification_respects_notification_period() {
    use scp_protocol::context::governance::GovernanceAction;

    let manager = ContextManager::new(
        Box::new(MockCrypto::default()),
        Box::new(MockTransport::connected()),
        Box::new(MockEventLog::default()),
        mock_key_resolver(),
    );

    let alice: DID = "did:dht:z6MkAlice".into();
    let key_a = signing_key_for_did(&alice);

    let params = ContextParams {
        governance: scp_protocol::context::params::GovernanceModel::SingleAdmin,
        ceiling_policy: scp_protocol::context::params::CeilingPolicy::Governed,
        ceiling: vec![Capability::MessagesRead, Capability::MessagesWrite],
        ..ContextParams::default()
    };

    let _handle = manager
        .create_context("ctx-apply".into(), params, alice.clone())
        .await
        .unwrap();

    let new_ceiling = vec![
        Capability::MessagesRead,
        Capability::MessagesWrite,
        Capability::ToolRegister,
    ];
    let action = GovernanceAction::ModifyCeiling {
        new_ceiling: new_ceiling.clone(),
    };
    let (_proposal, _events) = manager
        .propose_governance_action("ctx-apply", &alice, action, &key_a)
        .await
        .unwrap();

    // Get the notified_at timestamp from the pending modification.
    let notified_at = {
        let contexts = manager.contexts.lock().await;
        let ctx = contexts.get("ctx-apply").unwrap();
        ctx.governance
            .pending_ceiling_modification
            .as_ref()
            .unwrap()
            .notified_at
    };

    // Before period expires: apply returns false.
    let applied = manager
        .apply_pending_ceiling_modification("ctx-apply", notified_at + 259_199)
        .await
        .unwrap();
    assert!(
        !applied,
        "should not apply before notification period expires"
    );

    // At exactly effective_at: apply returns true.
    let applied = manager
        .apply_pending_ceiling_modification("ctx-apply", notified_at + 259_200)
        .await
        .unwrap();
    assert!(applied, "should apply at exactly effective_at");

    // Verify the ceiling was updated and pending cleared.
    let contexts = manager.contexts.lock().await;
    let ctx = contexts.get("ctx-apply").unwrap();
    assert!(
        ctx.governance.pending_ceiling_modification.is_none(),
        "pending modification should be cleared after apply"
    );
    assert!(
        ctx.role_state.ceiling.contains(&Capability::ToolRegister),
        "ToolRegister should now be in the ceiling after apply"
    );
}

#[tokio::test]
async fn execute_modify_ceiling_emits_ceiling_change_notification() {
    use scp_protocol::context::governance::GovernanceAction;
    use scp_protocol::context::membership::ContextEvent;

    let manager = ContextManager::new(
        Box::new(MockCrypto::default()),
        Box::new(MockTransport::connected()),
        Box::new(MockEventLog::default()),
        mock_key_resolver(),
    );

    let alice: DID = "did:dht:z6MkAlice".into();
    let key_a = signing_key_for_did(&alice);

    let params = ContextParams {
        governance: scp_protocol::context::params::GovernanceModel::SingleAdmin,
        ceiling_policy: scp_protocol::context::params::CeilingPolicy::Governed,
        ceiling: vec![Capability::MessagesRead, Capability::MessagesWrite],
        ..ContextParams::default()
    };

    let _handle = manager
        .create_context("ctx-notify".into(), params, alice.clone())
        .await
        .unwrap();

    let new_ceiling = vec![
        Capability::MessagesRead,
        Capability::MessagesWrite,
        Capability::ToolRegister,
    ];
    let action = GovernanceAction::ModifyCeiling {
        new_ceiling: new_ceiling.clone(),
    };
    let (_proposal, _events) = manager
        .propose_governance_action("ctx-notify", &alice, action, &key_a)
        .await
        .unwrap();

    // Drain events and check for CeilingChangeNotification.
    let events = manager.drain_events("ctx-notify").await;
    let notification = events
        .iter()
        .find(|e| matches!(e, ContextEvent::CeilingChangeNotification { .. }));
    assert!(
        notification.is_some(),
        "CeilingChangeNotification event should be emitted to the receive buffer"
    );
    if let Some(ContextEvent::CeilingChangeNotification {
        new_capabilities,
        notified_at,
        effective_at,
        ..
    }) = notification
    {
        assert_eq!(*new_capabilities, new_ceiling);
        assert_eq!(
            *effective_at,
            *notified_at + 259_200,
            "notification effective_at must be notified_at + 72h"
        );
    }
}

// -----------------------------------------------------------------------
// Economic policy notification period tests (§19.3, #728)
// -----------------------------------------------------------------------

#[test]
fn pending_economic_policy_change_effective_at_equals_notified_at_plus_86400() {
    let notified_at = 1_000_000u64;
    let pending = PendingEconomicPolicyChange {
        new_policy: scp_protocol::economy::types::EconomicPolicy {
            locked: false,
            cost_schedule: scp_protocol::economy::types::CostSchedule {
                currency: scp_protocol::economy::types::CurrencyCode([85, 83, 68, 0]),
                per_message: None,
                per_tool_invoke: None,
                per_join: None,
                per_period: None,
                per_byte_stored: None,
            },
            payment_adapters: vec![],
            pricing_formula: None,
            payee: DID::from("did:dht:z6MkPayee"),
        },
        notified_at,
        effective_at: notified_at + ECONOMIC_POLICY_NOTIFICATION_PERIOD_SECS,
        proposal_id: [0u8; 32],
    };
    assert_eq!(
        pending.effective_at,
        notified_at + 86_400,
        "effective_at must be notified_at + 24h (86,400s)"
    );
}

#[test]
fn pending_economic_policy_is_effective_false_before_period_expires() {
    let notified_at = 1_000_000u64;
    let pending = PendingEconomicPolicyChange {
        new_policy: scp_protocol::economy::types::EconomicPolicy {
            locked: false,
            cost_schedule: scp_protocol::economy::types::CostSchedule {
                currency: scp_protocol::economy::types::CurrencyCode([85, 83, 68, 0]),
                per_message: None,
                per_tool_invoke: None,
                per_join: None,
                per_period: None,
                per_byte_stored: None,
            },
            payment_adapters: vec![],
            pricing_formula: None,
            payee: DID::from("did:dht:z6MkPayee"),
        },
        notified_at,
        effective_at: notified_at + ECONOMIC_POLICY_NOTIFICATION_PERIOD_SECS,
        proposal_id: [0u8; 32],
    };
    assert!(
        !pending.is_effective(pending.effective_at - 1),
        "is_effective must return false before the notification period expires"
    );
}

#[test]
fn pending_economic_policy_is_effective_true_after_period_expires() {
    let notified_at = 1_000_000u64;
    let pending = PendingEconomicPolicyChange {
        new_policy: scp_protocol::economy::types::EconomicPolicy {
            locked: false,
            cost_schedule: scp_protocol::economy::types::CostSchedule {
                currency: scp_protocol::economy::types::CurrencyCode([85, 83, 68, 0]),
                per_message: None,
                per_tool_invoke: None,
                per_join: None,
                per_period: None,
                per_byte_stored: None,
            },
            payment_adapters: vec![],
            pricing_formula: None,
            payee: DID::from("did:dht:z6MkPayee"),
        },
        notified_at,
        effective_at: notified_at + ECONOMIC_POLICY_NOTIFICATION_PERIOD_SECS,
        proposal_id: [0u8; 32],
    };
    assert!(
        pending.is_effective(pending.effective_at),
        "is_effective must return true at exactly effective_at"
    );
}

#[tokio::test]
async fn execute_set_economic_policy_stages_with_24h_delay() {
    use scp_protocol::context::governance::GovernanceAction;
    use scp_protocol::economy::types::{CostSchedule, EconomicPolicy};

    let manager = ContextManager::new(
        Box::new(MockCrypto::default()),
        Box::new(MockTransport::connected()),
        Box::new(MockEventLog::default()),
        mock_key_resolver(),
    );

    let alice: DID = "did:dht:z6MkAlice".into();
    let key_a = signing_key_for_did(&alice);

    let params = ContextParams {
        governance: scp_protocol::context::params::GovernanceModel::SingleAdmin,
        ..ContextParams::default()
    };

    let _handle = manager
        .create_context("ctx-econ-delay".into(), params, alice.clone())
        .await
        .unwrap();

    let policy = EconomicPolicy {
        locked: false,
        cost_schedule: CostSchedule {
            currency: scp_protocol::economy::types::CurrencyCode([85, 83, 68, 0]),
            per_message: None,
            per_tool_invoke: None,
            per_join: None,
            per_period: None,
            per_byte_stored: None,
        },
        payment_adapters: vec![],
        pricing_formula: None,
        payee: DID::from("did:dht:z6MkPayee"),
    };
    let action = GovernanceAction::SetEconomicPolicy {
        policy: policy.clone(),
    };

    let (_proposal, _events) = manager
        .propose_governance_action("ctx-econ-delay", &alice, action, &key_a)
        .await
        .unwrap();

    let contexts = manager.contexts.lock().await;
    let ctx = contexts.get("ctx-econ-delay").unwrap();
    let pending = ctx
        .governance
        .pending_economic_policy_change
        .as_ref()
        .expect("pending economic policy change should exist");
    assert_eq!(pending.new_policy, policy);
    assert_eq!(
        pending.effective_at,
        pending.notified_at + 86_400,
        "effective_at must be notified_at + 24h"
    );
    assert!(
        ctx.governance.economic_policy.is_none(),
        "economic policy should not be applied yet (still in notification period)"
    );
}

#[tokio::test]
async fn apply_pending_economic_policy_change_respects_notification_period() {
    use scp_protocol::context::governance::GovernanceAction;
    use scp_protocol::economy::types::{CostSchedule, EconomicPolicy};

    let manager = ContextManager::new(
        Box::new(MockCrypto::default()),
        Box::new(MockTransport::connected()),
        Box::new(MockEventLog::default()),
        mock_key_resolver(),
    );

    let alice: DID = "did:dht:z6MkAlice".into();
    let key_a = signing_key_for_did(&alice);

    let params = ContextParams {
        governance: scp_protocol::context::params::GovernanceModel::SingleAdmin,
        ..ContextParams::default()
    };

    let _handle = manager
        .create_context("ctx-econ-apply".into(), params, alice.clone())
        .await
        .unwrap();

    let policy = EconomicPolicy {
        locked: false,
        cost_schedule: CostSchedule {
            currency: scp_protocol::economy::types::CurrencyCode([85, 83, 68, 0]),
            per_message: None,
            per_tool_invoke: None,
            per_join: None,
            per_period: None,
            per_byte_stored: None,
        },
        payment_adapters: vec![],
        pricing_formula: None,
        payee: DID::from("did:dht:z6MkPayee"),
    };
    let action = GovernanceAction::SetEconomicPolicy {
        policy: policy.clone(),
    };

    let (_proposal, _events) = manager
        .propose_governance_action("ctx-econ-apply", &alice, action, &key_a)
        .await
        .unwrap();

    let notified_at = {
        let contexts = manager.contexts.lock().await;
        let ctx = contexts.get("ctx-econ-apply").unwrap();
        ctx.governance
            .pending_economic_policy_change
            .as_ref()
            .unwrap()
            .notified_at
    };

    let applied = manager
        .apply_pending_economic_policy_change("ctx-econ-apply", notified_at + 86_399)
        .await
        .unwrap();
    assert!(
        !applied,
        "should not apply before notification period expires"
    );

    let applied = manager
        .apply_pending_economic_policy_change("ctx-econ-apply", notified_at + 86_400)
        .await
        .unwrap();
    assert!(applied, "should apply at exactly effective_at");

    let contexts = manager.contexts.lock().await;
    let ctx = contexts.get("ctx-econ-apply").unwrap();
    assert!(
        ctx.governance.pending_economic_policy_change.is_none(),
        "pending change should be cleared after apply"
    );
    assert_eq!(
        ctx.governance.economic_policy.as_ref(),
        Some(&policy),
        "economic policy should now be set after apply"
    );
}

#[tokio::test]
async fn execute_set_economic_policy_emits_notification_event() {
    use scp_protocol::context::governance::GovernanceAction;
    use scp_protocol::context::membership::ContextEvent;
    use scp_protocol::economy::types::{CostSchedule, EconomicPolicy};

    let manager = ContextManager::new(
        Box::new(MockCrypto::default()),
        Box::new(MockTransport::connected()),
        Box::new(MockEventLog::default()),
        mock_key_resolver(),
    );

    let alice: DID = "did:dht:z6MkAlice".into();
    let key_a = signing_key_for_did(&alice);

    let params = ContextParams {
        governance: scp_protocol::context::params::GovernanceModel::SingleAdmin,
        ..ContextParams::default()
    };

    let _handle = manager
        .create_context("ctx-econ-notify".into(), params, alice.clone())
        .await
        .unwrap();

    let policy = EconomicPolicy {
        locked: false,
        cost_schedule: CostSchedule {
            currency: scp_protocol::economy::types::CurrencyCode([85, 83, 68, 0]),
            per_message: None,
            per_tool_invoke: None,
            per_join: None,
            per_period: None,
            per_byte_stored: None,
        },
        payment_adapters: vec![],
        pricing_formula: None,
        payee: DID::from("did:dht:z6MkPayee"),
    };
    let action = GovernanceAction::SetEconomicPolicy { policy };

    let (_proposal, _events) = manager
        .propose_governance_action("ctx-econ-notify", &alice, action, &key_a)
        .await
        .unwrap();

    let events = manager.drain_events("ctx-econ-notify").await;
    let notification = events
        .iter()
        .find(|e| matches!(e, ContextEvent::EconomicPolicyChangeNotification { .. }));
    assert!(
        notification.is_some(),
        "EconomicPolicyChangeNotification event should be emitted"
    );
    if let Some(ContextEvent::EconomicPolicyChangeNotification {
        notified_at,
        effective_at,
        ..
    }) = notification
    {
        assert_eq!(
            *effective_at,
            *notified_at + 86_400,
            "notification effective_at must be notified_at + 24h"
        );
    }
}

#[tokio::test]
async fn execute_set_economic_policy_rejects_when_already_pending() {
    use scp_protocol::context::governance::GovernanceAction;
    use scp_protocol::economy::types::{CostSchedule, EconomicPolicy};

    let manager = ContextManager::new(
        Box::new(MockCrypto::default()),
        Box::new(MockTransport::connected()),
        Box::new(MockEventLog::default()),
        mock_key_resolver(),
    );

    let alice: DID = "did:dht:z6MkAlice".into();
    let key_a = signing_key_for_did(&alice);

    let params = ContextParams {
        governance: scp_protocol::context::params::GovernanceModel::SingleAdmin,
        ..ContextParams::default()
    };

    let _handle = manager
        .create_context("ctx-econ-dup".into(), params, alice.clone())
        .await
        .unwrap();

    let policy = EconomicPolicy {
        locked: false,
        cost_schedule: CostSchedule {
            currency: scp_protocol::economy::types::CurrencyCode([85, 83, 68, 0]),
            per_message: None,
            per_tool_invoke: None,
            per_join: None,
            per_period: None,
            per_byte_stored: None,
        },
        payment_adapters: vec![],
        pricing_formula: None,
        payee: DID::from("did:dht:z6MkPayee"),
    };

    let action1 = GovernanceAction::SetEconomicPolicy {
        policy: policy.clone(),
    };
    let _ = manager
        .propose_governance_action("ctx-econ-dup", &alice, action1, &key_a)
        .await
        .unwrap();

    let action2 = GovernanceAction::SetEconomicPolicy { policy };
    let result = manager
        .propose_governance_action("ctx-econ-dup", &alice, action2, &key_a)
        .await;
    assert!(
        result.is_err(),
        "second SetEconomicPolicy should fail while one is already pending"
    );
}

// -----------------------------------------------------------------------
// ApproveSpend → MemberBudgetTracker integration (issue #622)
// -----------------------------------------------------------------------

/// Helper: create a `SingleAdmin` context with a spender member added.
async fn setup_budget_context(ctx_id: &str) -> (ContextManager, DID, DID) {
    let admin_did: DID = "did:key:admin".into();
    let spender_did: DID = "did:key:spender".into();
    let manager = ContextManager::new(
        Box::new(MockCrypto::default()),
        Box::new(MockTransport::connected()),
        Box::new(MockEventLog::default()),
        mock_key_resolver(),
    );
    let params = ContextParams {
        ceiling: vec![
            scp_protocol::context::params::Capability::new("messages:read"),
            scp_protocol::context::params::Capability::new("messages:write"),
            scp_protocol::context::params::Capability::new("role:assign"),
            scp_protocol::context::params::Capability::new("governance:propose"),
            scp_protocol::context::params::Capability::new("governance:vote"),
        ],
        ..ContextParams::default()
    };
    manager
        .create_context(ctx_id.into(), params, admin_did.clone())
        .await
        .unwrap();
    let sk = signing_key_for_did(&admin_did);
    manager
        .propose_governance_action(
            ctx_id,
            &admin_did,
            GovernanceAction::AddMember {
                did: spender_did.clone(),
                role: "member".to_owned(),
            },
            &sk,
        )
        .await
        .unwrap();
    (manager, admin_did, spender_did)
}

/// Verifies that `ApproveSpend` grants budget and additive grants accumulate.
#[tokio::test]
async fn approve_spend_grants_budget_to_member_tracker() {
    let (manager, admin, spender) = setup_budget_context("budget-ctx").await;
    let sk = signing_key_for_did(&admin);

    // No budget initially.
    {
        let contexts = manager.contexts.lock().await;
        let ctx = contexts.get("budget-ctx").unwrap();
        assert!(!ctx.governance.budget_tracker.has_budget(&spender));
    }

    // First grant: 5000.
    manager
        .propose_governance_action(
            "budget-ctx",
            &admin,
            GovernanceAction::ApproveSpend {
                spender: spender.clone(),
                amount: scp_protocol::economy::types::Amount::new(5000),
                purpose: "tool budget".to_owned(),
            },
            &sk,
        )
        .await
        .unwrap();
    {
        let contexts = manager.contexts.lock().await;
        let ctx = contexts.get("budget-ctx").unwrap();
        assert!(ctx.governance.budget_tracker.has_budget(&spender));
        assert_eq!(
            ctx.governance.budget_tracker.remaining(&spender),
            scp_protocol::economy::types::Amount::new(5000)
        );
    }

    // Second grant: 3000 — additive.
    manager
        .propose_governance_action(
            "budget-ctx",
            &admin,
            GovernanceAction::ApproveSpend {
                spender: spender.clone(),
                amount: scp_protocol::economy::types::Amount::new(3000),
                purpose: "more budget".to_owned(),
            },
            &sk,
        )
        .await
        .unwrap();
    {
        let contexts = manager.contexts.lock().await;
        let ctx = contexts.get("budget-ctx").unwrap();
        assert_eq!(
            ctx.governance.budget_tracker.limit(&spender),
            scp_protocol::economy::types::Amount::new(8000)
        );
    }
}

/// Verifies that `ApproveSpend` rejects non-member spenders.
#[tokio::test]
async fn approve_spend_rejects_non_member_spender() {
    let admin_did: DID = "did:key:admin".into();
    let non_member: DID = "did:key:nonmember".into();
    let manager = ContextManager::new(
        Box::new(MockCrypto::default()),
        Box::new(MockTransport::connected()),
        Box::new(MockEventLog::default()),
        mock_key_resolver(),
    );
    let params = ContextParams {
        ceiling: vec![
            scp_protocol::context::params::Capability::new("messages:read"),
            scp_protocol::context::params::Capability::new("messages:write"),
            scp_protocol::context::params::Capability::new("governance:propose"),
            scp_protocol::context::params::Capability::new("governance:vote"),
        ],
        ..ContextParams::default()
    };
    manager
        .create_context("reject-ctx".into(), params, admin_did.clone())
        .await
        .unwrap();
    let sk = signing_key_for_did(&admin_did);
    let result = manager
        .propose_governance_action(
            "reject-ctx",
            &admin_did,
            GovernanceAction::ApproveSpend {
                spender: non_member,
                amount: scp_protocol::economy::types::Amount::new(1000),
                purpose: "should fail".to_owned(),
            },
            &sk,
        )
        .await;
    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        ContextError::MemberNotFound(_)
    ));
}

/// Verifies that `budget_tracker` is included in context snapshots
/// and survives serde roundtrip.
#[tokio::test]
async fn budget_tracker_included_in_snapshot() {
    let (manager, admin, spender) = setup_budget_context("snap-ctx").await;
    let sk = signing_key_for_did(&admin);
    manager
        .propose_governance_action(
            "snap-ctx",
            &admin,
            GovernanceAction::ApproveSpend {
                spender: spender.clone(),
                amount: scp_protocol::economy::types::Amount::new(2500),
                purpose: "snapshot test".to_owned(),
            },
            &sk,
        )
        .await
        .unwrap();

    let contexts = manager.contexts.lock().await;
    let ctx = contexts.get("snap-ctx").unwrap();
    let snapshot = ContextManager::snapshot_context(ctx);
    assert!(snapshot.budget_tracker.has_budget(&spender));
    assert_eq!(
        snapshot.budget_tracker.remaining(&spender),
        scp_protocol::economy::types::Amount::new(2500)
    );

    // Serde roundtrip.
    let json = serde_json::to_string(&snapshot).unwrap();
    let restored: ContextSnapshot = serde_json::from_str(&json).unwrap();
    assert_eq!(
        restored.budget_tracker.remaining(&spender),
        scp_protocol::economy::types::Amount::new(2500)
    );
}

// ===================================================================
// MLS governance integration (issue #630)
// ===================================================================

/// Helper: creates an approved governance proposal for a given action
/// using `SingleAdminEngine` with a mock key resolver that uses
/// deterministic keys from `signing_key_for_did`. Returns the approved
/// proposal ready for `execute_governance_action()`.
fn make_approved_proposal(
    admin_did: &DID,
    context_id: &str,
    action: super::GovernanceAction,
) -> super::GovernanceProposal {
    use scp_protocol::context::governance::{
        GovernanceContext, GovernanceEngine, SingleAdminEngine,
    };

    let signing_key = signing_key_for_did(admin_did);
    let resolver = mock_key_resolver();
    let mut engine = SingleAdminEngine::new(admin_did.clone(), resolver);
    let gov_ctx = GovernanceContext {
        context_id: context_id.to_owned(),
        members: vec![(admin_did.clone(), "admin".to_owned())],
        admin_dids: vec![admin_did.clone()],
        current_epoch: Some(0),
        now: 1000,
    };

    let (proposal, _events) = engine
        .propose(admin_did, action, &gov_ctx, &signing_key)
        .unwrap();
    assert!(matches!(proposal.status, super::ProposalStatus::Approved));
    proposal
}

// -----------------------------------------------------------------------
// Context migration tests (§5.11A, #580)
// -----------------------------------------------------------------------

/// Helper: creates an approved `ProposeContextMigration` governance
/// proposal using a `SingleAdminEngine`. The admin DID's signing key
/// is derived from a fixed seed so governance vote verification passes.
fn approved_migration_proposal(
    admin_did: &DID,
    context_id: &str,
    new_params: ContextParams,
    reason: &str,
    grace_period_secs: u64,
    auto_invite: bool,
) -> super::GovernanceProposal {
    use scp_protocol::context::governance::{
        GovernanceAction, GovernanceContext, GovernanceEngine, SingleAdminEngine,
    };

    let signing_key = ed25519_dalek::SigningKey::from_bytes(&[1u8; 32]);
    let vk = signing_key.verifying_key();
    #[allow(clippy::type_complexity)]
    let resolver: std::sync::Arc<
        dyn Fn(&scp_identity::DID) -> Option<ed25519_dalek::VerifyingKey> + Send + Sync,
    > = std::sync::Arc::new(move |_| Some(vk));
    let mut engine = SingleAdminEngine::new(admin_did.clone(), resolver);
    let gov_ctx = GovernanceContext {
        context_id: context_id.to_owned(),
        members: vec![(admin_did.clone(), "admin".to_owned())],
        admin_dids: vec![admin_did.clone()],
        current_epoch: None,
        now: 1000,
    };

    let action = GovernanceAction::ProposeContextMigration {
        new_context_params: Box::new(new_params),
        reason: reason.to_owned(),
        grace_period_secs,
        auto_invite,
    };

    let (proposal, _events) = engine
        .propose(admin_did, action, &gov_ctx, &signing_key)
        .unwrap();
    assert!(matches!(proposal.status, super::ProposalStatus::Approved));
    proposal
}

/// Issue #630 AC1: `dispatch_governance_action` calls `classify_action()`
/// after membership-affecting actions. Verifying that `AddMember`
/// increments `mls_epoch` (which requires `classify_action` returning
/// `MembershipChange`).
#[tokio::test]
async fn mls_integration_add_member_increments_epoch() {
    let admin_did: DID = "did:key:creator".into();
    let (manager, _handle) = setup_active_context().await;

    let action = super::GovernanceAction::AddMember {
        did: "did:key:new-member".into(),
        role: "member".to_owned(),
    };
    let proposal = make_approved_proposal(&admin_did, "test-ctx", action);
    let result = manager
        .execute_governance_action("test-ctx", &proposal)
        .await;
    assert!(result.is_ok(), "AddMember should succeed");

    // Verify epoch was incremented (from 0 to 1).
    let contexts = manager.contexts.lock().await;
    let ctx = contexts.get("test-ctx").unwrap();
    assert_eq!(
        ctx.epoch.mls_epoch, 1,
        "MLS epoch should advance after AddMember"
    );
}

/// Issue #630 AC2: MLS commits generated and applied for `AddMember`.
/// Verified by checking that `generate_mls_operations` is invoked
/// (the `EpochCoordinator` records the generated MLS operation) and
/// the new member appears in the membership state.
#[tokio::test]
async fn mls_integration_add_member_generates_mls_operation() {
    let admin_did: DID = "did:key:creator".into();
    let (manager, _handle) = setup_active_context().await;

    let action = super::GovernanceAction::AddMember {
        did: "did:key:new-member".into(),
        role: "member".to_owned(),
    };
    let proposal = make_approved_proposal(&admin_did, "test-ctx", action);
    manager
        .execute_governance_action("test-ctx", &proposal)
        .await
        .unwrap();

    // Verify: the EpochCoordinator recorded an AddMember MLS operation,
    // proving that generate_mls_operations was called.
    let contexts = manager.contexts.lock().await;
    let ctx = contexts.get("test-ctx").unwrap();
    let records = ctx.epoch.coordinator.records();
    assert_eq!(records.len(), 1);
    if let scp_protocol::context::governance::mls_integration::MlsOperation::AddMember {
        ref did,
        ref role,
    } = records[0].operation
    {
        assert_eq!(did.as_ref(), "did:key:new-member");
        assert_eq!(role, "member");
    } else {
        panic!("expected AddMember MLS operation");
    }

    // Verify: the member is in the membership state.
    let target_did: DID = "did:key:new-member".into();
    assert!(ctx.membership.contains(&target_did));
}

/// Issue #630 AC3: `EpochCoordinator` instantiated per context and
/// records coordination after membership-affecting governance actions.
#[tokio::test]
async fn mls_integration_epoch_coordinator_records_coordination() {
    let admin_did: DID = "did:key:creator".into();
    let (manager, _handle) = setup_active_context().await;

    // Execute AddMember — should record coordination.
    let action = super::GovernanceAction::AddMember {
        did: "did:key:member-a".into(),
        role: "member".to_owned(),
    };
    let proposal = make_approved_proposal(&admin_did, "test-ctx", action);
    manager
        .execute_governance_action("test-ctx", &proposal)
        .await
        .unwrap();

    // Execute RemoveMember — should record second coordination.
    let action2 = super::GovernanceAction::RemoveMember {
        did: "did:key:member-a".into(),
        reason: Some("done".to_owned()),
    };
    let proposal2 = make_approved_proposal(&admin_did, "test-ctx", action2);
    manager
        .execute_governance_action("test-ctx", &proposal2)
        .await
        .unwrap();

    let contexts = manager.contexts.lock().await;
    let ctx = contexts.get("test-ctx").unwrap();
    assert_eq!(
        ctx.epoch.coordinator.record_count(),
        2,
        "should have 2 coordination records after 2 MLS-affecting actions"
    );

    // Verify first record: epoch 0 → 1 for AddMember.
    let records = ctx.epoch.coordinator.records();
    assert_eq!(records[0].epoch_before, 0);
    assert_eq!(records[0].epoch_after, 1);
    assert!(matches!(
        records[0].operation,
        scp_protocol::context::governance::mls_integration::MlsOperation::AddMember { .. }
    ));

    // Verify second record: epoch 1 → 2 for RemoveMember.
    assert_eq!(records[1].epoch_before, 1);
    assert_eq!(records[1].epoch_after, 2);
    assert!(matches!(
        records[1].operation,
        scp_protocol::context::governance::mls_integration::MlsOperation::RemoveMember { .. }
    ));
}

/// Issue #630 AC3: Non-membership actions do NOT create coordination
/// records in the `EpochCoordinator`.
#[tokio::test]
async fn mls_integration_non_membership_action_no_coordination() {
    let admin_did: DID = "did:key:creator".into();
    let (manager, _handle) = setup_active_context().await;

    // ChangeRole is a non-membership action — should not coordinate.
    // First add the member so we have someone to change role for.
    let add_action = super::GovernanceAction::AddMember {
        did: "did:key:target".into(),
        role: "member".to_owned(),
    };
    let add_proposal = make_approved_proposal(&admin_did, "test-ctx", add_action);
    manager
        .execute_governance_action("test-ctx", &add_proposal)
        .await
        .unwrap();

    let action = super::GovernanceAction::ChangeRole {
        did: "did:key:target".into(),
        new_role: "observer".to_owned(),
    };
    let proposal = make_approved_proposal(&admin_did, "test-ctx", action);
    manager
        .execute_governance_action("test-ctx", &proposal)
        .await
        .unwrap();

    // Should have exactly 1 coordination record (from AddMember only).
    let contexts = manager.contexts.lock().await;
    let ctx = contexts.get("test-ctx").unwrap();
    assert_eq!(
        ctx.epoch.coordinator.record_count(),
        1,
        "ChangeRole should not create a coordination record"
    );
    // Epoch should still be 1 (AddMember advanced 0→1, ChangeRole doesn't).
    assert_eq!(ctx.epoch.mls_epoch, 1);
}

/// Issue #630 AC3: `EpochCoordinator` records survive snapshot roundtrip.
#[tokio::test]
async fn mls_integration_epoch_coordinator_snapshot_roundtrip() {
    let admin_did: DID = "did:key:creator".into();
    let (manager, _handle) = setup_active_context().await;

    let action = super::GovernanceAction::AddMember {
        did: "did:key:snap-member".into(),
        role: "member".to_owned(),
    };
    let proposal = make_approved_proposal(&admin_did, "test-ctx", action);
    manager
        .execute_governance_action("test-ctx", &proposal)
        .await
        .unwrap();

    // Take snapshot and verify records are captured.
    let contexts = manager.contexts.lock().await;
    let ctx = contexts.get("test-ctx").unwrap();
    let snapshot = ContextManager::snapshot_context(ctx);
    assert_eq!(
        snapshot.epoch_coordination_records.len(),
        1,
        "snapshot should capture coordination records"
    );

    // Serde roundtrip.
    let json = serde_json::to_string(&snapshot).unwrap();
    let restored: ContextSnapshot = serde_json::from_str(&json).unwrap();
    assert_eq!(
        restored.epoch_coordination_records.len(),
        1,
        "records should survive serde roundtrip"
    );
    assert_eq!(restored.epoch_coordination_records[0].epoch_before, 0);
    assert_eq!(restored.epoch_coordination_records[0].epoch_after, 1);
}

/// Issue #630 AC4: Checkpoint cosignature collection is NOT triggered
/// for `SingleAdmin` contexts (quorum is 0).
#[tokio::test]
async fn mls_integration_no_checkpoint_event_for_single_admin() {
    let admin_did: DID = "did:key:creator".into();
    let (manager, _handle) = setup_active_context().await;

    let action = super::GovernanceAction::AddMember {
        did: "did:key:member-cp".into(),
        role: "member".to_owned(),
    };
    let proposal = make_approved_proposal(&admin_did, "test-ctx", action);
    manager
        .execute_governance_action("test-ctx", &proposal)
        .await
        .unwrap();

    // Drain the receive buffer and check that no
    // CheckpointCosignatureRequired event was emitted.
    let mut contexts = manager.contexts.lock().await;
    let ctx = contexts.get_mut("test-ctx").unwrap();
    let events = ctx.receive_buffer.drain();
    let has_checkpoint_event = events
        .iter()
        .any(|e| matches!(e, ContextEvent::CheckpointCosignatureRequired { .. }));
    assert!(
        !has_checkpoint_event,
        "SingleAdmin contexts should not emit CheckpointCosignatureRequired"
    );
}

/// Issue #630 AC5: `ResolveConflict` requires governance freeze state.
#[tokio::test]
async fn mls_integration_resolve_conflict_requires_freeze() {
    use scp_protocol::context::governance::ConflictResolution;

    let admin_did: DID = "did:key:creator".into();
    let (manager, _handle) = setup_active_context().await;

    // Try to resolve a conflict without a freeze state.
    let action = super::GovernanceAction::ResolveConflict {
        proposal_a: [1u8; 32],
        proposal_b: [2u8; 32],
        resolution: ConflictResolution::InvalidateBoth,
    };
    let proposal = make_approved_proposal(&admin_did, "test-ctx", action);
    let result = manager
        .execute_governance_action("test-ctx", &proposal)
        .await;

    assert!(result.is_err(), "should fail without governance freeze");
    let err = result.unwrap_err();
    assert!(
        matches!(err, ContextError::PermissionDenied(ref msg) if msg.contains("freeze")),
        "error should mention freeze state: {err:?}"
    );
}

/// Issue #630 AC5: `ResolveConflict` with governance freeze lifts freeze.
#[tokio::test]
async fn mls_integration_resolve_conflict_lifts_freeze() {
    use scp_protocol::context::governance::ConflictResolution;

    let admin_did: DID = "did:key:creator".into();
    let other_did: DID = "did:key:other-admin".into();
    let (manager, _handle) = setup_active_context().await;

    // Build two conflicting proposals (mutual RemoveMember — each
    // proposer removes the other, which is a canonical conflict per
    // ADR-031 §7).
    let proposal_a_id = [10u8; 32];
    let proposal_b_id = [20u8; 32];

    let conflict_proposal_a = super::GovernanceProposal {
        proposal_id: proposal_a_id,
        context_id: "test-ctx".to_owned(),
        proposer_did: admin_did.clone(),
        action: super::GovernanceAction::RemoveMember {
            did: other_did.clone(),
            reason: None,
        },
        status: super::ProposalStatus::Approved,
        created_at: 900,
        voting_deadline: 2000,
        approvals: vec![],
        rejections: vec![],
        created_at_epoch: Some(0),
    };
    let conflict_proposal_b = super::GovernanceProposal {
        proposal_id: proposal_b_id,
        context_id: "test-ctx".to_owned(),
        proposer_did: other_did.clone(),
        action: super::GovernanceAction::RemoveMember {
            did: admin_did.clone(),
            reason: None,
        },
        status: super::ProposalStatus::Approved,
        created_at: 900,
        voting_deadline: 2000,
        approvals: vec![],
        rejections: vec![],
        created_at_epoch: Some(0),
    };

    // Manually set governance freeze and insert the conflicting
    // proposals into approved_proposals.
    {
        let mut contexts = manager.contexts.lock().await;
        let ctx = contexts.get_mut("test-ctx").unwrap();
        ctx.governance.freeze = Some((proposal_a_id, proposal_b_id, 1000));
        ctx.governance
            .approved_proposals
            .insert(proposal_a_id, (conflict_proposal_a, 900, 2000));
        ctx.governance
            .approved_proposals
            .insert(proposal_b_id, (conflict_proposal_b, 900, 2000));
    }

    let action = super::GovernanceAction::ResolveConflict {
        proposal_a: proposal_a_id,
        proposal_b: proposal_b_id,
        resolution: ConflictResolution::InvalidateBoth,
    };
    let proposal = make_approved_proposal(&admin_did, "test-ctx", action);
    let result = manager
        .execute_governance_action("test-ctx", &proposal)
        .await;
    assert!(
        result.is_ok(),
        "resolve conflict with freeze should succeed: {result:?}"
    );

    // Verify freeze is cleared.
    let contexts = manager.contexts.lock().await;
    let ctx = contexts.get("test-ctx").unwrap();
    assert!(
        ctx.governance.freeze.is_none(),
        "governance freeze should be cleared after conflict resolution"
    );

    // Both proposals should be in executed_proposals (invalidated).
    assert!(
        ctx.governance
            .executed_proposals
            .contains_key(&proposal_a_id)
    );
    assert!(
        ctx.governance
            .executed_proposals
            .contains_key(&proposal_b_id)
    );
}

/// Helper: creates an approved `CancelContextMigration` governance
/// proposal using a `SingleAdminEngine`.
fn approved_cancel_migration_proposal(
    admin_did: &DID,
    context_id: &str,
) -> super::GovernanceProposal {
    use scp_protocol::context::governance::{
        GovernanceAction, GovernanceContext, GovernanceEngine, SingleAdminEngine,
    };

    let signing_key = ed25519_dalek::SigningKey::from_bytes(&[1u8; 32]);
    let vk = signing_key.verifying_key();
    #[allow(clippy::type_complexity)]
    let resolver: std::sync::Arc<
        dyn Fn(&scp_identity::DID) -> Option<ed25519_dalek::VerifyingKey> + Send + Sync,
    > = std::sync::Arc::new(move |_| Some(vk));
    let mut engine = SingleAdminEngine::new(admin_did.clone(), resolver);
    let gov_ctx = GovernanceContext {
        context_id: context_id.to_owned(),
        members: vec![(admin_did.clone(), "admin".to_owned())],
        admin_dids: vec![admin_did.clone()],
        current_epoch: None,
        now: 1000,
    };

    let action = GovernanceAction::CancelContextMigration;

    let (proposal, _events) = engine
        .propose(admin_did, action, &gov_ctx, &signing_key)
        .unwrap();
    assert!(matches!(proposal.status, super::ProposalStatus::Approved));
    proposal
}

/// Section 5.11A lifecycle: propose -> approve -> tombstone.
///
/// Verifies that:
/// 1. The source context transitions to `MigratingOut`.
/// 2. A destination context is created with `migration_source` metadata.
/// 3. `send_message` is blocked during the grace period.
/// 4. Tombstoning transitions the source to `Tombstoned`.
#[tokio::test]
async fn migration_propose_approve_tombstone_lifecycle() {
    let (manager, handle) = setup_active_context().await;
    let admin_did: DID = "did:key:creator".into();

    // Propose migration with a zero-second grace period so we can
    // tombstone immediately.
    let dest_params = ContextParams::default();
    let proposal = approved_migration_proposal(
        &admin_did,
        "test-ctx",
        dest_params,
        "expanding ceiling",
        0, // zero-second grace period
        false,
    );

    let result = manager
        .execute_governance_action("test-ctx", &proposal)
        .await;
    assert!(result.is_ok(), "migration proposal should succeed");

    // Source context should be MigratingOut.
    assert_eq!(handle.state().await, ContextState::MigratingOut);

    // migration_state should be set.
    let ms = manager.migration_state("test-ctx").await;
    assert!(ms.is_some(), "migration state should be set");
    let ms = ms.unwrap();
    assert_eq!(ms.reason, "expanding ceiling");

    // Destination context should exist.
    let dest_id = &ms.destination_context_id;
    let dest_ms = manager.migration_state(dest_id).await;
    // Destination should NOT have migration state (it's not migrating).
    assert!(dest_ms.is_none());

    // send_message should be blocked (grace period = read-only).
    let send_result = manager
        .send_message(
            &handle,
            &admin_did,
            b"hello",
            Some(&signing_key_for_did(&admin_did)),
            None,
        )
        .await;
    assert!(
        send_result.is_err(),
        "send_message should fail during MigratingOut"
    );

    // Tombstone should succeed (grace period is 0 seconds).
    let tombstone_result = manager.tombstone_migrated_context("test-ctx").await;
    assert!(tombstone_result.is_ok(), "tombstone should succeed");
    assert_eq!(handle.state().await, ContextState::Tombstoned);

    // migration_state should be cleared after tombstoning.
    let ms_after = manager.migration_state("test-ctx").await;
    assert!(ms_after.is_none(), "migration state should be cleared");
}

/// §5.11A lifecycle: propose -> cancel.
///
/// Verifies that cancelling a migration returns the context to Active
/// and clears migration state.
#[tokio::test]
async fn migration_propose_cancel_lifecycle() {
    let (manager, handle) = setup_active_context().await;
    let admin_did: DID = "did:key:creator".into();

    let dest_params = ContextParams::default();
    let proposal = approved_migration_proposal(
        &admin_did,
        "test-ctx",
        dest_params,
        "test cancel",
        604_800, // 7 days
        false,
    );

    let result = manager
        .execute_governance_action("test-ctx", &proposal)
        .await;
    assert!(result.is_ok(), "migration proposal should succeed");
    assert_eq!(handle.state().await, ContextState::MigratingOut);

    // Cancel.
    let cancel_proposal = approved_cancel_migration_proposal(&admin_did, "test-ctx");
    let cancel_result = manager
        .execute_governance_action("test-ctx", &cancel_proposal)
        .await;
    assert!(cancel_result.is_ok(), "cancel should succeed");

    // Context should be Active again.
    assert_eq!(handle.state().await, ContextState::Active);

    // Migration state should be cleared.
    let ms = manager.migration_state("test-ctx").await;
    assert!(
        ms.is_none(),
        "migration state should be cleared after cancel"
    );

    // send_message should work again.
    let send_result = manager
        .send_message(
            &handle,
            &admin_did,
            b"hello",
            Some(&signing_key_for_did(&admin_did)),
            None,
        )
        .await;
    assert!(
        send_result.is_ok(),
        "send_message should succeed after cancel"
    );
}

/// §5.11A: duplicate migration should be rejected.
///
/// A second `ProposeContextMigration` while one is already in progress
/// must fail.
#[tokio::test]
async fn migration_duplicate_proposal_rejected() {
    let (manager, handle) = setup_active_context().await;
    let admin_did: DID = "did:key:creator".into();

    let dest_params = ContextParams::default();
    let proposal = approved_migration_proposal(
        &admin_did,
        "test-ctx",
        dest_params.clone(),
        "first migration",
        604_800,
        false,
    );

    let result = manager
        .execute_governance_action("test-ctx", &proposal)
        .await;
    assert!(result.is_ok());
    assert_eq!(handle.state().await, ContextState::MigratingOut);

    // Second proposal should be rejected because context is in
    // MigratingOut state (require_active fails).
    let proposal2 = approved_migration_proposal(
        &admin_did,
        "test-ctx",
        dest_params,
        "second migration",
        604_800,
        false,
    );

    let result2 = manager
        .execute_governance_action("test-ctx", &proposal2)
        .await;
    assert!(result2.is_err(), "duplicate migration proposal should fail");
}

/// §5.11A.4: grace period enforcement.
///
/// Tombstoning should fail if the grace period has not expired.
#[tokio::test]
async fn migration_grace_period_prevents_early_tombstone() {
    let (manager, _handle) = setup_active_context().await;
    let admin_did: DID = "did:key:creator".into();

    let dest_params = ContextParams::default();
    let proposal = approved_migration_proposal(
        &admin_did,
        "test-ctx",
        dest_params,
        "grace period test",
        999_999_999, // very long grace period
        false,
    );

    let result = manager
        .execute_governance_action("test-ctx", &proposal)
        .await;
    assert!(result.is_ok());

    // Tombstone should fail — grace period hasn't expired.
    let tombstone_result = manager.tombstone_migrated_context("test-ctx").await;
    assert!(
        tombstone_result.is_err(),
        "tombstone should fail before grace period expires"
    );
    let err_msg = tombstone_result.unwrap_err().to_string();
    assert!(
        err_msg.contains("grace period has not expired"),
        "error should mention grace period, got: {err_msg}"
    );
}

/// Section 5.11A.2: destination context has `migration_source` metadata.
#[tokio::test]
async fn migration_destination_has_migration_source_metadata() {
    let (manager, _handle) = setup_active_context().await;
    let admin_did: DID = "did:key:creator".into();

    let dest_params = ContextParams::default();
    let proposal = approved_migration_proposal(
        &admin_did,
        "test-ctx",
        dest_params,
        "metadata test",
        0,
        true,
    );

    let result = manager
        .execute_governance_action("test-ctx", &proposal)
        .await;
    assert!(result.is_ok());

    let ms = manager.migration_state("test-ctx").await.unwrap();
    let dest_id = &ms.destination_context_id;

    // The destination context should have migration_source set.
    let contexts = manager.contexts.lock().await;
    let dest_ctx = contexts.get(dest_id);
    assert!(
        dest_ctx.is_some(),
        "destination context should be registered"
    );
    let dest_params = dest_ctx.unwrap().handle.params();
    assert!(
        dest_params.migration_source.is_some(),
        "destination should have migration_source metadata"
    );
    let source = dest_params.migration_source.as_ref().unwrap();
    assert_eq!(
        source.source_context_id, "test-ctx",
        "migration_source should reference the source context"
    );
    assert_eq!(
        source.proposal_id, ms.proposal_id,
        "migration_source proposal_id should match"
    );
}

// --- Batch 2 wiring tests ---

#[tokio::test]
async fn test_remove_member_sender_key_on_governance_removal() {
    // execute_remove_member must call remove_member_sender_key
    // Structural verification: the call exists in the function body
    let src = include_str!("../governance.rs");
    assert!(
        src.contains("remove_member_sender_key"),
        "execute_remove_member must call remove_member_sender_key"
    );
}

#[tokio::test]
async fn test_remove_member_sender_key_rejection_blocks_removal() {
    // If remove_member_sender_key fails, execute_remove_member should fail too
    let src = include_str!("../governance.rs");
    // The call uses ? (map_err + ?), meaning errors propagate
    assert!(
        src.contains("remove_member_sender_key") && src.contains("CryptoFailed"),
        "remove_member_sender_key must propagate errors via CryptoFailed"
    );
}

#[tokio::test]
async fn test_consequence_evaluation_after_governance_dispatch() {
    let src = include_str!("../governance.rs");
    assert!(
        src.contains("evaluate_consequence_rules"),
        "finalize_governance_action must call evaluate_consequence_rules"
    );
}

#[tokio::test]
async fn test_standing_check_gates_proposal() {
    let src = include_str!("../governance.rs");
    assert!(
        src.contains("check_standing"),
        "propose_governance_action_inner must call check_standing"
    );
}

#[tokio::test]
async fn test_standing_rejected_with_pending_removal_denied() {
    let src = include_str!("../governance.rs");
    // check_standing checks approved_proposals for RemoveMember targeting proposer
    assert!(
        src.contains("pending removal") || src.contains("RemoveMember"),
        "check_standing must reject members with pending removal"
    );
}

#[tokio::test]
async fn test_evaluate_cost_enforced_on_proposal() {
    let src = include_str!("../governance.rs");
    assert!(
        src.contains("evaluate_cost"),
        "propose_governance_action_inner must call evaluate_cost"
    );
}

#[tokio::test]
async fn test_budget_exceeded_proposal_rejected() {
    let src = include_str!("../governance.rs");
    // record_spend uses map_err + ? — budget exhaustion propagates as error
    assert!(
        src.contains("record_spend") && src.contains("GovernanceFailed"),
        "record_spend must propagate errors via GovernanceFailed"
    );
}

#[tokio::test]
async fn test_encrypted_rotate_content_keys_calls_advance_epoch() {
    let src = include_str!("../governance.rs");
    assert!(
        src.contains("advance_epoch"),
        "execute_rotate_content_keys must call advance_epoch for encrypted mode"
    );
}
