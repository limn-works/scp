use super::*;

// -----------------------------------------------------------------------
// Member tracking tests
// -----------------------------------------------------------------------

#[tokio::test]
async fn member_list_queries() {
    let (manager, handle) = setup_active_context().await;

    // Initially only creator.
    assert_eq!(manager.member_count("test-ctx").await, Some(1));
    assert!(manager.is_member("test-ctx", "did:key:creator").await);

    // Add members.
    for name in &["alice", "bob", "charlie"] {
        let kp = KeyPackage::mock(format!("did:key:{name}").into());
        manager.join_context(&handle, kp, None, None).await.unwrap();
    }

    assert_eq!(manager.member_count("test-ctx").await, Some(4));
    assert!(manager.is_member("test-ctx", "did:key:alice").await);
    assert!(manager.is_member("test-ctx", "did:key:bob").await);
    assert!(manager.is_member("test-ctx", "did:key:charlie").await);

    let mut dids = manager.member_dids("test-ctx").await;
    dids.sort();
    assert_eq!(
        dids,
        vec![
            "did:key:alice",
            "did:key:bob",
            "did:key:charlie",
            "did:key:creator"
        ]
    );
}

#[tokio::test]
async fn member_role_assignment() {
    let (manager, handle) = setup_active_context().await;

    // Creator should be admin.
    let role = manager.member_role("test-ctx", "did:key:creator").await;
    assert!(role.is_some());
    assert_eq!(role.unwrap().role_name, "admin");

    // Add a member.
    let kp = KeyPackage::mock("did:key:alice".into());
    manager.join_context(&handle, kp, None, None).await.unwrap();

    let role = manager.member_role("test-ctx", "did:key:alice").await;
    assert!(role.is_some());
    assert_eq!(role.unwrap().role_name, "member");
}

// -----------------------------------------------------------------------
// Caller identity validation tests (#234)
// -----------------------------------------------------------------------

/// #234: `register_local_did` registers a DID as locally controlled,
/// and `is_local_did` confirms it.
#[tokio::test]
async fn register_local_did_is_queryable() {
    let manager = ContextManager::new(
        Box::new(MockCrypto::default()),
        Box::new(MockTransport::connected()),
        Box::new(MockEventLog::default()),
        noop_key_resolver(),
    );

    let did: DID = "did:key:local1".into();
    assert!(!manager.is_local_did(&did).await);

    manager.register_local_did(did.clone()).await;
    assert!(manager.is_local_did(&did).await);

    // Idempotent: re-registering is a no-op.
    manager.register_local_did(did.clone()).await;
    assert!(manager.is_local_did(&did).await);
}

/// #234: `handle_broadcast_key_request` with a locally controlled DID
/// succeeds (positive case -- defense-in-depth validation passes).
#[tokio::test]
async fn handle_broadcast_key_request_succeeds_with_local_did() {
    use scp_protocol::crypto::ucan::validate::{
        InMemoryDidResolver, InMemoryNonceTracker, InMemoryProofResolver, InMemoryRevocationChecker,
    };
    use std::hash::RandomState;

    let (manager, _handle, ctx_id) = setup_broadcast_context().await;

    // Subscribe a requester.
    manager
        .subscribe_broadcast::<
            InMemoryDidResolver,
            InMemoryNonceTracker,
            InMemoryRevocationChecker,
            InMemoryProofResolver,
            RandomState,
        >(
            &ctx_id,
            &"did:key:sub1".into(),
            None,
            1000,
            None,
        )
        .await
        .unwrap();

    // author1 is registered as a local DID by setup_broadcast_context.
    let decision = manager
        .handle_broadcast_key_request(&ctx_id, &"did:key:author1".into(), &"did:key:sub1".into())
        .await
        .unwrap();

    assert!(
        matches!(decision, super::KeyRequestDecision::Grant { .. }),
        "key request with locally controlled author DID should be granted"
    );
}

/// #234: `handle_broadcast_key_request` with an uncontrolled DID returns
/// `PermissionDenied` (negative case -- defense-in-depth validation
/// rejects the request before reaching `BroadcastContext`).
#[tokio::test]
async fn handle_broadcast_key_request_rejects_non_local_did() {
    use scp_protocol::crypto::ucan::validate::{
        InMemoryDidResolver, InMemoryNonceTracker, InMemoryProofResolver, InMemoryRevocationChecker,
    };
    use std::hash::RandomState;

    let (manager, _handle, ctx_id) = setup_broadcast_context().await;

    // Subscribe a requester.
    manager
        .subscribe_broadcast::<
            InMemoryDidResolver,
            InMemoryNonceTracker,
            InMemoryRevocationChecker,
            InMemoryProofResolver,
            RandomState,
        >(
            &ctx_id,
            &"did:key:sub1".into(),
            None,
            1000,
            None,
        )
        .await
        .unwrap();

    // "did:key:unknown-author" is NOT registered as a local DID.
    let result = manager
        .handle_broadcast_key_request(
            &ctx_id,
            &"did:key:unknown-author".into(),
            &"did:key:sub1".into(),
        )
        .await;

    assert!(result.is_err(), "should reject non-local author DID");
    let err = result.unwrap_err();
    assert!(
        matches!(err, ContextError::PermissionDenied(ref msg) if msg.contains("not controlled")),
        "error should be PermissionDenied with descriptive message, got: {err}"
    );
}

/// #234: blocked subscriber's key request still returns `Deny` (not
/// `PermissionDenied`) -- block list information is not leaked through
/// the new validation layer. The defense-in-depth check runs first,
/// but when the caller IS the local author, the existing block list
/// logic applies as before.
#[tokio::test]
async fn handle_broadcast_key_request_deny_does_not_leak_block_info() {
    use scp_protocol::crypto::ucan::validate::{
        InMemoryDidResolver, InMemoryNonceTracker, InMemoryProofResolver, InMemoryRevocationChecker,
    };
    use std::hash::RandomState;

    let (manager, _handle, ctx_id) = setup_broadcast_context().await;

    // Subscribe then block.
    manager
        .subscribe_broadcast::<
            InMemoryDidResolver,
            InMemoryNonceTracker,
            InMemoryRevocationChecker,
            InMemoryProofResolver,
            RandomState,
        >(
            &ctx_id,
            &"did:key:blocked-sub".into(),
            None,
            1000,
            None,
        )
        .await
        .unwrap();

    manager
        .block_broadcast_subscriber(
            &ctx_id,
            &"did:key:author1".into(),
            &"did:key:blocked-sub".into(),
        )
        .await
        .unwrap();

    // Key request for blocked subscriber returns Deny (not a
    // PermissionDenied error). The deny reason is generic and does
    // not reveal whether the subscriber is blocked or unregistered.
    let decision = manager
        .handle_broadcast_key_request(
            &ctx_id,
            &"did:key:author1".into(),
            &"did:key:blocked-sub".into(),
        )
        .await
        .unwrap();

    assert!(
        matches!(decision, super::KeyRequestDecision::Deny { .. }),
        "blocked subscriber should receive Deny decision"
    );
}

/// #234: DID validation runs before context lookup. When a non-local DID
/// is used AND the context doesn't exist, the result is `PermissionDenied`
/// (not `ContextNotRegistered`). This documents
/// the intentional fail-closed ordering: unauthenticated callers cannot
/// probe for context existence.
#[tokio::test]
async fn handle_broadcast_key_request_rejects_non_local_did_before_context_lookup() {
    // Create a manager but don't create any contexts.
    let manager = ContextManager::new(
        Box::new(MockCrypto::default()),
        Box::new(MockTransport::connected()),
        Box::new(MockEventLog::default()),
        noop_key_resolver(),
    );

    // Neither the author DID nor the context exist.
    let result = manager
        .handle_broadcast_key_request(
            "nonexistent-context",
            &"did:key:unregistered-author".into(),
            &"did:key:some-requester".into(),
        )
        .await;

    assert!(result.is_err(), "should reject non-local author DID");
    let err = result.unwrap_err();
    assert!(
        matches!(err, ContextError::PermissionDenied(_)),
        "should be PermissionDenied (DID check), not MembershipFailed (context lookup): {err}"
    );
}

// -----------------------------------------------------------------------
// SCP-OUT-012: Query outlet structural cost floor (§5.4.2)
// -----------------------------------------------------------------------

/// Helper: build a Query/Action `OutletRegistration` for SCP-OUT-012 tests.
fn out012_query_reg(
    outlet_id: &str,
    kind: scp_protocol::context::outlets::OutletKind,
    cost: Option<scp_protocol::context::outlets::registry::OutletCost>,
) -> OutletRegistration {
    use scp_protocol::context::outlets::registry::OutletSchema;
    OutletRegistration {
        outlet_id: outlet_id.to_owned(),
        kind,
        name: outlet_id.to_owned(),
        description: "SCP-OUT-012 fixture".to_owned(),
        schema: OutletSchema {
            input_schema: serde_json::json!({"type": "object"}),
            output_schema: serde_json::json!({"type": "object"}),
            aggregate_schema: None,
        },
        implementation_hash: [0u8; 32],
        test_vectors: Vec::new(),
        operator_did: "did:key:test-operator".into(),
        cost,
        registered_at: 0,
        signature: Vec::new(),
        message_catalog: Vec::new(),
    }
}

/// Counts the `OutletRegistered` events present in the event log.
fn out012_count_outlet_events(event_log: &MockEventLogWithActorDid) -> usize {
    event_log
        .entries
        .lock()
        .unwrap()
        .iter()
        .filter(|(_, name, _, _, _)| name == "OutletRegistered")
        .count()
}

/// SCP-OUT-012 AC: registering a Query outlet with `cost.amount = 1`
/// fails end-to-end through `ContextManager::execute_register_outlet`
/// (the runtime event-log commit boundary). The registry is unchanged
/// and no `OutletRegistered` event lands in the event log.
#[tokio::test]
async fn execute_register_outlet_rejects_query_with_positive_cost() {
    use scp_protocol::context::outlets::OutletKind;
    use scp_protocol::context::outlets::registry::OutletCost;

    // Use ArcEventLog so we can inspect the event-log contents after
    // the rejected registration to confirm no event was appended.
    let event_log = std::sync::Arc::new(MockEventLogWithActorDid::default());
    let manager = ContextManager::new(
        Box::new(MockCrypto::default()),
        Box::new(MockTransport::connected()),
        Box::new(ArcEventLog(event_log.clone())),
        noop_key_resolver(),
    );
    let params = ContextParams {
        ceiling: vec![
            scp_protocol::context::params::Capability::new("messages:read")
                .expect("known capability"),
            scp_protocol::context::params::Capability::new("messages:write")
                .expect("known capability"),
            scp_protocol::context::params::Capability::new("role:assign")
                .expect("known capability"),
            Capability::OutletRegister,
        ],
        ..ContextParams::default()
    };
    let _handle = manager
        .create_context("test-ctx".into(), params, "did:key:creator".into(), None)
        .await
        .unwrap();

    // Baseline: no OutletRegistered events landed before the test mutation.
    assert_eq!(out012_count_outlet_events(&event_log), 0);

    // Bad registration: Query + cost.amount = 1 (§5.4.2 violation).
    let bad_reg = out012_query_reg(
        "query-paid",
        OutletKind::Query,
        Some(OutletCost {
            amount: 1,
            currency: "USD".to_owned(),
            payee: "did:key:payee".into(),
            cost_formula: None,
        }),
    );

    let pid: ProposalId = [0u8; 32];
    let err = manager
        .execute_register_outlet("test-ctx", &bad_reg, pid, "did:key:creator")
        .await
        .expect_err("Query+cost.amount=1 must be rejected at the runtime boundary");

    // Verify the typed code surface: SCP-TOOL-6102 (Query cost violation).
    let err_str = err.to_string();
    assert!(
        matches!(err, ContextError::PermissionDenied(ref msg) if msg.contains("SCP-TOOL-6102")),
        "expected PermissionDenied carrying SCP-TOOL-6102, got: {err_str}"
    );
    assert!(
        err_str.contains("§5.4.2"),
        "error must cite §5.4.2 for traceability, got: {err_str}"
    );

    // The runtime MUST NOT emit an OutletRegistered event for the rejection.
    assert_eq!(
        out012_count_outlet_events(&event_log),
        0,
        "rejected Query+cost registration must NOT produce an OutletRegistered event"
    );

    // Sanity: a subsequent valid Query registration with cost = None
    // succeeds — proves the rejection was specifically about the cost
    // (not the ceiling) and the registry is in a clean state.
    let good_reg = out012_query_reg("query-free", OutletKind::Query, None);
    manager
        .execute_register_outlet("test-ctx", &good_reg, pid, "did:key:creator")
        .await
        .expect("Query+cost=None must register successfully");
    assert_eq!(
        out012_count_outlet_events(&event_log),
        1,
        "exactly one OutletRegistered event should land — the valid follow-up"
    );
}

/// SCP-OUT-012: a Query outlet with `cost.cost_formula = Some(_)` is
/// likewise rejected at the runtime event-log commit boundary, even
/// when `cost.amount = 0` (§5.4.2: dynamic pricing on a Query is
/// incoherent).
#[tokio::test]
async fn execute_register_outlet_rejects_query_with_cost_formula() {
    use scp_protocol::context::outlets::OutletKind;
    use scp_protocol::context::outlets::registry::OutletCost;

    let (manager, _handle) = setup_active_context().await;

    let bad_reg = out012_query_reg(
        "query-formula",
        OutletKind::Query,
        Some(OutletCost {
            amount: 0,
            currency: "USD".to_owned(),
            payee: "did:key:payee".into(),
            cost_formula: Some("linear".to_owned()),
        }),
    );

    let pid: ProposalId = [0u8; 32];
    let err = manager
        .execute_register_outlet("test-ctx", &bad_reg, pid, "did:key:creator")
        .await
        .expect_err("Query+cost_formula must be rejected even at amount=0");

    let err_str = err.to_string();
    assert!(
        matches!(err, ContextError::PermissionDenied(ref msg) if msg.contains("SCP-TOOL-6102")),
        "expected PermissionDenied carrying SCP-TOOL-6102, got: {err_str}"
    );
    assert!(
        err_str.contains("cost_formula"),
        "error message must cite cost_formula, got: {err_str}"
    );
}

// -----------------------------------------------------------------------
// Collection bounds tests (#360, §5.9)
// -----------------------------------------------------------------------

/// Build a minimal valid [`OutletRegistration`] for bounds tests.
/// #360: register exactly 256 outlets (the limit), verify the 256th succeeds;
/// attempt to register a 257th, verify `LimitExceeded` is returned.
#[tokio::test]
async fn registered_outlets_bounded_at_256() {
    let (manager, _handle) = setup_active_context().await;
    let pid: ProposalId = [0u8; 32];

    // Register exactly MAX_REGISTERED_OUTLETS outlets.
    for i in 0..super::MAX_REGISTERED_OUTLETS {
        let reg = test_outlet_registration(&format!("tool-{i}"));
        manager
            .execute_register_outlet("test-ctx", &reg, pid, "")
            .await
            .unwrap();
    }

    // The 257th must fail with LimitExceeded.
    let overflow = test_outlet_registration("tool-overflow");
    let err = manager
        .execute_register_outlet("test-ctx", &overflow, pid, "")
        .await
        .unwrap_err();
    assert!(
        matches!(&err, ContextError::LimitExceeded(msg) if msg.contains("256")),
        "expected LimitExceeded with limit value, got: {err}"
    );
}

/// #360: establish exactly 256 outlet interfaces (the limit), verify the 256th
/// succeeds; attempt to establish a 257th, verify `LimitExceeded` is returned.
#[tokio::test]
async fn tool_interfaces_bounded_at_256() {
    let (manager, _handle) = setup_active_context().await;
    let pid: ProposalId = [0u8; 32];

    // Establish exactly MAX_TOOL_INTERFACES interfaces.
    for i in 0..super::MAX_TOOL_INTERFACES {
        let iface = OutletInterface {
            source_context: "test-ctx".to_owned(),
            target_context: format!("target-{i}"),
            outlet_id: format!("tool-{i}"),
            rate_limit: None,
            per_caller_rate_limit: None,
            approved_by_source: true,
            approved_by_target: true,
            outbound_policy: None,
            inbound_policy: None,
        };
        manager
            .execute_establish_tool_interface("test-ctx", &iface, pid, "")
            .await
            .unwrap();
    }

    // The 257th must fail with LimitExceeded.
    let overflow = OutletInterface {
        source_context: "test-ctx".to_owned(),
        target_context: "target-overflow".to_owned(),
        outlet_id: "tool-overflow".to_owned(),
        rate_limit: None,
        per_caller_rate_limit: None,
        approved_by_source: true,
        approved_by_target: true,
        outbound_policy: None,
        inbound_policy: None,
    };
    let err = manager
        .execute_establish_tool_interface("test-ctx", &overflow, pid, "")
        .await
        .unwrap_err();
    assert!(
        matches!(&err, ContextError::LimitExceeded(msg) if msg.contains("256")),
        "expected LimitExceeded with limit value, got: {err}"
    );
}

/// #360: add exactly 64 signers (the limit), verify the 64th succeeds;
/// attempt to add a 65th, verify `LimitExceeded` is returned.
#[tokio::test]
async fn threshold_signers_bounded_at_64() {
    let (manager, _handle) = setup_active_context().await;
    let pid: ProposalId = [0u8; 32];

    // First, add 64 members to the context so they pass the membership check.
    // The creator ("did:key:creator") is already a member.
    let mut dids: Vec<DID> = Vec::with_capacity(super::MAX_THRESHOLD_SIGNERS);
    {
        let arc = manager.get_context_arc("test-ctx").unwrap();
        let mut g = arc.lock().await;
        let ctx = &mut *g;
        for i in 0..super::MAX_THRESHOLD_SIGNERS {
            let did: DID = format!("did:key:signer-{i}").into();
            ctx.membership
                .add_member(did.clone(), "member".to_owned(), vec![]);
            dids.push(did);
        }
    }

    // Add exactly MAX_THRESHOLD_SIGNERS signers.
    for did in &dids {
        manager
            .execute_add_signer("test-ctx", did, pid, "")
            .await
            .unwrap();
    }

    // The 65th must fail with LimitExceeded.
    let overflow_did: DID = "did:key:signer-overflow".into();
    {
        let arc = manager.get_context_arc("test-ctx").unwrap();
        let mut g = arc.lock().await;
        let ctx = &mut *g;
        ctx.membership
            .add_member(overflow_did.clone(), "member".to_owned(), vec![]);
    }
    let err = manager
        .execute_add_signer("test-ctx", &overflow_did, pid, "")
        .await
        .unwrap_err();
    assert!(
        matches!(&err, ContextError::LimitExceeded(msg) if msg.contains("64")),
        "expected LimitExceeded with limit value, got: {err}"
    );
}

// -----------------------------------------------------------------------
// get_broadcast_key_for_local_author
// -----------------------------------------------------------------------

#[tokio::test]
async fn get_broadcast_key_for_local_author_returns_key_and_epoch() {
    use zeroize::Zeroizing;

    let manager = ContextManager::new(
        Box::<MockCrypto>::default(),
        Box::new(MockTransport::default()),
        Box::new(MockEventLog::default()),
        noop_key_resolver(),
    );

    let creator_did: DID = "did:key:creator1".into();
    manager.register_local_did(creator_did.clone()).await;

    let params = ContextParams {
        mode: ContextMode::Broadcast,
        memory_scope: MemoryScope::Full,
        ..Default::default()
    };

    let _handle = manager
        .create_context("bc-key-test".into(), params, creator_did.clone(), None)
        .await
        .unwrap();

    let (key_bytes, epoch) = manager
        .get_broadcast_key_for_local_author("bc-key-test", creator_did.as_ref())
        .await
        .unwrap();

    assert_eq!(epoch, 0, "initial epoch should be 0");
    // Key should be 32 bytes, non-zero (randomly generated).
    let zero = Zeroizing::new([0u8; 32]);
    assert_ne!(key_bytes, zero, "broadcast key must not be all zeros");
}

#[tokio::test]
async fn get_broadcast_key_for_local_author_rejects_non_local_did() {
    let manager = ContextManager::new(
        Box::<MockCrypto>::default(),
        Box::new(MockTransport::default()),
        Box::new(MockEventLog::default()),
        noop_key_resolver(),
    );

    let creator_did: DID = "did:key:creator2".into();
    manager.register_local_did(creator_did.clone()).await;

    let params = ContextParams {
        mode: ContextMode::Broadcast,
        memory_scope: MemoryScope::Full,
        ..Default::default()
    };

    let _handle = manager
        .create_context("bc-key-test-2".into(), params, creator_did.clone(), None)
        .await
        .unwrap();

    let result = manager
        .get_broadcast_key_for_local_author("bc-key-test-2", "did:key:not-local")
        .await;

    assert!(result.is_err(), "should reject non-local DID");
    assert!(
        matches!(result.unwrap_err(), ContextError::PermissionDenied(_)),
        "error should be PermissionDenied"
    );
}

#[tokio::test]
async fn get_broadcast_key_for_local_author_rejects_unknown_context() {
    let manager = ContextManager::new(
        Box::<MockCrypto>::default(),
        Box::new(MockTransport::default()),
        Box::new(MockEventLog::default()),
        noop_key_resolver(),
    );

    let did: DID = "did:key:creator3".into();
    manager.register_local_did(did.clone()).await;

    let result = manager
        .get_broadcast_key_for_local_author("nonexistent-ctx", did.as_ref())
        .await;

    assert!(result.is_err(), "should reject unknown context");
    assert!(
        matches!(result.unwrap_err(), ContextError::ContextNotRegistered(_)),
        "error should be ContextNotRegistered"
    );
}

#[tokio::test]
async fn get_broadcast_key_for_local_author_rejects_encrypted_context() {
    let manager = ContextManager::new(
        Box::<MockCrypto>::default(),
        Box::new(MockTransport::default()),
        Box::new(MockEventLog::default()),
        noop_key_resolver(),
    );

    let creator_did: DID = "did:key:creator4".into();
    manager.register_local_did(creator_did.clone()).await;

    // Default mode is Encrypted, not Broadcast.
    let params = ContextParams::default();

    let _handle = manager
        .create_context("encrypted-ctx".into(), params, creator_did.clone(), None)
        .await
        .unwrap();

    let result = manager
        .get_broadcast_key_for_local_author("encrypted-ctx", creator_did.as_ref())
        .await;

    assert!(result.is_err(), "should reject encrypted context");
    assert!(
        matches!(result.unwrap_err(), ContextError::MembershipFailed(_)),
        "error should be MembershipFailed (not a broadcast context)"
    );
}

// -----------------------------------------------------------------------
// Checkpoint tests (§9.9.3, ADR-011 AC-8)
// -----------------------------------------------------------------------

/// Checkpoint is NOT created when neither event nor time threshold is met.
#[tokio::test]
async fn checkpoint_not_created_below_thresholds() {
    let (manager, _handle) = setup_active_context().await;
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&[42u8; 32]);
    let sender_did = DID("did:key:creator".into());

    let arc = manager.get_context_arc("test-ctx").unwrap();
    let mut g = arc.lock().await;
    let ctx = &mut *g;

    // Fresh context: 0 events, timestamp is recent → no checkpoint due.
    let result = manager.create_checkpoint_if_due("test-ctx", ctx, &sender_did, &signing_key);
    assert!(
        result.is_none(),
        "checkpoint should not be created with 0 events and recent timestamp"
    );
}

/// Checkpoint is created after 50 events.
#[tokio::test]
async fn checkpoint_created_after_50_events() {
    let (manager, _handle) = setup_active_context().await;
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&[42u8; 32]);
    let sender_did = DID("did:key:creator".into());

    let arc = manager.get_context_arc("test-ctx").unwrap();
    let mut g = arc.lock().await;
    let ctx = &mut *g;

    // Simulate 50 events.
    ctx.checkpoint_events_since = 50;

    let result = manager.create_checkpoint_if_due("test-ctx", ctx, &sender_did, &signing_key);
    assert!(
        result.is_some(),
        "checkpoint should be created after 50 events"
    );
    let cp = result.unwrap();
    assert_eq!(cp.context_id, "test-ctx");
    assert_eq!(cp.sender_did, sender_did);
    // Counter should be reset.
    assert_eq!(ctx.checkpoint_events_since, 0);
}

/// Checkpoint is created after 10 minutes (600 seconds).
#[tokio::test]
async fn checkpoint_created_after_10_minutes() {
    let (manager, _handle) = setup_active_context().await;
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&[42u8; 32]);
    let sender_did = DID("did:key:creator".into());

    let arc = manager.get_context_arc("test-ctx").unwrap();
    let mut g = arc.lock().await;
    let ctx = &mut *g;

    // Simulate 10+ minutes elapsed with at least 1 event.
    ctx.checkpoint_events_since = 1;
    ctx.checkpoint_last_time_secs = manager.clock.now_secs().saturating_sub(601);

    let result = manager.create_checkpoint_if_due("test-ctx", ctx, &sender_did, &signing_key);
    assert!(
        result.is_some(),
        "checkpoint should be created after 10 minutes"
    );
    let cp = result.unwrap();
    assert_eq!(cp.context_id, "test-ctx");
    // Last time should be updated.
    assert!(ctx.checkpoint_last_time_secs > 0);
}

/// Time-based checkpoint is NOT created when zero events have occurred,
/// even if 10+ minutes have elapsed.
#[tokio::test]
async fn checkpoint_not_created_with_zero_events_and_elapsed_time() {
    let (manager, _handle) = setup_active_context().await;
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&[42u8; 32]);
    let sender_did = DID("did:key:creator".into());

    let arc = manager.get_context_arc("test-ctx").unwrap();
    let mut g = arc.lock().await;
    let ctx = &mut *g;

    // Simulate 10+ minutes elapsed but zero events.
    ctx.checkpoint_events_since = 0;
    ctx.checkpoint_last_time_secs = manager.clock.now_secs().saturating_sub(601);

    let result = manager.create_checkpoint_if_due("test-ctx", ctx, &sender_did, &signing_key);
    assert!(
        result.is_none(),
        "checkpoint should NOT be created when zero events have occurred, even after time elapsed"
    );
}

/// Force checkpoint always creates regardless of thresholds.
#[tokio::test]
async fn force_checkpoint_always_creates() {
    let (manager, _handle) = setup_active_context().await;
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&[42u8; 32]);
    let sender_did = DID("did:key:creator".into());

    let arc = manager.get_context_arc("test-ctx").unwrap();
    let mut g = arc.lock().await;
    let ctx = &mut *g;

    // 0 events, recent timestamp — would NOT trigger a periodic checkpoint.
    ctx.checkpoint_events_since = 0;
    let result = manager.create_checkpoint_if_due("test-ctx", ctx, &sender_did, &signing_key);
    assert!(result.is_none(), "periodic should not fire");

    // But force always creates.
    let cp = manager.force_create_checkpoint("test-ctx", ctx, &sender_did, &signing_key);
    assert_eq!(cp.context_id, "test-ctx");
    assert_eq!(cp.sender_did, sender_did);
    assert_eq!(ctx.checkpoints.len(), 1);
}

/// `compare_remote_checkpoint` — consistent (same root and count).
#[tokio::test]
async fn compare_checkpoint_consistent() {
    let (manager, _handle) = setup_active_context_with_key_resolver().await;
    let sender_did = DID("did:key:creator".into());
    let context_id_bytes = scp_protocol::context::context_id_bytes("test-ctx");
    let local_root = manager
        .event_log
        .event_log_merkle_root(&context_id_bytes)
        .unwrap_or([0u8; 32]);
    let local_count = manager
        .event_log
        .event_log_entries(&context_id_bytes)
        .ok()
        .flatten()
        .map_or(0, |e| e.len() as u64);

    let remote = signed_checkpoint(
        "test-ctx",
        &sender_did,
        local_count,
        local_root,
        Some(0),
        1000,
    );

    let result = manager
        .compare_remote_checkpoint("test-ctx", &remote)
        .await
        .unwrap();
    assert_eq!(
        result,
        scp_event_log::checkpoint::CheckpointComparison::Consistent
    );
}

/// `compare_remote_checkpoint` — divergent (same count, different root).
#[tokio::test]
async fn compare_checkpoint_divergent() {
    let (manager, _handle) = setup_active_context_with_key_resolver().await;
    let sender_did = DID("did:key:creator".into());

    // Local has 1 event (ContextCreated). Set remote event_count to 1 with
    // a root that won't match the real hash, triggering Divergent.
    let remote = signed_checkpoint(
        "test-ctx",
        &sender_did,
        1,
        [0xFFu8; 32], // different from the real Merkle root
        Some(0),
        1000,
    );

    let result = manager
        .compare_remote_checkpoint("test-ctx", &remote)
        .await
        .unwrap();
    assert!(
        matches!(
            result,
            scp_event_log::checkpoint::CheckpointComparison::Divergent { .. }
        ),
        "same event count with different root should be Divergent, got {result:?}"
    );
}

/// `compare_remote_checkpoint` — behind (remote has more events).
#[tokio::test]
async fn compare_checkpoint_behind() {
    let (manager, _handle) = setup_active_context_with_key_resolver().await;
    let sender_did = DID("did:key:creator".into());

    let remote = signed_checkpoint(
        "test-ctx",
        &sender_did,
        100, // remote has 100, local has 1 (ContextCreated from create_context)
        [0u8; 32],
        Some(0),
        1000,
    );

    let result = manager
        .compare_remote_checkpoint("test-ctx", &remote)
        .await
        .unwrap();
    assert!(
        matches!(
            result,
            scp_event_log::checkpoint::CheckpointComparison::Behind { missing_events: 99 }
        ),
        "should be Behind with 99 missing events (100 - 1 ContextCreated), got {result:?}"
    );
}

/// `compare_remote_checkpoint` — ahead (local has more events).
///
/// Note: The default `MockEventLog` does not support `event_log_entries` reads,
/// so the local count is always 0. We verify the Ahead comparison by testing
/// with `event_count: 0` on the remote (matching the local mock) and a
/// negative case where local appears ahead is not reachable with the basic
/// mock. Instead, we validate the match arm exists via the Behind test above
/// and the Ahead code path via direct inspection.
///
/// The structural correctness of the Ahead branch is verified by the
/// `compare_checkpoint_behind` test (symmetric logic) and by the pipeline
/// wiring assertion `b3_merkle_proof_verification_wired`.
#[tokio::test]
async fn compare_checkpoint_ahead_verified_by_symmetry() {
    // The Ahead branch is exercised when local_count > remote.event_count.
    // MockEventLog now stores entries (including ContextCreated from
    // create_context), so local_count is 1 after setup. With
    // remote.event_count = 0, this exercises the Ahead branch.
    let (manager, _handle) = setup_active_context_with_key_resolver().await;
    let sender_did = DID("did:key:creator".into());

    let remote = signed_checkpoint(
        "test-ctx",
        &sender_did,
        0,
        [0u8; 32], // empty log root
        Some(0),
        1000,
    );

    let result = manager
        .compare_remote_checkpoint("test-ctx", &remote)
        .await
        .unwrap();
    // Local has 1 event (ContextCreated), remote has 0. Should be Ahead.
    assert!(
        matches!(
            result,
            scp_event_log::checkpoint::CheckpointComparison::Ahead { .. }
        ),
        "local (1 event) ahead of remote (0 events), got {result:?}"
    );
}

/// `compare_remote_checkpoint` — rejects non-member sender.
#[tokio::test]
async fn compare_checkpoint_rejects_non_member() {
    let (manager, _handle) = setup_active_context_with_key_resolver().await;
    let non_member = DID("did:key:outsider".into());

    let remote = signed_checkpoint("test-ctx", &non_member, 0, [0u8; 32], Some(0), 1000);

    let result = manager.compare_remote_checkpoint("test-ctx", &remote).await;
    assert!(result.is_err(), "should reject non-member sender");
    assert!(
        matches!(result.unwrap_err(), ContextError::MemberNotFound(_)),
        "error should be MemberNotFound"
    );
}

/// `compare_remote_checkpoint` — rejects tampered signature.
#[tokio::test]
async fn compare_checkpoint_rejects_invalid_signature() {
    let (manager, _handle) = setup_active_context_with_key_resolver().await;
    let sender_did = DID("did:key:creator".into());

    let mut remote = signed_checkpoint("test-ctx", &sender_did, 0, [0u8; 32], Some(0), 1000);
    // Tamper with the signature.
    remote.signature[0] ^= 0xFF;

    let result = manager.compare_remote_checkpoint("test-ctx", &remote).await;
    assert!(result.is_err(), "should reject tampered signature");
    assert!(
        matches!(result.unwrap_err(), ContextError::CryptoFailed(_)),
        "error should be CryptoFailed"
    );
}

// -----------------------------------------------------------------------
// Merkle proof tests (ADR-011, #1535)
// -----------------------------------------------------------------------

/// #1535: Send 5 messages, prove inclusion for each, verify all pass.
///
/// Each `send_message` call appends to the durable event log via the
/// provider. The per-context Merkle tree is lazily populated from the
/// provider at proof time via `sync_merkle_tree`, ensuring one consistent
/// hash format.
#[tokio::test]
async fn prove_event_inclusion_after_messages() {
    let (manager, handle) = setup_active_context().await;
    let sk = signing_key_for_did(&"did:key:creator".into());

    // Send 5 messages. Each send_message call appends a "MessageSent"
    // event to the per-context Merkle tree.
    for i in 1..=5u8 {
        manager
            .send_message(
                &handle,
                &"did:key:creator".into(),
                &[i],
                Some(&sk),
                None,
                None,
            )
            .await
            .unwrap();
    }

    // The Merkle tree should have exactly 5 entries (one per send_message).
    // Prove inclusion for each.
    for i in 0..5u64 {
        let proof = manager.prove_event_inclusion("test-ctx", i).await.unwrap();
        assert!(
            ContextManager::verify_event_inclusion(&proof),
            "inclusion proof for event {i} should verify"
        );
        assert_eq!(proof.leaf_index, i);
    }
}

/// #1535: Send 10 messages, prove consistency from size 5 to 10, verify.
#[tokio::test]
async fn prove_event_consistency_after_messages() {
    let (manager, handle) = setup_active_context().await;
    let sk = signing_key_for_did(&"did:key:creator".into());

    // Send 10 messages.
    for i in 1..=10u8 {
        manager
            .send_message(
                &handle,
                &"did:key:creator".into(),
                &[i],
                Some(&sk),
                None,
                None,
            )
            .await
            .unwrap();
    }

    // Prove consistency from size 5 to current size.
    // The total event count is 11: 1 ContextCreated (from create_context)
    // + 10 MessageSent. The Merkle tree is populated via sync_merkle_tree
    // from the event log provider, which includes all events.
    let proof = manager
        .prove_event_consistency("test-ctx", 5)
        .await
        .unwrap();
    assert!(
        ContextManager::verify_event_consistency(&proof),
        "consistency proof should verify"
    );
    assert_eq!(proof.old_size, 5);
    assert_eq!(proof.new_size, 11);
}

/// #1535: Prove inclusion with an invalid (out-of-bounds) index returns error.
#[tokio::test]
async fn prove_event_inclusion_invalid_index() {
    let (manager, handle) = setup_active_context().await;
    let sk = signing_key_for_did(&"did:key:creator".into());

    // Send one message so the Merkle tree has exactly 1 entry.
    manager
        .send_message(
            &handle,
            &"did:key:creator".into(),
            b"msg",
            Some(&sk),
            None,
            None,
        )
        .await
        .unwrap();

    // Index 999999 should be out of bounds (only 1 event exists).
    let result = manager.prove_event_inclusion("test-ctx", 999_999).await;
    assert!(result.is_err(), "out-of-bounds index should return error");
    assert!(matches!(
        result.unwrap_err(),
        ContextError::EventLogFailed(_)
    ));
}

/// #1535: Prove consistency with `old_size` > `current_size` returns error.
#[tokio::test]
async fn prove_event_consistency_old_size_too_large() {
    let (manager, handle) = setup_active_context().await;
    let sk = signing_key_for_did(&"did:key:creator".into());

    // Send one message so the Merkle tree has exactly 1 entry.
    manager
        .send_message(
            &handle,
            &"did:key:creator".into(),
            b"msg",
            Some(&sk),
            None,
            None,
        )
        .await
        .unwrap();

    // old_size 999999 should exceed current size (1 event).
    let result = manager.prove_event_consistency("test-ctx", 999_999).await;
    assert!(
        result.is_err(),
        "old_size exceeding current size should return error"
    );
    assert!(matches!(
        result.unwrap_err(),
        ContextError::EventLogFailed(_)
    ));
}

/// #1535: Pure verify functions reject tampered proofs.
#[tokio::test]
async fn verify_rejects_tampered_inclusion_proof() {
    let (manager, handle) = setup_active_context().await;
    let sk = signing_key_for_did(&"did:key:creator".into());

    manager
        .send_message(
            &handle,
            &"did:key:creator".into(),
            b"msg",
            Some(&sk),
            None,
            None,
        )
        .await
        .unwrap();

    let mut proof = manager.prove_event_inclusion("test-ctx", 0).await.unwrap();
    assert!(ContextManager::verify_event_inclusion(&proof));

    // Tamper with the root.
    proof.root[0] ^= 0xFF;
    assert!(
        !ContextManager::verify_event_inclusion(&proof),
        "tampered root should fail verification"
    );
}

/// #1535: Context not registered returns `ContextNotRegistered` error.
#[tokio::test]
async fn prove_event_inclusion_unknown_context() {
    let (manager, _handle) = setup_active_context().await;
    let result = manager.prove_event_inclusion("nonexistent-ctx", 0).await;
    assert!(matches!(
        result.unwrap_err(),
        ContextError::ContextNotRegistered(_)
    ));
}

// -----------------------------------------------------------------------
// §5.4.5 streaming-escrow reserve / settle tests (E1 / E2 remediation)
//
// These exercise the runtime's authoritative budget movement directly:
// `outlet_stream_reserve_escrow` DEBITS the open-time hold, the
// `outlet_stream_settle` path refunds the unspent portion so net spent ==
// billed, and two concurrent reserves cannot over-commit a single budget.
// -----------------------------------------------------------------------

/// Grants `amount` of budget to `did` in the test context.
async fn grant_stream_budget(manager: &ContextManager, context_id: &str, did: &DID, amount: u64) {
    let arc = manager.get_context_arc(context_id).unwrap();
    let mut g = arc.lock().await;
    g.governance
        .budget_tracker
        .grant(did, scp_protocol::economy::types::Amount::new(amount));
}

/// Reads the cumulative `total_spent` for `did` in the test context.
async fn stream_total_spent(manager: &ContextManager, context_id: &str, did: &DID) -> u64 {
    let arc = manager.get_context_arc(context_id).unwrap();
    let g = arc.lock().await;
    g.governance.budget_tracker.total_spent(did).value()
}

/// (a) A paid stream decrements the budget by exactly the billed amount at
/// close — the E1 regression guard (the pre-remediation code never debited,
/// so `total_spent` stayed 0).
#[tokio::test]
async fn outlet_stream_paid_decrements_budget_by_billed_at_close() {
    let (manager, _handle) = setup_active_context().await;
    let invoker: DID = "did:key:creator".into();
    grant_stream_budget(&manager, "test-ctx", &invoker, 1_000).await;

    // Reserve the open-time hold: cost_per_chunk = 10, estimate = 5 → hold 50.
    let reservation = manager
        .outlet_stream_reserve_escrow(
            "test-ctx",
            &invoker,
            scp_protocol::economy::types::Amount::new(10),
            5,
            None,
        )
        .await
        .expect("reserve must succeed within budget");
    assert_eq!(reservation.reserved.value(), 50, "hold == cost × estimate");
    // The hold is debited NOW.
    assert_eq!(stream_total_spent(&manager, "test-ctx", &invoker).await, 50);

    // Close: billed 3 chunks (30), refund 20.
    manager
        .outlet_stream_settle(
            "test-ctx",
            &invoker,
            scp_protocol::economy::types::Amount::new(30),
            scp_protocol::economy::types::Amount::new(20),
            3,
            *uuid::Uuid::now_v7().as_bytes(),
            &scp_protocol::context::outlets::OutletId::from("outlet-x"),
        )
        .await
        .expect("settle must succeed");

    // Net spent == billed (50 debited − 20 refunded == 30).
    assert_eq!(
        stream_total_spent(&manager, "test-ctx", &invoker).await,
        30,
        "net spent must equal the billed amount after refund"
    );
}

/// (b) Refund of unspent escrow: after a partial-consumption close the budget
/// reflects only the billed portion; a terminal error before any Data chunk
/// refunds the full hold (net spent 0).
#[tokio::test]
async fn outlet_stream_refunds_unspent_escrow() {
    let (manager, _handle) = setup_active_context().await;
    let invoker: DID = "did:key:creator".into();
    grant_stream_budget(&manager, "test-ctx", &invoker, 1_000).await;

    // Stream 1: hold B-worth (cost 4 × estimate 10 = 40), bill 6 chunks (24),
    // refund 16 → net spent 24.
    let r1 = manager
        .outlet_stream_reserve_escrow(
            "test-ctx",
            &invoker,
            scp_protocol::economy::types::Amount::new(4),
            10,
            None,
        )
        .await
        .unwrap();
    assert_eq!(r1.reserved.value(), 40);
    assert_eq!(stream_total_spent(&manager, "test-ctx", &invoker).await, 40);
    manager
        .outlet_stream_settle(
            "test-ctx",
            &invoker,
            scp_protocol::economy::types::Amount::new(24),
            scp_protocol::economy::types::Amount::new(16),
            6,
            *uuid::Uuid::now_v7().as_bytes(),
            &scp_protocol::context::outlets::OutletId::from("outlet-y"),
        )
        .await
        .unwrap();
    assert_eq!(
        stream_total_spent(&manager, "test-ctx", &invoker).await,
        24,
        "after partial-consumption close, spent == billed (B − refund)"
    );

    // Stream 2: terminal error before any Data chunk → full refund. Hold 40,
    // billed 0, refund 40 → net spent unchanged (still 24 from stream 1).
    let r2 = manager
        .outlet_stream_reserve_escrow(
            "test-ctx",
            &invoker,
            scp_protocol::economy::types::Amount::new(4),
            10,
            None,
        )
        .await
        .unwrap();
    assert_eq!(r2.reserved.value(), 40);
    assert_eq!(stream_total_spent(&manager, "test-ctx", &invoker).await, 64);
    manager
        .outlet_stream_settle(
            "test-ctx",
            &invoker,
            scp_protocol::economy::types::Amount::new(0),
            scp_protocol::economy::types::Amount::new(40),
            0,
            *uuid::Uuid::now_v7().as_bytes(),
            &scp_protocol::context::outlets::OutletId::from("outlet-y"),
        )
        .await
        .unwrap();
    assert_eq!(
        stream_total_spent(&manager, "test-ctx", &invoker).await,
        24,
        "terminal-error-before-Data refunds the full hold (net spent unchanged)"
    );
}

/// (c) Two concurrent opens cannot over-commit: with `2R > B ≥ R`, exactly one
/// reserve succeeds and the other is rejected with `EscrowInsufficientFunds`;
/// `total_spent` never exceeds `B`.
#[tokio::test]
async fn outlet_stream_concurrent_opens_cannot_over_commit() {
    let (manager, _handle) = setup_active_context().await;
    let invoker: DID = "did:key:creator".into();
    // B = 60; each reserve R = cost 10 × estimate 5 = 50. 2R = 100 > 60 ≥ 50.
    grant_stream_budget(&manager, "test-ctx", &invoker, 60).await;

    let m = std::sync::Arc::new(manager);
    let inv = invoker.clone();
    let m1 = std::sync::Arc::clone(&m);
    let inv1 = inv.clone();
    let m2 = std::sync::Arc::clone(&m);
    let inv2 = inv.clone();
    let t1 = tokio::spawn(async move {
        m1.outlet_stream_reserve_escrow(
            "test-ctx",
            &inv1,
            scp_protocol::economy::types::Amount::new(10),
            5,
            None,
        )
        .await
    });
    let t2 = tokio::spawn(async move {
        m2.outlet_stream_reserve_escrow(
            "test-ctx",
            &inv2,
            scp_protocol::economy::types::Amount::new(10),
            5,
            None,
        )
        .await
    });
    let (r1, r2) = (t1.await.unwrap(), t2.await.unwrap());

    let successes = usize::from(r1.is_ok()) + usize::from(r2.is_ok());
    let insufficient = [&r1, &r2]
        .iter()
        .filter(|r| matches!(r, Err(ContextError::EscrowInsufficientFunds(_))))
        .count();
    assert_eq!(successes, 1, "exactly one concurrent reserve may succeed");
    assert_eq!(insufficient, 1, "the loser must be EscrowInsufficientFunds");
    assert!(
        stream_total_spent(&m, "test-ctx", &invoker).await <= 60,
        "total_spent must never exceed the budget B"
    );
}

/// (d) `max_calls` bounds the estimate: a declared estimate above the caveat
/// ceiling is rejected by `enforce_estimated_chunk_count_bound`, and the
/// reserve over the coerced estimate never holds more than `cost × max_calls`.
#[tokio::test]
async fn outlet_stream_max_calls_bounds_estimate_and_escrow() {
    use crate::context::outlets::stream::{
        OpenError, coerce_estimated_chunk_count, enforce_estimated_chunk_count_bound,
    };
    let mut caveats = scp_protocol::trust::caveats::InvocationCaveats::empty();
    caveats.max_calls = Some(4);

    // estimate 5 > max_calls 4 → EstimateExceedsBound (credit_window large).
    assert_eq!(
        enforce_estimated_chunk_count_bound(5, 32, &caveats),
        Err(OpenError::EstimateExceedsBound),
        "estimate above max_calls must be rejected"
    );
    // estimate 4 ≤ min(credit_window, max_calls) → accepted.
    assert!(enforce_estimated_chunk_count_bound(4, 32, &caveats).is_ok());

    // The coerced estimate (no declared → falls back to max_calls) bounds the
    // hold to cost × max_calls.
    let (manager, _handle) = setup_active_context().await;
    let invoker: DID = "did:key:creator".into();
    grant_stream_budget(&manager, "test-ctx", &invoker, 1_000).await;
    let coerced = coerce_estimated_chunk_count(None, &caveats);
    assert_eq!(coerced, 4, "no declared estimate coerces to max_calls");
    let reservation = manager
        .outlet_stream_reserve_escrow(
            "test-ctx",
            &invoker,
            scp_protocol::economy::types::Amount::new(7),
            coerced,
            None,
        )
        .await
        .unwrap();
    assert_eq!(
        reservation.reserved.value(),
        28,
        "escrow hold ≤ cost × max_calls (7 × 4)"
    );
}

/// (e) The `caveats_binding` is computed over the REAL effective caveat set:
/// the binding over a non-empty set differs from the binding over an empty
/// set, so a stream that narrowed to `{max_calls: 4}` cannot reuse a binding
/// computed over `{}`. This is the E3 invariant the runtime's open-time
/// recompute enforces.
#[test]
fn caveats_binding_commits_to_real_effective_set() {
    use scp_protocol::context::outlets::stream::compute_caveats_binding;
    let request_id = [7u8; 16];
    let ucan_cid = b"bafy-test-cid";
    let invoker_did = "did:key:invoker";
    let estimate = 4u32;

    let empty = scp_protocol::trust::caveats::InvocationCaveats::empty();
    let mut narrowed = scp_protocol::trust::caveats::InvocationCaveats::empty();
    narrowed.max_calls = Some(4);

    let empty_jcs = empty.to_canonical_json_bytes().unwrap();
    let narrowed_jcs = narrowed.to_canonical_json_bytes().unwrap();

    let binding_empty =
        compute_caveats_binding(ucan_cid, &request_id, invoker_did, estimate, &empty_jcs);
    let binding_narrowed =
        compute_caveats_binding(ucan_cid, &request_id, invoker_did, estimate, &narrowed_jcs);

    assert_ne!(
        binding_empty, binding_narrowed,
        "binding over the real effective caveat set must differ from the empty-set binding"
    );
    // Determinism: recomputing over the same set yields the same binding (the
    // runtime's open-time recompute must match the SDK's value byte-for-byte).
    let binding_narrowed_again =
        compute_caveats_binding(ucan_cid, &request_id, invoker_did, estimate, &narrowed_jcs);
    assert_eq!(binding_narrowed, binding_narrowed_again);
}
