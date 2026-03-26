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
        manager.join_context(&handle, kp, None).await.unwrap();
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
    manager.join_context(&handle, kp, None).await.unwrap();

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
// Collection bounds tests (#360, §5.9)
// -----------------------------------------------------------------------

/// Build a minimal valid [`ToolRegistration`] for bounds tests.
/// #360: register exactly 256 tools (the limit), verify the 256th succeeds;
/// attempt to register a 257th, verify `LimitExceeded` is returned.
#[tokio::test]
async fn registered_tools_bounded_at_256() {
    let (manager, _handle) = setup_active_context().await;
    let pid: ProposalId = [0u8; 32];

    // Register exactly MAX_REGISTERED_TOOLS tools.
    for i in 0..super::MAX_REGISTERED_TOOLS {
        let reg = test_tool_registration(&format!("tool-{i}"));
        manager
            .execute_register_tool("test-ctx", &reg, pid, "")
            .await
            .unwrap();
    }

    // The 257th must fail with LimitExceeded.
    let overflow = test_tool_registration("tool-overflow");
    let err = manager
        .execute_register_tool("test-ctx", &overflow, pid, "")
        .await
        .unwrap_err();
    assert!(
        matches!(&err, ContextError::LimitExceeded(msg) if msg.contains("256")),
        "expected LimitExceeded with limit value, got: {err}"
    );
}

/// #360: establish exactly 256 tool interfaces (the limit), verify the 256th
/// succeeds; attempt to establish a 257th, verify `LimitExceeded` is returned.
#[tokio::test]
async fn tool_interfaces_bounded_at_256() {
    let (manager, _handle) = setup_active_context().await;
    let pid: ProposalId = [0u8; 32];

    // Establish exactly MAX_TOOL_INTERFACES interfaces.
    for i in 0..super::MAX_TOOL_INTERFACES {
        let iface = ToolInterface {
            source_context: "test-ctx".to_owned(),
            target_context: format!("target-{i}"),
            tool_id: format!("tool-{i}"),
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
    let overflow = ToolInterface {
        source_context: "test-ctx".to_owned(),
        target_context: "target-overflow".to_owned(),
        tool_id: "tool-overflow".to_owned(),
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
        let mut contexts = manager.contexts.lock().await;
        let ctx = contexts.get_mut("test-ctx").unwrap();
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
        let mut contexts = manager.contexts.lock().await;
        let ctx = contexts.get_mut("test-ctx").unwrap();
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
        .create_context("bc-key-test".into(), params, creator_did.clone())
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
        .create_context("bc-key-test-2".into(), params, creator_did.clone())
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
        .create_context("encrypted-ctx".into(), params, creator_did.clone())
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
