use super::*;

// -----------------------------------------------------------------------
// Broadcast context integration tests (SCP-227)
// -----------------------------------------------------------------------

/// SCP-227 AC1: `subscribe_broadcast` registers subscriber and returns
/// current author key epoch.
#[tokio::test]
async fn broadcast_subscribe_registers_and_returns_epoch() {
    use scp_protocol::crypto::ucan::validate::{
        InMemoryDidResolver, InMemoryNonceTracker, InMemoryProofResolver, InMemoryRevocationChecker,
    };
    use std::hash::RandomState;

    let (manager, _handle, ctx_id) = setup_broadcast_context().await;

    let result = manager
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
        .await;

    assert!(result.is_ok(), "subscribe should succeed on open context");
    let result = result.unwrap();

    // Author key epoch should be 0 (fresh author).
    assert_eq!(result.author_epochs.len(), 1);
    assert_eq!(result.author_epochs.get("did:key:author1"), Some(&0));

    // Event should be MemberJoined with role subscriber.
    assert!(matches!(
        result.event,
        ContextEvent::MemberJoined { ref role_name, .. } if role_name == "subscriber"
    ));

    // Manager should track the subscriber.
    assert!(
        manager
            .is_broadcast_subscriber(&ctx_id, "did:key:sub1")
            .await
    );
    assert_eq!(manager.broadcast_subscriber_count(&ctx_id).await, Some(1));
}

/// SCP-227 AC2: open broadcast allows subscription without UCAN.
#[tokio::test]
async fn broadcast_open_subscribe_no_ucan_required() {
    use scp_protocol::crypto::ucan::validate::{
        InMemoryDidResolver, InMemoryNonceTracker, InMemoryProofResolver, InMemoryRevocationChecker,
    };
    use std::hash::RandomState;

    let (manager, _handle, ctx_id) = setup_broadcast_context().await;

    // Subscribe without UCAN on open context -- should succeed.
    let result = manager
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
        .await;
    assert!(result.is_ok());

    // Admission should be Open.
    assert_eq!(
        manager.broadcast_admission(&ctx_id).await,
        Some(super::BroadcastAdmission::Open)
    );
}

/// SCP-227 AC4: `block_broadcast_author` revokes sender key.
#[tokio::test]
async fn broadcast_block_revokes_key() {
    use scp_protocol::crypto::ucan::validate::{
        InMemoryDidResolver, InMemoryNonceTracker, InMemoryProofResolver, InMemoryRevocationChecker,
    };
    use std::hash::RandomState;

    let (manager, _handle, ctx_id) = setup_broadcast_context().await;

    // Subscribe a victim.
    manager
        .subscribe_broadcast::<
            InMemoryDidResolver,
            InMemoryNonceTracker,
            InMemoryRevocationChecker,
            InMemoryProofResolver,
            RandomState,
        >(
            &ctx_id,
            &"did:key:victim".into(),
            None,
            1000,
            None,
        )
        .await
        .unwrap();

    // Block the victim.
    let block_result = manager
        .block_broadcast_subscriber(&ctx_id, &"did:key:author1".into(), &"did:key:victim".into())
        .await;

    assert!(block_result.is_ok());
    let block_result = block_result.unwrap();

    // New epoch should be 1 (rotated from 0).
    assert_eq!(block_result.new_epoch, 1);
    assert!(block_result.block_list.contains("did:key:victim"));

    // Key request from blocked subscriber should be denied.
    let decision = manager
        .handle_broadcast_key_request(&ctx_id, &"did:key:author1".into(), &"did:key:victim".into())
        .await
        .unwrap();
    assert!(matches!(decision, super::KeyRequestDecision::Deny { .. }));
}

/// Regression test for #1003: `block_broadcast_subscriber` must record the
/// blocker as the author — not the subscriber. Verifies:
/// 1. `BlockResult::author_did` matches the blocker DID.
/// 2. `BlockResult::block_list` contains the target subscriber DID.
/// 3. The `MemberBlocked` event carries `author_did = blocker` and
///    `blocked_did = subscriber`.
#[tokio::test]
async fn block_broadcast_subscriber_records_blocker_as_author() {
    let (manager, _handle, ctx_id) = setup_broadcast_context().await;

    let blocker_did: DID = "did:key:author1".into();
    let target_did: DID = "did:key:target_sub".into();

    // Subscribe the target.
    manager
        .subscribe_broadcast::<
            scp_protocol::crypto::ucan::validate::InMemoryDidResolver,
            scp_protocol::crypto::ucan::validate::InMemoryNonceTracker,
            scp_protocol::crypto::ucan::validate::InMemoryRevocationChecker,
            scp_protocol::crypto::ucan::validate::InMemoryProofResolver,
            std::hash::RandomState,
        >(
            &ctx_id,
            &target_did,
            None,
            1000,
            None,
        )
        .await
        .unwrap();

    // Block the target subscriber.
    let result = manager
        .block_broadcast_subscriber(&ctx_id, &blocker_did, &target_did)
        .await
        .unwrap();

    // AC: blocker_did appears as author_did in the block result.
    assert_eq!(
        result.author_did,
        blocker_did.to_string(),
        "BlockResult::author_did must be the blocker, not the subscriber"
    );

    // AC: target_did appears in the block list.
    assert!(
        result.block_list.contains(&target_did.to_string()),
        "BlockResult::block_list must contain the target subscriber DID"
    );

    // AC: MemberBlocked event carries the correct author and blocked DIDs.
    let events = manager.drain_events(&ctx_id).await;
    let blocked_event = events
        .iter()
        .find(|e| matches!(e, super::ContextEvent::MemberBlocked { .. }));
    assert!(
        blocked_event.is_some(),
        "MemberBlocked event must be emitted"
    );
    match blocked_event.unwrap() {
        super::ContextEvent::MemberBlocked {
            blocked_did,
            author_did,
        } => {
            assert_eq!(
                author_did, &blocker_did,
                "MemberBlocked::author_did must be the blocker"
            );
            assert_eq!(
                blocked_did, &target_did,
                "MemberBlocked::blocked_did must be the target subscriber"
            );
        }
        _ => unreachable!(),
    }
}

/// §9.16.8: `unblock_broadcast_subscriber` removes from block list
/// without key rotation, emits `MemberUnblocked` event, and allows
/// subsequent key requests.
#[tokio::test]
async fn broadcast_unblock_restores_key_access() {
    use scp_protocol::crypto::ucan::validate::{
        InMemoryDidResolver, InMemoryNonceTracker, InMemoryProofResolver, InMemoryRevocationChecker,
    };
    use std::hash::RandomState;

    let (manager, _handle, ctx_id) = setup_broadcast_context().await;

    // Subscribe a subscriber.
    manager
        .subscribe_broadcast::<
            InMemoryDidResolver,
            InMemoryNonceTracker,
            InMemoryRevocationChecker,
            InMemoryProofResolver,
            RandomState,
        >(
            &ctx_id,
            &"did:key:victim".into(),
            None,
            1000,
            None,
        )
        .await
        .unwrap();

    // Block the victim.
    manager
        .block_broadcast_subscriber(&ctx_id, &"did:key:author1".into(), &"did:key:victim".into())
        .await
        .unwrap();

    // Key request from blocked subscriber should be denied.
    let decision = manager
        .handle_broadcast_key_request(&ctx_id, &"did:key:author1".into(), &"did:key:victim".into())
        .await;
    assert!(matches!(
        decision,
        Ok(super::KeyRequestDecision::Deny { .. })
    ));

    // Unblock the victim.
    manager
        .unblock_broadcast_subscriber(&ctx_id, &"did:key:author1".into(), &"did:key:victim".into())
        .await
        .unwrap();

    // Key request should now succeed.
    let decision = manager
        .handle_broadcast_key_request(&ctx_id, &"did:key:author1".into(), &"did:key:victim".into())
        .await;
    assert!(
        !matches!(decision, Ok(super::KeyRequestDecision::Deny { .. })),
        "unblocked subscriber should be able to request keys"
    );

    // Drain events and verify MemberUnblocked event was emitted.
    let events = manager.drain_events(&ctx_id).await;
    assert!(
        events
            .iter()
            .any(|e| matches!(e, super::ContextEvent::MemberUnblocked { .. })),
        "MemberUnblocked event must be emitted"
    );
}

/// §9.16.8: unblocking a non-blocked subscriber returns an error.
#[tokio::test]
async fn broadcast_unblock_not_blocked_returns_error() {
    use scp_protocol::crypto::ucan::validate::{
        InMemoryDidResolver, InMemoryNonceTracker, InMemoryProofResolver, InMemoryRevocationChecker,
    };
    use std::hash::RandomState;

    let (manager, _handle, ctx_id) = setup_broadcast_context().await;

    // Subscribe.
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

    // Unblock without prior block should fail.
    let result = manager
        .unblock_broadcast_subscriber(&ctx_id, &"did:key:author1".into(), &"did:key:sub1".into())
        .await;
    assert!(
        result.is_err(),
        "unblocking non-blocked subscriber should fail"
    );
}

/// SCP-227 AC5: broadcast capabilities enforce `MessagesWrite` restricted
/// to authors, `MessagesRead` open to subscribers.
#[tokio::test]
async fn broadcast_capabilities_enforced() {
    use scp_protocol::crypto::ucan::validate::{
        InMemoryDidResolver, InMemoryNonceTracker, InMemoryProofResolver, InMemoryRevocationChecker,
    };
    use std::hash::RandomState;

    let (manager, handle, ctx_id) = setup_broadcast_context().await;

    // Subscribe a subscriber.
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

    // Author can publish (send_message routes to broadcast publish).
    let author_signing_key = ed25519_dalek::SigningKey::from_bytes(&[42u8; 32]);
    let result = manager
        .send_message(
            &handle,
            &"did:key:author1".into(),
            b"hello broadcast",
            Some(&author_signing_key),
            None,
            None,
        )
        .await;
    assert!(result.is_ok(), "author should be able to publish");

    // Non-author subscriber cannot publish.
    let sub_signing_key = ed25519_dalek::SigningKey::from_bytes(&[43u8; 32]);
    let result = manager
        .send_message(
            &handle,
            &"did:key:sub1".into(),
            b"unauthorized",
            Some(&sub_signing_key),
            None,
            None,
        )
        .await;
    assert!(result.is_err(), "subscriber should not be able to publish");
    assert!(matches!(
        result.unwrap_err(),
        ContextError::PermissionDenied(_)
    ));
}

/// SCP-227 AC6: integration test -- author publishes, 3 subscribers
/// receive and can request keys for decryption.
#[tokio::test]
async fn broadcast_publish_3_subscribers_decrypt() {
    use scp_protocol::crypto::sender_keys::open_broadcast;
    use scp_protocol::crypto::ucan::validate::{
        InMemoryDidResolver, InMemoryNonceTracker, InMemoryProofResolver, InMemoryRevocationChecker,
    };
    use std::hash::RandomState;

    let (manager, _handle, ctx_id) = setup_broadcast_context().await;
    let author_signing_key = ed25519_dalek::SigningKey::from_bytes(&[42u8; 32]);
    let author_verifying_key = author_signing_key.verifying_key();
    let (author_custody, author_key_handle) = test_custody_from_seed(&[42u8; 32]).await;

    // Subscribe 3 subscribers.
    for name in &["sub1", "sub2", "sub3"] {
        manager
            .subscribe_broadcast::<
                InMemoryDidResolver,
                InMemoryNonceTracker,
                InMemoryRevocationChecker,
                InMemoryProofResolver,
                RandomState,
            >(
                &ctx_id,
                &DID(format!("did:key:{name}")),
                None,
                1000,
                None,
            )
            .await
            .unwrap();
    }

    assert_eq!(manager.broadcast_subscriber_count(&ctx_id).await, Some(3));

    // Author publishes a message.
    let plaintext = b"hello all subscribers!";
    let envelope = manager
        .publish_broadcast(
            &ctx_id,
            &"did:key:author1".into(),
            plaintext,
            &author_custody,
            &author_key_handle,
        )
        .await
        .unwrap();

    // Each subscriber requests the key and decrypts.
    for name in &["sub1", "sub2", "sub3"] {
        let decision = manager
            .handle_broadcast_key_request(
                &ctx_id,
                &"did:key:author1".into(),
                &DID(format!("did:key:{name}")),
            )
            .await
            .unwrap();

        match decision {
            super::KeyRequestDecision::Grant {
                key_bytes, epoch, ..
            } => {
                assert_eq!(epoch, 0);
                // Reconstruct broadcast key and decrypt.
                let broadcast_key = scp_protocol::crypto::sender_keys::BroadcastKey::from_parts(
                    scp_protocol::crypto::sender_keys::SenderKey::from_bytes(*key_bytes),
                    epoch,
                    "did:key:author1".to_owned(),
                );
                let decrypted =
                    open_broadcast(&broadcast_key, &envelope, &author_verifying_key).unwrap();
                assert_eq!(decrypted, plaintext);
            }
            super::KeyRequestDecision::Deny { reason } => {
                panic!("key request should be granted for {name}: {reason}");
            }
        }
    }

    // Verify MessageSent event was emitted.
    let events = manager.drain_events(&ctx_id).await;
    let msg_events: Vec<_> = events
        .iter()
        .filter(|e| matches!(e, ContextEvent::MessageSent { .. }))
        .collect();
    assert_eq!(msg_events.len(), 1);
}

/// SCP-227 AC7: integration test -- blocked author's subsequent messages
/// are undecryptable by blocked subscriber.
#[tokio::test]
// Integration test exercises full context lifecycle; splitting would
// fragment a sequential scenario that must be verified end-to-end.
#[allow(clippy::too_many_lines)]
async fn broadcast_blocked_subscriber_cannot_decrypt() {
    use scp_protocol::crypto::sender_keys::open_broadcast;
    use scp_protocol::crypto::ucan::validate::{
        InMemoryDidResolver, InMemoryNonceTracker, InMemoryProofResolver, InMemoryRevocationChecker,
    };
    use std::hash::RandomState;

    let (manager, _handle, ctx_id) = setup_broadcast_context().await;
    let author_signing_key = ed25519_dalek::SigningKey::from_bytes(&[42u8; 32]);
    let author_verifying_key = author_signing_key.verifying_key();
    let (author_custody, author_key_handle) = test_custody_from_seed(&[42u8; 32]).await;

    // Subscribe 2 subscribers.
    for name in &["good-sub", "bad-sub"] {
        manager
            .subscribe_broadcast::<
                InMemoryDidResolver,
                InMemoryNonceTracker,
                InMemoryRevocationChecker,
                InMemoryProofResolver,
                RandomState,
            >(
                &ctx_id,
                &DID(format!("did:key:{name}")),
                None,
                1000,
                None,
            )
            .await
            .unwrap();
    }

    // Author publishes first message (both can decrypt).
    let msg1 = b"pre-block message";
    let envelope1 = manager
        .publish_broadcast(
            &ctx_id,
            &"did:key:author1".into(),
            msg1,
            &author_custody,
            &author_key_handle,
        )
        .await
        .unwrap();

    // Get the pre-block key for "bad-sub".
    let pre_block_decision = manager
        .handle_broadcast_key_request(
            &ctx_id,
            &"did:key:author1".into(),
            &"did:key:bad-sub".into(),
        )
        .await
        .unwrap();
    let super::KeyRequestDecision::Grant {
        key_bytes: pre_block_key_bytes,
        epoch: pre_block_epoch,
    } = pre_block_decision
    else {
        panic!("should be granted before block")
    };

    // Verify bad-sub can decrypt the pre-block message.
    let pre_block_broadcast_key = scp_protocol::crypto::sender_keys::BroadcastKey::from_parts(
        scp_protocol::crypto::sender_keys::SenderKey::from_bytes(*pre_block_key_bytes),
        pre_block_epoch,
        "did:key:author1".to_owned(),
    );
    let decrypted =
        open_broadcast(&pre_block_broadcast_key, &envelope1, &author_verifying_key).unwrap();
    assert_eq!(decrypted, msg1);

    // Block bad-sub.
    manager
        .block_broadcast_subscriber(
            &ctx_id,
            &"did:key:author1".into(),
            &"did:key:bad-sub".into(),
        )
        .await
        .unwrap();

    // Author publishes post-block message.
    let msg2 = b"post-block secret";
    let envelope2 = manager
        .publish_broadcast(
            &ctx_id,
            &"did:key:author1".into(),
            msg2,
            &author_custody,
            &author_key_handle,
        )
        .await
        .unwrap();

    // bad-sub's key request is now denied.
    let post_block_decision = manager
        .handle_broadcast_key_request(
            &ctx_id,
            &"did:key:author1".into(),
            &"did:key:bad-sub".into(),
        )
        .await
        .unwrap();
    assert!(
        matches!(post_block_decision, super::KeyRequestDecision::Deny { .. }),
        "blocked subscriber should be denied"
    );

    // bad-sub tries to decrypt with the old key -- should fail because
    // the message was encrypted with the new (post-rotation) key.
    let decrypt_attempt =
        open_broadcast(&pre_block_broadcast_key, &envelope2, &author_verifying_key);
    assert!(
        decrypt_attempt.is_err(),
        "blocked subscriber should not be able to decrypt post-block messages"
    );

    // good-sub can still get the new key and decrypt.
    let good_decision = manager
        .handle_broadcast_key_request(
            &ctx_id,
            &"did:key:author1".into(),
            &"did:key:good-sub".into(),
        )
        .await
        .unwrap();
    match good_decision {
        super::KeyRequestDecision::Grant {
            key_bytes, epoch, ..
        } => {
            assert_eq!(epoch, 1, "epoch should be 1 after rotation");
            let new_key = scp_protocol::crypto::sender_keys::BroadcastKey::from_parts(
                scp_protocol::crypto::sender_keys::SenderKey::from_bytes(*key_bytes),
                epoch,
                "did:key:author1".to_owned(),
            );
            let decrypted = open_broadcast(&new_key, &envelope2, &author_verifying_key).unwrap();
            assert_eq!(decrypted, msg2);
        }
        super::KeyRequestDecision::Deny { reason } => {
            panic!("good-sub should be granted: {reason}");
        }
    }
}

/// SCP-227: non-author publish is rejected.
#[tokio::test]
async fn broadcast_non_author_publish_rejected() {
    use scp_protocol::crypto::ucan::validate::{
        InMemoryDidResolver, InMemoryNonceTracker, InMemoryProofResolver, InMemoryRevocationChecker,
    };
    use std::hash::RandomState;

    let (manager, _handle, ctx_id) = setup_broadcast_context().await;

    // Subscribe.
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

    // Subscriber tries to publish -- should fail.
    let (sub_custody, sub_key_handle) = test_custody_from_seed(&[43u8; 32]).await;
    let result = manager
        .publish_broadcast(
            &ctx_id,
            &"did:key:sub1".into(),
            b"nope",
            &sub_custody,
            &sub_key_handle,
        )
        .await;
    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        ContextError::PermissionDenied(_)
    ));
}

/// SCP-227: `create_context` initializes `broadcast_context` for broadcast mode.
#[tokio::test]
async fn broadcast_create_context_initializes_broadcast_state() {
    let (manager, _handle, ctx_id) = setup_broadcast_context().await;

    // Admission should be Open (default for no template_id).
    assert_eq!(
        manager.broadcast_admission(&ctx_id).await,
        Some(super::BroadcastAdmission::Open)
    );

    // Subscriber count should be 0 initially.
    assert_eq!(manager.broadcast_subscriber_count(&ctx_id).await, Some(0));

    // Author should be able to publish.
    let (author_custody, author_key_handle) = test_custody_from_seed(&[42u8; 32]).await;
    let result = manager
        .publish_broadcast(
            &ctx_id,
            &"did:key:author1".into(),
            b"test",
            &author_custody,
            &author_key_handle,
        )
        .await;
    assert!(result.is_ok());
}

/// SCP-227: `leave_context` on broadcast context cleans up subscriber.
#[tokio::test]
async fn broadcast_leave_context_unsubscribes() {
    use scp_protocol::crypto::ucan::validate::{
        InMemoryDidResolver, InMemoryNonceTracker, InMemoryProofResolver, InMemoryRevocationChecker,
    };
    use std::hash::RandomState;

    let (manager, handle, ctx_id) = setup_broadcast_context().await;

    // Subscribe.
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
    assert!(
        manager
            .is_broadcast_subscriber(&ctx_id, "did:key:sub1")
            .await
    );

    // Leave via leave_context (self-removal).
    let result = manager
        .leave_context(&handle, &"did:key:sub1".into(), &"did:key:sub1".into())
        .await;
    assert!(result.is_ok());

    // Subscriber should be removed from broadcast context.
    assert!(
        !manager
            .is_broadcast_subscriber(&ctx_id, "did:key:sub1")
            .await
    );
}

/// SCP-227: `close_context` drops broadcast state.
#[tokio::test]
async fn broadcast_close_context_drops_state() {
    // Need context:close capability for the admin.
    let manager = ContextManager::new(
        Box::new(MockCrypto::default()),
        Box::new(MockTransport::connected()),
        Box::new(MockEventLog::default()),
        noop_key_resolver(),
    );

    let params = ContextParams {
        mode: ContextMode::Broadcast,
        memory_scope: scp_protocol::context::MemoryScope::Full,
        ceiling: vec![
            scp_protocol::context::params::Capability::new("messages:read"),
            scp_protocol::context::params::Capability::new("messages:write"),
            scp_protocol::context::params::Capability::new("role:assign"),
            scp_protocol::context::params::Capability::new("context:close"),
        ],
        ..ContextParams::default()
    };

    let handle = manager
        .create_context(
            "broadcast-close-ctx".into(),
            params,
            "did:key:author1".into(),
        )
        .await
        .unwrap();
    let ctx_id = "broadcast-close-ctx";

    // Close the context.
    let result = manager
        .close_context(&handle, &"did:key:author1".into())
        .await;
    assert!(result.is_ok());

    // Broadcast state should be None (dropped on close).
    assert_eq!(manager.broadcast_admission(ctx_id).await, None);
    assert_eq!(manager.broadcast_subscriber_count(ctx_id).await, None);
}

/// SCP-227: `unsubscribe_broadcast` removes subscriber and optionally rotates keys.
#[tokio::test]
async fn broadcast_unsubscribe_with_key_rotation() {
    use scp_protocol::crypto::ucan::validate::{
        InMemoryDidResolver, InMemoryNonceTracker, InMemoryProofResolver, InMemoryRevocationChecker,
    };
    use std::hash::RandomState;

    let (manager, _handle, ctx_id) = setup_broadcast_context().await;

    // Subscribe.
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

    // Unsubscribe with key rotation.
    let result = manager
        .unsubscribe_broadcast(&ctx_id, &"did:key:sub1".into(), true)
        .await;
    assert!(result.is_ok());
    let result = result.unwrap();
    assert_eq!(result.subscriber_did, "did:key:sub1");
    // Key rotation should have happened (one rotation per author).
    assert_eq!(result.key_rotations.len(), 1);
    assert_eq!(result.key_rotations[0].new_epoch, 1);

    // Subscriber should no longer be tracked.
    assert!(
        !manager
            .is_broadcast_subscriber(&ctx_id, "did:key:sub1")
            .await
    );
}

// ===================================================================
// Author blocking (SCP-227 AC4 + AC7) — governance-gated
// ===================================================================

/// SCP-227 AC4: governance-approved `Revoke` proposal revokes sender
/// key, preventing the blocked author from publishing.
#[tokio::test]
// Integration test exercises full governance + broadcast lifecycle; splitting
// would fragment a sequential scenario that must be verified end-to-end.
#[allow(clippy::too_many_lines)]
async fn broadcast_block_author_via_governance_revokes_publish() {
    use scp_protocol::crypto::ucan::validate::{
        InMemoryDidResolver, InMemoryNonceTracker, InMemoryProofResolver, InMemoryRevocationChecker,
    };
    use std::hash::RandomState;

    let (manager, _handle, ctx_id) = setup_broadcast_context_two_authors().await;

    // Subscribe 2 subscribers.
    for name in &["sub1", "sub2"] {
        manager
            .subscribe_broadcast::<
                InMemoryDidResolver,
                InMemoryNonceTracker,
                InMemoryRevocationChecker,
                InMemoryProofResolver,
                RandomState,
            >(
                &ctx_id,
                &DID(format!("did:key:{name}")),
                None,
                1000,
                None,
            )
            .await
            .unwrap();
    }

    let (alice_custody, alice_key_handle) = test_custody_from_seed(&[0xAA; 32]).await;
    let (bob_custody, bob_key_handle) = test_custody_from_seed(&[0xBB; 32]).await;

    // Both authors can publish before blocking.
    assert!(
        manager
            .publish_broadcast(
                &ctx_id,
                &"did:key:alice".into(),
                b"alice msg",
                &alice_custody,
                &alice_key_handle,
            )
            .await
            .is_ok()
    );
    assert!(
        manager
            .publish_broadcast(
                &ctx_id,
                &"did:key:bob".into(),
                b"bob msg",
                &bob_custody,
                &bob_key_handle,
            )
            .await
            .is_ok()
    );

    // Block bob via governance: admin proposes, auto-approved.
    let proposal =
        approved_revoke_proposal(&"did:key:alice".into(), &ctx_id, &"did:key:bob".into());
    let action_result = manager.execute_governance_action(&ctx_id, &proposal).await;
    assert!(action_result.is_ok());
    let super::GovernanceActionResult::AccessRevoked(revoke_result) = action_result.unwrap() else {
        panic!("expected AccessRevoked result from Revoke action");
    };
    assert_eq!(revoke_result.did.0, "did:key:bob");
    assert_eq!(revoke_result.access, super::AccessScope::Write);

    // Alice can still publish (unaffected).
    assert!(
        manager
            .publish_broadcast(
                &ctx_id,
                &"did:key:alice".into(),
                b"alice still ok",
                &alice_custody,
                &alice_key_handle,
            )
            .await
            .is_ok(),
        "unblocked author should still be able to publish"
    );

    // Bob cannot publish (PermissionDenied).
    let bob_result = manager
        .publish_broadcast(
            &ctx_id,
            &"did:key:bob".into(),
            b"bob tries",
            &bob_custody,
            &bob_key_handle,
        )
        .await;
    assert!(
        bob_result.is_err(),
        "blocked author should not be able to publish"
    );
    assert!(matches!(
        bob_result.unwrap_err(),
        ContextError::PermissionDenied(_)
    ));

    // Key request for bob returns Deny (author not found).
    let decision = manager
        .handle_broadcast_key_request(&ctx_id, &"did:key:bob".into(), &"did:key:sub1".into())
        .await
        .unwrap();
    assert!(
        matches!(decision, super::KeyRequestDecision::Deny { .. }),
        "key request for blocked author should be denied"
    );

    // Key request for alice still works.
    let decision = manager
        .handle_broadcast_key_request(&ctx_id, &"did:key:alice".into(), &"did:key:sub1".into())
        .await
        .unwrap();
    assert!(
        matches!(decision, super::KeyRequestDecision::Grant { .. }),
        "key request for unblocked author should succeed"
    );
}

/// Attempting to block an author with a non-approved proposal is rejected.
#[tokio::test]
async fn broadcast_block_author_rejects_pending_proposal() {
    use scp_protocol::context::governance::{GovernanceProposal, ProposalStatus};

    let (manager, _handle, ctx_id) = setup_broadcast_context_two_authors().await;

    // Construct a proposal that is NOT approved (still Pending).
    let pending_proposal = GovernanceProposal {
        proposal_id: [0u8; 32],
        context_id: ctx_id.clone(),
        proposer_did: "did:key:alice".into(),
        action: super::GovernanceAction::RevokeAccess {
            did: "did:key:bob".into(),
            access: super::AccessScope::Write,
        },
        status: ProposalStatus::Pending,
        created_at: 1000,
        voting_deadline: 2000,
        approvals: Vec::new(),
        rejections: Vec::new(),
        created_at_epoch: None,
    };

    let result = manager
        .execute_governance_action(&ctx_id, &pending_proposal)
        .await;
    assert!(result.is_err(), "pending proposal must not execute");
    assert!(
        matches!(result.unwrap_err(), ContextError::PermissionDenied(_)),
        "should return PermissionDenied for non-approved proposal"
    );
}

/// SCP-227 AC7: integration test -- after blocking an author, their
/// subsequent messages are undecryptable by subscribers (because the
/// author can no longer produce them).
#[tokio::test]
// Integration test exercises full broadcast lifecycle; splitting would
// fragment a sequential scenario that must be verified end-to-end.
#[allow(clippy::too_many_lines)]
async fn broadcast_blocked_author_messages_undecryptable() {
    use scp_protocol::crypto::sender_keys::open_broadcast;
    use scp_protocol::crypto::ucan::validate::{
        InMemoryDidResolver, InMemoryNonceTracker, InMemoryProofResolver, InMemoryRevocationChecker,
    };
    use std::hash::RandomState;

    let (manager, _handle, ctx_id) = setup_broadcast_context_two_authors().await;
    let alice_signing_key = ed25519_dalek::SigningKey::from_bytes(&[42u8; 32]);
    let alice_verifying_key = alice_signing_key.verifying_key();
    let bob_signing_key = ed25519_dalek::SigningKey::from_bytes(&[43u8; 32]);
    let bob_verifying_key = bob_signing_key.verifying_key();
    let (alice_custody, alice_key_handle) = test_custody_from_seed(&[42u8; 32]).await;
    let (bob_custody, bob_key_handle) = test_custody_from_seed(&[43u8; 32]).await;

    // Subscribe 2 subscribers.
    for name in &["sub1", "sub2"] {
        manager
            .subscribe_broadcast::<
                InMemoryDidResolver,
                InMemoryNonceTracker,
                InMemoryRevocationChecker,
                InMemoryProofResolver,
                RandomState,
            >(
                &ctx_id,
                &DID(format!("did:key:{name}")),
                None,
                1000,
                None,
            )
            .await
            .unwrap();
    }

    // Alice publishes — both subscribers can get key and decrypt.
    let alice_msg1 = b"Alice before block";
    let _alice_envelope1 = manager
        .publish_broadcast(
            &ctx_id,
            &"did:key:alice".into(),
            alice_msg1,
            &alice_custody,
            &alice_key_handle,
        )
        .await
        .unwrap();

    // Bob publishes — both subscribers can get key and decrypt.
    let bob_msg1 = b"Bob before block";
    let bob_envelope1 = manager
        .publish_broadcast(
            &ctx_id,
            &"did:key:bob".into(),
            bob_msg1,
            &bob_custody,
            &bob_key_handle,
        )
        .await
        .unwrap();

    // Get Bob's key before blocking (sub1 perspective).
    let bob_pre_block_decision = manager
        .handle_broadcast_key_request(&ctx_id, &"did:key:bob".into(), &"did:key:sub1".into())
        .await
        .unwrap();
    let super::KeyRequestDecision::Grant {
        key_bytes: bob_pre_key,
        epoch: bob_pre_epoch,
    } = bob_pre_block_decision
    else {
        panic!("bob key should be granted before block")
    };

    // Verify sub1 can decrypt Bob's pre-block message.
    let bob_broadcast_key = scp_protocol::crypto::sender_keys::BroadcastKey::from_parts(
        scp_protocol::crypto::sender_keys::SenderKey::from_bytes(*bob_pre_key),
        bob_pre_epoch,
        "did:key:bob".to_owned(),
    );
    let decrypted = open_broadcast(&bob_broadcast_key, &bob_envelope1, &bob_verifying_key).unwrap();
    assert_eq!(decrypted, bob_msg1);

    // Block Bob via governance (admin proposes, auto-approved).
    let proposal =
        approved_revoke_proposal(&"did:key:alice".into(), &ctx_id, &"did:key:bob".into());
    manager
        .execute_governance_action(&ctx_id, &proposal)
        .await
        .unwrap();

    // Bob tries to publish — PermissionDenied.
    let bob_result = manager
        .publish_broadcast(
            &ctx_id,
            &"did:key:bob".into(),
            b"bob after block",
            &bob_custody,
            &bob_key_handle,
        )
        .await;
    assert!(
        bob_result.is_err(),
        "blocked author should not be able to publish"
    );

    // Alice can still publish after Bob is blocked.
    let alice_msg2 = b"Alice after Bob blocked";
    let alice_envelope2 = manager
        .publish_broadcast(
            &ctx_id,
            &"did:key:alice".into(),
            alice_msg2,
            &alice_custody,
            &alice_key_handle,
        )
        .await
        .unwrap();

    // Sub1 can still get Alice's key and decrypt.
    let alice_decision = manager
        .handle_broadcast_key_request(&ctx_id, &"did:key:alice".into(), &"did:key:sub1".into())
        .await
        .unwrap();
    match alice_decision {
        super::KeyRequestDecision::Grant {
            key_bytes, epoch, ..
        } => {
            let alice_key = scp_protocol::crypto::sender_keys::BroadcastKey::from_parts(
                scp_protocol::crypto::sender_keys::SenderKey::from_bytes(*key_bytes),
                epoch,
                "did:key:alice".to_owned(),
            );
            let decrypted =
                open_broadcast(&alice_key, &alice_envelope2, &alice_verifying_key).unwrap();
            assert_eq!(decrypted, alice_msg2);
        }
        super::KeyRequestDecision::Deny { reason } => {
            panic!("alice key should be granted: {reason}");
        }
    }

    // Sub1 requests Bob's key — Deny (author no longer exists).
    let bob_post_decision = manager
        .handle_broadcast_key_request(&ctx_id, &"did:key:bob".into(), &"did:key:sub1".into())
        .await
        .unwrap();
    assert!(
        matches!(bob_post_decision, super::KeyRequestDecision::Deny { .. }),
        "key request for blocked author must be denied"
    );

    // Old messages from Bob are still decryptable with cached key
    // (forward access to historical content is preserved).
    let old_decrypted =
        open_broadcast(&bob_broadcast_key, &bob_envelope1, &bob_verifying_key).unwrap();
    assert_eq!(old_decrypted, bob_msg1);
}

/// SCP-227: governance-approved `Revoke` on non-broadcast context
/// returns error (the action only applies to broadcast contexts).
#[tokio::test]
async fn broadcast_block_author_on_encrypted_context_fails() {
    let (manager, _handle) = setup_active_context().await;

    let target_did: DID = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK".into();
    let admin_did: DID = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK".into();

    let proposal = approved_revoke_proposal(&admin_did, "test-ctx", &target_did);
    let result = manager
        .execute_governance_action("test-ctx", &proposal)
        .await;
    assert!(result.is_err());
}

/// Defense-in-depth: a proposal approved for context A must not be
/// executable against context B.
#[tokio::test]
async fn governance_action_rejects_wrong_context_id() {
    let (manager, _handle, ctx_id) = setup_broadcast_context_two_authors().await;

    // Create a proposal targeting a different context.
    let proposal = approved_revoke_proposal(
        &"did:key:alice".into(),
        "ctx-a-other",
        &"did:key:bob".into(),
    );

    let result = manager.execute_governance_action(&ctx_id, &proposal).await;
    assert!(
        result.is_err(),
        "proposal targeting a different context must be rejected"
    );
    assert!(
        matches!(result.unwrap_err(), ContextError::PermissionDenied(_)),
        "should return PermissionDenied for context mismatch"
    );
}

/// Defense-in-depth: replaying the same approved proposal a second time
/// is rejected with an explicit error rather than relying on downstream
/// `MemberNotFound`.
#[tokio::test]
async fn governance_action_rejects_replayed_proposal() {
    let (manager, _handle, ctx_id) = setup_broadcast_context_two_authors().await;

    let proposal =
        approved_revoke_proposal(&"did:key:alice".into(), &ctx_id, &"did:key:bob".into());

    // First execution should succeed.
    let result = manager.execute_governance_action(&ctx_id, &proposal).await;
    assert!(result.is_ok(), "first execution should succeed");

    // Second execution of the same proposal should fail (replay).
    let replay_result = manager.execute_governance_action(&ctx_id, &proposal).await;
    assert!(replay_result.is_err(), "replayed proposal must be rejected");
    assert!(
        matches!(
            replay_result.unwrap_err(),
            ContextError::PermissionDenied(_)
        ),
        "should return PermissionDenied for replayed proposal"
    );
}

// ===================================================================
// Read access revocation/restoration — governance-gated
// ===================================================================

/// Helper: creates a broadcast context with `MemberBan` in the ceiling,
/// one author (alice), and one subscriber (sub1).
/// `Revoke (read)` on broadcast context bans subscriber.
#[tokio::test]
async fn revoke_read_access_bans_subscriber_in_broadcast() {
    let (manager, ctx_id) = setup_broadcast_with_member_ban().await;

    // Verify sub1 is subscribed before revocation.
    assert!(
        manager
            .is_broadcast_subscriber(&ctx_id, "did:key:sub1")
            .await,
        "sub1 should be subscribed before revocation"
    );

    let action = super::GovernanceAction::RevokeAccess {
        did: "did:key:sub1".into(),
        access: super::AccessScope::Read,
    };
    let proposal = approved_governance_proposal(
        &"did:key:alice".into(),
        &ctx_id,
        &"did:key:sub1".into(),
        action,
    );

    let result = manager.execute_governance_action(&ctx_id, &proposal).await;
    assert!(result.is_ok(), "Revoke (read) should succeed");

    let result = result.unwrap();
    match result {
        super::GovernanceActionResult::AccessRevoked(revoke_result) => {
            assert_eq!(revoke_result.did.0, "did:key:sub1");
            // At least one author should have rotated keys.
            assert!(
                revoke_result.rotated_author_count > 0,
                "key rotation should occur on revoke"
            );
        }
        other => panic!("expected AccessRevoked, got {other:?}"),
    }

    // Subscriber should no longer be tracked.
    assert!(
        !manager
            .is_broadcast_subscriber(&ctx_id, "did:key:sub1")
            .await,
        "sub1 should not be subscribed after revocation"
    );

    // Verify AccessRevoked event was emitted.
    let events = manager.drain_events(&ctx_id).await;
    let has_revoke_event = events.iter().any(|e| {
        matches!(
            e,
            super::ContextEvent::ReadAccessRevoked { did } if did.0 == "did:key:sub1"
        )
    });
    assert!(
        has_revoke_event,
        "ReadAccessRevoked event should have been emitted"
    );
}

/// `Revoke (read)` fails when ceiling lacks `MemberBan`.
#[tokio::test]
async fn revoke_read_access_rejected_without_member_ban_ceiling() {
    // Create a broadcast context WITHOUT MemberBan in ceiling.
    let manager = ContextManager::new(
        Box::new(MockCrypto::default()),
        Box::new(MockTransport::connected()),
        Box::new(MockEventLog::default()),
        noop_key_resolver(),
    );
    manager.register_local_did("did:key:alice".into()).await;
    manager.register_local_did("did:key:bob".into()).await;
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
        .create_context("no-ban-ctx".into(), params, "did:key:alice".into())
        .await
        .unwrap();
    {
        let _arc = manager.contexts.get("no-ban-ctx").unwrap().value().clone();
        let mut _g = _arc.lock().await;
        let ctx = &mut *_g;
        let bc = ctx.broadcast_context.as_mut().unwrap();
        bc.add_author("did:key:bob").unwrap();
        ctx.membership
            .add_member("did:key:bob".into(), "author".into(), vec![]);
    }
    let ctx_id = "no-ban-ctx".to_owned();

    // Subscribe sub1.
    {
        use scp_protocol::crypto::ucan::validate::{
            InMemoryDidResolver, InMemoryNonceTracker, InMemoryProofResolver,
            InMemoryRevocationChecker,
        };
        use std::hash::RandomState;

        manager
            .subscribe_broadcast::<
                InMemoryDidResolver,
                InMemoryNonceTracker,
                InMemoryRevocationChecker,
                InMemoryProofResolver,
                RandomState,
            >(
                &ctx_id,
                &DID("did:key:sub1".into()),
                None,
                1000,
                None,
            )
            .await
            .unwrap();
    }

    let action = super::GovernanceAction::RevokeAccess {
        did: "did:key:sub1".into(),
        access: super::AccessScope::Read,
    };
    let proposal = approved_governance_proposal(
        &"did:key:alice".into(),
        &ctx_id,
        &"did:key:sub1".into(),
        action,
    );

    let result = manager.execute_governance_action(&ctx_id, &proposal).await;
    assert!(
        result.is_err(),
        "Revoke (read) should fail without MemberBan in ceiling"
    );
    assert!(
        matches!(result.unwrap_err(), ContextError::PermissionDenied(ref msg) if msg.contains("member:ban")),
        "error should mention missing member:ban capability"
    );
}

/// `RestoreAccess (read)` unbans subscriber in broadcast context.
#[tokio::test]
async fn restore_read_access_unbans_subscriber_in_broadcast() {
    let (manager, ctx_id) = setup_broadcast_with_member_ban().await;

    // First, revoke read access.
    let revoke_action = super::GovernanceAction::RevokeAccess {
        did: "did:key:sub1".into(),
        access: super::AccessScope::Read,
    };
    let revoke_proposal = approved_governance_proposal(
        &"did:key:alice".into(),
        &ctx_id,
        &"did:key:sub1".into(),
        revoke_action,
    );
    manager
        .execute_governance_action(&ctx_id, &revoke_proposal)
        .await
        .unwrap();

    // Drain events from revocation so we can check restore events cleanly.
    manager.drain_events(&ctx_id).await;

    // Now restore read access.
    let restore_action = super::GovernanceAction::RestoreAccess {
        did: "did:key:sub1".into(),
        capabilities: vec![super::Capability::MessagesRead],
    };
    let restore_proposal = approved_governance_proposal(
        &"did:key:alice".into(),
        &ctx_id,
        &"did:key:sub1".into(),
        restore_action,
    );

    let result = manager
        .execute_governance_action(&ctx_id, &restore_proposal)
        .await;
    assert!(result.is_ok(), "RestoreAccess (read) should succeed");

    match result.unwrap() {
        super::GovernanceActionResult::AccessRestored(restore_result) => {
            assert_eq!(restore_result.did.0, "did:key:sub1");
        }
        other => panic!("expected AccessRestored, got {other:?}"),
    }

    // Verify ReadAccessRestored event was emitted.
    let events = manager.drain_events(&ctx_id).await;
    let has_restore_event = events.iter().any(|e| {
        matches!(
            e,
            super::ContextEvent::ReadAccessRestored { did } if did.0 == "did:key:sub1"
        )
    });
    assert!(
        has_restore_event,
        "ReadAccessRestored event should have been emitted"
    );
}

/// `RestoreAccess (read)` also fails without `MemberBan` in ceiling.
#[tokio::test]
async fn restore_read_access_rejected_without_member_ban_ceiling() {
    // Create a broadcast context WITHOUT MemberBan in ceiling.
    let manager = ContextManager::new(
        Box::new(MockCrypto::default()),
        Box::new(MockTransport::connected()),
        Box::new(MockEventLog::default()),
        noop_key_resolver(),
    );
    manager.register_local_did("did:key:alice".into()).await;
    let params = ContextParams {
        mode: ContextMode::Broadcast,
        memory_scope: MemoryScope::Full,
        ceiling: vec![Capability::MessagesRead, Capability::MessagesWrite],
        ..ContextParams::default()
    };
    let _handle = manager
        .create_context("no-ban-restore-ctx".into(), params, "did:key:alice".into())
        .await
        .unwrap();
    let ctx_id = "no-ban-restore-ctx".to_owned();

    let action = super::GovernanceAction::RestoreAccess {
        did: "did:key:sub1".into(),
        capabilities: vec![super::Capability::MessagesRead],
    };
    let proposal = approved_governance_proposal(
        &"did:key:alice".into(),
        &ctx_id,
        &"did:key:sub1".into(),
        action,
    );

    let result = manager.execute_governance_action(&ctx_id, &proposal).await;
    assert!(
        result.is_err(),
        "RestoreAccess (read) should fail without MemberBan in ceiling"
    );
    assert!(
        matches!(result.unwrap_err(), ContextError::PermissionDenied(ref msg) if msg.contains("member:ban")),
        "error should mention missing member:ban capability"
    );
}

// ===================================================================
// Content access governance tests (SCP-CAC-007)
// ===================================================================

/// Helper: creates an encrypted context with `MemberBan` in ceiling,
/// admin (alice) and member (bob).
/// SCP-CAC-007: `Revoke (read)` works on encrypted contexts (not just broadcast).
#[tokio::test]
async fn revoke_read_access_works_on_encrypted_context() {
    let (manager, ctx_id) = setup_encrypted_with_member_ban().await;

    let action = super::GovernanceAction::RevokeAccess {
        did: "did:key:bob".into(),
        access: super::AccessScope::Read,
    };
    let proposal = approved_governance_proposal(
        &"did:key:alice".into(),
        &ctx_id,
        &"did:key:bob".into(),
        action,
    );

    let result = manager.execute_governance_action(&ctx_id, &proposal).await;
    assert!(
        result.is_ok(),
        "Revoke (read) on encrypted context should succeed"
    );

    // Verify bob is tracked as read-revoked.
    let _arc = manager.contexts.get(&ctx_id).unwrap().value().clone();
    let _g = _arc.lock().await;
    let ctx = &*_g;
    assert!(
        ctx.access
            .read_exclusion_list
            .contains(&DID::from("did:key:bob"))
    );
    assert!(
        ctx.access
            .read_exclusion_list
            .contains(&DID::from("did:key:bob"))
    );
    // Bob is still a member (membership/access decoupling).
    assert!(ctx.membership.contains("did:key:bob"));
}

/// SCP-CAC-007: redundant `Revoke (read)` is prevented by TOCTOU replay protection.
/// The governance engine assigns deterministic proposal IDs, so a second identical
/// proposal is rejected as "already executed" — redundancy is handled at the
/// governance layer, not the execution layer.
#[tokio::test]
async fn revoke_read_access_redundant_rejected_by_replay_protection() {
    let (manager, ctx_id) = setup_encrypted_with_member_ban().await;

    let action = super::GovernanceAction::RevokeAccess {
        did: "did:key:bob".into(),
        access: super::AccessScope::Read,
    };
    let proposal1 = approved_governance_proposal(
        &"did:key:alice".into(),
        &ctx_id,
        &"did:key:bob".into(),
        action.clone(),
    );

    // First revoke succeeds.
    manager
        .execute_governance_action(&ctx_id, &proposal1)
        .await
        .unwrap();

    // Second identical proposal is rejected by replay protection.
    let action2 = super::GovernanceAction::RevokeAccess {
        did: "did:key:bob".into(),
        access: super::AccessScope::Read,
    };
    let proposal2 = approved_governance_proposal(
        &"did:key:alice".into(),
        &ctx_id,
        &"did:key:bob".into(),
        action2,
    );
    let result = manager.execute_governance_action(&ctx_id, &proposal2).await;
    assert!(
        result.is_err(),
        "redundant proposal should be rejected by TOCTOU replay protection"
    );
}

/// SCP-CAC-007: `RestoreAccess (read)` returns `NothingToRestore` when never revoked.
#[tokio::test]
async fn restore_read_access_nothing_to_restore() {
    let (manager, ctx_id) = setup_encrypted_with_member_ban().await;

    let action = super::GovernanceAction::RestoreAccess {
        did: "did:key:bob".into(),
        capabilities: vec![super::Capability::MessagesRead],
    };
    let proposal = approved_governance_proposal(
        &"did:key:alice".into(),
        &ctx_id,
        &"did:key:bob".into(),
        action,
    );

    let result = manager.execute_governance_action(&ctx_id, &proposal).await;
    assert!(result.is_err());
    assert!(
        matches!(result.unwrap_err(), ContextError::NothingToRestore(_)),
        "should return NothingToRestore when read access was never revoked"
    );
}

/// SCP-CAC-007: `RestoreAccess (read)` succeeds after revocation on encrypted context.
#[tokio::test]
async fn restore_read_access_after_revocation_on_encrypted() {
    let (manager, ctx_id) = setup_encrypted_with_member_ban().await;

    // First revoke.
    let revoke_action = super::GovernanceAction::RevokeAccess {
        did: "did:key:bob".into(),
        access: super::AccessScope::Read,
    };
    let revoke_proposal = approved_governance_proposal(
        &"did:key:alice".into(),
        &ctx_id,
        &"did:key:bob".into(),
        revoke_action,
    );
    manager
        .execute_governance_action(&ctx_id, &revoke_proposal)
        .await
        .unwrap();

    // Now restore.
    let restore_action = super::GovernanceAction::RestoreAccess {
        did: "did:key:bob".into(),
        capabilities: vec![super::Capability::MessagesRead],
    };
    let restore_proposal = approved_governance_proposal(
        &"did:key:alice".into(),
        &ctx_id,
        &"did:key:bob".into(),
        restore_action,
    );
    let result = manager
        .execute_governance_action(&ctx_id, &restore_proposal)
        .await;
    assert!(
        result.is_ok(),
        "RestoreAccess (read) should succeed after revocation"
    );

    // Bob should no longer be read-revoked.
    let _arc = manager.contexts.get(&ctx_id).unwrap().value().clone();
    let _g = _arc.lock().await;
    let ctx = &*_g;
    assert!(
        !ctx.access
            .read_exclusion_list
            .contains(&DID::from("did:key:bob"))
    );
    assert!(
        !ctx.access
            .read_exclusion_list
            .contains(&DID::from("did:key:bob"))
    );
    // Bob still a member.
    assert!(ctx.membership.contains("did:key:bob"));
}

/// SCP-CAC-007: `Revoke (write)(Full)` destroys sender key in broadcast.
#[tokio::test]
async fn revoke_write_access_full_in_broadcast() {
    let (manager, ctx_id) = setup_broadcast_with_member_ban().await;

    // Add sub1 as member for governance purposes.
    {
        let _arc = manager.contexts.get(&ctx_id).unwrap().value().clone();
        let mut _g = _arc.lock().await;
        let ctx = &mut *_g;
        ctx.membership
            .add_member("did:key:sub1".into(), "subscriber".into(), vec![]);
    }

    let action = super::GovernanceAction::RevokeAccess {
        did: "did:key:alice".into(),
        access: super::AccessScope::Both,
    };
    let proposal = approved_governance_proposal(
        &"did:key:alice".into(),
        &ctx_id,
        &"did:key:alice".into(),
        action,
    );

    let result = manager.execute_governance_action(&ctx_id, &proposal).await;
    assert!(result.is_ok(), "Revoke (write)(Full) should succeed");

    // Alice should be in suspended_capabilities.
    let _arc = manager.contexts.get(&ctx_id).unwrap().value().clone();
    let _g = _arc.lock().await;
    let ctx = &*_g;
    assert!(
        ctx.role_state
            .suspended_capabilities
            .get("did:key:alice")
            .is_some_and(|s| s.contains(&Capability::MessagesWrite))
    );
    // Alice is still a member.
    assert!(ctx.membership.contains("did:key:alice"));
}

/// SCP-CAC-007: `Revoke { access: AccessScope::Write }` does NOT destroy broadcast key.
#[tokio::test]
async fn revoke_write_access_future_only_no_key_destruction() {
    let (manager, ctx_id) = setup_broadcast_with_member_ban().await;

    {
        let _arc = manager.contexts.get(&ctx_id).unwrap().value().clone();
        let mut _g = _arc.lock().await;
        let ctx = &mut *_g;
        ctx.membership
            .add_member("did:key:sub1".into(), "subscriber".into(), vec![]);
    }

    let action = super::GovernanceAction::RevokeAccess {
        did: "did:key:alice".into(),
        access: super::AccessScope::Write,
    };
    let proposal = approved_governance_proposal(
        &"did:key:alice".into(),
        &ctx_id,
        &"did:key:alice".into(),
        action,
    );

    let result = manager.execute_governance_action(&ctx_id, &proposal).await;
    assert!(result.is_ok(), "Revoke (write, FutureOnly) should succeed");

    // Alice should be in suspended_capabilities.
    let _arc = manager.contexts.get(&ctx_id).unwrap().value().clone();
    let _g = _arc.lock().await;
    let ctx = &*_g;
    assert!(
        ctx.role_state
            .suspended_capabilities
            .get("did:key:alice")
            .is_some_and(|s| s.contains(&Capability::MessagesWrite))
    );
    // Per spec §05-contexts §5.9, Revoke removes publishing authority:
    // the BroadcastContext author entry is removed. Subscribers retain
    // any cached broadcast keys for historical content (forward-only
    // restoration model).
    let bc = ctx.broadcast_context.as_ref().unwrap();
    assert!(
        !bc.is_author("did:key:alice"),
        "AccessScope::Write removes broadcast author"
    );
}

/// SCP-CAC-007: redundant `Revoke (write)` is prevented by TOCTOU replay protection.
#[tokio::test]
async fn revoke_write_access_redundant_rejected_by_replay_protection() {
    let (manager, ctx_id) = setup_encrypted_with_member_ban().await;

    let action = super::GovernanceAction::RevokeAccess {
        did: "did:key:bob".into(),
        access: super::AccessScope::Both,
    };
    let proposal = approved_governance_proposal(
        &"did:key:alice".into(),
        &ctx_id,
        &"did:key:bob".into(),
        action,
    );
    manager
        .execute_governance_action(&ctx_id, &proposal)
        .await
        .unwrap();

    // Second identical proposal is rejected by replay protection.
    let action2 = super::GovernanceAction::RevokeAccess {
        did: "did:key:bob".into(),
        access: super::AccessScope::Both,
    };
    let proposal2 = approved_governance_proposal(
        &"did:key:alice".into(),
        &ctx_id,
        &"did:key:bob".into(),
        action2,
    );
    let result = manager.execute_governance_action(&ctx_id, &proposal2).await;
    assert!(
        result.is_err(),
        "redundant proposal should be rejected by TOCTOU replay protection"
    );
}

/// SCP-CAC-007: `RestoreAccess (write)` returns `NothingToRestore` when never revoked.
#[tokio::test]
async fn restore_write_access_nothing_to_restore() {
    let (manager, ctx_id) = setup_encrypted_with_member_ban().await;

    let action = super::GovernanceAction::RestoreAccess {
        did: "did:key:bob".into(),
        capabilities: vec![super::Capability::MessagesWrite],
    };
    let proposal = approved_governance_proposal(
        &"did:key:alice".into(),
        &ctx_id,
        &"did:key:bob".into(),
        action,
    );

    let result = manager.execute_governance_action(&ctx_id, &proposal).await;
    assert!(result.is_err());
    assert!(
        matches!(result.unwrap_err(), ContextError::NothingToRestore(_)),
        "should return NothingToRestore when write access was never revoked"
    );
}

/// SCP-CAC-007: `RestoreAccess (write)` succeeds after revocation, emits event.
#[tokio::test]
async fn restore_write_access_after_revocation() {
    let (manager, ctx_id) = setup_encrypted_with_member_ban().await;

    // First revoke.
    let revoke_action = super::GovernanceAction::RevokeAccess {
        did: "did:key:bob".into(),
        access: super::AccessScope::Both,
    };
    let revoke_proposal = approved_governance_proposal(
        &"did:key:alice".into(),
        &ctx_id,
        &"did:key:bob".into(),
        revoke_action,
    );
    manager
        .execute_governance_action(&ctx_id, &revoke_proposal)
        .await
        .unwrap();
    manager.drain_events(&ctx_id).await;

    // Now restore.
    let restore_action = super::GovernanceAction::RestoreAccess {
        did: "did:key:bob".into(),
        capabilities: vec![super::Capability::MessagesWrite],
    };
    let restore_proposal = approved_governance_proposal(
        &"did:key:alice".into(),
        &ctx_id,
        &"did:key:bob".into(),
        restore_action,
    );
    let result = manager
        .execute_governance_action(&ctx_id, &restore_proposal)
        .await;
    assert!(result.is_ok(), "RestoreAccess (write) should succeed");

    // Bob should no longer be write-revoked.
    {
        let _arc = manager.contexts.get(&ctx_id).unwrap().value().clone();
        let _g = _arc.lock().await;
        let ctx = &*_g;
        assert!(
            !ctx.role_state
                .suspended_capabilities
                .get("did:key:bob")
                .is_some_and(|s| s.contains(&Capability::MessagesWrite))
        );
    }

    // Verify WriteAccessRestored event was emitted.
    let events = manager.drain_events(&ctx_id).await;
    let has_event = events.iter().any(|e| {
        matches!(
            e,
            super::ContextEvent::WriteAccessRestored { did } if did.0 == "did:key:bob"
        )
    });
    assert!(has_event, "AccessRestored event should have been emitted");
}

/// SCP-CAC-007: `RotateContentKeys` on broadcast context rotates all author keys.
#[tokio::test]
async fn rotate_content_keys_broadcast() {
    let (manager, ctx_id) = setup_broadcast_with_member_ban().await;

    let action = super::GovernanceAction::RotateContentKeys {
        reason: Some("periodic hygiene".to_owned()),
    };
    let proposal = approved_governance_proposal(
        &"did:key:alice".into(),
        &ctx_id,
        &"did:key:alice".into(),
        action,
    );

    let result = manager.execute_governance_action(&ctx_id, &proposal).await;
    assert!(result.is_ok(), "RotateContentKeys should succeed");

    match result.unwrap() {
        super::GovernanceActionResult::ContentKeysRotated(r) => {
            assert_eq!(r.reason, Some("periodic hygiene".to_owned()));
        }
        other => panic!("expected ContentKeysRotated, got {other:?}"),
    }

    // Verify ContentKeysRotated event emitted.
    let events = manager.drain_events(&ctx_id).await;
    let has_event = events
        .iter()
        .any(|e| matches!(e, super::ContextEvent::ContentKeysRotated { .. }));
    assert!(
        has_event,
        "ContentKeysRotated event should have been emitted"
    );
}

/// SCP-CAC-007: `RotateContentKeys` on encrypted context emits event
/// (MLS handles actual rotation).
#[tokio::test]
async fn rotate_content_keys_encrypted() {
    let (manager, ctx_id) = setup_encrypted_with_member_ban().await;

    let action = super::GovernanceAction::RotateContentKeys { reason: None };
    let proposal = approved_governance_proposal(
        &"did:key:alice".into(),
        &ctx_id,
        &"did:key:bob".into(),
        action,
    );

    let result = manager.execute_governance_action(&ctx_id, &proposal).await;
    assert!(
        result.is_ok(),
        "RotateContentKeys on encrypted should succeed"
    );

    // Verify event emitted.
    let events = manager.drain_events(&ctx_id).await;
    let has_event = events
        .iter()
        .any(|e| matches!(e, super::ContextEvent::ContentKeysRotated { .. }));
    assert!(
        has_event,
        "ContentKeysRotated event should have been emitted"
    );
}

/// SCP-CAC-007: presence-only members (read + write revoked) cannot propose.
#[tokio::test]
async fn presence_only_member_cannot_propose() {
    let (manager, ctx_id) = setup_encrypted_with_member_ban().await;

    // Revoke bob's read and write access to make them presence-only.
    let revoke_read = super::GovernanceAction::RevokeAccess {
        did: "did:key:bob".into(),
        access: super::AccessScope::Read,
    };
    let rr_proposal = approved_governance_proposal(
        &"did:key:alice".into(),
        &ctx_id,
        &"did:key:bob".into(),
        revoke_read,
    );
    manager
        .execute_governance_action(&ctx_id, &rr_proposal)
        .await
        .unwrap();

    let revoke_write = super::GovernanceAction::RevokeAccess {
        did: "did:key:bob".into(),
        access: super::AccessScope::Write,
    };
    let rw_proposal = approved_governance_proposal(
        &"did:key:alice".into(),
        &ctx_id,
        &"did:key:bob".into(),
        revoke_write,
    );
    manager
        .execute_governance_action(&ctx_id, &rw_proposal)
        .await
        .unwrap();

    // Now bob (presence-only) tries to propose — should fail.
    let bob_key = ed25519_dalek::SigningKey::from_bytes(&[2u8; 32]);
    let result = manager
        .propose_governance_action(
            &ctx_id,
            &"did:key:bob".into(),
            super::GovernanceAction::RotateContentKeys { reason: None },
            &bob_key,
        )
        .await;
    assert!(result.is_err());
    assert!(
        matches!(result.unwrap_err(), ContextError::PermissionDenied(ref msg) if msg.contains("presence-only")),
        "presence-only member should not be able to propose"
    );
}

/// SCP-CAC-007: member with only write revoked can still propose (not presence-only).
#[tokio::test]
async fn write_only_revoked_member_can_still_propose() {
    let (manager, ctx_id) = setup_encrypted_with_member_ban().await;

    // Revoke bob's write only.
    let revoke_write = super::GovernanceAction::RevokeAccess {
        did: "did:key:bob".into(),
        access: super::AccessScope::Write,
    };
    let rw_proposal = approved_governance_proposal(
        &"did:key:alice".into(),
        &ctx_id,
        &"did:key:bob".into(),
        revoke_write,
    );
    manager
        .execute_governance_action(&ctx_id, &rw_proposal)
        .await
        .unwrap();

    // Bob (read-only, not presence-only) can still propose.
    // Note: the governance engine may still reject based on role, but the
    // presence-only gate should not block them.
    let bob_key = ed25519_dalek::SigningKey::from_bytes(&[2u8; 32]);
    let result = manager
        .propose_governance_action(
            &ctx_id,
            &"did:key:bob".into(),
            super::GovernanceAction::RotateContentKeys { reason: None },
            &bob_key,
        )
        .await;
    // The governance engine may reject for other reasons (e.g. role),
    // but NOT because of presence-only check. Check it's not the
    // presence-only error specifically.
    if let Err(ref e) = result {
        assert!(
            !matches!(e, ContextError::PermissionDenied(msg) if msg.contains("presence-only")),
            "write-only-revoked member should not be blocked by presence-only check"
        );
    }
}

/// SCP-CAC-007: `Revoke (read)` fails for non-member DID.
#[tokio::test]
async fn revoke_read_access_non_member_fails() {
    let (manager, ctx_id) = setup_encrypted_with_member_ban().await;

    let action = super::GovernanceAction::RevokeAccess {
        did: "did:key:nonexistent".into(),
        access: super::AccessScope::Read,
    };
    let proposal = approved_governance_proposal(
        &"did:key:alice".into(),
        &ctx_id,
        &"did:key:nonexistent".into(),
        action,
    );

    let result = manager.execute_governance_action(&ctx_id, &proposal).await;
    assert!(result.is_err());
    assert!(
        matches!(result.unwrap_err(), ContextError::MemberNotFound(_)),
        "should return MemberNotFound for non-member DID"
    );
}

/// SCP-CAC-007: content access actions preserve membership (decoupling).
#[tokio::test]
async fn content_access_preserves_membership() {
    let (manager, ctx_id) = setup_encrypted_with_member_ban().await;

    // Revoke both read and write.
    let rr_action = super::GovernanceAction::RevokeAccess {
        did: "did:key:bob".into(),
        access: super::AccessScope::Read,
    };
    let rr_proposal = approved_governance_proposal(
        &"did:key:alice".into(),
        &ctx_id,
        &"did:key:bob".into(),
        rr_action,
    );
    manager
        .execute_governance_action(&ctx_id, &rr_proposal)
        .await
        .unwrap();

    let rw_action = super::GovernanceAction::RevokeAccess {
        did: "did:key:bob".into(),
        access: super::AccessScope::Both,
    };
    let rw_proposal = approved_governance_proposal(
        &"did:key:alice".into(),
        &ctx_id,
        &"did:key:bob".into(),
        rw_action,
    );
    manager
        .execute_governance_action(&ctx_id, &rw_proposal)
        .await
        .unwrap();

    // Bob is still a member despite both read and write revoked.
    let _arc = manager.contexts.get(&ctx_id).unwrap().value().clone();
    let _g = _arc.lock().await;
    let ctx = &*_g;
    assert!(
        ctx.membership.contains("did:key:bob"),
        "member should remain in context after both read and write revocation"
    );
    assert!(
        ctx.access
            .read_exclusion_list
            .contains(&DID::from("did:key:bob"))
    );
    assert!(
        ctx.role_state
            .suspended_capabilities
            .get("did:key:bob")
            .is_some_and(|s| s.contains(&Capability::MessagesWrite))
    );
}

// -----------------------------------------------------------------------
// Write access governance tests (SCP-CAC-007)
// -----------------------------------------------------------------------

/// SCP-CAC-007: `Revoke (write)` marks member as write-revoked.
#[tokio::test]
async fn revoke_write_access_marks_member() {
    let (manager, ctx_id) = setup_encrypted_with_member_ban().await;

    let action = super::GovernanceAction::RevokeAccess {
        did: "did:key:bob".into(),
        access: super::AccessScope::Write,
    };
    let proposal = approved_governance_proposal(
        &"did:key:alice".into(),
        &ctx_id,
        &"did:key:bob".into(),
        action,
    );

    let result = manager.execute_governance_action(&ctx_id, &proposal).await;
    assert!(result.is_ok(), "Revoke (write) should succeed");

    match result.unwrap() {
        super::GovernanceActionResult::AccessRevoked(r) => {
            assert_eq!(r.did.0, "did:key:bob");
        }
        other => panic!("expected AccessRevoked, got {other:?}"),
    }

    // Verify member is tracked as write-revoked.
    {
        let _arc = manager.contexts.get(&ctx_id).unwrap().value().clone();
        let _g = _arc.lock().await;
        let ctx = &*_g;
        assert!(
            ctx.role_state
                .suspended_capabilities
                .get("did:key:bob")
                .is_some_and(|s| s.contains(&Capability::MessagesWrite)),
            "bob should be in suspended_capabilities"
        );
    }

    // Verify WriteAccessRevoked event was emitted.
    let events = manager.drain_events(&ctx_id).await;
    let has_event = events.iter().any(|e| {
        matches!(
            e,
            super::ContextEvent::WriteAccessRevoked { did } if did.0 == "did:key:bob"
        )
    });
    assert!(has_event, "WriteAccessRevoked event should be emitted");
}

/// SCP-CAC-007: Redundant `Revoke (write)` is a no-op (§5.9).
#[tokio::test]
async fn revoke_write_access_redundant_is_noop() {
    let (manager, ctx_id) = setup_encrypted_with_member_ban().await;

    let action = super::GovernanceAction::RevokeAccess {
        did: "did:key:bob".into(),
        access: super::AccessScope::Write,
    };

    // First revocation.
    let proposal = approved_governance_proposal(
        &"did:key:alice".into(),
        &ctx_id,
        &"did:key:bob".into(),
        action.clone(),
    );
    manager
        .execute_governance_action(&ctx_id, &proposal)
        .await
        .unwrap();

    // Drain events from first call.
    manager.drain_events(&ctx_id).await;

    // Second revocation — should be a no-op (Ok(())).
    // Use a different proposal_id to bypass TOCTOU replay protection,
    // simulating a second proposal for the same action.
    let mut proposal2 = approved_governance_proposal(
        &"did:key:alice".into(),
        &ctx_id,
        &"did:key:bob".into(),
        action,
    );
    proposal2.proposal_id = [2u8; 32]; // distinct from first proposal
    let result = manager.execute_governance_action(&ctx_id, &proposal2).await;
    assert!(
        result.is_ok(),
        "redundant Revoke (write) should succeed (no-op)"
    );
}

/// SCP-CAC-007: `RestoreAccess (write)` removes write revocation.
#[tokio::test]
async fn restore_write_access_removes_revocation() {
    let (manager, ctx_id) = setup_encrypted_with_member_ban().await;

    // First revoke.
    let revoke = super::GovernanceAction::RevokeAccess {
        did: "did:key:bob".into(),
        access: super::AccessScope::Write,
    };
    let proposal = approved_governance_proposal(
        &"did:key:alice".into(),
        &ctx_id,
        &"did:key:bob".into(),
        revoke,
    );
    manager
        .execute_governance_action(&ctx_id, &proposal)
        .await
        .unwrap();
    manager.drain_events(&ctx_id).await;

    // Now restore.
    let restore = super::GovernanceAction::RestoreAccess {
        did: "did:key:bob".into(),
        capabilities: vec![super::Capability::MessagesWrite],
    };
    let restore_proposal = approved_governance_proposal(
        &"did:key:alice".into(),
        &ctx_id,
        &"did:key:bob".into(),
        restore,
    );
    let result = manager
        .execute_governance_action(&ctx_id, &restore_proposal)
        .await;
    assert!(result.is_ok(), "RestoreAccess (write) should succeed");

    match result.unwrap() {
        super::GovernanceActionResult::AccessRestored(r) => {
            assert_eq!(r.did.0, "did:key:bob");
        }
        other => panic!("expected AccessRestored, got {other:?}"),
    }

    // Verify member is no longer write-revoked.
    {
        let _arc = manager.contexts.get(&ctx_id).unwrap().value().clone();
        let _g = _arc.lock().await;
        let ctx = &*_g;
        assert!(
            !ctx.role_state
                .suspended_capabilities
                .get("did:key:bob")
                .is_some_and(|s| s.contains(&Capability::MessagesWrite)),
            "bob should not be in suspended_capabilities after restore"
        );
    }

    // Verify WriteAccessRestored event.
    let events = manager.drain_events(&ctx_id).await;
    let has_event = events.iter().any(|e| {
        matches!(
            e,
            super::ContextEvent::WriteAccessRestored { did } if did.0 == "did:key:bob"
        )
    });
    assert!(has_event, "WriteAccessRestored event should be emitted");
}

/// SCP-CAC-007: `RestoreAccess (write)` on never-revoked member returns
/// `NothingToRestore` error (§5.9).
#[tokio::test]
async fn restore_write_access_never_revoked_returns_error() {
    let (manager, ctx_id) = setup_encrypted_with_member_ban().await;

    let restore = super::GovernanceAction::RestoreAccess {
        did: "did:key:bob".into(),
        capabilities: vec![super::Capability::MessagesWrite],
    };
    let proposal = approved_governance_proposal(
        &"did:key:alice".into(),
        &ctx_id,
        &"did:key:bob".into(),
        restore,
    );

    let result = manager.execute_governance_action(&ctx_id, &proposal).await;
    assert!(
        result.is_err(),
        "RestoreAccess (write) on never-revoked should fail"
    );
    assert!(
        matches!(
            result.unwrap_err(),
            ContextError::NothingToRestore(ref msg) if msg.contains("did:key:bob")
        ),
        "error should be NothingToRestore"
    );
}

/// SCP-CAC-007: Presence-only state — revoking both read and write strips
/// governance capabilities.
#[tokio::test]
async fn presence_only_strips_governance_capabilities() {
    let (manager, ctx_id) = setup_encrypted_with_member_ban().await;

    // Revoke write access for bob.
    let revoke_write = super::GovernanceAction::RevokeAccess {
        did: "did:key:bob".into(),
        access: super::AccessScope::Write,
    };
    let proposal = approved_governance_proposal(
        &"did:key:alice".into(),
        &ctx_id,
        &"did:key:bob".into(),
        revoke_write,
    );
    manager
        .execute_governance_action(&ctx_id, &proposal)
        .await
        .unwrap();

    // Revoke read access for bob — now presence-only.
    let revoke_read = super::GovernanceAction::RevokeAccess {
        did: "did:key:bob".into(),
        access: super::AccessScope::Read,
    };
    let read_proposal = approved_governance_proposal(
        &"did:key:alice".into(),
        &ctx_id,
        &"did:key:bob".into(),
        revoke_read,
    );
    manager
        .execute_governance_action(&ctx_id, &read_proposal)
        .await
        .unwrap();

    // Verify both read and write are revoked.
    {
        let _arc = manager.contexts.get(&ctx_id).unwrap().value().clone();
        let _g = _arc.lock().await;
        let ctx = &*_g;
        assert!(
            ctx.role_state
                .suspended_capabilities
                .get("did:key:bob")
                .is_some_and(|s| s.contains(&Capability::MessagesWrite))
        );
        assert!(
            ctx.access
                .read_exclusion_list
                .contains(&DID("did:key:bob".into()))
        );
    }
}

/// SCP-CAC-007: `RotateContentKeys` emits `ContentKeysRotated` event.
#[tokio::test]
async fn rotate_content_keys_emits_event() {
    let (manager, ctx_id) = setup_encrypted_with_member_ban().await;

    let action = super::GovernanceAction::RotateContentKeys {
        reason: Some("periodic rotation".into()),
    };
    let proposal = approved_governance_proposal(
        &"did:key:alice".into(),
        &ctx_id,
        &"did:key:bob".into(),
        action,
    );

    let result = manager.execute_governance_action(&ctx_id, &proposal).await;
    assert!(result.is_ok(), "RotateContentKeys should succeed");

    match result.unwrap() {
        super::GovernanceActionResult::ContentKeysRotated(r) => {
            assert_eq!(r.reason.as_deref(), Some("periodic rotation"));
        }
        other => panic!("expected ContentKeysRotated, got {other:?}"),
    }

    // Verify ContentKeysRotated event.
    let events = manager.drain_events(&ctx_id).await;
    let has_event = events.iter().any(|e| {
        matches!(
            e,
            super::ContextEvent::ContentKeysRotated { reason } if reason.as_deref() == Some("periodic rotation")
        )
    });
    assert!(has_event, "ContentKeysRotated event should be emitted");
}

/// SCP-CAC-007: `RotateContentKeys` with no reason also works.
#[tokio::test]
async fn rotate_content_keys_no_reason() {
    let (manager, ctx_id) = setup_encrypted_with_member_ban().await;

    let action = super::GovernanceAction::RotateContentKeys { reason: None };
    let proposal = approved_governance_proposal(
        &"did:key:alice".into(),
        &ctx_id,
        &"did:key:bob".into(),
        action,
    );

    let result = manager.execute_governance_action(&ctx_id, &proposal).await;
    assert!(
        result.is_ok(),
        "RotateContentKeys with no reason should succeed"
    );

    match result.unwrap() {
        super::GovernanceActionResult::ContentKeysRotated(r) => {
            assert!(r.reason.is_none());
        }
        other => panic!("expected ContentKeysRotated, got {other:?}"),
    }
}

/// SCP-CAC-007: `Revoke (write)` with Full scope in broadcast context
/// blocks the author.
#[tokio::test]
async fn revoke_write_access_full_scope_broadcast() {
    let (manager, ctx_id) = setup_broadcast_with_member_ban().await;

    // Add sub1 as a member in membership so the revoke path finds them.
    {
        let _arc = manager.contexts.get(&ctx_id).unwrap().value().clone();
        let mut _g = _arc.lock().await;
        let ctx = &mut *_g;
        ctx.membership
            .add_member("did:key:sub1".into(), "subscriber".into(), vec![]);
        // Also add sub1 as an author in broadcast context.
        let bc = ctx.broadcast_context.as_mut().unwrap();
        bc.add_author("did:key:sub1").unwrap();
    }

    let action = super::GovernanceAction::RevokeAccess {
        did: "did:key:sub1".into(),
        access: super::AccessScope::Both,
    };
    let proposal = approved_governance_proposal(
        &"did:key:alice".into(),
        &ctx_id,
        &"did:key:sub1".into(),
        action,
    );

    let result = manager.execute_governance_action(&ctx_id, &proposal).await;
    assert!(
        result.is_ok(),
        "Revoke (write) Full in broadcast should succeed"
    );

    // Verify WriteAccessRevoked event.
    let events = manager.drain_events(&ctx_id).await;
    let has_event = events.iter().any(|e| {
        matches!(
            e,
            super::ContextEvent::WriteAccessRevoked { did } if did.0 == "did:key:sub1"
        )
    });
    assert!(has_event, "WriteAccessRevoked event should be emitted");
}

/// SCP-CAC-007: `Revoke (write)` fails without `MemberBan` in ceiling.
#[tokio::test]
async fn revoke_write_access_rejected_without_member_ban() {
    let manager = ContextManager::new(
        Box::new(MockCrypto::default()),
        Box::new(MockTransport::connected()),
        Box::new(MockEventLog::default()),
        noop_key_resolver(),
    );
    manager.register_local_did("did:key:alice".into()).await;
    manager.register_local_did("did:key:bob".into()).await;

    let params = ContextParams {
        mode: ContextMode::Encrypted,
        memory_scope: scp_protocol::context::MemoryScope::Full,
        ceiling: vec![
            scp_protocol::context::params::Capability::new("messages:read"),
            scp_protocol::context::params::Capability::new("messages:write"),
        ],
        ..ContextParams::default()
    };
    let _handle = manager
        .create_context("no-ban-write-ctx".into(), params, "did:key:alice".into())
        .await
        .unwrap();
    {
        let _arc = manager
            .contexts
            .get("no-ban-write-ctx")
            .unwrap()
            .value()
            .clone();
        let mut _g = _arc.lock().await;
        let ctx = &mut *_g;
        ctx.membership
            .add_member("did:key:bob".into(), "member".into(), vec![]);
    }

    let action = super::GovernanceAction::RevokeAccess {
        did: "did:key:bob".into(),
        access: super::AccessScope::Both,
    };
    let proposal = approved_governance_proposal(
        &"did:key:alice".into(),
        "no-ban-write-ctx",
        &"did:key:bob".into(),
        action,
    );

    let result = manager
        .execute_governance_action("no-ban-write-ctx", &proposal)
        .await;
    assert!(
        result.is_err(),
        "Revoke (write) should fail without MemberBan in ceiling"
    );
}

/// SCP-CAC-007: `Revoke (write)` on non-member returns error.
#[tokio::test]
async fn revoke_write_access_non_member_fails() {
    let (manager, ctx_id) = setup_encrypted_with_member_ban().await;

    let action = super::GovernanceAction::RevokeAccess {
        did: "did:key:nonexistent".into(),
        access: super::AccessScope::Both,
    };
    let proposal = approved_governance_proposal(
        &"did:key:alice".into(),
        &ctx_id,
        &"did:key:nonexistent".into(),
        action,
    );

    let result = manager.execute_governance_action(&ctx_id, &proposal).await;
    assert!(result.is_err(), "Revoke (write) on non-member should fail");
    assert!(
        matches!(result.unwrap_err(), ContextError::MemberNotFound(_)),
        "error should be MemberNotFound"
    );
}
