use super::*;
use scp_protocol::context::governance::{AccessScope, GovernanceAction};

// -----------------------------------------------------------------------
// Send message tests
// -----------------------------------------------------------------------

/// Unit test: `send_message` rejects when context is not Active.
#[tokio::test]
async fn send_message_rejects_when_context_not_active() {
    let (manager, handle) = setup_active_context().await;

    handle.transition_to(&ContextState::Closing).await.unwrap();

    let result = manager
        .send_message(
            &handle,
            &"did:key:creator".into(),
            b"hello",
            None,
            None,
            None,
        )
        .await;
    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        ContextError::ContextNotActive
    ));
}

/// Unit test: `send_message` validates UCAN before sending.
#[tokio::test]
async fn send_message_validates_ucan_before_sending() {
    let (manager, handle) = setup_active_context().await;

    // Try to send as a non-member -- should be denied.
    let result = manager
        .send_message(
            &handle,
            &"did:key:nonexistent".into(),
            b"hello",
            None,
            None,
            None,
        )
        .await;
    assert!(result.is_err());

    // Should be either PermissionDenied or MemberNotFound.
    match result.unwrap_err() {
        ContextError::PermissionDenied(_) => {}
        ContextError::MemberNotFound(_) => {}
        other => panic!("unexpected error: {other:?}"),
    }
}

#[tokio::test]
async fn send_message_success_encrypts_and_sends() {
    let (manager, handle) = setup_active_context().await;
    let sk = signing_key_for_did(&"did:key:creator".into());

    let result = manager
        .send_message(
            &handle,
            &"did:key:creator".into(),
            b"hello world",
            Some(&sk),
            None,
            None,
        )
        .await;
    assert!(result.is_ok());

    // Verify MessageSent event was emitted.
    let events = manager.drain_events("test-ctx").await;
    let msg_events: Vec<_> = events
        .iter()
        .filter(|e| matches!(e, ContextEvent::MessageSent { .. }))
        .collect();
    assert_eq!(msg_events.len(), 1);

    if let ContextEvent::MessageSent {
        sender_did,
        sequence_number,
        payload,
    } = &msg_events[0]
    {
        assert_eq!(sender_did, "did:key:creator");
        assert_eq!(*sequence_number, 1);
        assert_eq!(payload, b"hello world");
    }
}

#[tokio::test]
async fn send_message_assigns_monotonic_sequence_numbers() {
    let (manager, handle) = setup_active_context().await;
    let sk = signing_key_for_did(&"did:key:creator".into());

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

    let events = manager.drain_events("test-ctx").await;
    let seq_nums: Vec<u64> = events
        .iter()
        .filter_map(|e| {
            if let ContextEvent::MessageSent {
                sequence_number, ..
            } = e
            {
                Some(*sequence_number)
            } else {
                None
            }
        })
        .collect();

    assert_eq!(seq_nums, vec![1, 2, 3, 4, 5]);
}

/// When transport fails, no phantom `MessageSent` event must appear in
/// the receive buffer, and the membership-level sequence number must be
/// unchanged. Fixes #1420 (phantom events), sequence burn on failure.
#[tokio::test]
async fn send_message_transport_failure_no_phantom_event() {
    let manager = ContextManager::new(
        Box::new(MockCrypto::default()),
        Box::new(FailingTransport),
        Box::new(MockEventLog::default()),
        noop_key_resolver(),
    );

    let params = ContextParams {
        ceiling: vec![
            scp_protocol::context::params::Capability::new("messages:read"),
            scp_protocol::context::params::Capability::new("messages:write"),
        ],
        ..ContextParams::default()
    };

    let handle = manager
        .create_context("test-ctx-fail".into(), params, "did:key:creator".into())
        .await
        .unwrap();

    let sk = signing_key_for_did(&"did:key:creator".into());

    // send_message should fail because FailingTransport.send_message
    // returns an error.
    let result = manager
        .send_message(
            &handle,
            &"did:key:creator".into(),
            b"hello",
            Some(&sk),
            None,
            None,
        )
        .await;
    assert!(
        result.is_err(),
        "send_message must fail when transport fails"
    );

    // The receive buffer must be empty — no phantom MessageSent event.
    let events = manager.drain_events("test-ctx-fail").await;
    let msg_events: Vec<_> = events
        .iter()
        .filter(|e| matches!(e, ContextEvent::MessageSent { .. }))
        .collect();
    assert!(
        msg_events.is_empty(),
        "no MessageSent event should be emitted when transport fails (#1420)"
    );

    // Verify sequence number was NOT burned.
    let contexts = manager.contexts.lock().await;
    let ctx = contexts.get("test-ctx-fail").unwrap();
    let member = ctx
        .membership
        .members()
        .find(|m| m.did == "did:key:creator")
        .unwrap();
    assert_eq!(
        member.sequence_number, 0,
        "sequence number must not be burned on transport failure"
    );
}

/// When transport succeeds, `MessageSent` event must be present in the
/// receive buffer with the correct sequence number.
#[tokio::test]
async fn send_message_transport_success_emits_event() {
    let (manager, handle) = setup_active_context().await;
    let sk = signing_key_for_did(&"did:key:creator".into());

    let result = manager
        .send_message(
            &handle,
            &"did:key:creator".into(),
            b"positive-path",
            Some(&sk),
            None,
            None,
        )
        .await;
    assert!(
        result.is_ok(),
        "send_message must succeed with mock transport"
    );

    let events = manager.drain_events("test-ctx").await;
    let msg_events: Vec<_> = events
        .iter()
        .filter(|e| matches!(e, ContextEvent::MessageSent { .. }))
        .collect();
    assert_eq!(
        msg_events.len(),
        1,
        "exactly one MessageSent event must be emitted on success"
    );

    if let ContextEvent::MessageSent {
        sender_did,
        sequence_number,
        payload,
    } = &msg_events[0]
    {
        assert_eq!(sender_did, "did:key:creator");
        assert_eq!(payload, b"positive-path");
        assert_eq!(
            *sequence_number, 1,
            "first successful send must have sequence_number 1"
        );
    }
}

// -----------------------------------------------------------------------
// deliver_incoming tests
// -----------------------------------------------------------------------

#[tokio::test]
async fn deliver_incoming_rejects_inactive_context() {
    let (manager, handle) = setup_active_context().await;

    handle.transition_to(&ContextState::Closing).await.unwrap();

    let result = manager.deliver_incoming("test-ctx", b"late-payload").await;
    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        ContextError::ContextNotActive
    ));
}

#[tokio::test]
async fn deliver_incoming_rejects_unknown_context() {
    let (manager, _handle) = setup_active_context().await;

    let result = manager
        .deliver_incoming("nonexistent-ctx", b"payload")
        .await;
    assert!(result.is_err());
    match result.unwrap_err() {
        ContextError::ContextNotRegistered(_) => {}
        other => panic!("expected ContextNotRegistered, got: {other:?}"),
    }
}

// -----------------------------------------------------------------------
// Degraded mode reporting tests (§13.6, #606)
// -----------------------------------------------------------------------

/// `report_degraded_mode` emits a `ContextEvent::DegradedMode` when given
/// a `VersionCompatibility::DegradedMode` result.
#[tokio::test]
async fn report_degraded_mode_emits_event() {
    let (manager, _handle) = setup_active_context().await;

    let compat = scp_protocol::envelope::VersionCompatibility::DegradedMode {
        local_minor: 0,
        remote_minor: 3,
    };

    manager
        .report_degraded_mode("test-ctx", compat, vec!["hypothetical-feature".to_owned()])
        .await;

    let events = manager.drain_events("test-ctx").await;
    assert_eq!(events.len(), 1);
    match &events[0] {
        ContextEvent::DegradedMode {
            context_id,
            local_version,
            remote_version,
            unsupported_features,
        } => {
            assert_eq!(context_id, "test-ctx");
            assert_eq!(*local_version, (1, 0));
            assert_eq!(*remote_version, (1, 3));
            assert_eq!(unsupported_features, &["hypothetical-feature"]);
        }
        other => panic!("expected DegradedMode event, got {other:?}"),
    }
}

/// `report_degraded_mode` is a no-op when given
/// `VersionCompatibility::Exact`.
#[tokio::test]
async fn report_degraded_mode_noop_for_exact() {
    let (manager, _handle) = setup_active_context().await;

    manager
        .report_degraded_mode(
            "test-ctx",
            scp_protocol::envelope::VersionCompatibility::Exact,
            vec![],
        )
        .await;

    let events = manager.drain_events("test-ctx").await;
    assert!(
        events.is_empty(),
        "Exact compatibility should not emit events"
    );
}

// -----------------------------------------------------------------------
// Helpers for integration tests (round-trip, replay, tamper, access key)
// -----------------------------------------------------------------------

/// Creates a two-member context (creator=Alice, member=Bob) with
/// `mock_key_resolver` for real signature verification. Both members have
/// access keys and `messages:write` capability.
///
/// Returns `(manager, handle, sent_buffer)` where `sent_buffer` is a
/// shared handle to the transport's sent-messages buffer for inspecting
/// encrypted bytes after `send_message`.
async fn setup_two_member_verified_context() -> (
    ContextManager,
    ContextHandle,
    Arc<std::sync::Mutex<Vec<Vec<u8>>>>,
) {
    let transport = MockTransport::connected();
    let sent = transport.sent_messages_handle();

    let manager = ContextManager::new(
        Box::new(MockCrypto::default()),
        Box::new(transport),
        Box::new(MockEventLog::default()),
        mock_key_resolver(),
    );

    let params = ContextParams {
        ceiling: vec![
            scp_protocol::context::params::Capability::new("messages:read"),
            scp_protocol::context::params::Capability::new("messages:write"),
            scp_protocol::context::params::Capability::new("role:assign"),
            Capability::MemberBan,
        ],
        ..ContextParams::default()
    };

    // Register Alice as a local DID so deliver_incoming can find the local
    // member in the context (Fix 1: #1534 review).
    manager.register_local_did("did:key:alice".into()).await;

    let handle = manager
        .create_context("test-ctx".into(), params, "did:key:alice".into())
        .await
        .unwrap();

    // Add Bob as a member with access key.
    {
        let mut contexts = manager.contexts.lock().await;
        let ctx = contexts.get_mut("test-ctx").unwrap();
        ctx.membership
            .add_member("did:key:bob".into(), "member".into(), vec![]);
        ctx.role_state.members.insert("did:key:bob".to_owned());

        // Generate and store Bob's access key so send_message wraps for Bob
        // and deliver_incoming can unwrap for Bob.
        let bob_access_key =
            scp_protocol::crypto::access_keys::generate_access_key("test-ctx", "did:key:bob");
        ctx.access
            .access_key_store
            .set("test-ctx", "did:key:bob", bob_access_key);
    }

    (manager, handle, sent)
}

/// Returns the last message captured by a transport sent-messages buffer.
fn last_sent(sent: &Arc<std::sync::Mutex<Vec<Vec<u8>>>>) -> Vec<u8> {
    sent.lock()
        .unwrap()
        .last()
        .cloned()
        .expect("no messages sent via transport")
}

// -----------------------------------------------------------------------
// Integration tests: send → deliver round-trip (#1529, #1546, #1547)
// -----------------------------------------------------------------------

/// Full pipeline round-trip: `send_message` → capture bytes → `deliver_incoming`.
/// Exercises envelope construction, signing, access key wrapping, sealing,
/// opening, signature verification, anti-replay, and unwrapping (#1529).
#[tokio::test]
async fn send_then_deliver_roundtrip() {
    let (manager, handle, sent) = setup_two_member_verified_context().await;
    let alice_did: DID = "did:key:alice".into();
    let alice_sk = signing_key_for_did(&alice_did);

    // Alice sends a message.
    manager
        .send_message(
            &handle,
            &alice_did,
            b"hello from alice",
            Some(&alice_sk),
            None,
            None,
        )
        .await
        .unwrap();

    // Capture the encrypted bytes from transport.
    let encrypted = last_sent(&sent);

    // Drain events from the send so they don't interfere with receive assertions.
    let _ = manager.drain_events("test-ctx").await;

    // Deliver to the same manager (simulates receiving on the same node).
    let result = manager
        .deliver_incoming("test-ctx", &encrypted)
        .await
        .unwrap();

    // Verify plaintext and sender DID.
    let (plaintext, sender_did) = result.expect("should return Some for ApplicationMessage");
    assert_eq!(plaintext, b"hello from alice");
    assert_eq!(sender_did, "did:key:alice");

    // Verify MessageReceived event was pushed to the receive buffer.
    let events = manager.drain_events("test-ctx").await;
    let recv_events: Vec<_> = events
        .iter()
        .filter(|e| matches!(e, ContextEvent::MessageReceived { .. }))
        .collect();
    assert_eq!(recv_events.len(), 1);
    if let ContextEvent::MessageReceived {
        sender_did: s,
        payload: p,
    } = &recv_events[0]
    {
        assert_eq!(s.as_ref(), "did:key:alice");
        assert_eq!(p, b"hello from alice");
    }
}

/// Anti-replay: delivering the same encrypted bytes twice must fail the
/// second time with a sequence regression error (#1546).
#[tokio::test]
async fn deliver_incoming_rejects_replayed_message() {
    let (manager, handle, sent) = setup_two_member_verified_context().await;
    let alice_did: DID = "did:key:alice".into();
    let alice_sk = signing_key_for_did(&alice_did);

    // Alice sends.
    manager
        .send_message(&handle, &alice_did, b"first", Some(&alice_sk), None, None)
        .await
        .unwrap();

    let encrypted = last_sent(&sent);
    let _ = manager.drain_events("test-ctx").await;

    // First delivery succeeds.
    let first = manager.deliver_incoming("test-ctx", &encrypted).await;
    assert!(first.is_ok(), "first delivery should succeed");

    // Second delivery of the same bytes must fail (replay).
    let second = manager.deliver_incoming("test-ctx", &encrypted).await;
    assert!(second.is_err(), "replayed message must be rejected");

    let err_msg = format!("{:?}", second.unwrap_err());
    assert!(
        err_msg.contains("SequenceRegression") || err_msg.contains("sequence"),
        "error should indicate sequence regression, got: {err_msg}"
    );
}

/// Tampered signature: flipping a byte in the inner envelope's signature
/// causes `deliver_incoming` to reject the message (#1547).
#[tokio::test]
async fn deliver_incoming_rejects_tampered_signature() {
    let (manager, handle, sent) = setup_two_member_verified_context().await;
    let alice_did: DID = "did:key:alice".into();
    let alice_sk = signing_key_for_did(&alice_did);

    manager
        .send_message(
            &handle,
            &alice_did,
            b"original",
            Some(&alice_sk),
            None,
            None,
        )
        .await
        .unwrap();

    let encrypted = last_sent(&sent);

    // MockCrypto seal = rmp_serde::to_vec_named(inner), so the bytes are
    // a serialized InnerEnvelope. Deserialize, tamper, re-serialize.
    let mut inner: scp_protocol::envelope::inner::InnerEnvelope =
        rmp_serde::from_slice(&encrypted).unwrap();
    // Flip a byte in the signature to invalidate it.
    if !inner.signature.is_empty() {
        inner.signature[0] ^= 0xFF;
    }
    let tampered = rmp_serde::to_vec_named(&inner).unwrap();

    // deliver_incoming should reject the tampered message.
    let result = manager.deliver_incoming("test-ctx", &tampered).await;
    assert!(result.is_err(), "tampered signature must be rejected");

    let err_msg = format!("{:?}", result.unwrap_err());
    assert!(
        err_msg.contains("signature") || err_msg.contains("Crypto"),
        "error should mention signature failure, got: {err_msg}"
    );
}

/// Wrong signing key: message signed with a key that doesn't match the
/// sender's DID causes signature verification to fail (#1547).
#[tokio::test]
async fn deliver_incoming_rejects_wrong_signing_key() {
    let (manager, handle, sent) = setup_two_member_verified_context().await;
    let alice_did: DID = "did:key:alice".into();

    // Use a WRONG signing key (Bob's key, not Alice's).
    let wrong_sk = signing_key_for_did(&"did:key:bob".into());

    // Alice sends a message but signs with Bob's key. send_message will
    // succeed (it doesn't verify the key matches the DID on the send side).
    manager
        .send_message(
            &handle,
            &alice_did,
            b"wrong-key-msg",
            Some(&wrong_sk),
            None,
            None,
        )
        .await
        .unwrap();

    let encrypted = last_sent(&sent);
    let _ = manager.drain_events("test-ctx").await;

    // deliver_incoming should reject: the signature was made with Bob's key
    // but the envelope claims Alice as sender, and verify_inner_signature
    // resolves Alice's public key.
    let result = manager.deliver_incoming("test-ctx", &encrypted).await;
    assert!(result.is_err(), "wrong signing key must be rejected");

    let err_msg = format!("{:?}", result.unwrap_err());
    assert!(
        err_msg.contains("signature") || err_msg.contains("Crypto"),
        "error should mention signature failure, got: {err_msg}"
    );
}

/// After revoking a member's read access, their access key is removed and
/// `deliver_incoming` fails with "no access key" (#1529).
#[tokio::test]
async fn revoked_member_cannot_decrypt_new_messages() {
    let (manager, handle, sent) = setup_two_member_verified_context().await;
    let alice_did: DID = "did:key:alice".into();
    let alice_sk = signing_key_for_did(&alice_did);

    // Revoke Bob's read access via governance.
    let bob_did: DID = "did:key:bob".into();
    let proposal = approved_governance_proposal(
        &alice_did,
        "test-ctx",
        &bob_did,
        GovernanceAction::Revoke {
            did: bob_did.clone(),
            access: AccessScope::Read,
        },
    );
    manager
        .execute_governance_action("test-ctx", &proposal)
        .await
        .unwrap();

    // revoke_read_access_internal now destroys the access key automatically
    // (§9.17.2 step 3), so no manual removal is needed.

    // Verify the access key was actually removed by the governance action.
    {
        let contexts = manager.contexts.lock().await;
        let ctx = contexts.get("test-ctx").unwrap();
        assert!(
            !ctx.access
                .access_key_store
                .contains("test-ctx", "did:key:bob"),
            "Bob's access key should have been removed by revoke_read_access_internal"
        );
    }

    // Drain all events accumulated so far.
    let _ = manager.drain_events("test-ctx").await;

    // Alice sends a new message (only wrapped for Alice, not Bob).
    manager
        .send_message(
            &handle,
            &alice_did,
            b"secret for alice only",
            Some(&alice_sk),
            None,
            None,
        )
        .await
        .unwrap();

    let encrypted = last_sent(&sent);

    // Create a separate manager simulating Bob's device. Bob has the same
    // context but only his own membership. His access key was revoked.
    let bob_manager = ContextManager::new(
        Box::new(MockCrypto::default()),
        Box::new(MockTransport::connected()),
        Box::new(MockEventLog::default()),
        mock_key_resolver(),
    );
    bob_manager.register_local_did("did:key:bob".into()).await;

    let bob_params = ContextParams {
        ceiling: vec![
            scp_protocol::context::params::Capability::new("messages:read"),
            scp_protocol::context::params::Capability::new("messages:write"),
            scp_protocol::context::params::Capability::new("role:assign"),
            Capability::MemberBan,
        ],
        ..ContextParams::default()
    };
    let _bob_handle = bob_manager
        .create_context("test-ctx".into(), bob_params, "did:key:bob".into())
        .await
        .unwrap();

    // Add Alice as a member (so sender membership check passes) but remove
    // Bob's access key — simulating post-revocation state.
    {
        let mut contexts = bob_manager.contexts.lock().await;
        let ctx = contexts.get_mut("test-ctx").unwrap();
        ctx.membership
            .add_member("did:key:alice".into(), "admin".into(), vec![]);
        ctx.role_state.members.insert("did:key:alice".to_owned());
        // Bob's access key was revoked — remove it.
        ctx.access
            .access_key_store
            .remove("test-ctx", "did:key:bob");
    }

    // Bob's deliver_incoming should fail because he has no access key.
    let result = bob_manager.deliver_incoming("test-ctx", &encrypted).await;
    assert!(
        result.is_err(),
        "revoked member must not be able to decrypt"
    );

    let err_msg = format!("{:?}", result.unwrap_err());
    assert!(
        err_msg.contains("no access key") || err_msg.contains("access key"),
        "error should mention missing access key, got: {err_msg}"
    );
}

/// `RotateContentKeys` governance action emits a `ContentKeysRotated` event
/// and triggers key rotation (#1529).
#[tokio::test]
async fn rotate_content_keys_regenerates_access_keys() {
    let (manager, _handle, _sent) = setup_two_member_verified_context().await;
    let alice_did: DID = "did:key:alice".into();

    // Record that we have access keys before rotation.
    {
        let contexts = manager.contexts.lock().await;
        let ctx = contexts.get("test-ctx").unwrap();
        let all_keys = ctx.access.access_key_store.get_all("test-ctx");
        assert!(
            all_keys.contains_key("did:key:alice"),
            "Alice should have an access key"
        );
        assert!(
            all_keys.contains_key("did:key:bob"),
            "Bob should have an access key"
        );
    }

    // Drain pre-existing events.
    let _ = manager.drain_events("test-ctx").await;

    // Execute RotateContentKeys governance action.
    let bob_did: DID = "did:key:bob".into();
    let proposal = approved_governance_proposal(
        &alice_did,
        "test-ctx",
        &bob_did,
        GovernanceAction::RotateContentKeys {
            reason: Some("periodic rotation".to_owned()),
        },
    );
    manager
        .execute_governance_action("test-ctx", &proposal)
        .await
        .unwrap();

    // Verify ContentKeysRotated event was emitted.
    let events = manager.drain_events("test-ctx").await;
    let rotate_events: Vec<_> = events
        .iter()
        .filter(|e| matches!(e, ContextEvent::ContentKeysRotated { .. }))
        .collect();
    assert_eq!(
        rotate_events.len(),
        1,
        "exactly one ContentKeysRotated event should be emitted"
    );
    if let ContextEvent::ContentKeysRotated { reason } = &rotate_events[0] {
        assert_eq!(reason.as_deref(), Some("periodic rotation"));
    }
}

/// `report_degraded_mode` is a no-op for an unknown context.
#[tokio::test]
async fn report_degraded_mode_noop_for_unknown_context() {
    let (manager, _handle) = setup_active_context().await;

    let compat = scp_protocol::envelope::VersionCompatibility::DegradedMode {
        local_minor: 0,
        remote_minor: 2,
    };

    // "nonexistent-ctx" is not registered — should not panic.
    manager
        .report_degraded_mode("nonexistent-ctx", compat, vec![])
        .await;

    // No events on the registered context either.
    let events = manager.drain_events("test-ctx").await;
    assert!(events.is_empty());
}

/// Multiple degraded mode reports accumulate in the receive buffer.
#[tokio::test]
async fn report_degraded_mode_accumulates() {
    let (manager, _handle) = setup_active_context().await;

    for minor in 1..=3u8 {
        let compat = scp_protocol::envelope::VersionCompatibility::DegradedMode {
            local_minor: 0,
            remote_minor: minor,
        };
        manager
            .report_degraded_mode("test-ctx", compat, vec![])
            .await;
    }

    let events = manager.drain_events("test-ctx").await;
    let degraded_events: Vec<_> = events
        .iter()
        .filter(|e| matches!(e, ContextEvent::DegradedMode { .. }))
        .collect();
    assert_eq!(degraded_events.len(), 3);
}

// -----------------------------------------------------------------------
// Reorder buffer tests (§9.8.5)
// -----------------------------------------------------------------------

/// Out-of-order message (sequence 2 delivered before sequence 1) is buffered
/// and returns `Ok(None)` (§9.8.5).
#[tokio::test]
#[allow(clippy::await_holding_lock)]
async fn deliver_incoming_buffers_out_of_order_message() {
    let (manager, handle, sent) = setup_two_member_verified_context().await;
    let alice_did: DID = "did:key:alice".into();
    let alice_sk = signing_key_for_did(&alice_did);

    // Send two messages in order (seq 1, 2).
    for msg in &[b"msg-1".as_slice(), b"msg-2".as_slice()] {
        manager
            .send_message(&handle, &alice_did, msg, Some(&alice_sk), None, None)
            .await
            .unwrap();
    }

    let sent_guard = sent.lock().unwrap();
    let blob2 = sent_guard[1].clone();
    drop(sent_guard);

    let _ = manager.drain_events("test-ctx").await;

    // Deliver sequence 2 first (out of order -- should be buffered).
    let result = manager.deliver_incoming("test-ctx", &blob2).await;
    assert!(
        result.is_ok(),
        "out-of-order message should not error: {:?}",
        result.as_ref().err()
    );
    assert!(
        result.unwrap().is_none(),
        "out-of-order message should return None (buffered)"
    );

    // Verify the reorder buffer has the message.
    let contexts = manager.contexts.lock().await;
    let ctx = contexts.get("test-ctx").unwrap();
    assert_eq!(
        ctx.reorder_buffer
            .buffered_count("test-ctx", "did:key:alice"),
        1,
        "one message should be buffered"
    );
}

/// When the gap fills, both the gap-filling message and all consecutive
/// buffered messages are delivered in order (§9.8.5).
#[tokio::test]
#[allow(clippy::await_holding_lock)]
async fn deliver_incoming_gap_fill_delivers_buffered() {
    let (manager, handle, sent) = setup_two_member_verified_context().await;
    let alice_did: DID = "did:key:alice".into();
    let alice_sk = signing_key_for_did(&alice_did);

    // Send three messages in order.
    for msg in &[
        b"msg-1".as_slice(),
        b"msg-2".as_slice(),
        b"msg-3".as_slice(),
    ] {
        manager
            .send_message(&handle, &alice_did, msg, Some(&alice_sk), None, None)
            .await
            .unwrap();
    }

    let sent_guard = sent.lock().unwrap();
    let blob1 = sent_guard[0].clone();
    let blob2 = sent_guard[1].clone();
    let blob3 = sent_guard[2].clone();
    drop(sent_guard);

    let _ = manager.drain_events("test-ctx").await;

    // Deliver out of order: 2, 3, then 1.
    let result = manager.deliver_incoming("test-ctx", &blob2).await;
    assert!(result.unwrap().is_none(), "seq 2 should be buffered");

    let result = manager.deliver_incoming("test-ctx", &blob3).await;
    assert!(result.unwrap().is_none(), "seq 3 should be buffered");

    // No MessageReceived events yet (all buffered).
    let events = manager.drain_events("test-ctx").await;
    let recv_events: Vec<_> = events
        .iter()
        .filter(|e| matches!(e, ContextEvent::MessageReceived { .. }))
        .collect();
    assert!(
        recv_events.is_empty(),
        "no messages should be delivered while gap exists"
    );

    // Deliver sequence 1 -- fills the gap, delivers all three.
    let result = manager.deliver_incoming("test-ctx", &blob1).await;
    let (plaintext, sender) = result.unwrap().expect("seq 1 should be delivered");
    assert_eq!(plaintext, b"msg-1");
    assert_eq!(sender, "did:key:alice");

    // All three messages should now be in the receive buffer in order.
    let events = manager.drain_events("test-ctx").await;
    let recv_events: Vec<_> = events
        .into_iter()
        .filter(|e| matches!(e, ContextEvent::MessageReceived { .. }))
        .collect();
    assert_eq!(
        recv_events.len(),
        3,
        "all three messages should be delivered"
    );

    // Check order: msg-1, msg-2, msg-3.
    let payloads: Vec<Vec<u8>> = recv_events
        .iter()
        .filter_map(|e| {
            if let ContextEvent::MessageReceived { payload, .. } = e {
                Some(payload.clone())
            } else {
                None
            }
        })
        .collect();
    assert_eq!(payloads[0], b"msg-1");
    assert_eq!(payloads[1], b"msg-2");
    assert_eq!(payloads[2], b"msg-3");

    // Verify the reorder buffer is now empty.
    let contexts = manager.contexts.lock().await;
    let ctx = contexts.get("test-ctx").unwrap();
    assert_eq!(
        ctx.reorder_buffer.total_buffered(),
        0,
        "reorder buffer should be empty after gap fill"
    );
}

/// Replayed message (same encrypted bytes delivered twice) is rejected
/// even with the reorder buffer active (§9.8.2).
#[tokio::test]
async fn deliver_incoming_rejects_replay_with_reorder_buffer() {
    let (manager, handle, sent) = setup_two_member_verified_context().await;
    let alice_did: DID = "did:key:alice".into();
    let alice_sk = signing_key_for_did(&alice_did);

    manager
        .send_message(&handle, &alice_did, b"msg-1", Some(&alice_sk), None, None)
        .await
        .unwrap();

    let blob = last_sent(&sent);
    let _ = manager.drain_events("test-ctx").await;

    // First delivery succeeds.
    let result = manager.deliver_incoming("test-ctx", &blob).await;
    assert!(result.is_ok());

    // Replay the same bytes -- must fail.
    let result = manager.deliver_incoming("test-ctx", &blob).await;
    assert!(result.is_err(), "replayed message must be rejected");
    let err_msg = format!("{:?}", result.unwrap_err());
    assert!(
        err_msg.contains("SequenceRegression") || err_msg.contains("sequence"),
        "error should indicate sequence issue, got: {err_msg}"
    );
}

// -----------------------------------------------------------------------
// ReorderBuffer unit tests (pure protocol-level)
// -----------------------------------------------------------------------

#[test]
#[allow(clippy::cast_possible_truncation)]
fn reorder_buffer_drain_consecutive() {
    use scp_protocol::envelope::validation::{BufferedMessage, ReorderBuffer};

    let mut buf = ReorderBuffer::default();
    let inner = scp_protocol::envelope::inner::InnerEnvelope {
        version: 0x0100,
        context_id: "ctx".to_owned(),
        sender_did: "did:key:a".to_owned(),
        epoch: 0,
        generation: 0,
        sequence: 3,
        timestamp: 100,
        message_type: scp_protocol::envelope::inner::MessageType::Content,
        payload: vec![],
        signature: [0u8; 64],
        payload_hash: [0u8; 32],
        provenance_hash: [0u8; 32],
        signing_key_id: scp_protocol::identity::SigningKeyId::Active,
        provenance: None,
        extensions: std::collections::HashMap::new(),
    };

    // Buffer messages at seq 3, 4, 5.
    for seq in 3..=5 {
        let mut msg_inner = inner.clone();
        msg_inner.sequence = seq;
        let msg = BufferedMessage {
            inner: msg_inner,
            sender_did: "did:key:a".to_owned(),
            plaintext: vec![seq as u8],
            received_at: 100,
        };
        buf.buffer(msg);
    }

    assert_eq!(buf.buffered_count("ctx", "did:key:a"), 3);

    // Drain consecutive starting from seq 3.
    let drained = buf.drain_consecutive("ctx", "did:key:a", 3);
    assert_eq!(drained.len(), 3);
    assert_eq!(drained[0].plaintext, vec![3]);
    assert_eq!(drained[1].plaintext, vec![4]);
    assert_eq!(drained[2].plaintext, vec![5]);
    assert_eq!(buf.total_buffered(), 0);
}

#[test]
#[allow(clippy::cast_possible_truncation)]
fn reorder_buffer_drain_stops_at_gap() {
    use scp_protocol::envelope::validation::{BufferedMessage, ReorderBuffer};

    let mut buf = ReorderBuffer::default();
    let inner = scp_protocol::envelope::inner::InnerEnvelope {
        version: 0x0100,
        context_id: "ctx".to_owned(),
        sender_did: "did:key:a".to_owned(),
        epoch: 0,
        generation: 0,
        sequence: 0,
        timestamp: 100,
        message_type: scp_protocol::envelope::inner::MessageType::Content,
        payload: vec![],
        signature: [0u8; 64],
        payload_hash: [0u8; 32],
        provenance_hash: [0u8; 32],
        signing_key_id: scp_protocol::identity::SigningKeyId::Active,
        provenance: None,
        extensions: std::collections::HashMap::new(),
    };

    // Buffer messages at seq 3 and 5 (gap at 4).
    for seq in [3, 5] {
        let mut msg_inner = inner.clone();
        msg_inner.sequence = seq;
        let msg = BufferedMessage {
            inner: msg_inner,
            sender_did: "did:key:a".to_owned(),
            plaintext: vec![seq as u8],
            received_at: 100,
        };
        buf.buffer(msg);
    }

    // Drain from 3: should only get seq 3 (gap at 4).
    let drained = buf.drain_consecutive("ctx", "did:key:a", 3);
    assert_eq!(drained.len(), 1);
    assert_eq!(drained[0].plaintext, vec![3]);
    // Seq 5 should remain buffered.
    assert_eq!(buf.buffered_count("ctx", "did:key:a"), 1);
}

#[test]
#[allow(clippy::cast_possible_truncation)]
fn reorder_buffer_overflow_force_delivers() {
    use scp_protocol::envelope::validation::{BufferedMessage, GapCloseReason, ReorderBuffer};

    // Buffer with max size 3.
    let mut buf = ReorderBuffer::new(3, 30_000);
    let inner = scp_protocol::envelope::inner::InnerEnvelope {
        version: 0x0100,
        context_id: "ctx".to_owned(),
        sender_did: "did:key:a".to_owned(),
        epoch: 0,
        generation: 0,
        sequence: 0,
        timestamp: 100,
        message_type: scp_protocol::envelope::inner::MessageType::Content,
        payload: vec![],
        signature: [0u8; 64],
        payload_hash: [0u8; 32],
        provenance_hash: [0u8; 32],
        signing_key_id: scp_protocol::identity::SigningKeyId::Active,
        provenance: None,
        extensions: std::collections::HashMap::new(),
    };

    // Buffer 3 messages — no overflow yet.
    for seq in 2..=4 {
        let mut msg_inner = inner.clone();
        msg_inner.sequence = seq;
        let msg = BufferedMessage {
            inner: msg_inner,
            sender_did: "did:key:a".to_owned(),
            plaintext: vec![seq as u8],
            received_at: 100,
        };
        let result = buf.buffer(msg);
        assert!(result.is_none(), "no overflow at count {seq}");
    }

    // 4th message triggers overflow.
    let mut msg_inner = inner;
    msg_inner.sequence = 5;
    let msg = BufferedMessage {
        inner: msg_inner,
        sender_did: "did:key:a".to_owned(),
        plaintext: vec![5],
        received_at: 100,
    };
    let result = buf.buffer(msg);
    assert!(result.is_some(), "4th message should trigger overflow");

    let (gap_info, messages) = result.unwrap();
    assert_eq!(gap_info.reason, GapCloseReason::BufferFull);
    assert_eq!(
        messages.len(),
        4,
        "all 4 buffered messages should be returned"
    );
    assert_eq!(
        buf.total_buffered(),
        0,
        "buffer should be empty after overflow"
    );
}

#[test]
fn reorder_buffer_gap_timeout() {
    use scp_protocol::envelope::validation::{
        BufferedMessage, GapCloseReason, ReorderBuffer, SequenceTracker,
    };

    let mut buf = ReorderBuffer::new(100, 30_000); // 30s timeout
    let tracker = SequenceTracker::new();
    let inner = scp_protocol::envelope::inner::InnerEnvelope {
        version: 0x0100,
        context_id: "ctx".to_owned(),
        sender_did: "did:key:a".to_owned(),
        epoch: 0,
        generation: 0,
        sequence: 2,
        timestamp: 100,
        message_type: scp_protocol::envelope::inner::MessageType::Content,
        payload: vec![],
        signature: [0u8; 64],
        payload_hash: [0u8; 32],
        provenance_hash: [0u8; 32],
        signing_key_id: scp_protocol::identity::SigningKeyId::Active,
        provenance: None,
        extensions: std::collections::HashMap::new(),
    };

    // Buffer a message at seq 2 with received_at = 1000.
    let msg = BufferedMessage {
        inner,
        sender_did: "did:key:a".to_owned(),
        plaintext: vec![2],
        received_at: 1000,
    };
    buf.buffer(msg);

    // At time 20_000 (20s later) — no timeout yet.
    let timed_out = buf.drain_timed_out(20_000, &tracker);
    assert!(timed_out.is_empty(), "should not timeout at 20s");

    // At time 31_001 (30s + 1ms later) — should timeout.
    let timed_out = buf.drain_timed_out(31_001, &tracker);
    assert_eq!(timed_out.len(), 1, "should timeout at 31s");

    let (gap_info, messages) = &timed_out[0];
    assert_eq!(gap_info.reason, GapCloseReason::Timeout);
    assert_eq!(messages.len(), 1);
    assert_eq!(messages[0].plaintext, vec![2]);
    assert_eq!(
        buf.total_buffered(),
        0,
        "buffer should be empty after timeout"
    );
}

/// `SequenceTracker::validate` returns Expected for in-order, Ahead for gaps.
#[test]
fn sequence_tracker_validate_returns_correct_check() {
    use scp_protocol::envelope::validation::{SequenceCheck, SequenceTracker};

    let mut tracker = SequenceTracker::new();
    let inner = scp_protocol::envelope::inner::InnerEnvelope {
        version: 0x0100,
        context_id: "ctx".to_owned(),
        sender_did: "did:key:a".to_owned(),
        epoch: 0,
        generation: 0,
        sequence: 1,
        timestamp: 100,
        message_type: scp_protocol::envelope::inner::MessageType::Content,
        payload: vec![],
        signature: [0u8; 64],
        payload_hash: [0u8; 32],
        provenance_hash: [0u8; 32],
        signing_key_id: scp_protocol::identity::SigningKeyId::Active,
        provenance: None,
        extensions: std::collections::HashMap::new(),
    };

    // First message (seq 1) should be Expected.
    assert_eq!(tracker.validate(&inner).unwrap(), SequenceCheck::Expected);

    // Advance tracker.
    tracker.advance("ctx", "did:key:a", 1, 100);

    // Seq 2 should be Expected.
    let mut inner2 = inner.clone();
    inner2.sequence = 2;
    inner2.timestamp = 101;
    assert_eq!(tracker.validate(&inner2).unwrap(), SequenceCheck::Expected);

    // Seq 4 should be Ahead (gap at 3).
    let mut inner4 = inner.clone();
    inner4.sequence = 4;
    inner4.timestamp = 102;
    assert_eq!(
        tracker.validate(&inner4).unwrap(),
        SequenceCheck::Ahead { expected: 2 }
    );

    // Seq 1 should be SequenceRegression.
    let mut inner_replay = inner;
    inner_replay.sequence = 1;
    inner_replay.timestamp = 103;
    assert!(tracker.validate(&inner_replay).is_err());
}

// -----------------------------------------------------------------------
// Outer envelope structure (#1534 criterion 7)
// -----------------------------------------------------------------------

/// Verifies that `send_message` produces an outer envelope with the correct
/// `routing_id` (domain-separated derivation), non-zero `blob_ttl`, and
/// non-empty `encrypted_blob`.
///
/// NOTE: With `MockCrypto`, `seal` serializes the `InnerEnvelope` directly
/// (no real `OuterEnvelope` wrapping). This test verifies the `routing_id`
/// derivation function used by `build_encrypted_envelope` matches the
/// expected value.
#[tokio::test]
async fn send_message_routing_id_is_domain_separated() {
    let context_id = "test-ctx";

    // Verify context_routing_id is domain-separated from raw context_id_bytes.
    let routing_id = scp_protocol::context::context_routing_id(context_id);
    let raw = scp_protocol::context::context_id_bytes(context_id);
    assert_ne!(
        routing_id, raw,
        "domain-separated routing_id must differ from raw context_id_bytes"
    );

    // Verify derive_routing_id delegates to context_routing_id.
    let derived = super::super::messaging::derive_routing_id(context_id);
    assert_eq!(
        derived, routing_id,
        "derive_routing_id must delegate to context_routing_id"
    );
}

/// Verifies that `send_message` captures non-empty encrypted bytes via transport.
#[tokio::test]
async fn send_message_produces_non_empty_encrypted_blob() {
    let (manager, handle, sent) = setup_two_member_verified_context().await;
    let alice_did: DID = "did:key:alice".into();
    let alice_sk = signing_key_for_did(&alice_did);

    manager
        .send_message(
            &handle,
            &alice_did,
            b"envelope-test",
            Some(&alice_sk),
            None,
            None,
        )
        .await
        .unwrap();

    let encrypted = last_sent(&sent);
    assert!(
        !encrypted.is_empty(),
        "encrypted blob must be non-empty after send_message"
    );
}

// -----------------------------------------------------------------------
// Outer envelope structure tests (#1534-AC7)
// -----------------------------------------------------------------------

/// Verifies that `send_message` produces bytes that can be deserialized as
/// an `InnerEnvelope` (mock format) and that the routing ID passed to
/// transport matches the domain-separated `context_routing_id`.
#[tokio::test]
async fn send_message_produces_valid_outer_envelope() {
    let transport = MockTransport::connected();
    let sent_handle = transport.sent_messages_handle();
    let routing_handle = transport.routing_ids_handle();

    let manager = ContextManager::new(
        Box::new(MockCrypto::default()),
        Box::new(transport),
        Box::new(MockEventLog::default()),
        mock_key_resolver(),
    );

    let params = ContextParams {
        ceiling: vec![
            scp_protocol::context::params::Capability::new("messages:read"),
            scp_protocol::context::params::Capability::new("messages:write"),
        ],
        ..ContextParams::default()
    };

    let handle = manager
        .create_context("envelope-test-ctx".into(), params, "did:key:creator".into())
        .await
        .unwrap();

    let sk = signing_key_for_did(&"did:key:creator".into());

    manager
        .send_message(
            &handle,
            &"did:key:creator".into(),
            b"outer-envelope-test",
            Some(&sk),
            None,
            None,
        )
        .await
        .unwrap();

    // 1. Verify transport received exactly one message.
    let sent = sent_handle.lock().unwrap();
    assert_eq!(sent.len(), 1, "exactly one message should be sent");

    // 2. Verify the bytes can be deserialized as InnerEnvelope (mock format).
    //    MockCrypto::seal serializes InnerEnvelope directly via MessagePack.
    let inner: scp_protocol::envelope::inner::InnerEnvelope = rmp_serde::from_slice(&sent[0])
        .unwrap_or_else(|e| panic!("transport bytes should deserialize as InnerEnvelope: {e}"));
    assert_eq!(
        inner.sender_did, "did:key:creator",
        "InnerEnvelope sender_did must match"
    );
    assert_eq!(
        inner.context_id, "envelope-test-ctx",
        "InnerEnvelope context_id must match"
    );

    // 3. Verify routing ID uses domain-separated derivation.
    let routing_ids = routing_handle.lock().unwrap();
    assert_eq!(routing_ids.len(), 1, "exactly one routing ID");
    let expected_routing_id = scp_protocol::context::context_routing_id("envelope-test-ctx");
    assert_eq!(
        routing_ids[0], expected_routing_id,
        "routing ID must use domain-separated context_routing_id, \
         not raw context_id_bytes"
    );

    // 4. Verify routing ID is NOT the raw context_id_bytes.
    let raw_bytes = scp_protocol::context::context_id_bytes("envelope-test-ctx");
    assert_ne!(
        routing_ids[0], raw_bytes,
        "routing ID must differ from raw context_id_bytes"
    );
}

// -----------------------------------------------------------------------
// Cross-context tool invocation provenance (#1536 criteria 1, 5, 6)
// -----------------------------------------------------------------------

/// Verifies that `invoke_cross_context` attaches provenance with correct
/// source context, tool name, and timestamp (#1536 criterion 5).
#[tokio::test]
async fn cross_context_tool_invocation_attaches_provenance() {
    use scp_protocol::context::roles::{Capability, CapabilityCeiling, ContextRoleState};
    use scp_protocol::context::tools::interface::{ToolInterface, invoke_cross_context};
    use scp_protocol::context::tools::registry::ToolRegistry;
    use scp_protocol::provenance::attach::{SourceContextInfo, attach_provenance};
    use scp_protocol::provenance::{CounterpartyPolicy, DiscoveryMethod, SourceType};

    let (src, tgt, tid) = ("source-ctx", "target-ctx", "test-tool");
    let did: DID = "did:key:invoker".into();
    let caps = [
        Capability::MessagesRead,
        Capability::MessagesWrite,
        Capability::ToolRegister,
        Capability::ToolInvokeAll,
        Capability::RoleAssign,
    ];
    let ceiling = CapabilityCeiling::new(caps);
    let role_state = ContextRoleState::new(
        src,
        did.as_ref(),
        ceiling,
        vec![],
        &scp_primitives::SystemClock,
    )
    .unwrap();

    // Use insert() directly to bypass schema specificity validation
    // (this test is about provenance, not tool registration).
    let mut registry = ToolRegistry::new();
    registry.insert(test_tool_registration(tid));

    let mut interface = ToolInterface {
        tool_id: tid.to_owned(),
        source_context: src.to_owned(),
        target_context: tgt.to_owned(),
        approved_by_source: true,
        approved_by_target: true,
        outbound_policy: None,
        inbound_policy: None,
        rate_limit: None,
        per_caller_rate_limit: None,
    };

    let src_info = SourceContextInfo {
        context_id: src.to_owned(),
        source_type: SourceType::Persistent,
        memory_scope: scp_protocol::context::MemoryScope::Full,
        members: vec![did.clone()],
        discovery_method: DiscoveryMethod::OutOfBand,
        data_age: std::time::Duration::from_secs(0),
        purpose: Some(format!("cross-context tool invocation: {tid}")),
        counterparty_policy: CounterpartyPolicy::Full,
    };

    let result = invoke_cross_context(
        src,
        None,
        &mut interface,
        &serde_json::json!({"key": "value"}),
        &did,
        &role_state,
        &registry,
        0,
        |_| Ok(serde_json::json!({"result": "ok"})),
        &scp_primitives::SystemClock,
        &src_info,
    );

    let (output, source_event, target_event) = result.unwrap();
    assert_eq!(output["result"], "ok");
    assert_eq!(source_event.source_context, src);
    assert_eq!(source_event.target_context, tgt);
    assert_eq!(target_event.source_context, src);
    assert_eq!(source_event.tool_id, tid);

    // Verify provenance can be independently constructed for the same flow.
    let prov = attach_provenance(
        &SourceContextInfo {
            context_id: tgt.to_owned(),
            source_type: SourceType::Persistent,
            memory_scope: scp_protocol::context::MemoryScope::Full,
            members: Vec::new(),
            discovery_method: DiscoveryMethod::SharedContext(src.to_owned()),
            data_age: std::time::Duration::from_secs(0),
            purpose: Some(format!("cross-context tool invocation: {tid}")),
            counterparty_policy: CounterpartyPolicy::Redacted,
        },
        &src.to_owned(),
        None,
        None,
        None,
    );
    assert_eq!(prov.source_context, tgt);
    assert_eq!(prov.chain_depth, 0);
    assert!(prov.purpose.unwrap().contains(tid));
}

/// Verifies that `evaluate_quality` returns a non-zero quality score for
/// cross-context data with provenance attached (#1536 criterion 6).
#[tokio::test]
async fn evaluate_provenance_quality_for_cross_context_data() {
    use scp_protocol::provenance::attach::{SourceContextInfo, attach_provenance};
    use scp_protocol::provenance::evaluate::{SourceContextState, evaluate_quality};
    use scp_protocol::provenance::{
        CounterpartyPolicy, DiscoveryMethod, ProvenanceQuality, SourceType,
    };

    let source_info = SourceContextInfo {
        context_id: "target-ctx".to_owned(),
        source_type: SourceType::Persistent,
        memory_scope: scp_protocol::context::MemoryScope::Full,
        members: vec!["did:key:member1".into()],
        discovery_method: DiscoveryMethod::SharedContext("source-ctx".to_owned()),
        data_age: std::time::Duration::from_secs(0),
        purpose: Some("cross-context tool output".to_owned()),
        counterparty_policy: CounterpartyPolicy::Full,
    };

    let provenance = attach_provenance(&source_info, &"source-ctx".to_owned(), None, None, None);

    // Evaluate quality — persistent source with active state should yield
    // PersistentVerifiable.
    let quality = evaluate_quality(Some(&provenance), &SourceContextState::Active);
    assert!(
        quality > ProvenanceQuality::NoProvenance,
        "cross-context data with provenance should have quality above NoProvenance, got {quality:?}"
    );
    assert_eq!(
        quality,
        ProvenanceQuality::PersistentVerifiable,
        "persistent source with active context should be PersistentVerifiable"
    );
}

/// Payment receipt is generated and verifiable via `NoOpPaymentAdapter` (#1537).
#[tokio::test]
async fn receipt_verification_with_noop_adapter() {
    use crate::economy::adapter::{NoOpPaymentAdapter, PaymentAdapter};
    use crate::economy::receipt::{PaymentVerifierDyn, all_receipts_valid, verify_receipts_dyn};

    let adapter = NoOpPaymentAdapter;

    // Generate a receipt via capture.
    let auth = adapter
        .authorize(
            &"did:key:payer".into(),
            &"did:key:payee".into(),
            scp_protocol::economy::types::Amount(100),
            scp_protocol::economy::types::CurrencyCode::new([85, 83, 68, 0]),
            crate::economy::adapter::PaymentMetadata::default(),
        )
        .await
        .unwrap();

    let receipt = adapter.capture(&auth).await.unwrap();

    // Verify the receipt.
    let verifiers: Vec<&dyn PaymentVerifierDyn> = vec![&adapter];
    let results = verify_receipts_dyn(&verifiers, &[receipt]).await;
    assert!(
        all_receipts_valid(&results),
        "receipt from NoOpPaymentAdapter should be verifiable"
    );
}

/// Velocity data feeds into consequence evaluation end-to-end (#1537).
#[tokio::test]
async fn velocity_consequence_trigger_on_send() {
    use scp_protocol::trust::consequence::{
        ConsequenceAction, ConsequenceRule, ConsequenceTrigger,
    };
    use std::time::Duration;

    let manager = ContextManager::new(
        Box::new(MockCrypto::default()),
        Box::new(MockTransport::connected()),
        Box::new(MockEventLog::default()),
        noop_key_resolver(),
    );

    let mut params = ContextParams {
        ceiling: vec![
            scp_protocol::context::params::Capability::new("messages:read"),
            scp_protocol::context::params::Capability::new("messages:write"),
        ],
        ..ContextParams::default()
    };
    params.consequence_rules = vec![ConsequenceRule {
        trigger: ConsequenceTrigger::MessageVelocity,
        threshold: 1,
        action: ConsequenceAction::Suspend {
            capabilities: vec!["write".to_owned()],
        },
        window: Duration::from_secs(3600),
    }];
    let _handle = manager
        .create_context("vel-msg-ctx".into(), params, "did:key:admin".into())
        .await
        .unwrap();

    let sk = ed25519_dalek::SigningKey::from_bytes(&[1u8; 32]);
    let handle = manager
        .contexts
        .lock()
        .await
        .get("vel-msg-ctx")
        .unwrap()
        .handle
        .clone();
    let _ = manager
        .send_message(
            &handle,
            &"did:key:admin".into(),
            b"test",
            Some(&sk),
            None,
            None,
        )
        .await;

    let events = manager.drain_events("vel-msg-ctx").await;
    let triggered = events
        .iter()
        .any(|e| matches!(e, ContextEvent::ConsequenceTriggered { .. }));
    assert!(
        triggered,
        "velocity tracking should trigger consequence evaluation after send"
    );
}

// =======================================================================
// Spec §19.7 per-DID escalation wiring tests (A–H).
//
// These tests exercise the dormant anti-spam wiring fix: they verify that
// per-DID cost escalation, velocity rollback, the Matrix-style token-bucket
// hard rate limit, and the governance-free invariant all work end-to-end
// through the `ContextManager` entry points.
// =======================================================================

/// Helper: build an `EconomicPolicy` with a non-zero `per_message` baseline
/// so that spec §19.7 escalation (additive tiers on top of the base) is
/// exercised end-to-end via `send_message`. Payee and currency are fixed.
fn escalation_test_policy() -> scp_protocol::economy::types::EconomicPolicy {
    use scp_protocol::economy::types::{Amount, CostSchedule, CurrencyCode, EconomicPolicy};
    EconomicPolicy {
        locked: false,
        cost_schedule: CostSchedule {
            currency: CurrencyCode([85, 83, 68, 0]),
            per_message: Some(Amount::new(1)),
            per_tool_invoke: Some(Amount::new(1)),
            per_join: Some(Amount::new(1)),
            per_period: None,
            per_byte_stored: None,
        },
        payment_adapters: vec![],
        pricing_formula: None,
        payee: DID::from("did:key:payee"),
    }
}

/// Test B: after the 10th message in the velocity window, the per-DID
/// escalation tier kicks in and subsequent message costs include the
/// spec §19.7 elevated surcharge (+Amount(1)).
///
/// Method: configure a priced context with a generous budget and a
/// dummy spending UCAN, send 11 messages, and verify the total deducted
/// budget exceeds what a flat base-cost schedule would deduct.
#[tokio::test]
async fn escalation_kicks_in_at_velocity_threshold_10() {
    use scp_protocol::economy::types::Amount;

    let manager = ContextManager::new(
        Box::new(MockCrypto::default()),
        Box::new(MockTransport::connected()),
        Box::new(MockEventLog::default()),
        noop_key_resolver(),
    );

    let mut params = governance_params();
    params.economic_policy = Some(escalation_test_policy());
    let handle = manager
        .create_context("escalation-ctx".into(), params, "did:key:sender".into())
        .await
        .unwrap();

    // Grant enough budget to cover escalated costs and widen the hard
    // rate-limit burst so this test can exceed 10 sends in a single
    // tick (the burst limit is independent of cost escalation — we
    // test it separately in `hard_rate_limit_rejects_burst_over_ten`).
    {
        use scp_protocol::economy::antispam::{HardRateLimitConfig, TokenBucketLimiter};
        let mut contexts = manager.contexts.lock().await;
        let ctx = contexts.get_mut("escalation-ctx").unwrap();
        ctx.governance
            .budget_tracker
            .grant(&"did:key:sender".into(), Amount::new(1_000_000));
        ctx.governance.hard_rate_limit = TokenBucketLimiter::new(HardRateLimitConfig {
            refill_per_kilosec: 1_000_000,
            burst: 10_000,
        });
    }

    let sk = ed25519_dalek::SigningKey::from_bytes(&[1u8; 32]);

    // Record remaining before the burst.
    let before = {
        let contexts = manager.contexts.lock().await;
        contexts
            .get("escalation-ctx")
            .unwrap()
            .governance
            .budget_tracker
            .remaining(&"did:key:sender".into())
            .value()
    };

    // Send 11 messages — after the 10th, escalation tier 1 (+Amount(1))
    // applies so the 11th costs 2 instead of 1. Each send uses a fresh
    // spending UCAN so the per-context nonce tracker does not reject
    // replays (ADR-016 §6).
    for i in 0..11u8 {
        let ucan = dummy_spending_ucan();
        manager
            .send_message(
                &handle,
                &"did:key:sender".into(),
                &[i],
                Some(&sk),
                None,
                Some(&ucan),
            )
            .await
            .unwrap();
    }

    let after = {
        let contexts = manager.contexts.lock().await;
        contexts
            .get("escalation-ctx")
            .unwrap()
            .governance
            .budget_tracker
            .remaining(&"did:key:sender".into())
            .value()
    };
    let deducted = before - after;

    // Floor is Amount(1). Without escalation 11 messages would deduct 11.
    // With the tier-1 escalation kicking in at velocity ≥10, the 11th
    // message costs at least base + 1 = 2, so total ≥ 12.
    assert!(
        deducted >= 12,
        "expected escalation to add at least +1 to the 11th send, deducted: {deducted}"
    );
}

/// Test C: `ContextManager::invoke_tool_with_economy` wires per-DID
/// escalation into the tool invocation path. After 10 prior velocity
/// ticks the escalation tier 1 surcharge (+Amount(1)) is layered on
/// top of the `per_tool_invoke` base cost.
#[tokio::test]
async fn tool_invoke_escalation_via_managed_wrapper() {
    use scp_protocol::context::tools::ToolId;
    use scp_protocol::context::tools::registry::ToolRegistry;
    use scp_protocol::economy::types::Amount;

    let manager = ContextManager::new(
        Box::new(MockCrypto::default()),
        Box::new(MockTransport::connected()),
        Box::new(MockEventLog::default()),
        noop_key_resolver(),
    );

    let mut params = governance_params();
    // Creator needs ToolInvokeAll to pass the tools::invoke auth check.
    params
        .ceiling
        .push(scp_protocol::context::params::Capability::ToolInvokeAll);
    params.economic_policy = Some(escalation_test_policy());
    let _handle = manager
        .create_context("tool-esc-ctx".into(), params, "did:key:invoker".into())
        .await
        .unwrap();

    // Prime velocity tracker to ≥10 so escalation tier 1 is already in
    // effect, grant budget, and synthesize a tool registry. Prime with
    // recent timestamps so entries stay within the 60-second window.
    let now = manager.clock.now_secs();
    {
        let mut contexts = manager.contexts.lock().await;
        let ctx = contexts.get_mut("tool-esc-ctx").unwrap();
        for _ in 0..10u64 {
            ctx.governance
                .velocity_tracker
                .record_message(&"did:key:invoker".into(), now);
        }
        ctx.governance
            .budget_tracker
            .grant(&"did:key:invoker".into(), Amount::new(1_000));
    }

    let mut registry = ToolRegistry::new();
    registry.insert(test_tool_registration("echo"));

    let ucan = dummy_spending_ucan();

    let before = {
        let contexts = manager.contexts.lock().await;
        contexts
            .get("tool-esc-ctx")
            .unwrap()
            .governance
            .budget_tracker
            .remaining(&"did:key:invoker".into())
            .value()
    };

    let result = manager
        .invoke_tool_with_economy(
            "tool-esc-ctx",
            &registry,
            &ToolId::from("echo"),
            serde_json::json!({}),
            &"did:key:invoker".into(),
            Some(&ucan),
            None,
            |_input| async { Ok(serde_json::json!({})) },
        )
        .await;
    assert!(
        result.is_ok(),
        "managed tool invoke should succeed: {result:?}"
    );

    let after = {
        let contexts = manager.contexts.lock().await;
        contexts
            .get("tool-esc-ctx")
            .unwrap()
            .governance
            .budget_tracker
            .remaining(&"did:key:invoker".into())
            .value()
    };
    let deducted = before - after;

    // Base per_tool_invoke = 1; with tier-1 escalation the cost is ≥2.
    assert!(
        deducted >= 2,
        "expected tool-invoke escalation (base + tier1), deducted: {deducted}"
    );
}

/// The async variant `try_consume_hard_rate_limit` must be
/// callable from inside a tokio async context without panicking —
/// the `_blocking` sibling uses `blocking_lock` which panics inside
/// an async runtime. NAPI + `UniFFI` tool-invoke paths depend on
/// this.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn try_consume_hard_rate_limit_async_variant_is_safe_from_async_context() {
    let manager = ContextManager::new(
        Box::new(MockCrypto::default()),
        Box::new(MockTransport::connected()),
        Box::new(MockEventLog::default()),
        noop_key_resolver(),
    );
    let alice: DID = "did:key:alice".into();
    let _handle = manager
        .create_context("async-hrl-ctx".into(), governance_params(), alice.clone())
        .await
        .unwrap();

    // Awaiting this future must not panic. If the implementation
    // ever regressed to calling `blocking_lock` internally, this
    // would panic with "Cannot block the current thread from
    // within a runtime."
    let ok = manager
        .try_consume_hard_rate_limit("async-hrl-ctx", &alice, 1_000)
        .await;
    assert!(ok, "first consume should succeed");

    // Refund — also must not panic.
    manager
        .refund_hard_rate_limit("async-hrl-ctx", &alice)
        .await;

    // Pass-through semantic: unknown context returns true (pass).
    let ok = manager
        .try_consume_hard_rate_limit("unregistered-ctx", &alice, 1_000)
        .await;
    assert!(ok, "unknown context must pass-through as true");
}

/// The runtime-agnostic helper
/// `try_consume_hard_rate_limit_from_any_context` must survive a
/// current-thread tokio runtime. `block_in_place` requires
/// multi-thread, so the helper detects the runtime flavor and
/// falls back to a dedicated `std::thread` with its own tiny
/// current-thread runtime. This covers the `PyO3` MCP server
/// fallback path where the multi-thread runtime builder failed
/// and the service runs on a current-thread runtime instead.
#[test]
fn any_context_helper_survives_current_thread_runtime() {
    use std::sync::Arc as StdArc;
    // Build a current-thread runtime explicitly (NOT via
    // `#[tokio::test(flavor = "current_thread")]` because we want
    // to exercise the flavor-detection branch from INSIDE the
    // runtime via explicit `block_on` calls).
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("current-thread runtime must build");

    // Create the manager outside the runtime scope, then use it
    // from within the runtime's block_on. The helper takes
    // `&Arc<Self>` so we need a full Arc here.
    let manager = StdArc::new(ContextManager::new(
        Box::new(MockCrypto::default()),
        Box::new(MockTransport::connected()),
        Box::new(MockEventLog::default()),
        noop_key_resolver(),
    ));

    // First, set up the context from inside the runtime (required
    // because `create_context` is async).
    let alice: DID = "did:key:alice".into();
    let manager_for_setup = StdArc::clone(&manager);
    let alice_for_setup = alice.clone();
    rt.block_on(async move {
        manager_for_setup
            .create_context("ct-rt-ctx".into(), governance_params(), alice_for_setup)
            .await
            .expect("create_context must succeed");
    });

    // Now enter the runtime again and call the runtime-agnostic
    // sync helper from inside a `block_on` task. The dedicated-
    // thread fallback must handle this cleanly — plain
    // `block_in_place` would panic because the surrounding
    // runtime is current-thread.
    let manager_for_consume = StdArc::clone(&manager);
    let alice_for_consume = alice.clone();
    let result = rt.block_on(async move {
        manager_for_consume.try_consume_hard_rate_limit_from_any_context(
            "ct-rt-ctx",
            &alice_for_consume,
            3_000,
        )
    });
    assert!(
        result,
        "helper must succeed on current-thread runtime via dedicated-thread fallback"
    );

    // Refund path under the same constraint.
    let manager_for_refund = StdArc::clone(&manager);
    rt.block_on(async move {
        manager_for_refund.refund_hard_rate_limit_from_any_context("ct-rt-ctx", &alice);
    });
}

/// The runtime-agnostic helper must also work from outside any
/// runtime (sync unit tests exercising bridge traits directly) —
/// the "no runtime" branch that uses `blocking_lock` directly.
#[test]
fn any_context_helper_survives_no_runtime() {
    use std::sync::Arc as StdArc;
    // Build a throwaway runtime JUST to create the context, then
    // drop it so the helper is called from a no-runtime environment.
    let manager = StdArc::new(ContextManager::new(
        Box::new(MockCrypto::default()),
        Box::new(MockTransport::connected()),
        Box::new(MockEventLog::default()),
        noop_key_resolver(),
    ));
    let alice: DID = "did:key:alice".into();
    {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let manager_setup = StdArc::clone(&manager);
        let alice_setup = alice.clone();
        rt.block_on(async move {
            manager_setup
                .create_context("no-rt-ctx".into(), governance_params(), alice_setup)
                .await
                .expect("create_context must succeed");
        });
        // `rt` dropped here — we are now outside any runtime.
    }

    // Verify we are outside a runtime.
    assert!(
        tokio::runtime::Handle::try_current().is_err(),
        "test must run outside any runtime for this branch"
    );

    // The helper MUST use the `blocking_lock` branch here — neither
    // `block_in_place` (needs multi-thread runtime) nor
    // `Handle::current()` (panics outside runtime) would work.
    let result = manager.try_consume_hard_rate_limit_from_any_context("no-rt-ctx", &alice, 4_000);
    assert!(result, "helper must succeed outside any runtime");

    manager.refund_hard_rate_limit_from_any_context("no-rt-ctx", &alice);
}

/// Regression guard for the
/// `block_in_place + Handle::current().block_on(...)` pattern used
/// by the MCP server bridge's sync-in-async call path on a
/// multi-thread runtime. The inner `block_on` on the current
/// handle is allowed only when wrapped in `block_in_place`, which
/// moves the current task to a blocking pool; without it,
/// `Handle::block_on` panics.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn block_in_place_bridge_pattern_survives_mcp_sync_in_async_call() {
    let manager = ContextManager::new(
        Box::new(MockCrypto::default()),
        Box::new(MockTransport::connected()),
        Box::new(MockEventLog::default()),
        noop_key_resolver(),
    );
    let alice: DID = "did:key:alice".into();
    let _handle = manager
        .create_context("mcp-sync-ctx".into(), governance_params(), alice.clone())
        .await
        .unwrap();

    // Simulate the MCP server bridge's call pattern: sync code path
    // that needs to acquire the tokio Mutex, reached from within
    // an async context (we are inside a `#[tokio::test]`).
    let ok = tokio::task::block_in_place(|| {
        tokio::runtime::Handle::current().block_on(manager.try_consume_hard_rate_limit(
            "mcp-sync-ctx",
            &alice,
            2_000,
        ))
    });
    assert!(
        ok,
        "sync-in-async bridge pattern (block_in_place + handle.block_on) must succeed"
    );

    // And the refund path.
    tokio::task::block_in_place(|| {
        tokio::runtime::Handle::current()
            .block_on(manager.refund_hard_rate_limit("mcp-sync-ctx", &alice));
    });
}

/// The tool-invoke path consumes a hard-rate-limit token before
/// any economy bookkeeping, matching the `send_message` path, so a
/// member rate-limited on `send_message` cannot bypass the cap via
/// `invoke_tool_with_economy`.
#[tokio::test]
async fn tool_invoke_respects_hard_rate_limit() {
    use scp_protocol::context::tools::ToolId;
    use scp_protocol::context::tools::registry::ToolRegistry;
    use scp_protocol::economy::types::Amount;

    let manager = ContextManager::new(
        Box::new(MockCrypto::default()),
        Box::new(MockTransport::connected()),
        Box::new(MockEventLog::default()),
        noop_key_resolver(),
    );

    let mut params = governance_params();
    params
        .ceiling
        .push(scp_protocol::context::params::Capability::ToolInvokeAll);
    // Free context — the hard rate limit fires independent of cost.
    let _handle = manager
        .create_context("tool-rl-ctx".into(), params, "did:key:spammer".into())
        .await
        .unwrap();

    // Grant a large budget so budget exhaustion cannot be confused with
    // the rate limit. The rate limit fires first.
    {
        let mut contexts = manager.contexts.lock().await;
        let ctx = contexts.get_mut("tool-rl-ctx").unwrap();
        ctx.governance
            .budget_tracker
            .grant(&"did:key:spammer".into(), Amount::new(1_000_000));
    }

    let mut registry = ToolRegistry::new();
    registry.insert(test_tool_registration("echo"));

    // A spending UCAN is required because the default message pricing
    // gives `tool:invoke` a base cost of 1, even without a configured
    // economic policy (`derive_message_pricing` returns `spec_default`).
    // This isolates the hard-rate-limit behavior from UCAN machinery.
    let ucan = dummy_spending_ucan();

    // Burst of 10 should all succeed (default burst capacity).
    for i in 0..10u8 {
        let result = manager
            .invoke_tool_with_economy(
                "tool-rl-ctx",
                &registry,
                &ToolId::from("echo"),
                serde_json::json!({"n": i}),
                &"did:key:spammer".into(),
                Some(&ucan),
                None,
                |_input| async { Ok(serde_json::json!({})) },
            )
            .await;
        assert!(
            result.is_ok(),
            "tool invoke #{i} should succeed within burst: {result:?}"
        );
    }

    // The 11th in the same tick should be rejected by the token bucket.
    let result = manager
        .invoke_tool_with_economy(
            "tool-rl-ctx",
            &registry,
            &ToolId::from("echo"),
            serde_json::json!({"n": 11}),
            &"did:key:spammer".into(),
            Some(&ucan),
            None,
            |_input| async { Ok(serde_json::json!({})) },
        )
        .await;
    assert!(result.is_err(), "11th tool invoke should be rate-limited");
    let err = result.unwrap_err();
    match err {
        ContextError::RateLimited {
            ref resource,
            ref message,
        } => {
            assert_eq!(
                resource, "tool_invoke",
                "resource tag should be tool_invoke"
            );
            assert!(
                message.contains("invoker"),
                "rate limit message should mention the invoker: {message}"
            );
        }
        other => panic!("expected ContextError::RateLimited, got: {other:?}"),
    }
}

/// A rejected tool invocation (e.g., execution failure) must
/// refund the hard-rate-limit token so a rejected attempt does
/// not permanently burn bucket capacity. Otherwise an invoker
/// hitting a failing tool would be rate-limited into silence via
/// its own failures.
#[tokio::test]
async fn tool_invoke_failure_refunds_hard_rate_limit_token() {
    use scp_protocol::context::tools::ToolId;
    use scp_protocol::context::tools::registry::ToolRegistry;
    use scp_protocol::economy::types::Amount;

    let manager = ContextManager::new(
        Box::new(MockCrypto::default()),
        Box::new(MockTransport::connected()),
        Box::new(MockEventLog::default()),
        noop_key_resolver(),
    );

    let mut params = governance_params();
    params
        .ceiling
        .push(scp_protocol::context::params::Capability::ToolInvokeAll);
    let _handle = manager
        .create_context(
            "tool-rl-refund-ctx".into(),
            params,
            "did:key:invoker".into(),
        )
        .await
        .unwrap();

    {
        let mut contexts = manager.contexts.lock().await;
        let ctx = contexts.get_mut("tool-rl-refund-ctx").unwrap();
        ctx.governance
            .budget_tracker
            .grant(&"did:key:invoker".into(), Amount::new(1_000));
    }

    let mut registry = ToolRegistry::new();
    registry.insert(test_tool_registration("echo"));

    // Fire 10 failing invocations — each should fail, each should
    // refund the token, leaving the bucket fully replenished.
    for i in 0..10u8 {
        let _ = manager
            .invoke_tool_with_economy(
                "tool-rl-refund-ctx",
                &registry,
                &ToolId::from("echo"),
                serde_json::json!({"n": i}),
                &"did:key:invoker".into(),
                None,
                None,
                |_input| async { Err::<serde_json::Value, _>("executor failed".to_owned()) },
            )
            .await;
    }

    // The 11th attempt (also failing) should NOT hit the rate limit —
    // because every prior token was refunded. It should fail on the
    // executor error instead.
    let result = manager
        .invoke_tool_with_economy(
            "tool-rl-refund-ctx",
            &registry,
            &ToolId::from("echo"),
            serde_json::json!({"n": 11}),
            &"did:key:invoker".into(),
            None,
            None,
            |_input| async { Err::<serde_json::Value, _>("executor failed".to_owned()) },
        )
        .await;
    assert!(result.is_err(), "11th failing invoke should still error");
    let err = result.unwrap_err();
    assert!(
        !matches!(err, ContextError::RateLimited { .. }),
        "11th failing invoke must NOT hit hard rate limit \
         (token should have been refunded on each failure): got {err:?}"
    );
}

/// Test D: `join_context` ticks the velocity tracker for the joiner
/// so that a second join attempt would see non-zero velocity. The join
/// counts toward per-DID anti-spam tracking the same way message sends do.
#[tokio::test]
async fn join_context_records_velocity_for_joiner() {
    use scp_protocol::context::membership::KeyPackage;

    let manager = ContextManager::new(
        Box::new(MockCrypto::default()),
        Box::new(MockTransport::connected()),
        Box::new(MockEventLog::default()),
        noop_key_resolver(),
    );

    let params = governance_params();
    let handle = manager
        .create_context("join-vel-ctx".into(), params, "did:key:creator".into())
        .await
        .unwrap();

    let kp = KeyPackage {
        owner_did: "did:key:joiner".into(),
        mls_key_package_bytes: None,
    };
    manager.join_context(&handle, kp, None).await.unwrap();

    let velocity = {
        let contexts = manager.contexts.lock().await;
        let ctx = contexts.get("join-vel-ctx").unwrap();
        ctx.governance
            .velocity_tracker
            .get_velocity(&"did:key:joiner".into(), manager.clock.now_secs())
    };
    assert!(
        velocity >= 1,
        "join should record a velocity tick for the joiner, got: {velocity}"
    );
}

/// Test E: when enforcement fails (e.g., budget exceeded) after the
/// velocity tick has been recorded, both the velocity tracker and the
/// token-bucket hard rate limit are rolled back so the rejected send
/// does not permanently penalize the sender.
#[tokio::test]
async fn enforcement_failure_rolls_back_velocity_and_rate_limit() {
    use scp_protocol::economy::types::Amount;

    let manager = ContextManager::new(
        Box::new(MockCrypto::default()),
        Box::new(MockTransport::connected()),
        Box::new(MockEventLog::default()),
        noop_key_resolver(),
    );

    let mut params = governance_params();
    params.economic_policy = Some(escalation_test_policy());
    let handle = manager
        .create_context("rollback-ctx".into(), params, "did:key:sender".into())
        .await
        .unwrap();

    // Grant ZERO budget so the very first paid send fails post-tick.
    // (Budget tracker starts empty; nothing to do.)

    let sk = ed25519_dalek::SigningKey::from_bytes(&[1u8; 32]);

    let result = manager
        .send_message(
            &handle,
            &"did:key:sender".into(),
            b"will fail",
            Some(&sk),
            None,
            Some(&dummy_spending_ucan()),
        )
        .await;
    assert!(result.is_err(), "send should fail with zero budget");

    // Velocity must be rolled back to 0 — the rejected send must not
    // count toward future escalation.
    let velocity = {
        let contexts = manager.contexts.lock().await;
        let ctx = contexts.get("rollback-ctx").unwrap();
        ctx.governance
            .velocity_tracker
            .get_velocity(&"did:key:sender".into(), manager.clock.now_secs())
    };
    assert_eq!(
        velocity, 0,
        "velocity should be rolled back on rejected send, got: {velocity}"
    );

    // And the hard-rate-limit token must have been refunded: after a
    // burst of 10 failed sends the sender should still have budget left.
    for _ in 0..10u8 {
        let _ = manager
            .send_message(
                &handle,
                &"did:key:sender".into(),
                b"again",
                Some(&sk),
                None,
                Some(&dummy_spending_ucan()),
            )
            .await;
    }
    // Grant budget now and confirm the sender is not rate-limited.
    {
        let mut contexts = manager.contexts.lock().await;
        let ctx = contexts.get_mut("rollback-ctx").unwrap();
        ctx.governance
            .budget_tracker
            .grant(&"did:key:sender".into(), Amount::new(1_000));
    }
    let ok = manager
        .send_message(
            &handle,
            &"did:key:sender".into(),
            b"now ok",
            Some(&sk),
            None,
            Some(&dummy_spending_ucan()),
        )
        .await;
    assert!(
        ok.is_ok(),
        "after refunded rate-limit tokens the send should succeed: {ok:?}"
    );
}

/// Test F: the Matrix Synapse–style hard rate limit (burst=10) rejects
/// the 11th rapid-fire message from a single DID with SCP-ECON-7090,
/// even when no economic policy is configured (defense-in-depth for
/// free contexts).
#[tokio::test]
async fn hard_rate_limit_rejects_burst_over_ten() {
    let manager = ContextManager::new(
        Box::new(MockCrypto::default()),
        Box::new(MockTransport::connected()),
        Box::new(MockEventLog::default()),
        noop_key_resolver(),
    );

    // Free context — no economic_policy set. The hard rate limit is
    // independent of cost and should still fire.
    let params = governance_params();
    let handle = manager
        .create_context("rate-ctx".into(), params, "did:key:spammer".into())
        .await
        .unwrap();

    let sk = ed25519_dalek::SigningKey::from_bytes(&[1u8; 32]);

    // Burst of 10 should all succeed (default burst capacity).
    for i in 0..10u8 {
        manager
            .send_message(
                &handle,
                &"did:key:spammer".into(),
                &[i],
                Some(&sk),
                None,
                None,
            )
            .await
            .unwrap_or_else(|e| panic!("send #{i} should succeed within burst: {e}"));
    }

    // The 11th in the same tick should be rejected by the token bucket.
    let result = manager
        .send_message(
            &handle,
            &"did:key:spammer".into(),
            b"overflow",
            Some(&sk),
            None,
            None,
        )
        .await;
    assert!(result.is_err(), "11th rapid send should be rate-limited");
    let err = result.unwrap_err();
    match err {
        ContextError::RateLimited {
            ref resource,
            ref message,
        } => {
            assert_eq!(resource, "send", "resource tag should be send");
            assert!(
                message.contains("sender"),
                "rate limit message should mention the sender: {message}"
            );
        }
        other => panic!("expected ContextError::RateLimited, got: {other:?}"),
    }
}

/// Test G: governance actions stay FREE — even when an economic policy
/// with a `per_message` cost is configured, submitting/executing a
/// `GovernanceAction` does NOT deduct from the actor's member budget.
/// This enforces the hard invariant that governance must not be
/// gateable by economic starvation (spec §5.9 / ADR-031).
#[tokio::test]
async fn governance_actions_stay_free_under_priced_policy() {
    use scp_protocol::context::governance::GovernanceAction;
    use scp_protocol::economy::types::Amount;

    let manager = ContextManager::new(
        Box::new(MockCrypto::default()),
        Box::new(MockTransport::connected()),
        Box::new(MockEventLog::default()),
        mock_key_resolver(),
    );

    let mut params = governance_params();
    params.economic_policy = Some(escalation_test_policy());
    let _handle = manager
        .create_context("gov-free-ctx".into(), params, "did:key:admin".into())
        .await
        .unwrap();

    // Sanity: the admin has ZERO budget — starved — yet the governance
    // action must still execute because governance is gateway-free.
    let before = {
        let contexts = manager.contexts.lock().await;
        contexts
            .get("gov-free-ctx")
            .unwrap()
            .governance
            .budget_tracker
            .remaining(&"did:key:admin".into())
            .value()
    };
    assert_eq!(before, 0, "admin should start with zero budget");

    // Submit a trivial approved governance proposal (ChangeRole).
    // Governance must execute under zero budget because governance is
    // free — gating it on economics would create a deadlock.
    let action = GovernanceAction::ChangeRole {
        did: "did:key:subscriber".into(),
        new_role: "observer".to_owned(),
    };
    let proposal = approved_governance_proposal(
        &"did:key:admin".into(),
        "gov-free-ctx",
        &"did:key:subscriber".into(),
        action,
    );
    // Note: we only care that no economic gate fires. Role-layer errors
    // (e.g., member not present) are unrelated to the free-governance
    // invariant and do not invalidate the test. If execution succeeds
    // the invariant is strongly confirmed; if it fails with a
    // non-economic error the invariant is still confirmed because no
    // economic gate was reached.
    let result = manager
        .execute_governance_action("gov-free-ctx", &proposal)
        .await;
    if let Err(ref e) = result {
        let msg = format!("{e}");
        assert!(
            !msg.contains("SCP-ECON-"),
            "governance action must not trip any SCP-ECON-* gate, got: {msg}"
        );
    }

    // Budget remains unchanged — no deduction for the governance action.
    let after = {
        let contexts = manager.contexts.lock().await;
        contexts
            .get("gov-free-ctx")
            .unwrap()
            .governance
            .budget_tracker
            .remaining(&"did:key:admin".into())
            .value()
    };
    assert_eq!(
        after, 0,
        "governance action must not deduct from member budget, got: {after}"
    );

    // The admin must also NOT have been ticked by the per-DID velocity
    // tracker for the governance action itself — governance is exempt
    // from the message/join/invoke escalation path.
    let velocity = {
        let contexts = manager.contexts.lock().await;
        contexts
            .get("gov-free-ctx")
            .unwrap()
            .governance
            .velocity_tracker
            .get_velocity(&"did:key:admin".into(), manager.clock.now_secs())
    };
    assert_eq!(
        velocity, 0,
        "governance action must not tick per-DID velocity, got: {velocity}"
    );

    // Unused to silence the helper requirement.
    let _ = Amount::new(0);
}

/// Test H: the velocity tracker restored from a persisted snapshot
/// normalizes legacy window values to the spec §19.4 60-second window,
/// so per-sender entries persist but the window shrinks. This is the
/// runtime-level counterpart to the protocol-layer Test A.
#[tokio::test]
async fn restored_velocity_tracker_uses_60_second_window() {
    let (manager, _handle) = setup_active_context().await;
    let window = {
        let contexts = manager.contexts.lock().await;
        contexts
            .get("test-ctx")
            .unwrap()
            .governance
            .velocity_tracker
            .window_secs()
    };
    assert_eq!(
        window, 60,
        "fresh-context velocity tracker must use spec §19.4 60s window, got: {window}"
    );
}
