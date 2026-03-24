use super::*;

// -----------------------------------------------------------------------
// Send message tests
// -----------------------------------------------------------------------

/// Unit test: `send_message` rejects when context is not Active.
#[tokio::test]
async fn send_message_rejects_when_context_not_active() {
    let (manager, handle) = setup_active_context().await;

    handle.transition_to(&ContextState::Closing).await.unwrap();

    let result = manager
        .send_message(&handle, &"did:key:creator".into(), b"hello", None)
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
        .send_message(&handle, &"did:key:nonexistent".into(), b"hello", None)
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

    let result = manager
        .send_message(&handle, &"did:key:creator".into(), b"hello world", None)
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

    for i in 1..=5u8 {
        manager
            .send_message(&handle, &"did:key:creator".into(), &[i], None)
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

    // send_message should fail because FailingTransport.send_message
    // returns an error.
    let result = manager
        .send_message(&handle, &"did:key:creator".into(), b"hello", None)
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

    // Verify sequence number was NOT burned: a subsequent successful send
    // on a working transport should get sequence 1, not 2.
    // We can't retry with a different transport on the same manager, but
    // we CAN verify the internal state via the membership sequence counter.
    // The membership sequence should still be 0 (never incremented).
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
/// receive buffer with the correct sequence number. Validates the positive
/// path after the #1420 restructure and Phase 3 sequence assignment.
#[tokio::test]
async fn send_message_transport_success_emits_event() {
    let (manager, handle) = setup_active_context().await;

    let result = manager
        .send_message(&handle, &"did:key:creator".into(), b"positive-path", None)
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

/// Helper: build a manager whose `MockCrypto` supports `decrypt_message`,
/// returning `(plaintext_passthrough, sender_did)`.
async fn setup_active_context_with_decrypt(sender_did: &str) -> (ContextManager, ContextHandle) {
    let crypto = MockCrypto {
        decrypt_sender_did: Some(sender_did.to_owned()),
        ..MockCrypto::default()
    };

    let manager = ContextManager::new(
        Box::new(crypto),
        Box::new(MockTransport::connected()),
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
        .create_context("test-ctx".into(), params, "did:key:creator".into())
        .await
        .unwrap();

    (manager, handle)
}

#[tokio::test]
async fn deliver_incoming_success_for_member() {
    let (manager, _handle) = setup_active_context_with_decrypt("did:key:creator").await;

    let result = manager
        .deliver_incoming("test-ctx", b"encrypted-payload")
        .await;
    assert!(result.is_ok());

    let (plaintext, sender) = result
        .unwrap()
        .expect("expected Some for application message");
    assert_eq!(plaintext, b"encrypted-payload");
    assert_eq!(sender, "did:key:creator");

    // Verify MessageReceived event was emitted.
    let events = manager.drain_events("test-ctx").await;
    let recv_events: Vec<_> = events
        .iter()
        .filter(|e| matches!(e, ContextEvent::MessageReceived { .. }))
        .collect();
    assert_eq!(recv_events.len(), 1);
}

#[tokio::test]
async fn deliver_incoming_rejects_non_member_sender() {
    // Crypto mock claims "did:key:intruder" sent the message, but that
    // DID is not a member of the context.
    let (manager, _handle) = setup_active_context_with_decrypt("did:key:intruder").await;

    let result = manager.deliver_incoming("test-ctx", b"evil-payload").await;
    assert!(result.is_err());
    match result.unwrap_err() {
        ContextError::MemberNotFound(msg) => {
            assert!(
                msg.contains("did:key:intruder"),
                "error should mention the sender DID"
            );
        }
        other => panic!("expected MemberNotFound, got: {other:?}"),
    }

    // Verify no MessageReceived event was emitted.
    let events = manager.drain_events("test-ctx").await;
    assert!(
        events
            .iter()
            .all(|e| !matches!(e, ContextEvent::MessageReceived { .. })),
        "no MessageReceived event should be emitted for non-member sender"
    );
}

#[tokio::test]
async fn deliver_incoming_rejects_write_revoked_sender() {
    let (manager, _handle) = setup_active_context_with_decrypt("did:key:creator").await;

    // Revoke write access for the creator.
    {
        let mut contexts = manager.contexts.lock().await;
        let ctx = contexts.get_mut("test-ctx").unwrap();
        ctx.access
            .write_revoked_members
            .insert(DID("did:key:creator".to_owned()));
    }

    let result = manager
        .deliver_incoming("test-ctx", b"revoked-payload")
        .await;
    assert!(result.is_err());
    match result.unwrap_err() {
        ContextError::PermissionDenied(msg) => {
            assert!(msg.contains("revoked"), "error should mention revocation");
        }
        other => panic!("expected PermissionDenied, got: {other:?}"),
    }
}

#[tokio::test]
async fn deliver_incoming_rejects_sender_without_messages_write() {
    let (manager, _handle) = setup_active_context_with_decrypt("did:key:creator").await;

    // Remove messages:write capability from the creator.
    {
        let mut contexts = manager.contexts.lock().await;
        let ctx = contexts.get_mut("test-ctx").unwrap();
        if let Some(caps) = ctx
            .role_state
            .member_capabilities
            .get_mut("did:key:creator")
        {
            caps.remove(&Capability::MessagesWrite);
        }
    }

    let result = manager
        .deliver_incoming("test-ctx", b"no-write-cap-payload")
        .await;
    assert!(result.is_err());
    match result.unwrap_err() {
        ContextError::PermissionDenied(msg) => {
            assert!(
                msg.contains("messages:write"),
                "error should mention missing capability"
            );
        }
        other => panic!("expected PermissionDenied, got: {other:?}"),
    }
}

#[tokio::test]
async fn deliver_incoming_rejects_inactive_context() {
    let (manager, handle) = setup_active_context_with_decrypt("did:key:creator").await;

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
    let (manager, _handle) = setup_active_context_with_decrypt("did:key:creator").await;

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
