use super::*;

// ===================================================================
// CAC-009: full block/unblock lifecycle across context types
// ===================================================================

#[tokio::test]
async fn cac009_tier1_encrypted_block_unblock() {
    let manager = ContextManager::new(
        Box::new(MockCrypto::default()),
        Box::new(MockTransport::connected()),
        Box::new(MockEventLog::default()),
        noop_key_resolver(),
    );
    manager.register_local_did("did:key:alice".into()).await;
    let params = ContextParams {
        mode: ContextMode::Encrypted,
        memory_scope: MemoryScope::Full,
        ceiling: vec![
            Capability::MessagesRead,
            Capability::MessagesWrite,
            Capability::RoleAssign,
            Capability::MemberBan,
        ],
        ..ContextParams::default()
    };
    let _handle = manager
        .create_context("cac009-enc".into(), params, "did:key:alice".into(), None)
        .await
        .unwrap();
    for did in &["did:key:dave", "did:key:bob"] {
        let arc = manager.get_context_arc("cac009-enc").unwrap();
        let mut g = arc.lock().await;
        let ctx = &mut *g;
        ctx.membership
            .add_member((*did).to_owned().into(), "member".into(), vec![]);
    }
    let revoke = approved_governance_proposal(
        &"did:key:alice".into(),
        "cac009-enc",
        &"did:key:dave".into(),
        GovernanceAction::RevokeAccess {
            did: "did:key:dave".into(),
            access: super::AccessScope::Read,
        },
    );
    let result = manager
        .execute_governance_action("cac009-enc", &revoke)
        .await;
    assert!(result.is_ok(), "Revoke (read) should succeed: {result:?}");
    {
        let arc = manager.get_context_arc("cac009-enc").unwrap();
        let g = arc.lock().await;
        let ctx = &*g;
        assert!(
            ctx.access
                .read_exclusion_list
                .contains(&DID("did:key:dave".into())),
            "Dave should be read-revoked"
        );
        assert!(
            ctx.membership.contains("did:key:dave"),
            "Dave should remain a member"
        );
    }
    let events = manager.drain_events("cac009-enc").await;
    assert!(
        events.iter().any(
            |e| matches!(e, ContextEvent::ReadAccessRevoked { did } if did.0 == "did:key:dave")
        )
    );
    let restore = approved_governance_proposal(
        &"did:key:alice".into(),
        "cac009-enc",
        &"did:key:dave".into(),
        GovernanceAction::RestoreAccess {
            did: "did:key:dave".into(),
            capabilities: vec![super::Capability::MessagesRead],
        },
    );
    let result = manager
        .execute_governance_action("cac009-enc", &restore)
        .await;
    assert!(
        result.is_ok(),
        "RestoreAccess (read) should succeed: {result:?}"
    );
    {
        let arc = manager.get_context_arc("cac009-enc").unwrap();
        let g = arc.lock().await;
        let ctx = &*g;
        assert!(
            !ctx.access
                .read_exclusion_list
                .contains(&DID("did:key:dave".into()))
        );
    }
    let events = manager.drain_events("cac009-enc").await;
    assert!(
        events.iter().any(
            |e| matches!(e, ContextEvent::ReadAccessRestored { did } if did.0 == "did:key:dave")
        )
    );
}

#[tokio::test]
async fn cac009_tier2_global_block_multiple_contexts() {
    let manager = ContextManager::new(
        Box::new(MockCrypto::default()),
        Box::new(MockTransport::connected()),
        Box::new(MockEventLog::default()),
        noop_key_resolver(),
    );
    manager.register_local_did("did:key:alice".into()).await;
    let make_params = || ContextParams {
        mode: ContextMode::Encrypted,
        memory_scope: MemoryScope::Full,
        ceiling: vec![
            Capability::MessagesRead,
            Capability::MessagesWrite,
            Capability::RoleAssign,
            Capability::MemberBan,
        ],
        ..ContextParams::default()
    };
    let _h1 = manager
        .create_context(
            "cac009-g1".into(),
            make_params(),
            "did:key:alice".into(),
            None,
        )
        .await
        .unwrap();
    let _h2 = manager
        .create_context(
            "cac009-g2".into(),
            make_params(),
            "did:key:alice".into(),
            None,
        )
        .await
        .unwrap();
    for ctx_id in &["cac009-g1", "cac009-g2"] {
        let arc = manager.get_context_arc(ctx_id).unwrap();
        let mut ctx = arc.lock().await;
        ctx.membership
            .add_member("did:key:eve".into(), "member".into(), vec![]);
    }
    for ctx_id in &["cac009-g1", "cac009-g2"] {
        let revoke = approved_governance_proposal(
            &"did:key:alice".into(),
            ctx_id,
            &"did:key:eve".into(),
            GovernanceAction::RevokeAccess {
                did: "did:key:eve".into(),
                access: super::AccessScope::Read,
            },
        );
        manager
            .execute_governance_action(ctx_id, &revoke)
            .await
            .unwrap();
    }
    for ctx_id in &["cac009-g1", "cac009-g2"] {
        let arc = manager.get_context_arc(ctx_id).unwrap();
        let ctx = arc.lock().await;
        assert!(
            ctx.access
                .read_exclusion_list
                .contains(&DID("did:key:eve".into())),
            "Eve read-revoked in {ctx_id}"
        );
    }
    for ctx_id in &["cac009-g1", "cac009-g2"] {
        let restore = approved_governance_proposal(
            &"did:key:alice".into(),
            ctx_id,
            &"did:key:eve".into(),
            GovernanceAction::RestoreAccess {
                did: "did:key:eve".into(),
                capabilities: vec![super::Capability::MessagesRead],
            },
        );
        manager
            .execute_governance_action(ctx_id, &restore)
            .await
            .unwrap();
    }
    for ctx_id in &["cac009-g1", "cac009-g2"] {
        let arc = manager.get_context_arc(ctx_id).unwrap();
        let ctx = arc.lock().await;
        assert!(
            !ctx.access
                .read_exclusion_list
                .contains(&DID("did:key:eve".into())),
            "Eve restored in {ctx_id}"
        );
    }
}

#[tokio::test]
async fn cac009_broadcast_governance_revoke_restore() {
    let (manager, _handle, ctx_id) = setup_broadcast_context_two_authors().await;
    {
        let arc = manager.get_context_arc(&ctx_id).unwrap();
        let ctx = arc.lock().await;
        assert!(
            ctx.broadcast_context
                .as_ref()
                .unwrap()
                .is_author("did:key:bob")
        );
    }
    let revoke = approved_governance_proposal(
        &"did:key:alice".into(),
        &ctx_id,
        &"did:key:bob".into(),
        GovernanceAction::RevokeAccess {
            did: "did:key:bob".into(),
            access: super::AccessScope::Both,
        },
    );
    manager
        .execute_governance_action(&ctx_id, &revoke)
        .await
        .unwrap();
    let (bob_custody, bob_key_handle) = test_custody_from_seed(&[0xBB; 32]).await;
    assert!(
        manager
            .publish_broadcast(
                &ctx_id,
                &"did:key:bob".into(),
                b"blocked",
                &bob_custody,
                &bob_key_handle,
            )
            .await
            .is_err(),
        "revoked author should not publish"
    );
    {
        use scp_protocol::crypto::ucan::validate::{
            InMemoryDidResolver, InMemoryNonceTracker, InMemoryProofResolver,
            InMemoryRevocationChecker,
        };
        use std::hash::RandomState;
        manager.subscribe_broadcast::<InMemoryDidResolver, InMemoryNonceTracker, InMemoryRevocationChecker, InMemoryProofResolver, RandomState>(&ctx_id, &"did:key:sub1".into(), None, 1000, None).await.unwrap();
        let decision = manager
            .handle_broadcast_key_request(&ctx_id, &"did:key:bob".into(), &"did:key:sub1".into())
            .await
            .unwrap();
        assert!(
            matches!(decision, super::KeyRequestDecision::Deny { .. }),
            "key request denied"
        );
    }
    let restore = approved_governance_proposal(
        &"did:key:alice".into(),
        &ctx_id,
        &"did:key:bob".into(),
        GovernanceAction::RestoreAccess {
            did: "did:key:bob".into(),
            capabilities: vec![super::Capability::MessagesWrite],
        },
    );
    manager
        .execute_governance_action(&ctx_id, &restore)
        .await
        .unwrap();
    // After Full revocation + restore, the author entry was removed from the
    // BroadcastContext. Forward-only restoration clears the revocation flag
    // but does NOT re-create the author entry — bob must re-register.
    {
        let arc = manager.get_context_arc(&ctx_id).unwrap();
        let ctx = arc.lock().await;
        let bc = ctx.broadcast_context.as_ref().unwrap();
        assert!(
            !bc.is_author("did:key:bob"),
            "full revocation removes author; restore does not re-add"
        );
    }
}

#[tokio::test]
#[allow(clippy::too_many_lines)] // DashMap lock pattern adds verbosity
async fn cac009_tier_stacking_both_must_reverse() {
    let (manager, ctx_id) = setup_encrypted_with_member_ban().await;
    let revoke_w = approved_governance_proposal(
        &"did:key:alice".into(),
        &ctx_id,
        &"did:key:bob".into(),
        GovernanceAction::RevokeAccess {
            did: "did:key:bob".into(),
            access: super::AccessScope::Write,
        },
    );
    manager
        .execute_governance_action(&ctx_id, &revoke_w)
        .await
        .unwrap();
    let revoke_r = approved_governance_proposal(
        &"did:key:alice".into(),
        &ctx_id,
        &"did:key:bob".into(),
        GovernanceAction::RevokeAccess {
            did: "did:key:bob".into(),
            access: super::AccessScope::Read,
        },
    );
    manager
        .execute_governance_action(&ctx_id, &revoke_r)
        .await
        .unwrap();
    {
        let arc = manager.get_context_arc(&ctx_id).unwrap();
        let g = arc.lock().await;
        let ctx = &*g;
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
    let restore_w = approved_governance_proposal(
        &"did:key:alice".into(),
        &ctx_id,
        &"did:key:bob".into(),
        GovernanceAction::RestoreAccess {
            did: "did:key:bob".into(),
            capabilities: vec![super::Capability::MessagesWrite],
        },
    );
    manager
        .execute_governance_action(&ctx_id, &restore_w)
        .await
        .unwrap();
    {
        let arc = manager.get_context_arc(&ctx_id).unwrap();
        let g = arc.lock().await;
        let ctx = &*g;
        assert!(
            !ctx.role_state
                .suspended_capabilities
                .get("did:key:bob")
                .is_some_and(|s| s.contains(&Capability::MessagesWrite)),
            "write restored"
        );
        assert!(
            ctx.access
                .read_exclusion_list
                .contains(&DID("did:key:bob".into())),
            "read still revoked"
        );
    }
    let restore_r = approved_governance_proposal(
        &"did:key:alice".into(),
        &ctx_id,
        &"did:key:bob".into(),
        GovernanceAction::RestoreAccess {
            did: "did:key:bob".into(),
            capabilities: vec![super::Capability::MessagesRead],
        },
    );
    manager
        .execute_governance_action(&ctx_id, &restore_r)
        .await
        .unwrap();
    {
        let arc = manager.get_context_arc(&ctx_id).unwrap();
        let g = arc.lock().await;
        let ctx = &*g;
        assert!(
            !ctx.role_state
                .suspended_capabilities
                .get("did:key:bob")
                .is_some_and(|s| s.contains(&Capability::MessagesWrite))
        );
        assert!(
            !ctx.access
                .read_exclusion_list
                .contains(&DID("did:key:bob".into()))
        );
    }
}

#[tokio::test]
async fn cac009_layer_verification() {
    let (manager, _handle, ctx_id) = setup_broadcast_context_two_authors().await;
    {
        use scp_protocol::crypto::ucan::validate::{
            InMemoryDidResolver, InMemoryNonceTracker, InMemoryProofResolver,
            InMemoryRevocationChecker,
        };
        use std::hash::RandomState;
        manager.subscribe_broadcast::<InMemoryDidResolver, InMemoryNonceTracker, InMemoryRevocationChecker, InMemoryProofResolver, RandomState>(&ctx_id, &"did:key:sub1".into(), None, 1000, None).await.unwrap();
    }
    let revoke = approved_governance_proposal(
        &"did:key:alice".into(),
        &ctx_id,
        &"did:key:bob".into(),
        GovernanceAction::RevokeAccess {
            did: "did:key:bob".into(),
            access: super::AccessScope::Both,
        },
    );
    manager
        .execute_governance_action(&ctx_id, &revoke)
        .await
        .unwrap();
    {
        let arc = manager.get_context_arc(&ctx_id).unwrap();
        let g = arc.lock().await;
        let ctx = &*g;
        assert!(
            ctx.role_state
                .suspended_capabilities
                .get("did:key:bob")
                .is_some_and(|s| s.contains(&Capability::MessagesWrite)),
            "Layer 3"
        );
    }
    let decision = manager
        .handle_broadcast_key_request(&ctx_id, &"did:key:bob".into(), &"did:key:sub1".into())
        .await
        .unwrap();
    assert!(
        matches!(decision, super::KeyRequestDecision::Deny { .. }),
        "Layer 1"
    );
}

#[tokio::test]
async fn cac009_forward_only_verification() {
    let (manager, _handle, ctx_id) = setup_broadcast_context_two_authors().await;
    let _epoch_before = {
        let arc = manager.get_context_arc(&ctx_id).unwrap();
        let ctx_guard = arc.lock().await;
        ctx_guard
            .broadcast_context
            .as_ref()
            .unwrap()
            .get_author("did:key:bob")
            .unwrap()
            .epoch
    };
    let revoke = approved_governance_proposal(
        &"did:key:alice".into(),
        &ctx_id,
        &"did:key:bob".into(),
        GovernanceAction::RevokeAccess {
            did: "did:key:bob".into(),
            access: super::AccessScope::Both,
        },
    );
    manager
        .execute_governance_action(&ctx_id, &revoke)
        .await
        .unwrap();
    {
        let arc = manager.get_context_arc(&ctx_id).unwrap();
        let ctx = arc.lock().await;
        assert!(
            !ctx.broadcast_context
                .as_ref()
                .unwrap()
                .is_author("did:key:bob")
        );
    }
    let restore = approved_governance_proposal(
        &"did:key:alice".into(),
        &ctx_id,
        &"did:key:bob".into(),
        GovernanceAction::RestoreAccess {
            did: "did:key:bob".into(),
            capabilities: vec![super::Capability::MessagesWrite],
        },
    );
    manager
        .execute_governance_action(&ctx_id, &restore)
        .await
        .unwrap();
    // After Full revocation + restore, the author entry was removed.
    // Forward-only restoration clears the revocation flag but does NOT
    // re-create the author — bob must re-register as an author.
    let author_gone = {
        let arc = manager.get_context_arc(&ctx_id).unwrap();
        let ctx_guard = arc.lock().await;
        ctx_guard
            .broadcast_context
            .as_ref()
            .unwrap()
            .get_author("did:key:bob")
            .is_none()
    };
    assert!(
        author_gone,
        "full revocation removes author; restore does not re-add"
    );
}

// ===================================================================
// CAC-010: governance-gated content access control
// ===================================================================

#[tokio::test]
async fn cac010_threshold_revoke_read_access() {
    let creator: DID = "did:key:alice".into();
    let manager = ContextManager::new(
        Box::new(MockCrypto::default()),
        Box::new(MockTransport::connected()),
        Box::new(MockEventLog::default()),
        mock_key_resolver(),
    );
    let mut params = governance_params();
    params.mode = ContextMode::Broadcast;
    params.memory_scope = MemoryScope::Full;
    params.governance = GovernanceModel::Threshold {
        threshold: 1,
        signers: vec![creator.clone()],
    };
    let _handle = manager
        .create_context("cac010-thresh".into(), params, creator.clone(), None)
        .await
        .unwrap();
    {
        use scp_protocol::crypto::ucan::validate::{
            InMemoryDidResolver, InMemoryNonceTracker, InMemoryProofResolver,
            InMemoryRevocationChecker,
        };
        use std::hash::RandomState;
        manager.subscribe_broadcast::<InMemoryDidResolver, InMemoryNonceTracker, InMemoryRevocationChecker, InMemoryProofResolver, RandomState>("cac010-thresh", &"did:key:dave".into(), None, 1000, None).await.unwrap();
    }
    let signing_key = signing_key_for_did(&creator);
    let outcome = manager
        .propose_governance_action_checked(
            "cac010-thresh",
            &creator,
            GovernanceAction::RevokeAccess {
                did: "did:key:dave".into(),
                access: super::AccessScope::Read,
            },
            &signing_key,
        )
        .await
        .unwrap();
    assert_eq!(
        outcome.status,
        super::ProposalStatus::Approved,
        "1-of-1 threshold auto-approve"
    );
    assert!(
        outcome.execution_result.is_some(),
        "auto-approved should have execution_result"
    );
    assert!(
        !manager
            .is_broadcast_subscriber("cac010-thresh", "did:key:dave")
            .await,
        "dave unsubscribed"
    );
}

#[tokio::test]
async fn cac010_restore_read_access_forward_only() {
    let (manager, ctx_id) = setup_broadcast_with_member_ban().await;
    let revoke = approved_governance_proposal(
        &"did:key:alice".into(),
        &ctx_id,
        &"did:key:sub1".into(),
        GovernanceAction::RevokeAccess {
            did: "did:key:sub1".into(),
            access: super::AccessScope::Read,
        },
    );
    manager
        .execute_governance_action(&ctx_id, &revoke)
        .await
        .unwrap();
    assert!(
        !manager
            .is_broadcast_subscriber(&ctx_id, "did:key:sub1")
            .await
    );
    let restore = approved_governance_proposal(
        &"did:key:alice".into(),
        &ctx_id,
        &"did:key:sub1".into(),
        GovernanceAction::RestoreAccess {
            did: "did:key:sub1".into(),
            capabilities: vec![super::Capability::MessagesRead],
        },
    );
    manager
        .execute_governance_action(&ctx_id, &restore)
        .await
        .unwrap();
    let events = manager.drain_events(&ctx_id).await;
    assert!(
        events.iter().any(
            |e| matches!(e, ContextEvent::ReadAccessRestored { did } if did.0 == "did:key:sub1")
        )
    );
}

#[tokio::test]
async fn cac010_revoke_write_full_can_still_read() {
    let (manager, ctx_id) = setup_encrypted_with_member_ban().await;
    let revoke = approved_governance_proposal(
        &"did:key:alice".into(),
        &ctx_id,
        &"did:key:bob".into(),
        GovernanceAction::RevokeAccess {
            did: "did:key:bob".into(),
            access: super::AccessScope::Write,
        },
    );
    manager
        .execute_governance_action(&ctx_id, &revoke)
        .await
        .unwrap();
    {
        let arc = manager.get_context_arc(&ctx_id).unwrap();
        let g = arc.lock().await;
        let ctx = &*g;
        assert!(
            ctx.role_state
                .suspended_capabilities
                .get("did:key:bob")
                .is_some_and(|s| s.contains(&Capability::MessagesWrite)),
            "write-suspended"
        );
        assert!(
            !ctx.access
                .read_exclusion_list
                .contains(&DID("did:key:bob".into())),
            "NOT read-revoked"
        );
    }
}

#[tokio::test]
async fn cac010_revoke_write_future_only() {
    let (manager, _handle, ctx_id) = setup_broadcast_context_two_authors().await;
    let revoke = approved_governance_proposal(
        &"did:key:alice".into(),
        &ctx_id,
        &"did:key:bob".into(),
        GovernanceAction::RevokeAccess {
            did: "did:key:bob".into(),
            access: super::AccessScope::Write,
        },
    );
    manager
        .execute_governance_action(&ctx_id, &revoke)
        .await
        .unwrap();
    let (bob_custody, bob_key_handle) = test_custody_from_seed(&[0xBB; 32]).await;
    assert!(
        manager
            .publish_broadcast(
                &ctx_id,
                &"did:key:bob".into(),
                b"nope",
                &bob_custody,
                &bob_key_handle,
            )
            .await
            .is_err()
    );
    {
        // Per spec §05-contexts §5.9, revocation removes publishing
        // authority. In broadcast mode the BroadcastContext author entry
        // is removed; historical messages remain decryptable by
        // subscribers via cached broadcast keys (forward-only restoration
        // applies if access is later restored).
        let arc = manager.get_context_arc(&ctx_id).unwrap();
        let ctx = arc.lock().await;
        assert!(
            !ctx.broadcast_context
                .as_ref()
                .unwrap()
                .is_author("did:key:bob"),
            "AccessScope::Write removes author from BroadcastContext"
        );
    }
}

#[tokio::test]
async fn cac010_rotate_content_keys_context_wide() {
    let (manager, ctx_id) = setup_encrypted_with_member_ban().await;
    let rotate = approved_governance_proposal(
        &"did:key:alice".into(),
        &ctx_id,
        &"did:key:bob".into(),
        GovernanceAction::RotateContentKeys {
            reason: Some("periodic".into()),
        },
    );
    let result = manager.execute_governance_action(&ctx_id, &rotate).await;
    assert!(
        result.is_ok(),
        "RotateContentKeys should succeed: {result:?}"
    );
    match result.unwrap() {
        GovernanceActionResult::ContentKeysRotated(r) => {
            assert_eq!(r.reason.as_deref(), Some("periodic"));
        }
        other => panic!("expected ContentKeysRotated, got {other:?}"),
    }
    let events = manager.drain_events(&ctx_id).await;
    assert!(
        events
            .iter()
            .any(|e| matches!(e, ContextEvent::ContentKeysRotated { .. }))
    );
}

#[tokio::test]
async fn cac010_membership_access_decoupling() {
    let (manager, ctx_id) = setup_broadcast_with_member_ban().await;
    let revoke = approved_governance_proposal(
        &"did:key:alice".into(),
        &ctx_id,
        &"did:key:sub1".into(),
        GovernanceAction::RevokeAccess {
            did: "did:key:sub1".into(),
            access: super::AccessScope::Read,
        },
    );
    manager
        .execute_governance_action(&ctx_id, &revoke)
        .await
        .unwrap();
    assert!(
        !manager
            .is_broadcast_subscriber(&ctx_id, "did:key:sub1")
            .await,
        "unsubscribed"
    );
    assert!(
        manager.is_member(&ctx_id, "did:key:sub1").await,
        "still a member"
    );
}

#[tokio::test]
async fn cac010_single_admin_auto_execute() {
    let (manager, ctx_id) = setup_broadcast_with_member_ban().await;
    let revoke = approved_governance_proposal(
        &"did:key:alice".into(),
        &ctx_id,
        &"did:key:sub1".into(),
        GovernanceAction::RevokeAccess {
            did: "did:key:sub1".into(),
            access: super::AccessScope::Read,
        },
    );
    let result = manager.execute_governance_action(&ctx_id, &revoke).await;
    assert!(result.is_ok());
    match result.unwrap() {
        GovernanceActionResult::AccessRevoked(r) => {
            assert_eq!(r.did.0, "did:key:sub1");
        }
        other => panic!("expected AccessRevoked, got {other:?}"),
    }
}

// -----------------------------------------------------------------------
// recovery_advance_epoch tests (#1250, #1248)
// -----------------------------------------------------------------------

#[tokio::test]
#[allow(
    clippy::disallowed_types,
    reason = "Test scaffolding for `std::sync::Mutex`-based test harnesses; migrated to `tokio::sync::Mutex` in commit 11 of ADR-049 (actor refactor), where all 8 submodule handlers complete their migration. See plan §Commit ladder."
)]
async fn test_recovery_advance_epoch_calls_crypto_provider() {
    let shared_epochs: Arc<std::sync::Mutex<Vec<[u8; 32]>>> = Arc::default();
    let crypto = MockCrypto {
        epochs_advanced_shared: Arc::clone(&shared_epochs),
        ..MockCrypto::default()
    };

    let manager = ContextManager::new(
        Box::new(crypto),
        Box::new(MockTransport::connected()),
        Box::new(MockEventLog::default()),
        noop_key_resolver(),
    );

    let _handle = manager
        .create_context(
            "recovery-epoch-1".into(),
            ContextParams::default(),
            "did:key:creator".into(),
            None,
        )
        .await
        .unwrap();

    let expected_bytes = context_id_to_bytes("recovery-epoch-1");

    let new_epoch = manager
        .recovery_advance_epoch("recovery-epoch-1")
        .await
        .unwrap();

    assert_eq!(new_epoch, 1, "epoch should advance from 0 to 1");

    // Verify the crypto provider was actually called with the correct id.
    {
        let calls = shared_epochs.lock().unwrap();
        assert_eq!(calls.len(), 1, "crypto provider should be called once");
        assert_eq!(
            calls[0], expected_bytes,
            "crypto provider should receive the context id bytes"
        );
    }

    // A second advance should yield epoch 2, confirming the counter
    // increments correctly and the crypto provider is called each time.
    let epoch2 = manager
        .recovery_advance_epoch("recovery-epoch-1")
        .await
        .unwrap();
    assert_eq!(epoch2, 2, "second advance should yield epoch 2");

    // Verify two total crypto calls after the second advance.
    {
        let calls = shared_epochs.lock().unwrap();
        assert_eq!(calls.len(), 2, "crypto provider should be called twice");
    }
}

#[tokio::test]
async fn test_recovery_advance_epoch_rollback_on_crypto_failure() {
    let crypto = MockCrypto::default();
    crypto.fail_advance_epoch.store(true, Ordering::Relaxed);

    let manager = ContextManager::new(
        Box::new(crypto),
        Box::new(MockTransport::connected()),
        Box::new(MockEventLog::default()),
        noop_key_resolver(),
    );

    let _handle = manager
        .create_context(
            "recovery-fail-1".into(),
            ContextParams::default(),
            "did:key:creator".into(),
            None,
        )
        .await
        .unwrap();

    let result = manager.recovery_advance_epoch("recovery-fail-1").await;

    assert!(result.is_err(), "should fail when crypto fails");
    assert!(
        matches!(result.unwrap_err(), ContextError::CryptoFailed(_)),
        "should return CryptoFailed variant"
    );

    // Epoch counter must NOT have been incremented.
    let arc = manager
        .contexts
        .get("recovery-fail-1")
        .unwrap()
        .value()
        .clone();
    let g = arc.lock().await;
    let ctx = &*g;
    assert_eq!(
        ctx.epoch.mls_epoch, 0,
        "epoch counter must not increment on crypto failure"
    );
}

#[tokio::test]
async fn test_recovery_advance_epoch_rejects_inactive_context() {
    let manager = ContextManager::new(
        Box::new(MockCrypto::default()),
        Box::new(MockTransport::connected()),
        Box::new(MockEventLog::default()),
        noop_key_resolver(),
    );

    let handle = manager
        .create_context(
            "recovery-inactive-1".into(),
            ContextParams::default(),
            "did:key:creator".into(),
            None,
        )
        .await
        .unwrap();

    // Transition to Closing — no longer Active.
    handle.transition_to(&ContextState::Closing).await.unwrap();

    let result = manager.recovery_advance_epoch("recovery-inactive-1").await;

    assert!(result.is_err(), "should fail for non-active context");
    assert!(
        matches!(result.unwrap_err(), ContextError::ContextNotActive),
        "should return ContextNotActive"
    );

    // Verify epoch was not advanced.
    let arc = manager
        .contexts
        .get("recovery-inactive-1")
        .unwrap()
        .value()
        .clone();
    let g = arc.lock().await;
    let ctx = &*g;
    assert_eq!(
        ctx.epoch.mls_epoch, 0,
        "epoch must not change for inactive context"
    );
}
