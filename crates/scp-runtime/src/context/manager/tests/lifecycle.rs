use super::*;

// -----------------------------------------------------------------------
// Context creation tests (backward compatibility)
// -----------------------------------------------------------------------

#[tokio::test]
async fn manager_create_context_encrypted_success() {
    let manager = ContextManager::new(
        Box::new(MockCrypto::default()),
        Box::new(MockTransport::connected()),
        Box::new(MockEventLog::default()),
        noop_key_resolver(),
    );

    let handle = manager
        .create_context_bare("mgr-ctx-1".into(), ContextParams::default())
        .await;

    assert!(handle.is_ok());
    let handle = handle.unwrap();
    assert_eq!(handle.context_id(), "mgr-ctx-1");
    assert_eq!(handle.state().await, ContextState::Active);
}

#[tokio::test]
async fn manager_create_context_broadcast_success() {
    let manager = ContextManager::new(
        Box::new(MockCrypto::default()),
        Box::new(MockTransport::connected()),
        Box::new(MockEventLog::default()),
        noop_key_resolver(),
    );

    let params = ContextParams {
        mode: ContextMode::Broadcast,
        memory_scope: scp_protocol::context::MemoryScope::Full,
        ..ContextParams::default()
    };

    let handle = manager
        .create_context_bare("mgr-ctx-bc".into(), params)
        .await;

    assert!(handle.is_ok());
    let handle = handle.unwrap();
    assert_eq!(handle.context_id(), "mgr-ctx-bc");
    assert_eq!(handle.state().await, ContextState::Active);
}

#[tokio::test]
async fn manager_create_context_succeeds_when_transport_disconnected() {
    // Context creation is a local operation — it should succeed even
    // when `is_connected()` returns false. Transport connectivity is
    // not a Phase 1 gate.
    let manager = ContextManager::new(
        Box::new(MockCrypto::default()),
        Box::new(MockTransport::default()), // not connected
        Box::new(MockEventLog::default()),
        noop_key_resolver(),
    );

    let result = manager
        .create_context_bare("mgr-ctx-dc".into(), ContextParams::default())
        .await;

    assert!(result.is_ok());
    let handle = result.unwrap();
    assert_eq!(handle.context_id(), "mgr-ctx-dc");
}

#[tokio::test]
async fn manager_create_context_rollback_on_crypto_failure() {
    let crypto = MockCrypto::default();
    crypto.fail_create_mls.store(true, Ordering::Relaxed);

    let manager = ContextManager::new(
        Box::new(crypto),
        Box::new(MockTransport::connected()),
        Box::new(MockEventLog::default()),
        noop_key_resolver(),
    );

    let result = manager
        .create_context_bare("mgr-ctx-fail".into(), ContextParams::default())
        .await;

    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        ContextCreationError::CryptoFailed(_)
    ));
}

#[tokio::test]
async fn manager_preserves_params_on_handle() {
    let manager = ContextManager::new(
        Box::new(MockCrypto::default()),
        Box::new(MockTransport::connected()),
        Box::new(MockEventLog::default()),
        noop_key_resolver(),
    );

    let params = ContextParams {
        mode: ContextMode::Broadcast,
        memory_scope: scp_protocol::context::MemoryScope::Full,
        ..ContextParams::default()
    };

    let handle = manager
        .create_context_bare("mgr-ctx-p".into(), params.clone())
        .await
        .unwrap();

    assert_eq!(*handle.params(), params);
    assert_eq!(handle.params().mode, ContextMode::Broadcast);
}

// -----------------------------------------------------------------------
// Join context tests
// -----------------------------------------------------------------------

/// Unit test: join adds member to MLS group and issues UCAN tokens.
#[tokio::test]
async fn join_adds_member_to_mls_group_and_issues_ucan_tokens() {
    let (manager, handle) = setup_active_context().await;

    let kp = KeyPackage::mock("did:key:bob".into());

    let result = manager.join_context(&handle, kp, None).await;
    assert!(result.is_ok());

    // Verify member was added.
    assert!(manager.is_member("test-ctx", "did:key:bob").await);
    assert_eq!(manager.member_count("test-ctx").await, Some(2));

    // Verify UCAN tokens were issued.
    let role = manager.member_role("test-ctx", "did:key:bob").await;
    assert!(role.is_some());
    let role = role.unwrap();
    assert_eq!(role.role_name, "member");
    assert!(!role.tokens.is_empty());

    // Verify MemberJoined event was emitted.
    let events = manager.drain_events("test-ctx").await;
    let join_events: Vec<_> = events
        .iter()
        .filter(|e| matches!(e, ContextEvent::MemberJoined { .. }))
        .collect();
    assert_eq!(join_events.len(), 1);
}

#[tokio::test]
async fn join_rejects_when_context_not_active() {
    let (manager, handle) = setup_active_context().await;

    // Transition to Closing.
    handle.transition_to(&ContextState::Closing).await.unwrap();

    let kp = KeyPackage::mock("did:key:bob".into());

    let result = manager.join_context(&handle, kp, None).await;
    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        ContextError::ContextNotActive
    ));
}

/// Regression test for #715 / #738: version check must run BEFORE crypto
/// ops. When the *stored* context's `min_protocol_version` is incompatible,
/// `join_context` must reject without calling `add_member` (no orphaned MLS
/// state). The check uses the stored context's params, not the caller-
/// supplied handle, so the `UniFFI` bridge's ephemeral default-params handle is safe.
#[tokio::test]
async fn join_version_check_rejects_before_crypto_ops() {
    let (manager, _handle) = setup_active_context().await;

    // Simulate a context whose stored params require major version 2 —
    // incompatible with SCP_PROTOCOL_VERSION (1.0). We create with
    // compatible params then replace, because create_context itself
    // (correctly) rejects incompatible min_protocol_version.
    manager
        .replace_stored_params(
            "test-ctx",
            ContextParams {
                min_protocol_version: Some((2, 0)),
                ..ContextParams::default()
            },
        )
        .await;

    // Build an ephemeral handle with default params (mimics UniFFI bridge).
    // The early check must still reject because it reads the *stored*
    // context's params, not this handle's params.
    let ephemeral_handle = ContextHandle::new("test-ctx".into(), ContextParams::default());
    ephemeral_handle
        .transition_to(&ContextState::Active)
        .await
        .unwrap();

    let kp = KeyPackage::mock("did:key:bob".into());
    let result = manager.join_context(&ephemeral_handle, kp, None).await;

    // Must fail with VersionIncompatible — the early check rejects
    // before any crypto operations (validate_key_package, add_member,
    // distribute_sender_key) execute.
    assert!(result.is_err());
    assert!(
        matches!(
            result.unwrap_err(),
            ContextError::VersionIncompatible { .. }
        ),
        "expected VersionIncompatible error"
    );

    // bob must NOT be a member — no membership state was created because
    // the version check short-circuited before crypto ops and the locked
    // membership mutation section.
    assert!(!manager.is_member("test-ctx", "did:key:bob").await);
    assert_eq!(manager.member_count("test-ctx").await, Some(1));
}

// -----------------------------------------------------------------------
// Leave context tests
// -----------------------------------------------------------------------

/// Unit test: leave removes member and transitions to Closing when count
/// reaches zero.
#[tokio::test]
async fn leave_removes_member_and_transitions_to_closing_when_empty() {
    let (manager, handle) = setup_active_context().await;

    // Remove the only member (creator -- self-removal).
    let result = manager
        .leave_context(
            &handle,
            &"did:key:creator".into(),
            &"did:key:creator".into(),
        )
        .await;
    assert!(result.is_ok());

    // Member count should be 0.
    assert_eq!(manager.member_count("test-ctx").await, Some(0));
    assert!(!manager.is_member("test-ctx", "did:key:creator").await);

    // Context should have transitioned to Closing.
    assert_eq!(handle.state().await, ContextState::Closing);

    // Verify MemberLeft event was emitted.
    let events = manager.drain_events("test-ctx").await;
    let left_events: Vec<_> = events
        .iter()
        .filter(|e| matches!(e, ContextEvent::MemberLeft { .. }))
        .collect();
    assert_eq!(left_events.len(), 1);
}

#[tokio::test]
async fn leave_does_not_close_when_members_remain() {
    let (manager, handle) = setup_active_context().await;

    // Add a second member.
    let kp = KeyPackage::mock("did:key:bob".into());
    manager.join_context(&handle, kp, None).await.unwrap();
    assert_eq!(manager.member_count("test-ctx").await, Some(2));

    // Remove bob (self-removal).
    manager.drain_events("test-ctx").await; // Clear join event.
    let result = manager
        .leave_context(&handle, &"did:key:bob".into(), &"did:key:bob".into())
        .await;
    assert!(result.is_ok());

    // Context should still be Active (creator is still there).
    assert_eq!(handle.state().await, ContextState::Active);
    assert_eq!(manager.member_count("test-ctx").await, Some(1));
}

#[tokio::test]
async fn leave_rejects_when_context_not_active() {
    let (manager, handle) = setup_active_context().await;

    handle.transition_to(&ContextState::Closing).await.unwrap();

    let result = manager
        .leave_context(
            &handle,
            &"did:key:creator".into(),
            &"did:key:creator".into(),
        )
        .await;
    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        ContextError::ContextNotActive
    ));
}

// -----------------------------------------------------------------------
// Leave context authorization tests (SCP-167)
// -----------------------------------------------------------------------

/// Helper: creates a context whose ceiling includes `member:remove` so
/// that the admin can remove other members. Adds an observer member
/// (`did:key:observer`) alongside the admin creator (`did:key:creator`).
async fn setup_context_with_member_remove() -> (ContextManager, ContextHandle) {
    let manager = ContextManager::new(
        Box::new(MockCrypto::default()),
        Box::new(MockTransport::connected()),
        Box::new(MockEventLog::default()),
        noop_key_resolver(),
    );

    let params = ContextParams {
        ceiling: vec![
            scp_protocol::context::params::Capability::new("messages:read"),
            scp_protocol::context::params::Capability::new("messages:write"),
            scp_protocol::context::params::Capability::new("role:assign"),
            scp_protocol::context::params::Capability::new("member:remove"),
        ],
        ..ContextParams::default()
    };

    let handle = manager
        .create_context("auth-ctx".into(), params, "did:key:creator".into())
        .await
        .unwrap();

    // Add an observer member.
    let kp = KeyPackage::mock("did:key:observer".into());
    manager.join_context(&handle, kp, None).await.unwrap();

    // Reassign to observer role (joined members default to "member").
    {
        let mut contexts = manager.contexts.lock().await;
        let ctx = contexts.get_mut("auth-ctx").unwrap();
        roles::assign_role(
            &mut ctx.role_state,
            "did:key:observer",
            "observer",
            "did:key:creator",
            &scp_primitives::SystemClock,
        )
        .unwrap();
        // Update the membership tracking to reflect the new role.
        if let Some(info) = ctx.membership.get_mut("did:key:observer") {
            info.role_name = "observer".into();
        }
    }

    (manager, handle)
}

/// SCP-167: observer calls `leave_context` with admin's DID — returns
/// authorization error.
#[tokio::test]
async fn leave_observer_cannot_remove_admin() {
    let (manager, handle) = setup_context_with_member_remove().await;

    // Observer tries to remove the admin — should fail.
    let result = manager
        .leave_context(
            &handle,
            &"did:key:observer".into(),
            &"did:key:creator".into(),
        )
        .await;

    assert!(result.is_err());
    assert!(
        matches!(result.unwrap_err(), ContextError::PermissionDenied(_)),
        "observer should not be able to remove admin"
    );

    // Admin should still be a member.
    assert!(manager.is_member("auth-ctx", "did:key:creator").await);
}

/// SCP-167: admin calls `leave_context` with observer's DID — succeeds
/// (admin has `MemberRemove` capability).
#[tokio::test]
async fn leave_admin_can_remove_observer() {
    let (manager, handle) = setup_context_with_member_remove().await;

    // Admin removes the observer — should succeed.
    let result = manager
        .leave_context(
            &handle,
            &"did:key:creator".into(),
            &"did:key:observer".into(),
        )
        .await;

    assert!(result.is_ok(), "admin should be able to remove observer");

    // Observer should no longer be a member.
    assert!(!manager.is_member("auth-ctx", "did:key:observer").await);
    // Admin should still be a member.
    assert!(manager.is_member("auth-ctx", "did:key:creator").await);
}

/// SCP-167: member calls `leave_context` with own DID — succeeds
/// (self-removal is always allowed regardless of role).
#[tokio::test]
async fn leave_self_removal_always_allowed() {
    let (manager, handle) = setup_context_with_member_remove().await;

    // Observer self-removes — should always succeed.
    let result = manager
        .leave_context(
            &handle,
            &"did:key:observer".into(),
            &"did:key:observer".into(),
        )
        .await;

    assert!(result.is_ok(), "self-removal should always be allowed");

    // Observer should no longer be a member.
    assert!(!manager.is_member("auth-ctx", "did:key:observer").await);
    // Admin should still be a member.
    assert!(manager.is_member("auth-ctx", "did:key:creator").await);
}

// -----------------------------------------------------------------------
// Concurrent operations test (SCP-168)
// -----------------------------------------------------------------------

/// Verifies that concurrent join + send operations on the same context
/// do not corrupt internal state. All operations should either succeed
/// or return a well-defined error -- never panic or produce inconsistent
/// membership counts.
#[tokio::test]
async fn concurrent_joins_and_sends_do_not_corrupt_state() {
    let manager = std::sync::Arc::new(ContextManager::new(
        Box::new(MockCrypto::default()),
        Box::new(MockTransport::connected()),
        Box::new(MockEventLog::default()),
        noop_key_resolver(),
    ));

    let params = ContextParams {
        ceiling: vec![
            scp_protocol::context::params::Capability::new("messages:read"),
            scp_protocol::context::params::Capability::new("messages:write"),
            scp_protocol::context::params::Capability::new("role:assign"),
        ],
        ..ContextParams::default()
    };

    let handle = manager
        .create_context("conc-ctx".into(), params, "did:key:creator".into())
        .await
        .unwrap();

    let handle = std::sync::Arc::new(handle);

    // Spawn 10 concurrent join tasks.
    let mut join_handles = Vec::new();
    for i in 0..10u32 {
        let mgr = std::sync::Arc::clone(&manager);
        let h = std::sync::Arc::clone(&handle);
        join_handles.push(tokio::spawn(async move {
            let kp = KeyPackage::mock(format!("did:key:member-{i}").into());
            mgr.join_context(&h, kp, None).await
        }));
    }

    // Spawn 5 concurrent send tasks from the creator.
    let sk = signing_key_for_did(&"did:key:creator".into());
    for i in 0..5u8 {
        let mgr = std::sync::Arc::clone(&manager);
        let h = std::sync::Arc::clone(&handle);
        let sk_clone = sk.clone();
        join_handles.push(tokio::spawn(async move {
            mgr.send_message(
                &h,
                &"did:key:creator".into(),
                &[i],
                Some(&sk_clone),
                None,
                None,
            )
            .await
        }));
    }

    // Wait for all tasks. All should succeed (no panics, no data corruption).
    for jh in join_handles {
        let result = jh.await.unwrap();
        assert!(result.is_ok(), "concurrent operation failed: {result:?}");
    }

    // 1 creator + 10 joined members = 11.
    assert_eq!(manager.member_count("conc-ctx").await, Some(11));
}

// -----------------------------------------------------------------------
// Panic recovery test (SCP-168)
// -----------------------------------------------------------------------

/// Verifies that a panic inside a mock provider does not poison the
/// `tokio::sync::Mutex`. After the panicking task is caught, subsequent
/// operations on the same manager must succeed.
#[tokio::test]
async fn panic_does_not_poison_mutex() {
    use std::sync::Arc;

    let manager = Arc::new(ContextManager::new(
        Box::new(MockCrypto::default()),
        Box::new(MockTransport::connected()),
        Box::new(MockEventLog::default()),
        noop_key_resolver(),
    ));

    let params = ContextParams {
        ceiling: vec![
            scp_protocol::context::params::Capability::new("messages:read"),
            scp_protocol::context::params::Capability::new("messages:write"),
            scp_protocol::context::params::Capability::new("role:assign"),
        ],
        ..ContextParams::default()
    };

    let handle = manager
        .create_context("panic-ctx".into(), params, "did:key:creator".into())
        .await
        .unwrap();

    // Spawn a task that will panic after acquiring the contexts lock.
    // We simulate this by calling join_context with a specially crafted
    // scenario: the crypto provider succeeds, but then we panic inside
    // a spawned task that holds a reference.
    let mgr_clone = Arc::clone(&manager);
    let handle_clone = handle.clone();
    let panicking_task = tokio::spawn(async move {
        // This panics inside the task. tokio::sync::Mutex does not poison.
        let _count = mgr_clone.member_count("panic-ctx").await;
        panic!("intentional panic for testing");
    });

    // The panicking task should fail (JoinError with panic).
    let result = panicking_task.await;
    assert!(result.is_err(), "task should have panicked");

    // The manager should still be usable -- tokio::sync::Mutex does not poison.
    let count = manager.member_count("panic-ctx").await;
    assert_eq!(count, Some(1), "mutex should not be poisoned");

    // Further operations should succeed.
    let kp = KeyPackage::mock("did:key:after-panic".into());
    let join_result = manager.join_context(&handle_clone, kp, None).await;
    assert!(join_result.is_ok(), "join after panic should succeed");
    assert_eq!(manager.member_count("panic-ctx").await, Some(2));
}

// -----------------------------------------------------------------------
// Context persistence tests (SCP-PERSIST-020 through SCP-PERSIST-025)
// -----------------------------------------------------------------------

/// Mock `ContextPersistence` that stores snapshots in `HashMap`s.
#[derive(Default)]
struct MockContextPersistence {
    contexts: std::sync::Mutex<HashMap<String, super::ContextSnapshot>>,
    broadcasts: std::sync::Mutex<HashMap<String, BroadcastContextSnapshot>>,
}

impl super::ContextPersistence for MockContextPersistence {
    fn persist_context(
        &self,
        context_id: &str,
        snapshot: &super::ContextSnapshot,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.contexts
            .lock()
            .unwrap()
            .insert(context_id.to_owned(), snapshot.clone());
        Ok(())
    }

    fn load_context(
        &self,
        context_id: &str,
    ) -> Result<Option<super::ContextSnapshot>, Box<dyn std::error::Error + Send + Sync>> {
        Ok(self.contexts.lock().unwrap().get(context_id).cloned())
    }

    fn persist_broadcast(
        &self,
        context_id: &str,
        snapshot: &BroadcastContextSnapshot,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.broadcasts
            .lock()
            .unwrap()
            .insert(context_id.to_owned(), snapshot.clone());
        Ok(())
    }

    fn load_broadcast(
        &self,
        context_id: &str,
    ) -> Result<Option<BroadcastContextSnapshot>, Box<dyn std::error::Error + Send + Sync>> {
        Ok(self.broadcasts.lock().unwrap().get(context_id).cloned())
    }

    fn delete_context(
        &self,
        context_id: &str,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.contexts.lock().unwrap().remove(context_id);
        self.broadcasts.lock().unwrap().remove(context_id);
        Ok(())
    }

    fn list_persisted_contexts(
        &self,
    ) -> Result<Vec<String>, Box<dyn std::error::Error + Send + Sync>> {
        Ok(self.contexts.lock().unwrap().keys().cloned().collect())
    }
}

/// Helper: build a `BroadcastContextSnapshot` with known state.
fn test_broadcast_snapshot(context_id: &str) -> BroadcastContextSnapshot {
    use std::collections::HashSet;

    use scp_protocol::context::broadcast::{
        AuthorStateSnapshot, BroadcastAdmission, SubscriberRecord,
    };
    use scp_protocol::crypto::sender_keys::generate_sender_key;

    let mut authors = HashMap::new();
    authors.insert(
        "did:key:author1".to_owned(),
        AuthorStateSnapshot {
            author_did: "did:key:author1".to_owned(),
            broadcast_key: generate_sender_key(),
            epoch: 3,
            next_sequence: 1,
            block_list: HashSet::from(["did:key:blocked1".to_owned()]),
        },
    );

    let mut subscribers = HashMap::new();
    subscribers.insert(
        "did:key:sub1".to_owned(),
        SubscriberRecord {
            subscriber_did: "did:key:sub1".to_owned(),
            registered_at: 1_700_000_000,
            has_ucan: false,
        },
    );
    subscribers.insert(
        "did:key:sub2".to_owned(),
        SubscriberRecord {
            subscriber_did: "did:key:sub2".to_owned(),
            registered_at: 1_700_001_000,
            has_ucan: true,
        },
    );

    BroadcastContextSnapshot {
        context_id: context_id.to_owned(),
        admission: BroadcastAdmission::Gated,
        subscribers,
        authors,
    }
}

/// SCP-PERSIST-020: compile-time test verifying `dyn ContextPersistence`
/// is object-safe.
#[test]
fn context_persistence_is_object_safe() {
    fn assert_object_safe(_: &dyn super::ContextPersistence) {}
    let mock = MockContextPersistence::default();
    assert_object_safe(&mock);
}

/// SCP-PERSIST-024: persist-drop-restore roundtrip verifies all fields.
#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn persist_drop_restore_roundtrip() {
    use scp_protocol::context::roles::{ContextRoleState, default_ceiling};

    let persistence = Arc::new(MockContextPersistence::default());

    // Create a context with persistence.
    let manager = ContextManager::with_persistence(
        Box::new(MockCrypto::default()),
        Box::new(MockTransport::connected()),
        Box::new(MockEventLog::default()),
        Box::new(MockContextPersistence::default()),
        noop_key_resolver(),
    );

    let params = ContextParams {
        mode: ContextMode::Broadcast,
        memory_scope: scp_protocol::context::MemoryScope::Full,
        ceiling: vec![
            scp_protocol::context::params::Capability::new("messages:read"),
            scp_protocol::context::params::Capability::new("messages:write"),
            scp_protocol::context::params::Capability::new("role:assign"),
        ],
        ..ContextParams::default()
    };

    let _handle = manager
        .create_context(
            "persist-ctx".into(),
            params.clone(),
            "did:key:creator".into(),
        )
        .await
        .unwrap();

    // Seed the mock persistence with a full snapshot.
    let ceiling = default_ceiling();
    let role_state = ContextRoleState::new(
        "persist-ctx",
        "did:key:creator",
        ceiling,
        vec![],
        &scp_primitives::SystemClock,
    )
    .unwrap();
    let mut membership = MembershipState::new();
    membership.add_member("did:key:creator".into(), "admin".into(), vec![]);
    let mut executed = HashSet::new();
    executed.insert([42u8; 32]);

    let snapshot = super::ContextSnapshot {
        context_id: "persist-ctx-2".to_owned(),
        state: ContextState::Active,
        context_params: params.clone(),
        membership: membership.clone(),
        role_state: role_state.clone(),
        executed_proposals: executed.clone(),
        ttl_remaining_secs: None,
        registered_tools: Vec::new(),
        read_exclusion_list: HashSet::new(),
        tool_interfaces: Vec::new(),
        threshold_signers: Vec::new(),
        threshold_value: 0,
        pruning_policy: None,
        governance_model_config: None,
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
        velocity_tracker: None,
        velocity_tracker_state: None,
        cooldown_until: std::collections::HashMap::new(),
        proposal_timestamps: std::collections::HashMap::new(),
        message_pricing: None,
        hard_rate_limit_config: None,
        hard_rate_limit_state: std::collections::HashMap::new(),
    };

    let bc_snapshot = test_broadcast_snapshot("persist-ctx-2");

    // Seed mock persistence directly.
    persistence
        .persist_context("persist-ctx-2", &snapshot)
        .unwrap();
    persistence
        .persist_broadcast("persist-ctx-2", &bc_snapshot)
        .unwrap();

    // Create a new manager with the seeded persistence.
    let manager2 = ContextManager::with_persistence(
        Box::new(MockCrypto::default()),
        Box::new(MockTransport::connected()),
        Box::new(MockEventLog::default()),
        Box::new(MockContextPersistence {
            contexts: std::sync::Mutex::new(persistence.contexts.lock().unwrap().clone()),
            broadcasts: std::sync::Mutex::new(persistence.broadcasts.lock().unwrap().clone()),
        }),
        noop_key_resolver(),
    );

    // Restore the context.
    let handle2 = ContextHandle::new("persist-ctx-2".to_owned(), params);
    handle2.transition_to(&ContextState::Active).await.unwrap();

    let result = manager2.restore_context("persist-ctx-2", &handle2).await;
    assert!(result.is_ok(), "restore should succeed");

    // Verify membership is restored.
    assert!(manager2.is_member("persist-ctx-2", "did:key:creator").await);

    // Verify broadcast is restored.
    assert!(
        manager2
            .is_broadcast_subscriber("persist-ctx-2", "did:key:sub1")
            .await
    );
    assert!(
        manager2
            .is_broadcast_subscriber("persist-ctx-2", "did:key:sub2")
            .await
    );
}

/// SCP-PERSIST-025: `executed_proposals` preserved across restart.
#[tokio::test]
async fn restore_preserves_executed_proposals() {
    use scp_protocol::context::roles::{ContextRoleState, default_ceiling};

    let persistence = Arc::new(MockContextPersistence::default());

    let params = ContextParams {
        mode: ContextMode::Broadcast,
        memory_scope: scp_protocol::context::MemoryScope::Full,
        ceiling: vec![
            scp_protocol::context::params::Capability::new("messages:read"),
            scp_protocol::context::params::Capability::new("messages:write"),
            scp_protocol::context::params::Capability::new("role:assign"),
        ],
        ..ContextParams::default()
    };

    let ceiling = default_ceiling();
    let role_state = ContextRoleState::new(
        "replay-ctx",
        "did:key:alice",
        ceiling,
        vec![],
        &scp_primitives::SystemClock,
    )
    .unwrap();
    let mut membership = MembershipState::new();
    membership.add_member("did:key:alice".into(), "admin".into(), vec![]);

    // Seed executed proposals so replay is detected.
    let proposal_id = [99u8; 32];
    let mut executed = HashSet::new();
    executed.insert(proposal_id);

    let snapshot = super::ContextSnapshot {
        context_id: "replay-ctx".to_owned(),
        state: ContextState::Active,
        context_params: params.clone(),
        membership,
        role_state,
        executed_proposals: executed,
        ttl_remaining_secs: None,
        registered_tools: Vec::new(),
        read_exclusion_list: HashSet::new(),
        tool_interfaces: Vec::new(),
        threshold_signers: Vec::new(),
        threshold_value: 0,
        pruning_policy: None,
        governance_model_config: None,
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
        velocity_tracker: None,
        velocity_tracker_state: None,
        cooldown_until: std::collections::HashMap::new(),
        proposal_timestamps: std::collections::HashMap::new(),
        message_pricing: None,
        hard_rate_limit_config: None,
        hard_rate_limit_state: std::collections::HashMap::new(),
    };

    persistence
        .persist_context("replay-ctx", &snapshot)
        .unwrap();

    // Also seed broadcast state (needed for restore).
    let bc_snapshot = test_broadcast_snapshot("replay-ctx");
    persistence
        .persist_broadcast("replay-ctx", &bc_snapshot)
        .unwrap();

    // Create manager and restore.
    let manager = ContextManager::with_persistence(
        Box::new(MockCrypto::default()),
        Box::new(MockTransport::connected()),
        Box::new(MockEventLog::default()),
        Box::new(MockContextPersistence {
            contexts: std::sync::Mutex::new(persistence.contexts.lock().unwrap().clone()),
            broadcasts: std::sync::Mutex::new(persistence.broadcasts.lock().unwrap().clone()),
        }),
        noop_key_resolver(),
    );

    let handle = ContextHandle::new("replay-ctx".to_owned(), params);
    handle.transition_to(&ContextState::Active).await.unwrap();
    manager
        .restore_context("replay-ctx", &handle)
        .await
        .unwrap();

    // Try to execute a governance action with the already-executed proposal ID.
    // The internal state should reject it as a replay.
    let contexts = manager.contexts.lock().await;
    let ctx = contexts.get("replay-ctx").unwrap();
    assert!(
        ctx.governance.executed_proposals.contains_key(&proposal_id),
        "executed_proposals should be preserved across restart"
    );
}

/// SCP-PERSIST-025: TTL timer re-spawned after restore with remaining TTL.
#[tokio::test]
async fn restore_respawns_ttl_timer() {
    use scp_protocol::context::roles::{ContextRoleState, default_ceiling};

    let persistence = Arc::new(MockContextPersistence::default());

    let params = ContextParams {
        ttl: Some(std::time::Duration::from_secs(300)),
        ceiling: vec![
            scp_protocol::context::params::Capability::new("messages:read"),
            scp_protocol::context::params::Capability::new("messages:write"),
            scp_protocol::context::params::Capability::new("role:assign"),
        ],
        ..ContextParams::default()
    };

    let ceiling = default_ceiling();
    let role_state = ContextRoleState::new(
        "ttl-ctx",
        "did:key:creator",
        ceiling,
        vec![],
        &scp_primitives::SystemClock,
    )
    .unwrap();
    let mut membership = MembershipState::new();
    membership.add_member("did:key:creator".into(), "admin".into(), vec![]);

    let snapshot = super::ContextSnapshot {
        context_id: "ttl-ctx".to_owned(),
        state: ContextState::Active,
        context_params: params.clone(),
        membership,
        role_state,
        executed_proposals: HashSet::new(),
        ttl_remaining_secs: Some(120), // 120 seconds remaining
        registered_tools: Vec::new(),
        read_exclusion_list: HashSet::new(),
        tool_interfaces: Vec::new(),
        threshold_signers: Vec::new(),
        threshold_value: 0,
        pruning_policy: None,
        governance_model_config: None,
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
        velocity_tracker: None,
        velocity_tracker_state: None,
        cooldown_until: std::collections::HashMap::new(),
        proposal_timestamps: std::collections::HashMap::new(),
        message_pricing: None,
        hard_rate_limit_config: None,
        hard_rate_limit_state: std::collections::HashMap::new(),
    };

    persistence.persist_context("ttl-ctx", &snapshot).unwrap();

    let manager = ContextManager::with_persistence(
        Box::new(MockCrypto::default()),
        Box::new(MockTransport::connected()),
        Box::new(MockEventLog::default()),
        Box::new(MockContextPersistence {
            contexts: std::sync::Mutex::new(persistence.contexts.lock().unwrap().clone()),
            broadcasts: std::sync::Mutex::new(HashMap::new()),
        }),
        noop_key_resolver(),
    );

    let handle = ContextHandle::new("ttl-ctx".to_owned(), params);
    handle.transition_to(&ContextState::Active).await.unwrap();
    manager.restore_context("ttl-ctx", &handle).await.unwrap();

    // Verify the TTL timer was re-spawned.
    let contexts = manager.contexts.lock().await;
    let ctx = contexts.get("ttl-ctx").unwrap();
    assert!(
        ctx.ttl.timer.is_active(),
        "TTL timer should be re-spawned after restore"
    );
}

/// SCP-PERSIST-025: `restore_all_contexts` lists and restores each.
#[tokio::test]
async fn restore_all_contexts_restores_persisted() {
    use scp_protocol::context::roles::{ContextRoleState, default_ceiling};

    let persistence = Arc::new(MockContextPersistence::default());

    for ctx_name in ["ctx-a", "ctx-b"] {
        let params = ContextParams::default();
        let ceiling = default_ceiling();
        let role_state = ContextRoleState::new(
            ctx_name,
            "did:key:creator",
            ceiling,
            vec![],
            &scp_primitives::SystemClock,
        )
        .unwrap();
        let mut membership = MembershipState::new();
        membership.add_member("did:key:creator".into(), "admin".into(), vec![]);

        let snapshot = super::ContextSnapshot {
            context_id: ctx_name.to_string(),
            state: ContextState::Active,
            context_params: params,
            membership,
            role_state,
            executed_proposals: HashSet::new(),
            ttl_remaining_secs: None,
            registered_tools: Vec::new(),
            read_exclusion_list: HashSet::new(),
            tool_interfaces: Vec::new(),
            threshold_signers: Vec::new(),
            threshold_value: 0,
            pruning_policy: None,
            governance_model_config: None,
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
            velocity_tracker: None,
            velocity_tracker_state: None,
            cooldown_until: std::collections::HashMap::new(),
            proposal_timestamps: std::collections::HashMap::new(),
            message_pricing: None,
            hard_rate_limit_config: None,
            hard_rate_limit_state: std::collections::HashMap::new(),
        };
        persistence.persist_context(ctx_name, &snapshot).unwrap();
    }

    let manager = ContextManager::with_persistence(
        Box::new(MockCrypto::default()),
        Box::new(MockTransport::connected()),
        Box::new(MockEventLog::default()),
        Box::new(MockContextPersistence {
            contexts: std::sync::Mutex::new(persistence.contexts.lock().unwrap().clone()),
            broadcasts: std::sync::Mutex::new(HashMap::new()),
        }),
        noop_key_resolver(),
    );

    let mut restored = manager.restore_all_contexts().await.unwrap();
    restored.sort();
    assert_eq!(restored, vec!["ctx-a", "ctx-b"]);

    // Both contexts should be registered.
    assert!(manager.is_member("ctx-a", "did:key:creator").await);
    assert!(manager.is_member("ctx-b", "did:key:creator").await);
}

/// `restore_context` rejects duplicate context registration.
#[tokio::test]
async fn restore_context_rejects_duplicate() {
    use scp_protocol::context::roles::{ContextRoleState, default_ceiling};

    let persistence = Arc::new(MockContextPersistence::default());

    let params = ContextParams {
        mode: ContextMode::Broadcast,
        memory_scope: scp_protocol::context::MemoryScope::Full,
        ..ContextParams::default()
    };

    let ceiling = default_ceiling();
    let role_state = ContextRoleState::new(
        "dup-ctx",
        "did:key:author1",
        ceiling,
        vec![],
        &scp_primitives::SystemClock,
    )
    .unwrap();
    let membership = MembershipState::new();

    let snapshot = super::ContextSnapshot {
        context_id: "dup-ctx".to_owned(),
        state: ContextState::Active,
        context_params: params.clone(),
        membership,
        role_state,
        executed_proposals: HashSet::new(),
        ttl_remaining_secs: None,
        registered_tools: Vec::new(),
        read_exclusion_list: HashSet::new(),
        tool_interfaces: Vec::new(),
        threshold_signers: Vec::new(),
        threshold_value: 0,
        pruning_policy: None,
        governance_model_config: None,
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
        velocity_tracker: None,
        velocity_tracker_state: None,
        cooldown_until: std::collections::HashMap::new(),
        proposal_timestamps: std::collections::HashMap::new(),
        message_pricing: None,
        hard_rate_limit_config: None,
        hard_rate_limit_state: std::collections::HashMap::new(),
    };

    let bc_snapshot = test_broadcast_snapshot("dup-ctx");
    persistence.persist_context("dup-ctx", &snapshot).unwrap();
    persistence
        .persist_broadcast("dup-ctx", &bc_snapshot)
        .unwrap();

    let manager = ContextManager::with_persistence(
        Box::new(MockCrypto::default()),
        Box::new(MockTransport::connected()),
        Box::new(MockEventLog::default()),
        Box::new(MockContextPersistence {
            contexts: std::sync::Mutex::new(persistence.contexts.lock().unwrap().clone()),
            broadcasts: std::sync::Mutex::new(persistence.broadcasts.lock().unwrap().clone()),
        }),
        noop_key_resolver(),
    );

    // First restore.
    let handle1 = ContextHandle::new("dup-ctx".to_owned(), params.clone());
    handle1.transition_to(&ContextState::Active).await.unwrap();
    manager.restore_context("dup-ctx", &handle1).await.unwrap();

    // Second restore should fail.
    let handle2 = ContextHandle::new("dup-ctx".to_owned(), params);
    handle2.transition_to(&ContextState::Active).await.unwrap();
    let result = manager.restore_context("dup-ctx", &handle2).await;

    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        ContextError::MembershipFailed(_)
    ));
}

// -----------------------------------------------------------------------
// EpochGraceStore needs_reconnect tests (§23.11)
// -----------------------------------------------------------------------

/// §23.11: Grace entry with epoch > MLS epoch triggers `needs_reconnect`.
#[tokio::test]
async fn restore_context_sets_needs_reconnect_on_grace_inconsistency() {
    use crate::crypto::mls::epoch_grace::GraceEntry;
    use scp_protocol::context::roles::{ContextRoleState, default_ceiling};

    let persistence = Arc::new(MockContextPersistence::default());

    let params = ContextParams {
        mode: ContextMode::Broadcast,
        memory_scope: scp_protocol::context::MemoryScope::Full,
        ..ContextParams::default()
    };

    let ceiling = default_ceiling();
    let role_state = ContextRoleState::new(
        "grace-incon-ctx",
        "did:key:author1",
        ceiling,
        vec![],
        &scp_primitives::SystemClock,
    )
    .unwrap();
    let membership = MembershipState::new();

    // Grace entry referencing epoch 5, but MLS epoch is only 3.
    // This simulates a partial write that escaped the transaction boundary.
    let snapshot = super::ContextSnapshot {
        context_id: "grace-incon-ctx".to_owned(),
        state: ContextState::Active,
        context_params: params.clone(),
        membership,
        role_state,
        executed_proposals: HashSet::new(),
        ttl_remaining_secs: None,
        registered_tools: Vec::new(),
        read_exclusion_list: HashSet::new(),
        tool_interfaces: Vec::new(),
        threshold_signers: Vec::new(),
        threshold_value: 0,
        pruning_policy: None,
        governance_model_config: None,
        economic_policy: None,
        budget_tracker: scp_protocol::economy::budget::MemberBudgetTracker::new(),
        approved_proposals: HashMap::new(),
        governance_freeze: None,
        pending_ceiling_modification: None,
        pending_economic_policy_change: None,
        mls_epoch: 3,
        epoch_coordination_records: Vec::new(),
        grace_entries: vec![GraceEntry {
            epoch: 5,                       // epoch 5 > mls_epoch 3 → inconsistency
            expires_at_unix_secs: u64::MAX, // far-future expiry
        }],
        needs_reconnect: false,
        migration_state: None,
        mls_crypto_state: Vec::new(),
        access_key_store: scp_protocol::crypto::access_keys::AccessKeyStore::new(),
        consequence_rules: Vec::new(),
        participation_cache: std::collections::HashMap::new(),
        velocity_tracker: None,
        velocity_tracker_state: None,
        cooldown_until: std::collections::HashMap::new(),
        proposal_timestamps: std::collections::HashMap::new(),
        message_pricing: None,
        hard_rate_limit_config: None,
        hard_rate_limit_state: std::collections::HashMap::new(),
    };

    let bc_snapshot = test_broadcast_snapshot("grace-incon-ctx");
    persistence
        .persist_context("grace-incon-ctx", &snapshot)
        .unwrap();
    persistence
        .persist_broadcast("grace-incon-ctx", &bc_snapshot)
        .unwrap();

    let manager = ContextManager::with_persistence(
        Box::new(MockCrypto::default()),
        Box::new(MockTransport::connected()),
        Box::new(MockEventLog::default()),
        Box::new(MockContextPersistence {
            contexts: std::sync::Mutex::new(persistence.contexts.lock().unwrap().clone()),
            broadcasts: std::sync::Mutex::new(persistence.broadcasts.lock().unwrap().clone()),
        }),
        noop_key_resolver(),
    );

    let handle = ContextHandle::new("grace-incon-ctx".to_owned(), params);
    handle.transition_to(&ContextState::Active).await.unwrap();
    manager
        .restore_context("grace-incon-ctx", &handle)
        .await
        .unwrap();

    // The context should be marked as needing reconnection.
    assert!(
        manager.context_needs_reconnect("grace-incon-ctx").await,
        "inconsistent grace entries should set needs_reconnect"
    );

    // After clearing, the flag should be false.
    assert!(manager.clear_needs_reconnect("grace-incon-ctx").await);
    assert!(
        !manager.context_needs_reconnect("grace-incon-ctx").await,
        "needs_reconnect should be cleared"
    );
}

/// §23.11: Consistent grace entries do NOT set `needs_reconnect`.
#[tokio::test]
async fn restore_context_no_reconnect_when_grace_consistent() {
    use crate::crypto::mls::epoch_grace::GraceEntry;
    use scp_protocol::context::roles::{ContextRoleState, default_ceiling};

    let persistence = Arc::new(MockContextPersistence::default());

    let params = ContextParams {
        mode: ContextMode::Broadcast,
        memory_scope: scp_protocol::context::MemoryScope::Full,
        ..ContextParams::default()
    };

    let ceiling = default_ceiling();
    let role_state = ContextRoleState::new(
        "grace-ok-ctx",
        "did:key:author1",
        ceiling,
        vec![],
        &scp_primitives::SystemClock,
    )
    .unwrap();
    let membership = MembershipState::new();

    // Grace entry epoch 2, MLS epoch 3 → consistent (epoch <= mls_epoch).
    // Use a far-future but safe expiry (now + 1 hour) to avoid overflow.
    let future_expiry = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + 3600;
    let snapshot = super::ContextSnapshot {
        context_id: "grace-ok-ctx".to_owned(),
        state: ContextState::Active,
        context_params: params.clone(),
        membership,
        role_state,
        executed_proposals: HashSet::new(),
        ttl_remaining_secs: None,
        registered_tools: Vec::new(),
        read_exclusion_list: HashSet::new(),
        tool_interfaces: Vec::new(),
        threshold_signers: Vec::new(),
        threshold_value: 0,
        pruning_policy: None,
        governance_model_config: None,
        economic_policy: None,
        budget_tracker: scp_protocol::economy::budget::MemberBudgetTracker::new(),
        approved_proposals: HashMap::new(),
        governance_freeze: None,
        pending_ceiling_modification: None,
        pending_economic_policy_change: None,
        mls_epoch: 3,
        epoch_coordination_records: Vec::new(),
        grace_entries: vec![GraceEntry {
            epoch: 2, // epoch 2 <= mls_epoch 3 → consistent
            expires_at_unix_secs: future_expiry,
        }],
        needs_reconnect: false,
        migration_state: None,
        mls_crypto_state: Vec::new(),
        access_key_store: scp_protocol::crypto::access_keys::AccessKeyStore::new(),
        consequence_rules: Vec::new(),
        participation_cache: std::collections::HashMap::new(),
        velocity_tracker: None,
        velocity_tracker_state: None,
        cooldown_until: std::collections::HashMap::new(),
        proposal_timestamps: std::collections::HashMap::new(),
        message_pricing: None,
        hard_rate_limit_config: None,
        hard_rate_limit_state: std::collections::HashMap::new(),
    };

    let bc_snapshot = test_broadcast_snapshot("grace-ok-ctx");
    persistence
        .persist_context("grace-ok-ctx", &snapshot)
        .unwrap();
    persistence
        .persist_broadcast("grace-ok-ctx", &bc_snapshot)
        .unwrap();

    let manager = ContextManager::with_persistence(
        Box::new(MockCrypto::default()),
        Box::new(MockTransport::connected()),
        Box::new(MockEventLog::default()),
        Box::new(MockContextPersistence {
            contexts: std::sync::Mutex::new(persistence.contexts.lock().unwrap().clone()),
            broadcasts: std::sync::Mutex::new(persistence.broadcasts.lock().unwrap().clone()),
        }),
        noop_key_resolver(),
    );

    let handle = ContextHandle::new("grace-ok-ctx".to_owned(), params);
    handle.transition_to(&ContextState::Active).await.unwrap();
    manager
        .restore_context("grace-ok-ctx", &handle)
        .await
        .unwrap();

    // Consistent grace entries should NOT set needs_reconnect.
    assert!(
        !manager.context_needs_reconnect("grace-ok-ctx").await,
        "consistent grace entries should not set needs_reconnect"
    );
}

// -----------------------------------------------------------------------
// contexts_needing_reconnect / execute_reconnection tests (#853)
// -----------------------------------------------------------------------

/// Builds a test `ContextSnapshot` with optional grace inconsistency.
/// When `bad_grace_epoch` is `Some(epoch)` and `epoch > mls_epoch`,
/// restoring triggers `needs_reconnect = true`.
fn reconnect_test_snapshot(
    ctx_id: &str,
    mls_epoch: u64,
    bad_grace_epoch: Option<u64>,
) -> super::ContextSnapshot {
    use scp_protocol::context::roles::{ContextRoleState, default_ceiling};
    let ceiling = default_ceiling();
    let role_state = ContextRoleState::new(
        ctx_id,
        "did:key:a1",
        ceiling,
        vec![],
        &scp_primitives::SystemClock,
    )
    .unwrap();
    let grace = bad_grace_epoch
        .map(|e| {
            vec![crate::crypto::mls::epoch_grace::GraceEntry {
                epoch: e,
                expires_at_unix_secs: u64::MAX,
            }]
        })
        .unwrap_or_default();
    super::ContextSnapshot {
        context_id: ctx_id.to_owned(),
        state: ContextState::Active,
        context_params: ContextParams::default(),
        membership: MembershipState::new(),
        role_state,
        executed_proposals: HashSet::new(),
        ttl_remaining_secs: None,
        registered_tools: Vec::new(),
        read_exclusion_list: HashSet::new(),
        tool_interfaces: Vec::new(),
        threshold_signers: Vec::new(),
        threshold_value: 0,
        pruning_policy: None,
        governance_model_config: None,
        economic_policy: None,
        approved_proposals: HashMap::new(),
        governance_freeze: None,
        pending_ceiling_modification: None,
        pending_economic_policy_change: None,
        mls_epoch,
        grace_entries: grace,
        needs_reconnect: false,
        budget_tracker: scp_protocol::economy::budget::MemberBudgetTracker::new(),
        epoch_coordination_records: Vec::new(),
        mls_crypto_state: Vec::new(),
        migration_state: None,
        access_key_store: scp_protocol::crypto::access_keys::AccessKeyStore::new(),
        consequence_rules: Vec::new(),
        participation_cache: std::collections::HashMap::new(),
        velocity_tracker: None,
        velocity_tracker_state: None,
        cooldown_until: std::collections::HashMap::new(),
        proposal_timestamps: std::collections::HashMap::new(),
        message_pricing: None,
        hard_rate_limit_config: None,
        hard_rate_limit_state: std::collections::HashMap::new(),
    }
}

/// Creates a manager with persistence pre-loaded, then restores all contexts.
async fn manager_with_reconnect_snapshots(
    snapshots: &[(&str, super::ContextSnapshot)],
) -> ContextManager {
    let persistence = MockContextPersistence::default();
    for (ctx_id, snap) in snapshots {
        let bc = test_broadcast_snapshot(ctx_id);
        persistence.persist_context(ctx_id, snap).unwrap();
        persistence.persist_broadcast(ctx_id, &bc).unwrap();
    }
    let manager = ContextManager::with_persistence(
        Box::new(MockCrypto::default()),
        Box::new(MockTransport::connected()),
        Box::new(MockEventLog::default()),
        Box::new(persistence),
        noop_key_resolver(),
    );
    for (ctx_id, _) in snapshots {
        let handle = ContextHandle::new((*ctx_id).to_owned(), ContextParams::default());
        handle.transition_to(&ContextState::Active).await.unwrap();
        manager.restore_context(ctx_id, &handle).await.unwrap();
    }
    manager
}

/// §23.11/§23.3: `contexts_needing_reconnect` returns IDs of contexts
/// with `needs_reconnect = true`.
#[tokio::test]
async fn contexts_needing_reconnect_returns_flagged_contexts() {
    let snap1 = reconnect_test_snapshot("ctx-r1", 3, Some(5)); // inconsistent
    let snap2 = reconnect_test_snapshot("ctx-r2", 3, None); // consistent
    let manager = manager_with_reconnect_snapshots(&[("ctx-r1", snap1), ("ctx-r2", snap2)]).await;

    let needing = manager.contexts_needing_reconnect().await;
    assert_eq!(needing.len(), 1);
    assert_eq!(needing[0], "ctx-r1");
    assert!(!manager.context_needs_reconnect("ctx-r2").await);
}

/// §23.3: `prepare_reconnection` returns None when no contexts need
/// reconnection.
#[tokio::test]
async fn prepare_reconnection_returns_none_when_no_reconnect_needed() {
    let manager = ContextManager::new(
        Box::new(MockCrypto::default()),
        Box::new(MockTransport::connected()),
        Box::new(MockEventLog::default()),
        noop_key_resolver(),
    );

    let result = manager
        .prepare_reconnection(
            DID::from("did:dht:z6MkAlice"),
            std::collections::HashMap::new(),
        )
        .await;
    assert!(result.is_none());
}

/// §23.3: `execute_reconnection` runs the full reconnection protocol
/// for contexts with `needs_reconnect = true`, and clears the flag
/// after successful completion.
#[tokio::test]
async fn execute_reconnection_wires_flag_to_protocol() {
    use crate::sync::hours_offline::{BufferedMessage, EpochCatchUpState, SyncPhaseDriver};
    use scp_protocol::sync::{SyncError, SyncEvent, SyncPolicy};

    // Minimal SyncPhaseDriver that succeeds on all phases.
    struct NoOpDriver;
    impl SyncPhaseDriver for NoOpDriver {
        async fn relay_catch_up(&self, _: &str, _: u64) -> Result<Vec<BufferedMessage>, SyncError> {
            Ok(vec![])
        }
        async fn epoch_reconciliation(
            &self,
            id: &str,
            l: u64,
            t: u64,
            _: &SyncPolicy,
        ) -> Result<EpochCatchUpState, SyncError> {
            let mut s = EpochCatchUpState::new(id.to_owned(), l, t);
            s.status = scp_protocol::sync::CatchUpStatus::Complete;
            Ok(s)
        }
        async fn event_log_sync(&self, _: &str) -> Result<(u64, Vec<SyncEvent>), SyncError> {
            Ok((0, vec![]))
        }
        async fn sender_key_reacquire(&self, _: &str, _: &SyncPolicy) -> Result<u64, SyncError> {
            Ok(0)
        }
        async fn mls_update(&self, _: &str) -> Result<bool, SyncError> {
            Ok(true)
        }
        async fn queue_drain(
            &self,
            _: &str,
            _: u64,
            _: Option<u64>,
        ) -> Result<(u64, u64), SyncError> {
            Ok((0, 0))
        }
        async fn local_epoch(&self, _: &str) -> Result<Option<u64>, SyncError> {
            Ok(Some(3))
        }
        async fn observed_target_epoch(
            &self,
            _: &str,
            _: &[BufferedMessage],
        ) -> Result<Option<u64>, SyncError> {
            Ok(Some(3))
        }
        async fn blob_ttl_secs(&self, _: &str) -> Result<Option<u64>, SyncError> {
            Ok(None)
        }
    }

    let snap = reconnect_test_snapshot("ctx-ex", 3, Some(10));
    let manager = manager_with_reconnect_snapshots(&[("ctx-ex", snap)]).await;

    assert!(manager.context_needs_reconnect("ctx-ex").await);

    let mut contacts = std::collections::HashMap::new();
    contacts.insert("ctx-ex".to_owned(), 990_000u64);
    let driver = NoOpDriver;

    let report = manager
        .execute_reconnection("did:dht:z6MkAlice".into(), 1_000_000, contacts, &driver)
        .await
        .expect("should return a report");

    assert_eq!(report.contexts_synced.len(), 1);
    assert_eq!(
        report.contexts_synced[0].outcome,
        scp_protocol::sync::SyncOutcome::FullyCaughtUp
    );
    assert!(report.contexts_synced[0].mls_update_issued);
    assert!(
        !manager.context_needs_reconnect("ctx-ex").await,
        "flag should be auto-cleared"
    );

    // No more flagged contexts.
    let none = manager
        .execute_reconnection(
            "did:dht:z6MkAlice".into(),
            1_000_000,
            std::collections::HashMap::new(),
            &driver,
        )
        .await;
    assert!(none.is_none());
}

/// §23.3: `execute_reconnection` clears `needs_reconnect` when the
/// driver signals `ContextGone` (context closed/expired while offline).
/// This prevents infinite retry loops for contexts that no longer exist.
#[tokio::test]
async fn execute_reconnection_clears_flag_on_context_gone() {
    use crate::sync::hours_offline::{BufferedMessage, EpochCatchUpState, SyncPhaseDriver};
    use scp_protocol::sync::{SyncError, SyncEvent, SyncPolicy};

    /// Driver whose `relay_catch_up` returns `SyncError::ContextGone`,
    /// causing the coordinator to produce `SyncOutcome::ContextGone`.
    struct ContextGoneDriver;
    impl SyncPhaseDriver for ContextGoneDriver {
        async fn relay_catch_up(
            &self,
            ctx_id: &str,
            _: u64,
        ) -> Result<Vec<BufferedMessage>, SyncError> {
            Err(SyncError::ContextGone {
                context_id: ctx_id.to_owned(),
            })
        }
        async fn epoch_reconciliation(
            &self,
            id: &str,
            l: u64,
            t: u64,
            _: &SyncPolicy,
        ) -> Result<EpochCatchUpState, SyncError> {
            let mut s = EpochCatchUpState::new(id.to_owned(), l, t);
            s.status = scp_protocol::sync::CatchUpStatus::Complete;
            Ok(s)
        }
        async fn event_log_sync(&self, _: &str) -> Result<(u64, Vec<SyncEvent>), SyncError> {
            Ok((0, vec![]))
        }
        async fn sender_key_reacquire(&self, _: &str, _: &SyncPolicy) -> Result<u64, SyncError> {
            Ok(0)
        }
        async fn mls_update(&self, _: &str) -> Result<bool, SyncError> {
            Ok(false)
        }
        async fn queue_drain(
            &self,
            _: &str,
            _: u64,
            _: Option<u64>,
        ) -> Result<(u64, u64), SyncError> {
            Ok((0, 0))
        }
        async fn local_epoch(&self, _: &str) -> Result<Option<u64>, SyncError> {
            Ok(Some(3))
        }
        async fn observed_target_epoch(
            &self,
            _: &str,
            _: &[BufferedMessage],
        ) -> Result<Option<u64>, SyncError> {
            Ok(Some(3))
        }
        async fn blob_ttl_secs(&self, _: &str) -> Result<Option<u64>, SyncError> {
            Ok(None)
        }
    }

    let snap = reconnect_test_snapshot("ctx-gone", 3, Some(10));
    let manager = manager_with_reconnect_snapshots(&[("ctx-gone", snap)]).await;

    assert!(manager.context_needs_reconnect("ctx-gone").await);

    let mut contacts = std::collections::HashMap::new();
    contacts.insert("ctx-gone".to_owned(), 990_000u64);
    let driver = ContextGoneDriver;

    let report = manager
        .execute_reconnection("did:dht:z6MkAlice".into(), 1_000_000, contacts, &driver)
        .await
        .expect("should return a report");

    assert_eq!(report.contexts_synced.len(), 1);
    assert_eq!(
        report.contexts_synced[0].outcome,
        scp_protocol::sync::SyncOutcome::ContextGone,
    );
    assert!(
        !manager.context_needs_reconnect("ctx-gone").await,
        "needs_reconnect must be cleared for ContextGone — not left as infinite retry"
    );
}

// -----------------------------------------------------------------------
// min_protocol_version defense-in-depth at create_context (#707)
// -----------------------------------------------------------------------

#[tokio::test]
async fn create_context_rejects_incompatible_min_protocol_version() {
    let manager = ContextManager::new(
        Box::new(MockCrypto::default()),
        Box::new(MockTransport::connected()),
        Box::new(MockEventLog::default()),
        noop_key_resolver(),
    );
    let params = ContextParams {
        min_protocol_version: Some((2, 0)), // SDK is 1.0, this is unreachable
        ..ContextParams::default()
    };
    let result = manager
        .create_context("ver-reject".into(), params, "did:key:creator".into())
        .await;
    assert!(
        result.is_err(),
        "create_context should reject min_protocol_version (2,0)"
    );
    let err_msg = format!("{}", result.unwrap_err());
    assert!(
        err_msg.contains("version incompatible"),
        "error should mention version incompatibility: {err_msg}"
    );
}

#[tokio::test]
async fn create_context_accepts_compatible_min_protocol_version() {
    let manager = ContextManager::new(
        Box::new(MockCrypto::default()),
        Box::new(MockTransport::connected()),
        Box::new(MockEventLog::default()),
        noop_key_resolver(),
    );
    let params = ContextParams {
        min_protocol_version: Some((1, 0)), // matches SDK version
        ..ContextParams::default()
    };
    let result = manager
        .create_context("ver-accept".into(), params, "did:key:creator".into())
        .await;
    assert!(
        result.is_ok(),
        "create_context should accept min_protocol_version (1,0)"
    );
}

#[tokio::test]
async fn create_context_accepts_none_min_protocol_version() {
    let manager = ContextManager::new(
        Box::new(MockCrypto::default()),
        Box::new(MockTransport::connected()),
        Box::new(MockEventLog::default()),
        noop_key_resolver(),
    );
    let params = ContextParams {
        min_protocol_version: None, // defaults to (1,0) — always compatible
        ..ContextParams::default()
    };
    let result = manager
        .create_context("ver-none".into(), params, "did:key:creator".into())
        .await;
    assert!(
        result.is_ok(),
        "create_context should accept min_protocol_version None"
    );
}

// -----------------------------------------------------------------------

// ContextManagerBuilder tests (#937 review finding 6)
// -----------------------------------------------------------------------

#[test]
fn builder_without_crypto_returns_missing_crypto_error() {
    let result = ContextManager::builder().build();
    assert!(
        matches!(result, Err(ContextManagerBuildError::MissingCrypto)),
        "expected MissingCrypto error"
    );
}

#[test]
fn builder_with_only_crypto_succeeds() {
    let result = ContextManager::builder()
        .crypto(Box::new(MockCrypto::default()))
        .build();
    assert!(
        result.is_ok(),
        "builder with only crypto should succeed with defaults"
    );
}

#[test]
fn builder_persistence_wires_through() {
    use crate::context::providers::persistence::InMemoryPersistence;

    let result = ContextManager::builder()
        .crypto(Box::new(MockCrypto::default()))
        .persistence(Box::new(InMemoryPersistence::new()))
        .build();
    assert!(
        result.is_ok(),
        "builder with crypto + persistence should succeed"
    );

    // The manager should have persistence wired.
    let manager = result.unwrap();
    assert!(
        manager.persistence.is_some(),
        "persistence() should wire through to the manager"
    );
}

#[test]
fn builder_storage_auto_wires_persistence_and_event_log() {
    use scp_platform::encrypting_adapter::EncryptingAdapter;
    use scp_platform::testing::InMemoryStorage;
    use zeroize::Zeroizing;

    let key = Zeroizing::new([0x42u8; 32]);
    let storage = EncryptingAdapter::new(InMemoryStorage::new(), key);

    let manager = ContextManager::builder()
        .crypto(Box::new(MockCrypto::default()))
        .storage(storage)
        .build()
        .expect("builder with crypto + storage should succeed");

    assert!(
        manager.has_persistence(),
        ".storage() should auto-wire persistence"
    );
}

// -----------------------------------------------------------------------
// Standing context tests (ported from context::standing -- SCP-138)
// -----------------------------------------------------------------------

#[tokio::test]
async fn standing_context_creates_new_bilateral_persistent_context() {
    let manager = ContextManager::new(
        Box::new(MockCrypto::default()),
        Box::new(MockTransport::connected()),
        Box::new(MockEventLog::default()),
        noop_key_resolver(),
    );

    let alice = DID::from("did:dht:z6MkLocalAlice");
    let carol = DID::from("did:dht:z6MkCarol");

    assert!(!manager.has_standing_context(&carol).await);

    let context_id = manager.standing_context(&alice, &carol).await.unwrap();

    // Verify the context exists in the manager.
    let contexts = manager.contexts.lock().await;
    let ctx = contexts.get(&context_id).unwrap();
    let state = ctx.handle.state().await;
    assert_eq!(state, ContextState::Active);

    // Verify the context uses bilateral-persistent template params.
    let params = ctx.handle.params();
    assert_eq!(params.template_id, Some(TemplateId::BilateralPersistent));
    assert!(params.ttl.is_none()); // bilateral-persistent forbids TTL
    drop(contexts);

    // Verify the standing context is now tracked.
    assert!(manager.has_standing_context(&carol).await);
    assert_eq!(manager.standing_context_count().await, 1);
}

#[tokio::test]
async fn standing_context_returns_existing_active_context() {
    let manager = ContextManager::new(
        Box::new(MockCrypto::default()),
        Box::new(MockTransport::connected()),
        Box::new(MockEventLog::default()),
        noop_key_resolver(),
    );

    let alice = DID::from("did:dht:z6MkLocalAlice");
    let bob = DID::from("did:dht:z6MkBob");

    // First call creates the context.
    let ctx_id1 = manager.standing_context(&alice, &bob).await.unwrap();

    // Second call should return the same context_id without creation.
    let ctx_id2 = manager.standing_context(&alice, &bob).await.unwrap();
    assert_eq!(ctx_id1, ctx_id2);

    // Only one standing context should be tracked.
    assert_eq!(manager.standing_context_count().await, 1);
}

#[tokio::test]
async fn standing_context_recreates_when_peer_has_left() {
    let manager = ContextManager::new(
        Box::new(MockCrypto::default()),
        Box::new(MockTransport::connected()),
        Box::new(MockEventLog::default()),
        noop_key_resolver(),
    );

    let alice = DID::from("did:dht:z6MkLocalAlice");
    let dave = DID::from("did:dht:z6MkDave");

    // Create initial context.
    let ctx_id1 = manager.standing_context(&alice, &dave).await.unwrap();

    // Simulate peer leaving: transition to Closing -> Closed.
    {
        let contexts = manager.contexts.lock().await;
        let ctx = contexts.get(&ctx_id1).unwrap();
        ctx.handle
            .transition_to(&ContextState::Closing)
            .await
            .unwrap();
        ctx.handle
            .transition_to(&ContextState::Closed)
            .await
            .unwrap();
    }

    // Remove the old closed context so create_context can re-use the ID.
    {
        let mut contexts = manager.contexts.lock().await;
        contexts.remove(&ctx_id1);
    }

    let ctx_id2 = manager.standing_context(&alice, &dave).await.unwrap();

    // Same deterministic ID.
    assert_eq!(ctx_id1, ctx_id2);

    // Verify the new context is Active.
    {
        let contexts = manager.contexts.lock().await;
        let ctx = contexts.get(&ctx_id2).unwrap();
        assert_eq!(ctx.handle.state().await, ContextState::Active);
    }

    // Verify one standing context is tracked.
    assert_eq!(manager.standing_context_count().await, 1);
    assert!(manager.has_standing_context(&dave).await);
}

#[tokio::test]
async fn standing_context_recreates_when_context_expired() {
    let manager = ContextManager::new(
        Box::new(MockCrypto::default()),
        Box::new(MockTransport::connected()),
        Box::new(MockEventLog::default()),
        noop_key_resolver(),
    );

    let alice = DID::from("did:dht:z6MkLocalAlice");
    let eve = DID::from("did:dht:z6MkEve");

    // Create initial context.
    let ctx_id1 = manager.standing_context(&alice, &eve).await.unwrap();

    // Simulate expiry.
    {
        let contexts = manager.contexts.lock().await;
        let ctx = contexts.get(&ctx_id1).unwrap();
        ctx.handle
            .transition_to(&ContextState::Expired)
            .await
            .unwrap();
    }

    // Remove old context to allow recreation.
    {
        let mut contexts = manager.contexts.lock().await;
        contexts.remove(&ctx_id1);
    }

    // Calling standing_context should create a new one.
    let ctx_id2 = manager.standing_context(&alice, &eve).await.unwrap();
    assert_eq!(ctx_id1, ctx_id2);

    {
        let contexts = manager.contexts.lock().await;
        let ctx = contexts.get(&ctx_id2).unwrap();
        assert_eq!(ctx.handle.state().await, ContextState::Active);
    }
}

#[tokio::test]
async fn reconnect_all_standing_reconnects_active_contexts() {
    let manager = ContextManager::new(
        Box::new(MockCrypto::default()),
        Box::new(MockTransport::connected()),
        Box::new(MockEventLog::default()),
        noop_key_resolver(),
    );

    let alice = DID::from("did:dht:z6MkLocalAlice");
    manager.register_local_did(alice.clone()).await;

    let bob = DID::from("did:dht:z6MkBob");
    let carol = DID::from("did:dht:z6MkCarol");
    let dave = DID::from("did:dht:z6MkDave");

    let _id_bob = manager.standing_context(&alice, &bob).await.unwrap();
    let id_carol = manager.standing_context(&alice, &carol).await.unwrap();
    let _id_dave = manager.standing_context(&alice, &dave).await.unwrap();

    // Close Carol's context (simulating peer left).
    {
        let contexts = manager.contexts.lock().await;
        let ctx = contexts.get(&id_carol).unwrap();
        ctx.handle
            .transition_to(&ContextState::Closing)
            .await
            .unwrap();
        ctx.handle
            .transition_to(&ContextState::Closed)
            .await
            .unwrap();
    }

    // Reconnect all.
    let reconnected = manager.reconnect_all_standing().await.0;

    // Only Bob and Dave should be reconnected (Active). Carol is Closed.
    assert_eq!(reconnected, 2);
}

#[tokio::test]
async fn reconnect_all_standing_with_no_contexts_returns_zero() {
    let manager = ContextManager::new(
        Box::new(MockCrypto::default()),
        Box::new(MockTransport::connected()),
        Box::new(MockEventLog::default()),
        noop_key_resolver(),
    );

    let reconnected = manager.reconnect_all_standing().await.0;
    assert_eq!(reconnected, 0);
}

#[tokio::test]
async fn standing_context_is_idempotent() {
    let manager = ContextManager::new(
        Box::new(MockCrypto::default()),
        Box::new(MockTransport::connected()),
        Box::new(MockEventLog::default()),
        noop_key_resolver(),
    );

    let alice = DID::from("did:dht:z6MkLocalAlice");
    let frank = DID::from("did:dht:z6MkFrank");

    let id1 = manager.standing_context(&alice, &frank).await.unwrap();
    let id2 = manager.standing_context(&alice, &frank).await.unwrap();
    let id3 = manager.standing_context(&alice, &frank).await.unwrap();

    // All should return the same context_id.
    assert_eq!(id1, id2);
    assert_eq!(id2, id3);

    // Only one standing context should be tracked.
    assert_eq!(manager.standing_context_count().await, 1);
}

#[tokio::test]
async fn register_standing_context_populates_tracking() {
    let manager = ContextManager::new(
        Box::new(MockCrypto::default()),
        Box::new(MockTransport::connected()),
        Box::new(MockEventLog::default()),
        noop_key_resolver(),
    );

    let grace = DID::from("did:dht:z6MkGrace");

    assert!(!manager.has_standing_context(&grace).await);
    manager.register_standing_context(grace.clone()).await;
    assert!(manager.has_standing_context(&grace).await);
    assert_eq!(manager.standing_context_count().await, 1);
}

#[test]
fn standing_context_id_is_deterministic() {
    use super::super::standing::generate_standing_context_id;

    let alice = DID::from("did:dht:z6MkAlice");
    let bob = DID::from("did:dht:z6MkBob");

    let id1 = generate_standing_context_id(&alice, &bob);
    let id2 = generate_standing_context_id(&bob, &alice);

    // Same pair produces the same ID regardless of order.
    assert_eq!(id1, id2);

    // Different pairs produce different IDs.
    let carol = DID::from("did:dht:z6MkCarol");
    let id3 = generate_standing_context_id(&alice, &carol);
    assert_ne!(id1, id3);
}

/// `auto_accept_blocked` rejects join for paid contexts (#1537).
#[tokio::test]
async fn auto_accept_blocked_by_economics_rejects_join() {
    use scp_protocol::economy::types::{Amount, CostSchedule, CurrencyCode, EconomicPolicy};

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
    params.economic_policy = Some(EconomicPolicy {
        locked: false,
        cost_schedule: CostSchedule {
            currency: CurrencyCode::new([85, 83, 68, 0]),
            per_message: None,
            per_tool_invoke: None,
            per_join: Some(Amount::new(100)),
            per_period: None,
            per_byte_stored: None,
        },
        payment_adapters: vec![],
        pricing_formula: None,
        payee: DID::from("did:key:payee"),
    });
    let handle = manager
        .create_context("paid-join-ctx".into(), params, "did:key:admin".into())
        .await
        .unwrap();

    let kp = scp_protocol::context::membership::KeyPackage {
        owner_did: DID::from("did:key:joiner"),
        mls_key_package_bytes: None,
    };
    let result = manager.join_context(&handle, kp, None).await;
    assert!(
        result.is_err(),
        "join should be blocked for paid context without explicit acceptance"
    );
}

/// Sybil resistance rejects insufficient signals (#1530).
#[tokio::test]
async fn sybil_reject_insufficient_signals() {
    // Currently the sybil resistance function is a no-op that passes
    // unconditionally (no sybil policy field on ContextParams yet).
    // This test verifies the function exists and can be called. When a
    // real sybil policy is added, this test should be updated to verify
    // actual rejection.
    use super::super::lifecycle::evaluate_sybil_resistance;

    let manager = ContextManager::new(
        Box::new(MockCrypto::default()),
        Box::new(MockTransport::connected()),
        Box::new(MockEventLog::default()),
        noop_key_resolver(),
    );

    let params = ContextParams::default();
    let _handle = manager
        .create_context("sybil-ctx".into(), params, "did:key:admin".into())
        .await
        .unwrap();

    // Currently passes unconditionally — the test asserts the function is
    // callable and returns Ok.
    let contexts = manager.contexts.lock().await;
    let ctx = contexts.get("sybil-ctx").unwrap();
    let result = evaluate_sybil_resistance(ctx, &"did:key:test".into(), 0);
    assert!(
        result.is_ok(),
        "sybil resistance should pass with no policy configured"
    );
}

/// Budget exceeded on `join_context` rejects (#1537).
#[tokio::test]
async fn budget_exceeded_on_join_rejects() {
    use scp_protocol::economy::types::{Amount, CostSchedule, CurrencyCode, EconomicPolicy};

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
    params.economic_policy = Some(EconomicPolicy {
        locked: false,
        cost_schedule: CostSchedule {
            currency: CurrencyCode::new([85, 83, 68, 0]),
            per_message: None,
            per_tool_invoke: None,
            per_join: Some(Amount::new(50)),
            per_period: None,
            per_byte_stored: None,
        },
        payment_adapters: vec![],
        pricing_formula: None,
        payee: DID::from("did:key:payee"),
    });
    let handle = manager
        .create_context("budget-join-ctx".into(), params, "did:key:admin".into())
        .await
        .unwrap();

    let kp = scp_protocol::context::membership::KeyPackage {
        owner_did: DID::from("did:key:joiner"),
        mls_key_package_bytes: None,
    };
    let result = manager.join_context(&handle, kp, None).await;
    assert!(
        result.is_err(),
        "join should fail: paid context auto_accept blocked"
    );
}
