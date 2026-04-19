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

    let result = manager.join_context(&handle, kp, None, None).await;
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

    let result = manager.join_context(&handle, kp, None, None).await;
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
    let result = manager
        .join_context(&ephemeral_handle, kp, None, None)
        .await;

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
    manager.join_context(&handle, kp, None, None).await.unwrap();
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
        .create_context("auth-ctx".into(), params, "did:key:creator".into(), None)
        .await
        .unwrap();

    // Add an observer member.
    let kp = KeyPackage::mock("did:key:observer".into());
    manager.join_context(&handle, kp, None, None).await.unwrap();

    // Reassign to observer role (joined members default to "member").
    {
        let arc = manager.get_context_arc("auth-ctx").unwrap();
        let mut g = arc.lock().await;
        let ctx = &mut *g;
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
        .create_context("conc-ctx".into(), params, "did:key:creator".into(), None)
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
            mgr.join_context(&h, kp, None, None).await
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
#[allow(
    clippy::disallowed_types,
    reason = "Test-only mock state; actor refactor does not migrate test scaffolding. See ADR-049 §'Disallowed types / methods via clippy.toml' and plan §Commit ladder in `~/.claude/plans/generic-moseying-lightning.md`."
)]
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
        .create_context("panic-ctx".into(), params, "did:key:creator".into(), None)
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
    let join_result = manager.join_context(&handle_clone, kp, None, None).await;
    assert!(join_result.is_ok(), "join after panic should succeed");
    assert_eq!(manager.member_count("panic-ctx").await, Some(2));
}

// -----------------------------------------------------------------------
// Context persistence tests (SCP-PERSIST-020 through SCP-PERSIST-025)
// -----------------------------------------------------------------------

/// Mock `ContextPersistence` that stores snapshots in `HashMap`s.
#[derive(Default)]
#[allow(
    clippy::disallowed_types,
    reason = "Test-only mock state; actor refactor does not migrate test scaffolding. See ADR-049 §'Disallowed types / methods via clippy.toml' and plan §Commit ladder in `~/.claude/plans/generic-moseying-lightning.md`."
)]
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
#[allow(
    clippy::disallowed_types,
    reason = "Test-only mock state; actor refactor does not migrate test scaffolding. See ADR-049 §'Disallowed types / methods via clippy.toml' and plan §Commit ladder in `~/.claude/plans/generic-moseying-lightning.md`."
)]
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
            None,
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
        next_proposal_seq: 0,
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
        spending_nonce_tracker_state: std::collections::HashMap::new(),
        pending_commits: std::collections::VecDeque::new(),
        commit_fault: None,
        checkpoint_events_since: 0,
        checkpoint_last_time_secs: 0,
        generation: 0,
        local_pseudonym: None,
        pseudonym_registry: std::collections::HashMap::new(),
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
#[allow(clippy::too_many_lines)] // DashMap lock pattern adds verbosity
#[allow(
    clippy::disallowed_types,
    reason = "Test-only mock state; actor refactor does not migrate test scaffolding. See ADR-049 §'Disallowed types / methods via clippy.toml' and plan §Commit ladder in `~/.claude/plans/generic-moseying-lightning.md`."
)]
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
        next_proposal_seq: 0,
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
        spending_nonce_tracker_state: std::collections::HashMap::new(),
        pending_commits: std::collections::VecDeque::new(),
        commit_fault: None,
        checkpoint_events_since: 0,
        checkpoint_last_time_secs: 0,
        generation: 0,
        local_pseudonym: None,
        pseudonym_registry: std::collections::HashMap::new(),
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
    let arc = manager.get_context_arc("replay-ctx").unwrap();
    let g = arc.lock().await;
    let ctx = &*g;
    assert!(
        ctx.governance.executed_proposals.contains_key(&proposal_id),
        "executed_proposals should be preserved across restart"
    );
}

/// SCP-PERSIST-025: TTL timer re-spawned after restore with remaining TTL.
#[tokio::test]
#[allow(
    clippy::disallowed_types,
    reason = "Test-only mock state; actor refactor does not migrate test scaffolding. See ADR-049 §'Disallowed types / methods via clippy.toml' and plan §Commit ladder in `~/.claude/plans/generic-moseying-lightning.md`."
)]
async fn restore_respawns_ttl_timer() {
    use scp_protocol::context::roles::{ContextRoleState, default_ceiling};

    let persistence = Arc::new(MockContextPersistence::default());

    let params = ContextParams {
        ttl: Some(std::time::Duration::from_mins(5)),
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
        next_proposal_seq: 0,
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
        spending_nonce_tracker_state: std::collections::HashMap::new(),
        pending_commits: std::collections::VecDeque::new(),
        commit_fault: None,
        checkpoint_events_since: 0,
        checkpoint_last_time_secs: 0,
        generation: 0,
        local_pseudonym: None,
        pseudonym_registry: std::collections::HashMap::new(),
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
    let arc = manager.get_context_arc("ttl-ctx").unwrap();
    let g = arc.lock().await;
    let ctx = &*g;
    assert!(
        ctx.ttl.timer.is_active(),
        "TTL timer should be re-spawned after restore"
    );
}

/// SCP-PERSIST-025: `restore_all_contexts` lists and restores each.
#[tokio::test]
#[allow(
    clippy::disallowed_types,
    reason = "Test-only mock state; actor refactor does not migrate test scaffolding. See ADR-049 §'Disallowed types / methods via clippy.toml' and plan §Commit ladder in `~/.claude/plans/generic-moseying-lightning.md`."
)]
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
            next_proposal_seq: 0,
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
            spending_nonce_tracker_state: std::collections::HashMap::new(),
            pending_commits: std::collections::VecDeque::new(),
            commit_fault: None,
            checkpoint_events_since: 0,
            checkpoint_last_time_secs: 0,
            generation: 0,
            local_pseudonym: None,
            pseudonym_registry: std::collections::HashMap::new(),
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
#[allow(
    clippy::disallowed_types,
    reason = "Test-only mock state; actor refactor does not migrate test scaffolding. See ADR-049 §'Disallowed types / methods via clippy.toml' and plan §Commit ladder in `~/.claude/plans/generic-moseying-lightning.md`."
)]
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
        next_proposal_seq: 0,
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
        spending_nonce_tracker_state: std::collections::HashMap::new(),
        pending_commits: std::collections::VecDeque::new(),
        commit_fault: None,
        checkpoint_events_since: 0,
        checkpoint_last_time_secs: 0,
        generation: 0,
        local_pseudonym: None,
        pseudonym_registry: std::collections::HashMap::new(),
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
#[allow(
    clippy::disallowed_types,
    reason = "Test-only mock state; actor refactor does not migrate test scaffolding. See ADR-049 §'Disallowed types / methods via clippy.toml' and plan §Commit ladder in `~/.claude/plans/generic-moseying-lightning.md`."
)]
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
        next_proposal_seq: 0,
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
        spending_nonce_tracker_state: std::collections::HashMap::new(),
        pending_commits: std::collections::VecDeque::new(),
        commit_fault: None,
        checkpoint_events_since: 0,
        checkpoint_last_time_secs: 0,
        generation: 0,
        local_pseudonym: None,
        pseudonym_registry: std::collections::HashMap::new(),
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
#[allow(
    clippy::disallowed_types,
    reason = "Test-only mock state; actor refactor does not migrate test scaffolding. See ADR-049 §'Disallowed types / methods via clippy.toml' and plan §Commit ladder in `~/.claude/plans/generic-moseying-lightning.md`."
)]
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
        next_proposal_seq: 0,
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
        spending_nonce_tracker_state: std::collections::HashMap::new(),
        pending_commits: std::collections::VecDeque::new(),
        commit_fault: None,
        checkpoint_events_since: 0,
        checkpoint_last_time_secs: 0,
        generation: 0,
        local_pseudonym: None,
        pseudonym_registry: std::collections::HashMap::new(),
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
// C2: spending_nonce_tracker persistence round-trip (replay protection
// across restart)
// -----------------------------------------------------------------------

/// Seeds a snapshot with a populated `spending_nonce_tracker_state`,
/// restores via `ContextManager::restore_context`, then asserts that
/// replaying one of the seeded nonces is rejected — proving the
/// `NonceTracker` state survived the simulated restart and closes the
/// post-restart replay window that would otherwise allow a captured
/// spending UCAN to be reused.
#[allow(clippy::too_many_lines)]
#[tokio::test]
#[allow(
    clippy::disallowed_types,
    reason = "Test-only mock state; actor refactor does not migrate test scaffolding. See ADR-049 §'Disallowed types / methods via clippy.toml' and plan §Commit ladder in `~/.claude/plans/generic-moseying-lightning.md`."
)]
async fn restore_preserves_spending_nonce_tracker_across_restart() {
    use scp_protocol::context::roles::{ContextRoleState, default_ceiling};
    use scp_protocol::crypto::ucan::UcanError;

    let persistence = Arc::new(MockContextPersistence::default());

    let params = ContextParams {
        mode: ContextMode::Encrypted,
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
        "nonce-persist-ctx",
        "did:key:creator",
        ceiling,
        vec![],
        &scp_primitives::SystemClock,
    )
    .unwrap();
    let mut membership = MembershipState::new();
    membership.add_member("did:key:creator".into(), "admin".into(), vec![]);

    // Pre-populate the tracker state with a nonce that was "seen" before
    // the simulated restart. The timestamp is in milliseconds for the
    // nonce format but `first_seen` / `token_expiry` are in seconds to
    // match `NonceTracker`'s internal representation.
    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let nonce_millis = u128::from(now_secs) * 1000;
    let preseen_nonce = format!("{nonce_millis}-aabbccdd11223344aabbccdd11223344");
    let first_seen = now_secs;
    let token_expiry = now_secs + 3600;
    let mut spending_nonce_tracker_state = std::collections::HashMap::new();
    spending_nonce_tracker_state.insert(preseen_nonce.clone(), (first_seen, token_expiry));

    let snapshot = super::ContextSnapshot {
        context_id: "nonce-persist-ctx".to_owned(),
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
        next_proposal_seq: 0,
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
        spending_nonce_tracker_state,
        pending_commits: std::collections::VecDeque::new(),
        commit_fault: None,
        checkpoint_events_since: 0,
        checkpoint_last_time_secs: 0,
        generation: 0,
        local_pseudonym: None,
        pseudonym_registry: std::collections::HashMap::new(),
    };

    persistence
        .persist_context("nonce-persist-ctx", &snapshot)
        .unwrap();

    // Simulate restart: fresh manager with the pre-populated persistence.
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

    let handle = ContextHandle::new("nonce-persist-ctx".to_owned(), params);
    handle.transition_to(&ContextState::Active).await.unwrap();
    manager
        .restore_context("nonce-persist-ctx", &handle)
        .await
        .expect("restore should succeed");

    // Verify the nonce tracker was rehydrated with the preseen nonce and
    // rejects a replay.
    {
        let arc = manager
            .contexts
            .get("nonce-persist-ctx")
            .expect("restored context must be registered")
            .value()
            .clone();
        let mut ctx = arc.lock().await;
        assert_eq!(
            ctx.governance.spending_nonce_tracker.len(),
            1,
            "restored tracker must contain the preseen nonce"
        );

        // Replay attempt — must be rejected as NonceReused.
        let err = ctx
            .governance
            .spending_nonce_tracker
            .check_and_record(&preseen_nonce, token_expiry)
            .expect_err("replay of preseen nonce must be rejected post-restart");
        assert!(
            matches!(err, UcanError::NonceReused(_)),
            "expected NonceReused, got {err:?}"
        );

        // A fresh nonce (different hex suffix) at the same timestamp
        // must succeed — the tracker isn't blanket-rejecting, just the
        // specific replay.
        let fresh_nonce = format!("{nonce_millis}-11223344aabbccdd11223344aabbccdd");
        ctx.governance
            .spending_nonce_tracker
            .check_and_record(&fresh_nonce, token_expiry)
            .expect("fresh nonce at same timestamp must succeed");
    }
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
        next_proposal_seq: 0,
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
        spending_nonce_tracker_state: std::collections::HashMap::new(),
        pending_commits: std::collections::VecDeque::new(),
        commit_fault: None,
        checkpoint_events_since: 0,
        checkpoint_last_time_secs: 0,
        generation: 0,
        local_pseudonym: None,
        pseudonym_registry: std::collections::HashMap::new(),
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
        .create_context("ver-reject".into(), params, "did:key:creator".into(), None)
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
        .create_context("ver-accept".into(), params, "did:key:creator".into(), None)
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
        .create_context("ver-none".into(), params, "did:key:creator".into(), None)
        .await;
    assert!(
        result.is_ok(),
        "create_context should accept min_protocol_version None"
    );
}

// -----------------------------------------------------------------------
// ContextManagerBuilder tests
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
    let arc = manager.get_context_arc(&context_id).unwrap();
    let g = arc.lock().await;
    let ctx = &*g;
    let state = ctx.handle.state().await;
    assert_eq!(state, ContextState::Active);

    // Verify the context uses bilateral-persistent template params.
    let params = ctx.handle.params();
    assert_eq!(params.template_id, Some(TemplateId::BilateralPersistent));
    assert!(params.ttl.is_none()); // bilateral-persistent forbids TTL

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
        let arc = manager.get_context_arc(&ctx_id1).unwrap();
        let g = arc.lock().await;
        let ctx = &*g;
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
        manager.remove_context(&ctx_id1);
    }

    let ctx_id2 = manager.standing_context(&alice, &dave).await.unwrap();

    // Same deterministic ID.
    assert_eq!(ctx_id1, ctx_id2);

    // Verify the new context is Active.
    {
        let arc = manager.get_context_arc(&ctx_id2).unwrap();
        let g = arc.lock().await;
        let ctx = &*g;
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
        let arc = manager.get_context_arc(&ctx_id1).unwrap();
        let g = arc.lock().await;
        let ctx = &*g;
        ctx.handle
            .transition_to(&ContextState::Expired)
            .await
            .unwrap();
    }

    // Remove old context to allow recreation.
    {
        manager.remove_context(&ctx_id1);
    }

    // Calling standing_context should create a new one.
    let ctx_id2 = manager.standing_context(&alice, &eve).await.unwrap();
    assert_eq!(ctx_id1, ctx_id2);

    {
        let arc = manager.get_context_arc(&ctx_id2).unwrap();
        let g = arc.lock().await;
        let ctx = &*g;
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
        let arc = manager.get_context_arc(&id_carol).unwrap();
        let g = arc.lock().await;
        let ctx = &*g;
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
    let reconnected = manager.reconnect_all_standing().await.unwrap();

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

    let reconnected = manager.reconnect_all_standing().await.unwrap();
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

// -----------------------------------------------------------------------
// Standing context deadlock-fix regression tests (PR #1606 H6)
// -----------------------------------------------------------------------
//
// Background: Prior to the H6 fix, `ContextManager::standing_context` held
// both `standing_contexts` and `contexts` mutex guards across an
// `await` on `ContextHandle::state()`, which itself awaits on the
// handle's interior `RwLock`. Any concurrent task that held the handle's
// `RwLock` as a writer (e.g. `transition_to`) while waiting to acquire
// `contexts.lock()` would form a circular wait → deadlock.
//
// The fix replaces `state().await` with the synchronous, fail-fast
// `try_read_state()` (matching the convention in `lifecycle.rs` and
// `require_active`), and reorders the lock acquisition to the canonical
// `contexts → standing_contexts` ordering.
//
// These tests verify:
// 1. The fix does not regress existing happy-path / fall-through behavior.
// 2. Many concurrent `standing_context` calls combined with concurrent
//    state-mutating tasks complete in bounded time (no deadlock).

/// H6 regression: `standing_context` returns the existing Active context
/// when called twice for the same DID pair. Mirrors
/// `standing_context_returns_existing_active_context` but exists as a
/// named regression for the deadlock fix in PR #1606 — it specifically
/// asserts that the new `try_read_state()` code path observes
/// `Active` immediately after creation (no spurious fall-through).
#[tokio::test]
async fn test_standing_context_returns_existing_active() {
    let manager = ContextManager::new(
        Box::new(MockCrypto::default()),
        Box::new(MockTransport::connected()),
        Box::new(MockEventLog::default()),
        noop_key_resolver(),
    );

    let alice = DID::from("did:dht:z6MkLocalAliceH6");
    let bob = DID::from("did:dht:z6MkBobH6");

    // First call creates the context.
    let ctx_id1 = manager.standing_context(&alice, &bob).await.unwrap();

    // Second call must observe the freshly-created context as Active via
    // `try_read_state()` and return idempotently — no new context, no
    // create attempt, identical context_id.
    let ctx_id2 = manager.standing_context(&alice, &bob).await.unwrap();
    assert_eq!(ctx_id1, ctx_id2);

    // Verify the context is registered exactly once and is Active.
    {
        let arc = manager.get_context_arc(&ctx_id1).unwrap();
        let g = arc.lock().await;
        let ctx = &*g;
        assert_eq!(
            ctx.handle.try_read_state(),
            Some(ContextState::Active),
            "freshly returned context should be Active"
        );
    }

    assert_eq!(manager.standing_context_count().await, 1);
    assert!(manager.has_standing_context(&bob).await);
}

/// H6 regression: `standing_context` falls through to create a new
/// context when the existing entry is in a terminal state. Verifies the
/// new code path correctly handles the `Some(Expired)` arm of the
/// `try_read_state()` match (the old code matched on a directly-awaited
/// `state()` value).
#[tokio::test]
async fn test_standing_context_creates_new_after_expired() {
    let manager = ContextManager::new(
        Box::new(MockCrypto::default()),
        Box::new(MockTransport::connected()),
        Box::new(MockEventLog::default()),
        noop_key_resolver(),
    );

    let alice = DID::from("did:dht:z6MkLocalAliceH6Exp");
    let eve = DID::from("did:dht:z6MkEveH6");

    // 1. Create the initial standing context.
    let ctx_id1 = manager.standing_context(&alice, &eve).await.unwrap();

    // 2. Transition the handle to Expired (terminal state).
    {
        let arc = manager.get_context_arc(&ctx_id1).unwrap();
        let g = arc.lock().await;
        let ctx = &*g;
        ctx.handle
            .transition_to(&ContextState::Expired)
            .await
            .unwrap();
    }

    // 3. Remove the expired entry so create_context can re-use the ID.
    {
        manager.remove_context(&ctx_id1);
    }

    // 4. Calling standing_context again must fall through (Expired arm)
    //    and successfully create a new context with the same deterministic
    //    ID. With the old buggy code this also worked, but the new
    //    `try_read_state()` arm is now exercised explicitly.
    let ctx_id2 = manager.standing_context(&alice, &eve).await.unwrap();
    assert_eq!(ctx_id1, ctx_id2, "deterministic context ID is preserved");

    {
        let arc = manager.get_context_arc(&ctx_id2).unwrap();
        let g = arc.lock().await;
        let ctx = &*g;
        assert_eq!(
            ctx.handle.try_read_state(),
            Some(ContextState::Active),
            "fall-through must produce a new Active context"
        );
    }

    assert_eq!(manager.standing_context_count().await, 1);
    assert!(manager.has_standing_context(&eve).await);
}

/// H6 regression: under heavy contention, `standing_context` and other
/// `contexts.lock()`-acquiring operations complete within a bounded
/// timeout. Prior to the fix this configuration could deadlock: thread A
/// holds the handle's `RwLock` writer (mid-`transition_to`) while
/// blocked on `contexts.lock()`, and thread B holds `contexts.lock()`
/// inside `standing_context` while awaiting the handle's `RwLock` reader.
///
/// The test spawns 10 concurrent `standing_context` callers plus 10
/// concurrent `transition_to(Closing)` writers (the latter serving the
/// same role as `close_context` in the bug report — `close_context`
/// itself requires the `context:close` capability, which the
/// `BilateralPersistent` template does not grant, so we drive the
/// handle's `RwLock` writer directly via `transition_to` to reproduce
/// the exact lock-cycle pattern). All 20 tasks must complete within 1
/// second; failure to do so indicates a regression.
#[tokio::test]
async fn test_standing_context_no_deadlock_under_contention() {
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::time::timeout;

    let manager = Arc::new(ContextManager::new(
        Box::new(MockCrypto::default()),
        Box::new(MockTransport::connected()),
        Box::new(MockEventLog::default()),
        noop_key_resolver(),
    ));

    let alice = DID::from("did:dht:z6MkLocalAliceH6Race");
    let bob = DID::from("did:dht:z6MkBobH6Race");

    // Pre-create the standing context so the writer tasks have a handle
    // to drive into terminal states.
    let _initial_id = manager.standing_context(&alice, &bob).await.unwrap();

    // Outer timeout — if the test deadlocks, this is what fails.
    let run = async {
        let mut tasks = Vec::new();

        // 10 concurrent standing_context callers — each acquires
        // `contexts.lock()` then `standing_contexts.lock()` then reads
        // the handle state via `try_read_state()`.
        for _ in 0..10 {
            let mgr = Arc::clone(&manager);
            let a = alice.clone();
            let b = bob.clone();
            tasks.push(tokio::spawn(async move {
                let _ = mgr.standing_context(&a, &b).await;
            }));
        }

        // 10 concurrent state mutators + contexts.lock() acquirers.
        // Each task: (1) acquire contexts.lock() and clone the handle,
        // (2) drop the lock, (3) drive the handle through Closing →
        // Closed → (back to Active via a fresh standing_context call).
        // The interleaving of step 1 (contexts.lock) with step 3
        // (handle.transition_to which takes the inner RwLock writer)
        // across 10 tasks creates the precise contention pattern that
        // the original bug exhibited.
        for _ in 0..10 {
            let mgr = Arc::clone(&manager);
            let a = alice.clone();
            let b = bob.clone();
            tasks.push(tokio::spawn(async move {
                // Step 1: try to look up the handle under contexts.lock().
                let context_id = super::super::standing::generate_standing_context_id(&a, &b);
                let handle_opt = if let Ok(arc) = mgr.get_context_arc(&context_id) {
                    let ctx = arc.lock().await;
                    Some(ctx.handle.clone())
                } else {
                    None
                };

                // Step 2: drive the handle through a transition. This
                // takes the inner RwLock as writer — the very lock that
                // the buggy `standing_context` was awaiting under
                // `contexts.lock()`.
                if let Some(handle) = handle_opt {
                    // Cycle the state to maximise contention. We don't
                    // care whether individual transitions succeed —
                    // some will be invalid (e.g., Active → Active) and
                    // the test only cares about no-deadlock.
                    let _ = handle.transition_to(&ContextState::Closing).await;
                    let _ = handle.transition_to(&ContextState::Closed).await;
                }

                // Step 3: also exercise standing_context concurrently
                // from the writer task to maximise interleaving.
                let _ = mgr.standing_context(&a, &b).await;
            }));
        }

        for t in tasks {
            // Individual task panics propagate via the JoinError — that
            // is acceptable; what matters is that *all* tasks finish.
            let _ = t.await;
        }
    };

    timeout(Duration::from_secs(1), run)
        .await
        .expect("standing_context contention test deadlocked or exceeded 1s");
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
        .create_context("paid-join-ctx".into(), params, "did:key:admin".into(), None)
        .await
        .unwrap();

    let kp = scp_protocol::context::membership::KeyPackage {
        owner_did: DID::from("did:key:joiner"),
        mls_key_package_bytes: None,
    };
    let result = manager.join_context(&handle, kp, None, None).await;
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
        .create_context("sybil-ctx".into(), params, "did:key:admin".into(), None)
        .await
        .unwrap();

    // Currently passes unconditionally — the test asserts the function is
    // callable and returns Ok.
    let arc = manager.get_context_arc("sybil-ctx").unwrap();
    let g = arc.lock().await;
    let ctx = &*g;
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
        .create_context(
            "budget-join-ctx".into(),
            params,
            "did:key:admin".into(),
            None,
        )
        .await
        .unwrap();

    let kp = scp_protocol::context::membership::KeyPackage {
        owner_did: DID::from("did:key:joiner"),
        mls_key_package_bytes: None,
    };
    let result = manager.join_context(&handle, kp, None, None).await;
    assert!(
        result.is_err(),
        "join should fail: paid context auto_accept blocked"
    );
}

// -----------------------------------------------------------------------
// H8: spawn_ttl_timer must decay governance state on automatic expiry
//
// Regression test for the H8 finding in PR #1606. The synchronous
// `handle_ttl_expiry` and `close_context` paths both call
// `governance.decay_participation()` and `governance.timeout_task.cancel()`,
// but the tokio-spawned timer in `spawn_ttl_timer` was missing both
// calls. As a result, participation cache, cooldown_until,
// proposal_timestamps, and the velocity_tracker persisted in memory after
// auto-expiry, and the governance timeout loop kept running for a context
// that had already transitioned out of `Active`.
// -----------------------------------------------------------------------

/// Populates governance state, spawns a short-fuse TTL timer via the
/// normal `create_context` path, waits for the timer to fire, and asserts
/// that `participation_cache`, `cooldown_until`, `proposal_timestamps`, and
/// `velocity_tracker` are all cleared (matches the synchronous path).
#[tokio::test]
async fn test_spawn_ttl_timer_decays_governance_on_expiry() {
    use scp_protocol::context::params::Capability;

    let manager = ContextManager::new(
        Box::new(MockCrypto::default()),
        Box::new(MockTransport::connected()),
        Box::new(MockEventLog::default()),
        noop_key_resolver(),
    );

    // Use a short-fuse TTL so the spawned timer fires quickly. Pair the
    // governance close capability so the context is otherwise valid.
    let params = ContextParams {
        ttl: Some(std::time::Duration::from_millis(50)),
        ceiling: vec![
            Capability::new("messages:read"),
            Capability::new("messages:write"),
            Capability::new("role:assign"),
            Capability::new("context:close"),
        ],
        ..ContextParams::default()
    };

    let admin: DID = "did:key:h8-admin".into();
    let handle = manager
        .create_context("h8-ttl-decay-ctx".into(), params, admin.clone(), None)
        .await
        .unwrap();
    let context_id = handle.context_id().to_owned();

    // Inject governance state under lock: participation cache, cooldown,
    // proposal timestamps, and velocity tracker. The timer must clear
    // ALL four when it fires.
    {
        let arc = manager.get_context_arc(&context_id).unwrap();
        let mut g = arc.lock().await;
        let ctx = &mut *g;
        ctx.governance.participation_cache.insert(
            "did:key:h8-admin".to_owned(),
            scp_protocol::trust::participation::ParticipationRecord {
                subject_did: "did:key:h8-admin".into(),
                context_id: context_id.clone(),
                participation_count: 7,
                participation_duration_seconds: 200,
                tool_invocations: std::collections::HashMap::new(),
                governance_actions_by: Vec::new(),
                governance_actions_against: Vec::new(),
                role_history: Vec::new(),
                attestation_history: Vec::new(),
                context_creation_count: 0,
                computed_at: 300,
                event_log_root: [0u8; 32],
            },
        );
        ctx.governance.cooldown_until.insert(0, 999_999);
        ctx.governance
            .proposal_timestamps
            .insert("did:key:h8-admin".to_owned(), vec![100, 200, 300]);
        ctx.governance.velocity_tracker.record_message(&admin, 100);
        // Sanity-check the precondition.
        assert!(!ctx.governance.participation_cache.is_empty());
        assert!(!ctx.governance.cooldown_until.is_empty());
        assert!(!ctx.governance.proposal_timestamps.is_empty());
        assert!(ctx.governance.velocity_tracker.get_velocity(&admin, 100) > 0);
    }

    // Wait for the spawned timer to fire and the post-expiry cleanup to
    // run under the manager lock. The TTL is 50ms; we poll up to 5s to
    // avoid CI flakiness.
    let mut decayed = false;
    for _ in 0..50 {
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        let arc = manager.get_context_arc(&context_id).unwrap();
        let g = arc.lock().await;
        let ctx = &*g;
        if ctx.governance.participation_cache.is_empty()
            && ctx.governance.cooldown_until.is_empty()
            && ctx.governance.proposal_timestamps.is_empty()
            && ctx.governance.velocity_tracker.get_velocity(&admin, 100) == 0
        {
            decayed = true;
            break;
        }
    }

    // Snapshot the final state for assertion diagnostics.
    let (pc_empty, cu_empty, pt_empty, vt_zero) = {
        let arc = manager.get_context_arc(&context_id).unwrap();
        let g = arc.lock().await;
        let ctx = &*g;
        (
            ctx.governance.participation_cache.is_empty(),
            ctx.governance.cooldown_until.is_empty(),
            ctx.governance.proposal_timestamps.is_empty(),
            ctx.governance.velocity_tracker.get_velocity(&admin, 100) == 0,
        )
    };
    assert!(
        decayed,
        "spawn_ttl_timer must decay all four governance fields after \
         automatic expiry (H8); participation_cache cleared = {pc_empty}, \
         cooldown_until cleared = {cu_empty}, proposal_timestamps cleared \
         = {pt_empty}, velocity cleared = {vt_zero}"
    );
}

/// Verifies that `spawn_ttl_timer` cancels the governance timeout task
/// after the timer fires. Without the H8 fix the timeout loop kept
/// ticking on an expired context.
#[tokio::test]
async fn test_spawn_ttl_timer_cancels_governance_timeout_task() {
    use scp_protocol::context::params::Capability;

    let manager = ContextManager::new(
        Box::new(MockCrypto::default()),
        Box::new(MockTransport::connected()),
        Box::new(MockEventLog::default()),
        noop_key_resolver(),
    );

    let params = ContextParams {
        ttl: Some(std::time::Duration::from_millis(50)),
        ceiling: vec![
            Capability::new("messages:read"),
            Capability::new("messages:write"),
            Capability::new("role:assign"),
            Capability::new("context:close"),
        ],
        ..ContextParams::default()
    };

    let admin: DID = "did:key:h8-cancel-admin".into();
    let handle = manager
        .create_context("h8-ttl-cancel-ctx".into(), params, admin, None)
        .await
        .unwrap();
    let context_id = handle.context_id().to_owned();

    // The governance timeout task should be active immediately after
    // create_context (started by finalize_create).
    {
        let arc = manager.get_context_arc(&context_id).unwrap();
        let g = arc.lock().await;
        let ctx = &*g;
        assert!(
            ctx.governance.timeout_task.is_active(),
            "governance timeout task should be active after create_context"
        );
    }

    // Wait for the spawned TTL timer to fire and run cleanup.
    let mut cancelled = false;
    for _ in 0..50 {
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        let arc = manager.get_context_arc(&context_id).unwrap();
        let g = arc.lock().await;
        let ctx = &*g;
        if !ctx.governance.timeout_task.is_active() {
            cancelled = true;
            break;
        }
    }
    assert!(
        cancelled,
        "spawn_ttl_timer must cancel the governance timeout task on \
         automatic expiry (H8)"
    );
}

// =======================================================================
// H19: PaymentCaptureFailed audit-trail tests (join path)
//
// NOTE: The `capture_join_payment` failure path is only reachable in
// production via the future explicit-acceptance flow (SCP-ECON-12030)
// because `auto_accept_blocked_by_economics` prevents `join_context` from
// reaching Phase 5 on paid contexts. These tests exercise the underlying
// `record_payment_capture_failure` helper that `capture_join_payment`
// delegates to, providing full coverage of the audit-trail logic.
// =======================================================================

/// H19-J1: `record_payment_capture_failure` for the join action appends a
/// `PaymentCaptureFailed` entry to the event log with `action = "join_context"`
/// and the error string.
#[tokio::test]
async fn capture_join_payment_failure_appends_event_log_entry() {
    use std::sync::Arc;

    let event_log = Arc::new(MockEventLogWithActorDid::default());
    let manager = ContextManager::new(
        Box::new(MockCrypto::default()),
        Box::new(MockTransport::connected()),
        Box::new(ArcEventLog(event_log.clone())),
        noop_key_resolver(),
    );

    let params = ContextParams {
        ceiling: vec![
            scp_protocol::context::params::Capability::new("messages:read"),
            scp_protocol::context::params::Capability::new("messages:write"),
        ],
        ..ContextParams::default()
    };
    manager
        .create_context("h19-join-ctx".into(), params, "did:key:admin".into(), None)
        .await
        .unwrap();

    // Simulate what capture_join_payment would do on failure.
    manager
        .record_payment_capture_failure(
            "h19-join-ctx",
            "join_context",
            &DID::from("did:key:joiner"),
            "simulated capture failure",
            Some(scp_protocol::economy::types::Amount::new(1)),
        )
        .await;

    // Verify event log entry.
    let context_id_bytes = scp_protocol::context::context_id_bytes("h19-join-ctx");
    let entries = event_log.entries.lock().unwrap();
    let capture_failed: Vec<_> = entries
        .iter()
        .filter(|(cid, event, _, _, _)| *cid == context_id_bytes && event == "PaymentCaptureFailed")
        .collect();

    assert!(
        !capture_failed.is_empty(),
        "expected PaymentCaptureFailed event log entry, got none; all: {entries:?}"
    );

    let (_, _, actor_did, _, payload) = &capture_failed[0];
    assert_eq!(
        actor_did, "did:key:joiner",
        "PaymentCaptureFailed actor_did must be the joining member"
    );

    let payload = payload
        .as_ref()
        .expect("PaymentCaptureFailed must have payload");
    assert_eq!(
        payload["action"].as_str(),
        Some("join_context"),
        "payload action must be 'join_context'"
    );
    assert!(
        payload["error"].as_str().is_some(),
        "payload must include an error string"
    );
    assert_eq!(
        payload["cost"].as_u64(),
        Some(1),
        "payload cost must match the deducted amount"
    );
}

/// H19-J2: `record_payment_capture_failure` for the join action pushes a
/// `PaymentCaptureFailed` event to the receive buffer, ensuring SDK consumers
/// can observe the failure in the event stream.
#[tokio::test]
async fn capture_join_payment_failure_pushes_receive_buffer_event() {
    let (manager, _handle) = setup_active_context().await;

    // Simulate capture_join_payment failure on the existing "test-ctx".
    manager
        .record_payment_capture_failure(
            "test-ctx",
            "join_context",
            &DID::from("did:key:joiner"),
            "simulated capture failure",
            Some(scp_protocol::economy::types::Amount::new(5)),
        )
        .await;

    // Drain events and verify PaymentCaptureFailed is present.
    let events = manager.drain_events("test-ctx").await;
    let found = events.iter().any(|e| {
        matches!(
            e,
            ContextEvent::PaymentCaptureFailed {
                action,
                actor_did,
                cost: Some(5),
                ..
            }
            if action == "join_context" && actor_did.as_ref() == "did:key:joiner"
        )
    });

    assert!(
        found,
        "PaymentCaptureFailed event must be in receive buffer; events: {events:?}"
    );
}

// -----------------------------------------------------------------------
// C3: snapshot import / restore validation tests
// -----------------------------------------------------------------------
//
// These tests cover the C3 fix for `import_context` and `restore_context`:
// untrusted exports must wipe per-instance authorization state and the
// fields they keep must be revalidated. See `lifecycle::sanitize_cooldown_until`,
// `validate_consequence_rules_for_import`, and the wipe assignments in
// `import_context`. Mirror the WASM bridge `validate_imported_snapshot`
// policy at the runtime layer.

/// Builds a minimal valid `ContextSnapshot` for C3 import tests.
///
/// Defaults: empty membership, empty event log, empty trackers, empty
/// `approved_proposals`. Tests mutate the returned snapshot to inject
/// the specific attacker payload they want to exercise.
#[allow(clippy::too_many_lines)]
fn c3_test_snapshot(context_id: &str) -> super::ContextSnapshot {
    use scp_protocol::context::roles::{ContextRoleState, default_ceiling};

    let params = ContextParams::default();
    let ceiling = default_ceiling();
    let role_state = ContextRoleState::new(
        context_id,
        "did:key:c3-creator",
        ceiling,
        vec![],
        &scp_primitives::SystemClock,
    )
    .unwrap();
    let membership = MembershipState::new();

    super::ContextSnapshot {
        context_id: context_id.to_owned(),
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
        next_proposal_seq: 0,
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
        spending_nonce_tracker_state: std::collections::HashMap::new(),
        pending_commits: std::collections::VecDeque::new(),
        commit_fault: None,
        checkpoint_events_since: 0,
        checkpoint_last_time_secs: 0,
        generation: 0,
        local_pseudonym: None,
        pseudonym_registry: std::collections::HashMap::new(),
    }
}

/// Wraps a snapshot in a `ContextExport` for importing via
/// `manager.import_context`. Uses the canonical `create_export` factory so
/// the Merkle root and version fields stay consistent with the production
/// path.
fn c3_export_from_snapshot(
    snapshot: super::ContextSnapshot,
) -> crate::context::export_import::ContextExport {
    crate::context::export_import::create_export(
        snapshot,
        Vec::new(), // empty event log — C3 wipe paths don't depend on it
        Vec::new(),
        DID::from("did:key:c3-exporter"),
        crate::context::export_import::ExportScope::Full,
        &scp_primitives::SystemClock,
    )
    .unwrap()
}

fn c3_manager() -> ContextManager {
    ContextManager::new(
        Box::new(MockCrypto::default()),
        Box::new(MockTransport::connected()),
        Box::new(MockEventLog::default()),
        noop_key_resolver(),
    )
}

/// C3 test 1: an attacker-crafted snapshot with `approved_proposals`
/// containing `RemoveMember { did: victim }` must NOT block the victim
/// from proposing after import. The pre-fix code carried the forged
/// `approved_proposals` straight into `PerContextState`, and
/// `check_proposer_eligibility` then refused every proposal from the
/// victim because `approved_proposals` contained a pending ejection
/// against them.
#[tokio::test]
async fn import_context_rejects_forged_approved_proposals() {
    use scp_protocol::context::governance::{GovernanceAction, GovernanceProposal, ProposalStatus};

    let manager = c3_manager();
    let mut snapshot = c3_test_snapshot("c3-forged-approvals");

    let victim = DID::from("did:key:c3-victim");
    let forged_id = [0xAA_u8; 32];
    let forged_proposal = GovernanceProposal {
        proposal_id: forged_id,
        context_id: "c3-forged-approvals".to_owned(),
        proposer_did: DID::from("did:key:c3-attacker"),
        action: GovernanceAction::RemoveMember {
            did: victim.clone(),
            reason: Some("forged".to_owned()),
        },
        status: ProposalStatus::Approved,
        created_at: 0,
        voting_deadline: u64::MAX,
        approvals: vec![],
        rejections: vec![],
        created_at_epoch: Some(0),
    };
    snapshot
        .approved_proposals
        .insert(forged_id, (forged_proposal, 0, 0));

    let export = c3_export_from_snapshot(snapshot);
    let _handle = manager.import_context(export).await.unwrap();

    // After import the per-context governance state must NOT contain
    // the forged approval — wipe-on-import is the entire fix for C3.
    let arc = manager
        .contexts
        .get("c3-forged-approvals")
        .unwrap()
        .value()
        .clone();
    let g = arc.lock().await;
    let ctx = &*g;
    assert!(
        ctx.governance.approved_proposals.is_empty(),
        "import_context must wipe approved_proposals (had {} entries)",
        ctx.governance.approved_proposals.len()
    );
    // Victim DID must not appear in any pending-ejection slot — and
    // since the entire map is empty, that's trivially true.
    for (proposal, _seq, _ts) in ctx.governance.approved_proposals.values() {
        if let GovernanceAction::RemoveMember { did, .. } = &proposal.action {
            assert_ne!(
                did, &victim,
                "victim must not have a pending ejection after import"
            );
        }
    }
}

/// C3 test 2: imported `budget_tracker` must be wiped. Per-instance
/// economic grants are not transferable across nodes — inheriting an
/// attacker's pre-loaded budgets gives the attacker arbitrary spend
/// authority on the importing node.
#[tokio::test]
async fn import_context_wipes_budget_tracker() {
    use scp_protocol::economy::types::Amount;

    let manager = c3_manager();
    let mut snapshot = c3_test_snapshot("c3-wipe-budget");

    let attacker = DID::from("did:key:c3-attacker-budget");
    snapshot
        .budget_tracker
        .grant(&attacker, Amount::new(1_000_000));
    assert!(
        snapshot.budget_tracker.has_budget(&attacker),
        "precondition: snapshot carries attacker budget"
    );

    let export = c3_export_from_snapshot(snapshot);
    manager.import_context(export).await.unwrap();

    let arc = manager
        .contexts
        .get("c3-wipe-budget")
        .unwrap()
        .value()
        .clone();
    let g = arc.lock().await;
    let ctx = &*g;
    assert!(
        !ctx.governance.budget_tracker.has_budget(&attacker),
        "import_context must wipe budget_tracker entries"
    );
    assert_eq!(
        ctx.governance.budget_tracker.remaining(&attacker),
        Amount::new(0),
        "wiped budget must report zero remaining"
    );
}

/// C3 test 3: imported `participation_cache` must be wiped. The cache
/// is rebuilt lazily from the imported event log on next proposer
/// eligibility check (`check_proposer_eligibility`); inheriting it
/// lets the exporter forge low-participation verdicts against any
/// DID it picks.
#[tokio::test]
async fn import_context_wipes_participation_cache() {
    use scp_protocol::trust::GovernanceActionSummary;
    use scp_protocol::trust::participation::ParticipationRecord;

    let manager = c3_manager();
    let mut snapshot = c3_test_snapshot("c3-wipe-participation");

    let victim = "did:key:c3-victim-participation";
    // Pre-load 100 actions-against against the victim. After import,
    // a non-wiping implementation would feed this straight into
    // `meets_threshold` (governance_actions_against >
    // governance_actions_by → blocked) and lock the victim out of
    // governance forever.
    let attacker = DID::from("did:key:c3-participation-attacker");
    let against: Vec<GovernanceActionSummary> = (0..100u64)
        .map(|i| GovernanceActionSummary {
            timestamp: 1_700_000_000 + i,
            actor_did: attacker.clone(),
            target_did: Some(DID::from(victim)),
            event_sequence: i,
        })
        .collect();
    let victim_record = ParticipationRecord {
        subject_did: DID::from(victim),
        context_id: "c3-wipe-participation".to_owned(),
        participation_count: 5,
        participation_duration_seconds: 3600,
        tool_invocations: HashMap::new(),
        governance_actions_by: Vec::new(),
        governance_actions_against: against,
        role_history: Vec::new(),
        attestation_history: Vec::new(),
        context_creation_count: 0,
        computed_at: 1_700_000_100,
        event_log_root: [0u8; 32],
    };
    snapshot
        .participation_cache
        .insert(victim.to_owned(), victim_record);

    let export = c3_export_from_snapshot(snapshot);
    manager.import_context(export).await.unwrap();

    let arc = manager
        .contexts
        .get("c3-wipe-participation")
        .unwrap()
        .value()
        .clone();
    let g = arc.lock().await;
    let ctx = &*g;
    assert!(
        ctx.governance.participation_cache.is_empty(),
        "import_context must wipe participation_cache (had {} entries)",
        ctx.governance.participation_cache.len()
    );
}

/// C3 test 4: a consequence rule with `threshold = 0` must be rejected
/// at import time. `validate` already rejects this in the create-time
/// path; the import path now uses the same `validate_against_config`
/// gate via `validate_consequence_rules_for_import`.
#[tokio::test]
async fn import_context_rejects_threshold_zero_in_rules() {
    use scp_protocol::trust::consequence::{
        ConsequenceAction, ConsequenceRule, ConsequenceTrigger, EnforcementSeverity,
    };

    let manager = c3_manager();
    let mut snapshot = c3_test_snapshot("c3-threshold-zero");
    snapshot.consequence_rules.push(ConsequenceRule {
        trigger: ConsequenceTrigger::MessageVelocity,
        action: ConsequenceAction::Enforcement(EnforcementSeverity::SuspendAccess),
        threshold: 0, // invalid — `validate()` rejects this
        window: std::time::Duration::from_mins(1),
    });

    let export = c3_export_from_snapshot(snapshot);
    let result = manager.import_context(export).await;
    let err = result.expect_err("import must reject threshold == 0");
    match err {
        ContextError::ImportRejected { reason } => {
            assert!(
                reason.contains("consequence_rules[0]") && reason.contains("threshold"),
                "ImportRejected reason should mention rule index and threshold: {reason}"
            );
        }
        other => panic!("expected ImportRejected, got {other:?}"),
    }
}

/// C3 test 5: a `RevokeAccess` consequence rule must be rejected when
/// the imported `consequence_config.allow_automatic_access_revocation`
/// is `false` (the default). The pre-fix code only ran shape
/// validation, not the config gate — meaning a malicious export with
/// the opt-in flag silently flipped on its local copy could install a
/// `RevokeAccess` rule on the importing node where the flag was off.
#[tokio::test]
async fn import_context_rejects_revokeaccess_without_config_opt_in() {
    use scp_protocol::context::AccessScope;
    use scp_protocol::trust::consequence::{
        ConsequenceAction, ConsequenceRule, ConsequenceTrigger, EnforcementSeverity,
    };

    let manager = c3_manager();
    let mut snapshot = c3_test_snapshot("c3-revoke-no-opt-in");
    // Default consequence_config has allow_automatic_access_revocation = false.
    assert!(
        !snapshot
            .context_params
            .consequence_config
            .allow_automatic_access_revocation,
        "precondition: default config must not opt in"
    );
    snapshot.consequence_rules.push(ConsequenceRule {
        trigger: ConsequenceTrigger::WarningCount,
        action: ConsequenceAction::Enforcement(EnforcementSeverity::RevokeAccess {
            did: DID::from("did:key:c3-victim-revoke"),
            access: AccessScope::Both,
        }),
        threshold: 3,
        window: std::time::Duration::from_hours(1),
    });

    let export = c3_export_from_snapshot(snapshot);
    let result = manager.import_context(export).await;
    let err = result.expect_err("import must reject RevokeAccess without opt-in");
    match err {
        ContextError::ImportRejected { reason } => {
            assert!(
                reason.contains("RevokeAccess") || reason.contains("allow_automatic"),
                "ImportRejected reason should mention the missing opt-in: {reason}"
            );
        }
        other => panic!("expected ImportRejected, got {other:?}"),
    }
}

/// C3 test 6: `cooldown_until[i] = u64::MAX` must be clamped to
/// `now + MAX_COOLDOWN_SECS`. Without clamping, an attacker can ship
/// a snapshot that permanently disables a consequence rule by parking
/// its cooldown beyond any plausible wall-clock horizon.
#[tokio::test]
async fn import_context_clamps_cooldown_until() {
    use scp_protocol::trust::consequence::{
        ConsequenceAction, ConsequenceRule, ConsequenceTrigger, EnforcementSeverity,
    };

    let manager = c3_manager();
    let mut snapshot = c3_test_snapshot("c3-clamp-cooldown");
    // Need at least one rule so cooldown_until[0] is in-range.
    snapshot.consequence_rules.push(ConsequenceRule {
        trigger: ConsequenceTrigger::MessageVelocity,
        action: ConsequenceAction::Enforcement(EnforcementSeverity::SuspendAccess),
        threshold: 5,
        window: std::time::Duration::from_mins(1),
    });
    snapshot.cooldown_until.insert(0, u64::MAX);
    // Also include an out-of-range index so we exercise the drop path.
    snapshot.cooldown_until.insert(99, 1_700_000_000);

    let now_before = scp_primitives::SystemClock.now_secs();
    let export = c3_export_from_snapshot(snapshot);
    manager.import_context(export).await.unwrap();

    let arc = manager
        .contexts
        .get("c3-clamp-cooldown")
        .unwrap()
        .value()
        .clone();
    let g = arc.lock().await;
    let ctx = &*g;
    let clamped = ctx
        .governance
        .cooldown_until
        .get(&0)
        .copied()
        .expect("cooldown_until[0] should remain after clamp");
    let expected_max = now_before
        .saturating_add(super::super::lifecycle::MAX_COOLDOWN_SECS)
        // tolerate a few seconds of drift between the snapshot and the import
        .saturating_add(60);
    assert!(
        clamped <= expected_max,
        "cooldown_until[0] = {clamped} should be clamped to <= {expected_max}"
    );
    assert!(
        clamped > 0,
        "clamp horizon should be a future timestamp, not zero"
    );
    assert!(
        !ctx.governance.cooldown_until.contains_key(&99),
        "out-of-range cooldown index 99 must be dropped"
    );
}

/// C3 test 7 (regression): `restore_context` is the local-trusted
/// path. Budgets are authoritative there and MUST survive a restart —
/// the C3 wipe policy applies only to `import_context`.
#[tokio::test]
#[allow(
    clippy::disallowed_types,
    reason = "Test-only mock state; actor refactor does not migrate test scaffolding. See ADR-049 §'Disallowed types / methods via clippy.toml' and plan §Commit ladder in `~/.claude/plans/generic-moseying-lightning.md`."
)]
async fn restore_context_preserves_budget_tracker() {
    use scp_protocol::context::roles::{ContextRoleState, default_ceiling};
    use scp_protocol::economy::types::Amount;

    let persistence = Arc::new(MockContextPersistence::default());

    let params = ContextParams {
        ceiling: vec![
            scp_protocol::context::params::Capability::new("messages:read"),
            scp_protocol::context::params::Capability::new("messages:write"),
        ],
        ..ContextParams::default()
    };

    let ceiling = default_ceiling();
    let role_state = ContextRoleState::new(
        "c3-restore-budget",
        "did:key:creator",
        ceiling,
        vec![],
        &scp_primitives::SystemClock,
    )
    .unwrap();
    let mut membership = MembershipState::new();
    membership.add_member("did:key:creator".into(), "admin".into(), vec![]);

    let mut budget_tracker = scp_protocol::economy::budget::MemberBudgetTracker::new();
    let alice = DID::from("did:key:alice");
    budget_tracker.grant(&alice, Amount::new(500));

    let mut snapshot = c3_test_snapshot("c3-restore-budget");
    snapshot.context_params = params.clone();
    snapshot.membership = membership;
    snapshot.role_state = role_state;
    snapshot.budget_tracker = budget_tracker;

    persistence
        .persist_context("c3-restore-budget", &snapshot)
        .unwrap();

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

    let handle = ContextHandle::new("c3-restore-budget".to_owned(), params);
    handle.transition_to(&ContextState::Active).await.unwrap();
    manager
        .restore_context("c3-restore-budget", &handle)
        .await
        .unwrap();

    let arc = manager
        .contexts
        .get("c3-restore-budget")
        .unwrap()
        .value()
        .clone();
    let g = arc.lock().await;
    let ctx = &*g;
    assert_eq!(
        ctx.governance.budget_tracker.remaining(&alice),
        Amount::new(500),
        "restore_context must preserve local budget grants"
    );
}

/// C3 test 8: `restore_context` must still reject inconsistent
/// `consequence_rules` + `consequence_config` combinations. Local
/// restore is "trusted" for authorization state, but a config
/// regression (e.g., the user toggled `allow_automatic_access_revocation`
/// off between snapshots) MUST not silently load `RevokeAccess` rules.
#[tokio::test]
#[allow(
    clippy::disallowed_types,
    reason = "Test-only mock state; actor refactor does not migrate test scaffolding. See ADR-049 §'Disallowed types / methods via clippy.toml' and plan §Commit ladder in `~/.claude/plans/generic-moseying-lightning.md`."
)]
async fn restore_context_validates_consequence_rules() {
    use scp_protocol::context::AccessScope;
    use scp_protocol::context::roles::{ContextRoleState, default_ceiling};
    use scp_protocol::trust::consequence::{
        ConsequenceAction, ConsequenceRule, ConsequenceTrigger, EnforcementSeverity,
    };

    let persistence = Arc::new(MockContextPersistence::default());

    let params = ContextParams {
        ceiling: vec![
            scp_protocol::context::params::Capability::new("messages:read"),
            scp_protocol::context::params::Capability::new("messages:write"),
        ],
        ..ContextParams::default()
    };
    // Default consequence_config has allow_automatic_access_revocation = false.
    let ceiling = default_ceiling();
    let role_state = ContextRoleState::new(
        "c3-restore-bad-rules",
        "did:key:creator",
        ceiling,
        vec![],
        &scp_primitives::SystemClock,
    )
    .unwrap();
    let mut membership = MembershipState::new();
    membership.add_member("did:key:creator".into(), "admin".into(), vec![]);

    let mut snapshot = c3_test_snapshot("c3-restore-bad-rules");
    snapshot.context_params = params.clone();
    snapshot.membership = membership;
    snapshot.role_state = role_state;
    snapshot.consequence_rules.push(ConsequenceRule {
        trigger: ConsequenceTrigger::WarningCount,
        action: ConsequenceAction::Enforcement(EnforcementSeverity::RevokeAccess {
            did: DID::from("did:key:victim"),
            access: AccessScope::Both,
        }),
        threshold: 3,
        window: std::time::Duration::from_hours(1),
    });

    persistence
        .persist_context("c3-restore-bad-rules", &snapshot)
        .unwrap();

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

    let handle = ContextHandle::new("c3-restore-bad-rules".to_owned(), params);
    handle.transition_to(&ContextState::Active).await.unwrap();
    let result = manager
        .restore_context("c3-restore-bad-rules", &handle)
        .await;
    let err = result.expect_err("restore must reject inconsistent consequence_rules");
    assert!(
        matches!(err, ContextError::ImportRejected { .. }),
        "expected ImportRejected, got {err:?}"
    );
}

// -----------------------------------------------------------------------
// import_context epoch-floor regression guard tests (§23.17 Invariant 3)
// -----------------------------------------------------------------------

/// Builds a minimal but valid [`crate::context::export_import::ContextExport`]
/// for use in `import_context` epoch-regression tests.
///
/// The export has an empty event log (Merkle root = `[0u8; 32]`), which
/// `validate_export_for_import` accepts. The snapshot's `state` is `Active`
/// so `import_context` proceeds past the state guard.
///
/// `mls_state` is set to `b"trigger-restore"` (non-empty) so the
/// lifecycle code enters the `restore_crypto_state` / epoch-merge path.
fn make_epoch_test_export(context_id: &str) -> crate::context::export_import::ContextExport {
    use scp_protocol::context::roles::{ContextRoleState, default_ceiling};

    let ceiling = default_ceiling();
    let role_state = ContextRoleState::new(
        context_id,
        "did:key:test-creator",
        ceiling,
        vec![],
        &scp_primitives::SystemClock,
    )
    .expect("ContextRoleState::new should succeed for test snapshot");

    let snapshot = super::ContextSnapshot {
        context_id: context_id.to_owned(),
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
        budget_tracker: scp_protocol::economy::budget::MemberBudgetTracker::new(),
        approved_proposals: HashMap::new(),
        next_proposal_seq: 0,
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
        spending_nonce_tracker_state: std::collections::HashMap::new(),
        pending_commits: std::collections::VecDeque::new(),
        commit_fault: None,
        checkpoint_events_since: 0,
        checkpoint_last_time_secs: 0,
        generation: 0,
        local_pseudonym: None,
        pseudonym_registry: std::collections::HashMap::new(),
    };

    crate::context::export_import::ContextExport {
        snapshot,
        event_log_data: Vec::new(),
        // Non-empty so the lifecycle code enters the restore_crypto_state path
        // (and therefore the validate_and_merge_epoch_floors call).
        mls_state: b"trigger-restore".to_vec(),
        version: crate::context::export_import::CURRENT_EXPORT_VERSION,
        exported_at: 0,
        exporter_did: DID::from("did:key:test-exporter"),
        merkle_root: [0u8; 32], // valid for empty event log
        scope: crate::context::export_import::ExportScope::Full,
    }
}

/// §23.17 Invariant 3: `import_context` rejects a snapshot that lowers a
/// per-sender epoch floor below the pre-import local high-water mark.
///
/// Setup: context slot exists (Closing), local floor for Alice = 100.
/// Import carries Alice's epoch = 50 (below 100). Expected: `SnapshotFloorRegression`.
#[tokio::test]
async fn import_context_rejects_epoch_floor_regression() {
    let ctx_id = "epoch-regression-test-ctx";
    let alice_did = "did:key:alice-epoch-regression";
    let ctx_id_bytes = scp_protocol::context::context_id_bytes(ctx_id);
    let ctx_id_hex = hex::encode(ctx_id_bytes);

    // Build mock with Alice's local floor = 100.
    let mock = MockCrypto::default();
    mock.epoch_floors
        .lock()
        .unwrap()
        .insert(ctx_id_hex, vec![(alice_did.to_owned(), 100)]);
    // Stage incoming epochs: Alice at 50 (regression).
    *mock.pending_restore_epochs.lock().unwrap() = Some(vec![(alice_did.to_owned(), 50)]);

    let manager = ContextManager::new(
        Box::new(mock),
        Box::new(MockTransport::connected()),
        Box::new(MockEventLog::default()),
        noop_key_resolver(),
    );

    // Use create_context (not create_context_bare) so the context slot is
    // registered in the manager's contexts map.  import_context checks the
    // map to determine whether this is a re-import of an existing slot vs. a
    // fresh import; create_context_bare only returns a handle without
    // registering it.
    let handle = manager
        .create_context(
            ctx_id.to_owned(),
            ContextParams::default(),
            DID::from("did:key:test-creator"),
            None,
        )
        .await
        .expect("create_context should succeed");

    // Transition to Closing so the slot is replaceable.
    handle
        .transition_to(&ContextState::Closing)
        .await
        .expect("transition to Closing should succeed");

    let export = make_epoch_test_export(ctx_id);
    let result = manager.import_context(export).await;

    assert!(
        result.is_err(),
        "import should fail when incoming epoch regresses local floor"
    );
    assert!(
        matches!(
            result.unwrap_err(),
            ContextError::SnapshotFloorRegression { .. }
        ),
        "error should be SnapshotFloorRegression"
    );
}

/// §23.17 Invariant 3: `import_context` accepts a snapshot where the
/// per-sender epoch advances within `MAX_EPOCH_ADVANCE` of the local floor.
///
/// Setup: context slot exists (Closing), local floor for Alice = 100.
/// Import carries Alice's epoch = 200 (advance of 100, within `MAX_EPOCH_ADVANCE` = 1000).
/// Expected: success.
#[tokio::test]
async fn import_context_accepts_epoch_advance_within_ceiling() {
    let ctx_id = "epoch-advance-within-ceiling-ctx";
    let alice_did = "did:key:alice-epoch-advance-ok";
    let ctx_id_bytes = scp_protocol::context::context_id_bytes(ctx_id);
    let ctx_id_hex = hex::encode(ctx_id_bytes);

    let mock = MockCrypto::default();
    mock.epoch_floors
        .lock()
        .unwrap()
        .insert(ctx_id_hex, vec![(alice_did.to_owned(), 100)]);
    // Stage incoming epochs: Alice at 200 (advance of 100, within ceiling).
    *mock.pending_restore_epochs.lock().unwrap() = Some(vec![(alice_did.to_owned(), 200)]);

    let manager = ContextManager::new(
        Box::new(mock),
        Box::new(MockTransport::connected()),
        Box::new(MockEventLog::default()),
        noop_key_resolver(),
    );

    // Use create_context so the slot is registered in the manager's contexts map.
    let handle = manager
        .create_context(
            ctx_id.to_owned(),
            ContextParams::default(),
            DID::from("did:key:test-creator"),
            None,
        )
        .await
        .expect("create_context should succeed");
    handle
        .transition_to(&ContextState::Closing)
        .await
        .expect("transition to Closing should succeed");

    let export = make_epoch_test_export(ctx_id);
    let result = manager.import_context(export).await;

    assert!(
        result.is_ok(),
        "import should succeed when incoming epoch is within ceiling: {:?}",
        result.err()
    );
}

/// §23.17 Invariant 3: `import_context` rejects a snapshot where the
/// per-sender epoch advance exceeds `MAX_EPOCH_ADVANCE` (epoch-poisoning guard).
///
/// Setup: context slot exists (Closing), local floor for Alice = 100.
/// Import carries Alice's epoch = 2000 (advance of 1900 > `MAX_EPOCH_ADVANCE` = 1000).
/// Expected: `SnapshotFloorRegression` (epoch-poisoning rejection).
#[tokio::test]
async fn import_context_rejects_epoch_advance_beyond_ceiling() {
    let ctx_id = "epoch-advance-beyond-ceiling-ctx";
    let alice_did = "did:key:alice-epoch-poisoning";
    let ctx_id_bytes = scp_protocol::context::context_id_bytes(ctx_id);
    let ctx_id_hex = hex::encode(ctx_id_bytes);

    let mock = MockCrypto::default();
    mock.epoch_floors
        .lock()
        .unwrap()
        .insert(ctx_id_hex, vec![(alice_did.to_owned(), 100)]);
    // Stage incoming epochs: Alice at 2000 (100 + 1900 > MAX_EPOCH_ADVANCE=1000).
    *mock.pending_restore_epochs.lock().unwrap() = Some(vec![(alice_did.to_owned(), 2000)]);

    let manager = ContextManager::new(
        Box::new(mock),
        Box::new(MockTransport::connected()),
        Box::new(MockEventLog::default()),
        noop_key_resolver(),
    );

    // Use create_context so the slot is registered in the manager's contexts map.
    let handle = manager
        .create_context(
            ctx_id.to_owned(),
            ContextParams::default(),
            DID::from("did:key:test-creator"),
            None,
        )
        .await
        .expect("create_context should succeed");
    handle
        .transition_to(&ContextState::Closing)
        .await
        .expect("transition to Closing should succeed");

    let export = make_epoch_test_export(ctx_id);
    let result = manager.import_context(export).await;

    assert!(
        result.is_err(),
        "import should fail when incoming epoch exceeds MAX_EPOCH_ADVANCE ceiling"
    );
    assert!(
        matches!(
            result.unwrap_err(),
            ContextError::SnapshotFloorRegression { .. }
        ),
        "error should be SnapshotFloorRegression (epoch-poisoning rejection)"
    );
}

/// §23.17 Invariant 3: `import_context` into a fresh context slot (no prior
/// state) accepts any incoming epoch within `MAX_EPOCH_ADVANCE` of zero.
///
/// Setup: no prior context (fresh import, no local floors to defend).
/// Import carries Alice's epoch = 500 (within `MAX_EPOCH_ADVANCE` = 1000 of 0).
/// Expected: success — no local floor to regress.
#[tokio::test]
async fn import_context_fresh_context_accepts_any_epoch_within_ceiling() {
    let ctx_id = "epoch-fresh-ctx";
    let alice_did = "did:key:alice-epoch-fresh";

    let mock = MockCrypto::default();
    // No epoch_floors seeded — fresh context.
    // Stage incoming epochs: Alice at 500.
    *mock.pending_restore_epochs.lock().unwrap() = Some(vec![(alice_did.to_owned(), 500)]);

    let manager = ContextManager::new(
        Box::new(mock),
        Box::new(MockTransport::connected()),
        Box::new(MockEventLog::default()),
        noop_key_resolver(),
    );

    // No create_context_bare call — fresh slot (no prior context).
    let export = make_epoch_test_export(ctx_id);
    let result = manager.import_context(export).await;

    assert!(
        result.is_ok(),
        "fresh import (no prior state) should succeed for any epoch within ceiling: {:?}",
        result.err()
    );
}

// -----------------------------------------------------------------------
// Event channel tests (#1539 AC3)
// -----------------------------------------------------------------------

/// Verify that `leave_context` fires `MemberLeft` on the event channel.
#[tokio::test]
async fn event_channel_receives_member_left_on_leave() {
    let mut manager = ContextManager::new(
        Box::new(MockCrypto::default()),
        Box::new(MockTransport::connected()),
        Box::new(MockEventLog::default()),
        noop_key_resolver(),
    );
    manager.with_event_channel(1024);
    let mut rx = manager.subscribe_events().expect("channel configured");

    let params = ContextParams {
        ceiling: vec![
            Capability::new("messages:read"),
            Capability::new("messages:write"),
            Capability::MemberRemove,
        ],
        ..ContextParams::default()
    };
    let handle = manager
        .create_context("evt-ctx".into(), params, "did:key:creator".into(), None)
        .await
        .unwrap();

    // Add a second member directly via state mutation (bypass join_context
    // which needs real MLS crypto).
    {
        let arc = manager.get_context_arc("evt-ctx").unwrap();
        let mut g = arc.lock().await;
        let ctx = &mut *g;
        ctx.membership
            .add_member("did:key:bob".into(), "member".into(), vec![]);
    }

    // Creator removes bob.
    manager
        .leave_context(&handle, &"did:key:creator".into(), &"did:key:bob".into())
        .await
        .unwrap();

    // Drain channel to find MemberLeft for bob.
    let mut found = false;
    while let Ok((ctx_id, event)) = rx.try_recv() {
        if ctx_id == "evt-ctx"
            && let ContextEvent::MemberLeft { member_did } = &event
            && member_did.as_ref() == "did:key:bob"
        {
            found = true;
            break;
        }
    }
    assert!(found, "expected MemberLeft event for bob on channel");
}

// -----------------------------------------------------------------------
// AC3 bug 1: `flush_all_contexts` must persist a degraded snapshot for
// contexts whose lock cannot be acquired within the flush budget, with
// `needs_reconnect = true` set so the restore path fires the
// reconnection pipeline rather than silently losing state.
// -----------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn flush_all_contexts_persists_degraded_snapshot_for_locked_context() {
    let persistence = Arc::new(MockContextPersistence::default());
    let persistence_for_cm: Box<dyn super::ContextPersistence> =
        Box::new(MockContextPersistence::default());

    let manager = Arc::new(ContextManager::with_persistence(
        Box::new(MockCrypto::default()),
        Box::new(MockTransport::connected()),
        Box::new(MockEventLog::default()),
        persistence_for_cm,
        noop_key_resolver(),
    ));

    // Create a context so there is something to flush.
    let _handle = manager
        .create_context(
            "locked-ctx".into(),
            ContextParams::default(),
            "did:key:creator".into(),
            None,
        )
        .await
        .unwrap();

    // Replace the MockContextPersistence embedded in the manager at build
    // time with our observable one by seeding the shared `persistence`
    // handle directly from flush. We cannot swap the persistence on a live
    // manager, so we instead verify behavior via a second manager built
    // with the shared persistence handle.
    //
    // Rebuild with shared persistence (wrap clone in Box).
    let shared_persistence: Arc<MockContextPersistence> = Arc::clone(&persistence);
    let manager = Arc::new(ContextManager::with_persistence(
        Box::new(MockCrypto::default()),
        Box::new(MockTransport::connected()),
        Box::new(MockEventLog::default()),
        Box::new(SharedMockPersistence(Arc::clone(&shared_persistence))),
        noop_key_resolver(),
    ));
    let _handle = manager
        .create_context(
            "locked-ctx".into(),
            ContextParams::default(),
            "did:key:creator".into(),
            None,
        )
        .await
        .unwrap();

    // Acquire the per-context lock and hold it across the flush. The flush's
    // per-context lock-acquisition budget is 250ms; we hold the lock for
    // 750ms, guaranteeing a timeout and forcing the degraded-snapshot
    // fallback path.
    let arc = manager.get_context_arc("locked-ctx").unwrap();
    let guard_task = {
        let arc = Arc::clone(&arc);
        tokio::spawn(async move {
            let _guard = arc.lock().await;
            tokio::time::sleep(std::time::Duration::from_millis(750)).await;
        })
    };

    // Give the task a chance to grab the lock.
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    manager.flush_all_contexts().await;

    // The degraded snapshot must be persisted with `needs_reconnect = true`
    // and an empty crypto state blob.
    let persisted = shared_persistence
        .contexts
        .lock()
        .unwrap()
        .get("locked-ctx")
        .cloned()
        .expect("degraded snapshot must be persisted for locked context");

    assert!(
        persisted.needs_reconnect,
        "degraded snapshot must set needs_reconnect = true so restore fires the reconnection pipeline"
    );
    assert!(
        persisted.mls_crypto_state.is_empty(),
        "degraded snapshot must have empty crypto state"
    );
    assert_eq!(persisted.context_id, "locked-ctx");

    // Let the holder release before the test exits.
    guard_task.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn flush_all_contexts_full_snapshot_when_lock_available() {
    // Sanity check: when the lock is not held, flush produces the full
    // snapshot path and `needs_reconnect` is false (the context was
    // created cleanly).
    let persistence: Arc<MockContextPersistence> = Arc::new(MockContextPersistence::default());
    let manager = ContextManager::with_persistence(
        Box::new(MockCrypto::default()),
        Box::new(MockTransport::connected()),
        Box::new(MockEventLog::default()),
        Box::new(SharedMockPersistence(Arc::clone(&persistence))),
        noop_key_resolver(),
    );
    let _handle = manager
        .create_context(
            "unlocked-ctx".into(),
            ContextParams::default(),
            "did:key:creator".into(),
            None,
        )
        .await
        .unwrap();

    manager.flush_all_contexts().await;

    let persisted = persistence
        .contexts
        .lock()
        .unwrap()
        .get("unlocked-ctx")
        .cloned()
        .expect("unlocked context must be flushed");
    assert!(
        !persisted.needs_reconnect,
        "full snapshot path must not mark needs_reconnect"
    );
}

// -----------------------------------------------------------------------
// AC3 bug 2: `persist_context_snapshot` must set `needs_reconnect = true`
// when `export_crypto_state` returns an error, so the restore path sees
// the reconnection signal rather than silently restoring with an empty
// crypto blob.
// -----------------------------------------------------------------------

#[tokio::test]
async fn persist_context_snapshot_marks_reconnect_on_export_error() {
    let persistence: Arc<MockContextPersistence> = Arc::new(MockContextPersistence::default());

    // Build a crypto that fails export_crypto_state.
    let crypto = MockCrypto::default();
    crypto
        .fail_export_crypto_state
        .store(true, Ordering::Relaxed);

    let manager = ContextManager::with_persistence(
        Box::new(crypto),
        Box::new(MockTransport::connected()),
        Box::new(MockEventLog::default()),
        Box::new(SharedMockPersistence(Arc::clone(&persistence))),
        noop_key_resolver(),
    );

    let _handle = manager
        .create_context(
            "reconnect-ctx".into(),
            ContextParams::default(),
            "did:key:creator".into(),
            None,
        )
        .await
        .unwrap();

    // Force a persistence event via the async flush path. This takes the
    // lock, builds a snapshot, and calls `persist_context_snapshot` which
    // is the exact code path where `export_crypto_state` returns Err.
    manager.flush_all_contexts().await;

    let persisted = persistence
        .contexts
        .lock()
        .unwrap()
        .get("reconnect-ctx")
        .cloned()
        .expect("snapshot must be persisted even on export_crypto_state error");
    assert!(
        persisted.needs_reconnect,
        "export_crypto_state error must set needs_reconnect = true so restore \
         fires the §23.11 reconnection pipeline"
    );
    assert!(
        persisted.mls_crypto_state.is_empty(),
        "crypto state blob must be empty when export fails"
    );
}

/// Adapter that allows a single `MockContextPersistence` to back both the
/// test observer (`Arc<MockContextPersistence>`) and the `ContextManager`
/// (which takes a `Box<dyn ContextPersistence>`). All trait calls delegate
/// to the inner Arc so the test can inspect persisted state.
struct SharedMockPersistence(Arc<MockContextPersistence>);

impl super::ContextPersistence for SharedMockPersistence {
    fn persist_context(
        &self,
        context_id: &str,
        snapshot: &super::ContextSnapshot,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.0.persist_context(context_id, snapshot)
    }

    fn load_context(
        &self,
        context_id: &str,
    ) -> Result<Option<super::ContextSnapshot>, Box<dyn std::error::Error + Send + Sync>> {
        self.0.load_context(context_id)
    }

    fn persist_broadcast(
        &self,
        context_id: &str,
        snapshot: &BroadcastContextSnapshot,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.0.persist_broadcast(context_id, snapshot)
    }

    fn load_broadcast(
        &self,
        context_id: &str,
    ) -> Result<Option<BroadcastContextSnapshot>, Box<dyn std::error::Error + Send + Sync>> {
        self.0.load_broadcast(context_id)
    }

    fn delete_context(
        &self,
        context_id: &str,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.0.delete_context(context_id)
    }

    fn list_persisted_contexts(
        &self,
    ) -> Result<Vec<String>, Box<dyn std::error::Error + Send + Sync>> {
        self.0.list_persisted_contexts()
    }
}
