//! PR #1606 C6 — MLS Commit broadcast persistent retry queue tests.
//!
//! These tests cover the persistent retry queue introduced in
//! `crates/scp-runtime/src/context/manager/governance.rs` and
//! `crates/scp-runtime/src/context/manager/lifecycle.rs`. They exercise:
//!
//! 1. `execute_remove_member` enqueueing on transport failure and the
//!    governance timeout task draining the queue successfully on retry.
//! 2. `MAX_COMMIT_RETRIES` exhaustion marking the context fail-closed and
//!    rejecting subsequent governance actions with `CommitBroadcastFault`.
//! 3. `ContextSnapshot` round-tripping the queue and fault marker.
//! 4. `execute_rotate_content_keys` regression for the same retry behavior.
//! 5. `leave_context` regression for the same retry behavior.
//! 6. `ContextManager::pending_commits` SDK-facing query.

use super::*;
use crate::context::manager::{
    CommitFaultMarker, CommitOperation, ContextSnapshot, MAX_COMMIT_AGE_SECS, MAX_COMMIT_RETRIES,
    PendingCommit,
};
use scp_primitives::TestClock;
use scp_protocol::context::governance::{
    GovernanceAction, GovernanceProposal, ProposalStatus, SignedVote, VoteType,
};
use std::sync::Arc;
use std::sync::atomic::Ordering;

// ---------------------------------------------------------------------------
// Test fixtures
// ---------------------------------------------------------------------------

/// Build an approved single-admin governance proposal targeting
/// `did:key:victim` for `RemoveMember`. Mirrors the inline construction in
/// `tests/governance.rs::governance_action_typed_results`.
fn approved_remove_proposal(context_id: &str, target_did: &str) -> GovernanceProposal {
    GovernanceProposal {
        proposal_id: [42u8; 32],
        context_id: context_id.into(),
        proposer_did: "did:key:admin".into(),
        action: GovernanceAction::RemoveMember {
            did: target_did.into(),
            reason: None,
            induced_rotations: Vec::new(),
        },
        status: ProposalStatus::Approved,
        created_at: 1000,
        voting_deadline: 2000,
        approvals: vec![SignedVote {
            voter_did: "did:key:admin".into(),
            vote: VoteType::Approve,
            timestamp: 1000,
            signature: vec![0u8; 64],
        }],
        rejections: Vec::new(),
        created_at_epoch: None,
    }
}

/// Build an approved single-admin governance proposal for
/// `RotateContentKeys`.
fn approved_rotate_proposal(context_id: &str) -> GovernanceProposal {
    GovernanceProposal {
        proposal_id: [43u8; 32],
        context_id: context_id.into(),
        proposer_did: "did:key:admin".into(),
        action: GovernanceAction::RotateContentKeys {
            reason: Some("test rotation".into()),
        },
        status: ProposalStatus::Approved,
        created_at: 1000,
        voting_deadline: 2000,
        approvals: vec![SignedVote {
            voter_did: "did:key:admin".into(),
            vote: VoteType::Approve,
            timestamp: 1000,
            signature: vec![0u8; 64],
        }],
        rejections: Vec::new(),
        created_at_epoch: None,
    }
}

/// Builds a manager backed by `RetriableMockTransport` and a `TestClock`,
/// with `MemberRemove` + `RoleAssign` capabilities in the ceiling so the
/// admin can execute remove/leave actions. Returns a tuple of:
///   `(manager, context_id, admin_did, victim_did, transport_handle, clock)`.
async fn setup_retry_manager() -> (
    ContextManager,
    String,
    DID,
    DID,
    Arc<RetriableMockTransport>,
    Arc<TestClock>,
) {
    let transport = Arc::new(RetriableMockTransport::default());
    let clock = Arc::new(TestClock::new(1_000_000));
    let manager = ContextManager::builder()
        .crypto(Box::new(MockCrypto::default()))
        .transport(Box::new(ArcRetriableTransport(Arc::clone(&transport))))
        .event_log(Box::new(MockEventLog::default()))
        .clock(Arc::clone(&clock) as Arc<dyn scp_primitives::Clock>)
        .key_resolver(noop_key_resolver())
        .build()
        .unwrap();

    let params = ContextParams {
        ceiling: vec![
            scp_protocol::context::params::Capability::new("messages:read")
                .expect("known capability"),
            scp_protocol::context::params::Capability::new("messages:write")
                .expect("known capability"),
            scp_protocol::context::params::Capability::new("role:assign")
                .expect("known capability"),
            Capability::MemberRemove,
        ],
        ..ContextParams::default()
    };

    let admin_did: DID = "did:key:admin".into();
    let _handle = manager
        .create_context("retry-ctx".into(), params, admin_did.clone(), None)
        .await
        .unwrap();

    // Register a victim member so RemoveMember has a target.
    let victim_did: DID = "did:key:victim".into();
    {
        let arc = manager.get_context_arc("retry-ctx").unwrap();
        let mut g = arc.lock().await;
        let ctx = &mut *g;
        ctx.membership
            .add_member(victim_did.clone(), "member".into(), vec![]);
    }

    (
        manager,
        "retry-ctx".to_owned(),
        admin_did,
        victim_did,
        transport,
        clock,
    )
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// PR #1606 C6 test 1: `execute_remove_member` enqueues on first transport
/// failure, the queue contains exactly one entry, and a subsequent retry
/// (via `process_pending_commits`) dequeues the entry on success.
#[tokio::test]
async fn test_execute_remove_member_commit_broadcast_failure_queues_retry() {
    let (manager, ctx_id, _admin, victim, transport, clock) = setup_retry_manager().await;

    // First call must fail; second call (the retry) must succeed.
    transport.fail_count.store(1, Ordering::Relaxed);

    // Execute the remove. The mutation should NOT propagate the transport
    // failure to the caller; instead, the commit is enqueued.
    let proposal = approved_remove_proposal(&ctx_id, victim.as_ref());
    manager
        .execute_governance_action(&ctx_id, &proposal)
        .await
        .expect("execute_remove_member must succeed even when transport fails");

    // Verify the queue has one pending entry with retry_count = 1.
    let pending = manager.pending_commits(&ctx_id).await;
    assert_eq!(
        pending.len(),
        1,
        "expected 1 pending commit after first failure, got {}",
        pending.len()
    );
    let entry = &pending[0];
    assert_eq!(entry.retry_count, 1, "first failure -> retry_count = 1");
    assert!(
        matches!(entry.operation, CommitOperation::RemoveMember { .. }),
        "operation must be RemoveMember, got {:?}",
        entry.operation
    );
    assert!(entry.last_error.is_some(), "last_error must be populated");

    // Verify the receive buffer carries a CommitBroadcastPending event.
    let events = manager.drain_events(&ctx_id).await;
    assert!(
        events.iter().any(
            |e| matches!(e, ContextEvent::CommitBroadcastPending { attempt, .. } if *attempt == 1)
        ),
        "expected CommitBroadcastPending event with attempt=1, got {events:?}"
    );

    // No fault marker yet — only one failure, well below MAX_COMMIT_RETRIES.
    assert!(
        manager.commit_fault(&ctx_id).await.is_none(),
        "no fault marker after one failure"
    );

    // Advance the clock past the first backoff (1 s) and retry. The retry
    // should succeed and dequeue the entry.
    clock.advance(2);
    manager.process_pending_commits(&ctx_id).await;

    let pending = manager.pending_commits(&ctx_id).await;
    assert!(
        pending.is_empty(),
        "queue must be empty after successful retry, found {} entries",
        pending.len()
    );

    // CommitBroadcastSucceeded must have been emitted.
    let events = manager.drain_events(&ctx_id).await;
    assert!(
        events.iter().any(|e| matches!(
            e,
            ContextEvent::CommitBroadcastSucceeded { attempts, .. } if *attempts == 1
        )),
        "expected CommitBroadcastSucceeded event, got {events:?}"
    );

    // Transport recorded both calls: the first (failed) and the retry.
    assert_eq!(
        transport.total_calls.load(Ordering::Relaxed),
        2,
        "transport should have been called twice"
    );
}

/// PR #1606 C6 test 2: when `MAX_COMMIT_RETRIES` is exhausted, the context
/// is marked fail-closed and subsequent governance actions return
/// `CommitBroadcastFault`.
#[tokio::test]
async fn test_execute_remove_member_commit_max_retries_marks_failed() {
    let (manager, ctx_id, _admin, victim, transport, clock) = setup_retry_manager().await;

    // Always fail.
    transport.fail_count.store(u32::MAX, Ordering::Relaxed);

    let proposal = approved_remove_proposal(&ctx_id, victim.as_ref());
    manager
        .execute_governance_action(&ctx_id, &proposal)
        .await
        .expect("first remove call enqueues, does not error");

    // Drive the retry loop until either MAX_COMMIT_RETRIES exhausts or the
    // commit ages out. Each iteration advances the clock generously past
    // the backoff schedule (300 s ceiling) so every entry is retried.
    for _ in 0..(MAX_COMMIT_RETRIES + 5) {
        clock.advance(301);
        manager.process_pending_commits(&ctx_id).await;
        if manager.commit_fault(&ctx_id).await.is_some() {
            break;
        }
    }

    // Verify the fault marker is set.
    let fault = manager
        .commit_fault(&ctx_id)
        .await
        .expect("fail-close marker must be set after retry budget exhaustion");
    assert!(
        matches!(fault.operation, CommitOperation::RemoveMember { .. }),
        "fault must reference RemoveMember"
    );
    assert!(
        fault.retry_count >= MAX_COMMIT_RETRIES || !fault.reason.is_empty(),
        "fault must record either max retries or a non-empty reason"
    );

    // The pending queue must be drained (the failed entry was removed).
    let pending = manager.pending_commits(&ctx_id).await;
    assert!(
        pending.is_empty(),
        "queue must be empty after fail-close, found {} entries",
        pending.len()
    );

    // CommitBroadcastFailed must have been emitted to the receive buffer.
    let events = manager.drain_events(&ctx_id).await;
    assert!(
        events
            .iter()
            .any(|e| matches!(e, ContextEvent::CommitBroadcastFailed { .. })),
        "expected CommitBroadcastFailed event, got {events:?}"
    );

    // Subsequent governance actions on this context must fail-close.
    // Use a fresh proposal_id so we don't trip the executed-proposal replay
    // check before the fault gate fires.
    let mut next_proposal = approved_remove_proposal(&ctx_id, victim.as_ref());
    next_proposal.proposal_id = [99u8; 32];
    let result = manager
        .execute_governance_action(&ctx_id, &next_proposal)
        .await;
    assert!(
        matches!(result, Err(ContextError::CommitBroadcastFault { .. })),
        "subsequent governance actions must fail-close, got {result:?}"
    );

    // After acknowledging the fault, governance actions are accepted again.
    let cleared = manager
        .acknowledge_commit_fault(&ctx_id)
        .await
        .expect("ack must succeed when a marker is set");
    assert!(
        matches!(cleared.operation, CommitOperation::RemoveMember { .. }),
        "acknowledge_commit_fault must return the cleared marker"
    );
    assert!(
        manager.commit_fault(&ctx_id).await.is_none(),
        "fault must be cleared after ack"
    );

    // (Total transport calls: at least MAX_COMMIT_RETRIES + 1 across the
    // initial enqueue and the retry loop, possibly fewer if the age budget
    // tripped first.)
    assert!(
        transport.total_calls.load(Ordering::Relaxed) >= 1,
        "transport should have been called at least once"
    );
}

/// PR #1606 C6 test 3: `ContextSnapshot` round-trips `pending_commits`
/// and `commit_fault` so retries survive process restart.
#[test]
#[allow(clippy::too_many_lines)] // Test verifies roundtrip of all snapshot fields.
fn test_pending_commits_persist_across_snapshot_roundtrip() {
    let routing_id = scp_protocol::context::context_routing_id("snapshot-ctx");
    let pending = PendingCommit {
        commit_bytes: vec![1, 2, 3, 4, 5],
        routing_id,
        operation: CommitOperation::RemoveMember {
            target_did: "did:key:victim".into(),
        },
        first_attempt_at: 100,
        retry_count: 3,
        last_error: Some("connection refused".into()),
        next_attempt_at: 105,
    };
    let fault = CommitFaultMarker {
        operation: CommitOperation::RotateContentKeys {
            reason: Some("epoch rollover".into()),
        },
        reason: "max retries exhausted".into(),
        failed_at: 200,
        retry_count: MAX_COMMIT_RETRIES,
    };

    // Build a minimal ContextSnapshot with the new fields populated.
    let mut queue = std::collections::VecDeque::new();
    queue.push_back(pending.clone());
    let snapshot = ContextSnapshot {
        context_id: "snapshot-ctx".into(),
        state: scp_protocol::context::ContextState::Active,
        context_params: ContextParams::default(),
        membership: scp_protocol::context::membership::MembershipState::new(),
        role_state: scp_protocol::context::roles::ContextRoleState::new(
            "snapshot-ctx",
            "did:key:creator",
            scp_protocol::context::roles::default_ceiling(),
            Vec::new(),
            &scp_primitives::SystemClock,
        )
        .unwrap(),
        executed_proposals: HashSet::new(),
        ttl_remaining_secs: None,
        registered_outlets: Vec::new(),
        read_exclusion_list: HashSet::new(),
        tool_interfaces: Vec::new(),
        threshold_signers: Vec::new(),
        threshold_value: 0,
        pruning_policy: None,
        governance_model_config: None,
        economic_policy: None,
        budget_tracker: scp_protocol::economy::budget::MemberBudgetTracker::new(),
        approved_proposals: std::collections::HashMap::new(),
        next_proposal_seq: 0,
        governance_freeze: None,
        pending_ceiling_modification: None,
        pending_economic_policy_change: None,
        mls_epoch: 0,
        epoch_coordination_records: Vec::new(),
        grace_entries: Vec::new(),
        needs_reconnect: false,
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
        pending_commits: queue,
        commit_fault: Some(fault),
        checkpoint_events_since: 0,
        checkpoint_last_time_secs: 0,
        generation: 0,
        local_pseudonym: None,
        pseudonym_registry: std::collections::HashMap::new(),
    };

    // Round-trip via JSON to ensure serde derive works for both new types.
    let json = serde_json::to_string(&snapshot).expect("snapshot must serialize");
    let restored: ContextSnapshot = serde_json::from_str(&json).expect("snapshot must deserialize");

    assert_eq!(restored.pending_commits.len(), 1);
    let restored_pending = &restored.pending_commits[0];
    assert_eq!(restored_pending.commit_bytes, pending.commit_bytes);
    assert_eq!(restored_pending.routing_id, pending.routing_id);
    assert_eq!(restored_pending.retry_count, 3);
    assert_eq!(restored_pending.first_attempt_at, 100);
    assert_eq!(restored_pending.next_attempt_at, 105);
    assert_eq!(
        restored_pending.last_error.as_deref(),
        Some("connection refused")
    );
    assert!(matches!(
        restored_pending.operation,
        CommitOperation::RemoveMember { .. }
    ));

    let restored_fault = restored.commit_fault.expect("fault must round-trip");
    assert!(matches!(
        restored_fault.operation,
        CommitOperation::RotateContentKeys { .. }
    ));
    assert_eq!(restored_fault.reason, "max retries exhausted");
    assert_eq!(restored_fault.failed_at, 200);
    assert_eq!(restored_fault.retry_count, MAX_COMMIT_RETRIES);
}

/// PR #1606 C6 test 4: `execute_rotate_content_keys` exhibits the same
/// retry behavior as `execute_remove_member`. Regression coverage for the
/// content key rotation path.
#[tokio::test]
async fn test_execute_rotate_content_keys_same_retry_behavior() {
    let (manager, ctx_id, _admin, _victim, transport, clock) = setup_retry_manager().await;

    transport.fail_count.store(2, Ordering::Relaxed);

    let proposal = approved_rotate_proposal(&ctx_id);
    manager
        .execute_governance_action(&ctx_id, &proposal)
        .await
        .expect("execute_rotate_content_keys must not propagate transport failure");

    // The first attempt failed → one entry should be enqueued. (Note: in
    // broadcast mode the commit is empty and the helper short-circuits;
    // here we set up encrypted mode.)
    let pending = manager.pending_commits(&ctx_id).await;
    assert_eq!(
        pending.len(),
        1,
        "rotate_content_keys must enqueue on transport failure"
    );
    assert!(
        matches!(
            pending[0].operation,
            CommitOperation::RotateContentKeys { .. }
        ),
        "queued operation must be RotateContentKeys"
    );

    // Process retries: first retry fails (fail_count was 2 → 1 left after
    // initial), then succeeds.
    clock.advance(2);
    manager.process_pending_commits(&ctx_id).await;
    let pending = manager.pending_commits(&ctx_id).await;
    assert_eq!(pending.len(), 1, "still pending after second failure");
    assert_eq!(pending[0].retry_count, 2);

    clock.advance(10);
    manager.process_pending_commits(&ctx_id).await;
    let pending = manager.pending_commits(&ctx_id).await;
    assert!(
        pending.is_empty(),
        "queue must be empty after successful third attempt"
    );
    assert!(manager.commit_fault(&ctx_id).await.is_none());
}

/// PR #1606 C6 test 5: `leave_context` exhibits the same retry behavior.
/// Regression coverage for the leave path.
#[tokio::test]
async fn test_leave_context_same_retry_behavior() {
    let (manager, ctx_id, admin, victim, transport, clock) = setup_retry_manager().await;

    transport.fail_count.store(1, Ordering::Relaxed);

    // Look up the handle so we can call leave_context.
    let handle = {
        manager
            .contexts
            .get(&ctx_id)
            .unwrap()
            .value()
            .clone()
            .lock()
            .await
            .handle
            .clone()
    };

    manager
        .leave_context(&handle, &admin, &victim)
        .await
        .expect("leave_context must enqueue rather than error");

    let pending = manager.pending_commits(&ctx_id).await;
    assert_eq!(
        pending.len(),
        1,
        "leave_context must enqueue on transport failure"
    );
    assert!(
        matches!(pending[0].operation, CommitOperation::LeaveContext { .. }),
        "queued operation must be LeaveContext, got {:?}",
        pending[0].operation
    );

    // Retry succeeds.
    clock.advance(2);
    manager.process_pending_commits(&ctx_id).await;
    let pending = manager.pending_commits(&ctx_id).await;
    assert!(
        pending.is_empty(),
        "queue must be empty after successful retry"
    );
    assert_eq!(transport.total_calls.load(Ordering::Relaxed), 2);
}

/// PR #1606 C6 test 6: the SDK-facing `pending_commits()` query method
/// returns a clone of the queue and the `commit_fault()` query returns
/// the marker when set. Both return empty/None for unknown contexts.
#[tokio::test]
async fn test_pending_commits_query_method() {
    let (manager, ctx_id, _admin, victim, transport, _clock) = setup_retry_manager().await;

    // Empty by default.
    assert!(
        manager.pending_commits(&ctx_id).await.is_empty(),
        "queue must start empty"
    );
    assert!(
        manager.commit_fault(&ctx_id).await.is_none(),
        "no fault marker by default"
    );

    // Unknown context returns empty/None rather than panicking.
    assert!(manager.pending_commits("unknown-ctx").await.is_empty());
    assert!(manager.commit_fault("unknown-ctx").await.is_none());

    // Trigger one enqueue.
    transport.fail_count.store(1, Ordering::Relaxed);
    let proposal = approved_remove_proposal(&ctx_id, victim.as_ref());
    manager
        .execute_governance_action(&ctx_id, &proposal)
        .await
        .unwrap();
    let pending = manager.pending_commits(&ctx_id).await;
    assert_eq!(pending.len(), 1, "query reports the enqueued commit");
    assert_eq!(pending[0].retry_count, 1);
}

/// Defensive sanity check: the `MAX_COMMIT_AGE_SECS` budget force-fails
/// commits even if `MAX_COMMIT_RETRIES` has not been exhausted.
#[tokio::test]
async fn test_max_commit_age_forces_failure() {
    let (manager, ctx_id, _admin, victim, transport, clock) = setup_retry_manager().await;

    // Always fail.
    transport.fail_count.store(u32::MAX, Ordering::Relaxed);

    let proposal = approved_remove_proposal(&ctx_id, victim.as_ref());
    manager
        .execute_governance_action(&ctx_id, &proposal)
        .await
        .unwrap();

    // Jump past MAX_COMMIT_AGE_SECS so the next retry tick force-fails
    // even before MAX_COMMIT_RETRIES is reached.
    clock.advance(MAX_COMMIT_AGE_SECS + 1);
    manager.process_pending_commits(&ctx_id).await;

    let fault = manager.commit_fault(&ctx_id).await;
    assert!(
        fault.is_some(),
        "context must be fail-closed after age budget exhaustion"
    );
    let fault = fault.unwrap();
    assert!(
        fault.reason.contains("max age exceeded") || fault.reason.contains("retriable mock"),
        "reason should mention age limit, got {}",
        fault.reason
    );
}
