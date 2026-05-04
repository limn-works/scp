//! Governance helpers — actor-shape signatures
//! (ADR-049 Phase 2A.8, `governance` domain migration).
//!
//! # Purpose
//!
//! This module hosts governance-domain helpers that operate on
//! actor-owned [`PerContextState`](crate::context::actor::state::PerContextState)
//! and capability-reduced [`ActorDeps`](crate::context::actor::deps::ActorDeps).
//! The legacy `&Supervisor` lock-and-call bodies live in
//! [`crate::context::governance_helpers_legacy`] until Phase 2A
//! finalization removes the shim fallback.
//!
//! # Migration shape
//!
//! Phase 2A.8 lands as a multi-commit ladder. Each commit migrates a
//! group of related helpers, wiring the actor-shape
//! `handlers::governance::dispatch` arms incrementally. Five
//! supervisor-scoped helpers (`start_governance_timeout_task`,
//! `evaluate_periodic_consequences`, `process_pending_commits`,
//! `compute_commit_retry_outcomes`, `apply_commit_retry_outcomes`)
//! inherently iterate the contexts `DashMap` and have no actor-shape
//! twin — they remain in
//! [`crate::context::governance_helpers_legacy`] until the legacy
//! contexts map dissolves at Phase 2A finalization.
//!
//! Legacy `lifecycle_helpers` callsites (`create_context`,
//! `drain_and_deliver_sender_keys`) are reached via the
//! [`SupervisorHandle::shim_supervisor`](crate::context::supervisor::handle::SupervisorHandle::shim_supervisor)
//! escape hatch until those domains migrate (Phase 2A.9).

use std::sync::Arc;

use scp_identity::DID;
use scp_primitives::Clock;
use scp_protocol::context::governance::mls_integration::{
    MlsImpact, classify_action, generate_mls_operations,
};
use scp_protocol::context::governance::{
    AccessScope, GovernanceAction, GovernanceContext, GovernanceEvent, GovernanceProposal,
    ProposalId, ProposalStatus, PruningPolicy,
};
use scp_protocol::context::membership::ContextEvent;
use scp_protocol::context::params::ToolRegistration;
use scp_protocol::context::roles::{self, Capability, CapabilityCeiling};
use scp_protocol::context::tools::interface::ToolInterface;
use scp_protocol::context::{ContextError, ContextParams, ContextState};
use scp_protocol::economy::types::EconomicPolicy;
use tracing::instrument;

use crate::context::actor::deps::ActorDeps;
use crate::context::actor::state::PerContextState;
use crate::context::governance_logic::{
    EnforceConsequencesCtx, check_proposer_eligibility, dispatch_consequences,
    enforce_triggered_consequences_split, event_log_entries_for_consequences_split,
};
use crate::context::governance_logic::ConsequenceStateSplit;
use crate::context::state::{
    CEILING_CHANGE_NOTIFICATION_PERIOD_SECS, CommitFaultMarker, CommitOperation,
    ContentKeysRotatedResult, ECONOMIC_POLICY_NOTIFICATION_PERIOD_SECS,
    EXECUTED_PROPOSALS_TTL_SECS, GovernanceActionResult, GovernanceReconfiguredResult,
    MAX_COMMIT_AGE_SECS, MAX_COMMIT_RETRIES, MAX_PENDING_COMMITS, MAX_REGISTERED_TOOLS,
    MAX_THRESHOLD_SIGNERS, MAX_TOOL_INTERFACES, MigrationProposedResult, MigrationState,
    PendingCeilingModification, PendingCommit, PendingEconomicPolicyChange, ProposalOutcome,
    RestoreAccessResult, RevokeResult, SuspendMemberResult, commit_retry_backoff,
    context_id_to_bytes, emit_event_into, push_welcome_event, require_active,
    require_migrating_out, strip_event_payload,
};

// ---------------------------------------------------------------------------
// check_commit_fault_marker (transitive helper, already actor-shape)
// ---------------------------------------------------------------------------

/// Field-disjoint variant of `check_commit_fault` used by both the
/// legacy [`crate::context::state::PerContextState`] and the
/// actor-shape
/// [`crate::context::actor::state::PerContextState`].
///
/// ADR-049 Phase 2A.7 — added so the actor-shape `messaging_helpers`
/// can drive the same fail-closed gate without going through the
/// legacy state struct.
///
/// # Errors
///
/// Returns [`ContextError::CommitBroadcastFault`] if the marker is `Some`.
pub fn check_commit_fault_marker(marker: Option<&CommitFaultMarker>) -> Result<(), ContextError> {
    if let Some(marker) = marker {
        return Err(ContextError::CommitBroadcastFault {
            operation: marker.operation.label(),
            reason: marker.reason.clone(),
            attempts: marker.retry_count,
        });
    }
    Ok(())
}

/// Returns `Err(CommitBroadcastFault)` if the actor-shape state has an
/// active commit fault marker (PR #1606 C6), otherwise `Ok(())`.
pub fn check_commit_fault(state: &PerContextState) -> Result<(), ContextError> {
    check_commit_fault_marker(state.commit_fault.as_ref())
}

// ---------------------------------------------------------------------------
// emit helpers — re-export for convenience
// ---------------------------------------------------------------------------

/// Emit an event into the actor's receive buffer + optional broadcast
/// channel. Mirrors the legacy `PerContextState::emit_event` body but
/// works on actor-owned state.
fn emit(state: &mut PerContextState, event: ContextEvent, context_id: &str, deps: &ActorDeps) {
    emit_event_into(
        &mut state.receive_buffer,
        event,
        context_id,
        deps.event_tx.as_ref(),
    );
}

// ---------------------------------------------------------------------------
// build_governance_context (transitive helper, actor-shape)
// ---------------------------------------------------------------------------

/// Build a [`GovernanceContext`] from actor-owned state + a clock.
///
/// Used by every governance engine call that needs membership +
/// admin + epoch + wall-clock context. Pure projection; no I/O.
pub fn build_governance_context(state: &PerContextState, clock: &dyn Clock) -> GovernanceContext {
    let members: Vec<(DID, String)> = state
        .membership
        .members()
        .map(|m| (m.did.clone(), m.role_name.clone()))
        .collect();
    let admin_dids: Vec<DID> = state
        .membership
        .members()
        .filter(|m| m.role_name == "admin")
        .map(|m| m.did.clone())
        .collect();
    GovernanceContext {
        context_id: state.handle.context_id().to_owned(),
        members,
        admin_dids,
        current_epoch: Some(state.epoch.mls_epoch),
        now: clock.now_secs(),
    }
}

// ---------------------------------------------------------------------------
// governance_event_label (transitive helper, actor-shape — pure)
// ---------------------------------------------------------------------------

/// Returns the event-log label string for a [`GovernanceEvent`] variant.
///
/// Pure projection over a borrowed event; no `state`/`deps` needed.
#[must_use]
pub const fn governance_event_label(event: &GovernanceEvent) -> &'static str {
    match event {
        GovernanceEvent::ProposalCreated { .. } => "GovernanceProposalCreated",
        GovernanceEvent::VoteCast { .. } => "GovernanceVoteCast",
        GovernanceEvent::VoteWithdrawn { .. } => "GovernanceVoteWithdrawn",
        GovernanceEvent::ProposalResolved { .. } => "GovernanceProposalResolved",
        GovernanceEvent::DeadlockRecovery { .. } => "GovernanceDeadlockRecovery",
        GovernanceEvent::ConflictDetected { .. } => "GovernanceConflictDetected",
        GovernanceEvent::ConflictResolved { .. } => "GovernanceConflictResolved",
        GovernanceEvent::GovernanceActionExecuted { .. } => "GovernanceActionExecuted",
    }
}

// ---------------------------------------------------------------------------
// translate_timeout_events (pure)
// ---------------------------------------------------------------------------

/// Translates governance timeout events into [`ContextEvent`]s for the
/// receive buffer. Pure projection.
pub fn translate_timeout_events(
    result_events: &[GovernanceEvent],
    mls_epoch: u64,
    conditions: &[crate::context::governance::timeout::DeadlockCondition],
    recovery_in_progress: bool,
) -> Vec<ContextEvent> {
    let mut ctx_events = Vec::new();
    for event in result_events {
        let ctx_event = match event {
            GovernanceEvent::ProposalResolved {
                proposal_id,
                status,
            } => ContextEvent::ProposalTimedOut {
                proposal_id: *proposal_id,
                resolution_summary: format!("ProposalResolved({status:?})"),
                resulting_epoch: Some(mls_epoch),
            },
            GovernanceEvent::VoteWithdrawn {
                proposal_id,
                voter_did,
            } => ContextEvent::VoteWithdrawn {
                proposal_id: *proposal_id,
                voter_did: voter_did.clone(),
            },
            GovernanceEvent::GovernanceActionExecuted {
                proposal_id,
                action,
                executor_did,
                resulting_epoch,
            } => ContextEvent::GovernanceActionExecuted {
                proposal_id: *proposal_id,
                action_summary: action.variant_name().to_owned(),
                executor_did: executor_did.clone(),
                resulting_epoch: *resulting_epoch,
                target_did: action.target_did().cloned(),
            },
            // These variants are not expected from timeout processing;
            // listed explicitly so the compiler warns on new variants.
            GovernanceEvent::ProposalCreated { .. }
            | GovernanceEvent::VoteCast { .. }
            | GovernanceEvent::DeadlockRecovery { .. }
            | GovernanceEvent::ConflictDetected { .. }
            | GovernanceEvent::ConflictResolved { .. } => continue,
        };
        ctx_events.push(ctx_event);
    }

    if !conditions.is_empty() && !recovery_in_progress {
        for condition in conditions {
            let summary = match condition {
                crate::context::governance::timeout::DeadlockCondition::ThresholdInsufficient {
                    ..
                } => "ThresholdInsufficient",
                crate::context::governance::timeout::DeadlockCondition::MajorityUnresponsive {
                    ..
                } => "MajorityUnresponsive",
                crate::context::governance::timeout::DeadlockCondition::UnanimityOffline {
                    ..
                } => "UnanimityOffline",
            };
            ctx_events.push(ContextEvent::DeadlockDetected {
                condition_summary: summary.to_owned(),
                resulting_epoch: Some(mls_epoch),
            });
        }
    }

    ctx_events
}

// ---------------------------------------------------------------------------
// Read entry points
// ---------------------------------------------------------------------------

/// Fetch a single governance proposal by ID.
///
/// # Errors
///
/// - [`ContextError::GovernanceFailed`] if the proposal is not found.
pub fn get_proposal(
    state: &PerContextState,
    proposal_id: &ProposalId,
) -> Result<GovernanceProposal, ContextError> {
    state
        .governance
        .engine
        .get_proposal(proposal_id)
        .cloned()
        .ok_or_else(|| {
            ContextError::GovernanceFailed(format!(
                "proposal not found: {}",
                hex::encode(proposal_id)
            ))
        })
}

/// Enumerate every governance proposal tracked by the context's engine.
#[must_use]
pub fn list_proposals(state: &PerContextState) -> Vec<GovernanceProposal> {
    state.governance.engine.list_proposals()
}

/// Snapshot the current migration metadata for the context, if any.
#[must_use]
pub fn migration_state(state: &PerContextState) -> Option<MigrationState> {
    state.migration_state.clone()
}

// ---------------------------------------------------------------------------
// tombstone_migrated_context (entry point — mutation)
// ---------------------------------------------------------------------------

/// Tombstone a context after migration grace period expiry (§5.11A.5).
///
/// # Errors
///
/// - [`ContextError::ContextNotActive`] if the context's handle is not
///   readable.
/// - [`ContextError::PermissionDenied`] if the context is not
///   `MigratingOut`, no migration metadata exists, or the grace
///   period has not yet expired.
/// - [`ContextError::NotInitialized`] if the actor has no event-log
///   provider attached.
#[instrument(skip_all, fields(context_id))]
pub async fn tombstone_migrated_context(
    state: &mut PerContextState,
    deps: &ActorDeps,
    context_id: &str,
) -> Result<(), ContextError> {
    let context_id_bytes = context_id_to_bytes(context_id);
    let now = deps.clock.now_secs();

    let handle_state = state
        .handle
        .try_read_state()
        .ok_or(ContextError::ContextNotActive)?;
    if handle_state != ContextState::MigratingOut {
        return Err(ContextError::PermissionDenied(
            "context is not in MigratingOut state — cannot tombstone".to_owned(),
        ));
    }

    let migration = state.migration_state.as_ref().ok_or_else(|| {
        ContextError::PermissionDenied(
            "no migration state found despite MigratingOut state".to_owned(),
        )
    })?;

    if now < migration.grace_period_end {
        return Err(ContextError::PermissionDenied(format!(
            "migration grace period has not expired (ends at {}, now {})",
            migration.grace_period_end, now
        )));
    }

    let destination_id = migration.destination_context_id.clone();
    let migration_pid = migration.proposal_id;

    state
        .handle
        .transition_to(&ContextState::Tombstoned)
        .await
        .map_err(|_| {
            ContextError::PermissionDenied(
                "cannot transition from MigratingOut to Tombstoned".to_owned(),
            )
        })?;

    let tombstone_event = ContextEvent::ContextTombstoned {
        destination_context_id: destination_id.clone(),
        migration_proposal_id: migration_pid,
    };
    emit(state, tombstone_event, context_id, deps);

    state.ttl.timer.cancel();
    state.governance.timeout_task.cancel();
    state.broadcast_context = None;
    state.migration_state = None;
    // M7: Participation decay on tombstone (#1530).
    state.governance.decay_participation();

    crate::context::messaging_helpers::persist_state_best_effort(state, deps, context_id);

    deps.event_log.append_context_event(
        &context_id_bytes,
        &format!(
            "ContextTombstoned:{}:{}",
            destination_id,
            hex::encode(migration_pid)
        ),
        "system",
    )?;
    state.checkpoint_events_since += 1;

    Ok(())
}

// ---------------------------------------------------------------------------
// acknowledge_commit_fault (entry point — mutation)
// ---------------------------------------------------------------------------

/// Acknowledge a commit broadcast fault and clear the fail-close
/// marker so the context can accept further mutations (PR #1606 C6).
///
/// # Errors
///
/// - [`ContextError::InvalidState`] if no fault marker is set.
#[instrument(skip_all, fields(context_id))]
pub fn acknowledge_commit_fault(
    state: &mut PerContextState,
    context_id: &str,
) -> Result<CommitFaultMarker, ContextError> {
    state.commit_fault.take().ok_or_else(|| {
        ContextError::InvalidState(format!(
            "context {context_id} has no commit fault to acknowledge"
        ))
    })
}

// ---------------------------------------------------------------------------
// withdraw_governance_vote (entry point — mutation)
// ---------------------------------------------------------------------------

/// Withdraw a previously-cast vote from a proposal.
///
/// # Errors
///
/// - [`ContextError::ContextNotActive`] if the context is not `Active`.
/// - [`ContextError::PermissionDenied`] if the engine rejects the
///   withdrawal (no prior vote, proposal already resolved, etc.).
/// - [`ContextError::NotInitialized`] if no event-log provider is
///   attached.
#[instrument(skip_all, fields(context_id))]
pub async fn withdraw_governance_vote(
    state: &mut PerContextState,
    deps: &ActorDeps,
    context_id: &str,
    proposal_id: &ProposalId,
    voter_did: &DID,
) -> Result<ProposalStatus, ContextError> {
    require_active(&state.handle)?;

    let gov_ctx = build_governance_context(state, &*deps.clock);
    let (status, events) = state
        .governance
        .engine
        .withdraw_vote(proposal_id, voter_did, &gov_ctx)
        .map_err(|e| ContextError::PermissionDenied(e.to_string()))?;

    let context_id_bytes = context_id_to_bytes(context_id);
    let mut event_count: u64 = 0;
    for event in &events {
        deps.event_log.append_context_event(
            &context_id_bytes,
            governance_event_label(event),
            voter_did.as_ref(),
        )?;
        event_count += 1;
    }
    if event_count > 0 {
        state.checkpoint_events_since += event_count;
    }

    crate::context::messaging_helpers::persist_state_best_effort(state, deps, context_id);

    Ok(status)
}

// ---------------------------------------------------------------------------
// apply_pending_ceiling_modification (entry point — conditional mutation)
// ---------------------------------------------------------------------------

/// Apply a pending ceiling modification when its notification period
/// has elapsed (M7, §5.3.2).
///
/// # Errors
///
/// - [`ContextError::ContextNotActive`] if the context is not `Active`.
/// - [`ContextError::NotInitialized`] if no event-log provider is
///   attached.
#[instrument(skip_all, fields(context_id))]
pub async fn apply_pending_ceiling_modification(
    state: &mut PerContextState,
    deps: &ActorDeps,
    context_id: &str,
    current_timestamp: u64,
) -> Result<bool, ContextError> {
    require_active(&state.handle)?;

    let pending = match &state.governance.pending_ceiling_modification {
        Some(p) if p.is_effective(current_timestamp) => p.clone(),
        _ => return Ok(false),
    };

    state.role_state.ceiling = CapabilityCeiling::new(pending.new_capabilities.iter().cloned());
    state.governance.pending_ceiling_modification = None;

    crate::context::messaging_helpers::persist_state_best_effort(state, deps, context_id);

    let context_id_bytes = context_id_to_bytes(context_id);
    deps.event_log
        .append_context_event(&context_id_bytes, "CeilingModified", "")?;
    state.checkpoint_events_since += 1;

    Ok(true)
}

// ---------------------------------------------------------------------------
// apply_pending_economic_policy_change (entry point — conditional mutation)
// ---------------------------------------------------------------------------

/// Apply a pending economic-policy change when its notification
/// period has elapsed.
///
/// # Errors
///
/// - [`ContextError::ContextNotActive`] if the context is not `Active`.
/// - [`ContextError::NotInitialized`] if no event-log provider is
///   attached.
#[instrument(skip_all, fields(context_id))]
pub async fn apply_pending_economic_policy_change(
    state: &mut PerContextState,
    deps: &ActorDeps,
    context_id: &str,
    current_timestamp: u64,
) -> Result<bool, ContextError> {
    require_active(&state.handle)?;

    let pending = match &state.governance.pending_economic_policy_change {
        Some(p) if p.is_effective(current_timestamp) => p.clone(),
        _ => return Ok(false),
    };

    state.governance.economic_policy = Some(pending.new_policy);
    state.governance.pending_economic_policy_change = None;

    crate::context::messaging_helpers::persist_state_best_effort(state, deps, context_id);

    let context_id_bytes = context_id_to_bytes(context_id);
    deps.event_log
        .append_context_event(&context_id_bytes, "EconomicPolicyApplied", "")?;
    state.checkpoint_events_since += 1;

    Ok(true)
}

// ---------------------------------------------------------------------------
// Persistence helpers (best-effort)
// ---------------------------------------------------------------------------

/// Best-effort persist of broadcast snapshot via `deps.persistence`.
fn persist_broadcast_snapshot(
    deps: &ActorDeps,
    context_id: &str,
    snapshot: &scp_protocol::context::broadcast::BroadcastContextSnapshot,
) {
    if let Err(e) = deps.persistence.persist_broadcast(context_id, snapshot) {
        tracing::warn!(
            context_id = %context_id,
            error = %e,
            "failed to persist broadcast snapshot"
        );
    }
}

// ---------------------------------------------------------------------------
// detect_and_handle_conflicts (transitive helper, actor-shape)
// ---------------------------------------------------------------------------

/// Detects and handles conflicts when a proposal becomes approved
/// (ADR-031 §7).
pub fn detect_and_handle_conflicts(
    state: &mut PerContextState,
    deps: &ActorDeps,
    new_proposal: &GovernanceProposal,
) -> Vec<GovernanceEvent> {
    use scp_protocol::context::governance::actions_conflict;

    let mut events = Vec::new();
    // Wall-clock timestamp — used ONLY for the audit slot of
    // `approved_proposals` and for the freeze start time. Never
    // used for sequence comparison (H10).
    let current_timestamp = deps.clock.now_secs();

    // H10: assign the monotonic seq for the new proposal up front, and
    // bump the counter immediately so any nested or concurrent call
    // cannot reuse it.
    let new_seq = state.governance.next_proposal_seq;
    state.governance.next_proposal_seq = state.governance.next_proposal_seq.saturating_add(1);

    // Check for conflicts with existing approved proposals.
    let mut conflicts = Vec::new();
    for (existing_id, (existing_proposal, existing_seq, existing_timestamp)) in
        &state.governance.approved_proposals
    {
        if actions_conflict(
            &new_proposal.action,
            &new_proposal.proposer_did,
            &existing_proposal.action,
            &existing_proposal.proposer_did,
        ) {
            conflicts.push((
                *existing_id,
                *existing_seq,
                *existing_timestamp,
                existing_proposal.clone(),
            ));
        }
    }

    for (conflicting_id, conflicting_seq, _conflicting_timestamp, _conflicting_proposal) in
        conflicts
    {
        match new_seq.cmp(&conflicting_seq) {
            std::cmp::Ordering::Equal => {
                state.governance.freeze =
                    Some((new_proposal.proposal_id, conflicting_id, current_timestamp));
                events.push(GovernanceEvent::ConflictDetected {
                    proposal_a: new_proposal.proposal_id,
                    proposal_b: conflicting_id,
                });
            }
            std::cmp::Ordering::Less => {
                state.governance.approved_proposals.remove(&conflicting_id);
                events.push(GovernanceEvent::ConflictResolved {
                    winner_id: new_proposal.proposal_id,
                    loser_id: conflicting_id,
                });
            }
            std::cmp::Ordering::Greater => {
                events.push(GovernanceEvent::ConflictResolved {
                    winner_id: conflicting_id,
                    loser_id: new_proposal.proposal_id,
                });
                return events; // Don't add the new proposal
            }
        }
    }

    if !events.iter().any(|e| matches!(e, GovernanceEvent::ConflictResolved { loser_id, .. } if *loser_id == new_proposal.proposal_id))
    {
        state.governance.approved_proposals.insert(
            new_proposal.proposal_id,
            (new_proposal.clone(), new_seq, current_timestamp),
        );
    }

    events
}

// ---------------------------------------------------------------------------
// check_and_resolve_expired_freezes (transitive helper, actor-shape)
// ---------------------------------------------------------------------------

/// Checks for and resolves expired governance freezes (ADR-031 §7).
pub fn check_and_resolve_expired_freezes(
    state: &mut PerContextState,
    deps: &ActorDeps,
) -> Vec<GovernanceEvent> {
    const FREEZE_TIMEOUT_SECONDS: u64 = 48 * 60 * 60; // 48 hours

    let current_timestamp = deps.clock.now_secs();

    if let Some((proposal_a, proposal_b, freeze_start)) = state.governance.freeze
        && current_timestamp.saturating_sub(freeze_start) >= FREEZE_TIMEOUT_SECONDS
    {
        state.governance.approved_proposals.remove(&proposal_a);
        state.governance.approved_proposals.remove(&proposal_b);
        state.governance.freeze = None;

        return vec![
            GovernanceEvent::ConflictResolved {
                winner_id: proposal_b,
                loser_id: proposal_a,
            },
            GovernanceEvent::ConflictResolved {
                winner_id: proposal_a,
                loser_id: proposal_b,
            },
        ];
    }

    Vec::new()
}

// ---------------------------------------------------------------------------
// fail_close_remove_member (private transitive helper)
// ---------------------------------------------------------------------------

/// Sender-key step failed after the MLS commit succeeded. Mark the
/// context fail-closed via [`CommitFaultMarker`] and surface a typed
/// `CryptoFailed` error so the operator must `acknowledge_commit_fault`
/// before subsequent sends can resume.
fn fail_close_remove_member(
    state: &mut PerContextState,
    deps: &ActorDeps,
    context_id: &str,
    did: &DID,
    operation: &str,
    error: &str,
) -> Result<(), ContextError> {
    tracing::error!(
        context_id,
        member = %did,
        op = operation,
        error,
        "{operation} failed after MLS removal — fail-closing context"
    );
    state.commit_fault = Some(CommitFaultMarker {
        operation: CommitOperation::RemoveMember {
            target_did: did.clone(),
        },
        reason: format!("{operation} failed: {error}"),
        failed_at: deps.clock.now_secs(),
        retry_count: 0,
    });
    Err(ContextError::CryptoFailed(format!(
        "{operation} failed after MLS removal of {did}: {error}"
    )))
}

// ---------------------------------------------------------------------------
// execute_suspend_member (per-action leaf helper)
// ---------------------------------------------------------------------------

/// Executes a `SuspendMember` governance action.
pub async fn execute_suspend_member(
    state: &mut PerContextState,
    deps: &ActorDeps,
    context_id: &str,
    did: &DID,
    capabilities: &[Capability],
    _proposal_id: ProposalId,
    actor_did: &str,
) -> Result<(), ContextError> {
    require_active(&state.handle)?;

    if !state.role_state.ceiling.contains(&Capability::MemberBan) {
        return Err(ContextError::PermissionDenied(
            "member:ban (MemberBan) capability not in ceiling".to_owned(),
        ));
    }
    if !state.membership.contains(did) {
        return Err(ContextError::MemberNotFound(did.to_string()));
    }

    state
        .role_state
        .suspend_capabilities(did.as_ref(), capabilities.iter().cloned());

    emit(
        state,
        ContextEvent::CapabilitiesSuspended {
            did: did.clone(),
            capabilities: capabilities.to_vec(),
        },
        context_id,
        deps,
    );

    crate::context::messaging_helpers::persist_state_best_effort(state, deps, context_id);

    let context_id_bytes = context_id_to_bytes(context_id);
    deps.event_log
        .append_context_event(&context_id_bytes, "MemberSuspended", actor_did)?;
    state.checkpoint_events_since += 1;
    Ok(())
}

// ---------------------------------------------------------------------------
// execute_revoke (per-action leaf helper)
// ---------------------------------------------------------------------------

/// Executes a `Revoke` governance action — cryptographic key destruction.
///
/// Returns the number of rotated authors (for broadcast contexts).
#[allow(clippy::too_many_lines)]
pub async fn execute_revoke(
    state: &mut PerContextState,
    deps: &ActorDeps,
    context_id: &str,
    did: &DID,
    access: AccessScope,
    _proposal_id: ProposalId,
    actor_did: &str,
) -> Result<usize, ContextError> {
    let context_id_bytes = context_id_to_bytes(context_id);

    require_active(&state.handle)?;

    if !state.role_state.ceiling.contains(&Capability::MemberBan) {
        return Err(ContextError::PermissionDenied(
            "member:ban (MemberBan) capability not in ceiling".to_owned(),
        ));
    }
    if !state.membership.contains(did) {
        return Err(ContextError::MemberNotFound(did.to_string()));
    }

    let mut rotated = 0usize;
    let mut bc_snap = None;

    // Write revocation.
    if matches!(access, AccessScope::Write | AccessScope::Both) {
        state
            .role_state
            .suspend_capabilities(did.as_ref(), [Capability::MessagesWrite]);

        if let Some(ref mut bc) = state.broadcast_context {
            match bc.block_author(&did.0) {
                Ok(_) | Err(ContextError::MemberNotFound(_)) => {}
                Err(e) => return Err(e),
            }
            bc_snap = Some(bc.to_snapshot());
        }

        emit(
            state,
            ContextEvent::WriteAccessRevoked { did: did.clone() },
            context_id,
            deps,
        );
    }

    // Read revocation.
    if matches!(access, AccessScope::Read | AccessScope::Both) {
        state
            .role_state
            .suspend_capabilities(did.as_ref(), [Capability::MessagesRead]);

        state.access.read_exclusion_list.insert(did.clone());

        if let Some(ref mut bc) = state.broadcast_context {
            match bc.governance_ban_subscriber(&did.0, access) {
                Ok(r) => {
                    rotated = r.rotated_authors.len();
                }
                Err(ContextError::MemberNotFound(_)) => {}
                Err(e) => return Err(e),
            }
            bc_snap = Some(bc.to_snapshot());
        } else {
            state
                .access
                .access_key_store
                .remove(context_id, did.as_ref());
        }

        emit(
            state,
            ContextEvent::ReadAccessRevoked { did: did.clone() },
            context_id,
            deps,
        );
        emit(
            state,
            ContextEvent::AccessKeyRevoked { did: did.clone() },
            context_id,
            deps,
        );
    }

    let needs_sender_key_rotation =
        matches!(access, AccessScope::Write | AccessScope::Both) && state.broadcast_context.is_none();

    crate::context::messaging_helpers::persist_state_best_effort(state, deps, context_id);
    if let Some(ref bc) = bc_snap {
        persist_broadcast_snapshot(deps, context_id, bc);
    }
    deps.event_log.append_context_event_with_payload(
        &context_id_bytes,
        "AccessRevoked",
        actor_did,
        Some(&serde_json::json!({"target_did": did.as_ref()})),
    )?;
    state.checkpoint_events_since += 1;

    // H7: Rotate sender key after write-side revocation.
    if needs_sender_key_rotation {
        if let Err(e) = deps.crypto.rotate_sender_key(&context_id_bytes) {
            tracing::warn!(
                context_id = %context_id,
                error = %e,
                "rotate_sender_key failed after access revocation"
            );
        }
        // drain_and_deliver_sender_keys still lives in lifecycle_helpers
        // (legacy supervisor-shape until Phase 2A.9). Reach via shim.
        let supervisor = deps.supervisor.shim_supervisor();
        if let Err(e) = crate::context::lifecycle_helpers::drain_and_deliver_sender_keys(
            supervisor.as_ref(),
            context_id,
            &context_id_bytes,
        ) {
            tracing::warn!(
                context_id = %context_id,
                error = %e,
                "drain_and_deliver_sender_keys failed after access revocation"
            );
        }
    }

    Ok(rotated)
}

// ---------------------------------------------------------------------------
// execute_restore_access (per-action leaf helper)
// ---------------------------------------------------------------------------

/// Executes a `RestoreAccess` governance action.
pub async fn execute_restore_access(
    state: &mut PerContextState,
    deps: &ActorDeps,
    context_id: &str,
    did: &DID,
    capabilities: &[Capability],
    _proposal_id: ProposalId,
    actor_did: &str,
) -> Result<(), ContextError> {
    let context_id_bytes = context_id_to_bytes(context_id);

    require_active(&state.handle)?;

    if !state.role_state.ceiling.contains(&Capability::MemberBan) {
        return Err(ContextError::PermissionDenied(
            "member:ban (MemberBan) capability not in ceiling".to_owned(),
        ));
    }

    let suspended_set = state.role_state.suspended_capabilities.get(did.as_ref());
    let nothing_suspended_for_request =
        suspended_set.is_none_or(|set| !capabilities.iter().any(|c| set.contains(c)));
    let read_excluded = state.access.read_exclusion_list.contains(did);
    let read_requested = capabilities.contains(&Capability::MessagesRead);
    if nothing_suspended_for_request && !(read_requested && read_excluded) {
        return Err(ContextError::NothingToRestore(format!(
            "no suspended capabilities to restore for {did}"
        )));
    }

    state
        .role_state
        .restore_capabilities(did.as_ref(), capabilities);

    let has_read = capabilities.contains(&Capability::MessagesRead);
    let bc_snap = if has_read {
        state.access.read_exclusion_list.remove(did);

        let snap = state.broadcast_context.as_mut().map(|bc| {
            bc.governance_unban_subscriber(&did.0);
            bc.to_snapshot()
        });

        if state.broadcast_context.is_none() {
            let restored_key =
                scp_protocol::crypto::access_keys::generate_access_key(context_id, did.as_ref());
            state
                .access
                .access_key_store
                .set(context_id, did.as_ref(), restored_key);
        }

        emit(
            state,
            ContextEvent::ReadAccessRestored { did: did.clone() },
            context_id,
            deps,
        );
        emit(
            state,
            ContextEvent::AccessKeyRestored {
                did: did.clone(),
                new_epoch: 1,
            },
            context_id,
            deps,
        );

        snap
    } else {
        None
    };

    if capabilities.contains(&Capability::MessagesWrite) {
        emit(
            state,
            ContextEvent::WriteAccessRestored { did: did.clone() },
            context_id,
            deps,
        );
    }

    crate::context::messaging_helpers::persist_state_best_effort(state, deps, context_id);
    if let Some(ref bc) = bc_snap {
        persist_broadcast_snapshot(deps, context_id, bc);
    }
    deps.event_log
        .append_context_event(&context_id_bytes, "AccessRestored", actor_did)?;
    state.checkpoint_events_since += 1;

    Ok(())
}

// ---------------------------------------------------------------------------
// execute_add_member (per-action leaf helper)
// ---------------------------------------------------------------------------

pub async fn execute_add_member(
    state: &mut PerContextState,
    deps: &ActorDeps,
    context_id: &str,
    did: &DID,
    role: &str,
    _proposal_id: ProposalId,
    actor_did: &str,
) -> Result<(), ContextError> {
    let context_id_bytes = context_id_to_bytes(context_id);

    require_active(&state.handle)?;

    let add_output = deps
        .crypto
        .add_member(&context_id_bytes, did, None)
        .map_err(|e| ContextError::MembershipFailed(e.to_string()))?;

    state.role_state.members.insert(did.to_string());
    let tokens = roles::system_assign_role(&mut state.role_state, did, role, &*deps.clock)
        .map_err(|e| ContextError::MembershipFailed(e.to_string()))?;
    let creator_did = state.role_state.creator_did.clone();

    state
        .membership
        .add_member(did.clone(), role.to_owned(), tokens);

    let access_key =
        scp_protocol::crypto::access_keys::generate_access_key(context_id, did.as_ref());
    state
        .access
        .access_key_store
        .set(context_id, did.as_ref(), access_key);

    emit(
        state,
        ContextEvent::MemberJoined {
            member_did: did.clone(),
            role_name: role.to_owned(),
        },
        context_id,
        deps,
    );

    // push_welcome_event still works on legacy `state::PerContextState`,
    // but the actor `PerContextState` and legacy share `receive_buffer`,
    // `emit_event`-equivalent paths. Do the equivalent inline.
    if !add_output.welcome_bytes.is_empty() {
        emit(
            state,
            ContextEvent::WelcomeGenerated {
                context_id: context_id.to_owned(),
                creator_did: DID(creator_did),
                member_did: did.clone(),
                welcome_bytes: scp_protocol::context::membership::RedactedBytes(
                    add_output.welcome_bytes,
                ),
                commit_bytes: scp_protocol::context::membership::RedactedBytes(
                    add_output.commit_bytes,
                ),
            },
            context_id,
            deps,
        );
    }

    crate::context::messaging_helpers::persist_state_best_effort(state, deps, context_id);
    deps.event_log
        .append_context_event(&context_id_bytes, "MemberJoined", actor_did)?;
    state.checkpoint_events_since += 1;
    Ok(())
}

// ---------------------------------------------------------------------------
// execute_remove_member (per-action leaf helper)
// ---------------------------------------------------------------------------

pub async fn execute_remove_member(
    state: &mut PerContextState,
    deps: &ActorDeps,
    context_id: &str,
    did: &DID,
    _proposal_id: ProposalId,
    actor_did: &str,
) -> Result<(), ContextError> {
    let context_id_bytes = context_id_to_bytes(context_id);

    require_active(&state.handle)?;

    if !state.membership.contains(did) {
        return Err(ContextError::MemberNotFound(did.to_string()));
    }

    // H9: MLS group removal FIRST (hard security boundary).
    let remove_output = deps
        .crypto
        .remove_member(&context_id_bytes, did)
        .map_err(|e| ContextError::MembershipFailed(e.to_string()))?;

    if let Err(e) = deps
        .crypto
        .remove_member_sender_key(&context_id_bytes, did.as_ref())
    {
        return fail_close_remove_member(
            state,
            deps,
            context_id,
            did,
            "remove_member_sender_key",
            &e.to_string(),
        );
    }

    if let Err(e) = deps.crypto.rotate_sender_key(&context_id_bytes) {
        return fail_close_remove_member(
            state,
            deps,
            context_id,
            did,
            "rotate_sender_key",
            &e.to_string(),
        );
    }

    state.membership.remove_member(did);
    state.role_state.members.remove(did.as_ref());
    state.role_state.assignments.remove(did.as_ref());
    state.role_state.member_capabilities.remove(did.as_ref());

    state
        .access
        .access_key_store
        .remove(context_id, did.as_ref());

    state.pseudonym_registry.remove(did);

    emit(
        state,
        ContextEvent::MemberLeft {
            member_did: did.clone(),
        },
        context_id,
        deps,
    );

    try_broadcast_commit_or_enqueue(
        state,
        deps,
        context_id,
        remove_output.commit_bytes,
        CommitOperation::RemoveMember {
            target_did: did.clone(),
        },
        actor_did,
    )
    .await?;

    // drain_and_deliver_sender_keys still lives in lifecycle_helpers
    // (legacy supervisor-shape until Phase 2A.9).
    let supervisor = deps.supervisor.shim_supervisor();
    if let Err(e) = crate::context::lifecycle_helpers::drain_and_deliver_sender_keys(
        supervisor.as_ref(),
        context_id,
        &context_id_bytes,
    ) {
        tracing::warn!(
            context_id = %context_id,
            error = %e,
            "failed to deliver rotated sender keys after member removal"
        );
    }

    crate::context::messaging_helpers::persist_state_best_effort(state, deps, context_id);
    deps.event_log
        .append_context_event(&context_id_bytes, "MemberLeft", actor_did)?;
    state.checkpoint_events_since += 1;
    Ok(())
}

// ---------------------------------------------------------------------------
// execute_change_role (per-action leaf helper)
// ---------------------------------------------------------------------------

pub async fn execute_change_role(
    state: &mut PerContextState,
    deps: &ActorDeps,
    context_id: &str,
    did: &DID,
    new_role: &str,
    _proposal_id: ProposalId,
    actor_did: &str,
) -> Result<(), ContextError> {
    let context_id_bytes = context_id_to_bytes(context_id);

    require_active(&state.handle)?;

    if !state.membership.contains(did) {
        return Err(ContextError::MemberNotFound(did.to_string()));
    }

    let tokens = roles::system_assign_role(&mut state.role_state, did, new_role, &*deps.clock)
        .map_err(|e| ContextError::MembershipFailed(e.to_string()))?;

    if let Some(info) = state.membership.get_mut(did) {
        new_role.clone_into(&mut info.role_name);
        info.tokens = tokens;
    }

    crate::context::messaging_helpers::persist_state_best_effort(state, deps, context_id);
    deps.event_log
        .append_context_event(&context_id_bytes, "RoleAssigned", actor_did)?;
    state.checkpoint_events_since += 1;
    Ok(())
}

// ---------------------------------------------------------------------------
// execute_register_tool (per-action leaf helper)
// ---------------------------------------------------------------------------

pub async fn execute_register_tool(
    state: &mut PerContextState,
    deps: &ActorDeps,
    context_id: &str,
    registration: &ToolRegistration,
    _proposal_id: ProposalId,
    actor_did: &str,
) -> Result<(), ContextError> {
    let context_id_bytes = context_id_to_bytes(context_id);

    require_active(&state.handle)?;

    if !state.role_state.ceiling.contains(&Capability::ToolRegister) {
        return Err(ContextError::PermissionDenied(
            "context ceiling does not include tool registration capability".into(),
        ));
    }

    if state.governance.registered_tools.len() >= MAX_REGISTERED_TOOLS {
        return Err(ContextError::LimitExceeded(format!(
            "registered tool limit of {MAX_REGISTERED_TOOLS} exceeded"
        )));
    }
    state.governance.registered_tools.push(registration.clone());

    crate::context::messaging_helpers::persist_state_best_effort(state, deps, context_id);
    deps.event_log
        .append_context_event(&context_id_bytes, "ToolRegistered", actor_did)?;
    state.checkpoint_events_since += 1;
    Ok(())
}

// ---------------------------------------------------------------------------
// execute_remove_tool (per-action leaf helper)
// ---------------------------------------------------------------------------

pub async fn execute_remove_tool(
    state: &mut PerContextState,
    deps: &ActorDeps,
    context_id: &str,
    tool_id: &str,
    _proposal_id: ProposalId,
    actor_did: &str,
) -> Result<(), ContextError> {
    let context_id_bytes = context_id_to_bytes(context_id);

    require_active(&state.handle)?;

    state
        .governance
        .registered_tools
        .retain(|t| t.tool_id != tool_id);

    crate::context::messaging_helpers::persist_state_best_effort(state, deps, context_id);
    deps.event_log
        .append_context_event(&context_id_bytes, "ToolRemoved", actor_did)?;
    state.checkpoint_events_since += 1;
    Ok(())
}

// ---------------------------------------------------------------------------
// execute_modify_ceiling (per-action leaf helper)
// ---------------------------------------------------------------------------

pub async fn execute_modify_ceiling(
    state: &mut PerContextState,
    deps: &ActorDeps,
    context_id: &str,
    new_ceiling: &[Capability],
    proposal_id: ProposalId,
    actor_did: &str,
) -> Result<(), ContextError> {
    let context_id_bytes = context_id_to_bytes(context_id);

    require_active(&state.handle)?;

    if !matches!(
        state.handle.params().ceiling_policy,
        scp_protocol::context::params::CeilingPolicy::Governed
    ) {
        return Err(ContextError::PermissionDenied(
            "ceiling_policy is not Governed".to_owned(),
        ));
    }

    if state.governance.pending_ceiling_modification.is_some() {
        return Err(ContextError::PermissionDenied(
            "a ceiling modification is already pending notification period".to_owned(),
        ));
    }

    let now = deps.clock.now_secs();
    let effective_at = now + CEILING_CHANGE_NOTIFICATION_PERIOD_SECS;
    state.governance.pending_ceiling_modification = Some(PendingCeilingModification {
        new_capabilities: new_ceiling.to_vec(),
        notified_at: now,
        effective_at,
        proposal_id,
    });

    emit(
        state,
        ContextEvent::CeilingChangeNotification {
            new_capabilities: new_ceiling.to_vec(),
            notified_at: now,
            effective_at,
            proposal_id,
        },
        context_id,
        deps,
    );

    crate::context::messaging_helpers::persist_state_best_effort(state, deps, context_id);
    deps.event_log.append_context_event(
        &context_id_bytes,
        "CeilingModificationPending",
        actor_did,
    )?;
    state.checkpoint_events_since += 1;
    Ok(())
}

// ---------------------------------------------------------------------------
// execute_close_context (per-action leaf helper)
// ---------------------------------------------------------------------------

pub async fn execute_close_context(
    state: &mut PerContextState,
    deps: &ActorDeps,
    context_id: &str,
    _reason: Option<&str>,
    _proposal_id: ProposalId,
    actor_did: &str,
) -> Result<(), ContextError> {
    let context_id_bytes = context_id_to_bytes(context_id);

    require_active(&state.handle)?;
    let handle = state.handle.clone();

    // Transition to Closing via the state machine. The actor owns
    // `state` so this is a single linear sequence.
    handle
        .transition_to(&ContextState::Closing)
        .await
        .map_err(|_| ContextError::PermissionDenied("cannot transition to Closing".to_owned()))?;

    state.ttl.timer.cancel();
    state.governance.timeout_task.cancel();
    state.broadcast_context = None;
    state.governance.decay_participation();

    crate::context::messaging_helpers::persist_state_best_effort(state, deps, context_id);
    deps.event_log
        .append_context_event(&context_id_bytes, "ContextClosing", actor_did)?;
    state.checkpoint_events_since += 1;
    Ok(())
}

// ---------------------------------------------------------------------------
// execute_extend_ttl (per-action leaf helper)
// ---------------------------------------------------------------------------

/// Extends the context's TTL. Requires unanimous consent from ALL
/// current members regardless of governance model — protocol-level
/// override per ADR-031 §4d and spec §5.10.
#[allow(clippy::too_many_arguments)]
pub async fn execute_extend_ttl(
    state: &mut PerContextState,
    deps: &ActorDeps,
    context_id: &str,
    additional_secs: u64,
    approvals: &[scp_protocol::context::governance::SignedVote],
    proposal_id: ProposalId,
    actor_did: &str,
) -> Result<(), ContextError> {
    let context_id_bytes = context_id_to_bytes(context_id);

    require_active(&state.handle)?;

    let member_dids: std::collections::HashSet<&str> =
        state.membership.member_dids().map(|d| &**d).collect();
    let approval_dids: std::collections::HashSet<&str> =
        approvals.iter().map(|v| &*v.voter_did).collect();
    let missing: Vec<&str> = member_dids.difference(&approval_dids).copied().collect();
    if !missing.is_empty() {
        let rejecting_members: Vec<&str> = missing.clone();
        let rejected_payload = serde_json::json!({
            "event": "TTLExtensionRejected",
            "proposal_id": hex::encode(proposal_id),
            "rejecting_members": rejecting_members,
        });
        deps.event_log.append_context_event(
            &context_id_bytes,
            &rejected_payload.to_string(),
            actor_did,
        )?;
        state.checkpoint_events_since += 1;
        return Err(ContextError::PermissionDenied(format!(
            "TTL extension requires unanimous consent — {} of {} members have not approved",
            missing.len(),
            member_dids.len()
        )));
    }

    let consenting: Vec<String> = approval_dids.iter().map(|d| (*d).to_owned()).collect();

    state.ttl.timer.cancel();
    let old_dl = state.ttl.timer.deadline_unix_secs.unwrap_or(0);

    let now = deps.clock.now_secs();
    let remaining_secs = state.ttl.timer.deadline_unix_secs.as_mut().map(|deadline| {
        *deadline = deadline.saturating_add(additional_secs);
        deadline.saturating_sub(now)
    });

    let new_dl = state.ttl.timer.deadline_unix_secs.unwrap_or(0);

    state.ttl.timer.cancel = Arc::new(tokio::sync::Notify::new());
    state.ttl.timer.task = None;

    // Phase 2A.6 Option B: actor-shape ttl_close_helpers::start_ttl_timer
    // exists. Call it if a remaining duration is set.
    if let Some(secs) = remaining_secs {
        let handle = state.handle.clone();
        crate::context::ttl_close_helpers::start_ttl_timer(
            state,
            deps,
            context_id,
            std::time::Duration::from_secs(secs),
            handle,
        )
        .await;
    }

    crate::context::messaging_helpers::persist_state_best_effort(state, deps, context_id);

    let extended_payload = serde_json::json!({
        "event": "TTLExtended",
        "old_deadline_unix": old_dl,
        "new_deadline_unix": new_dl,
        "proposal_id": hex::encode(proposal_id),
        "consenting_members": consenting,
    });
    deps.event_log.append_context_event(
        &context_id_bytes,
        &extended_payload.to_string(),
        actor_did,
    )?;
    state.checkpoint_events_since += 1;
    Ok(())
}

// ---------------------------------------------------------------------------
// execute_transfer_admin (per-action leaf helper)
// ---------------------------------------------------------------------------

pub async fn execute_transfer_admin(
    state: &mut PerContextState,
    deps: &ActorDeps,
    context_id: &str,
    new_admin: &DID,
    _proposal_id: ProposalId,
    actor_did: &str,
) -> Result<(), ContextError> {
    let context_id_bytes = context_id_to_bytes(context_id);

    require_active(&state.handle)?;

    if !state.membership.contains(new_admin) {
        return Err(ContextError::MemberNotFound(new_admin.to_string()));
    }

    let current_admins: Vec<String> = state
        .role_state
        .assignments
        .iter()
        .filter(|(_, a)| a.role_name == "admin")
        .map(|(did, _)| did.clone())
        .collect();
    for admin_did in &current_admins {
        roles::system_assign_role(&mut state.role_state, admin_did, "member", &*deps.clock)
            .map_err(|e| ContextError::MembershipFailed(e.to_string()))?;
        if let Some(info) = state.membership.get_mut(admin_did) {
            "member".clone_into(&mut info.role_name);
        }
    }
    let tokens =
        roles::system_assign_role(&mut state.role_state, new_admin, "admin", &*deps.clock)
            .map_err(|e| ContextError::MembershipFailed(e.to_string()))?;
    if let Some(info) = state.membership.get_mut(new_admin) {
        "admin".clone_into(&mut info.role_name);
        info.tokens = tokens;
    }

    crate::context::messaging_helpers::persist_state_best_effort(state, deps, context_id);
    deps.event_log
        .append_context_event(&context_id_bytes, "AdminTransferred", actor_did)?;
    state.checkpoint_events_since += 1;
    Ok(())
}

// ---------------------------------------------------------------------------
// execute_create_child_context (per-action leaf helper)
// ---------------------------------------------------------------------------

pub async fn execute_create_child_context(
    state: &mut PerContextState,
    deps: &ActorDeps,
    context_id: &str,
    _params: &ContextParams,
    _proposal_id: ProposalId,
    actor_did: &str,
) -> Result<(), ContextError> {
    let context_id_bytes = context_id_to_bytes(context_id);

    require_active(&state.handle)?;

    if !state
        .role_state
        .ceiling
        .contains(&Capability::ChildContextCreate)
    {
        return Err(ContextError::PermissionDenied(
            "context ceiling does not include child context creation capability".into(),
        ));
    }

    deps.event_log
        .append_context_event(&context_id_bytes, "ChildContextCreated", actor_did)?;
    state.checkpoint_events_since += 1;
    Ok(())
}

// ---------------------------------------------------------------------------
// execute_modify_pruning_policy (per-action leaf helper)
// ---------------------------------------------------------------------------

pub async fn execute_modify_pruning_policy(
    state: &mut PerContextState,
    deps: &ActorDeps,
    context_id: &str,
    new_policy: &PruningPolicy,
    _proposal_id: ProposalId,
    actor_did: &str,
) -> Result<(), ContextError> {
    let context_id_bytes = context_id_to_bytes(context_id);

    let structural_mul_bp = new_policy
        .event_type_retention
        .structural_retention_multiplier;
    if structural_mul_bp == 0 {
        return Err(ContextError::PermissionDenied(
            "structural_retention_multiplier must be > 0".to_owned(),
        ));
    }
    let operational_mul_bp = new_policy
        .event_type_retention
        .operational_retention_multiplier;
    if operational_mul_bp == 0 {
        return Err(ContextError::PermissionDenied(
            "operational_retention_multiplier must be > 0".to_owned(),
        ));
    }

    if let Some(ref tb) = new_policy.time_based
        && tb.retention_secs < 2_592_000
    {
        return Err(ContextError::PermissionDenied(
            "time_based.retention_secs must be >= 2,592,000 (30 days)".to_owned(),
        ));
    }
    if let Some(ref tb) = new_policy.time_based {
        let effective = tb
            .retention_secs
            .saturating_mul(u64::from(structural_mul_bp))
            / 10_000;
        if effective < 7_776_000 {
            return Err(ContextError::PermissionDenied(
                "effective structural event retention must be >= 7,776,000 seconds (90 days)"
                    .to_owned(),
            ));
        }
    }

    require_active(&state.handle)?;
    state.governance.pruning_policy = Some(new_policy.clone());

    crate::context::messaging_helpers::persist_state_best_effort(state, deps, context_id);
    deps.event_log
        .append_context_event(&context_id_bytes, "PruningPolicyModified", actor_did)?;
    state.checkpoint_events_since += 1;
    Ok(())
}

// ---------------------------------------------------------------------------
// execute_add_signer (per-action leaf helper)
// ---------------------------------------------------------------------------

pub async fn execute_add_signer(
    state: &mut PerContextState,
    deps: &ActorDeps,
    context_id: &str,
    did: &DID,
    _proposal_id: ProposalId,
    actor_did: &str,
) -> Result<(), ContextError> {
    let context_id_bytes = context_id_to_bytes(context_id);

    require_active(&state.handle)?;

    if !state.membership.contains(did) {
        return Err(ContextError::MemberNotFound(did.to_string()));
    }
    if state.governance.threshold_signers.contains(did) {
        return Err(ContextError::PermissionDenied(format!(
            "DID is already a signer: {did}"
        )));
    }
    if state.governance.threshold_signers.len() >= MAX_THRESHOLD_SIGNERS {
        return Err(ContextError::LimitExceeded(format!(
            "threshold signer limit of {MAX_THRESHOLD_SIGNERS} exceeded"
        )));
    }
    state.governance.threshold_signers.push(did.clone());

    let creator_did = state.role_state.creator_did.clone();
    let capabilities = [Capability::GovernancePropose, Capability::GovernanceVote];
    for cap in &capabilities {
        let att = roles::UcanAttestation {
            with: format!("scp:ctx:{context_id}/{cap}"),
            can: "invoke".to_owned(),
        };
        let nonce = scp_protocol::crypto::ucan::nonce::generate_nonce(&*deps.clock);
        let token = roles::UcanToken {
            iss: creator_did.clone(),
            aud: did.to_string(),
            att: vec![att],
            nnc: nonce,
        };
        state
            .role_state
            .member_capabilities
            .entry(did.to_string())
            .or_default()
            .insert(cap.clone());
        if let Some(info) = state.membership.get_mut(did) {
            info.tokens.push(token);
        }
    }

    crate::context::messaging_helpers::persist_state_best_effort(state, deps, context_id);
    deps.event_log
        .append_context_event(&context_id_bytes, "SignerAdded", actor_did)?;
    state.checkpoint_events_since += 1;
    Ok(())
}

// ---------------------------------------------------------------------------
// execute_remove_signer (per-action leaf helper)
// ---------------------------------------------------------------------------

pub async fn execute_remove_signer(
    state: &mut PerContextState,
    deps: &ActorDeps,
    context_id: &str,
    did: &DID,
    _proposal_id: ProposalId,
    actor_did: &str,
) -> Result<(), ContextError> {
    let context_id_bytes = context_id_to_bytes(context_id);

    require_active(&state.handle)?;

    let before = state.governance.threshold_signers.len();
    state.governance.threshold_signers.retain(|s| s != did);
    if state.governance.threshold_signers.len() == before {
        return Err(ContextError::MemberNotFound(did.to_string()));
    }
    if state.governance.threshold_value > 0 {
        let remaining =
            u32::try_from(state.governance.threshold_signers.len()).unwrap_or(u32::MAX);
        if state.governance.threshold_value > remaining {
            state.governance.threshold_signers.push(did.clone());
            return Err(ContextError::PermissionDenied(format!(
                "removing signer would leave {remaining} signers < threshold {}",
                state.governance.threshold_value
            )));
        }
    }

    if let Some(caps) = state.role_state.member_capabilities.get_mut(did.as_ref()) {
        caps.retain(|c| {
            !matches!(
                c,
                Capability::GovernancePropose | Capability::GovernanceVote
            )
        });
    }
    if let Some(info) = state.membership.get_mut(did) {
        info.tokens.retain(|t| {
            !t.att.iter().any(|a| {
                a.with.contains("governance:propose") || a.with.contains("governance:vote")
            })
        });
    }

    crate::context::messaging_helpers::persist_state_best_effort(state, deps, context_id);
    deps.event_log
        .append_context_event(&context_id_bytes, "SignerRemoved", actor_did)?;
    state.checkpoint_events_since += 1;
    Ok(())
}

// ---------------------------------------------------------------------------
// execute_modify_threshold (per-action leaf helper)
// ---------------------------------------------------------------------------

pub async fn execute_modify_threshold(
    state: &mut PerContextState,
    deps: &ActorDeps,
    context_id: &str,
    new_threshold: u32,
    _proposal_id: ProposalId,
    actor_did: &str,
) -> Result<(), ContextError> {
    let context_id_bytes = context_id_to_bytes(context_id);

    require_active(&state.handle)?;

    let signer_count =
        u32::try_from(state.governance.threshold_signers.len()).unwrap_or(u32::MAX);
    if new_threshold == 0 || new_threshold > signer_count {
        return Err(ContextError::PermissionDenied(format!(
            "threshold must be 1..={signer_count}, got {new_threshold}"
        )));
    }
    state.governance.threshold_value = new_threshold;

    crate::context::messaging_helpers::persist_state_best_effort(state, deps, context_id);
    deps.event_log
        .append_context_event(&context_id_bytes, "ThresholdModified", actor_did)?;
    state.checkpoint_events_since += 1;
    Ok(())
}

// ---------------------------------------------------------------------------
// execute_establish_tool_interface (per-action leaf helper)
// ---------------------------------------------------------------------------

pub async fn execute_establish_tool_interface(
    state: &mut PerContextState,
    deps: &ActorDeps,
    context_id: &str,
    interface: &ToolInterface,
    _proposal_id: ProposalId,
    actor_did: &str,
) -> Result<(), ContextError> {
    let context_id_bytes = context_id_to_bytes(context_id);

    require_active(&state.handle)?;

    if !state.role_state.ceiling.contains(&Capability::ToolInterface) {
        return Err(ContextError::PermissionDenied(
            "context ceiling does not include tool interface capability".into(),
        ));
    }

    if state.governance.tool_interfaces.len() >= MAX_TOOL_INTERFACES {
        return Err(ContextError::LimitExceeded(format!(
            "tool interface limit of {MAX_TOOL_INTERFACES} exceeded"
        )));
    }
    state.governance.tool_interfaces.push(interface.clone());

    crate::context::messaging_helpers::persist_state_best_effort(state, deps, context_id);
    deps.event_log.append_context_event(
        &context_id_bytes,
        "ToolInterfaceEstablished",
        actor_did,
    )?;
    state.checkpoint_events_since += 1;
    Ok(())
}

// ---------------------------------------------------------------------------
// execute_reset_member (per-action leaf helper)
// ---------------------------------------------------------------------------

pub async fn execute_reset_member(
    state: &mut PerContextState,
    deps: &ActorDeps,
    context_id: &str,
    did: &DID,
    _reason: &str,
    _proposal_id: ProposalId,
    actor_did: &str,
) -> Result<(), ContextError> {
    let context_id_bytes = context_id_to_bytes(context_id);

    require_active(&state.handle)?;

    if !state.membership.contains(did) {
        return Err(ContextError::MemberNotFound(did.to_string()));
    }

    // Member reset = leave + immediately re-join (ADR-029 §Tier 3).
    let remove_output = deps
        .crypto
        .remove_member(&context_id_bytes, did)
        .map_err(|e| ContextError::MembershipFailed(e.to_string()))?;
    let add_output = deps
        .crypto
        .add_member(&context_id_bytes, did, None)
        .map_err(|e| ContextError::MembershipFailed(e.to_string()))?;

    try_broadcast_commit_or_enqueue(
        state,
        deps,
        context_id,
        remove_output.commit_bytes,
        CommitOperation::ResetMember {
            target_did: did.clone(),
            is_remove: true,
        },
        actor_did,
    )
    .await?;
    try_broadcast_commit_or_enqueue(
        state,
        deps,
        context_id,
        add_output.commit_bytes,
        CommitOperation::ResetMember {
            target_did: did.clone(),
            is_remove: false,
        },
        actor_did,
    )
    .await?;

    if let Err(e) = deps
        .crypto
        .remove_member_sender_key(&context_id_bytes, did.as_ref())
    {
        tracing::warn!(
            context_id,
            member = %did,
            error = %e,
            "remove_member_sender_key failed after MLS reset — \
             sender key layer may retain stale key"
        );
    }
    if let Err(e) = deps.crypto.rotate_sender_key(&context_id_bytes) {
        tracing::warn!(
            context_id,
            error = %e,
            "rotate_sender_key failed after MLS reset"
        );
    }

    let supervisor = deps.supervisor.shim_supervisor();
    if let Err(e) = crate::context::lifecycle_helpers::drain_and_deliver_sender_keys(
        supervisor.as_ref(),
        context_id,
        &context_id_bytes,
    ) {
        tracing::warn!(
            context_id = %context_id,
            error = %e,
            "failed to deliver rotated sender keys after member reset"
        );
    }

    deps.event_log
        .append_context_event(&context_id_bytes, "MemberReset", actor_did)?;
    state.checkpoint_events_since += 1;
    state.governance.pending_epoch_resets.push(did.clone());

    Ok(())
}

// ---------------------------------------------------------------------------
// execute_resolve_conflict (per-action leaf helper)
// ---------------------------------------------------------------------------

#[allow(
    clippy::too_many_lines,
    reason = "single-pipeline conflict-resolution scope"
)]
#[allow(clippy::too_many_arguments)]
pub async fn execute_resolve_conflict(
    state: &mut PerContextState,
    deps: &ActorDeps,
    context_id: &str,
    proposal_a: &ProposalId,
    proposal_b: &ProposalId,
    resolution: &scp_protocol::context::governance::ConflictResolution,
    _proposal_id: ProposalId,
    actor_did: &str,
) -> Result<(), ContextError> {
    let context_id_bytes = context_id_to_bytes(context_id);

    require_active(&state.handle)?;

    let (freeze_a, freeze_b, _) = state.governance.freeze.ok_or_else(|| {
        ContextError::PermissionDenied(
            "context is not in governance freeze state — no conflict to resolve".into(),
        )
    })?;
    let proposals_match = (*proposal_a == freeze_a && *proposal_b == freeze_b)
        || (*proposal_a == freeze_b && *proposal_b == freeze_a);
    if !proposals_match {
        return Err(ContextError::PermissionDenied(
            "ResolveConflict proposals do not match the governance freeze".into(),
        ));
    }

    let action_a = state
        .governance
        .approved_proposals
        .get(proposal_a)
        .map(|(p, _, _)| &p.action);
    let action_b = state
        .governance
        .approved_proposals
        .get(proposal_b)
        .map(|(p, _, _)| &p.action);

    let (Some(act_a), Some(act_b)) = (action_a, action_b) else {
        return Err(ContextError::PermissionDenied(
            "one or both conflict proposals are not in the approved set — \
             cannot verify conflict"
                .into(),
        ));
    };

    let proposer_a = &state.governance.approved_proposals[proposal_a].0.proposer_did;
    let proposer_b = &state.governance.approved_proposals[proposal_b].0.proposer_did;
    if !scp_protocol::sync::conflict_resolution::actions_conflict(
        act_a, proposer_a, act_b, proposer_b,
    ) {
        return Err(ContextError::PermissionDenied(
            "the specified proposals do not conflict per \
             sync::conflict_resolution::actions_conflict"
                .into(),
        ));
    }

    match resolution {
        scp_protocol::context::governance::ConflictResolution::AcceptProposal { winner_id } => {
            let loser = if *winner_id == *proposal_a {
                proposal_b
            } else if *winner_id == *proposal_b {
                proposal_a
            } else {
                return Err(ContextError::PermissionDenied(format!(
                    "winner_id {winner_id:?} is not one of the conflicting proposals"
                )));
            };
            let now = deps.clock.now_secs();
            state.governance.executed_proposals.insert(*loser, now);
        }
        scp_protocol::context::governance::ConflictResolution::InvalidateBoth => {
            let now = deps.clock.now_secs();
            state.governance.executed_proposals.insert(*proposal_a, now);
            state.governance.executed_proposals.insert(*proposal_b, now);
        }
    }

    state.governance.freeze = None;

    crate::context::messaging_helpers::persist_state_best_effort(state, deps, context_id);
    deps.event_log
        .append_context_event(&context_id_bytes, "GovernanceConflictResolved", actor_did)?;
    state.checkpoint_events_since += 1;
    Ok(())
}

// ---------------------------------------------------------------------------
// execute_promote_context (per-action leaf helper)
// ---------------------------------------------------------------------------

pub async fn execute_promote_context(
    state: &mut PerContextState,
    deps: &ActorDeps,
    context_id: &str,
    approvals: &[scp_protocol::context::governance::SignedVote],
    _proposal_id: ProposalId,
    actor_did: &str,
) -> Result<(), ContextError> {
    let context_id_bytes = context_id_to_bytes(context_id);

    require_active(&state.handle)?;

    if !matches!(
        state.handle.params().promotion_policy,
        scp_protocol::context::params::PromotionPolicy::Promotable
    ) {
        return Err(ContextError::PermissionDenied(
            "context promotion_policy is not Promotable".to_owned(),
        ));
    }

    let member_dids: std::collections::HashSet<&str> =
        state.membership.member_dids().map(|d| &**d).collect();
    let approval_dids: std::collections::HashSet<&str> =
        approvals.iter().map(|v| &*v.voter_did).collect();
    let missing: Vec<&str> = member_dids.difference(&approval_dids).copied().collect();
    if !missing.is_empty() {
        return Err(ContextError::PermissionDenied(format!(
            "promotion requires unanimous consent — {} of {} members have not approved",
            missing.len(),
            member_dids.len()
        )));
    }

    state.ttl.timer.cancel();
    state.ttl.timer.deadline_unix_secs = None;
    state.handle.promote_memory_scope();

    crate::context::messaging_helpers::persist_state_best_effort(state, deps, context_id);
    deps.event_log
        .append_context_event(&context_id_bytes, "ContextPromoted", actor_did)?;
    state.checkpoint_events_since += 1;
    Ok(())
}

// ---------------------------------------------------------------------------
// execute_rotate_content_keys (per-action leaf helper)
// ---------------------------------------------------------------------------

#[allow(clippy::too_many_lines)]
pub async fn execute_rotate_content_keys(
    state: &mut PerContextState,
    deps: &ActorDeps,
    context_id: &str,
    reason: Option<&str>,
    _proposal_id: ProposalId,
    actor_did: &str,
) -> Result<(), ContextError> {
    let context_id_bytes = context_id_to_bytes(context_id);

    require_active(&state.handle)?;

    let (epoch_output, bc_snap) = if let Some(ref mut bc) = state.broadcast_context {
        bc.rotate_all_author_keys()?;
        let snap = Some(bc.to_snapshot());
        (None, snap)
    } else {
        let epoch_out = deps.crypto.advance_epoch(&context_id_bytes)?;

        let member_dids: Vec<String> =
            state.membership.member_dids().map(|d| d.0.clone()).collect();
        let current_epoch = state
            .access
            .access_key_store
            .get_all(context_id)
            .values()
            .map(scp_protocol::crypto::access_keys::AccessKey::epoch)
            .max()
            .unwrap_or(0);
        let did_refs: Vec<&str> = member_dids.iter().map(String::as_str).collect();
        let rotation = crate::crypto::access_keys::lifecycle::rotate_all_access_keys(
            context_id,
            &did_refs,
            current_epoch,
        )
        .map_err(|e| ContextError::CryptoFailed(e.to_string()))?;
        for new_key in rotation.new_keys {
            let did = new_key.member_did().to_owned();
            state.access.access_key_store.set(context_id, &did, new_key);
        }
        (Some(epoch_out), None)
    };

    emit(
        state,
        ContextEvent::ContentKeysRotated {
            reason: reason.map(String::from),
        },
        context_id,
        deps,
    );

    if let Some(epoch_out) = epoch_output {
        try_broadcast_commit_or_enqueue(
            state,
            deps,
            context_id,
            epoch_out.commit_bytes,
            CommitOperation::RotateContentKeys {
                reason: reason.map(String::from),
            },
            actor_did,
        )
        .await?;
    }

    crate::context::messaging_helpers::persist_state_best_effort(state, deps, context_id);
    if let Some(ref snap) = bc_snap {
        persist_broadcast_snapshot(deps, context_id, snap);
    }

    deps.event_log
        .append_context_event(&context_id_bytes, "ContentKeysRotated", actor_did)?;
    state.checkpoint_events_since += 1;
    Ok(())
}

// ---------------------------------------------------------------------------
// execute_reconfigure_governance (per-action leaf helper)
// ---------------------------------------------------------------------------

#[allow(clippy::too_many_arguments)]
pub async fn execute_reconfigure_governance(
    state: &mut PerContextState,
    deps: &ActorDeps,
    context_id: &str,
    changes: &[scp_protocol::context::governance::GovernanceReconfigAction],
    justification: &scp_protocol::context::governance::DeadlockJustification,
    _proposal_id: ProposalId,
    actor_did: &str,
) -> Result<(), ContextError> {
    if changes.is_empty() {
        return Err(ContextError::PermissionDenied(
            "reconfigure_governance requires at least one change".to_owned(),
        ));
    }
    if justification.unavailable_dids.is_empty() && justification.missed_windows.is_empty() {
        return Err(ContextError::PermissionDenied(
            "deadlock justification must provide evidence (unavailable_dids or missed_windows)"
                .to_owned(),
        ));
    }

    let context_id_bytes = context_id_to_bytes(context_id);

    require_active(&state.handle)?;

    let original_signers = state.governance.threshold_signers.clone();
    let original_threshold = state.governance.threshold_value;

    let reconfigure_result: Result<(), ContextError> = (|| {
        for change in changes {
            match change {
                scp_protocol::context::governance::GovernanceReconfigAction::RemoveInactiveSigner {
                    did,
                } => {
                    state.governance.threshold_signers.retain(|s| s != did);
                }
                scp_protocol::context::governance::GovernanceReconfigAction::ReduceThreshold {
                    new_threshold,
                } => {
                    let signer_count = u32::try_from(state.governance.threshold_signers.len())
                        .unwrap_or(u32::MAX);
                    if *new_threshold == 0 || *new_threshold > signer_count {
                        return Err(ContextError::PermissionDenied(format!(
                            "reconfigured threshold must be 1..={signer_count}, got {new_threshold}"
                        )));
                    }
                    state.governance.threshold_value = *new_threshold;
                }
            }
        }

        if state.governance.threshold_value > 0 {
            let remaining =
                u32::try_from(state.governance.threshold_signers.len()).unwrap_or(u32::MAX);
            if state.governance.threshold_value > remaining {
                return Err(ContextError::PermissionDenied(format!(
                    "reconfiguration left {remaining} signers < threshold {}",
                    state.governance.threshold_value,
                )));
            }
        }
        Ok(())
    })();

    if let Err(e) = reconfigure_result {
        state.governance.threshold_signers = original_signers;
        state.governance.threshold_value = original_threshold;
        return Err(e);
    }

    crate::context::messaging_helpers::persist_state_best_effort(state, deps, context_id);
    deps.event_log
        .append_context_event(&context_id_bytes, "GovernanceReconfigured", actor_did)?;
    state.checkpoint_events_since += 1;
    Ok(())
}

// ---------------------------------------------------------------------------
// execute_set_economic_policy (per-action leaf helper)
// ---------------------------------------------------------------------------

pub async fn execute_set_economic_policy(
    state: &mut PerContextState,
    deps: &ActorDeps,
    context_id: &str,
    policy: &EconomicPolicy,
    proposal_id: ProposalId,
    actor_did: &str,
) -> Result<(), ContextError> {
    scp_protocol::economy::policy::validate_economic_policy_metrics(Some(policy))
        .map_err(|e| ContextError::PermissionDenied(format!("invalid economic policy: {e}")))?;

    let context_id_bytes = context_id_to_bytes(context_id);

    require_active(&state.handle)?;

    if let Some(existing) = &state.governance.economic_policy
        && existing.locked
    {
        return Err(ContextError::PermissionDenied(
            "economic policy is locked and cannot be changed".to_owned(),
        ));
    }

    if state.governance.pending_economic_policy_change.is_some() {
        return Err(ContextError::PermissionDenied(
            "an economic policy change is already pending notification period".to_owned(),
        ));
    }

    let now = deps.clock.now_secs();
    let effective_at = now + ECONOMIC_POLICY_NOTIFICATION_PERIOD_SECS;
    state.governance.pending_economic_policy_change = Some(PendingEconomicPolicyChange {
        new_policy: policy.clone(),
        notified_at: now,
        effective_at,
        proposal_id,
    });

    emit(
        state,
        ContextEvent::EconomicPolicyChangeNotification {
            notified_at: now,
            effective_at,
            proposal_id,
        },
        context_id,
        deps,
    );

    crate::context::messaging_helpers::persist_state_best_effort(state, deps, context_id);
    deps.event_log
        .append_context_event(&context_id_bytes, "EconomicPolicyChanged", actor_did)?;
    state.checkpoint_events_since += 1;
    Ok(())
}

// ---------------------------------------------------------------------------
// execute_approve_spend (per-action leaf helper)
// ---------------------------------------------------------------------------

#[allow(clippy::too_many_arguments)]
pub async fn execute_approve_spend(
    state: &mut PerContextState,
    deps: &ActorDeps,
    context_id: &str,
    spender: &DID,
    amount: scp_protocol::economy::types::Amount,
    purpose: &str,
    _proposal_id: ProposalId,
    actor_did: &str,
) -> Result<(), ContextError> {
    let context_id_bytes = context_id_to_bytes(context_id);

    require_active(&state.handle)?;

    if !state.membership.contains(spender.as_ref()) {
        return Err(ContextError::MemberNotFound(spender.to_string()));
    }

    state.governance.budget_tracker.grant(spender, amount);

    crate::context::messaging_helpers::persist_state_best_effort(state, deps, context_id);
    let payload = serde_json::json!({
        "event": "SpendApproved",
        "spender": spender.as_ref(),
        "amount": amount,
        "purpose": purpose,
    });
    deps.event_log
        .append_context_event(&context_id_bytes, &payload.to_string(), actor_did)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// execute_lock_economic_policy (per-action leaf helper)
// ---------------------------------------------------------------------------

pub async fn execute_lock_economic_policy(
    state: &mut PerContextState,
    deps: &ActorDeps,
    context_id: &str,
    _proposal_id: ProposalId,
    actor_did: &str,
) -> Result<(), ContextError> {
    let context_id_bytes = context_id_to_bytes(context_id);

    require_active(&state.handle)?;

    match &mut state.governance.economic_policy {
        None => {
            return Err(ContextError::PermissionDenied(
                "cannot lock economic policy: no policy is set".to_owned(),
            ));
        }
        Some(policy) if policy.locked => {
            return Err(ContextError::PermissionDenied(
                "economic policy is already locked".to_owned(),
            ));
        }
        Some(policy) => {
            policy.locked = true;
        }
    }

    crate::context::messaging_helpers::persist_state_best_effort(state, deps, context_id);
    deps.event_log
        .append_context_event(&context_id_bytes, "EconomicPolicyLocked", actor_did)?;
    state.checkpoint_events_since += 1;
    Ok(())
}

// ---------------------------------------------------------------------------
// execute_modify_hard_rate_limit (per-action leaf helper)
// ---------------------------------------------------------------------------

pub async fn execute_modify_hard_rate_limit(
    state: &mut PerContextState,
    deps: &ActorDeps,
    context_id: &str,
    new_config: &scp_protocol::economy::antispam::HardRateLimitConfig,
    _proposal_id: ProposalId,
    actor_did: &str,
) -> Result<(), ContextError> {
    let context_id_bytes = context_id_to_bytes(context_id);

    new_config.validate().map_err(|e| {
        ContextError::GovernanceFailed(format!(
            "ModifyHardRateLimit: new config failed validation: {e}"
        ))
    })?;

    require_active(&state.handle)?;

    let mut preserved_state = state.governance.hard_rate_limit.snapshot_entries();
    scp_protocol::economy::antispam::TokenBucketLimiter::validate_and_sanitize_snapshot(
        &mut preserved_state,
        new_config,
        deps.clock.now_secs(),
        scp_protocol::economy::antispam::SNAPSHOT_CLOCK_SKEW_TOLERANCE_SECS,
    )
    .map_err(|e| {
        ContextError::GovernanceFailed(format!(
            "ModifyHardRateLimit: preserved state sanitization failed: {e}"
        ))
    })?;
    state.governance.hard_rate_limit =
        scp_protocol::economy::antispam::TokenBucketLimiter::from_snapshot(
            new_config.clone(),
            preserved_state,
        );

    crate::context::messaging_helpers::persist_state_best_effort(state, deps, context_id);
    deps.event_log
        .append_context_event(&context_id_bytes, "HardRateLimitModified", actor_did)?;
    state.checkpoint_events_since += 1;
    Ok(())
}

// ---------------------------------------------------------------------------
// execute_propose_context_migration (per-action leaf helper)
// ---------------------------------------------------------------------------

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
pub async fn execute_propose_context_migration(
    state: &mut PerContextState,
    deps: &ActorDeps,
    context_id: &str,
    new_context_params: &scp_protocol::context::params::ContextParams,
    reason: &str,
    grace_period_secs: u64,
    auto_invite: bool,
    proposal_id: ProposalId,
    actor_did: &str,
) -> Result<MigrationProposedResult, ContextError> {
    let context_id_bytes = context_id_to_bytes(context_id);

    let destination_context_id = {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(b"SCP-MIGRATION-DEST:");
        hasher.update(context_id.as_bytes());
        hasher.update(proposal_id);
        hex::encode(hasher.finalize())
    };

    let now = deps.clock.now_secs();
    let grace_period_end = now.saturating_add(grace_period_secs);

    let mut dest_params = new_context_params.clone();
    dest_params.migration_source = Some(scp_protocol::context::params::MigrationSource {
        source_context_id: context_id.to_owned(),
        proposal_id,
    });

    require_active(&state.handle)?;

    if state.migration_state.is_some() {
        return Err(ContextError::PermissionDenied(
            "context migration is already in progress".to_owned(),
        ));
    }

    let creator = state
        .membership
        .members()
        .find(|m| m.role_name == "admin")
        .map(|m| m.did.clone())
        .ok_or_else(|| {
            ContextError::PermissionDenied(
                "no admin found in source context for destination creation".to_owned(),
            )
        })?;

    state
        .handle
        .transition_to(&ContextState::MigratingOut)
        .await
        .map_err(|_| {
            ContextError::PermissionDenied("cannot transition to MigratingOut".to_owned())
        })?;

    state.migration_state = Some(MigrationState {
        destination_context_id: destination_context_id.clone(),
        reason: reason.to_owned(),
        grace_period_end,
        auto_invite,
        proposal_id,
    });

    let buffer_len_before_migration = state.receive_buffer.len();

    // Buffer migration events WITHOUT broadcasting (rollback-able block).
    let proposed_event = ContextEvent::ContextMigrationProposed {
        destination_context_id: destination_context_id.clone(),
        reason: reason.to_owned(),
        grace_period_secs,
        auto_invite,
        proposal_id,
    };
    let started_event = ContextEvent::ContextMigrationStarted {
        destination_context_id: destination_context_id.clone(),
        grace_period_end,
    };
    state.receive_buffer.push(proposed_event.clone());
    state.receive_buffer.push(started_event.clone());

    // Create the destination context. lifecycle_helpers::create_context
    // is still &Supervisor-shaped; reach via shim until Phase 2A.9.
    let supervisor = deps.supervisor.shim_supervisor();
    if let Err(e) = crate::context::lifecycle_helpers::create_context(
        supervisor.as_ref(),
        destination_context_id.clone(),
        dest_params,
        creator,
        None,
    )
    .await
    {
        // Roll back: revert source to Active and clear migration state.
        let _ = state.handle.transition_to(&ContextState::Active).await;
        state.migration_state = None;
        state.receive_buffer.truncate(buffer_len_before_migration);
        return Err(ContextError::PermissionDenied(format!(
            "failed to create destination context: {e}"
        )));
    }

    // Broadcast the migration events that were buffered above.
    if let Some(tx) = deps.event_tx.as_ref() {
        let _ = tx.send((context_id.to_owned(), strip_event_payload(&proposed_event)));
        let _ = tx.send((context_id.to_owned(), strip_event_payload(&started_event)));
    }

    crate::context::messaging_helpers::persist_state_best_effort(state, deps, context_id);
    deps.event_log.append_context_event(
        &context_id_bytes,
        "ContextMigrationStarted",
        actor_did,
    )?;
    state.checkpoint_events_since += 1;

    Ok(MigrationProposedResult {
        destination_context_id,
        grace_period_end,
    })
}

// ---------------------------------------------------------------------------
// execute_cancel_context_migration (per-action leaf helper)
// ---------------------------------------------------------------------------

pub async fn execute_cancel_context_migration(
    state: &mut PerContextState,
    deps: &ActorDeps,
    context_id: &str,
    _proposal_id: ProposalId,
    actor_did: &str,
) -> Result<(), ContextError> {
    let context_id_bytes = context_id_to_bytes(context_id);

    let s = state
        .handle
        .try_read_state()
        .ok_or(ContextError::ContextNotActive)?;
    if s != ContextState::MigratingOut {
        return Err(ContextError::PermissionDenied(
            "context is not in MigratingOut state — cannot cancel migration".to_owned(),
        ));
    }

    state
        .handle
        .transition_to(&ContextState::Active)
        .await
        .map_err(|_| {
            ContextError::PermissionDenied(
                "cannot transition from MigratingOut to Active".to_owned(),
            )
        })?;

    let migration = state.migration_state.take().ok_or_else(|| {
        ContextError::PermissionDenied(
            "no migration state found despite MigratingOut state".to_owned(),
        )
    })?;
    let original_proposal_id = migration.proposal_id;

    emit(
        state,
        ContextEvent::ContextMigrationCancelled {
            original_proposal_id,
        },
        context_id,
        deps,
    );

    crate::context::messaging_helpers::persist_state_best_effort(state, deps, context_id);
    deps.event_log.append_context_event(
        &context_id_bytes,
        &format!(
            "ContextMigrationCancelled:{}",
            hex::encode(original_proposal_id)
        ),
        actor_did,
    )?;
    state.checkpoint_events_since += 1;
    Ok(())
}

// ---------------------------------------------------------------------------
// try_broadcast_commit_or_enqueue (transitive helper, actor-shape)
// ---------------------------------------------------------------------------

/// Attempts to broadcast an MLS Commit and, on transport failure,
/// enqueues the commit in the persistent retry queue (PR #1606 C6).
///
/// # Errors
///
/// Returns [`ContextError::EventLogFailed`] if the durable event log
/// append fails.
#[allow(
    clippy::too_many_lines,
    reason = "single-pipeline broadcast-enqueue scope — splitting fragments the failure path"
)]
pub async fn try_broadcast_commit_or_enqueue(
    state: &mut PerContextState,
    deps: &ActorDeps,
    context_id: &str,
    commit_bytes: Vec<u8>,
    operation: CommitOperation,
    actor_did: &str,
) -> Result<(), ContextError> {
    if commit_bytes.is_empty() {
        return Ok(());
    }
    let routing_id = scp_protocol::context::context_routing_id(context_id);
    match deps.transport.send_message(&routing_id, &commit_bytes) {
        Ok(()) => {
            let context_id_bytes = context_id_to_bytes(context_id);
            deps.event_log.append_context_event(
                &context_id_bytes,
                "CommitBroadcasted",
                actor_did,
            )?;
            state.checkpoint_events_since += 1;
            Ok(())
        }
        Err(e) => {
            let now = deps.clock.now_secs();
            let error_str = e.to_string();
            let backoff = commit_retry_backoff(1);
            let pending = PendingCommit {
                commit_bytes,
                routing_id,
                operation: operation.clone(),
                first_attempt_at: now,
                retry_count: 1,
                last_error: Some(error_str.clone()),
                next_attempt_at: now.saturating_add(backoff),
            };
            let label = operation.label();
            let context_id_bytes = context_id_to_bytes(context_id);

            // N2: Cap the pending commits queue.
            if state.pending_commits.len() >= MAX_PENDING_COMMITS {
                state.commit_fault = Some(CommitFaultMarker {
                    operation: operation.clone(),
                    reason: format!("pending commit queue full ({MAX_PENDING_COMMITS} entries)"),
                    retry_count: 1,
                    failed_at: now,
                });
                emit(
                    state,
                    ContextEvent::CommitBroadcastFailed {
                        operation: label.clone(),
                        reason: format!("queue full ({MAX_PENDING_COMMITS}): {error_str}"),
                        attempts: 1,
                    },
                    context_id,
                    deps,
                );
                return Ok(());
            }
            state.pending_commits.push_back(pending);
            emit(
                state,
                ContextEvent::CommitBroadcastPending {
                    operation: label.clone(),
                    error: error_str.clone(),
                    attempt: 1,
                },
                context_id,
                deps,
            );
            deps.event_log.append_context_event(
                &context_id_bytes,
                "CommitBroadcastPending",
                actor_did,
            )?;
            state.checkpoint_events_since += 1;
            tracing::warn!(
                context_id = %context_id,
                operation = %label,
                error = %error_str,
                "MLS commit broadcast failed; enqueued for persistent retry (PR #1606 C6)"
            );
            Ok(())
        }
    }
}
