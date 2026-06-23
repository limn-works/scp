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
use crate::context::governance_logic::ConsequenceStateSplit;
use crate::context::governance_logic::{
    EnforceConsequencesCtx, enforce_triggered_consequences, event_log_entries_for_consequences,
};
use crate::context::state::{
    CEILING_CHANGE_NOTIFICATION_PERIOD_SECS, CommitFaultMarker, CommitOperation,
    ContentKeysRotatedResult, ECONOMIC_POLICY_NOTIFICATION_PERIOD_SECS,
    EXECUTED_PROPOSALS_TTL_SECS, GovernanceActionResult, GovernanceReconfiguredResult,
    MAX_PENDING_COMMITS, MAX_REGISTERED_TOOLS, MAX_THRESHOLD_SIGNERS, MAX_TOOL_INTERFACES,
    MigrationProposedResult, MigrationState, PendingCeilingModification, PendingCommit,
    PendingEconomicPolicyChange, ProposalOutcome, RestoreAccessResult, RevokeResult,
    SuspendMemberResult, commit_retry_backoff, context_id_to_bytes, emit_event_into,
    require_active, require_migrating_out, strip_event_payload,
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

/// Governance-freeze auto-resolution timeout (§ SCP-272): a simultaneous-
/// conflict freeze auto-resolves this many seconds after it began. The expiry
/// instant (`freeze_start + FREEZE_TIMEOUT_SECONDS`) is the convergent deadline
/// recorded on the `GovernanceFreezeExpired` leaf (§7.3.1, §9.9.3).
const FREEZE_TIMEOUT_SECONDS: u64 = 48 * 60 * 60; // 48 hours

/// Commit-provenance for a governance-action leaf: the approved proposal id,
/// the acting DID, and the committer-assigned leaf timestamp.
///
/// The timestamp is `proposal.created_at` — a value bound into the SIGNED
/// proposal, so it is identical and tamper-evident for every member that
/// processes the proposal (convergent-by-construction). The leaf carrying it,
/// however, is currently appended ONLY by the committing member: the
/// receive-side append path is dormant, so governance leaves are not yet
/// replicated cross-member. Cross-member leaf replication is the forward step
/// under ADR-051 (§7.3.1, §9.9.3).
///
/// Bundled so the per-action `execute_*` helpers carry one provenance value
/// instead of three loose trailing parameters (keeps each helper within the
/// argument budget and groups the "who/what/when committed this" triplet).
#[derive(Clone, Copy)]
pub struct CommitMeta<'a> {
    /// The approved proposal whose execution mints this leaf.
    pub pid: ProposalId,
    /// The acting DID recorded as the leaf actor.
    pub actor_did: &'a str,
    /// The convergent committer-assigned leaf timestamp (Unix seconds).
    pub timestamp_secs: u64,
}

/// Returns the [`scp_event_log::EventType`] for a [`GovernanceEvent`] variant.
///
/// Pure projection over a borrowed event; no `state`/`deps` needed.
#[must_use]
pub const fn governance_event_label(event: &GovernanceEvent) -> scp_event_log::EventType {
    use scp_event_log::EventType;
    match event {
        GovernanceEvent::ProposalCreated { .. } => EventType::GovernanceProposalCreated,
        GovernanceEvent::VoteCast { .. } => EventType::GovernanceVoteCast,
        GovernanceEvent::VoteWithdrawn { .. } => EventType::GovernanceVoteWithdrawn,
        GovernanceEvent::ProposalResolved { .. } => EventType::GovernanceProposalResolved,
        GovernanceEvent::DeadlockRecovery { .. } => EventType::GovernanceDeadlockRecovery,
        GovernanceEvent::ConflictDetected { .. } => EventType::GovernanceConflictDetected,
        GovernanceEvent::ConflictResolved { .. } => EventType::GovernanceConflictResolved,
        GovernanceEvent::GovernanceActionExecuted { .. } => EventType::GovernanceActionExecuted,
    }
}

// ---------------------------------------------------------------------------
// translate_timeout_events (pure)
// ---------------------------------------------------------------------------

// `translate_timeout_events` (the actor-shape timeout-event translator)
// is defined at the bottom of this module and driven by the per-context
// actor's governance timeout handler.

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
    cell: &mut crate::context::actor::class_s::ClassSCell,
    deps: &ActorDeps,
    context_id: &str,
) -> Result<(), ContextError> {
    let context_id_bytes = context_id_to_bytes(context_id);
    let now = deps.clock.now_secs();

    let handle_state = cell
        .handle
        .try_read_state()
        .ok_or(ContextError::ContextNotActive)?;
    if handle_state != ContextState::MigratingOut {
        return Err(ContextError::PermissionDenied(
            "context is not in MigratingOut state — cannot tombstone".to_owned(),
        ));
    }

    let migration = cell.migration_state.as_ref().ok_or_else(|| {
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
    // Timer-triggered tombstone (grace period elapsed): the convergent leaf
    // timestamp is the pre-computed grace-period deadline (deterministic across
    // members), never local `now()` (§7.3.1, §9.9.3).
    let tombstone_ts = migration.grace_period_end;

    // The handle FSM is an external effect; the `.await` runs BEFORE the fail-
    // closed persist (the combinator closure is sync). A failed transition
    // returns early, before any `state`-field mutation or persist.
    cell.handle
        .transition_to(&ContextState::Tombstoned)
        .await
        .map_err(|_| {
            ContextError::PermissionDenied(
                "cannot transition from MigratingOut to Tombstoned".to_owned(),
            )
        })?;

    // ADR-049 §9 Class S: tombstoning is a terminal lifecycle transition (the
    // context is migrated out and must not silently re-open) — route the in-state
    // cleanup through `commit_class_s_keep` so it persists fail-closed (keep-
    // direction: on persist failure the tombstone STAYS — silently re-opening a
    // migrated-out context is the unsafe direction). The emit + timer/broadcast/
    // migration/participation cleanup (Class-C) ride the fail-closed persist via
    // `view.rest_mut()`.
    cell.commit_class_s_keep(deps, context_id, |mut view| {
        let state = view.rest_mut();
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
        Ok(())
    })?;

    let tombstone_payload =
        scp_event_log::payload::encode_payload(&scp_event_log::payload::ContextTombstonedPayload {
            destination_id: destination_id.clone(),
            migration_proposal_id: migration_pid,
        })
        .map_err(|e| ContextError::EventLogFailed(e.to_string()))?;
    deps.event_log.append_context_event_with_payload(
        &context_id_bytes,
        scp_event_log::EventType::ContextTombstoned,
        "system",
        tombstone_payload,
        tombstone_ts,
    )?;
    *cell.class_c_view().checkpoint_events_since_mut() += 1;

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
    cell: &mut crate::context::actor::class_s::ClassSCell,
    context_id: &str,
) -> Result<CommitFaultMarker, ContextError> {
    // Clearing the commit-fault marker is a coalesced Class-C mutation (the
    // handler reports `mutated`; the run loop flushes the persist). Take it
    // through the non-persisting Class-C view — no per-site persist injected.
    cell.class_c_view()
        .commit_fault_mut()
        .take()
        .ok_or_else(|| {
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
    cell: &mut crate::context::actor::class_s::ClassSCell,
    deps: &ActorDeps,
    context_id: &str,
    proposal_id: &ProposalId,
    voter_did: &DID,
) -> Result<ProposalStatus, ContextError> {
    require_active(&cell.handle)?;

    // `gov_ctx` is a pure projection over `&PerContextState` (cell `Deref`).
    let gov_ctx = build_governance_context(&*cell, &*deps.clock);
    // Committer-assigned convergent leaf timestamp for the withdrawal commit:
    // the same value the engine context observes and the outgoing commit
    // envelope is stamped with; receivers copy it from the inbound envelope.
    // Never a per-member local reading divergent from the commit (§7.3.1,
    // §9.9.3).
    let withdraw_ts = gov_ctx.now;
    let (status, events) = {
        let mut view = cell.class_c_view();
        view.governance_class_c_mut()
            .engine_mut()
            .withdraw_vote(proposal_id, voter_did, &gov_ctx)
            .map_err(|e| ContextError::PermissionDenied(e.to_string()))?
    };

    let context_id_bytes = context_id_to_bytes(context_id);
    let mut event_count: u64 = 0;
    for event in &events {
        deps.event_log.append_context_event(
            &context_id_bytes,
            governance_event_label(event),
            voter_did.as_ref(),
            withdraw_ts,
        )?;
        event_count += 1;
    }

    // Best-effort persist (matches the pre-migration unconditional
    // `persist_state_best_effort`); the checkpoint bump remains conditional on
    // events having been appended.
    cell.commit_class_c_best_effort(deps, context_id, |mut view| {
        if event_count > 0 {
            *view.checkpoint_events_since_mut() += event_count;
        }
    });

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
    cell: &mut crate::context::actor::class_s::ClassSCell,
    deps: &ActorDeps,
    context_id: &str,
    current_timestamp: u64,
) -> Result<bool, ContextError> {
    require_active(&cell.handle)?;

    let pending = match &cell.governance.pending_ceiling_modification {
        Some(p) if p.is_effective(current_timestamp) => p.clone(),
        _ => return Ok(false),
    };

    // ADR-049 §9 Class S: applying a ceiling modification is a downward-
    // authorization transition (the effective capability ceiling lowers) — route
    // the ceiling-lower + pending-clear through `commit_class_s_keep` so it
    // persists fail-closed (keep-direction: on persist failure the lowered
    // ceiling STAYS — restoring the prior, broader ceiling is the unsafe
    // direction). The not-yet-effective early return above ran before any
    // mutation. The `ceiling` set + pending clear (Class-C) ride the fail-closed
    // persist via `view.rest_mut()`.
    cell.commit_class_s_keep(deps, context_id, |mut view| {
        let state = view.rest_mut();
        state.role_state.ceiling = CapabilityCeiling::new(pending.new_capabilities.iter().cloned());
        state.governance.pending_ceiling_modification = None;
        Ok(())
    })?;

    let context_id_bytes = context_id_to_bytes(context_id);
    deps.event_log.append_context_event(
        &context_id_bytes,
        scp_event_log::EventType::CeilingModified,
        "",
        // Timer-triggered deferred application: the convergent leaf timestamp is
        // the pre-computed effective deadline (deterministic across members),
        // never local `now()` (§7.3.1, §9.9.3).
        pending.effective_at,
    )?;
    *cell.class_c_view().checkpoint_events_since_mut() += 1;

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
    cell: &mut crate::context::actor::class_s::ClassSCell,
    deps: &ActorDeps,
    context_id: &str,
    current_timestamp: u64,
) -> Result<bool, ContextError> {
    // Applying a matured pending economic-policy change is Class-C governance
    // config. The active-state gate + effective-window read go through the
    // cell's `Deref`; the `economic_policy` set + `pending` clear (Class-C) ride
    // `commit_class_c_best_effort`, preserving the prior best-effort persist
    // exactly. The not-yet-effective early return runs before any mutation.
    require_active(&cell.handle)?;

    let pending = match &cell.governance.pending_economic_policy_change {
        Some(p) if p.is_effective(current_timestamp) => p.clone(),
        _ => return Ok(false),
    };

    let effective_at = pending.effective_at;
    cell.commit_class_c_best_effort(deps, context_id, |mut view| {
        let gov = view.governance_class_c_mut();
        *gov.economic_policy_mut() = Some(pending.new_policy);
        *gov.pending_economic_policy_change_mut() = None;
    });

    let context_id_bytes = context_id_to_bytes(context_id);
    deps.event_log.append_context_event(
        &context_id_bytes,
        scp_event_log::EventType::EconomicPolicyApplied,
        "",
        // Timer-triggered deferred application: the convergent leaf timestamp is
        // the pre-computed effective deadline (deterministic across members),
        // never local `now()` (§7.3.1, §9.9.3).
        effective_at,
    )?;
    *cell.class_c_view().checkpoint_events_since_mut() += 1;

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
    cell: &mut crate::context::actor::class_s::ClassSCell,
    deps: &ActorDeps,
    new_proposal: &GovernanceProposal,
) -> Vec<GovernanceEvent> {
    use scp_protocol::context::governance::actions_conflict;

    let mut events = Vec::new();
    // Wall-clock timestamp — used ONLY for the local audit slot of
    // `approved_proposals`. NOT used for the freeze start time (that is
    // derived convergently from the conflicting proposals' signed
    // `created_at`, below) and never used for sequence comparison (H10).
    let current_timestamp = deps.clock.now_secs();

    // H10: assign the monotonic seq for the new proposal up front, and
    // bump the counter immediately so any nested or concurrent call
    // cannot reuse it.
    let new_seq = {
        let mut view = cell.class_c_view();
        let gov = view.governance_class_c_mut();
        let seq = gov.next_proposal_seq();
        *gov.next_proposal_seq_mut() = seq.saturating_add(1);
        seq
    };

    // Check for conflicts with existing approved proposals (read via the
    // cell's `Deref`).
    let mut conflicts = Vec::new();
    for (existing_id, (existing_proposal, existing_seq, existing_timestamp)) in
        &cell.governance.approved_proposals
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

    for (conflicting_id, conflicting_seq, _conflicting_timestamp, conflicting_proposal) in conflicts
    {
        match new_seq.cmp(&conflicting_seq) {
            std::cmp::Ordering::Equal => {
                // Convergent freeze start: derive from the conflicting proposals'
                // signed `created_at` values, never local `now()`. Every member
                // observes the same two signed proposals, so
                // `max(created_at_a, created_at_b)` is identical across members and
                // tamper-evident (it is bound into the signed proposals). The
                // `GovernanceFreezeExpired` leaf (`freeze_start + FREEZE_TIMEOUT`)
                // is thus convergent-by-construction (§7.3.1, §9.9.3), matching the
                // committer-assigned-timestamp treatment of other governance leaves.
                //
                // SECURITY (residual, accepted): `created_at` is proposer-chosen
                // and backdatable (signature-bound only against third parties), so
                // `freeze_start` — and thus the auto-resolution deadline — can be
                // pulled earlier than honest wall-clock. Unlike the deferred
                // ceiling / economic-policy windows (whose apply gate is pinned to
                // a local non-backdatable `observed_at + PERIOD` floor in
                // `is_effective`), the freeze is NOT an authorization control: it
                // is a liveness safety valve that auto-resolves a stuck two-proposal
                // deadlock. Backdating only ENDS a deadlock earlier (benign for
                // safety, and never grants capability), and it requires TWO
                // conflicting SIGNED proposals at the same sequence — i.e. two
                // colluding signers, not a unilateral proposer. The
                // local-floor treatment is therefore intentionally not applied
                // here: it would force widening the `governance.freeze` tuple and
                // its expiry/leaf-deadline consumers for no authorization gain.
                let freeze_start = new_proposal.created_at.max(conflicting_proposal.created_at);
                *cell.class_c_view().governance_class_c_mut().freeze_mut() =
                    Some((new_proposal.proposal_id, conflicting_id, freeze_start));
                events.push(GovernanceEvent::ConflictDetected {
                    proposal_a: new_proposal.proposal_id,
                    proposal_b: conflicting_id,
                });
            }
            std::cmp::Ordering::Less => {
                cell.class_c_view()
                    .governance_class_c_mut()
                    .approved_proposals_mut()
                    .remove(&conflicting_id);
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
        cell.class_c_view()
            .governance_class_c_mut()
            .approved_proposals_mut()
            .insert(
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
    cell: &mut crate::context::actor::class_s::ClassSCell,
    deps: &ActorDeps,
) -> Vec<GovernanceEvent> {
    let current_timestamp = deps.clock.now_secs();

    if let Some((proposal_a, proposal_b, freeze_start)) = cell.governance.freeze
        && current_timestamp.saturating_sub(freeze_start) >= FREEZE_TIMEOUT_SECONDS
    {
        let mut view = cell.class_c_view();
        let gov = view.governance_class_c_mut();
        gov.approved_proposals_mut().remove(&proposal_a);
        gov.approved_proposals_mut().remove(&proposal_b);
        *gov.freeze_mut() = None;

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
pub fn execute_suspend_member(
    cell: &mut crate::context::actor::class_s::ClassSCell,
    deps: &ActorDeps,
    context_id: &str,
    did: &DID,
    capabilities: &[Capability],
    meta: CommitMeta<'_>,
) -> Result<(), ContextError> {
    let CommitMeta {
        pid: _,
        actor_did,
        timestamp_secs,
    } = meta;

    // ADR-049 §9 Class S: member suspension is a downward-authorization
    // transition — route the `role_state` mutation + emit through
    // `commit_class_s_keep` so it persists fail-closed (keep-direction: on
    // persist failure the suspension STAYS applied — un-suspending a member the
    // caller was told was suspended is the unsafe direction). The
    // reject-before-mutate guards return `Err` from inside the closure (no
    // persist runs); the `role_state` strip + emit (Class-C) ride the SAME
    // fail-closed persist via `view.rest_mut()`.
    cell.commit_class_s_keep(deps, context_id, |mut view| {
        require_active(&view.handle)?;

        if !view.role_state.ceiling.contains(&Capability::MemberBan) {
            return Err(ContextError::PermissionDenied(
                "member:ban (MemberBan) capability not in ceiling".to_owned(),
            ));
        }
        if !view.membership.contains(did) {
            return Err(ContextError::MemberNotFound(did.to_string()));
        }

        let state = view.rest_mut();
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
        Ok(())
    })?;

    let context_id_bytes = context_id_to_bytes(context_id);
    deps.event_log.append_context_event(
        &context_id_bytes,
        scp_event_log::EventType::MemberSuspended,
        actor_did,
        timestamp_secs,
    )?;
    *cell.class_c_view().checkpoint_events_since_mut() += 1;
    Ok(())
}

// ---------------------------------------------------------------------------
// execute_revoke (per-action leaf helper)
// ---------------------------------------------------------------------------

/// Executes a `Revoke` governance action — cryptographic key destruction.
///
/// Returns the number of rotated authors (for broadcast contexts).
#[allow(clippy::too_many_lines)]
pub fn execute_revoke(
    cell: &mut crate::context::actor::class_s::ClassSCell,
    deps: &ActorDeps,
    context_id: &str,
    did: &DID,
    access: AccessScope,
    meta: CommitMeta<'_>,
) -> Result<usize, ContextError> {
    let CommitMeta {
        pid: _,
        actor_did,
        timestamp_secs,
    } = meta;
    let context_id_bytes = context_id_to_bytes(context_id);

    // SECURITY-FLAG (ADR-049 §9, FC→FC, no behaviour change): revocation
    // (capability / access / write) is a DOWNWARD-AUTHORIZATION Class-S
    // transition — it MUST persist fail-closed so a crash cannot re-grant
    // authority the caller was told was revoked. The suspension /
    // read-exclusion / access-key writes + their checks are STAGED inside the
    // `commit_class_s_keep` closure (reached via `view.rest_mut()`, which the
    // fail-closed combinator may hand out), and the combinator performs the
    // SAME fail-closed persist the prior inline `persist_state_fail_closed`
    // did (keep-direction: a downward suspension stays applied even if the
    // persist fails — un-applying it would re-grant the revoked authority).
    // A check reject (`Err` from the closure) returns before any persist,
    // exactly as the prior early returns did. The post-persist external work
    // (broadcast snapshot, event-log append, sender-key rotation, the
    // coalesced `checkpoint_events_since` bump) is UNCHANGED and runs after.
    let (rotated, bc_snap, needs_sender_key_rotation) =
        cell.commit_class_s_keep(deps, context_id, |mut view| {
            let state = view.rest_mut();
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
                matches!(access, AccessScope::Write | AccessScope::Both)
                    && state.broadcast_context.is_none();

            Ok((rotated, bc_snap, needs_sender_key_rotation))
        })?;

    if let Some(ref bc) = bc_snap {
        persist_broadcast_snapshot(deps, context_id, bc);
    }
    let access_revoked_payload =
        scp_event_log::payload::encode_payload(&scp_event_log::payload::AccessRevokedPayload {
            target_did: did.as_ref().to_owned(),
        })
        .map_err(|e| ContextError::EventLogFailed(e.to_string()))?;
    deps.event_log.append_context_event_with_payload(
        &context_id_bytes,
        scp_event_log::EventType::AccessRevoked,
        actor_did,
        access_revoked_payload,
        timestamp_secs,
    )?;
    // Coalesced Class-C counter bump (rides the next run-loop persist, exactly
    // as before the combinator migration — NOT covered by the FC persist above).
    *cell.class_c_view().checkpoint_events_since_mut() += 1;

    // H7: Rotate sender key after write-side revocation.
    if needs_sender_key_rotation {
        if let Err(e) = deps.crypto.rotate_sender_key(&context_id_bytes) {
            tracing::warn!(
                context_id = %context_id,
                error = %e,
                "rotate_sender_key failed after access revocation"
            );
        }
        // Phase 2A.9: drain_and_deliver_sender_keys is now actor-shape
        // and operates directly on `state` + `deps`.
        if let Err(e) = crate::context::lifecycle_helpers::drain_and_deliver_sender_keys(
            deps,
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
pub fn execute_restore_access(
    cell: &mut crate::context::actor::class_s::ClassSCell,
    deps: &ActorDeps,
    context_id: &str,
    did: &DID,
    capabilities: &[Capability],
    meta: CommitMeta<'_>,
) -> Result<(), ContextError> {
    let CommitMeta {
        pid: _,
        actor_did,
        timestamp_secs,
    } = meta;
    let context_id_bytes = context_id_to_bytes(context_id);

    // SECURITY-FLAG (ADR-049 §9, CONSCIOUS SAFE STRENGTHENING best-effort→FC):
    // restoring access (clearing a suspension / read-exclusion, re-minting the
    // access key) was persisted BEST-EFFORT. It is routed here through
    // `commit_class_s_keep`, a FAIL-CLOSED persist. This is strictly safer and
    // shrinks the best-effort allowlist: a coalesce-window rollback of a
    // restore would silently re-suspend a member the caller was told was
    // restored — a liveness regression, not a security one — but failing closed
    // here never re-opens an authorization the caller observed as denied (the
    // direction §9 protects), so the strengthening introduces no new risk and
    // removes one. Keep-direction: a restore that did not durably land stays
    // applied in memory and the persist error surfaces (the member is, if
    // anything, MORE permissioned in memory than on disk — the safe direction).
    // The check rejects (`Err` from the closure) run before any persist exactly
    // as the prior early returns did. The post-persist external work (broadcast
    // snapshot, event-log append, coalesced `checkpoint_events_since` bump) is
    // unchanged.
    let bc_snap = cell.commit_class_s_keep(deps, context_id, |mut view| {
        let state = view.rest_mut();
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
                let restored_key = scp_protocol::crypto::access_keys::generate_access_key(
                    context_id,
                    did.as_ref(),
                );
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

        Ok(bc_snap)
    })?;

    if let Some(ref bc) = bc_snap {
        persist_broadcast_snapshot(deps, context_id, bc);
    }
    deps.event_log.append_context_event(
        &context_id_bytes,
        scp_event_log::EventType::AccessRestored,
        actor_did,
        timestamp_secs,
    )?;
    // Coalesced Class-C counter bump (rides the next run-loop persist).
    *cell.class_c_view().checkpoint_events_since_mut() += 1;

    Ok(())
}

// ---------------------------------------------------------------------------
// execute_add_member (per-action leaf helper)
// ---------------------------------------------------------------------------

pub fn execute_add_member(
    cell: &mut crate::context::actor::class_s::ClassSCell,
    deps: &ActorDeps,
    context_id: &str,
    did: &DID,
    role: &str,
    meta: CommitMeta<'_>,
) -> Result<(), ContextError> {
    let CommitMeta {
        pid: _,
        actor_did,
        timestamp_secs,
    } = meta;
    let context_id_bytes = context_id_to_bytes(context_id);

    require_active(&cell.handle)?;

    let add_output = deps
        .crypto
        .add_member(&context_id_bytes, did, None)
        .map_err(|e| ContextError::MembershipFailed(e.to_string()))?;

    // The fallible role assignment mutates the WHOLE `ContextRoleState` — it
    // prunes `suspended_capabilities` (a downward-auth field) to the new role's
    // grants, so the restricted Class-C role view cannot serve it. It runs in a
    // NON-PERSISTING Class-C view borrow (the run-loop / the best-effort persist
    // below covers it): this site is best-effort BY DESIGN — member ADD is
    // coalesce-window-rollback acceptable (ADR-049 §9), so the suspension prune
    // rides the SAME best-effort persist it always did. It is NOT strengthened
    // to fail-closed.
    let tokens = {
        let mut view = cell.class_c_view();
        let role_state = view.role_state_mut();
        role_state.members.insert(did.to_string());
        roles::system_assign_role(role_state, did, role, &*deps.clock)
            .map_err(|e| ContextError::MembershipFailed(e.to_string()))?
    };
    let creator_did = cell.role_state.creator_did.clone();

    // Infallible in-state mutations + the MemberJoined / WelcomeGenerated emits,
    // all riding ONE best-effort persist (unchanged from the pre-migration
    // single `persist_state_best_effort`).
    cell.commit_class_c_best_effort(deps, context_id, |mut view| {
        view.membership_class_c_mut()
            .add_member(did.clone(), role.to_owned(), tokens);

        let access_key =
            scp_protocol::crypto::access_keys::generate_access_key(context_id, did.as_ref());
        view.access_mut()
            .access_key_store
            .set(context_id, did.as_ref(), access_key);

        view.emit_event(
            ContextEvent::MemberJoined {
                member_did: did.clone(),
                role_name: role.to_owned(),
            },
            context_id,
            deps.event_tx.as_ref(),
        );

        // Emit the WelcomeGenerated event inline against actor-owned state.
        if !add_output.welcome_bytes.is_empty() {
            view.emit_event(
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
                deps.event_tx.as_ref(),
            );
        }
    });

    deps.event_log.append_context_event(
        &context_id_bytes,
        scp_event_log::EventType::MemberJoined,
        actor_did,
        timestamp_secs,
    )?;
    *cell.class_c_view().checkpoint_events_since_mut() += 1;
    Ok(())
}

// ---------------------------------------------------------------------------
// execute_remove_member (per-action leaf helper)
// ---------------------------------------------------------------------------

pub fn execute_remove_member(
    cell: &mut crate::context::actor::class_s::ClassSCell,
    deps: &ActorDeps,
    context_id: &str,
    did: &DID,
    meta: CommitMeta<'_>,
) -> Result<(), ContextError> {
    let CommitMeta {
        pid: _,
        actor_did,
        timestamp_secs,
    } = meta;
    let context_id_bytes = context_id_to_bytes(context_id);

    // ADR-049 §9 Class S: member removal is a downward-authorization
    // transition — route the membership/role_state strip (and the MLS commit
    // boundary that precedes it) through `commit_class_s_keep` so the removal
    // persists fail-closed (keep-direction: on persist failure the removal
    // STAYS — re-admitting a removed member is the unsafe direction). The
    // reject-before-mutate guard and the two MLS fail-close arms return `Err`
    // from inside the closure (no persist runs — preserving today's behavior
    // where the fail-close `commit_fault` marker is set but NOT persisted before
    // the early return). All structural mutations + emit + broadcast + sender-
    // key drain ride the SAME fail-closed persist via `view.rest_mut()`.
    cell.commit_class_s_keep(deps, context_id, |mut view| {
        let state = view.rest_mut();

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

        // §9.10.4: drop the removed member's pseudonym routing ID. No-op on a
        // broadcast context (which carries no peer registry).
        if let Some(reg) = state.routing.peer_registry_mut() {
            reg.remove(did);
        }

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
            &CommitOperation::RemoveMember {
                target_did: did.clone(),
            },
        );

        // Phase 2A.9: drain_and_deliver_sender_keys is now actor-shape.
        if let Err(e) = crate::context::lifecycle_helpers::drain_and_deliver_sender_keys(
            deps,
            context_id,
            &context_id_bytes,
        ) {
            tracing::warn!(
                context_id = %context_id,
                error = %e,
                "failed to deliver rotated sender keys after member removal"
            );
        }
        Ok(())
    })?;
    deps.event_log.append_context_event(
        &context_id_bytes,
        scp_event_log::EventType::MemberLeft,
        actor_did,
        timestamp_secs,
    )?;
    *cell.class_c_view().checkpoint_events_since_mut() += 1;
    Ok(())
}

// ---------------------------------------------------------------------------
// execute_change_role (per-action leaf helper)
// ---------------------------------------------------------------------------

pub fn execute_change_role(
    cell: &mut crate::context::actor::class_s::ClassSCell,
    deps: &ActorDeps,
    context_id: &str,
    did: &DID,
    new_role: &str,
    meta: CommitMeta<'_>,
) -> Result<(), ContextError> {
    let CommitMeta {
        pid: _,
        actor_did,
        timestamp_secs,
    } = meta;
    let context_id_bytes = context_id_to_bytes(context_id);

    // ADR-049 §9 Class S: a role change can be a demotion (downward
    // authorization) — route the role assignment through `commit_class_s_keep`
    // so it persists fail-closed (keep-direction: on persist failure the new
    // role STAYS — restoring authority a demotion removed is the unsafe
    // direction). The reject-before-mutate guards return `Err` from inside the
    // closure (no persist runs); the `role_state` + membership mutation (Class-C)
    // rides the SAME fail-closed persist via `view.rest_mut()`.
    cell.commit_class_s_keep(deps, context_id, |mut view| {
        require_active(&view.handle)?;

        if !view.membership.contains(did) {
            return Err(ContextError::MemberNotFound(did.to_string()));
        }

        let state = view.rest_mut();
        let tokens = roles::system_assign_role(&mut state.role_state, did, new_role, &*deps.clock)
            .map_err(|e| ContextError::MembershipFailed(e.to_string()))?;

        if let Some(info) = state.membership.get_mut(did) {
            new_role.clone_into(&mut info.role_name);
            info.tokens = tokens;
        }
        Ok(())
    })?;
    deps.event_log.append_context_event(
        &context_id_bytes,
        scp_event_log::EventType::RoleAssigned,
        actor_did,
        timestamp_secs,
    )?;
    *cell.class_c_view().checkpoint_events_since_mut() += 1;
    Ok(())
}

// ---------------------------------------------------------------------------
// execute_register_tool (per-action leaf helper)
// ---------------------------------------------------------------------------

pub fn execute_register_tool(
    cell: &mut crate::context::actor::class_s::ClassSCell,
    deps: &ActorDeps,
    context_id: &str,
    registration: &ToolRegistration,
    meta: CommitMeta<'_>,
) -> Result<(), ContextError> {
    let CommitMeta {
        pid: _,
        actor_did,
        timestamp_secs,
    } = meta;
    let context_id_bytes = context_id_to_bytes(context_id);

    // Tool registration is an UPWARD grant (Class-C governance config). The
    // fallible guards read through the cell's `Deref` (no mutation); the
    // `registered_tools` push (Class-C) rides `commit_class_c_best_effort`,
    // preserving the prior best-effort persist exactly.
    require_active(&cell.handle)?;

    if !cell.role_state.ceiling.contains(&Capability::ToolRegister) {
        return Err(ContextError::PermissionDenied(
            "context ceiling does not include tool registration capability".into(),
        ));
    }

    if cell.governance.registered_tools.len() >= MAX_REGISTERED_TOOLS {
        return Err(ContextError::LimitExceeded(format!(
            "registered tool limit of {MAX_REGISTERED_TOOLS} exceeded"
        )));
    }
    cell.commit_class_c_best_effort(deps, context_id, |mut view| {
        view.governance_class_c_mut()
            .registered_tools_mut()
            .push(registration.clone());
    });
    deps.event_log.append_context_event(
        &context_id_bytes,
        scp_event_log::EventType::ToolRegistered,
        actor_did,
        timestamp_secs,
    )?;
    *cell.class_c_view().checkpoint_events_since_mut() += 1;
    Ok(())
}

// ---------------------------------------------------------------------------
// execute_remove_tool (per-action leaf helper)
// ---------------------------------------------------------------------------

pub fn execute_remove_tool(
    cell: &mut crate::context::actor::class_s::ClassSCell,
    deps: &ActorDeps,
    context_id: &str,
    tool_id: &str,
    meta: CommitMeta<'_>,
) -> Result<(), ContextError> {
    let CommitMeta {
        pid: _,
        actor_did,
        timestamp_secs,
    } = meta;
    let context_id_bytes = context_id_to_bytes(context_id);

    // ADR-049 §9 Class S: removing a registered tool revokes the authority to
    // invoke it — a downward-authorization transition (the inverse of
    // `execute_register_tool`'s upward grant). Route through `commit_class_s_keep`
    // so the removal persists fail-closed (keep-direction: on persist failure the
    // tool STAYS removed — re-granting invocation of a tool the caller was told
    // was removed is the unsafe direction). The reject-before-mutate guard
    // returns `Err` from inside the closure (no persist runs); the
    // `registered_tools` retain (Class-C) rides the SAME fail-closed persist via
    // `view.rest_mut()`.
    cell.commit_class_s_keep(deps, context_id, |mut view| {
        require_active(&view.handle)?;

        view.rest_mut()
            .governance
            .registered_tools
            .retain(|t| t.tool_id != tool_id);
        Ok(())
    })?;
    deps.event_log.append_context_event(
        &context_id_bytes,
        scp_event_log::EventType::ToolRemoved,
        actor_did,
        timestamp_secs,
    )?;
    *cell.class_c_view().checkpoint_events_since_mut() += 1;
    Ok(())
}

// ---------------------------------------------------------------------------
// execute_modify_ceiling (per-action leaf helper)
// ---------------------------------------------------------------------------

pub fn execute_modify_ceiling(
    cell: &mut crate::context::actor::class_s::ClassSCell,
    deps: &ActorDeps,
    context_id: &str,
    new_ceiling: &[Capability],
    meta: CommitMeta<'_>,
) -> Result<(), ContextError> {
    let CommitMeta {
        pid: proposal_id,
        actor_did,
        timestamp_secs,
    } = meta;
    let context_id_bytes = context_id_to_bytes(context_id);

    // ADR-049 §9 Class S: staging a pending ceiling modification is part of a
    // ceiling-lowering decision chain (downward authorization) — route it
    // through `commit_class_s_keep` so the pending record persists fail-closed
    // (keep-direction: on persist failure the staged modification STAYS — losing
    // a pending downward-authorization record is the unsafe direction). The
    // reject-before-mutate guards return `Err` from inside the closure (no
    // persist runs); the `pending_ceiling_modification` set + emit (Class-C) ride
    // the SAME fail-closed persist via `view.rest_mut()`.
    cell.commit_class_s_keep(deps, context_id, |mut view| {
        let state = view.rest_mut();
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

        // Convergent notification/activation window: anchor on the committer-
        // assigned proposal timestamp (`CommitMeta::timestamp_secs`, every member
        // copies the same value), never local `now()`. `effective_at =
        // proposal.created_at + NOTIFICATION_PERIOD` is therefore identical across
        // members, so the deferred ceiling change activates at the same instant
        // everywhere (§7.3.1, §9.9.3). This convergent value is also what lands on
        // the `CeilingModified` leaf when the change applies.
        //
        // SECURITY: `proposal.created_at` is proposer-chosen and signature-bound
        // only against third parties — the proposer can backdate it freely. Used
        // alone as the apply gate, a proposer could set `created_at` far in the
        // past so `effective_at <= commit time` and collapse the mandatory
        // notification window to zero. To keep activation convergent yet
        // non-backdatable, also record `observed_at` — THIS member's local clock at
        // commit-processing time (not proposer-controlled). `is_effective` requires
        // `current >= max(effective_at, observed_at + PERIOD)`, so the window can
        // never be shorter than `PERIOD` of locally observed time (§5.3.2).
        let notified_at = timestamp_secs;
        let effective_at = notified_at + CEILING_CHANGE_NOTIFICATION_PERIOD_SECS;
        let observed_at = deps.clock.now_secs();
        state.governance.pending_ceiling_modification = Some(PendingCeilingModification {
            new_capabilities: new_ceiling.to_vec(),
            notified_at,
            effective_at,
            observed_at,
            proposal_id,
        });

        emit(
            state,
            ContextEvent::CeilingChangeNotification {
                new_capabilities: new_ceiling.to_vec(),
                notified_at,
                effective_at,
                proposal_id,
            },
            context_id,
            deps,
        );
        Ok(())
    })?;
    deps.event_log.append_context_event(
        &context_id_bytes,
        scp_event_log::EventType::CeilingModificationPending,
        actor_did,
        timestamp_secs,
    )?;
    *cell.class_c_view().checkpoint_events_since_mut() += 1;
    Ok(())
}

// ---------------------------------------------------------------------------
// execute_close_context (per-action leaf helper)
// ---------------------------------------------------------------------------

pub async fn execute_close_context(
    cell: &mut crate::context::actor::class_s::ClassSCell,
    deps: &ActorDeps,
    context_id: &str,
    _reason: Option<&str>,
    meta: CommitMeta<'_>,
) -> Result<(), ContextError> {
    let CommitMeta {
        pid: _,
        actor_did,
        timestamp_secs,
    } = meta;
    let context_id_bytes = context_id_to_bytes(context_id);

    require_active(&cell.handle)?;
    let handle = cell.handle.clone();

    // Transition to Closing via the state machine. The handle FSM is an external
    // (cloned) effect, so the `.await` runs BEFORE the fail-closed persist (the
    // combinator closure is sync). A failed transition returns early, before any
    // `state`-field mutation or persist.
    handle
        .transition_to(&ContextState::Closing)
        .await
        .map_err(|_| ContextError::PermissionDenied("cannot transition to Closing".to_owned()))?;

    // ADR-049 §9 Class S: the lifecycle close transition is security-critical
    // (a closed context must not silently re-open on a crash) — route the in-
    // state cleanup through `commit_class_s_keep` so it persists fail-closed
    // (keep-direction: on persist failure the close STAYS — silently re-opening a
    // closed context is the unsafe direction). The timer/broadcast/participation
    // cleanup (Class-C) rides the fail-closed persist via `view.rest_mut()`.
    cell.commit_class_s_keep(deps, context_id, |mut view| {
        let state = view.rest_mut();
        state.ttl.timer.cancel();
        state.governance.timeout_task.cancel();
        state.broadcast_context = None;
        state.governance.decay_participation();
        Ok(())
    })?;
    deps.event_log.append_context_event(
        &context_id_bytes,
        scp_event_log::EventType::ContextClosing,
        actor_did,
        timestamp_secs,
    )?;
    *cell.class_c_view().checkpoint_events_since_mut() += 1;
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
    cell: &mut crate::context::actor::class_s::ClassSCell,
    deps: &ActorDeps,
    context_id: &str,
    additional_secs: u64,
    approvals: &[scp_protocol::context::governance::SignedVote],
    meta: CommitMeta<'_>,
) -> Result<(), ContextError> {
    let CommitMeta {
        pid: proposal_id,
        actor_did,
        timestamp_secs,
    } = meta;
    let context_id_bytes = context_id_to_bytes(context_id);

    require_active(&cell.handle)?;

    let member_dids: std::collections::HashSet<&str> =
        cell.membership.member_dids().map(|d| &**d).collect();
    let approval_dids: std::collections::HashSet<&str> =
        approvals.iter().map(|v| &*v.voter_did).collect();
    let missing: Vec<&str> = member_dids.difference(&approval_dids).copied().collect();
    if !missing.is_empty() {
        let rejecting_members: Vec<&str> = missing.clone();
        let rejected_payload = scp_event_log::payload::encode_payload(
            &scp_event_log::payload::TtlExtensionRejectedPayload {
                proposal_id,
                rejecting_members: rejecting_members.iter().map(|m| (*m).to_owned()).collect(),
            },
        )
        .map_err(|e| ContextError::EventLogFailed(e.to_string()))?;
        deps.event_log.append_context_event_with_payload(
            &context_id_bytes,
            scp_event_log::EventType::TtlExtensionRejected,
            actor_did,
            rejected_payload,
            timestamp_secs,
        )?;
        let missing_len = missing.len();
        let member_count = member_dids.len();
        // Drop the `member_dids` / `missing` borrows of `cell` (held via
        // `member_dids()`) before taking the Class-C view.
        drop(missing);
        drop(member_dids);
        *cell.class_c_view().checkpoint_events_since_mut() += 1;
        return Err(ContextError::PermissionDenied(format!(
            "TTL extension requires unanimous consent — {missing_len} of {member_count} members have not approved",
        )));
    }

    let consenting: Vec<String> = approval_dids.iter().map(|d| (*d).to_owned()).collect();
    drop(approval_dids);
    drop(member_dids);

    let now = deps.clock.now_secs();
    // Snapshot the context handle for the re-armed timer BEFORE taking the
    // Class-C view (read via `Deref`).
    let handle = cell.handle.clone();

    // Coalesced TTL-timer re-arm: the timer fields are Class-C / structural
    // (SCP-021). A single non-persisting Class-C view borrow holds `&mut ttl`
    // across the `start_ttl_timer(...).await`, then drops before the best-effort
    // persist — no fail-closed strengthening, no extra persist injected.
    let (old_dl, new_dl) = {
        let mut view = cell.class_c_view();
        let ttl = view.ttl_mut();
        ttl.timer.cancel();
        let old_dl = ttl.timer.deadline_unix_secs.unwrap_or(0);
        let remaining_secs = ttl.timer.deadline_unix_secs.as_mut().map(|deadline| {
            *deadline = deadline.saturating_add(additional_secs);
            deadline.saturating_sub(now)
        });
        let new_dl = ttl.timer.deadline_unix_secs.unwrap_or(0);
        ttl.timer.cancel = Arc::new(tokio::sync::Notify::new());
        ttl.timer.task = None;

        // Phase 2A.6 Option B: actor-shape ttl_close_helpers::start_ttl_timer
        // exists. Call it if a remaining duration is set.
        if let Some(secs) = remaining_secs {
            crate::context::ttl_close_helpers::start_ttl_timer(
                // ADR-049 §9: `start_ttl_timer` was narrowed from
                // `&mut PerContextState` to `&mut TtlTimer` so the ttl_close actor
                // handler can reach it through the non-persisting Class-C view; the
                // governance path passes the same timer directly. Behaviour
                // unchanged — the helper only ever touched `state.ttl.timer`.
                &mut ttl.timer,
                deps,
                context_id,
                std::time::Duration::from_secs(secs),
                // The extended deadline `new_dl` was computed convergently above as
                // `old_deadline + additional_secs` (anchored on the prior
                // convergent deadline). Pass it through as the override so the
                // re-armed timer records that convergent value — not the local
                // arm-time `now + remaining` — on the `ContextExpired` leaf.
                Some(new_dl),
                handle,
            )
            .await;
        }
        (old_dl, new_dl)
    };

    crate::context::messaging_helpers::persist_state_best_effort(&*cell, deps, context_id);

    let extended_payload =
        scp_event_log::payload::encode_payload(&scp_event_log::payload::TtlExtendedPayload {
            old_deadline_unix: old_dl,
            new_deadline_unix: new_dl,
            proposal_id,
            consenting_members: consenting,
        })
        .map_err(|e| ContextError::EventLogFailed(e.to_string()))?;
    deps.event_log.append_context_event_with_payload(
        &context_id_bytes,
        scp_event_log::EventType::TtlExtended,
        actor_did,
        extended_payload,
        timestamp_secs,
    )?;
    *cell.class_c_view().checkpoint_events_since_mut() += 1;
    Ok(())
}

// ---------------------------------------------------------------------------
// execute_transfer_admin (per-action leaf helper)
// ---------------------------------------------------------------------------

pub fn execute_transfer_admin(
    cell: &mut crate::context::actor::class_s::ClassSCell,
    deps: &ActorDeps,
    context_id: &str,
    new_admin: &DID,
    meta: CommitMeta<'_>,
) -> Result<(), ContextError> {
    let CommitMeta {
        pid: _,
        actor_did,
        timestamp_secs,
    } = meta;
    let context_id_bytes = context_id_to_bytes(context_id);

    // ADR-049 §9 Class S: admin transfer is an authorization transition (the
    // prior admin loses admin authority) — route the role reassignment through
    // `commit_class_s_keep` so it persists fail-closed (keep-direction: on persist
    // failure the transfer STAYS — restoring the prior admin's authority after
    // the transfer was acknowledged is the unsafe direction). The reject-before-
    // mutate guards return `Err` from inside the closure (no persist runs); the
    // `role_state` + membership reassignment (Class-C) rides the SAME fail-closed
    // persist via `view.rest_mut()`.
    cell.commit_class_s_keep(deps, context_id, |mut view| {
        let state = view.rest_mut();
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
        Ok(())
    })?;
    deps.event_log.append_context_event(
        &context_id_bytes,
        scp_event_log::EventType::AdminTransferred,
        actor_did,
        timestamp_secs,
    )?;
    *cell.class_c_view().checkpoint_events_since_mut() += 1;
    Ok(())
}

// ---------------------------------------------------------------------------
// execute_create_child_context (per-action leaf helper)
// ---------------------------------------------------------------------------

pub fn execute_create_child_context(
    cell: &mut crate::context::actor::class_s::ClassSCell,
    deps: &ActorDeps,
    context_id: &str,
    _params: &ContextParams,
    meta: CommitMeta<'_>,
) -> Result<(), ContextError> {
    let CommitMeta {
        pid: _,
        actor_did,
        timestamp_secs,
    } = meta;
    let context_id_bytes = context_id_to_bytes(context_id);

    // Pure read-gate + event-log append; the only state mutation is the
    // coalesced checkpoint counter (no site persist today). Guards read through
    // the cell's `Deref`; the counter bumps via the non-persisting Class-C view.
    require_active(&cell.handle)?;

    if !cell
        .role_state
        .ceiling
        .contains(&Capability::ChildContextCreate)
    {
        return Err(ContextError::PermissionDenied(
            "context ceiling does not include child context creation capability".into(),
        ));
    }

    deps.event_log.append_context_event(
        &context_id_bytes,
        scp_event_log::EventType::ChildContextCreated,
        actor_did,
        timestamp_secs,
    )?;
    *cell.class_c_view().checkpoint_events_since_mut() += 1;
    Ok(())
}

// ---------------------------------------------------------------------------
// execute_modify_pruning_policy (per-action leaf helper)
// ---------------------------------------------------------------------------

pub fn execute_modify_pruning_policy(
    cell: &mut crate::context::actor::class_s::ClassSCell,
    deps: &ActorDeps,
    context_id: &str,
    new_policy: &PruningPolicy,
    meta: CommitMeta<'_>,
) -> Result<(), ContextError> {
    let CommitMeta {
        pid: _,
        actor_did,
        timestamp_secs,
    } = meta;
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

    // Validation guards above read only the borrowed `new_policy`. The
    // active-state gate reads through the cell's `Deref`; the `pruning_policy`
    // set (Class-C governance config) rides `commit_class_c_best_effort`,
    // preserving the prior best-effort persist exactly.
    require_active(&cell.handle)?;
    cell.commit_class_c_best_effort(deps, context_id, |mut view| {
        *view.governance_class_c_mut().pruning_policy_mut() = Some(new_policy.clone());
    });
    deps.event_log.append_context_event(
        &context_id_bytes,
        scp_event_log::EventType::PruningPolicyModified,
        actor_did,
        timestamp_secs,
    )?;
    *cell.class_c_view().checkpoint_events_since_mut() += 1;
    Ok(())
}

// ---------------------------------------------------------------------------
// execute_add_signer (per-action leaf helper)
// ---------------------------------------------------------------------------

pub fn execute_add_signer(
    cell: &mut crate::context::actor::class_s::ClassSCell,
    deps: &ActorDeps,
    context_id: &str,
    did: &DID,
    meta: CommitMeta<'_>,
) -> Result<(), ContextError> {
    let CommitMeta {
        pid: _,
        actor_did,
        timestamp_secs,
    } = meta;
    let context_id_bytes = context_id_to_bytes(context_id);

    // ADR-049 §9 Class S: adding a threshold signer is an UPWARD governance
    // grant. Migrating onto `commit_class_s_keep` STRENGTHENS the prior
    // best-effort persist to fail-closed (keep-direction): on persist failure
    // the in-memory grant STAYS granted — a granted-and-kept signer is the
    // fail-closed-correct direction (un-granting an already-acknowledged signer
    // is the unsafe move). The Class-S `threshold_signers.push` and the Class-C
    // capability/token grants ride the SAME fail-closed persist (both inside the
    // closure); the reject-before-mutate guards return `Err` (no persist).
    cell.commit_class_s_keep(deps, context_id, |mut view| {
        require_active(&view.handle)?;

        if !view.membership.contains(did) {
            return Err(ContextError::MemberNotFound(did.to_string()));
        }
        if view.governance.class_s.threshold_signers.contains(did) {
            return Err(ContextError::PermissionDenied(format!(
                "DID is already a signer: {did}"
            )));
        }
        if view.governance.class_s.threshold_signers.len() >= MAX_THRESHOLD_SIGNERS {
            return Err(ContextError::LimitExceeded(format!(
                "threshold signer limit of {MAX_THRESHOLD_SIGNERS} exceeded"
            )));
        }
        view.governance_class_s_mut()
            .threshold_signers
            .push(did.clone());

        let state = view.rest_mut();
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
        Ok(())
    })?;
    deps.event_log.append_context_event(
        &context_id_bytes,
        scp_event_log::EventType::SignerAdded,
        actor_did,
        timestamp_secs,
    )?;
    *cell.class_c_view().checkpoint_events_since_mut() += 1;
    Ok(())
}

// ---------------------------------------------------------------------------
// execute_remove_signer (per-action leaf helper)
// ---------------------------------------------------------------------------

pub fn execute_remove_signer(
    cell: &mut crate::context::actor::class_s::ClassSCell,
    deps: &ActorDeps,
    context_id: &str,
    did: &DID,
    meta: CommitMeta<'_>,
) -> Result<(), ContextError> {
    let CommitMeta {
        pid: _,
        actor_did,
        timestamp_secs,
    } = meta;
    let context_id_bytes = context_id_to_bytes(context_id);

    // ADR-049 §9 Class S: removing a threshold signer TIGHTENS governance
    // authorization. `commit_class_s_keep` is the keep-direction: on persist
    // failure the removal STAYS removed — re-admitting an already-acknowledged
    // removed signer is the unsafe direction, so keeping the tightening is
    // fail-closed-correct. (The prior fail-closed persist is preserved; only the
    // rollback DIRECTION on persist failure is the keep choice.) The Class-S
    // `threshold_signers.retain` rides the same fail-closed persist as the
    // Class-C capability/token strip. The reject-before-mutate guards return
    // `Err` from inside the closure (no persist); the threshold-floor guard
    // undoes its own `retain` before returning, exactly as before.
    cell.commit_class_s_keep(deps, context_id, |mut view| {
        require_active(&view.handle)?;

        let before = view.governance.class_s.threshold_signers.len();
        view.governance_class_s_mut()
            .threshold_signers
            .retain(|s| s != did);
        if view.governance.class_s.threshold_signers.len() == before {
            return Err(ContextError::MemberNotFound(did.to_string()));
        }
        if view.governance.class_s.threshold_value > 0 {
            let remaining =
                u32::try_from(view.governance.class_s.threshold_signers.len()).unwrap_or(u32::MAX);
            if view.governance.class_s.threshold_value > remaining {
                let threshold_value = view.governance.class_s.threshold_value;
                view.governance_class_s_mut()
                    .threshold_signers
                    .push(did.clone());
                return Err(ContextError::PermissionDenied(format!(
                    "removing signer would leave {remaining} signers < threshold {threshold_value}"
                )));
            }
        }

        let state = view.rest_mut();
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
        Ok(())
    })?;
    deps.event_log.append_context_event(
        &context_id_bytes,
        scp_event_log::EventType::SignerRemoved,
        actor_did,
        timestamp_secs,
    )?;
    *cell.class_c_view().checkpoint_events_since_mut() += 1;
    Ok(())
}

// ---------------------------------------------------------------------------
// execute_modify_threshold (per-action leaf helper)
// ---------------------------------------------------------------------------

pub fn execute_modify_threshold(
    cell: &mut crate::context::actor::class_s::ClassSCell,
    deps: &ActorDeps,
    context_id: &str,
    new_threshold: u32,
    meta: CommitMeta<'_>,
) -> Result<(), ContextError> {
    let CommitMeta {
        pid: _,
        actor_did,
        timestamp_secs,
    } = meta;
    let context_id_bytes = context_id_to_bytes(context_id);

    // ADR-049 §9 Class S: changing the governance threshold is an
    // authorization-control transition. The reject-before-mutate guards run
    // inside the closure (returning `Err` skips the persist and drops the
    // snapshot); on persist failure the combinator RESTORES `threshold_value`
    // so the caller never observes success for an undurable change.
    cell.commit_class_s_restore(deps, context_id, |mut view| {
        require_active(&view.handle)?;

        let signer_count =
            u32::try_from(view.governance.class_s.threshold_signers.len()).unwrap_or(u32::MAX);
        if new_threshold == 0 || new_threshold > signer_count {
            return Err(ContextError::PermissionDenied(format!(
                "threshold must be 1..={signer_count}, got {new_threshold}"
            )));
        }
        view.governance_class_s_mut().threshold_value = new_threshold;
        Ok(())
    })?;
    deps.event_log.append_context_event(
        &context_id_bytes,
        scp_event_log::EventType::ThresholdModified,
        actor_did,
        timestamp_secs,
    )?;
    *cell.class_c_view().checkpoint_events_since_mut() += 1;
    Ok(())
}

// ---------------------------------------------------------------------------
// execute_establish_tool_interface (per-action leaf helper)
// ---------------------------------------------------------------------------

pub fn execute_establish_tool_interface(
    cell: &mut crate::context::actor::class_s::ClassSCell,
    deps: &ActorDeps,
    context_id: &str,
    interface: &ToolInterface,
    meta: CommitMeta<'_>,
) -> Result<(), ContextError> {
    let CommitMeta {
        pid: _,
        actor_did,
        timestamp_secs,
    } = meta;
    let context_id_bytes = context_id_to_bytes(context_id);

    // Establishing a tool interface is Class-C governance config. The fallible
    // guards read through the cell's `Deref`; the `tool_interfaces` push
    // (Class-C) rides `commit_class_c_best_effort`, preserving the prior
    // best-effort persist exactly.
    require_active(&cell.handle)?;

    if !cell.role_state.ceiling.contains(&Capability::ToolInterface) {
        return Err(ContextError::PermissionDenied(
            "context ceiling does not include tool interface capability".into(),
        ));
    }

    if cell.governance.tool_interfaces.len() >= MAX_TOOL_INTERFACES {
        return Err(ContextError::LimitExceeded(format!(
            "tool interface limit of {MAX_TOOL_INTERFACES} exceeded"
        )));
    }
    cell.commit_class_c_best_effort(deps, context_id, |mut view| {
        view.governance_class_c_mut()
            .tool_interfaces_mut()
            .push(interface.clone());
    });
    deps.event_log.append_context_event(
        &context_id_bytes,
        scp_event_log::EventType::ToolInterfaceEstablished,
        actor_did,
        timestamp_secs,
    )?;
    *cell.class_c_view().checkpoint_events_since_mut() += 1;
    Ok(())
}

// ---------------------------------------------------------------------------
// execute_reset_member (per-action leaf helper)
// ---------------------------------------------------------------------------

pub fn execute_reset_member(
    state: &mut PerContextState,
    deps: &ActorDeps,
    context_id: &str,
    did: &DID,
    _reason: &str,
    meta: CommitMeta<'_>,
) -> Result<(), ContextError> {
    let CommitMeta {
        pid: _,
        actor_did,
        timestamp_secs,
    } = meta;
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
        &CommitOperation::ResetMember {
            target_did: did.clone(),
            is_remove: true,
        },
    );
    try_broadcast_commit_or_enqueue(
        state,
        deps,
        context_id,
        add_output.commit_bytes,
        &CommitOperation::ResetMember {
            target_did: did.clone(),
            is_remove: false,
        },
    );

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

    // Phase 2A.9: drain_and_deliver_sender_keys is now actor-shape.
    if let Err(e) = crate::context::lifecycle_helpers::drain_and_deliver_sender_keys(
        deps,
        context_id,
        &context_id_bytes,
    ) {
        tracing::warn!(
            context_id = %context_id,
            error = %e,
            "failed to deliver rotated sender keys after member reset"
        );
    }

    deps.event_log.append_context_event(
        &context_id_bytes,
        scp_event_log::EventType::MemberReset,
        actor_did,
        timestamp_secs,
    )?;
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
pub fn execute_resolve_conflict(
    cell: &mut crate::context::actor::class_s::ClassSCell,
    deps: &ActorDeps,
    context_id: &str,
    proposal_a: &ProposalId,
    proposal_b: &ProposalId,
    resolution: &scp_protocol::context::governance::ConflictResolution,
    meta: CommitMeta<'_>,
) -> Result<(), ContextError> {
    let CommitMeta {
        pid: _,
        actor_did,
        timestamp_secs,
    } = meta;
    let context_id_bytes = context_id_to_bytes(context_id);

    // ADR-049 §9 Class S: `executed_proposals` is security-critical replay-
    // protection state that does NOT survive an actor crash (it lives in the
    // actor-owned `GovernanceState`). `commit_class_s_keep` persists fail-closed
    // BEFORE acknowledging the resolution — un-recording an executed-proposal
    // marker re-opens the replay window (the canonical keep criterion), so on
    // persist failure the markers STAY recorded and the persist error is
    // returned. All reject-before-mutate guards return `Err` from inside the
    // closure (no persist runs); `governance.freeze = None` (Class-C) rides the
    // same fail-closed persist.
    cell.commit_class_s_keep(deps, context_id, |mut view| {
        require_active(&view.handle)?;

        let (freeze_a, freeze_b, _) = view.governance.freeze.ok_or_else(|| {
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

        let action_a = view
            .governance
            .approved_proposals
            .get(proposal_a)
            .map(|(p, _, _)| &p.action);
        let action_b = view
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

        let proposer_a = &view.governance.approved_proposals[proposal_a]
            .0
            .proposer_did;
        let proposer_b = &view.governance.approved_proposals[proposal_b]
            .0
            .proposer_did;
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
                view.governance_class_s_mut()
                    .executed_proposals
                    .insert(*loser, now);
            }
            scp_protocol::context::governance::ConflictResolution::InvalidateBoth => {
                let now = deps.clock.now_secs();
                view.governance_class_s_mut()
                    .executed_proposals
                    .insert(*proposal_a, now);
                view.governance_class_s_mut()
                    .executed_proposals
                    .insert(*proposal_b, now);
            }
        }

        view.rest_mut().governance.freeze = None;
        Ok(())
    })?;
    deps.event_log.append_context_event(
        &context_id_bytes,
        scp_event_log::EventType::GovernanceConflictResolved,
        actor_did,
        timestamp_secs,
    )?;
    *cell.class_c_view().checkpoint_events_since_mut() += 1;
    Ok(())
}

// ---------------------------------------------------------------------------
// execute_promote_context (per-action leaf helper)
// ---------------------------------------------------------------------------

pub fn execute_promote_context(
    cell: &mut crate::context::actor::class_s::ClassSCell,
    deps: &ActorDeps,
    context_id: &str,
    approvals: &[scp_protocol::context::governance::SignedVote],
    meta: CommitMeta<'_>,
) -> Result<(), ContextError> {
    let CommitMeta {
        pid: _,
        actor_did,
        timestamp_secs,
    } = meta;
    let context_id_bytes = context_id_to_bytes(context_id);

    // Promotion clears the TTL timer + promotes the handle's memory scope —
    // both Class-C structural state. The active-state + promotable-policy +
    // unanimity guards read through the cell's `Deref`; the `ttl` / `handle`
    // mutations ride `commit_class_c_best_effort`, preserving the prior
    // best-effort persist exactly.
    require_active(&cell.handle)?;

    if !matches!(
        cell.handle.params().promotion_policy,
        scp_protocol::context::params::PromotionPolicy::Promotable
    ) {
        return Err(ContextError::PermissionDenied(
            "context promotion_policy is not Promotable".to_owned(),
        ));
    }

    let member_dids: std::collections::HashSet<&str> =
        cell.membership.member_dids().map(|d| &**d).collect();
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
    drop(member_dids);
    drop(approval_dids);

    cell.commit_class_c_best_effort(deps, context_id, |mut view| {
        let ttl = view.ttl_mut();
        ttl.timer.cancel();
        ttl.timer.deadline_unix_secs = None;
        view.handle_mut().promote_memory_scope();
    });
    deps.event_log.append_context_event(
        &context_id_bytes,
        scp_event_log::EventType::ContextPromoted,
        actor_did,
        timestamp_secs,
    )?;
    *cell.class_c_view().checkpoint_events_since_mut() += 1;
    Ok(())
}

// ---------------------------------------------------------------------------
// execute_rotate_content_keys (per-action leaf helper)
// ---------------------------------------------------------------------------

#[allow(clippy::too_many_lines)]
pub fn execute_rotate_content_keys(
    cell: &mut crate::context::actor::class_s::ClassSCell,
    deps: &ActorDeps,
    context_id: &str,
    reason: Option<&str>,
    meta: CommitMeta<'_>,
) -> Result<(), ContextError> {
    let CommitMeta {
        pid: _,
        actor_did,
        timestamp_secs,
    } = meta;
    let context_id_bytes = context_id_to_bytes(context_id);

    // ADR-049 §9 Class S: content-key rotation is a forward-secrecy transition
    // (the prior wrapping/content keys are superseded) — route the rotation
    // through `commit_class_s_keep` so it persists fail-closed (keep-direction:
    // on persist failure the rotation STAYS — reverting to the pre-rotation key
    // state after the rotation was acknowledged is the unsafe direction). The
    // crypto/access-key mutations + emit + broadcast enqueue (Class-C) ride the
    // SAME fail-closed persist via `view.rest_mut()`. The closure returns the
    // optional broadcast snapshot so its separate best-effort persist can run
    // AFTER the fail-closed persist, exactly as before.
    let bc_snap = cell.commit_class_s_keep(deps, context_id, |mut view| {
        let state = view.rest_mut();
        require_active(&state.handle)?;

        let (epoch_output, bc_snap) = if let Some(ref mut bc) = state.broadcast_context {
            bc.rotate_all_author_keys()?;
            let snap = Some(bc.to_snapshot());
            (None, snap)
        } else {
            let epoch_out = deps.crypto.advance_epoch(&context_id_bytes)?;

            let member_dids: Vec<String> = state
                .membership
                .member_dids()
                .map(|d| d.0.clone())
                .collect();
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
                &CommitOperation::RotateContentKeys {
                    reason: reason.map(String::from),
                },
            );
        }
        Ok(bc_snap)
    })?;
    if let Some(ref snap) = bc_snap {
        persist_broadcast_snapshot(deps, context_id, snap);
    }

    deps.event_log.append_context_event(
        &context_id_bytes,
        scp_event_log::EventType::ContentKeysRotated,
        actor_did,
        timestamp_secs,
    )?;
    *cell.class_c_view().checkpoint_events_since_mut() += 1;
    Ok(())
}

// ---------------------------------------------------------------------------
// execute_reconfigure_governance (per-action leaf helper)
// ---------------------------------------------------------------------------

#[allow(clippy::too_many_arguments)]
pub fn execute_reconfigure_governance(
    cell: &mut crate::context::actor::class_s::ClassSCell,
    deps: &ActorDeps,
    context_id: &str,
    changes: &[scp_protocol::context::governance::GovernanceReconfigAction],
    justification: &scp_protocol::context::governance::DeadlockJustification,
    meta: CommitMeta<'_>,
) -> Result<(), ContextError> {
    let CommitMeta {
        pid: _,
        actor_did,
        timestamp_secs,
    } = meta;
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

    // ADR-049 §9 Class S: governance reconfiguration (signer/threshold changes)
    // is an authorization-control transition — persist fail-closed so a crash
    // cannot revert to the prior governance configuration after the
    // reconfiguration was acknowledged. The combinator's own Class-S
    // snapshot/restore SUBSUMES the former hand-rolled `original_signers` /
    // `original_threshold` save+rollback: a validation failure returns `Err`
    // from inside the closure (snapshot dropped, nothing persisted), and a
    // persist failure restores both Class-S sub-structs.
    cell.commit_class_s_restore(deps, context_id, |mut view| {
        require_active(&view.handle)?;

        for change in changes {
            match change {
                scp_protocol::context::governance::GovernanceReconfigAction::RemoveInactiveSigner {
                    did,
                } => {
                    view.governance_class_s_mut()
                        .threshold_signers
                        .retain(|s| s != did);
                }
                scp_protocol::context::governance::GovernanceReconfigAction::ReduceThreshold {
                    new_threshold,
                } => {
                    let signer_count =
                        u32::try_from(view.governance.class_s.threshold_signers.len())
                            .unwrap_or(u32::MAX);
                    if *new_threshold == 0 || *new_threshold > signer_count {
                        return Err(ContextError::PermissionDenied(format!(
                            "reconfigured threshold must be 1..={signer_count}, got {new_threshold}"
                        )));
                    }
                    view.governance_class_s_mut().threshold_value = *new_threshold;
                }
            }
        }

        if view.governance.class_s.threshold_value > 0 {
            let remaining =
                u32::try_from(view.governance.class_s.threshold_signers.len()).unwrap_or(u32::MAX);
            if view.governance.class_s.threshold_value > remaining {
                return Err(ContextError::PermissionDenied(format!(
                    "reconfiguration left {remaining} signers < threshold {}",
                    view.governance.class_s.threshold_value,
                )));
            }
        }
        Ok(())
    })?;
    deps.event_log.append_context_event(
        &context_id_bytes,
        scp_event_log::EventType::GovernanceReconfigured,
        actor_did,
        timestamp_secs,
    )?;
    *cell.class_c_view().checkpoint_events_since_mut() += 1;
    Ok(())
}

// ---------------------------------------------------------------------------
// execute_set_economic_policy (per-action leaf helper)
// ---------------------------------------------------------------------------

pub fn execute_set_economic_policy(
    cell: &mut crate::context::actor::class_s::ClassSCell,
    deps: &ActorDeps,
    context_id: &str,
    policy: &EconomicPolicy,
    meta: CommitMeta<'_>,
) -> Result<(), ContextError> {
    let CommitMeta {
        pid: proposal_id,
        actor_did,
        timestamp_secs,
    } = meta;
    scp_protocol::economy::policy::validate_economic_policy_metrics(Some(policy))
        .map_err(|e| ContextError::PermissionDenied(format!("invalid economic policy: {e}")))?;

    let context_id_bytes = context_id_to_bytes(context_id);

    // Staging a pending economic-policy change is Class-C governance config. The
    // validation + active-state + locked/already-pending guards read through
    // the cell's `Deref`; the pending-change set + notification emit (Class-C)
    // ride `commit_class_c_best_effort`, preserving the prior best-effort
    // persist exactly. The notification `emit` is inlined as `emit_event_into`
    // over the view's `receive_buffer_mut()` (identical to the free `emit`
    // helper, which the airtight Class-C view cannot be handed whole-state to).
    require_active(&cell.handle)?;

    if let Some(existing) = &cell.governance.economic_policy
        && existing.locked
    {
        return Err(ContextError::PermissionDenied(
            "economic policy is locked and cannot be changed".to_owned(),
        ));
    }

    if cell.governance.pending_economic_policy_change.is_some() {
        return Err(ContextError::PermissionDenied(
            "an economic policy change is already pending notification period".to_owned(),
        ));
    }

    // Convergent notification/activation window: anchor on the committer-
    // assigned proposal timestamp (`CommitMeta::timestamp_secs`, every member
    // copies the same value), never local `now()`. `effective_at =
    // proposal.created_at + NOTIFICATION_PERIOD` is therefore identical across
    // members, so the deferred economic-policy change activates at the same
    // instant everywhere (§7.3.1, §9.9.3). This convergent value is also what
    // lands on the `EconomicPolicyApplied` leaf when the change applies.
    //
    // SECURITY: `proposal.created_at` is proposer-chosen and signature-bound
    // only against third parties — the proposer can backdate it freely. Used
    // alone as the apply gate, a proposer could set `created_at` far in the
    // past so `effective_at <= commit time` and collapse the mandatory 24-hour
    // notification window to zero, violating §19.3 ("MUST NOT take effect
    // sooner than 24 hours after the `EconomicPolicyChanged` event is committed
    // to the event log"). To keep activation convergent yet non-backdatable,
    // also record `observed_at` — THIS member's local clock at commit-
    // processing time (not proposer-controlled). `is_effective` requires
    // `current >= max(effective_at, observed_at + PERIOD)`, so the window can
    // never be shorter than `PERIOD` of locally observed time.
    let notified_at = timestamp_secs;
    let effective_at = notified_at + ECONOMIC_POLICY_NOTIFICATION_PERIOD_SECS;
    let observed_at = deps.clock.now_secs();
    cell.commit_class_c_best_effort(deps, context_id, |mut view| {
        *view
            .governance_class_c_mut()
            .pending_economic_policy_change_mut() = Some(PendingEconomicPolicyChange {
            new_policy: policy.clone(),
            notified_at,
            effective_at,
            observed_at,
            proposal_id,
        });

        emit_event_into(
            view.receive_buffer_mut(),
            ContextEvent::EconomicPolicyChangeNotification {
                notified_at,
                effective_at,
                proposal_id,
            },
            context_id,
            deps.event_tx.as_ref(),
        );
    });
    deps.event_log.append_context_event(
        &context_id_bytes,
        scp_event_log::EventType::EconomicPolicyChanged,
        actor_did,
        timestamp_secs,
    )?;
    *cell.class_c_view().checkpoint_events_since_mut() += 1;
    Ok(())
}

// ---------------------------------------------------------------------------
// execute_approve_spend (per-action leaf helper)
// ---------------------------------------------------------------------------

#[allow(clippy::too_many_arguments)]
pub fn execute_approve_spend(
    cell: &mut crate::context::actor::class_s::ClassSCell,
    deps: &ActorDeps,
    context_id: &str,
    spender: &DID,
    amount: scp_protocol::economy::types::Amount,
    purpose: &str,
    meta: CommitMeta<'_>,
) -> Result<(), ContextError> {
    let CommitMeta {
        pid: _,
        actor_did,
        timestamp_secs,
    } = meta;
    let context_id_bytes = context_id_to_bytes(context_id);

    // Granting spend budget is Class-C governance state. The fallible guards
    // read through the cell's `Deref`; the `budget_tracker.grant` (Class-C)
    // rides `commit_class_c_best_effort`, preserving the prior best-effort
    // persist exactly.
    require_active(&cell.handle)?;

    if !cell.membership.contains(spender.as_ref()) {
        return Err(ContextError::MemberNotFound(spender.to_string()));
    }

    cell.commit_class_c_best_effort(deps, context_id, |mut view| {
        view.governance_class_c_mut()
            .budget_tracker_mut()
            .grant(spender, amount);
    });
    let spend_payload =
        scp_event_log::payload::encode_payload(&scp_event_log::payload::SpendApprovedPayload {
            spender: spender.as_ref().to_owned(),
            amount: amount.value(),
            purpose: purpose.to_owned(),
        })
        .map_err(|e| ContextError::EventLogFailed(e.to_string()))?;
    deps.event_log.append_context_event_with_payload(
        &context_id_bytes,
        scp_event_log::EventType::SpendApproved,
        actor_did,
        spend_payload,
        timestamp_secs,
    )?;
    Ok(())
}

// ---------------------------------------------------------------------------
// execute_lock_economic_policy (per-action leaf helper)
// ---------------------------------------------------------------------------

pub fn execute_lock_economic_policy(
    cell: &mut crate::context::actor::class_s::ClassSCell,
    deps: &ActorDeps,
    context_id: &str,
    meta: CommitMeta<'_>,
) -> Result<(), ContextError> {
    let CommitMeta {
        pid: _,
        actor_did,
        timestamp_secs,
    } = meta;
    let context_id_bytes = context_id_to_bytes(context_id);

    // Locking the economic policy is Class-C governance config. The active-state
    // gate + presence/already-locked checks read through the cell's `Deref`;
    // the `locked = true` set (Class-C) rides `commit_class_c_best_effort`,
    // preserving the prior best-effort persist exactly. The reject checks run
    // BEFORE the commit closure (the closure is infallible) so a rejected lock
    // triggers no persist, matching the prior reject-before-persist behaviour.
    require_active(&cell.handle)?;

    match &cell.governance.economic_policy {
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
        Some(_) => {}
    }

    cell.commit_class_c_best_effort(deps, context_id, |mut view| {
        if let Some(policy) = view.governance_class_c_mut().economic_policy_mut() {
            policy.locked = true;
        }
    });
    deps.event_log.append_context_event(
        &context_id_bytes,
        scp_event_log::EventType::EconomicPolicyLocked,
        actor_did,
        timestamp_secs,
    )?;
    *cell.class_c_view().checkpoint_events_since_mut() += 1;
    Ok(())
}

// ---------------------------------------------------------------------------
// execute_modify_hard_rate_limit (per-action leaf helper)
// ---------------------------------------------------------------------------

pub fn execute_modify_hard_rate_limit(
    cell: &mut crate::context::actor::class_s::ClassSCell,
    deps: &ActorDeps,
    context_id: &str,
    new_config: &scp_protocol::economy::antispam::HardRateLimitConfig,
    meta: CommitMeta<'_>,
) -> Result<(), ContextError> {
    let CommitMeta {
        pid: _,
        actor_did,
        timestamp_secs,
    } = meta;
    let context_id_bytes = context_id_to_bytes(context_id);

    new_config.validate().map_err(|e| {
        ContextError::GovernanceFailed(format!(
            "ModifyHardRateLimit: new config failed validation: {e}"
        ))
    })?;

    // The hard rate limiter is Class-C defense-in-depth state. Validation +
    // the preserved-state snapshot read happen BEFORE the commit (reading the
    // limiter through the cell's `Deref`); the limiter REPLACEMENT (Class-C)
    // rides `commit_class_c_best_effort`, preserving the prior best-effort
    // persist exactly. A validation/sanitization reject returns `Err` before
    // the commit closure runs, so no persist fires — matching the prior
    // reject-before-persist behaviour.
    require_active(&cell.handle)?;

    let mut preserved_state = cell.governance.hard_rate_limit.snapshot_entries();
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
    cell.commit_class_c_best_effort(deps, context_id, |mut view| {
        *view.governance_class_c_mut().hard_rate_limit_mut() =
            scp_protocol::economy::antispam::TokenBucketLimiter::from_snapshot(
                new_config.clone(),
                preserved_state,
            );
    });
    deps.event_log.append_context_event(
        &context_id_bytes,
        scp_event_log::EventType::HardRateLimitModified,
        actor_did,
        timestamp_secs,
    )?;
    *cell.class_c_view().checkpoint_events_since_mut() += 1;
    Ok(())
}

// ---------------------------------------------------------------------------
// execute_propose_context_migration (per-action leaf helper)
// ---------------------------------------------------------------------------

/// Execute the `ProposeContextMigration` governance action.
///
/// Returns a hand-boxed `Pin<Box<dyn Future + Send>>` rather than the
/// usual `async fn` opaque-type future. This signature is mechanical
/// (ADR-049 Phase 2A finalization owned-state spawn): the function
/// is reachable from `ContextActor::run()` via the migrated governance
/// dispatch, AND it transitively calls
/// `lifecycle_helpers::create_context` which now spawns a
/// `ContextActor::run()` task through
/// `Supervisor::spawn_actor_with_state`. The recursive Send-inference
/// cycle through opaque async-fn types fails to converge; a named
/// `dyn Future + Send` return type erases the opaque chain and lets the
/// spawned actor's `.run()` future be provably `Send`.
#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
pub fn execute_propose_context_migration<'a>(
    cell: &'a mut crate::context::actor::class_s::ClassSCell,
    deps: &'a ActorDeps,
    context_id: &'a str,
    new_context_params: &'a scp_protocol::context::params::ContextParams,
    reason: &'a str,
    grace_period_secs: u64,
    auto_invite: bool,
    meta: CommitMeta<'a>,
) -> std::pin::Pin<
    Box<
        dyn std::future::Future<Output = Result<MigrationProposedResult, ContextError>> + Send + 'a,
    >,
> {
    let CommitMeta {
        pid: proposal_id,
        actor_did,
        timestamp_secs,
    } = meta;
    Box::pin(async move {
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

        // Reads via the cell's `Deref`; `transition_to` takes `&self`.
        require_active(&cell.handle)?;

        if cell.migration_state.is_some() {
            return Err(ContextError::PermissionDenied(
                "context migration is already in progress".to_owned(),
            ));
        }

        let creator = cell
            .membership
            .members()
            .find(|m| m.role_name == "admin")
            .map(|m| m.did.clone())
            .ok_or_else(|| {
                ContextError::PermissionDenied(
                    "no admin found in source context for destination creation".to_owned(),
                )
            })?;

        cell.handle
            .transition_to(&ContextState::MigratingOut)
            .await
            .map_err(|_| {
                ContextError::PermissionDenied("cannot transition to MigratingOut".to_owned())
            })?;

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

        // Coalesced Class-C staging (migration_state + buffered events) in a
        // view borrow that drops before the `create_context` await.
        let buffer_len_before_migration = {
            let mut view = cell.class_c_view();
            *view.migration_state_mut() = Some(MigrationState {
                destination_context_id: destination_context_id.clone(),
                reason: reason.to_owned(),
                grace_period_end,
                auto_invite,
                proposal_id,
            });
            let buffer_len_before_migration = view.receive_buffer_mut().len();
            view.receive_buffer_mut().push(proposed_event.clone());
            view.receive_buffer_mut().push(started_event.clone());
            buffer_len_before_migration
        };

        // Phase 2A.9: lifecycle_helpers::create_context is now actor-shape
        // (bootstrap form — constructs fresh PerContextState, registers
        // through SupervisorHandle).
        //
        // Type-erased `Pin<Box<dyn Future + Send>>` breaks the
        // Send-inference auto-trait cycle: this helper is reachable from
        // `ContextActor::run()` via the migrated governance dispatch, AND
        // `create_context` (Phase 2A finalization owned-state spawn)
        // spawns a `ContextActor::run()` task through
        // `Supervisor::spawn_actor_with_state`. Erasing the inner
        // future type here shields auto-trait propagation from chasing the
        // cycle.
        let create_fut: std::pin::Pin<
            Box<
                dyn std::future::Future<
                        Output = Result<
                            crate::context::ContextHandle,
                            scp_protocol::context::builder::ContextCreationError,
                        >,
                    > + Send,
            >,
        > = Box::pin(crate::context::lifecycle_helpers::create_context(
            deps,
            destination_context_id.clone(),
            dest_params,
            creator,
            None,
        ));
        if let Err(e) = create_fut.await {
            // Roll back: revert source to Active and clear migration state. The
            // `transition_to` await runs with no view borrow live; the Class-C
            // rollback (clear migration state + truncate the buffered events)
            // then runs in a short view borrow.
            let _ = cell.handle.transition_to(&ContextState::Active).await;
            {
                let mut view = cell.class_c_view();
                *view.migration_state_mut() = None;
                view.receive_buffer_mut()
                    .truncate(buffer_len_before_migration);
            }
            return Err(ContextError::PermissionDenied(format!(
                "failed to create destination context: {e}"
            )));
        }

        // Broadcast the migration events that were buffered above.
        if let Some(tx) = deps.event_tx.as_ref() {
            let _ = tx.send((context_id.to_owned(), strip_event_payload(&proposed_event)));
            let _ = tx.send((context_id.to_owned(), strip_event_payload(&started_event)));
        }

        crate::context::messaging_helpers::persist_state_best_effort(&*cell, deps, context_id);
        deps.event_log.append_context_event(
            &context_id_bytes,
            scp_event_log::EventType::ContextMigrationStarted,
            actor_did,
            timestamp_secs,
        )?;
        *cell.class_c_view().checkpoint_events_since_mut() += 1;

        Ok(MigrationProposedResult {
            destination_context_id,
            grace_period_end,
        })
    })
}

// ---------------------------------------------------------------------------
// execute_cancel_context_migration (per-action leaf helper)
// ---------------------------------------------------------------------------

pub async fn execute_cancel_context_migration(
    cell: &mut crate::context::actor::class_s::ClassSCell,
    deps: &ActorDeps,
    context_id: &str,
    meta: CommitMeta<'_>,
) -> Result<(), ContextError> {
    let CommitMeta {
        pid: _,
        actor_did,
        timestamp_secs,
    } = meta;
    let context_id_bytes = context_id_to_bytes(context_id);

    // Reads via the cell's `Deref`; `transition_to` takes `&self`.
    let s = cell
        .handle
        .try_read_state()
        .ok_or(ContextError::ContextNotActive)?;
    if s != ContextState::MigratingOut {
        return Err(ContextError::PermissionDenied(
            "context is not in MigratingOut state — cannot cancel migration".to_owned(),
        ));
    }

    cell.handle
        .transition_to(&ContextState::Active)
        .await
        .map_err(|_| {
            ContextError::PermissionDenied(
                "cannot transition from MigratingOut to Active".to_owned(),
            )
        })?;

    // Class-C migration-state clear + cancel-event emit run after the
    // transition await, in a short non-persisting view borrow.
    let original_proposal_id = {
        let mut view = cell.class_c_view();
        let migration = view.migration_state_mut().take().ok_or_else(|| {
            ContextError::PermissionDenied(
                "no migration state found despite MigratingOut state".to_owned(),
            )
        })?;
        let original_proposal_id = migration.proposal_id;
        view.emit_event(
            ContextEvent::ContextMigrationCancelled {
                original_proposal_id,
            },
            context_id,
            deps.event_tx.as_ref(),
        );
        original_proposal_id
    };

    crate::context::messaging_helpers::persist_state_best_effort(&*cell, deps, context_id);
    let cancel_payload = scp_event_log::payload::encode_payload(
        &scp_event_log::payload::ContextMigrationCancelledPayload {
            original_proposal_id,
        },
    )
    .map_err(|e| ContextError::EventLogFailed(e.to_string()))?;
    deps.event_log.append_context_event_with_payload(
        &context_id_bytes,
        scp_event_log::EventType::ContextMigrationCancelled,
        actor_did,
        cancel_payload,
        timestamp_secs,
    )?;
    *cell.class_c_view().checkpoint_events_since_mut() += 1;
    Ok(())
}

// ---------------------------------------------------------------------------
// try_broadcast_commit_or_enqueue (transitive helper, actor-shape)
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// propose_governance_action_inner (entry point — internal)
// ---------------------------------------------------------------------------

/// Inner implementation of proposal submission with auto-execution.
///
/// Returns the proposal, events, and optional execution result. The
/// execution result is `Some` when the proposal was auto-approved
/// (`SingleAdmin`) and the action was successfully executed.
///
/// When `check_propose_capability` is `true`, the `GovernancePropose`
/// capability is verified under the same path as the proposal
/// submission (actor-owned state — no TOCTOU window).
#[allow(clippy::too_many_lines)]
pub async fn propose_governance_action_inner(
    cell: &mut crate::context::actor::class_s::ClassSCell,
    deps: &ActorDeps,
    context_id: &str,
    proposer_did: &DID,
    action: GovernanceAction,
    signing_key: &ed25519_dalek::SigningKey,
    check_propose_capability: bool,
) -> Result<
    (
        GovernanceProposal,
        Vec<GovernanceEvent>,
        Option<GovernanceActionResult>,
    ),
    ContextError,
> {
    // ADR-049 §9 Class-S cell seam: the pre-execute body reads through the
    // cell's `Deref` and routes each Class-C mutation through the non-persisting
    // `class_c_view()`; the single best-effort persist is at the tail (preserved
    // from the legacy `state_mut` body). The cell is handed to the auto-execute
    // path once these reads/mutations complete.
    //
    // CancelContextMigration is allowed during MigratingOut (§5.11A);
    // all other actions require Active state.
    if matches!(action, GovernanceAction::CancelContextMigration) {
        require_migrating_out(&cell.handle)?;
    } else {
        require_active(&cell.handle)?;
    }

    if check_propose_capability
        && !cell
            .role_state
            .member_has_capability(proposer_did.as_ref(), &Capability::GovernancePropose)
    {
        return Err(ContextError::PermissionDenied(format!(
            "member {proposer_did} does not have governance:propose capability"
        )));
    }

    // Presence-only members (read + write both suspended) lose
    // GovernancePropose capability.
    if cell
        .role_state
        .suspended_capabilities
        .get(proposer_did.as_ref())
        .is_some_and(|s| {
            s.contains(&Capability::MessagesRead) && s.contains(&Capability::MessagesWrite)
        })
    {
        return Err(ContextError::PermissionDenied(
            "presence-only members cannot propose governance actions".into(),
        ));
    }

    // Eligibility check (#1530). The composite proposer-eligibility gate
    // (pending-removal + participation threshold + earned-capacity rate
    // limit) runs against actor-owned state via `actor_check_proposer_eligibility`.
    actor_check_proposer_eligibility(cell, proposer_did, deps.clock.now_secs(), &*deps.event_log)?;

    // SCP-272: Check and auto-resolve expired governance freezes.
    // Timer-triggered expiry: capture the pre-computed freeze deadline
    // (freeze_start + timeout) BEFORE resolution clears the freeze, so the
    // GovernanceFreezeExpired leaf carries that convergent deadline rather than
    // a per-member local `now()` (§7.3.1, §9.9.3).
    let freeze_expiry_deadline = cell
        .governance
        .freeze
        .map(|(_, _, freeze_start)| freeze_start.saturating_add(FREEZE_TIMEOUT_SECONDS));
    let freeze_events = check_and_resolve_expired_freezes(cell, deps);
    if !freeze_events.is_empty() {
        let cid_bytes = context_id_to_bytes(context_id);
        // The freeze was present when `freeze_events` is non-empty (expiry just
        // fired), so the deadline is always `Some` here.
        let freeze_ts = freeze_expiry_deadline.unwrap_or(0);
        for event in &freeze_events {
            if let GovernanceEvent::ConflictResolved { .. } = event {
                deps.event_log.append_context_event(
                    &cid_bytes,
                    scp_event_log::EventType::GovernanceFreezeExpired,
                    proposer_did.as_ref(),
                    freeze_ts,
                )?;
                *cell.class_c_view().checkpoint_events_since_mut() += 1;
            }
        }
    }

    if cell.governance.freeze.is_some()
        && !matches!(action, GovernanceAction::ResolveConflict { .. })
    {
        return Err(ContextError::GovernanceFailed(
            "governance is frozen due to simultaneous conflict — only ResolveConflict proposals are accepted".into(),
        ));
    }

    let gov_ctx = build_governance_context(&*cell, &*deps.clock);
    let (proposal, events) = {
        let mut view = cell.class_c_view();
        view.governance_class_c_mut().engine_mut().propose(
            proposer_did,
            action,
            &gov_ctx,
            signing_key,
        )
    }
    .map_err(|e| ContextError::GovernanceFailed(e.to_string()))?;

    cell.class_c_view()
        .governance_class_c_mut()
        .proposal_timestamps_mut()
        .entry(proposer_did.to_string())
        .or_default()
        .push(deps.clock.now_secs());

    let should_execute = proposal.status == ProposalStatus::Approved;

    let conflict_events = if should_execute {
        detect_and_handle_conflicts(cell, deps, &proposal)
    } else {
        Vec::new()
    };

    let invalidated_by_conflict = conflict_events.iter().any(|e| {
        matches!(e, GovernanceEvent::ConflictResolved { loser_id, .. } if *loser_id == proposal.proposal_id)
    });

    let in_freeze = cell.governance.freeze.is_some();

    // Emit conflict events to the event log.
    if !conflict_events.is_empty() {
        let context_id_bytes = context_id_to_bytes(context_id);
        let mut conflict_event_count: u64 = 0;
        for event in &conflict_events {
            match event {
                GovernanceEvent::ConflictDetected { .. } => {
                    deps.event_log.append_context_event(
                        &context_id_bytes,
                        scp_event_log::EventType::GovernanceConflictDetected,
                        proposer_did.as_ref(),
                        // Conflict detected deterministically while processing
                        // this proposal: the convergent leaf timestamp is the
                        // proposal's signed `created_at` (§7.3.1, §9.9.3).
                        proposal.created_at,
                    )?;
                    conflict_event_count += 1;
                }
                GovernanceEvent::ConflictResolved { .. } => {
                    deps.event_log.append_context_event(
                        &context_id_bytes,
                        scp_event_log::EventType::GovernanceConflictResolved,
                        proposer_did.as_ref(),
                        proposal.created_at,
                    )?;
                    conflict_event_count += 1;
                }
                _ => {}
            }
        }
        if conflict_event_count > 0 {
            *cell.class_c_view().checkpoint_events_since_mut() += conflict_event_count;
        }
    }

    // If the proposal was auto-approved (SingleAdmin), execute
    // immediately — unless invalidated by conflict or in freeze.
    let execution_result = if should_execute && !invalidated_by_conflict && !in_freeze {
        // The top `state` borrow has ended (NLL); hand the cell to the execute
        // path so the governance leaves it reaches can later migrate.
        Some(Box::pin(execute_governance_action(cell, deps, context_id, &proposal)).await?)
    } else {
        None
    };

    crate::context::messaging_helpers::persist_state_best_effort(&*cell, deps, context_id);

    Ok((proposal, events, execution_result))
}

/// Composite proposer-eligibility gate running against actor-owned
/// `PerContextState`: pending-removal defense-in-depth, `SingleAdmin`
/// bypass, participation-threshold gate, and earned-capacity rate limit.
#[allow(clippy::too_many_lines)]
fn actor_check_proposer_eligibility(
    cell: &mut crate::context::actor::class_s::ClassSCell,
    proposer_did: &DID,
    now: u64,
    event_log: &dyn crate::context::builder::ContextEventLogProvider,
) -> Result<(), ContextError> {
    use scp_protocol::context::params::GovernanceModel;
    use scp_protocol::trust::participation::{compute_participation_record, meets_threshold};

    // Pending-removal defense-in-depth (read via the cell's `Deref`).
    for (proposal, _seq, _ts) in cell.governance.approved_proposals.values() {
        if let GovernanceAction::RemoveMember { did, .. } = &proposal.action
            && did == proposer_did
        {
            return Err(ContextError::PermissionDenied(
                "member has a pending ejection — cannot propose governance actions".into(),
            ));
        }
    }

    // SingleAdmin bypass: the sole authority is always eligible.
    if matches!(
        cell.handle.params().governance,
        GovernanceModel::SingleAdmin
    ) {
        return Ok(());
    }

    // Participation refresh + cache + threshold.
    let context_id = cell.handle.context_id().to_owned();
    if !cell
        .governance
        .participation_cache
        .contains_key(proposer_did.as_ref())
    {
        let context_id_bytes = context_id_to_bytes(&context_id);
        let merkle_root = event_log
            .event_log_merkle_root(&context_id_bytes)
            .unwrap_or([0u8; 32]);
        // Participation-record path consumes only the merged event set;
        // `convergent_now` (the consequence window anchor) is unused here.
        let (events, _convergent_now) =
            event_log_entries_for_consequences(&cell.receive_buffer, &context_id, now, event_log);
        if !events.is_empty() {
            match compute_participation_record(
                &events,
                proposer_did.as_ref(),
                &context_id,
                merkle_root,
                now,
            ) {
                Err(e) => {
                    tracing::warn!(
                        proposer = %proposer_did,
                        error = %e,
                        "compute_participation_record failed — denying proposal"
                    );
                    return Err(ContextError::PermissionDenied(
                    "SCP-GOV-11021: participation record computation failed — cannot verify proposer eligibility"
                        .into(),
                ));
                }
                Ok(record) => {
                    if record.participation_count > 0 {
                        cell.class_c_view()
                            .governance_class_c_mut()
                            .participation_cache_mut()
                            .insert(proposer_did.to_string(), record);
                    }
                }
            }
        }
    }

    if let Some(record) = cell
        .governance
        .participation_cache
        .get(proposer_did.as_ref())
        && !meets_threshold(record)
    {
        return Err(ContextError::PermissionDenied(
            "member participation below threshold — cannot propose governance actions (SCP-GOV-11020)"
                .into(),
        ));
    }

    // Earned capacity enforcement (§9.3).
    if let Some(sybil_policy) = cell.handle.params().sybil_policy.as_ref() {
        let assessment = crate::context::lifecycle_logic::build_identity_assessment(
            proposer_did,
            &cell.governance,
            now,
        );
        let (_level, capacity) =
            scp_protocol::trust::sybil::evaluate_earned_capacity(&assessment, sybil_policy, now);

        let window_secs = capacity.governance_proposal_window_secs;
        let max_proposals = capacity.max_governance_proposals_per_window;
        let window_start = now.saturating_sub(window_secs);

        let mut view = cell.class_c_view();
        let timestamps = view
            .governance_class_c_mut()
            .proposal_timestamps_mut()
            .entry(proposer_did.to_string())
            .or_default();

        timestamps.retain(|&ts| ts > window_start);

        #[allow(clippy::cast_possible_truncation)]
        let recent_count = timestamps.len() as u32;
        if recent_count >= max_proposals {
            return Err(ContextError::PermissionDenied(format!(
                "earned capacity limit reached: {recent_count}/{max_proposals} governance proposals \
                 in {window_secs}s window (SCP-GOV-11030)"
            )));
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// propose_governance_action (entry point — unchecked) — NOT MIGRATED
// ---------------------------------------------------------------------------
//
// The unchecked actor-shape twin of `propose_governance_action` is not
// provided here. Production callers always route through
// `propose_governance_action_checked` because spec §5.9 capability
// suspension overlays must apply on the propose path. The unchecked
// variant exists in the legacy module for the supervisor passthrough
// (`Supervisor::propose_governance_action`) which keeps the legacy
// shape until Phase 2A finalization. The actor-shape unchecked twin
// lands here when a non-test caller appears.

// ---------------------------------------------------------------------------
// propose_governance_action_checked (entry point)
// ---------------------------------------------------------------------------

/// Submits a new governance proposal with capability validation.
///
/// Validates the `GovernancePropose` capability under the same atomic
/// path as the proposal submission (no TOCTOU).
#[instrument(skip_all, fields(context_id))]
pub async fn propose_governance_action_checked(
    cell: &mut crate::context::actor::class_s::ClassSCell,
    deps: &ActorDeps,
    context_id: &str,
    proposer_did: &DID,
    action: GovernanceAction,
    signing_key: &ed25519_dalek::SigningKey,
) -> Result<ProposalOutcome, ContextError> {
    let (proposal, _events, execution_result) = propose_governance_action_inner(
        cell,
        deps,
        context_id,
        proposer_did,
        action,
        signing_key,
        true,
    )
    .await?;

    let status = proposal.status.clone();
    Ok(ProposalOutcome {
        proposal,
        status,
        execution_result,
    })
}

// ---------------------------------------------------------------------------
// vote_on_proposal_inner (entry point — internal)
// ---------------------------------------------------------------------------

/// Inner vote implementation. When `check_vote_capability` is `true`,
/// additionally verifies `GovernanceVote` via `member_has_capability`
/// (actor-owned — no TOCTOU window).
#[allow(clippy::too_many_lines, clippy::too_many_arguments)]
#[instrument(skip_all, fields(context_id))]
pub async fn vote_on_proposal_inner(
    cell: &mut crate::context::actor::class_s::ClassSCell,
    deps: &ActorDeps,
    context_id: &str,
    proposal_id: &ProposalId,
    voter_did: &DID,
    approve: bool,
    signing_key: &ed25519_dalek::SigningKey,
    check_vote_capability: bool,
) -> Result<(ProposalStatus, Vec<GovernanceEvent>), ContextError> {
    // ADR-049 §9 Class-S cell seam: the pre-execute body reads through the
    // cell's `Deref` and routes each Class-C mutation through the non-persisting
    // `class_c_view()`; the single best-effort persist is at the tail (preserved
    // from the legacy `state_mut` body). The cell is handed to the auto-execute
    // path once these reads/mutations complete.
    require_active(&cell.handle)?;

    let suspended = cell
        .role_state
        .suspended_capabilities
        .get(voter_did.as_ref());
    if suspended.is_some_and(|s| s.contains(&Capability::GovernanceVote)) {
        return Err(ContextError::PermissionDenied(
            "member does not have governance:vote capability".into(),
        ));
    }
    if suspended.is_some_and(|s| {
        s.contains(&Capability::MessagesRead) && s.contains(&Capability::MessagesWrite)
    }) {
        return Err(ContextError::PermissionDenied(
            "presence-only members cannot vote on governance proposals".into(),
        ));
    }

    if check_vote_capability
        && !cell
            .role_state
            .member_has_capability(voter_did.as_ref(), &Capability::GovernanceVote)
    {
        return Err(ContextError::PermissionDenied(format!(
            "member {voter_did} does not have governance:vote capability"
        )));
    }

    let gov_ctx = build_governance_context(&*cell, &*deps.clock);
    let (status, events) = {
        let mut view = cell.class_c_view();
        let engine = view.governance_class_c_mut().engine_mut();
        if approve {
            engine.approve(proposal_id, voter_did, &gov_ctx, signing_key)
        } else {
            engine.reject(proposal_id, voter_did, &gov_ctx, signing_key)
        }
    }
    .map_err(|e| ContextError::GovernanceFailed(e.to_string()))?;

    let proposal_for_execution = if status == ProposalStatus::Approved {
        cell.governance.engine.get_proposal(proposal_id).cloned()
    } else {
        None
    };

    let conflict_events = proposal_for_execution
        .as_ref()
        .map_or_else(Vec::new, |proposal| {
            detect_and_handle_conflicts(cell, deps, proposal)
        });

    // Emit conflict events to the event log.
    if !conflict_events.is_empty() {
        let context_id_bytes = context_id_to_bytes(context_id);
        // Conflict detected/resolved deterministically while processing this
        // approved proposal: the convergent leaf timestamp is the proposal's
        // signed `created_at` (§7.3.1, §9.9.3).
        let conflict_ts = proposal_for_execution.as_ref().map_or(0, |p| p.created_at);
        let mut conflict_event_count: u64 = 0;
        for event in &conflict_events {
            match event {
                GovernanceEvent::ConflictDetected { .. } => {
                    deps.event_log.append_context_event(
                        &context_id_bytes,
                        scp_event_log::EventType::GovernanceConflictDetected,
                        voter_did.as_ref(),
                        conflict_ts,
                    )?;
                    conflict_event_count += 1;
                }
                GovernanceEvent::ConflictResolved { .. } => {
                    deps.event_log.append_context_event(
                        &context_id_bytes,
                        scp_event_log::EventType::GovernanceConflictResolved,
                        voter_did.as_ref(),
                        conflict_ts,
                    )?;
                    conflict_event_count += 1;
                }
                _ => {}
            }
        }
        if conflict_event_count > 0 {
            *cell.class_c_view().checkpoint_events_since_mut() += conflict_event_count;
        }
    }

    let invalidated_by_conflict = conflict_events.iter().any(|e| {
        matches!(e, GovernanceEvent::ConflictResolved { loser_id, .. } if *loser_id == *proposal_id)
    });

    if let Some(proposal) = proposal_for_execution {
        let in_freeze = cell.governance.freeze.is_some();
        if !in_freeze && !invalidated_by_conflict {
            // The top `state` borrow has ended (NLL); hand the cell to the execute
            // path so the governance leaves it reaches can later migrate.
            Box::pin(execute_governance_action(cell, deps, context_id, &proposal)).await?;
        }
    }

    crate::context::messaging_helpers::persist_state_best_effort(&*cell, deps, context_id);

    Ok((status, events))
}

// The unchecked actor-shape twin of `vote_on_proposal` is not provided
// here. Production callers always route through
// `approve_governance_proposal` / `reject_governance_proposal` because
// spec §5.9 suspension overlays must apply on the vote path. The
// unchecked variant exists in the legacy module for the supervisor
// passthrough (`Supervisor::vote_on_proposal`) which keeps the legacy
// shape until Phase 2A finalization.

// ---------------------------------------------------------------------------
// approve_governance_proposal (entry point — checked)
// ---------------------------------------------------------------------------

/// Casts an approval vote on a pending governance proposal with
/// `GovernanceVote` capability validation under the same atomic path
/// as the vote.
#[instrument(skip_all, fields(context_id))]
pub async fn approve_governance_proposal(
    cell: &mut crate::context::actor::class_s::ClassSCell,
    deps: &ActorDeps,
    context_id: &str,
    proposal_id: &ProposalId,
    voter_did: &DID,
    signing_key: &ed25519_dalek::SigningKey,
) -> Result<ProposalStatus, ContextError> {
    let (status, _events) = vote_on_proposal_inner(
        cell,
        deps,
        context_id,
        proposal_id,
        voter_did,
        true,
        signing_key,
        true,
    )
    .await?;
    Ok(status)
}

// ---------------------------------------------------------------------------
// reject_governance_proposal (entry point — checked)
// ---------------------------------------------------------------------------

/// Casts a rejection vote on a pending governance proposal with
/// `GovernanceVote` capability validation under the same atomic path
/// as the vote.
#[instrument(skip_all, fields(context_id))]
pub async fn reject_governance_proposal(
    cell: &mut crate::context::actor::class_s::ClassSCell,
    deps: &ActorDeps,
    context_id: &str,
    proposal_id: &ProposalId,
    voter_did: &DID,
    signing_key: &ed25519_dalek::SigningKey,
) -> Result<ProposalStatus, ContextError> {
    let (status, _events) = vote_on_proposal_inner(
        cell,
        deps,
        context_id,
        proposal_id,
        voter_did,
        false,
        signing_key,
        true,
    )
    .await?;
    Ok(status)
}

// ---------------------------------------------------------------------------
// dispatch_content_governance_action (orchestrator)
// ---------------------------------------------------------------------------

/// Dispatches content access, structural, and reconfiguration governance
/// actions. Companion to [`dispatch_context_governance_action`].
#[allow(clippy::too_many_lines)]
pub fn dispatch_content_governance_action(
    cell: &mut crate::context::actor::class_s::ClassSCell,
    deps: &ActorDeps,
    context_id: &str,
    action: &GovernanceAction,
    meta: CommitMeta<'_>,
) -> Result<GovernanceActionResult, ContextError> {
    let CommitMeta {
        pid,
        actor_did,
        timestamp_secs,
    } = meta;
    match action {
        GovernanceAction::AddSigner { did } => {
            execute_add_signer(
                cell,
                deps,
                context_id,
                did,
                CommitMeta {
                    pid,
                    actor_did,
                    timestamp_secs,
                },
            )?;
            Ok(GovernanceActionResult::SignerAdded)
        }
        GovernanceAction::RemoveSigner { did } => {
            execute_remove_signer(
                cell,
                deps,
                context_id,
                did,
                CommitMeta {
                    pid,
                    actor_did,
                    timestamp_secs,
                },
            )?;
            Ok(GovernanceActionResult::SignerRemoved)
        }
        GovernanceAction::ModifyThreshold { new_threshold } => {
            execute_modify_threshold(
                cell,
                deps,
                context_id,
                *new_threshold,
                CommitMeta {
                    pid,
                    actor_did,
                    timestamp_secs,
                },
            )?;
            Ok(GovernanceActionResult::ThresholdModified)
        }
        GovernanceAction::EstablishToolInterface { interface } => {
            execute_establish_tool_interface(
                cell,
                deps,
                context_id,
                interface,
                CommitMeta {
                    pid,
                    actor_did,
                    timestamp_secs,
                },
            )?;
            Ok(GovernanceActionResult::ToolInterfaceEstablished)
        }
        GovernanceAction::ResetMember { did, reason } => {
            execute_reset_member(
                cell.state_mut(),
                deps,
                context_id,
                did,
                reason,
                CommitMeta {
                    pid,
                    actor_did,
                    timestamp_secs,
                },
            )?;
            Ok(GovernanceActionResult::MemberReset)
        }
        GovernanceAction::ResolveConflict {
            proposal_a,
            proposal_b,
            resolution,
        } => {
            execute_resolve_conflict(
                cell,
                deps,
                context_id,
                proposal_a,
                proposal_b,
                resolution,
                CommitMeta {
                    pid,
                    actor_did,
                    timestamp_secs,
                },
            )?;
            Ok(GovernanceActionResult::ConflictResolved)
        }
        GovernanceAction::RotateContentKeys { reason } => {
            execute_rotate_content_keys(
                cell,
                deps,
                context_id,
                reason.as_deref(),
                CommitMeta {
                    pid,
                    actor_did,
                    timestamp_secs,
                },
            )?;
            Ok(GovernanceActionResult::ContentKeysRotated(
                ContentKeysRotatedResult {
                    reason: reason.clone(),
                },
            ))
        }
        GovernanceAction::ReconfigureGovernance {
            changes,
            justification,
        } => {
            execute_reconfigure_governance(
                cell,
                deps,
                context_id,
                changes,
                justification,
                CommitMeta {
                    pid,
                    actor_did,
                    timestamp_secs,
                },
            )?;
            Ok(GovernanceActionResult::GovernanceReconfigured(
                GovernanceReconfiguredResult {
                    changes_applied: changes.len(),
                },
            ))
        }
        // Variants handled by dispatch_governance_action or
        // dispatch_context_governance_action.
        GovernanceAction::PromoteContext
        | GovernanceAction::ExtendTtl { .. }
        | GovernanceAction::SuspendCapability { .. }
        | GovernanceAction::SuspendAccess { .. }
        | GovernanceAction::RevokeAccess { .. }
        | GovernanceAction::RestoreAccess { .. }
        | GovernanceAction::SetEconomicPolicy { .. }
        | GovernanceAction::ApproveSpend { .. }
        | GovernanceAction::LockEconomicPolicy
        | GovernanceAction::AddMember { .. }
        | GovernanceAction::RemoveMember { .. }
        | GovernanceAction::ChangeRole { .. }
        | GovernanceAction::RegisterTool { .. }
        | GovernanceAction::RemoveTool { .. }
        | GovernanceAction::ModifyCeiling { .. }
        | GovernanceAction::CloseContext { .. }
        | GovernanceAction::TransferAdmin { .. }
        | GovernanceAction::CreateChildContext { .. }
        | GovernanceAction::ModifyPruningPolicy { .. }
        | GovernanceAction::ProposeContextMigration { .. }
        | GovernanceAction::CancelContextMigration
        | GovernanceAction::ModifyHardRateLimit { .. } => {
            // ADR-049 §10 (round-9): these variants are routed by
            // `dispatch_governance_action` / `dispatch_context_governance_action`
            // and never reach this content-level leaf. A future routing change
            // that mis-delivers one here must surface as a recoverable typed
            // error — NOT a panic. A panic inside a per-context actor handler
            // unwinds the task; the watchdog catches it but discards the payload
            // (it may interpolate key material) and burns respawn budget toward
            // poison (a self-DoS). Return a typed `GovernanceFailed` instead.
            Err(ContextError::GovernanceFailed(format!(
                "governance action {} is not a content-level leaf — it is routed by \
                 dispatch_governance_action / dispatch_context_governance_action",
                action.variant_name()
            )))
        }
    }
}

// ---------------------------------------------------------------------------
// dispatch_context_governance_action (orchestrator)
// ---------------------------------------------------------------------------

/// Dispatches context-level governance actions to their implementation
/// methods, returning typed [`GovernanceActionResult`] variants.
#[allow(clippy::too_many_lines)]
pub async fn dispatch_context_governance_action(
    cell: &mut crate::context::actor::class_s::ClassSCell,
    deps: &ActorDeps,
    context_id: &str,
    action: &GovernanceAction,
    meta: CommitMeta<'_>,
) -> Result<GovernanceActionResult, ContextError> {
    let CommitMeta {
        pid,
        actor_did,
        timestamp_secs,
    } = meta;
    match action {
        GovernanceAction::AddMember { did, role } => {
            execute_add_member(
                cell,
                deps,
                context_id,
                did,
                role,
                CommitMeta {
                    pid,
                    actor_did,
                    timestamp_secs,
                },
            )?;
            Ok(GovernanceActionResult::MemberAdded)
        }
        GovernanceAction::RemoveMember { did, .. } => {
            execute_remove_member(
                cell,
                deps,
                context_id,
                did,
                CommitMeta {
                    pid,
                    actor_did,
                    timestamp_secs,
                },
            )?;
            Ok(GovernanceActionResult::MemberRemoved)
        }
        GovernanceAction::ChangeRole { did, new_role } => {
            execute_change_role(
                cell,
                deps,
                context_id,
                did,
                new_role,
                CommitMeta {
                    pid,
                    actor_did,
                    timestamp_secs,
                },
            )?;
            Ok(GovernanceActionResult::RoleChanged)
        }
        GovernanceAction::RegisterTool { registration } => {
            execute_register_tool(
                cell,
                deps,
                context_id,
                registration,
                CommitMeta {
                    pid,
                    actor_did,
                    timestamp_secs,
                },
            )?;
            Ok(GovernanceActionResult::ToolRegistered)
        }
        GovernanceAction::RemoveTool { tool_id } => {
            execute_remove_tool(
                cell,
                deps,
                context_id,
                tool_id,
                CommitMeta {
                    pid,
                    actor_did,
                    timestamp_secs,
                },
            )?;
            Ok(GovernanceActionResult::ToolRemoved)
        }
        GovernanceAction::ModifyCeiling { new_ceiling } => {
            execute_modify_ceiling(
                cell,
                deps,
                context_id,
                new_ceiling,
                CommitMeta {
                    pid,
                    actor_did,
                    timestamp_secs,
                },
            )?;
            Ok(GovernanceActionResult::CeilingModified)
        }
        GovernanceAction::CloseContext { reason } => {
            execute_close_context(
                cell,
                deps,
                context_id,
                reason.as_deref(),
                CommitMeta {
                    pid,
                    actor_did,
                    timestamp_secs,
                },
            )
            .await?;
            Ok(GovernanceActionResult::ContextClosed)
        }
        GovernanceAction::TransferAdmin { new_admin } => {
            execute_transfer_admin(
                cell,
                deps,
                context_id,
                new_admin,
                CommitMeta {
                    pid,
                    actor_did,
                    timestamp_secs,
                },
            )?;
            Ok(GovernanceActionResult::AdminTransferred)
        }
        GovernanceAction::CreateChildContext { params } => {
            execute_create_child_context(
                cell,
                deps,
                context_id,
                params,
                CommitMeta {
                    pid,
                    actor_did,
                    timestamp_secs,
                },
            )?;
            Ok(GovernanceActionResult::ChildContextCreated)
        }
        GovernanceAction::ModifyPruningPolicy { new_policy } => {
            execute_modify_pruning_policy(
                cell,
                deps,
                context_id,
                new_policy,
                CommitMeta {
                    pid,
                    actor_did,
                    timestamp_secs,
                },
            )?;
            Ok(GovernanceActionResult::PruningPolicyModified)
        }
        GovernanceAction::ProposeContextMigration {
            new_context_params,
            reason,
            grace_period_secs,
            auto_invite,
        } => {
            // `execute_propose_context_migration` returns a hand-boxed
            // `Pin<Box<dyn Future + Send>>` (rather than the usual
            // `async fn` opaque-type future) so that this caller's own
            // future remains provably `Send` — see the function-level
            // doc for ADR-049 Phase 2A finalization rationale.
            let result = execute_propose_context_migration(
                cell,
                deps,
                context_id,
                new_context_params,
                reason,
                *grace_period_secs,
                *auto_invite,
                CommitMeta {
                    pid,
                    actor_did,
                    timestamp_secs,
                },
            )
            .await?;
            Ok(GovernanceActionResult::MigrationProposed(result))
        }
        GovernanceAction::CancelContextMigration => {
            execute_cancel_context_migration(
                cell,
                deps,
                context_id,
                CommitMeta {
                    pid,
                    actor_did,
                    timestamp_secs,
                },
            )
            .await?;
            Ok(GovernanceActionResult::MigrationCancelled)
        }
        GovernanceAction::AddSigner { .. }
        | GovernanceAction::RemoveSigner { .. }
        | GovernanceAction::ModifyThreshold { .. }
        | GovernanceAction::EstablishToolInterface { .. }
        | GovernanceAction::ResetMember { .. }
        | GovernanceAction::ResolveConflict { .. }
        | GovernanceAction::RotateContentKeys { .. }
        | GovernanceAction::ReconfigureGovernance { .. } => dispatch_content_governance_action(
            cell,
            deps,
            context_id,
            action,
            CommitMeta {
                pid,
                actor_did,
                timestamp_secs,
            },
        ),
        GovernanceAction::PromoteContext
        | GovernanceAction::ExtendTtl { .. }
        | GovernanceAction::SuspendCapability { .. }
        | GovernanceAction::SuspendAccess { .. }
        | GovernanceAction::RevokeAccess { .. }
        | GovernanceAction::RestoreAccess { .. }
        | GovernanceAction::SetEconomicPolicy { .. }
        | GovernanceAction::ApproveSpend { .. }
        | GovernanceAction::LockEconomicPolicy
        | GovernanceAction::ModifyHardRateLimit { .. } => {
            // ADR-049 §10 (round-9): these variants are handled by the top-level
            // `dispatch_governance_action` and never reach this context-level
            // dispatcher. A future routing change that delivers one here must
            // surface as a recoverable typed error, never an actor-killing panic
            // (see the matching arm in `dispatch_content_governance_action`).
            Err(ContextError::GovernanceFailed(format!(
                "governance action {} is not a context-level leaf — it is handled by \
                 dispatch_governance_action",
                action.variant_name()
            )))
        }
    }
}

// ---------------------------------------------------------------------------
// dispatch_governance_action (orchestrator — top-level)
// ---------------------------------------------------------------------------

/// Dispatches an approved governance action to its implementation method.
#[allow(clippy::too_many_lines)]
pub async fn dispatch_governance_action(
    cell: &mut crate::context::actor::class_s::ClassSCell,
    deps: &ActorDeps,
    context_id: &str,
    proposal: &GovernanceProposal,
) -> Result<GovernanceActionResult, ContextError> {
    let pid = proposal.proposal_id;
    let actor = proposal.proposer_did.as_ref();
    // Committer-assigned leaf timestamp: the proposal's signed `created_at`.
    // The value is identical and tamper-evident for every member that
    // processes the signed proposal (convergent-by-construction), never local
    // `now()`. The leaf itself is currently committer-appended-only — the
    // receive-side append path is dormant, so cross-member leaf replication is
    // the forward step under ADR-051 (§7.3.1, §9.9.3).
    let ts = proposal.created_at;
    match &proposal.action {
        GovernanceAction::SuspendCapability { did, capabilities } => {
            execute_suspend_member(
                cell,
                deps,
                context_id,
                did,
                capabilities,
                CommitMeta {
                    pid,
                    actor_did: actor,
                    timestamp_secs: ts,
                },
            )?;
            Ok(GovernanceActionResult::MemberSuspended(
                SuspendMemberResult {
                    did: did.clone(),
                    capabilities: capabilities.clone(),
                },
            ))
        }
        GovernanceAction::SuspendAccess { did } => {
            // Suspend all capabilities for the member. ADR-049 §9 Class S:
            // `suspend_all` strips a member's ENTIRE capability set — a downward-
            // authorization transition, identical in shape to
            // `execute_suspend_member`'s `suspend_capabilities`. Route through
            // `commit_class_s_keep` so it persists fail-closed (keep-direction: on
            // persist failure the ban STAYS — re-granting the suspended member's
            // capabilities after the caller was told the ban applied is the unsafe
            // direction). The reject-before-mutate guards return `Err` from inside
            // the closure (no persist runs); the `suspend_all` + emit (Class-C)
            // ride the SAME fail-closed persist via `view.rest_mut()`.
            cell.commit_class_s_keep(deps, context_id, |mut view| {
                let state = view.rest_mut();
                require_active(&state.handle)?;

                if !state.role_state.ceiling.contains(&Capability::MemberBan) {
                    return Err(ContextError::PermissionDenied(
                        "member:ban (MemberBan) capability not in ceiling".to_owned(),
                    ));
                }
                if !state.membership.contains(did) {
                    return Err(ContextError::MemberNotFound(did.to_string()));
                }

                state.role_state.suspend_all(did.as_ref());

                emit(
                    state,
                    ContextEvent::CapabilitiesSuspended {
                        did: did.clone(),
                        capabilities: vec![],
                    },
                    context_id,
                    deps,
                );
                Ok(())
            })?;
            let context_id_bytes = context_id_to_bytes(context_id);
            deps.event_log.append_context_event(
                &context_id_bytes,
                scp_event_log::EventType::MemberSuspendedAll,
                actor,
                ts,
            )?;
            *cell.class_c_view().checkpoint_events_since_mut() += 1;
            Ok(GovernanceActionResult::Executed)
        }
        GovernanceAction::RevokeAccess { did, access } => {
            let r = execute_revoke(
                cell,
                deps,
                context_id,
                did,
                *access,
                CommitMeta {
                    pid,
                    actor_did: actor,
                    timestamp_secs: ts,
                },
            )?;
            Ok(GovernanceActionResult::AccessRevoked(RevokeResult {
                did: did.clone(),
                access: *access,
                rotated_author_count: r,
            }))
        }
        GovernanceAction::RestoreAccess { did, capabilities } => {
            execute_restore_access(
                cell,
                deps,
                context_id,
                did,
                capabilities,
                CommitMeta {
                    pid,
                    actor_did: actor,
                    timestamp_secs: ts,
                },
            )?;
            Ok(GovernanceActionResult::AccessRestored(
                RestoreAccessResult {
                    did: did.clone(),
                    capabilities: capabilities.clone(),
                },
            ))
        }
        GovernanceAction::PromoteContext => {
            execute_promote_context(
                cell,
                deps,
                context_id,
                &proposal.approvals,
                CommitMeta {
                    pid,
                    actor_did: actor,
                    timestamp_secs: ts,
                },
            )?;
            Ok(GovernanceActionResult::ContextPromoted)
        }
        GovernanceAction::ExtendTtl { additional_secs } => {
            execute_extend_ttl(
                cell,
                deps,
                context_id,
                *additional_secs,
                &proposal.approvals,
                CommitMeta {
                    pid,
                    actor_did: actor,
                    timestamp_secs: ts,
                },
            )
            .await?;
            Ok(GovernanceActionResult::TtlExtended)
        }
        GovernanceAction::SetEconomicPolicy { policy } => {
            execute_set_economic_policy(
                cell,
                deps,
                context_id,
                policy,
                CommitMeta {
                    pid,
                    actor_did: actor,
                    timestamp_secs: ts,
                },
            )?;
            Ok(GovernanceActionResult::Executed)
        }
        GovernanceAction::ApproveSpend {
            spender,
            amount,
            purpose,
        } => {
            execute_approve_spend(
                cell,
                deps,
                context_id,
                spender,
                *amount,
                purpose,
                CommitMeta {
                    pid,
                    actor_did: actor,
                    timestamp_secs: ts,
                },
            )?;
            Ok(GovernanceActionResult::Executed)
        }
        GovernanceAction::LockEconomicPolicy => {
            execute_lock_economic_policy(
                cell,
                deps,
                context_id,
                CommitMeta {
                    pid,
                    actor_did: actor,
                    timestamp_secs: ts,
                },
            )?;
            Ok(GovernanceActionResult::Executed)
        }
        GovernanceAction::ModifyHardRateLimit { new_config } => {
            execute_modify_hard_rate_limit(
                cell,
                deps,
                context_id,
                new_config,
                CommitMeta {
                    pid,
                    actor_did: actor,
                    timestamp_secs: ts,
                },
            )?;
            Ok(GovernanceActionResult::Executed)
        }
        // Remaining actions dispatched to context-level handler.
        GovernanceAction::AddMember { .. }
        | GovernanceAction::RemoveMember { .. }
        | GovernanceAction::ChangeRole { .. }
        | GovernanceAction::RegisterTool { .. }
        | GovernanceAction::RemoveTool { .. }
        | GovernanceAction::ModifyCeiling { .. }
        | GovernanceAction::CloseContext { .. }
        | GovernanceAction::TransferAdmin { .. }
        | GovernanceAction::CreateChildContext { .. }
        | GovernanceAction::ModifyPruningPolicy { .. }
        | GovernanceAction::AddSigner { .. }
        | GovernanceAction::RemoveSigner { .. }
        | GovernanceAction::ModifyThreshold { .. }
        | GovernanceAction::EstablishToolInterface { .. }
        | GovernanceAction::ResetMember { .. }
        | GovernanceAction::ResolveConflict { .. }
        | GovernanceAction::RotateContentKeys { .. }
        | GovernanceAction::ReconfigureGovernance { .. }
        | GovernanceAction::ProposeContextMigration { .. }
        | GovernanceAction::CancelContextMigration => {
            dispatch_context_governance_action(
                cell,
                deps,
                context_id,
                &proposal.action,
                CommitMeta {
                    pid,
                    actor_did: actor,
                    timestamp_secs: ts,
                },
            )
            .await
        }
    }
}

// ---------------------------------------------------------------------------
// finalize_governance_action (post-dispatch)
// ---------------------------------------------------------------------------

/// Post-dispatch finalization for an executed governance action.
///
/// Handles MLS epoch coordination (ADR-031 §8), event emission
/// (PRD SCP-269/SCP-270), checkpoint cosignature triggering (ADR-031 §9),
/// and cleanup of approved proposals (ADR-031 §7).
#[allow(clippy::too_many_lines, clippy::option_if_let_else)]
pub fn finalize_governance_action(
    state: &mut PerContextState,
    deps: &ActorDeps,
    context_id: &str,
    proposal: &GovernanceProposal,
) -> Result<(), ContextError> {
    // For MLS-mutating actions (AddMember, RemoveMember, Revoke,
    // ResetMember), increment the epoch counter, place the old epoch into
    // the grace store (§23.11), record the coordination in the
    // EpochCoordinator (ADR-031 §8). Non-MLS actions leave the epoch
    // unchanged and report None.
    let resulting_epoch = if classify_action(&proposal.action) == MlsImpact::MembershipChange {
        let mls_op = generate_mls_operations(proposal)
            .map_err(|e| ContextError::GovernanceFailed(e.to_string()))?;

        let old_epoch = state.epoch.mls_epoch;
        state.epoch.mls_epoch = old_epoch.saturating_add(1);
        let _expired = state.epoch.grace_store.add_epoch(old_epoch);

        if let Some(operation) = mls_op {
            let timestamp = deps.clock.now_secs();
            let _ = state.epoch.coordinator.record_coordination(
                proposal.proposal_id,
                old_epoch,
                state.epoch.mls_epoch,
                operation,
                timestamp,
            );
        }

        Some(state.epoch.mls_epoch)
    } else {
        None
    };

    // Construct the structured GovernanceEvent::GovernanceActionExecuted
    // and emit it to both the Merkle event log and the receive buffer
    // (ADR-031 §8, PRD SCP-269/SCP-270).
    let executed_event = GovernanceEvent::GovernanceActionExecuted {
        proposal_id: proposal.proposal_id,
        action: Box::new(proposal.action.clone()),
        executor_did: proposal.proposer_did.clone(),
        resulting_epoch,
    };

    let context_id_bytes = context_id_to_bytes(context_id);
    let action_variant = proposal.action.variant_name();
    let executed_payload = scp_event_log::payload::encode_payload(
        &scp_event_log::payload::GovernanceActionExecutedPayload {
            target_did: proposal
                .action
                .target_did()
                .map(|d| d.as_ref().to_owned())
                .unwrap_or_default(),
            action_type: action_variant.to_owned(),
        },
    )
    .map_err(|e| ContextError::EventLogFailed(e.to_string()))?;
    deps.event_log.append_context_event_with_payload(
        &context_id_bytes,
        governance_event_label(&executed_event),
        proposal.proposer_did.as_ref(),
        executed_payload,
        // Committer-assigned timestamp: the proposal's signed `created_at` —
        // identical and tamper-evident for every member that processes the
        // signed proposal (convergent-by-construction), never local `now()`.
        // The leaf is currently committer-appended-only; cross-member leaf
        // replication is the forward step under ADR-051 (§7.3.1, §9.9.3).
        proposal.created_at,
    )?;

    let action_summary = proposal.action.variant_name().to_owned();
    let target_did = proposal.action.target_did().cloned();
    state.checkpoint_events_since += 1;

    // 1. Push GovernanceActionExecuted to receive buffer.
    let gov_event = ContextEvent::GovernanceActionExecuted {
        proposal_id: proposal.proposal_id,
        action_summary,
        executor_did: proposal.proposer_did.clone(),
        resulting_epoch,
        target_did,
    };
    emit(state, gov_event, context_id, deps);

    // 2. Trigger checkpoint cosignature collection for multi-admin
    //    contexts (ADR-031 §9).
    let (required_signers, minimum_count) = state
        .governance
        .engine
        .checkpoint_cosignature_requirements();
    if minimum_count > 0 {
        emit(
            state,
            ContextEvent::CheckpointCosignatureRequired {
                proposal_id: proposal.proposal_id,
                required_signers,
                minimum_count,
                at_epoch: state.epoch.mls_epoch,
            },
            context_id,
            deps,
        );
    }

    // 3. Remove the executed proposal from approved_proposals.
    state
        .governance
        .approved_proposals
        .remove(&proposal.proposal_id);

    // Evaluate consequence rules after governance action (ADR-017,
    // #1531). Use split-borrow variant so both legacy and actor-shape
    // states feed the same enforcement pipeline.
    {
        let now = deps.clock.now_secs();
        let rules = state.governance.consequence_rules.clone();
        if !rules.is_empty() {
            // Proposer and target share one merged event set and one convergent
            // window anchor so both evaluations are convergent across members.
            let (buf_events, convergent_now) = event_log_entries_for_consequences(
                &state.receive_buffer,
                context_id,
                now,
                &*deps.event_log,
            );
            let triggered_proposer = scp_protocol::trust::consequence::evaluate_consequence_rules(
                &rules,
                &buf_events,
                proposal.proposer_did.as_ref(),
                now,
                convergent_now,
            );
            let triggered_target = if let Some(target) = proposal.action.target_did()
                && target != &proposal.proposer_did
            {
                Some((
                    target.clone(),
                    scp_protocol::trust::consequence::evaluate_consequence_rules(
                        &rules,
                        &buf_events,
                        target.as_ref(),
                        now,
                        convergent_now,
                    ),
                ))
            } else {
                None
            };

            let mut split = ConsequenceStateSplit::from_state(state);
            enforce_triggered_consequences(
                &mut split,
                &EnforceConsequencesCtx {
                    context_id,
                    member_did: &proposal.proposer_did,
                    now,
                    triggered: &triggered_proposer,
                    rules: &rules,
                    clock: &*deps.clock,
                    event_log: &*deps.event_log,
                    event_tx: deps.event_tx.as_ref(),
                },
            );
            if let Some((target, triggered)) = triggered_target {
                let mut split = ConsequenceStateSplit::from_state(state);
                enforce_triggered_consequences(
                    &mut split,
                    &EnforceConsequencesCtx {
                        context_id,
                        member_did: &target,
                        now,
                        triggered: &triggered,
                        rules: &rules,
                        clock: &*deps.clock,
                        event_log: &*deps.event_log,
                        event_tx: deps.event_tx.as_ref(),
                    },
                );
            }
        }
    }

    // Update participation record after governance action (#1530).
    {
        let now = deps.clock.now_secs();
        // Participation-record path: only the merged event set is consumed.
        let (gov_events, _convergent_now) = event_log_entries_for_consequences(
            &state.receive_buffer,
            context_id,
            now,
            &*deps.event_log,
        );
        let gov_merkle = deps
            .event_log
            .event_log_merkle_root(&context_id_bytes)
            .unwrap_or([0u8; 32]);
        if !gov_events.is_empty()
            && let Ok(record) = scp_protocol::trust::participation::compute_participation_record(
                &gov_events,
                proposal.proposer_did.as_ref(),
                context_id,
                gov_merkle,
                now,
            )
            && record.participation_count > 0
        {
            state
                .governance
                .participation_cache
                .insert(proposal.proposer_did.to_string(), record);
        }
    }

    // 4. Persistence is no longer performed here. ADR-049 §9 (authorized
    // strengthening): the caller `execute_governance_action` now persists the
    // whole post-finalize state via the deferred `ClassSCommitToken`'s
    // FAIL-CLOSED `commit` (previously this was a best-effort persist), so the
    // `executed_proposals` replay marker and every other finalize mutation are
    // durable before the governance action is acknowledged. `state`, `deps`, and
    // `context_id` remain used above (MLS-epoch / event-log append / cache).

    Ok(())
}

// ---------------------------------------------------------------------------
// execute_governance_action (entry point — orchestrates dispatch + finalize)
// ---------------------------------------------------------------------------

/// Executes an approved governance action on a broadcast context.
///
/// # Errors
///
/// - [`ContextError::PermissionDenied`] if the proposal is not in
///   `Approved` status.
/// - [`ContextError::PermissionDenied`] if the proposal targets a
///   different context than the one provided.
/// - [`ContextError::ContextNotActive`] if the context is not `Active`.
#[instrument(skip_all, fields(context_id))]
pub async fn execute_governance_action(
    cell: &mut crate::context::actor::class_s::ClassSCell,
    deps: &ActorDeps,
    context_id: &str,
    proposal: &GovernanceProposal,
) -> Result<GovernanceActionResult, ContextError> {
    // ADR-049 §9 Class-S cell seam: this entry holds the cell. The pre-dispatch
    // gate is READ-ONLY (proposal status/context match, commit-fault gate,
    // replay-marker presence) — read through the cell's `Deref` (`&*cell`), no
    // mutation. The `executed_proposals` replay-marker WRITE below routes through
    // the deferred-persist `begin_class_s` combinator; the downstream dispatch
    // chain takes the cell directly.
    if !matches!(proposal.status, ProposalStatus::Approved) {
        return Err(ContextError::PermissionDenied(format!(
            "governance proposal is not approved (status: {:?})",
            proposal.status
        )));
    }

    if proposal.context_id != context_id {
        return Err(ContextError::PermissionDenied(format!(
            "governance proposal targets context '{}' but was submitted to '{}'",
            proposal.context_id, context_id
        )));
    }

    // PR #1606 C6 fail-close gate + atomically check replay AND mark as
    // executed before dispatch. Actor-owned state — single linear sequence.
    check_commit_fault(cell)?;

    if cell
        .governance
        .class_s
        .executed_proposals
        .contains_key(&proposal.proposal_id)
    {
        return Err(ContextError::PermissionDenied(
            "governance proposal has already been executed".into(),
        ));
    }
    let now = deps.clock.now_secs();

    // Governance action costing: no PaidActionType::GovernanceAction
    // variant exists yet. Governance actions are free until the economy
    // spec adds a governance cost tier. Tracked by #1537.

    // ADR-049 §9 Class S: route the `executed_proposals` replay-marker
    // (retain TTL + insert) through the DEFERRED-persist combinator. The mark is
    // applied in memory now; its fail-closed persist is DEFERRED until the
    // dispatch + finalize either succeed (committed below) or abort (the marker
    // is un-marked, then the removal is itself committed fail-closed —
    // keep-direction: the replay window must be closed durably whichever way it
    // resolves). The top `state` borrow has ended (NLL) so the cell is free for
    // the combinator and the downstream dispatch chain.
    let ((), token) = cell.begin_class_s(context_id, |mut view| {
        let class_s = view.governance_class_s_mut();
        class_s
            .executed_proposals
            .retain(|_, ts| now.saturating_sub(*ts) < EXECUTED_PROPOSALS_TTL_SECS);
        class_s.executed_proposals.insert(proposal.proposal_id, now);
        Ok(())
    })?;

    let result = match dispatch_governance_action(cell, deps, context_id, proposal).await {
        Ok(r) => r,
        Err(e) => {
            // Roll back the executed marker on dispatch failure so the proposal
            // can be retried (e.g. after a transient crypto error). The removal
            // is itself a Class-S transition that must be durable fail-closed
            // (keep-direction: a crash must not resurrect the marker and block
            // the retry). It is staged through the deferred-persist token's own
            // ClassSMut flow — `discharge_with` runs the removal closure
            // (`ClassSMut::governance_class_s_mut().executed_proposals.remove`)
            // and then performs the SINGLE fail-closed persist the token already
            // owed, so the removed-marker state is what lands durably (no
            // `state_mut`, exactly one persist — the one the token deferred).
            token.discharge_with(cell, deps, context_id, |mut view| {
                view.governance_class_s_mut()
                    .executed_proposals
                    .remove(&proposal.proposal_id);
                Ok(())
            })?;
            return Err(e);
        }
    };

    // STRENGTHENING (ADR-049 §9, authorized): `finalize_governance_action`'s
    // own persist was best-effort; the executed-marker durability now rides the
    // token's FAIL-CLOSED `commit` instead. `finalize_governance_action` is a
    // Class-C body reached through the token's `discharge_with` ClassSMut view
    // (`rest_mut()`), so it runs and is then persisted FAIL-CLOSED by the SINGLE
    // deferred persist the token owed — no whole-state `state_mut`. On a finalize
    // error the persist STILL runs (keep-direction — the executed marker stays
    // set and must persist) and `discharge_with` surfaces the finalize error.
    token.discharge_with(cell, deps, context_id, |mut view| {
        finalize_governance_action(view.rest_mut(), deps, context_id, proposal)
    })?;

    Ok(result)
}

// ---------------------------------------------------------------------------
// try_broadcast_commit_or_enqueue (transitive helper, actor-shape)
// ---------------------------------------------------------------------------

/// Attempts to broadcast an MLS Commit and, on transport failure,
/// enqueues the commit in the persistent retry queue (PR #1606 C6).
///
/// Per the phase-2.md ADR-011-amendment exclusion taxonomy (per-committer
/// broadcast-retry bookkeeping), the commit-broadcast lifecycle events
/// (`CommitBroadcasted` / `CommitBroadcastPending`) are NOT durably appended
/// to the canonical Merkle log: only the broadcasting member holds the notion,
/// so two honest members diverge at equal event count (§9.9.3). They are
/// surfaced as local `ContextEvent`s only (first-attempt success is not
/// surfaced); no durable consumer reads them.
///
/// Infallible: a transport-send failure is absorbed into the persistent
/// retry queue (or a `commit_fault` marker when the queue is full) rather
/// than propagated. Dropping the durable commit-lifecycle appends removed the
/// function's only `Result`-returning path.
pub fn try_broadcast_commit_or_enqueue(
    state: &mut PerContextState,
    deps: &ActorDeps,
    context_id: &str,
    commit_bytes: Vec<u8>,
    operation: &CommitOperation,
) {
    if commit_bytes.is_empty() {
        return;
    }
    let routing_id = scp_protocol::context::context_routing_id(context_id);
    match deps.transport.send_message(&routing_id, &commit_bytes) {
        Ok(()) => {}
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
                        operation: label,
                        reason: format!("queue full ({MAX_PENDING_COMMITS}): {error_str}"),
                        attempts: 1,
                    },
                    context_id,
                    deps,
                );
                return;
            }
            state.pending_commits.push_back(pending);
            let label_for_event = label.clone();
            emit(
                state,
                ContextEvent::CommitBroadcastPending {
                    operation: label_for_event,
                    error: error_str.clone(),
                    attempt: 1,
                },
                context_id,
                deps,
            );
            tracing::warn!(
                context_id = %context_id,
                operation = %label,
                error = %error_str,
                "MLS commit broadcast failed; enqueued for persistent retry (PR #1606 C6)"
            );
        }
    }
}

// ===========================================================================
// Supervisor-iterating sweep entry points (Phase 2A finalization)
// ===========================================================================
//
// These are the non-legacy replacements for the `_legacy` sweep helpers
// in `governance_helpers_legacy.rs`. Each iterates
// [`Supervisor::actor_ids`](crate::context::supervisor::Supervisor::actor_ids)
// (the actor registry — NOT the legacy `Supervisor::contexts` DashMap)
// and dispatches one typed sweep command per actor via the per-actor
// mailbox.
//
// Per-actor sweep bodies live in
// [`crate::context::actor::handlers::governance`] as
// `handle_*_actor` functions, dispatched from the actor's
// `dispatch_state` arm for the matching `GovernanceCommand` variant.
//
// Sweep commands carry no `context_id` field — the routing target is
// decided at the iteration site (one command per known actor). They
// are NOT routable via `Supervisor::dispatch_governance_command`
// because `governance_command_context_id` returns `None`; callers MUST
// go through these entry points.

/// Sweep entry point: evaluate consequence rules for every registered
/// actor.
///
/// Relocates the legacy `evaluate_periodic_consequences_legacy` off
/// the `Supervisor::contexts` `DashMap` (now deleted). Iterates the
/// actor registry and dispatches one
/// [`GovernanceCommand::EvaluatePeriodicConsequences`](crate::context::actor::commands::GovernanceCommand::EvaluatePeriodicConsequences)
/// per actor.
///
/// Best-effort: if an actor's mailbox is closed mid-sweep (actor has
/// shut down) the iteration silently skips it. Per-actor replies are
/// awaited in turn — the sweep returns when every actor has either
/// replied or its mailbox is gone.
///
/// First bulk-iterator caller lands in Phase 2B per ADR-049 — the
/// per-context governance-timeout task's tick closure already
/// dispatches the per-actor variant directly via the actor mailbox
/// (see `start_governance_timeout_task_legacy`'s Phase 4), so the
/// supervisor-scope sweep is only needed for FFI bridge "evaluate
/// now" operations or test fixtures that drive deterministic ticks.
#[allow(
    dead_code,
    reason = "first bulk-iterator caller lands in Phase 2B per ADR-049 — \
              the per-actor variant is wired through the timer task today"
)]
pub async fn evaluate_periodic_consequences(supervisor: &crate::context::supervisor::Supervisor) {
    use crate::context::actor::commands::{ContextCommand, GovernanceCommand};

    for ctx_id in supervisor.actor_ids() {
        let Some(actor) = supervisor.lookup(&ctx_id) else {
            continue;
        };
        let (tx, rx) = tokio::sync::oneshot::channel();
        let cmd = ContextCommand::Governance(GovernanceCommand::EvaluatePeriodicConsequences {
            reply: tx,
        });
        if actor
            .send_with_timeout(cmd, crate::context::actor::SEND_TIMEOUT)
            .await
            .is_err()
        {
            // Mailbox closed — actor shut down between snapshot and
            // dispatch. Skip silently (legacy did the same on
            // DashMap::get returning None mid-iteration).
            continue;
        }
        let _ = rx.await;
    }
}

/// Sweep entry point: process the MLS commit retry queue for every
/// registered actor (PR #1606 C6).
///
/// Relocates the legacy `process_pending_commits_legacy` off the
/// `Supervisor::contexts` `DashMap` (now deleted). Iterates the actor
/// registry and dispatches one
/// [`GovernanceCommand::ProcessPendingCommits`](crate::context::actor::commands::GovernanceCommand::ProcessPendingCommits)
/// per actor.
///
/// First bulk-iterator caller lands in Phase 2B per ADR-049 — see
/// [`evaluate_periodic_consequences`] for the rationale (the
/// per-actor variant is already wired through the timer task).
#[allow(
    dead_code,
    reason = "first bulk-iterator caller lands in Phase 2B per ADR-049 — \
              the per-actor variant is wired through the timer task today"
)]
pub async fn process_pending_commits(supervisor: &crate::context::supervisor::Supervisor) {
    use crate::context::actor::commands::{ContextCommand, GovernanceCommand};

    for ctx_id in supervisor.actor_ids() {
        let Some(actor) = supervisor.lookup(&ctx_id) else {
            continue;
        };
        let (tx, rx) = tokio::sync::oneshot::channel();
        let cmd =
            ContextCommand::Governance(GovernanceCommand::ProcessPendingCommits { reply: tx });
        if actor
            .send_with_timeout(cmd, crate::context::actor::SEND_TIMEOUT)
            .await
            .is_err()
        {
            continue;
        }
        let _ = rx.await;
    }
}

/// Sweep entry point: run one tick of the governance timeout pipeline
/// for a single context (target supplied by the caller — the
/// supervisor's spawn-time per-context timer task).
///
/// This is the per-tick body that the spawn-time governance-timeout
/// task invokes. Unlike the bulk sweeps above, this entry point
/// targets a single named context (the timer's own); the
/// supervisor-iterating shape is reserved for the bulk consequence /
/// commit sweeps.
///
/// Dispatches
/// [`GovernanceCommand::EvaluateTimeouts`](crate::context::actor::commands::GovernanceCommand::EvaluateTimeouts)
/// to the named actor and returns whether the timer loop should
/// continue (`true`) or stop (`false`). Matches the legacy timer
/// closure's `bool` return.
///
/// Returns `false` if the actor cannot be reached (mailbox closed or
/// no actor registered for `context_id`) — the timer loop stops in
/// that case, matching the legacy `contexts.get(ctx_id) = None ->
/// return false` semantics (registry-based replacement for the
/// stale-generation gate).
async fn tick_governance_timeout(
    supervisor: &crate::context::supervisor::handle::SupervisorHandle,
    context_id: &str,
) -> bool {
    use crate::context::actor::commands::{ContextCommand, GovernanceCommand};

    let Some(actor) = supervisor.lookup(context_id) else {
        return false;
    };
    let (tx, rx) = tokio::sync::oneshot::channel();
    let cmd = ContextCommand::Governance(GovernanceCommand::EvaluateTimeouts { reply: tx });
    if actor
        .send_with_timeout(cmd, crate::context::actor::SEND_TIMEOUT)
        .await
        .is_err()
    {
        return false;
    }
    match rx.await {
        Ok(Ok(b)) => b,
        _ => false,
    }
}

/// Spawn (or respawn) THIS context's governance-timeout interval task on
/// actor-owned state.
///
/// Replaces `start_governance_timeout_task_legacy`: the new interval
/// loop holds no `&Supervisor` and reads no `contexts` `DashMap`. On each
/// 60-second wake it resolves the owning actor via
/// [`SupervisorHandle::lookup`](crate::context::supervisor::handle::SupervisorHandle::lookup)
/// and mailboxes
/// [`GovernanceCommand::EvaluateTimeouts`](crate::context::actor::commands::GovernanceCommand::EvaluateTimeouts),
/// whose actor handler runs all five timeout phases (proposal
/// resolution, deadlock detection, event writeback, consequence
/// evaluation, commit-retry drain) on the actor's owned `&mut state`. A
/// `lookup → None` / mailbox failure stops the loop — the registry-based
/// replacement for the legacy stale-generation gate.
///
/// The loop is spawned onto the supervisor's tracked `task_set` via
/// [`SupervisorHandle::tracked_spawn`](crate::context::supervisor::handle::SupervisorHandle::tracked_spawn);
/// its cancel `Notify` + `AbortHandle` are installed on
/// `state.governance.timeout_task` via
/// [`GovernanceTimeoutTask::install`](crate::context::governance::timeout::GovernanceTimeoutTask::install),
/// which aborts any prior task first (cancel/reset semantics preserved).
///
/// `tracked_spawn` is awaited (it acquires the `task_set` mutex) so the
/// abort handle is available to install before returning. Called from
/// the actor handler for
/// [`GovernanceCommand::StartTimeoutTask`](crate::context::actor::commands::GovernanceCommand::StartTimeoutTask).
pub async fn spawn_governance_timeout_task(
    cell: &mut crate::context::actor::class_s::ClassSCell,
    deps: &ActorDeps,
) {
    use crate::context::governance::timeout::TIMEOUT_CHECK_INTERVAL_SECS;

    // Reads of the context id go through the cell's `Deref`; no whole-state
    // `&mut` is taken across the spawn `.await`.
    let context_id = cell.handle.context_id().to_owned();
    let supervisor = deps.supervisor.clone();
    let cancel = std::sync::Arc::new(tokio::sync::Notify::new());

    let loop_cancel = std::sync::Arc::clone(&cancel);
    let loop_fut = async move {
        loop {
            tokio::select! {
                () = tokio::time::sleep(std::time::Duration::from_secs(
                    TIMEOUT_CHECK_INTERVAL_SECS,
                )) => {
                    if !tick_governance_timeout(&supervisor, &context_id).await {
                        break;
                    }
                }
                () = loop_cancel.notified() => {
                    break;
                }
            }
        }
    };

    // Spawn onto the supervisor's tracked task_set and install the
    // cancel signal + abort handle on actor-owned state. In the degraded
    // no-task-set config `tracked_spawn` returns `None`; nothing to
    // install (matches the legacy `task_set_ref() == None` early-return).
    // Coalesced: the timeout-task handle is Class-C / structural (a transient
    // abort handle, not durable authorization state) — installed through the
    // non-persisting Class-C view AFTER the spawn `.await` resolves, with no
    // per-site persist injected.
    if let Some(abort) = deps.supervisor.tracked_spawn(loop_fut).await {
        cell.class_c_view()
            .governance_class_c_mut()
            .timeout_task_mut()
            .install(cancel, abort);
    }
}

/// Sweep entry point retained as the non-legacy module surface for the
/// lifecycle bootstrap. Mailboxes
/// [`GovernanceCommand::StartTimeoutTask`](crate::context::actor::commands::GovernanceCommand::StartTimeoutTask)
/// to the freshly-spawned actor, which installs the interval task on its
/// owned `state.governance.timeout_task` via
/// [`spawn_governance_timeout_task`].
///
/// Best-effort: a `lookup → None` (actor not yet registered) or
/// mailbox-send failure is logged and skipped — the governance-timeout
/// task is a background facility, not part of the create/restore success
/// contract.
pub async fn start_governance_timeout_task(
    supervisor: &crate::context::supervisor::handle::SupervisorHandle,
    context_id: &str,
) {
    use crate::context::actor::commands::{ContextCommand, GovernanceCommand};

    let Some(actor) = supervisor.lookup(context_id) else {
        tracing::warn!(
            context_id,
            "start_governance_timeout_task: no actor registered — timeout task not installed"
        );
        return;
    };
    let (tx, rx) = tokio::sync::oneshot::channel();
    let cmd = ContextCommand::Governance(GovernanceCommand::StartTimeoutTask { reply: tx });
    if actor
        .send_with_timeout(cmd, crate::context::actor::SEND_TIMEOUT)
        .await
        .is_err()
    {
        tracing::warn!(
            context_id,
            "start_governance_timeout_task: mailbox send failed — timeout task not installed"
        );
        return;
    }
    if let Ok(Err(e)) = rx.await {
        tracing::warn!(
            context_id,
            error = %e,
            "start_governance_timeout_task: actor reported timeout-task install failure"
        );
    }
}

/// Translates governance timeout events into [`ContextEvent`]s for the
/// receive buffer.
///
/// Pure transform over the timeout-processing outputs: it reads only the
/// resolved [`GovernanceEvent`] slice, the MLS epoch, the detected
/// deadlock conditions, and the current recovery flag, and produces the
/// [`ContextEvent`]s to emit. No actor state or supervisor handle is
/// touched, so it is shared verbatim by the actor-shape timeout path.
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
