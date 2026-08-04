//! Governance helpers — actor-shape signatures
//! (ADR-049 Phase 2A.8, `governance` domain migration).
//!
//! # Purpose
//!
//! This module hosts governance-domain helpers that operate on
//! actor-owned [`PerContextState`](crate::context::actor::state::PerContextState)
//! and capability-reduced [`ActorDeps`](crate::context::actor::deps::ActorDeps).
//! The pre-migration `&Supervisor` lock-and-call bodies have been removed
//! (Phase 2A finalization); this module is the sole home for these helpers.
//!
//! # Migration shape
//!
//! Phase 2A.8 lands as a multi-commit ladder. Each commit migrates a
//! group of related helpers, wiring the actor-shape
//! `handlers::governance::dispatch` arms incrementally. The
//! supervisor-scoped sweep helpers (`evaluate_periodic_consequences`,
//! `process_pending_commits`, `compute_commit_retry_outcomes`,
//! `apply_commit_retry_outcomes`) iterate the actor registry and drive
//! each context's per-actor sweep body through its mailbox. (Governance
//! timeouts are an ACTOR-OWNED interval arm — ADR-049 finding A3 — not a
//! supervisor-spawned task.)

use scp_clock::Clock;
use scp_did::DID;
use scp_protocol::context::broadcast::AuthorKeyRotation;
use scp_protocol::context::governance::mls_integration::{
    MlsImpact, classify_action, generate_mls_operations,
};
use scp_protocol::context::governance::{
    AccessScope, GovernanceAction, GovernanceContext, GovernanceEvent, GovernanceProposal,
    ProposalId, ProposalStatus, PruningPolicy,
};
use scp_protocol::context::membership::{ContextEvent, ReceiveBuffer};
use scp_protocol::context::outlets::interface::OutletInterface;
use scp_protocol::context::params::OutletRegistration;
use scp_protocol::context::roles::{self, Capability, CapabilityCeiling};
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
    MAX_OUTLET_INTERFACES, MAX_PENDING_COMMITS, MAX_REGISTERED_OUTLETS, MAX_THRESHOLD_SIGNERS,
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

    let handle_state = cell.handle.state();
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

        // TTL + governance timers are actor-owned arms (ADR-049 finding A3);
        // the tombstone leaves the context non-Active so `reconcile_timers`
        // clears the governance interval and disarms the TTL arm. Clear the
        // recorded TTL deadline HERE (durably, in the fail-closed snapshot) so a
        // stale absolute deadline cannot fire against the tombstoned context on
        // a later restore and despawn it — which would defeat tombstone finality
        // by making the id re-creatable (BUG-1).
        state.ttl.timer.deadline_unix_secs = None;
        state.broadcast_context = None;
        state.migration_state = None;
        // M7: Participation decay on tombstone (#1530).
        state.governance.decay_participation();
        Ok(())
    })
    .await?;

    let tombstone_payload =
        scp_event_log::payload::encode_payload(&scp_event_log::payload::ContextTombstonedPayload {
            destination_id,
            migration_proposal_id: migration_pid,
        })
        .map_err(|e| ContextError::EventLogFailed(e.to_string()))?;
    deps.event_log
        .append_context_event_with_payload(
            &context_id_bytes,
            scp_event_log::EventType::ContextTombstoned,
            "system",
            tombstone_payload,
            tombstone_ts,
        )
        .await?;
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
        deps.event_log
            .append_context_event(
                &context_id_bytes,
                governance_event_label(event),
                voter_did.as_ref(),
                withdraw_ts,
            )
            .await?;
        event_count += 1;
    }

    // Best-effort persist (matches the pre-migration unconditional
    // `persist_state_best_effort`); the checkpoint bump remains conditional on
    // events having been appended.
    cell.commit_class_c_best_effort(deps, context_id, |mut view| {
        if event_count > 0 {
            *view.checkpoint_events_since_mut() += event_count;
        }
    })
    .await;

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
        // ADR-049 §9: downward-auth ceiling WRITE via the named `set_ceiling`
        // mutator, inside this fail-closed-persisting `commit_class_s_keep`.
        // `set_ceiling` re-validates the whole replacement against the
        // ceiling-entry grammar (spec §5.3.1.1) before storing: the
        // construction invariant holds even if a malformed pending modification
        // somehow reached this apply step (it cannot — `execute_modify_ceiling`
        // rejects malformed entries at propose/stage time — but the invariant is
        // enforced by construction at the write, not assumed). On a rejected
        // write the prior ceiling stays and the pending record is NOT cleared.
        state
            .role_state
            .set_ceiling(CapabilityCeiling::new(
                pending.new_capabilities.iter().cloned(),
            ))
            .map_err(|e| {
                ContextError::InvalidState(format!(
                    "pending ceiling modification has a malformed entry: {e}"
                ))
            })?;
        state.governance.pending_ceiling_modification = None;
        Ok(())
    })
    .await?;

    let context_id_bytes = context_id_to_bytes(context_id);
    deps.event_log
        .append_context_event(
            &context_id_bytes,
            scp_event_log::EventType::CeilingModified,
            "",
            // Timer-triggered deferred application: the convergent leaf timestamp is
            // the pre-computed effective deadline (deterministic across members),
            // never local `now()` (§7.3.1, §9.9.3).
            pending.effective_at,
        )
        .await?;
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
    })
    .await;

    let context_id_bytes = context_id_to_bytes(context_id);
    deps.event_log
        .append_context_event(
            &context_id_bytes,
            scp_event_log::EventType::EconomicPolicyApplied,
            "",
            // Timer-triggered deferred application: the convergent leaf timestamp is
            // the pre-computed effective deadline (deterministic across members),
            // never local `now()` (§7.3.1, §9.9.3).
            effective_at,
        )
        .await?;
    *cell.class_c_view().checkpoint_events_since_mut() += 1;

    Ok(true)
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
pub async fn execute_suspend_member(
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

        if !view.role_state.ceiling().contains(&Capability::MemberBan) {
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
    })
    .await?;

    let context_id_bytes = context_id_to_bytes(context_id);
    deps.event_log
        .append_context_event(
            &context_id_bytes,
            scp_event_log::EventType::MemberSuspended,
            actor_did,
            timestamp_secs,
        )
        .await?;
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
pub async fn execute_revoke(
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
    // exactly as the prior early returns did. Broadcast security state (author
    // block lists + governance-ban key-epoch advance) now rides the Class-S
    // `ContextSnapshot`, so the combinator's fail-closed persist covers it
    // ATOMICALLY with `read_exclusion_list` — the prior trailing best-effort
    // `persist_broadcast_snapshot` (a separate warn-and-continue write) is gone
    // (§5.14.8 block-before-serve). The post-persist external work (event-log
    // append, sender-key rotation, the coalesced `checkpoint_events_since` bump)
    // is UNCHANGED and runs after.
    let (rotated_authors, needs_sender_key_rotation) = cell
        .commit_class_s_keep(deps, context_id, |mut view| {
            let state = view.rest_mut();
            require_active(&state.handle)?;

            if !state.role_state.ceiling().contains(&Capability::MemberBan) {
                return Err(ContextError::PermissionDenied(
                    "member:ban (MemberBan) capability not in ceiling".to_owned(),
                ));
            }
            if !state.membership.contains(did) {
                return Err(ContextError::MemberNotFound(did.to_string()));
            }

            let mut rotated_authors: Vec<AuthorKeyRotation> = Vec::new();

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
                    // `governance_ban_subscriber` ALWAYS records the durable ban
                    // AND rotates every author's broadcast key (forward secrecy,
                    // §9.5 / #2088), whether or not the DID is a current subscriber
                    // — a non-subscriber returns `Ok` with a NON-empty rotation set.
                    // The `MemberNotFound` arm now covers only the internal
                    // author-not-found safety net (unreachable in practice).
                    match bc.governance_ban_subscriber(&did.0, access) {
                        Ok(r) => {
                            rotated_authors = r.rotated_authors;
                        }
                        Err(ContextError::MemberNotFound(_)) => {}
                        Err(e) => return Err(e),
                    }
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

            Ok((rotated_authors, needs_sender_key_rotation))
        })
        .await?;

    let access_revoked_payload =
        scp_event_log::payload::encode_payload(&scp_event_log::payload::AccessRevokedPayload {
            target_did: did.as_ref().to_owned(),
        })
        .map_err(|e| ContextError::EventLogFailed(e.to_string()))?;
    deps.event_log
        .append_context_event_with_payload(
            &context_id_bytes,
            scp_event_log::EventType::AccessRevoked,
            actor_did,
            access_revoked_payload,
            timestamp_secs,
        )
        .await?;
    // Class-C counter bump for the AccessRevoked leaf, inline immediately after
    // its `?`-append. The counter must track the true durable-leaf count
    // (governance_logic.rs:156-158) to prevent §9.9.3 checkpoint-position drift.
    *cell.class_c_view().checkpoint_events_since_mut() += 1;

    // §5.14.10: one KeyEpochAdvance leaf per author whose broadcast key was
    // rotated by the governance ban. Each rotation advances by exactly 1, so
    // old_epoch = new_epoch.saturating_sub(1).
    //
    // DURABILITY-SIGNALLING, NOT FAIL-ATOMIC. `?`-propagating an append failure
    // rolls nothing back: by the time this loop runs, the ban and the key
    // rotation are already durably persisted (the fail-closed
    // `commit_class_s_keep` above) and the `AccessRevoked` anchor leaf is
    // already appended. A failure on leaf k of n returns `Err` while leaving
    // leaves 0..k durable and leaves k..n absent, with no repair path. What `?`
    // buys over the previous warn-and-continue is that the failure reaches the
    // caller instead of being swallowed, giving operators a concrete error
    // signal that the log is short some leaves — the same rationale as the
    // GovernanceDeadlockRecovery companion leaf in
    // `execute_reconfigure_governance`.
    //
    // The counter is bumped INLINE after each successful append, never
    // coalesced at the end, so the leaves that did land are still credited when
    // a later one fails.
    //
    // Aborting here cannot skip the H7 sender-key rotation below: `rotated_authors`
    // is non-empty only for a broadcast context, and `needs_sender_key_rotation`
    // requires `broadcast_context.is_none()` — the two are mutually exclusive.
    for rotation in &rotated_authors {
        let old_epoch = rotation.new_epoch.saturating_sub(1);
        let payload = scp_event_log::payload::encode_payload(
            &scp_event_log::payload::KeyEpochAdvancePayload {
                old_epoch,
                new_epoch: rotation.new_epoch,
            },
        )
        .map_err(|e| ContextError::EventLogFailed(e.to_string()))?;
        deps.event_log
            .append_context_event_with_payload(
                &context_id_bytes,
                scp_event_log::EventType::KeyEpochAdvance,
                rotation.author_did.as_str(),
                payload,
                timestamp_secs,
            )
            .await?;
        *cell.class_c_view().checkpoint_events_since_mut() += 1;
    }

    // H7: Rotate sender key after write-side revocation.
    if needs_sender_key_rotation {
        // ADR-049 PR-7: Class-S — the epoch bump is sync-persisted fail-closed via
        // `commit_class_s_keep`; anti-replay backstop is the never-regressing
        // registry floor (`mirror_forward`, `?`-propagated). M23: sender-key
        // rotation + distribution stays best-effort (rotate/persist failure logged,
        // revocation continues — the write-side capability strip above is the hard
        // boundary).
        let local_did = deps.crypto.local_did().to_owned();
        match cell
            .commit_class_s_keep(deps, context_id, |mut v| {
                let s = v.rest_mut();
                s.rotate_sender_key(&local_did)?;
                Ok(s.local_sender_key_epoch())
            })
            .await
        {
            Ok(epoch) => {
                // ADR-049 PR-6/PR-7: advance the durably-bumped local epoch in the
                // authoritative floor registry (fail-closed backstop).
                crate::context::messaging_helpers::mirror_forward_local_sender_epoch(
                    deps,
                    &context_id_bytes,
                    epoch,
                )?;
            }
            Err(e) => {
                tracing::warn!(
                    context_id = %context_id,
                    error = %e,
                    "rotate_sender_key failed after access revocation"
                );
            }
        }
        // Drain through the actor's crypto state (same one the rotation populated).
        {
            let mut view = cell.class_c_view();
            if let Err(e) = crate::context::lifecycle_helpers::drain_and_deliver_sender_keys(
                deps,
                view.mode_mut().crypto_mut(),
                context_id,
            )
            .await
            {
                tracing::warn!(
                    context_id = %context_id,
                    error = %e,
                    "drain_and_deliver_sender_keys failed after access revocation"
                );
            }
        }
    }

    Ok(rotated_authors.len())
}

// ---------------------------------------------------------------------------
// execute_restore_access (per-action leaf helper)
// ---------------------------------------------------------------------------

/// Executes a `RestoreAccess` governance action.
pub async fn execute_restore_access(
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
    // as the prior early returns did. Broadcast block-list state now rides the
    // Class-S `ContextSnapshot`, so the combinator's fail-closed persist covers the
    // governance-unban block-list REMOVE atomically — the prior trailing
    // best-effort `persist_broadcast_snapshot` is gone. The post-persist external
    // work (event-log append, coalesced `checkpoint_events_since` bump) is
    // unchanged.
    cell.commit_class_s_keep(deps, context_id, |mut view| {
        let state = view.rest_mut();
        require_active(&state.handle)?;

        if !state.role_state.ceiling().contains(&Capability::MemberBan) {
            return Err(ContextError::PermissionDenied(
                "member:ban (MemberBan) capability not in ceiling".to_owned(),
            ));
        }

        let suspended_set = state.role_state.suspended_for(did.as_ref());
        let nothing_suspended_for_request =
            suspended_set.is_none_or(|set| !capabilities.iter().any(|c| set.contains(c)));
        let read_excluded = state.access.read_exclusion_list.contains(did);
        let read_requested = capabilities.contains(&Capability::MessagesRead);
        // #2088 Finding 2: a durable broadcast ban is a restorable condition too.
        // BOTH `suspended_capabilities` and `read_exclusion_list` are wiped by the
        // banned subject's own self-leave (`leave_context` clears role suspension
        // and the exclusion entry) — but the durable `banned_subscribers` record
        // survives it by design. Without this, `RestoreAccess{MessagesRead}` after
        // a leave would short-circuit `NothingToRestore` and never reach
        // `governance_unban_subscriber`, leaving the DID PERMANENTLY banned with no
        // authority recovery — falsifying the "cleared ONLY by RestoreAccess"
        // invariant. Treat an outstanding durable ban as a read-restorable signal.
        let durably_banned = state
            .broadcast_context
            .as_ref()
            .is_some_and(|bc| bc.is_banned(did.as_ref()));
        if nothing_suspended_for_request && !(read_requested && (read_excluded || durably_banned)) {
            return Err(ContextError::NothingToRestore(format!(
                "no suspended capabilities to restore for {did}"
            )));
        }

        state
            .role_state
            .restore_capabilities(did.as_ref(), capabilities);

        let has_read = capabilities.contains(&Capability::MessagesRead);
        if has_read {
            state.access.read_exclusion_list.remove(did);

            if let Some(bc) = state.broadcast_context.as_mut() {
                bc.governance_unban_subscriber(&did.0);
            }

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
        }

        if capabilities.contains(&Capability::MessagesWrite) {
            emit(
                state,
                ContextEvent::WriteAccessRestored { did: did.clone() },
                context_id,
                deps,
            );
        }

        Ok(())
    })
    .await?;

    deps.event_log
        .append_context_event(
            &context_id_bytes,
            scp_event_log::EventType::AccessRestored,
            actor_did,
            timestamp_secs,
        )
        .await?;
    // Coalesced Class-C counter bump (rides the next run-loop persist).
    *cell.class_c_view().checkpoint_events_since_mut() += 1;

    Ok(())
}

// ---------------------------------------------------------------------------
// execute_add_member (per-action leaf helper)
// ---------------------------------------------------------------------------

#[allow(clippy::too_many_lines)]
pub async fn execute_add_member(
    cell: &mut crate::context::actor::class_s::ClassSCell,
    deps: &ActorDeps,
    context_id: &str,
    did: &DID,
    role: &str,
    // The invitee's TLS-serialized MLS `KeyPackage`, carried on the actor
    // command envelope by the invitation-sealing caller
    // ([`crate::context::supervisor::Supervisor::invite_member`]) and threaded
    // through the governance dispatch to here. `Some(..)` on the real
    // invitation path; `None` on the paths that never carried a real add
    // (the generic FFI `AddMember` arm and `execute_reset_member` — issue
    // #2029), where production `add_member` errors and `cfg(test)`/`testing`
    // returns an empty `AddMemberOutput` (preserving the non-crypto pipeline).
    key_package: Option<&[u8]>,
    meta: CommitMeta<'_>,
) -> Result<scp_protocol::context::builder::AddMemberOutput, ContextError> {
    let CommitMeta {
        pid: _,
        actor_did,
        timestamp_secs,
    } = meta;
    let context_id_bytes = context_id_to_bytes(context_id);

    require_active(&cell.handle)?;

    // Bind the supplied KeyPackage to the target DID BEFORE the add: the KP's
    // MLS credential DID MUST equal `did`, or a caller could add a member under
    // one DID using a KeyPackage minted for a different identity. Under
    // `cfg(test)`/`testing` with `None` this is a no-op (matches the mock
    // fixture); in production a mismatched or malformed KP is rejected here.
    //
    // ADR-049 §15 / SCP-CRYPTOMOVE-000c: the stateless validation routes through
    // the stateless `MlsBackend` (`deps.mls`) — the provider `validate_key_package`
    // copy is retired from the production call path (§15 grants no carve-out; the
    // symbol is retained only as a test-exercised copy at `crypto/mls/provider.rs`).
    // `validate_key_package` runs the full validation (signature / hardened-clock
    // lifetime / ciphersuite) ONCE and returns the authenticated `credential_did`
    // extracted from the same validated leaf, so the DID binding is preserved
    // here as a single validate-and-bind under the same hardened clock the MLS
    // add uses — no second parse or re-validation.
    match key_package {
        Some(bytes) => {
            let validated = deps
                .mls
                .validate_key_package(bytes, deps.clock.as_ref())
                .await
                .map_err(|e| ContextError::MembershipFailed(e.to_string()))?;
            let owner_did: &str = did.as_ref();
            if validated.credential_did.as_str() != owner_did {
                return Err(ContextError::MembershipFailed(
                    "key package credential DID does not match target DID".to_string(),
                ));
            }
        }
        None => {
            if !cfg!(any(test, feature = "testing")) {
                return Err(ContextError::MembershipFailed(
                    "production add_member requires MLS key package bytes".to_string(),
                ));
            }
        }
    }

    // The invitee's KeyPackage is carried on the command envelope (`Some` on
    // the invitation path). Under `cfg(test)`/`testing` with `None` the actor
    // returns an empty `AddMemberOutput`, preserving the non-crypto pipeline
    // tests. This is what makes `GovernanceAction::AddMember` do a REAL MLS add
    // in production (§5.12.3) rather than erroring on a missing KP.
    //
    // ADR-049 PR-7 (SCP-CRYPTOMOVE-001): the MLS add runs on the ACTOR-OWNED
    // crypto (`PerContextState::add_member`), not the provider — after the
    // create/welcome take, `deps.crypto.add_member` fails closed
    // ("context state owned by actor"). `add_member` is §9 Class-S (the epoch
    // bump is durably persisted fail-closed before ack), reached only through
    // `rest_mut()` inside `commit_class_s_keep`, mirroring the `join_context`
    // add path. On add failure NO MLS rollback is needed (no member was added),
    // matching the prior provider disposition; the error propagates unchanged.
    let add_output = cell
        .commit_class_s_keep(deps, context_id, |mut v| {
            v.rest_mut()
                .add_member(did.as_ref(), key_package, deps.clock.as_ref())
                .map_err(|e| ContextError::MembershipFailed(e.to_string()))
        })
        .await?;

    // Clone the Welcome + Commit for the return value (the invitation-sealing
    // caller needs the Welcome to seal the bundle; the Commit is surfaced for
    // observability) and for the existing-member broadcast below, BEFORE the
    // originals are moved into the `WelcomeGenerated` emit.
    let welcome_bytes_out = add_output.welcome_bytes.clone();
    let commit_bytes_out = add_output.commit_bytes.clone();
    let commit_for_broadcast = add_output.commit_bytes.clone();

    // ADR-049 PR-7 (SCP-CRYPTOMOVE-001) — join-time sender-key PUSH. Enqueue the
    // inviter's CURRENT sender key for the newly-added member, mirroring the
    // `join_context` add path (`lifecycle_helpers`, §9.16.2). The deleted provider
    // `distribute_sender_key` used to do this on the invitation path; here we run
    // its actor replacement on the actor-OWNED crypto: `distribute_sender_key`
    // HPKE-seals the local sender key to the member's wrapping pubkey (extracted
    // from the just-added KeyPackage's 0xFF01 leaf) and queues it onto
    // `pending_distributions`; the async `drain_and_deliver_sender_keys` below
    // MLS-wraps + delivers it over the management channel. Class-S — the enqueue
    // touches the same actor crypto the add advanced, reached only through
    // `rest_mut()` inside `commit_class_s_keep` (parity with the join add path).
    // Best-effort disposition (M23, parity with the remove/revoke governance
    // paths): a failure is warned and the add proceeds — the new member recovers
    // the key via `SenderKeyRequest`. Gated on a non-empty Welcome so the
    // `cfg(test)`/`testing` no-crypto pipeline (empty `AddMemberOutput`, no MLS
    // group) skips it exactly as the broadcast + `WelcomeGenerated` emit below do.
    let local_did = deps.crypto.local_did().to_owned();
    if !welcome_bytes_out.is_empty()
        && let Err(e) = cell
            .commit_class_s_keep(deps, context_id, |mut v| {
                v.rest_mut().distribute_sender_key(&local_did, did.as_ref())
            })
            .await
    {
        tracing::warn!(
            context_id = %context_id,
            member_did = %did,
            error = %e,
            "distribute_sender_key failed after member add — new member will \
             recover via SenderKeyRequest"
        );
    }

    // The fallible role assignment + structural member insert run through the
    // field-granular Class-C role view (ADR-049 §9): `system_assign_role` mints +
    // inserts assignments / member_capabilities and runs the SHRINK-only suspension
    // prune over the view's own disjoint fields — no whole `&mut ContextRoleState`,
    // no downward-auth GROW. It runs in a NON-PERSISTING Class-C view borrow (the
    // run-loop / the best-effort persist below covers it): this site is best-effort
    // BY DESIGN — member ADD is coalesce-window-rollback acceptable (ADR-049 §9), so
    // the suspension prune rides the SAME best-effort persist it always did. It is
    // NOT strengthened to fail-closed.
    let tokens = {
        let mut view = cell.class_c_view();
        let mut role_state = view.role_state_class_c_mut();
        role_state.members_mut().insert(did.to_string());
        role_state
            .system_assign_role(did, role, &*deps.clock)
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
    })
    .await;

    // ROOT FIX (parity with `execute_remove_member` / `execute_reset_member`):
    // broadcast the MLS Commit to the EXISTING members. An MLS Add advances the
    // group epoch exactly like a Remove, so without this the add's Commit was only
    // buffered into the (broadcast-suppressed) `WelcomeGenerated` event and NEVER
    // reached the group — every existing member desynced from the admin after any
    // add. Routed through the same persistent retry queue (`try_broadcast_commit`
    // + `apply_broadcast_failure`) as the remove/reset commits. A no-op when
    // `commit_for_broadcast` is empty (the `cfg(test)` no-crypto pipeline).
    //
    // Hoisted AFTER the best-effort persist above (ADR-049 Decision 7 — transport
    // is async and cannot be awaited inside the sync closure). The broadcast is
    // async; on failure the retry-queue bookkeeping is applied Class-C (coalesced
    // — picked up by the actor's persist tick), which is this add's correct class
    // (member-add is not a downward-authorization transition — parity with the
    // pre-async `commit_class_c_best_effort` shape).
    if !commit_for_broadcast.is_empty()
        && let Some(failure) = try_broadcast_commit(
            deps,
            context_id,
            commit_for_broadcast,
            &CommitOperation::AddMember {
                target_did: did.clone(),
            },
        )
        .await
    {
        apply_broadcast_failure(
            cell.class_c_view().commit_broadcast_borrows(),
            deps,
            context_id,
            failure,
        );
    }

    // ADR-049 PR-7: deliver the queued join-time sender-key distribution to the
    // newly-added member over the MLS management channel (§9.16.2). Drains the
    // actor-owned `pending_distributions` the `distribute_sender_key` above
    // populated (same crypto state), MLS-wraps each entry, and sends it — the
    // MLS-wrap is mandatory (see `drain_and_deliver_sender_keys`). Runs AFTER the
    // best-effort persist (transport is async — ADR-049 Decision 7), matching the
    // remove/revoke drain call sites. Best-effort: a per-target send failure is
    // warned; the member recovers via `SenderKeyRequest`. `&mut` view scoped so
    // `cell` is free afterward. No-op on the `cfg(test)` no-crypto pipeline (the
    // queue is empty — `distribute_sender_key` was skipped above).
    {
        let mut view = cell.class_c_view();
        if let Err(e) = crate::context::lifecycle_helpers::drain_and_deliver_sender_keys(
            deps,
            view.mode_mut().crypto_mut(),
            context_id,
        )
        .await
        {
            tracing::warn!(
                context_id = %context_id,
                member_did = %did,
                error = %e,
                "failed to deliver join-time sender key after member add"
            );
        }
    }

    // Subject-bearing leaf (ADR-011 amendment): carry the *affected member*
    // (`did`) in the payload, not just `actor_did` (which on this admin-driven
    // add is the executing admin). Participation `participation_duration_secs`
    // (§7.3.2) attributes the join interval to this subject.
    deps.event_log
        .append_membership_change_leaf(
            &context_id_bytes,
            scp_event_log::EventType::MemberJoined,
            actor_did,
            did.as_ref(),
            role,
            timestamp_secs,
        )
        .await?;
    *cell.class_c_view().checkpoint_events_since_mut() += 1;
    Ok(scp_protocol::context::builder::AddMemberOutput {
        welcome_bytes: welcome_bytes_out,
        commit_bytes: commit_bytes_out,
    })
}

// ---------------------------------------------------------------------------
// execute_remove_member (per-action leaf helper)
// ---------------------------------------------------------------------------

#[allow(clippy::too_many_lines)]
pub async fn execute_remove_member(
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
    let (removed_role_name, remove_commit_bytes) = cell
        .commit_class_s_keep(deps, context_id, |mut view| {
            let state = view.rest_mut();

            require_active(&state.handle)?;

            if !state.membership.contains(did) {
                return Err(ContextError::MemberNotFound(did.to_string()));
            }

            // Role at departure, captured BEFORE the strip below for the
            // subject-bearing MemberLeft leaf (ADR-011 amendment; §7.3.2).
            let removed_role_name = state
                .membership
                .get(did.as_ref())
                .map_or_else(String::new, |info| info.role_name.clone());

            // H9: MLS group removal FIRST (hard security boundary). ADR-049 PR-7:
            // the whole in-closure crypto orchestration (MLS remove, per-member
            // sender-key prune, sender-key rotation) is driven on the actor's
            // `state` — all riding this ONE `commit_class_s_keep` fail-closed
            // persist (Class-S), so the epoch bump is durable. `local_did` is
            // sourced from the retained `deps.crypto.local_did()`.
            let remove_output = state
                .remove_member(deps.crypto.local_did(), did.as_ref())
                .map_err(|e| ContextError::MembershipFailed(e.to_string()))?;

            if let Err(e) = state.remove_member_sender_key(did.as_ref()) {
                return fail_close_remove_member(
                    state,
                    deps,
                    context_id,
                    did,
                    "remove_member_sender_key",
                    &e.to_string(),
                )
                .map(|()| (String::new(), None));
            }
            // ADR-049 PR-6: prune the departed member's Class-M registry floors
            // (member-granular; siblings + the local scalar retained). See
            // `Supervisor::remove_member_floors` for why no membership sweep.
            deps.supervisor
                .remove_member_floors(&context_id_bytes, did.as_ref());

            if let Err(e) = state.rotate_sender_key(deps.crypto.local_did()) {
                return fail_close_remove_member(
                    state,
                    deps,
                    context_id,
                    did,
                    "rotate_sender_key",
                    &e.to_string(),
                )
                .map(|()| (String::new(), None));
            }
            // ADR-049 PR-6/PR-7: rotate succeeded (the Err arm returns above) —
            // advance the durably-bumped local epoch (read from the actor `state`,
            // which the rotate above advanced) in the authoritative floor registry
            // (fail-closed anti-replay backstop). Read-authority follows
            // write-authority.
            crate::context::messaging_helpers::mirror_forward_local_sender_epoch(
                deps,
                &context_id_bytes,
                state.local_sender_key_epoch(),
            )?;

            state.membership.remove_member(did);
            // Clean teardown of ALL per-DID role state (spec §5.6.1): members,
            // assignments, member_capabilities, AND suspended_capabilities. Replaces
            // the prior strip that left the removed DID's suspension dangling, so a
            // re-admitted same-DID member no longer inherits a phantom suspension.
            // Inside `commit_class_s_keep`, so the downward-auth suspension drop
            // persists fail-closed (ADR-049 §9).
            state.role_state.remove_member(did.as_ref());

            state
                .access
                .access_key_store
                .remove(context_id, did.as_ref());

            // Drop the removed member's CEK-exclusion entry (spec §5.6.1, §9.17) —
            // per-DID content-access state outside the role state. Mirrors
            // `execute_restore_access`. Without this, a re-admitted same-DID member
            // would inherit a phantom read exclusion.
            state.access.read_exclusion_list.remove(did);

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

            // Capture the removal Commit bytes; the ASYNC broadcast + sender-key
            // delivery run AFTER the fail-closed persist, outside this sync
            // `_keep` closure (ADR-049 Decision 7 — transport is async). `None`
            // on the fail-close paths above, which skip the broadcast/drain
            // exactly as the pre-hoist early returns did.
            Ok((removed_role_name, Some(remove_output.commit_bytes)))
        })
        .await?;

    // Async transport ops AFTER the Class-S removal persist (ADR-049 Decision 7:
    // `ContextTransportProvider` is async and cannot be awaited inside the sync
    // `_keep` closure above). The membership removal is already
    // fail-closed-persisted; the sender-key delivery is best-effort.
    // `remove_commit_bytes` is `Some` only on the success path (the fail-close
    // paths return `None` and skip both, matching pre-hoist ordering); it is the
    // removal Commit already produced under the crypto `Arc` (Class-M) inside the
    // closure.
    if let Some(remove_commit_bytes) = remove_commit_bytes {
        // Broadcast async (Decision 7); on FAILURE the retry-queue bookkeeping is
        // persisted FAIL-CLOSED via `keep_broadcast_failure` (removal Commit is a
        // safety-gated site — see that helper's doc for why the second persist).
        if let Some(failure) = try_broadcast_commit(
            deps,
            context_id,
            remove_commit_bytes,
            &CommitOperation::RemoveMember {
                target_did: did.clone(),
            },
        )
        .await
        {
            keep_broadcast_failure(cell, deps, context_id, failure).await?;
        }

        // ADR-049 PR-7: drain through the actor's crypto state (same one the
        // in-closure `rotate_sender_key` above populated); `&mut` view scoped so
        // `cell` is free afterward.
        {
            let mut view = cell.class_c_view();
            if let Err(e) = crate::context::lifecycle_helpers::drain_and_deliver_sender_keys(
                deps,
                view.mode_mut().crypto_mut(),
                context_id,
            )
            .await
            {
                tracing::warn!(
                    context_id = %context_id,
                    error = %e,
                    "failed to deliver rotated sender keys after member removal"
                );
            }
        }
    }

    // Subject-bearing leaf (ADR-011 amendment): carry the *affected member*
    // (`did`) and the role it held at departure, not just `actor_did` (the
    // executing admin). Participation `participation_duration_secs` (§7.3.2)
    // attributes the leave interval to this subject.
    deps.event_log
        .append_membership_change_leaf(
            &context_id_bytes,
            scp_event_log::EventType::MemberLeft,
            actor_did,
            did.as_ref(),
            &removed_role_name,
            timestamp_secs,
        )
        .await?;
    *cell.class_c_view().checkpoint_events_since_mut() += 1;
    Ok(())
}

// ---------------------------------------------------------------------------
// execute_change_role (per-action leaf helper)
// ---------------------------------------------------------------------------

pub async fn execute_change_role(
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
    })
    .await?;
    // Subject-bearing leaf (ADR-011 amendment): carry the *affected member*
    // (`did`) and the newly-assigned role, not just `actor_did` (which on this
    // admin-driven change is the executing admin). Participation
    // `role_progression_count` (§7.3.2) attributes the role transition to this
    // subject.
    deps.event_log
        .append_role_assigned_leaf(
            &context_id_bytes,
            actor_did,
            did.as_ref(),
            new_role,
            timestamp_secs,
        )
        .await?;
    *cell.class_c_view().checkpoint_events_since_mut() += 1;
    Ok(())
}

// ---------------------------------------------------------------------------
// execute_register_outlet (per-action leaf helper)
// ---------------------------------------------------------------------------

pub async fn execute_register_outlet(
    cell: &mut crate::context::actor::class_s::ClassSCell,
    deps: &ActorDeps,
    context_id: &str,
    registration: &OutletRegistration,
    meta: CommitMeta<'_>,
) -> Result<(), ContextError> {
    let CommitMeta {
        pid: _,
        actor_did,
        timestamp_secs,
    } = meta;
    let context_id_bytes = context_id_to_bytes(context_id);

    // Outlet registration is an UPWARD grant (Class-C governance config). The
    // fallible guards read through the cell's `Deref` (no mutation); the
    // `registered_outlets` push (Class-C) rides `commit_class_c_best_effort`,
    // preserving the prior best-effort persist exactly.
    require_active(&cell.handle)?;

    if !cell
        .role_state
        .ceiling()
        .contains(&Capability::OutletRegister)
    {
        return Err(ContextError::PermissionDenied(
            "context ceiling does not include outlet registration capability".into(),
        ));
    }

    if cell.governance.registered_outlets.len() >= MAX_REGISTERED_OUTLETS {
        return Err(ContextError::LimitExceeded(format!(
            "registered outlet limit of {MAX_REGISTERED_OUTLETS} exceeded"
        )));
    }
    cell.commit_class_c_best_effort(deps, context_id, |mut view| {
        view.governance_class_c_mut()
            .registered_outlets_mut()
            .push(registration.clone());
    })
    .await;
    deps.event_log
        .append_context_event(
            &context_id_bytes,
            scp_event_log::EventType::OutletRegistered,
            actor_did,
            timestamp_secs,
        )
        .await?;
    *cell.class_c_view().checkpoint_events_since_mut() += 1;
    Ok(())
}

// ---------------------------------------------------------------------------
// execute_remove_outlet (per-action leaf helper)
// ---------------------------------------------------------------------------

pub async fn execute_remove_outlet(
    cell: &mut crate::context::actor::class_s::ClassSCell,
    deps: &ActorDeps,
    context_id: &str,
    outlet_id: &str,
    meta: CommitMeta<'_>,
) -> Result<(), ContextError> {
    let CommitMeta {
        pid: _,
        actor_did,
        timestamp_secs,
    } = meta;
    let context_id_bytes = context_id_to_bytes(context_id);

    // ADR-049 §9 Class S: removing a registered outlet revokes the authority to
    // invoke it — a downward-authorization transition (the inverse of
    // `execute_register_outlet`'s upward grant). Route through `commit_class_s_keep`
    // so the removal persists fail-closed (keep-direction: on persist failure the
    // outlet STAYS removed — re-granting invocation of a outlet the caller was told
    // was removed is the unsafe direction). The reject-before-mutate guard
    // returns `Err` from inside the closure (no persist runs); the
    // `registered_outlets` retain (Class-C) rides the SAME fail-closed persist via
    // `view.rest_mut()`.
    cell.commit_class_s_keep(deps, context_id, |mut view| {
        require_active(&view.handle)?;

        view.rest_mut()
            .governance
            .registered_outlets
            .retain(|t| t.outlet_id != outlet_id);
        Ok(())
    })
    .await?;
    deps.event_log
        .append_context_event(
            &context_id_bytes,
            scp_event_log::EventType::OutletRemoved,
            actor_did,
            timestamp_secs,
        )
        .await?;
    *cell.class_c_view().checkpoint_events_since_mut() += 1;
    Ok(())
}

// ---------------------------------------------------------------------------
// execute_modify_ceiling (per-action leaf helper)
// ---------------------------------------------------------------------------

pub async fn execute_modify_ceiling(
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

        // Ceiling-entry grammar enforcement at PROPOSE/STAGE time (spec §5.3.1.1).
        // Validate every proposed ceiling entry BEFORE staging it into
        // `pending_ceiling_modification`, so a malformed proposal fails fast —
        // rather than only at apply time, after the §5.3.2 notification window has
        // elapsed. This is a reject-before-mutate guard: it returns `Err` from
        // inside the `commit_class_s_keep` closure before any state is written, so
        // no persist runs and the prior ceiling/pending state is untouched
        // (fail-closed). The `set_ceiling` invariant at apply time
        // (`apply_pending_ceiling_modification`) is the construction backstop; this
        // is the fast-fail front door.
        for cap in new_ceiling {
            cap.validate_as_ceiling_entry().map_err(|e| {
                ContextError::InvalidState(format!(
                    "proposed ceiling entry is malformed (spec §5.3.1.1): {e}"
                ))
            })?;
        }

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
    })
    .await?;
    deps.event_log
        .append_context_event(
            &context_id_bytes,
            scp_event_log::EventType::CeilingModificationPending,
            actor_did,
            timestamp_secs,
        )
        .await?;
    *cell.class_c_view().checkpoint_events_since_mut() += 1;
    Ok(())
}

// ---------------------------------------------------------------------------
// execute_close_context (per-action leaf helper)
// ---------------------------------------------------------------------------

// ADR-049 §Decision 12: `state`/`transition_to` are now synchronous lock-free
// ArcSwap ops. Async is retained as the ContextManager helper API contract —
// callers await uniformly, and provider-trait calls regain await points under
// ADR-049 Decision 7 (async-provider-trait conversion).
#[allow(clippy::unused_async)]
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
        .map_err(|_| ContextError::PermissionDenied("cannot transition to Closing".to_owned()))?;

    // ADR-049 §9 Class S: the lifecycle close transition is security-critical
    // (a closed context must not silently re-open on a crash) — route the in-
    // state cleanup through `commit_class_s_keep` so it persists fail-closed
    // (keep-direction: on persist failure the close STAYS — silently re-opening a
    // closed context is the unsafe direction). The timer/broadcast/participation
    // cleanup (Class-C) rides the fail-closed persist via `view.rest_mut()`.
    cell.commit_class_s_keep(deps, context_id, |mut view| {
        let state = view.rest_mut();
        // TTL + governance timers are actor-owned arms (ADR-049 finding A3):
        // this close leaves the context non-Active so `reconcile_timers`
        // clears the governance interval and disarms the TTL arm. Clear the
        // recorded TTL deadline HERE (durably, in the fail-closed snapshot) so a
        // stale absolute deadline cannot fire against the closed context on a
        // later restore and despawn it (BUG-1) — mirroring
        // `execute_promote_context`.
        state.ttl.timer.deadline_unix_secs = None;
        state.broadcast_context = None;
        state.governance.decay_participation();
        Ok(())
    })
    .await?;
    deps.event_log
        .append_context_event(
            &context_id_bytes,
            scp_event_log::EventType::ContextClosing,
            actor_did,
            timestamp_secs,
        )
        .await?;
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
        deps.event_log
            .append_context_event_with_payload(
                &context_id_bytes,
                scp_event_log::EventType::TtlExtensionRejected,
                actor_did,
                rejected_payload,
                timestamp_secs,
            )
            .await?;
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

    // Leaf-atomic TTL extension (ADR-049 §9, B3): raise the log-derived
    // convergent deadline by `additional_secs`, mutate the recorded (actor-owned,
    // §A3) timer AND append the matching `TtlExtended` leaf from the SAME
    // resolved value, via the shared `extend_ttl_deadline_and_record` combinator
    // (also used by the bilateral `reset_ttl_timer` path) so a deadline mutation
    // can never drift from its convergent leaf. The combinator derives the
    // current deadline from the single authoritative source (the log), extends
    // it (`old_deadline + additional_secs`, convergent across members), and
    // stamps the leaf with the committer-assigned `timestamp_secs`
    // (`proposal.created_at`). A context whose log yields no convergent deadline
    // has no TTL to extend ⇒ no-op, no leaf. The append is best-effort/fail-safe
    // (a lost leaf re-derives the shorter un-extended base on restore).
    crate::context::ttl_close_helpers::extend_ttl_deadline_and_record(
        cell,
        deps.event_log.as_ref(),
        &context_id_bytes,
        actor_did,
        additional_secs,
        crate::context::ttl_close_helpers::ExtensionLeaf::Governance {
            proposal_id,
            committer_timestamp_secs: timestamp_secs,
            consenting_members: consenting,
        },
    )
    .await;

    crate::context::messaging_helpers::persist_state_best_effort(&*cell, deps, context_id).await;
    *cell.class_c_view().checkpoint_events_since_mut() += 1;
    Ok(())
}

// ---------------------------------------------------------------------------
// execute_transfer_admin (per-action leaf helper)
// ---------------------------------------------------------------------------

pub async fn execute_transfer_admin(
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
    })
    .await?;
    deps.event_log
        .append_context_event(
            &context_id_bytes,
            scp_event_log::EventType::AdminTransferred,
            actor_did,
            timestamp_secs,
        )
        .await?;
    *cell.class_c_view().checkpoint_events_since_mut() += 1;
    Ok(())
}

// ---------------------------------------------------------------------------
// execute_create_child_context (per-action leaf helper)
// ---------------------------------------------------------------------------

pub async fn execute_create_child_context(
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
        .ceiling()
        .contains(&Capability::ChildContextCreate)
    {
        return Err(ContextError::PermissionDenied(
            "context ceiling does not include child context creation capability".into(),
        ));
    }

    deps.event_log
        .append_context_event(
            &context_id_bytes,
            scp_event_log::EventType::ChildContextCreated,
            actor_did,
            timestamp_secs,
        )
        .await?;
    *cell.class_c_view().checkpoint_events_since_mut() += 1;
    Ok(())
}

// ---------------------------------------------------------------------------
// execute_modify_pruning_policy (per-action leaf helper)
// ---------------------------------------------------------------------------

pub async fn execute_modify_pruning_policy(
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
    })
    .await;
    deps.event_log
        .append_context_event(
            &context_id_bytes,
            scp_event_log::EventType::PruningPolicyModified,
            actor_did,
            timestamp_secs,
        )
        .await?;
    *cell.class_c_view().checkpoint_events_since_mut() += 1;
    Ok(())
}

// ---------------------------------------------------------------------------
// execute_add_signer (per-action leaf helper)
// ---------------------------------------------------------------------------

pub async fn execute_add_signer(
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
    })
    .await?;
    deps.event_log
        .append_context_event(
            &context_id_bytes,
            scp_event_log::EventType::SignerAdded,
            actor_did,
            timestamp_secs,
        )
        .await?;
    *cell.class_c_view().checkpoint_events_since_mut() += 1;
    Ok(())
}

// ---------------------------------------------------------------------------
// execute_remove_signer (per-action leaf helper)
// ---------------------------------------------------------------------------

pub async fn execute_remove_signer(
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
    })
    .await?;
    deps.event_log
        .append_context_event(
            &context_id_bytes,
            scp_event_log::EventType::SignerRemoved,
            actor_did,
            timestamp_secs,
        )
        .await?;
    *cell.class_c_view().checkpoint_events_since_mut() += 1;
    Ok(())
}

// ---------------------------------------------------------------------------
// execute_modify_threshold (per-action leaf helper)
// ---------------------------------------------------------------------------

pub async fn execute_modify_threshold(
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
    })
    .await?;
    deps.event_log
        .append_context_event(
            &context_id_bytes,
            scp_event_log::EventType::ThresholdModified,
            actor_did,
            timestamp_secs,
        )
        .await?;
    *cell.class_c_view().checkpoint_events_since_mut() += 1;
    Ok(())
}

// ---------------------------------------------------------------------------
// execute_establish_outlet_interface (per-action leaf helper)
// ---------------------------------------------------------------------------

pub async fn execute_establish_outlet_interface(
    cell: &mut crate::context::actor::class_s::ClassSCell,
    deps: &ActorDeps,
    context_id: &str,
    interface: &OutletInterface,
    meta: CommitMeta<'_>,
) -> Result<(), ContextError> {
    let CommitMeta {
        pid: _,
        actor_did,
        timestamp_secs,
    } = meta;
    let context_id_bytes = context_id_to_bytes(context_id);

    // Establishing a outlet interface is Class-C governance config. The fallible
    // guards read through the cell's `Deref`; the `outlet_interfaces` push
    // (Class-C) rides `commit_class_c_best_effort`, preserving the prior
    // best-effort persist exactly.
    require_active(&cell.handle)?;

    if !cell
        .role_state
        .ceiling()
        .contains(&Capability::OutletInterface)
    {
        return Err(ContextError::PermissionDenied(
            "context ceiling does not include outlet interface capability".into(),
        ));
    }

    if cell.governance.outlet_interfaces.len() >= MAX_OUTLET_INTERFACES {
        return Err(ContextError::LimitExceeded(format!(
            "outlet interface limit of {MAX_OUTLET_INTERFACES} exceeded"
        )));
    }
    cell.commit_class_c_best_effort(deps, context_id, |mut view| {
        view.governance_class_c_mut()
            .outlet_interfaces_mut()
            .push(interface.clone());
    })
    .await;
    deps.event_log
        .append_context_event(
            &context_id_bytes,
            scp_event_log::EventType::OutletInterfaceEstablished,
            actor_did,
            timestamp_secs,
        )
        .await?;
    *cell.class_c_view().checkpoint_events_since_mut() += 1;
    Ok(())
}

// ---------------------------------------------------------------------------
// execute_reset_member (per-action leaf helper)
// ---------------------------------------------------------------------------

#[allow(
    clippy::too_many_lines,
    reason = "single-pipeline member-reset orchestration (remove+add+broadcast+rotate+drain) with the detailed §9 residual-of-coalescing rationale inline"
)]
pub async fn execute_reset_member(
    cell: &mut crate::context::actor::class_s::ClassSCell,
    deps: &ActorDeps,
    context_id: &str,
    did: &DID,
    _reason: &str,
    meta: CommitMeta<'_>,
) -> Result<(), ContextError> {
    // ADR-049 PR-7 (SCP-CRYPTOMOVE-001): reset now takes the whole `ClassSCell`
    // (was a `ClassCMut` view) so the sender-key ROTATION can go through
    // `commit_class_s_keep`→`rest_mut` — §9 classifies rotation as Class-S (the
    // epoch bump must be durable), exactly as leave/revoke. The membership
    // remove+add and the broadcast/retry bookkeeping remain the coalesced Class-C
    // work they were (reset is a same-member key REFRESH, net-neutral on authority
    // — see the residual-of-coalescing note below); those reach their fields
    // through short-lived `cell.class_c_view()` borrows.
    let CommitMeta {
        pid: _,
        actor_did,
        timestamp_secs,
    } = meta;
    let context_id_bytes = context_id_to_bytes(context_id);

    {
        let mut view = cell.class_c_view();
        require_active(view.handle_mut())?;
        if !view.membership_class_c_mut().contains(did.as_ref()) {
            return Err(ContextError::MemberNotFound(did.to_string()));
        }
    }

    // Member reset = leave + immediately re-join (ADR-029 §Tier 3).
    // ADR-049 PR-7 (SCP-CRYPTOMOVE-001): the MLS group is actor-owned, so the
    // remove+add mutate the actor's OWNED group via `rest_mut()`. The whole
    // `&mut PerContextState` these MLS ops require is reachable ONLY through a
    // Class-S combinator (the coalesced Class-C view is field-granular by
    // construction and cannot hand out `rest_mut()`), so the net-neutral
    // remove+add pair is persisted fail-closed via `commit_class_s_keep` — a safe
    // over-persist versus the former provider path's coalesced write (reset is a
    // rare governance op, not the hot send path; the membership effect is
    // net-neutral, so nothing security-critical rides on the persist class). The
    // two commit-byte outputs drive the async broadcasts below. `local_did` is
    // node-resident (retained `deps.crypto.local_did()`), read once here and
    // reused by the rotation block below.
    let local_did = deps.crypto.local_did().to_owned();
    let (remove_output, add_output) = cell
        .commit_class_s_keep(deps, context_id, |mut v| {
            let s = v.rest_mut();
            let remove_output = s
                .remove_member(&local_did, did.as_ref())
                .map_err(|e| ContextError::MembershipFailed(e.to_string()))?;
            let add_output = s
                .add_member(did.as_ref(), None, deps.clock.as_ref())
                .map_err(|e| ContextError::MembershipFailed(e.to_string()))?;
            Ok((remove_output, add_output))
        })
        .await?;

    // Member reset operates on a coalesced `ClassCMut` view (best-effort). The
    // broadcasts are async; on failure the retry-queue bookkeeping is applied
    // through the same coalesced view (`view.commit_broadcast_borrows()`), so a
    // crash before the ≤50 ms persist tick can drop the `commit_fault`/retry
    // bookkeeping. RESIDUAL of coalescing here (be honest): a lost reset Commit
    // leaves remaining members on an epoch where the reset member's OLD
    // (rotated-out, possibly compromised) keys still decrypt until the Commit is
    // re-delivered — the same desync class the safety-gated sites fail-close
    // against. Coalesced is nonetheless the correct/defensible class for reset,
    // for three reasons: (1) reset is a same-member key REFRESH — the member is
    // removed and IMMEDIATELY re-added in the same operation and remains
    // authorized throughout, so it is net-neutral versus a true `RemoveMember`
    // (no authority is being withdrawn from anyone); (2) §9 classifies the
    // membership effect as Class-M, not a downward-authorization Class-S
    // transition, so it carries no §9 fail-closed obligation; and (3) it matches
    // the pre-async coalesced `ClassCMut` shape exactly — coalescing here is
    // parity, NOT a regression introduced by the async-transport hoist. (The
    // fail-closed sites — remove/rotate/leave/recovery — genuinely withdraw
    // authority or re-key away from a compromised party, which reset does not.)
    if let Some(failure) = try_broadcast_commit(
        deps,
        context_id,
        remove_output.commit_bytes,
        &CommitOperation::ResetMember {
            target_did: did.clone(),
            is_remove: true,
        },
    )
    .await
    {
        apply_broadcast_failure(
            cell.class_c_view().commit_broadcast_borrows(),
            deps,
            context_id,
            failure,
        );
    }
    if let Some(failure) = try_broadcast_commit(
        deps,
        context_id,
        add_output.commit_bytes,
        &CommitOperation::ResetMember {
            target_did: did.clone(),
            is_remove: false,
        },
    )
    .await
    {
        apply_broadcast_failure(
            cell.class_c_view().commit_broadcast_borrows(),
            deps,
            context_id,
            failure,
        );
    }

    // ADR-049 PR-7 (SCP-CRYPTOMOVE-001): remove the reset member's stale sender
    // key from the actor-owned store. Routed through `commit_class_s_keep` because
    // the sender-key store lives behind the whole-`&mut PerContextState` reachable
    // only via a Class-S combinator; the persist is fail-closed but the outcome is
    // swallowed to preserve the prior best-effort disposition (the anti-replay
    // backstop is the never-regressing registry floor pruned just below).
    if let Err(e) = cell
        .commit_class_s_keep(deps, context_id, |mut v| {
            v.rest_mut().remove_member_sender_key(did.as_ref())
        })
        .await
    {
        tracing::warn!(
            context_id,
            member = %did,
            error = %e,
            "remove_member_sender_key failed after MLS reset — \
             sender key layer may retain stale key"
        );
    }
    // ADR-049 PR-6: prune the departed member's Class-M registry floors
    // (member-granular; siblings + the local scalar retained).
    deps.supervisor
        .remove_member_floors(&context_id_bytes, did.as_ref());
    // ADR-049 PR-7 (RESET-SITE ruling a): the sender-key ROTATION is Class-S per
    // §9 — the epoch bump is sync-persisted fail-closed via `commit_class_s_keep`
    // (treated exactly like leave/revoke), NOT the coalesced best-effort it was
    // when this site only held a `ClassCMut` view. Swallow-and-log disposition
    // preserved on failure (rotation + distribution best-effort, M23); anti-replay
    // backstop is the never-regressing registry floor (`mirror_forward`,
    // `?`-propagated). `local_did` was read once above and is reused here.
    match cell
        .commit_class_s_keep(deps, context_id, |mut v| {
            let s = v.rest_mut();
            s.rotate_sender_key(&local_did)?;
            Ok(s.local_sender_key_epoch())
        })
        .await
    {
        Ok(epoch) => {
            // ADR-049 PR-6/PR-7: advance the durably-bumped local epoch (read from
            // the actor state the rotate above advanced) in the authoritative floor
            // registry (fail-closed backstop).
            crate::context::messaging_helpers::mirror_forward_local_sender_epoch(
                deps,
                &context_id_bytes,
                epoch,
            )?;
        }
        Err(e) => {
            tracing::warn!(
                context_id,
                error = %e,
                "rotate_sender_key failed after MLS reset"
            );
        }
    }

    // ADR-049 PR-7: drain through the actor's crypto state (same one the rotation
    // populated — reset has no separate `distribute_sender_key`, so `rotate` is the
    // sole producer of the pending queue). `&mut` view scoped so `cell` is free.
    {
        let mut view = cell.class_c_view();
        if let Err(e) = crate::context::lifecycle_helpers::drain_and_deliver_sender_keys(
            deps,
            view.mode_mut().crypto_mut(),
            context_id,
        )
        .await
        {
            tracing::warn!(
                context_id = %context_id,
                error = %e,
                "failed to deliver rotated sender keys after member reset"
            );
        }
    }

    deps.event_log
        .append_context_event(
            &context_id_bytes,
            scp_event_log::EventType::MemberReset,
            actor_did,
            timestamp_secs,
        )
        .await?;
    // Coalesced Class-C bookkeeping through a short-lived view (the checkpoint
    // counter + the pending epoch-reset queue are Class-C, ride the next persist).
    {
        let mut view = cell.class_c_view();
        *view.checkpoint_events_since_mut() += 1;
        view.governance_class_c_mut()
            .pending_epoch_resets_mut()
            .push(did.clone());
    }

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
    })
    .await?;
    deps.event_log
        .append_context_event(
            &context_id_bytes,
            scp_event_log::EventType::GovernanceConflictResolved,
            actor_did,
            timestamp_secs,
        )
        .await?;
    *cell.class_c_view().checkpoint_events_since_mut() += 1;
    Ok(())
}

// ---------------------------------------------------------------------------
// execute_promote_context (per-action leaf helper)
// ---------------------------------------------------------------------------

pub async fn execute_promote_context(
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

    // Promotion clears the TTL timer + applies the §5.10 params mutation
    // (memory scope → Full AND `params.ttl` → None). Clearing `params.ttl` is the
    // SOLE prune-immune promotion authority for the single-source TTL-deadline
    // invariant (ADR-049 §9): the deadline reader derives "promoted ⇒ no arm" from
    // `params.ttl == None` and does NOT read the `ContextPromoted` leaf for the
    // arm. That makes the params mutation SECURITY-CRITICAL: if a best-effort
    // persist of it silently fails and the actor crashes before a later
    // re-persist, a respawn reads a stale `params.ttl = Some` snapshot, re-arms
    // the TTL, and destroys the keys of a context members unanimously voted
    // permanent (the fail-DANGEROUS direction §9 names). Route the mutation
    // through the FAIL-CLOSED Class-S combinator `commit_class_s_keep` (the same
    // tier `execute_close_context` uses; the two now genuinely mirror each other)
    // so a persist failure surfaces as an error rather than leaving a re-armable
    // stale snapshot. Keep-direction: on persist failure the promotion STAYS
    // (re-arming a context voted permanent is the unsafe direction). The
    // active-state + promotable-policy + unanimity guards read through the cell's
    // `Deref` before the commit; the `ttl` / `handle` mutations ride the
    // fail-closed persist via `view.rest_mut()`. The `ContextPromoted` leaf is
    // appended AFTER the durable persist succeeds, and remains only a RECORD (it
    // is NOT read back to disarm the TTL — re-adding a leaf-fallback read would
    // let a forged/spurious leaf make a finite context never expire, the other
    // fail-dangerous direction pass-4e closed).
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

    cell.commit_class_s_keep(deps, context_id, |mut view| {
        let state = view.rest_mut();
        // Clear the recorded deadline so the actor-owned TTL arm disarms on the
        // next `reconcile_timers` (ADR-049 finding A3; no task to cancel).
        state.ttl.timer.deadline_unix_secs = None;
        // §5.10 params mutation: memory scope → Full AND `params.ttl` → None (the
        // prune-immune promotion authority the deadline reader consults).
        state.handle.promote_params();
        Ok(())
    })
    .await?;
    deps.event_log
        .append_context_event(
            &context_id_bytes,
            scp_event_log::EventType::ContextPromoted,
            actor_did,
            timestamp_secs,
        )
        .await?;
    *cell.class_c_view().checkpoint_events_since_mut() += 1;
    Ok(())
}

// ---------------------------------------------------------------------------
// execute_rotate_content_keys (per-action leaf helper)
// ---------------------------------------------------------------------------

#[allow(clippy::too_many_lines)]
pub async fn execute_rotate_content_keys(
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
    // crypto/access-key mutations + emit ride the fail-closed persist via
    // `view.rest_mut()`. The MLS-Commit broadcast ENQUEUE (Class-C) is hoisted to
    // AFTER the persist (ADR-049 Decision 7 — transport is async and cannot be
    // awaited inside the sync closure); it is coalesced, not fail-closed, which is
    // its correct class. Broadcast per-author key epochs still ride the Class-S
    // `ContextSnapshot`, so the all-author key-epoch advance persists fail-closed
    // atomically inside the combinator — the prior trailing best-effort
    // `persist_broadcast_snapshot` is gone (§5.14.8).
    let (rotate_commit_bytes, key_advances) = cell
        .commit_class_s_keep(deps, context_id, |mut view| {
            let state = view.rest_mut();
            require_active(&state.handle)?;

            let (epoch_output, advances) = if let Some(ref mut bc) = state.broadcast_context {
                // `rotate_all_author_keys` now returns per-author advance data so
                // the caller can emit `KeyEpochAdvance` event-log leaves after the
                // fail-closed persist (async appends cannot run inside this sync
                // `commit_class_s_keep` closure — ADR-049 Decision 7). The advance
                // Vec is threaded out of the closure as the second tuple element.
                let advances = bc.rotate_all_author_keys(timestamp_secs.saturating_mul(1_000))?;
                (None, advances)
            } else {
                // ADR-049 PR-7 (SCP-CRYPTOMOVE-001): advance the MLS epoch on the
                // actor state (already inside this fail-closed `commit_class_s_keep`
                // closure — §9 Class-S). `wrapping_public_key` from the retained
                // `deps.crypto.wrapping_keypair()`. Behavior otherwise unchanged
                // (content-key rotation does not touch the `mls_epoch` mirror).
                let epoch_out = state.advance_epoch(deps.crypto.wrapping_keypair().0)?;

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
                // Non-broadcast: no broadcast-key epoch advances.
                (Some(epoch_out), vec![])
            };

            emit(
                state,
                ContextEvent::ContentKeysRotated {
                    reason: reason.map(String::from),
                },
                context_id,
                deps,
            );

            // Capture the epoch-advance Commit bytes (non-broadcast path); the ASYNC
            // Commit broadcast runs AFTER the fail-closed persist, outside this sync
            // `_keep` closure (ADR-049 Decision 7 — transport is async). `None` on
            // the broadcast path (no MLS Commit) or when no epoch advance occurred.
            // The `advances` Vec carries per-author BroadcastKeyEpochAdvance data
            // for KeyEpochAdvance event-log appends AFTER the persist (below).
            Ok((
                epoch_output.map(|epoch_out| epoch_out.commit_bytes),
                advances,
            ))
        })
        .await?;

    // Async transport op AFTER the Class-S rotation persist (ADR-049 Decision 7).
    // The key rotation is fail-closed-persisted; the commit bytes were produced
    // under the crypto `Arc` (Class-M) inside the closure. Broadcast async
    // (Decision 7); on FAILURE the retry-queue bookkeeping is persisted
    // FAIL-CLOSED via `keep_broadcast_failure` (epoch-advance is a safety-gated
    // site — see that helper's doc for why the second persist).
    if let Some(commit_bytes) = rotate_commit_bytes
        && let Some(failure) = try_broadcast_commit(
            deps,
            context_id,
            commit_bytes,
            &CommitOperation::RotateContentKeys {
                reason: reason.map(String::from),
            },
        )
        .await
    {
        keep_broadcast_failure(cell, deps, context_id, failure).await?;
    }

    deps.event_log
        .append_context_event(
            &context_id_bytes,
            scp_event_log::EventType::ContentKeysRotated,
            actor_did,
            timestamp_secs,
        )
        .await?;

    // Class-C counter bump for the ContentKeysRotated leaf, inline immediately
    // after its `?`-append. The counter must track the true durable-leaf count
    // (governance_logic.rs:156-158) to prevent §9.9.3 checkpoint-position drift.
    *cell.class_c_view().checkpoint_events_since_mut() += 1;

    // One `KeyEpochAdvance` leaf per broadcast author whose key was rotated
    // (§5.14.10, #1847). `key_advances` is empty on the non-broadcast path, and
    // arrives in DID-lexicographic order by construction (the `authors`
    // `BTreeMap` in `scp_protocol::context::broadcast`), so the leaf sequence —
    // and therefore the Merkle root — is identical on every member and across
    // replays.
    //
    // DURABILITY-SIGNALLING, NOT FAIL-ATOMIC. `?`-propagating an append failure
    // rolls nothing back: the rotation is already durably persisted (the
    // fail-closed `commit_class_s_keep` above) and the `ContentKeysRotated`
    // anchor leaf is already appended. A failure on leaf k of n returns `Err`
    // while leaving leaves 0..k durable and leaves k..n absent, with no repair
    // path. What `?` buys over the previous warn-and-continue is that the
    // failure reaches the caller instead of being swallowed, giving operators a
    // concrete error signal that the log is short some leaves — the same
    // rationale as the GovernanceDeadlockRecovery companion leaf in
    // `execute_reconfigure_governance`.
    //
    // The counter is bumped INLINE after each successful append, never coalesced
    // at the end, so the leaves that did land are still credited when a later
    // one fails.
    //
    // NOTE: `advance.timestamp` (milliseconds) is not used here — the event-log
    // append takes `timestamp_secs` directly. The ms field is carried by
    // `BroadcastKeyEpochAdvance` for the relay-message consumer on the per-author
    // block path; it is dead data in this governance path. `old_epoch` is
    // derived as `new_epoch - 1` because `rotate_all_author_keys` always
    // increments by exactly 1 (pre-validated, sound by construction).
    for advance in &key_advances {
        let old_epoch = advance.new_epoch.saturating_sub(1);
        let payload = scp_event_log::payload::encode_payload(
            &scp_event_log::payload::KeyEpochAdvancePayload {
                old_epoch,
                new_epoch: advance.new_epoch,
            },
        )
        .map_err(|e| ContextError::EventLogFailed(e.to_string()))?;
        deps.event_log
            .append_context_event_with_payload(
                &context_id_bytes,
                scp_event_log::EventType::KeyEpochAdvance,
                advance.author_did.as_str(),
                payload,
                timestamp_secs,
            )
            .await?;
        *cell.class_c_view().checkpoint_events_since_mut() += 1;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// execute_reconfigure_governance (per-action leaf helper)
// ---------------------------------------------------------------------------
//
// INVARIANT: This function is exclusively called from the `ReconfigureGovernance`
// deadlock-resolution action. It always emits a `GovernanceDeadlockRecovery`
// companion leaf (the justification evidence) paired with `GovernanceReconfigured`.
// Do NOT reuse this function for non-deadlock governance reconfigurations — it
// would emit a spurious `GovernanceDeadlockRecovery` leaf with no real justification.

#[allow(clippy::too_many_arguments)]
pub async fn execute_reconfigure_governance(
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
    })
    .await?;
    deps.event_log
        .append_context_event(
            &context_id_bytes,
            scp_event_log::EventType::GovernanceReconfigured,
            actor_did,
            timestamp_secs,
        )
        .await?;
    // Inline Class-C counter bump for THIS leaf. This helper appends TWO durable
    // leaves; each needs its own bump immediately after its `?`-append so a
    // failure on the second still credits the first (governance_logic.rs:156-158,
    // §9.9.3 checkpoint-position drift).
    *cell.class_c_view().checkpoint_events_since_mut() += 1;

    // Append the companion GovernanceDeadlockRecovery leaf carrying the
    // structured recovery justification (issue #1847).  The two leaves share
    // the same actor_did and timestamp so verifiers can correlate them.
    // Fail-closed (error-surfaced, not atomically co-present): the signer
    // removal and the GovernanceReconfigured leaf above are already durable
    // by this point, so an append failure here does not roll back the
    // reconfiguration.  Fail-closed is still preferred over best-effort
    // because it surfaces the failure to the caller rather than swallowing
    // it silently, giving operators a concrete error signal to investigate.
    let recovery_payload = scp_event_log::payload::encode_payload(
        &scp_event_log::payload::GovernanceDeadlockRecoveryPayload {
            unavailable_dids: justification
                .unavailable_dids
                .iter()
                .map(|d| d.0.clone())
                .collect(),
            missed_windows: justification
                .missed_windows
                .iter()
                .map(|(d, n)| (d.0.clone(), *n))
                .collect(),
            detected_at: justification.detected_at,
        },
    )
    .map_err(|e| ContextError::EventLogFailed(e.to_string()))?;
    deps.event_log
        .append_context_event_with_payload(
            &context_id_bytes,
            scp_event_log::EventType::GovernanceDeadlockRecovery,
            actor_did,
            recovery_payload,
            timestamp_secs,
        )
        .await?;
    *cell.class_c_view().checkpoint_events_since_mut() += 1;
    Ok(())
}

// ---------------------------------------------------------------------------
// execute_set_economic_policy (per-action leaf helper)
// ---------------------------------------------------------------------------

pub async fn execute_set_economic_policy(
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
    })
    .await;
    deps.event_log
        .append_context_event(
            &context_id_bytes,
            scp_event_log::EventType::EconomicPolicyChanged,
            actor_did,
            timestamp_secs,
        )
        .await?;
    *cell.class_c_view().checkpoint_events_since_mut() += 1;
    Ok(())
}

// ---------------------------------------------------------------------------
// execute_approve_spend (per-action leaf helper)
// ---------------------------------------------------------------------------

#[allow(clippy::too_many_arguments)]
pub async fn execute_approve_spend(
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
    })
    .await;
    let spend_payload =
        scp_event_log::payload::encode_payload(&scp_event_log::payload::SpendApprovedPayload {
            spender: spender.as_ref().to_owned(),
            amount: amount.value(),
            purpose: purpose.to_owned(),
        })
        .map_err(|e| ContextError::EventLogFailed(e.to_string()))?;
    deps.event_log
        .append_context_event_with_payload(
            &context_id_bytes,
            scp_event_log::EventType::SpendApproved,
            actor_did,
            spend_payload,
            timestamp_secs,
        )
        .await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// execute_lock_economic_policy (per-action leaf helper)
// ---------------------------------------------------------------------------

pub async fn execute_lock_economic_policy(
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
    })
    .await;
    deps.event_log
        .append_context_event(
            &context_id_bytes,
            scp_event_log::EventType::EconomicPolicyLocked,
            actor_did,
            timestamp_secs,
        )
        .await?;
    *cell.class_c_view().checkpoint_events_since_mut() += 1;
    Ok(())
}

// ---------------------------------------------------------------------------
// execute_modify_hard_rate_limit (per-action leaf helper)
// ---------------------------------------------------------------------------

pub async fn execute_modify_hard_rate_limit(
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
    })
    .await;
    deps.event_log
        .append_context_event(
            &context_id_bytes,
            scp_event_log::EventType::HardRateLimitModified,
            actor_did,
            timestamp_secs,
        )
        .await?;
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
            let _ = cell.handle.transition_to(&ContextState::Active);
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

        crate::context::messaging_helpers::persist_state_best_effort(&*cell, deps, context_id)
            .await;
        deps.event_log
            .append_context_event(
                &context_id_bytes,
                scp_event_log::EventType::ContextMigrationStarted,
                actor_did,
                timestamp_secs,
            )
            .await?;
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

// ADR-049 §Decision 12: `state`/`transition_to` are now synchronous lock-free
// ArcSwap ops. Async is retained as the ContextManager helper API contract —
// callers await uniformly, and provider-trait calls regain await points under
// ADR-049 Decision 7 (async-provider-trait conversion).
#[allow(clippy::unused_async)]
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
    let s = cell.handle.state();
    if s != ContextState::MigratingOut {
        return Err(ContextError::PermissionDenied(
            "context is not in MigratingOut state — cannot cancel migration".to_owned(),
        ));
    }

    cell.handle
        .transition_to(&ContextState::Active)
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

    crate::context::messaging_helpers::persist_state_best_effort(&*cell, deps, context_id).await;
    let cancel_payload = scp_event_log::payload::encode_payload(
        &scp_event_log::payload::ContextMigrationCancelledPayload {
            original_proposal_id,
        },
    )
    .map_err(|e| ContextError::EventLogFailed(e.to_string()))?;
    deps.event_log
        .append_context_event_with_payload(
            &context_id_bytes,
            scp_event_log::EventType::ContextMigrationCancelled,
            actor_did,
            cancel_payload,
            timestamp_secs,
        )
        .await?;
    *cell.class_c_view().checkpoint_events_since_mut() += 1;
    Ok(())
}

// ---------------------------------------------------------------------------
// try_broadcast_commit / apply_broadcast_failure (transitive helpers, actor-shape)
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
#[allow(clippy::too_many_lines, clippy::too_many_arguments)]
pub async fn propose_governance_action_inner(
    cell: &mut crate::context::actor::class_s::ClassSCell,
    deps: &ActorDeps,
    context_id: &str,
    proposer_did: &DID,
    action: GovernanceAction,
    signing_key: &ed25519_dalek::SigningKey,
    check_propose_capability: bool,
    // The invitee's MLS `KeyPackage` for an `AddMember` auto-execute, carried on
    // the actor command envelope by `Supervisor::invite_member` and threaded to
    // `execute_add_member`. `None` on every path that is not a real invitation
    // add (governed-context invite is issue #2027).
    key_package: Option<&[u8]>,
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
        .suspended_for(proposer_did.as_ref())
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
                deps.event_log
                    .append_context_event(
                        &cid_bytes,
                        scp_event_log::EventType::GovernanceFreezeExpired,
                        proposer_did.as_ref(),
                        freeze_ts,
                    )
                    .await?;
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
                    deps.event_log
                        .append_context_event(
                            &context_id_bytes,
                            scp_event_log::EventType::GovernanceConflictDetected,
                            proposer_did.as_ref(),
                            // Conflict detected deterministically while processing
                            // this proposal: the convergent leaf timestamp is the
                            // proposal's signed `created_at` (§7.3.1, §9.9.3).
                            proposal.created_at,
                        )
                        .await?;
                    conflict_event_count += 1;
                }
                GovernanceEvent::ConflictResolved { .. } => {
                    deps.event_log
                        .append_context_event(
                            &context_id_bytes,
                            scp_event_log::EventType::GovernanceConflictResolved,
                            proposer_did.as_ref(),
                            proposal.created_at,
                        )
                        .await?;
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
        //
        // Auto-execute (SingleAdmin / quorum==0): the proposer IS the
        // committing member, so the executor is the proposer. Preserves the
        // existing leaf bytes on this path.
        Some(
            Box::pin(execute_governance_action(
                cell,
                deps,
                context_id,
                &proposal.proposal_id,
                Some(proposer_did),
                key_package,
            ))
            .await?,
        )
    } else {
        None
    };

    crate::context::messaging_helpers::persist_state_best_effort(&*cell, deps, context_id).await;

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
                // attestation_count is a credential-layer, verifier-relative
                // fact (§7.3.2); proposer eligibility gates only on
                // participation_count and has no attestation-cache access, so it
                // passes an empty accessible-attestation set (count 0) by
                // design — NOT a stub.
                &[],
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
    // The invitee's MLS `KeyPackage` for an `AddMember` auto-execute, carried on
    // the actor command envelope by `Supervisor::invite_member`. `None` for the
    // generic FFI governance path (which never invites a member here).
    key_package: Option<&[u8]>,
) -> Result<ProposalOutcome, ContextError> {
    let (proposal, _events, execution_result) = propose_governance_action_inner(
        cell,
        deps,
        context_id,
        proposer_did,
        action,
        signing_key,
        true,
        key_package,
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

    let suspended = cell.role_state.suspended_for(voter_did.as_ref());
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
                    deps.event_log
                        .append_context_event(
                            &context_id_bytes,
                            scp_event_log::EventType::GovernanceConflictDetected,
                            voter_did.as_ref(),
                            conflict_ts,
                        )
                        .await?;
                    conflict_event_count += 1;
                }
                GovernanceEvent::ConflictResolved { .. } => {
                    deps.event_log
                        .append_context_event(
                            &context_id_bytes,
                            scp_event_log::EventType::GovernanceConflictResolved,
                            voter_did.as_ref(),
                            conflict_ts,
                        )
                        .await?;
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
            //
            // Quorum-approval path: the executor is THIS voter — the member
            // whose approval crossed quorum and therefore committed the action
            // (ADR-031 §7.3.1 "committing member"). This is the divergence-
            // causing path: stamping the proposer here (the old behavior) made
            // the leaf diverge whenever proposer != quorum-crossing
            // voter.
            Box::pin(execute_governance_action(
                cell,
                deps,
                context_id,
                &proposal.proposal_id,
                Some(voter_did),
                // The quorum-approval path never carries an invitee KeyPackage
                // (deferred governed invite is issue #2027).
                None,
            ))
            .await?;
        }
    }

    crate::context::messaging_helpers::persist_state_best_effort(&*cell, deps, context_id).await;

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
pub async fn dispatch_content_governance_action(
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
            )
            .await?;
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
            )
            .await?;
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
            )
            .await?;
            Ok(GovernanceActionResult::ThresholdModified)
        }
        GovernanceAction::EstablishOutletInterface { interface } => {
            execute_establish_outlet_interface(
                cell,
                deps,
                context_id,
                interface,
                CommitMeta {
                    pid,
                    actor_did,
                    timestamp_secs,
                },
            )
            .await?;
            Ok(GovernanceActionResult::OutletInterfaceEstablished)
        }
        GovernanceAction::ResetMember { did, reason } => {
            execute_reset_member(
                cell,
                deps,
                context_id,
                did,
                reason,
                CommitMeta {
                    pid,
                    actor_did,
                    timestamp_secs,
                },
            )
            .await?;
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
            )
            .await?;
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
            )
            .await?;
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
            )
            .await?;
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
        | GovernanceAction::RegisterOutlet { .. }
        | GovernanceAction::RemoveOutlet { .. }
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
    // The invitee's MLS `KeyPackage`, threaded from the propose/execute entry
    // for the `AddMember` action only (the invitation path carries it on the
    // command envelope). `None` for every other action and for the paths that
    // never carried a real add (issue #2029).
    key_package: Option<&[u8]>,
    meta: CommitMeta<'_>,
) -> Result<GovernanceActionResult, ContextError> {
    let CommitMeta {
        pid,
        actor_did,
        timestamp_secs,
    } = meta;
    match action {
        GovernanceAction::AddMember { did, role } => {
            let add_output = execute_add_member(
                cell,
                deps,
                context_id,
                did,
                role,
                key_package,
                CommitMeta {
                    pid,
                    actor_did,
                    timestamp_secs,
                },
            )
            .await?;
            Ok(GovernanceActionResult::MemberAdded {
                welcome_bytes: scp_protocol::context::membership::RedactedBytes(
                    add_output.welcome_bytes,
                ),
                commit_bytes: scp_protocol::context::membership::RedactedBytes(
                    add_output.commit_bytes,
                ),
            })
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
            )
            .await?;
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
            )
            .await?;
            Ok(GovernanceActionResult::RoleChanged)
        }
        GovernanceAction::RegisterOutlet { registration } => {
            execute_register_outlet(
                cell,
                deps,
                context_id,
                registration,
                CommitMeta {
                    pid,
                    actor_did,
                    timestamp_secs,
                },
            )
            .await?;
            Ok(GovernanceActionResult::OutletRegistered)
        }
        GovernanceAction::RemoveOutlet { outlet_id } => {
            execute_remove_outlet(
                cell,
                deps,
                context_id,
                outlet_id,
                CommitMeta {
                    pid,
                    actor_did,
                    timestamp_secs,
                },
            )
            .await?;
            Ok(GovernanceActionResult::OutletRemoved)
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
            )
            .await?;
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
            )
            .await?;
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
            )
            .await?;
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
            )
            .await?;
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
        | GovernanceAction::EstablishOutletInterface { .. }
        | GovernanceAction::ResetMember { .. }
        | GovernanceAction::ResolveConflict { .. }
        | GovernanceAction::RotateContentKeys { .. }
        | GovernanceAction::ReconfigureGovernance { .. } => {
            dispatch_content_governance_action(
                cell,
                deps,
                context_id,
                action,
                CommitMeta {
                    pid,
                    actor_did,
                    timestamp_secs,
                },
            )
            .await
        }
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
    // The committing member (quorum-crossing voter, or proposer on
    // auto-execute). Every per-action dispatch leaf (RoleAssigned,
    // CeilingModified, etc.) is stamped with the executor — uniform with the
    // `GovernanceActionExecuted` leaf and spec-correct per ADR-031 §8 /
    // §7.3.1 / ADR-051 §6.
    executor_did: &DID,
    // The invitee's MLS `KeyPackage` for an `AddMember` auto-execute — carried
    // on the actor command envelope by `Supervisor::invite_member` and threaded
    // to `execute_add_member`. `None` on every non-invite execute path.
    key_package: Option<&[u8]>,
) -> Result<GovernanceActionResult, ContextError> {
    let pid = proposal.proposal_id;
    let actor = executor_did.as_ref();
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
            )
            .await?;
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

                if !state.role_state.ceiling().contains(&Capability::MemberBan) {
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
            })
            .await?;
            let context_id_bytes = context_id_to_bytes(context_id);
            deps.event_log
                .append_context_event(
                    &context_id_bytes,
                    scp_event_log::EventType::MemberSuspendedAll,
                    actor,
                    ts,
                )
                .await?;
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
            )
            .await?;
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
            )
            .await?;
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
            )
            .await?;
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
            )
            .await?;
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
            )
            .await?;
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
            )
            .await?;
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
            )
            .await?;
            Ok(GovernanceActionResult::Executed)
        }
        // Remaining actions dispatched to context-level handler.
        GovernanceAction::AddMember { .. }
        | GovernanceAction::RemoveMember { .. }
        | GovernanceAction::ChangeRole { .. }
        | GovernanceAction::RegisterOutlet { .. }
        | GovernanceAction::RemoveOutlet { .. }
        | GovernanceAction::ModifyCeiling { .. }
        | GovernanceAction::CloseContext { .. }
        | GovernanceAction::TransferAdmin { .. }
        | GovernanceAction::CreateChildContext { .. }
        | GovernanceAction::ModifyPruningPolicy { .. }
        | GovernanceAction::AddSigner { .. }
        | GovernanceAction::RemoveSigner { .. }
        | GovernanceAction::ModifyThreshold { .. }
        | GovernanceAction::EstablishOutletInterface { .. }
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
                key_package,
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
pub async fn finalize_governance_action(
    state: &mut PerContextState,
    deps: &ActorDeps,
    context_id: &str,
    proposal: &GovernanceProposal,
    // The committing member — the DID whose approval crossed quorum (or, for
    // auto-execute, the proposer). Stamped as the `GovernanceActionExecuted`
    // leaf `actor_did` and the event's `executor_did` per ADR-031 §8
    // ("executor DID") / §7.3.1 ("committing member") / ADR-051 §6. This is
    // DISTINCT from `proposal.proposer_did`, which remains the consequence
    // SUBJECT below (a different semantic — see the consequence-evaluation
    // block).
    executor_did: &DID,
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
        executor_did: executor_did.clone(),
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
    deps.event_log
        .append_context_event_with_payload(
            &context_id_bytes,
            governance_event_label(&executed_event),
            executor_did.as_ref(),
            executed_payload,
            // Committer-assigned timestamp: the proposal's signed `created_at` —
            // identical and tamper-evident for every member that processes the
            // signed proposal (convergent-by-construction), never local `now()`.
            // The leaf is currently committer-appended-only; cross-member leaf
            // replication is the forward step under ADR-051 (§7.3.1, §9.9.3).
            proposal.created_at,
        )
        .await?;

    let action_summary = proposal.action.variant_name().to_owned();
    let target_did = proposal.action.target_did().cloned();
    state.checkpoint_events_since += 1;

    // 1. Push GovernanceActionExecuted to receive buffer.
    let gov_event = ContextEvent::GovernanceActionExecuted {
        proposal_id: proposal.proposal_id,
        action_summary,
        executor_did: executor_did.clone(),
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

            // ADR-049 §9 (RED-CS3): a consequence here may apply a downward-auth
            // mutation (a capability suspension or an `AssignRole` demotion), which
            // ARMS `downward_auth_sink` via the GROW method. On THIS path the
            // fail-closed persist is already owed by the caller —
            // `execute_governance_action` runs this whole
            // `finalize_governance_action` body inside the deferred
            // `ClassSCommitToken::discharge_with`, which performs a SINGLE
            // FAIL-CLOSED persist of the post-finalize state (keep-direction). So an
            // armed sink here is REDUNDANT — it is subsumed by the caller's
            // discharge (no second persist) below.
            let mut downward_auth_sink: Option<crate::context::actor::class_s::ClassSCommitToken> =
                None;
            let mut split = ConsequenceStateSplit::from_state(state);
            let _ = enforce_triggered_consequences(
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
                &mut downward_auth_sink,
            )
            .await;
            if let Some((target, triggered)) = triggered_target {
                let mut split = ConsequenceStateSplit::from_state(state);
                let _ = enforce_triggered_consequences(
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
                    &mut downward_auth_sink,
                )
                .await;
            }
            // Covered fail-closed by the caller's `discharge_with` commit (above):
            // subsume any armed obligation so EXACTLY ONE persist is owed.
            if let Some(token) = downward_auth_sink.take() {
                token.subsume(context_id);
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
                // attestation_count is a credential-layer, verifier-relative
                // fact (§7.3.2); proposer eligibility gates only on
                // participation_count and has no attestation-cache access, so it
                // passes an empty accessible-attestation set (count 0) by
                // design — NOT a stub.
                &[],
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
    // Identifier of the proposal to execute. The authoritative proposal is
    // resolved from the context actor's OWN governance engine via
    // `engine.get_proposal(proposal_id)` — never from a caller-supplied
    // proposal/action/status. This is the trust boundary that closes the
    // direct-execute quorum bypass: the engine only sets
    // `ProposalStatus::Approved` after verifying every vote's Ed25519
    // signature at genuine quorum (see the governance engines in
    // `scp_protocol::context::governance`), and only the engine-retained
    // proposal is ever dispatched.
    proposal_id: &ProposalId,
    // The committing member whose DID is stamped on the per-action dispatch
    // leaves and the `GovernanceActionExecuted` leaf/event:
    // - `Some(voter)` on the quorum-approval path (the quorum-crossing voter)
    //   and the auto-execute / `SingleAdmin` path (the proposer), supplied by
    //   the internal callers that already hold that DID.
    // - `None` on the direct-execute FFI path, where there is no
    //   quorum-crossing voter: the executor is resolved from the *tracked*
    //   proposal's `proposer_did` (never a caller-supplied DID), preserving the
    //   convention and the cross-implementation leaf convergence established for the
    //   direct path. Spec: ADR-031 §8 "executor DID" / §7.3.1 "committing
    //   member" / ADR-051 §6.
    executor_did: Option<&DID>,
    // The invitee's MLS `KeyPackage` for an `AddMember` auto-execute, carried on
    // the actor command envelope by `Supervisor::invite_member` and threaded to
    // `execute_add_member`. `None` on the vote-approval and direct-execute
    // paths — those never carry a real KeyPackage (governed-context invite is
    // issue #2027).
    key_package: Option<&[u8]>,
) -> Result<GovernanceActionResult, ContextError> {
    // ADR-049 §9 Class-S cell seam: this entry holds the cell. The pre-dispatch
    // gate is READ-ONLY (commit-fault gate, authoritative-proposal resolution,
    // proposal status/context match, replay-marker presence) — read through the
    // cell's `Deref` (`&*cell`), no mutation. The `executed_proposals`
    // replay-marker WRITE below routes through the deferred-persist
    // `begin_class_s` combinator; the downstream dispatch chain takes the cell
    // directly.

    // PR #1606 C6 fail-close gate + atomically check replay AND mark as
    // executed before dispatch. Actor-owned state — single linear sequence.
    check_commit_fault(cell)?;

    // Resolve the authoritative proposal from the engine. Clone so the engine
    // borrow (taken via the cell's `Deref`) is dropped before the Class-S
    // replay-marker WRITE below. A missing proposal means the caller referenced
    // something the quorum-validated engine never retained — reject rather than
    // trust caller-supplied data.
    let proposal = cell
        .governance
        .engine
        .get_proposal(proposal_id)
        .cloned()
        .ok_or_else(|| {
            ContextError::PermissionDenied(format!(
                "governance proposal not tracked: {}",
                hex::encode(proposal_id)
            ))
        })?;
    let proposal = &proposal;

    // Resolve the committing member. The direct-execute path (`None`) attributes
    // to the TRACKED proposal's proposer — never a caller-supplied DID — so the
    // `GovernanceActionExecuted` leaf actor_did is convergent across honest
    // members and with the quorum path's own attribution.
    let executor_did: &DID = executor_did.unwrap_or(&proposal.proposer_did);

    // The engine's own status — set to `Approved` only at genuine quorum.
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

    // Atomically check replay AND mark as executed before dispatch (the
    // commit-fault gate already ran above). Actor-owned state — single linear
    // sequence.
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

    let result = match dispatch_governance_action(
        cell,
        deps,
        context_id,
        proposal,
        executor_did,
        key_package,
    )
    .await
    {
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
            token
                .discharge_with(cell, deps, context_id, |mut view| {
                    view.governance_class_s_mut()
                        .executed_proposals
                        .remove(&proposal.proposal_id);
                    Ok(())
                })
                .await?;
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
    // Deferred fail-closed discharge with an ASYNC finalize body (ADR-049
    // Decision 7): `finalize_governance_action` appends to the async
    // `EventLogPersistence`-backed Merkle log while mutating the state,
    // interleaved, so it runs inside the RAII `begin_discharge` guard (which hands
    // out the `ClassSMut` view held across the finalize awaits) rather than a
    // synchronous `discharge_with` closure. Keep-direction: the SINGLE persist runs
    // REGARDLESS of the finalize result; the finalize error is surfaced after.
    let mut discharge = token.begin_discharge(cell);
    let finalize_result = finalize_governance_action(
        discharge.view().rest_mut(),
        deps,
        context_id,
        proposal,
        executor_did,
    )
    .await;
    // Keep-direction: the fail-closed persist runs REGARDLESS of the finalize
    // result. Error priority matches the former `discharge_with` `match`: a
    // finalize error is surfaced BEFORE a persist error when both fail.
    let persist_result = discharge.commit_fail_closed(deps, context_id).await;
    finalize_result?;
    persist_result?;

    Ok(result)
}

// ---------------------------------------------------------------------------
// try_broadcast_commit / apply_broadcast_failure (transitive helpers, actor-shape)
// ---------------------------------------------------------------------------

/// The three disjoint Class-C `&mut` fields [`apply_broadcast_failure`] mutates,
/// threaded as ONE struct so the caller holds all three at once (they are
/// distinct fields of [`PerContextState`], so the borrow checker accepts the
/// simultaneous `&mut`).
///
/// Replaces the prior whole `&mut PerContextState` parameter: the broadcast-
/// failure apply touches ONLY the MLS Commit retry queue (`pending_commits`), the
/// queue-full fail-close marker (`commit_fault`), and the local receive buffer
/// (`receive_buffer`). The borrow is field-granular and reaches no Class-S
/// sub-struct; the DURABILITY class is the caller's choice — the safety-gated
/// sites supply these from a `commit_class_s_keep` `rest_mut()` view (fail-closed
/// persist of `pending_commits`/`commit_fault`), the best-effort sites from a
/// coalesced `ClassCMut` view (see [`apply_broadcast_failure`]).
pub struct CommitBroadcastBorrows<'a> {
    /// `&mut` to the MLS Commit retry queue (Class-C / §9.9.3).
    pub pending_commits: &'a mut std::collections::VecDeque<PendingCommit>,
    /// `&mut` to the queue-full fail-close marker (Class-C / structural).
    pub commit_fault: &'a mut Option<CommitFaultMarker>,
    /// `&mut` to the local receive buffer (Class-C / structural).
    pub receive_buffer: &'a mut ReceiveBuffer,
}

/// The retry-queue bookkeeping an MLS-Commit broadcast requires when its
/// transport send FAILS, returned by [`try_broadcast_commit`] so the CALLER
/// applies it (via [`apply_broadcast_failure`]) in the correct durability class.
///
/// Splitting the failure bookkeeping OUT of the async transport send is what
/// lets the safety-gated Class-S sites — `execute_remove_member`,
/// `execute_rotate_content_keys` (this module) and `leave_context`
/// (`lifecycle_helpers`) — persist the `commit_fault` marker + `pending_commits`
/// enqueue FAIL-CLOSED even though the broadcast itself, being async under
/// ADR-049 Decision 7, cannot run inside their synchronous `commit_class_s_keep`
/// closure. The best-effort sites (`execute_add_member`, `execute_reset_member`)
/// apply the identical value coalesced through a `ClassCMut` view.
///
/// Why fail-closed matters here: `commit_fault` is a SAFETY GATE
/// ([`check_commit_fault`] blocks send/lifecycle/governance) and the
/// `pending_commits` entry is the ONLY re-delivery of the epoch-advancing
/// Commit. If a crash lands between a broadcast failure and the ≤50 ms coalesced
/// persist tick, a coalesced-only write loses BOTH — the context respawns
/// "healthy" while members are stuck on a stale MLS epoch with no retry queued:
/// silent, permanent group desync (ADR-049 §9 / §9.9.3).
pub struct BroadcastFailure {
    /// The retry record to enqueue (or, when the queue is full at apply time,
    /// the source of the fail-close [`CommitFaultMarker`]).
    pending: PendingCommit,
    /// Operation label for the surfaced local `ContextEvent`.
    label: String,
    /// Transport error string for the surfaced local `ContextEvent`.
    error: String,
}

/// Attempts to broadcast an MLS Commit. Returns `None` on success (or an empty
/// commit — the `cfg(test)` no-crypto pipeline); on transport failure returns
/// `Some(BroadcastFailure)` describing the retry-queue bookkeeping the caller
/// must persist via [`apply_broadcast_failure`].
///
/// Per the phase-2.md ADR-011-amendment exclusion taxonomy (per-committer
/// broadcast-retry bookkeeping), the commit-broadcast lifecycle events
/// (`CommitBroadcasted` / `CommitBroadcastPending`) are NOT durably appended
/// to the canonical Merkle log: only the broadcasting member holds the notion,
/// so two honest members diverge at equal event count (§9.9.3). They are
/// surfaced as local `ContextEvent`s only (first-attempt success is not
/// surfaced); no durable consumer reads them.
///
/// # No state mutation (ADR-049 §9 / Decision 7)
///
/// This function performs ONLY the async transport send and builds the retry
/// payload; it touches NO `PerContextState` field. Applying that payload —
/// enqueue into `pending_commits`, set the `commit_fault` marker, emit the local
/// event — is deferred to the synchronous [`apply_broadcast_failure`] so the
/// CALLER picks the durability class (fail-closed at the safety-gated Class-S
/// sites, coalesced at the best-effort sites). This is the decoupling that
/// restores fail-closed durability of the `commit_fault` safety gate after the
/// transport became async and the broadcast could no longer live inside the
/// sync `commit_class_s_keep` closure.
pub async fn try_broadcast_commit(
    deps: &ActorDeps,
    context_id: &str,
    commit_bytes: Vec<u8>,
    operation: &CommitOperation,
) -> Option<BroadcastFailure> {
    if commit_bytes.is_empty() {
        return None;
    }
    let routing_id = scp_protocol::context::context_routing_id(context_id);
    match deps
        .transport
        .send_message(&routing_id, &commit_bytes)
        .await
    {
        Ok(()) => None,
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
            Some(BroadcastFailure {
                pending,
                label: operation.label(),
                error: error_str,
            })
        }
    }
}

/// Applies the retry-queue bookkeeping from a failed [`try_broadcast_commit`] to
/// the three disjoint Class-C fields it touches (`pending_commits`,
/// `commit_fault`, `receive_buffer`) and emits the surfaced local event.
///
/// SYNCHRONOUS by design: a caller runs it INSIDE a `commit_class_s_keep`
/// closure (via `view.rest_mut()`) to persist the fields FAIL-CLOSED at the
/// safety-gated sites, or against a coalesced `class_c_view()` / `ClassCMut` at
/// the best-effort sites. The durability class is the CALLER's choice; this
/// helper only mutates the borrowed fields.
///
/// # Field-granular borrows (ADR-049 §9)
///
/// Takes a [`CommitBroadcastBorrows`] — the THREE disjoint Class-C `&mut` fields
/// rather than a whole `&mut PerContextState`.
///
/// Preserves the exact `MAX_PENDING_COMMITS` cap semantics: the length check
/// runs HERE, holding the live `&mut pending_commits`, so a full queue converts
/// the enqueue into a fail-close [`CommitFaultMarker`] instead — identical to the
/// pre-async single-function behavior (§9.9.3).
pub fn apply_broadcast_failure(
    borrows: CommitBroadcastBorrows<'_>,
    deps: &ActorDeps,
    context_id: &str,
    failure: BroadcastFailure,
) {
    let CommitBroadcastBorrows {
        pending_commits,
        commit_fault,
        receive_buffer,
    } = borrows;
    let BroadcastFailure {
        pending,
        label,
        error,
    } = failure;

    // N2: Cap the pending commits queue.
    if pending_commits.len() >= MAX_PENDING_COMMITS {
        *commit_fault = Some(CommitFaultMarker {
            operation: pending.operation.clone(),
            reason: format!("pending commit queue full ({MAX_PENDING_COMMITS} entries)"),
            retry_count: 1,
            failed_at: pending.first_attempt_at,
        });
        emit_event_into(
            receive_buffer,
            ContextEvent::CommitBroadcastFailed {
                operation: label,
                reason: format!("queue full ({MAX_PENDING_COMMITS}): {error}"),
                attempts: 1,
            },
            context_id,
            deps.event_tx.as_ref(),
        );
        return;
    }
    pending_commits.push_back(pending);
    let label_for_event = label.clone();
    emit_event_into(
        receive_buffer,
        ContextEvent::CommitBroadcastPending {
            operation: label_for_event,
            error: error.clone(),
            attempt: 1,
        },
        context_id,
        deps.event_tx.as_ref(),
    );
    tracing::warn!(
        context_id = %context_id,
        operation = %label,
        error = %error,
        "MLS commit broadcast failed; enqueued for persistent retry (PR #1606 C6)"
    );
}

/// Applies a failed MLS-Commit broadcast's retry-queue bookkeeping FAIL-CLOSED,
/// inside a second [`commit_class_s_keep`](crate::context::actor::class_s::ClassSCell::commit_class_s_keep)
/// so it survives a crash before the actor's ≤50 ms coalesced persist tick.
///
/// The single call the safety-gated commit-broadcast sites —
/// [`execute_remove_member`], [`execute_rotate_content_keys`] (this module),
/// [`recovery_advance_epoch`](crate::context::trust_recovery_helpers::recovery_advance_epoch)
/// (§9.12 post-compromise recovery), and
/// [`leave_context`](crate::context::lifecycle_helpers::leave_context) —
/// make after [`try_broadcast_commit`] returns `Some(BroadcastFailure)`.
///
/// # Why the second fail-closed persist (ADR-049 §9 / §9.9.3)
///
/// The transport became async under ADR-049 Decision 7, so the broadcast can no
/// longer be awaited inside the primary `commit_class_s_keep` closure that
/// fail-closed-persisted the underlying mutation; it now runs AFTER it. Its
/// failure bookkeeping, however — the `commit_fault` safety-gate marker
/// ([`check_commit_fault`] blocks send/lifecycle/governance) and the
/// `pending_commits` entry that is the ONLY re-delivery of the epoch-advancing
/// Commit — is synchronous ([`apply_broadcast_failure`]) and DOES ride a second
/// `commit_class_s_keep`. If instead it were only coalesced (a plain `ClassCMut`
/// write), a crash between the broadcast failure and the next persist tick would
/// drop BOTH: the context respawns "healthy" while remaining members are stuck on
/// a stale MLS epoch with no retry queued — silent, permanent group desync. The
/// success path persists nothing (there is no `BroadcastFailure` to apply).
///
/// `pub` (not `pub(crate)`) is the private-module convention here —
/// `clippy::redundant_pub_crate` forbids `pub(crate)` in this non-`pub` module;
/// the helper is not FFI-exported (reconciled via the cross-layer PR-body marker,
/// like the sibling async transport helpers).
pub async fn keep_broadcast_failure(
    cell: &mut crate::context::actor::class_s::ClassSCell,
    deps: &ActorDeps,
    context_id: &str,
    failure: BroadcastFailure,
) -> Result<(), ContextError> {
    cell.commit_class_s_keep(deps, context_id, |mut view| {
        apply_broadcast_failure(view.commit_broadcast_borrows(), deps, context_id, failure);
        Ok(())
    })
    .await
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
/// per-actor `EvaluatePeriodicConsequences` body is also invoked
/// directly (Phase 4) by the ACTOR-OWNED governance-timeout sweep
/// ([`handlers::governance::evaluate_governance_timeouts`](crate::context::actor::handlers::governance),
/// ADR-049 finding A3), so this supervisor-scope bulk sweep is only
/// needed for FFI bridge "evaluate now" operations or test fixtures that
/// drive deterministic ticks.
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

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    // Test-only capturing persistence: the `Mutex<Option<ContextSnapshot>>` is
    // never held across `.await` (the write is a synchronous store inside the
    // trait method), so a plain `std::sync::Mutex` is the right outlet. The
    // runtime's actor path bans it (ADR-049); test fixtures are exempt, mirroring
    // the sibling `CapturingPersistence` in `lifecycle_helpers.rs`.
    clippy::disallowed_types
)]
mod commit_broadcast_retry_tests {
    //! ADR-049 Decision 7, PR-3: pins the retry-queue bookkeeping split out of
    //! the (now async) MLS-Commit broadcast.
    //!
    //! [`try_broadcast_commit`] performs ONLY the async transport send and, on
    //! failure, builds a [`BroadcastFailure`] payload (it touches no state); the
    //! synchronous [`apply_broadcast_failure`] applies that payload to the three
    //! disjoint Class-C fields, preserving the `MAX_PENDING_COMMITS` cap →
    //! `commit_fault` fail-close conversion; [`keep_broadcast_failure`] rides a
    //! second `commit_class_s_keep` so the safety-gated call sites persist the
    //! marker + retry entry FAIL-CLOSED (§9 / §9.9.3).
    //!
    //! NOTE (coverage boundary): the full call sites
    //! ([`execute_remove_member`], [`execute_rotate_content_keys`],
    //! [`recovery_advance_epoch`], [`leave_context`]) cannot be driven end-to-end
    //! here — under the `cfg(test)` no-crypto pipeline the MLS Commit serializes
    //! to EMPTY bytes, so `try_broadcast_commit` short-circuits to `None` and
    //! never reaches the fail-closed enqueue. These tests therefore exercise the
    //! extracted helpers directly with a manufactured `BroadcastFailure` (the
    //! payload a real failed broadcast produces) plus a real failing transport,
    //! and drive `keep_broadcast_failure` against a real `ClassSCell` +
    //! failing/succeeding persistence to pin the fail-closed durability.
    //!
    //! This is an ACCEPTED boundary, stated honestly: the surrounding
    //! governance/remove/rotate/leave suites run under the SAME `cfg(test)`
    //! no-crypto pipeline, so their Commits also serialize to empty bytes and
    //! `try_broadcast_commit` short-circuits to `None` — they exercise only the
    //! happy-path invocation of the broadcast helper, NOT the
    //! failure→`keep_broadcast_failure` routing. Consequently the fail-closed
    //! HELPER semantics (enqueue, cap→`commit_fault`, fail-closed persist) are
    //! FULLY pinned by these unit tests, but each safety-gated SITE's CHOICE of
    //! `keep_broadcast_failure` over the coalesced
    //! `apply_broadcast_failure(class_c_view())` on the failure path is guarded
    //! by CODE REVIEW — not structurally by a test — because the no-crypto
    //! pipeline cannot manufacture the non-empty Commit those sites would need to
    //! reach the failure branch.

    use std::collections::VecDeque;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    use scp_did::DID;
    use scp_protocol::context::builder::ContextCreationError;
    use scp_protocol::context::membership::{ContextEvent, ReceiveBuffer};
    use scp_protocol::context::{ContextError, ContextParams};

    use super::{
        CommitBroadcastBorrows, apply_broadcast_failure, keep_broadcast_failure,
        try_broadcast_commit,
    };
    use crate::context::actor::class_s::ClassSCell;
    use crate::context::actor::deps::ActorDeps;
    use crate::context::actor::state::PerContextState;
    use crate::context::builder::{ContextEventLogProvider, ContextTransportProvider};
    use crate::context::persistence::ContextPersistence;
    use crate::context::state::{
        CommitFaultMarker, CommitOperation, MAX_PENDING_COMMITS, PendingCommit,
    };

    const ADMIN: &str = "did:dht:z6MkAdminBroadcastRetry";
    const TARGET: &str = "did:dht:z6MkTargetBroadcastRetry";
    const CTX_BYTE: u8 = 0x7d;

    /// 64-hex context id matching `[CTX_BYTE; 32]` (the form the code under test
    /// hashes for the routing id and keys the persisted snapshot under).
    fn ctx_hex() -> String {
        hex::encode([CTX_BYTE; 32])
    }

    /// A transport that records every `send_message` call and either fails or
    /// succeeds it, deterministically. `fail == true` mirrors an unreachable
    /// relay (the case that produces a `BroadcastFailure`).
    struct RecordingTransport {
        sends: Arc<AtomicUsize>,
        fail: bool,
    }

    #[async_trait::async_trait]
    impl ContextTransportProvider for RecordingTransport {
        fn is_connected(&self) -> bool {
            !self.fail
        }
        async fn publish_context(
            &self,
            _: &[u8; 32],
            _: &ContextParams,
        ) -> Result<(), ContextCreationError> {
            Ok(())
        }
        async fn delete_published(&self, _: &[u8; 32]) -> Result<(), ContextCreationError> {
            Ok(())
        }
        async fn send_message(&self, _: &[u8; 32], _: &[u8]) -> Result<(), ContextError> {
            self.sends.fetch_add(1, Ordering::SeqCst);
            if self.fail {
                Err(ContextError::TransportFailed("induced send failure".into()))
            } else {
                Ok(())
            }
        }
    }

    /// Minimal event-log provider whose reads are empty (mirrors the sibling
    /// `TestEventLog` fixtures).
    struct TestEventLog;
    #[async_trait::async_trait]
    impl ContextEventLogProvider for TestEventLog {
        async fn init_event_log(&self, _: &[u8; 32]) -> Result<(), ContextCreationError> {
            Ok(())
        }
        async fn append_event(
            &self,
            _: &[u8; 32],
            _event_type: scp_event_log::EventType,
            _actor_did: &str,
            _payload: scp_event_log::EventPayload,
            _timestamp_secs: u64,
        ) -> Result<(), ContextCreationError> {
            Ok(())
        }
        async fn destroy_event_log(&self, _: &[u8; 32]) -> Result<(), ContextCreationError> {
            Ok(())
        }
    }

    /// Persistence whose every `persist_context` SUCCEEDS, counting calls and
    /// capturing the LAST persisted snapshot — lets the fail-closed keep test
    /// assert the marker was actually persisted before `keep_broadcast_failure`
    /// returned `Ok`, and that the retry entry is IN the persisted snapshot (not
    /// merely that a persist happened).
    struct CountingOkPersistence {
        persists: Arc<AtomicUsize>,
        last_snapshot: Arc<Mutex<Option<crate::context::state::ContextSnapshot>>>,
    }
    #[async_trait::async_trait]
    impl ContextPersistence for CountingOkPersistence {
        async fn persist_context(
            &self,
            _: &str,
            snapshot: &crate::context::state::ContextSnapshot,
        ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
            self.persists.fetch_add(1, Ordering::SeqCst);
            *self.last_snapshot.lock().unwrap() = Some(snapshot.clone());
            Ok(())
        }
        async fn load_context(
            &self,
            _: &str,
        ) -> Result<
            Option<crate::context::state::ContextSnapshot>,
            Box<dyn std::error::Error + Send + Sync>,
        > {
            Ok(None)
        }
        async fn delete_context(
            &self,
            _: &str,
        ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
            Ok(())
        }
        async fn list_persisted_contexts(
            &self,
        ) -> Result<Vec<String>, Box<dyn std::error::Error + Send + Sync>> {
            Ok(Vec::new())
        }
    }

    /// Persistence whose every `persist_context` FAILS — the fail-closed path.
    struct FailPersistence;
    #[async_trait::async_trait]
    impl ContextPersistence for FailPersistence {
        async fn persist_context(
            &self,
            _: &str,
            _: &crate::context::state::ContextSnapshot,
        ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
            Err("induced persist failure".into())
        }
        async fn load_context(
            &self,
            _: &str,
        ) -> Result<
            Option<crate::context::state::ContextSnapshot>,
            Box<dyn std::error::Error + Send + Sync>,
        > {
            Ok(None)
        }
        async fn delete_context(
            &self,
            _: &str,
        ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
            Ok(())
        }
        async fn list_persisted_contexts(
            &self,
        ) -> Result<Vec<String>, Box<dyn std::error::Error + Send + Sync>> {
            Ok(Vec::new())
        }
    }

    /// Assemble an `ActorDeps` wired with the supplied transport and persistence
    /// (and the minimal in-memory event log + MLS storage), mirroring the
    /// `class_s`/`governance` fail-closed test fixtures.
    async fn build_deps(
        transport: Box<dyn ContextTransportProvider>,
        persistence: Box<dyn ContextPersistence>,
    ) -> ActorDeps {
        use crate::context::supervisor::supervisor::Supervisor;
        use scp_platform::in_memory::InMemoryStorage;

        let crypto = Arc::new(crate::crypto::mls::provider::NodeMlsFactory::new(
            ADMIN.to_owned(),
            Arc::new(scp_clock::SystemClock),
        ));
        let event_log: Box<dyn ContextEventLogProvider> = Box::new(TestEventLog);
        let key_resolver: scp_protocol::context::governance::KeyResolver = Arc::new(|_, _| None);
        let mls_storage: Arc<dyn crate::crypto::mls::storage_adapter::OpenMlsStorageAdapter> =
            Arc::new(
                crate::crypto::mls::storage_adapter::SpawnBlockingStorageAdapter::new(Arc::new(
                    InMemoryStorage::new(),
                )),
            );
        let clock: Arc<dyn scp_clock::Clock> = Arc::new(scp_clock::TestClock::new(1_700_000_000));
        let supervisor = Supervisor::with_providers(
            crypto,
            transport,
            event_log,
            key_resolver,
            Some(persistence),
            None,
            None,
            Some(clock),
            mls_storage,
        );
        supervisor
            .build_actor_deps(&DID(ADMIN.to_owned()))
            .await
            .expect("build_actor_deps")
    }

    /// `execute_reconfigure_governance` appends TWO durable leaves —
    /// `GovernanceReconfigured` and its `GovernanceDeadlockRecovery` companion
    /// — so `checkpoint_events_since` must advance by TWO. Crediting one drifts
    /// the §9.9.3 checkpoint position by a leaf per deadlock recovery.
    #[tokio::test]
    async fn reconfigure_governance_credits_both_durable_leaves() {
        use scp_protocol::context::governance::{DeadlockJustification, GovernanceReconfigAction};

        let deps = build_deps(
            Box::new(RecordingTransport {
                sends: Arc::new(AtomicUsize::new(0)),
                fail: false,
            }),
            Box::new(CountingOkPersistence {
                persists: Arc::new(AtomicUsize::new(0)),
                last_snapshot: Arc::new(Mutex::new(None)),
            }),
        )
        .await;
        let mut state = fresh_state();
        state
            .handle
            .transition_to(&scp_protocol::context::ContextState::Active)
            .expect("activate");
        state.governance.class_s.threshold_signers = vec![
            DID(ADMIN.to_owned()),
            DID(TARGET.to_owned()),
            DID("did:dht:z6MkThirdSigner".to_owned()),
        ];
        state.governance.class_s.threshold_value = 2;
        let mut cell = ClassSCell::new(state);
        *cell.class_c_view().checkpoint_events_since_mut() = 0;

        super::execute_reconfigure_governance(
            &mut cell,
            &deps,
            &ctx_hex(),
            &[GovernanceReconfigAction::RemoveInactiveSigner {
                did: DID(TARGET.to_owned()),
            }],
            &DeadlockJustification {
                unavailable_dids: vec![DID(TARGET.to_owned())],
                missed_windows: vec![(DID(TARGET.to_owned()), 3)],
                detected_at: 1_700_000_000,
            },
            super::CommitMeta {
                pid: [0x4d; 32],
                actor_did: ADMIN,
                timestamp_secs: 1_700_000_000,
            },
        )
        .await
        .expect("reconfigure succeeds");

        assert_eq!(
            cell.checkpoint_events_since, 2,
            "checkpoint_events_since must equal the durable-leaf count: \
             GovernanceReconfigured AND its GovernanceDeadlockRecovery companion"
        );
    }

    /// A fresh encrypted test state with an empty pending-commit queue.
    fn fresh_state() -> PerContextState {
        PerContextState::new_for_test_encrypted(
            [CTX_BYTE; 32],
            1_700_000_000,
            DID(ADMIN.to_owned()),
        )
    }

    fn remove_op() -> CommitOperation {
        CommitOperation::RemoveMember {
            target_did: DID(TARGET.to_owned()),
        }
    }

    /// Produce a real `BroadcastFailure` by driving `try_broadcast_commit`
    /// against a failing transport — the exact payload a failed broadcast hands
    /// the caller to apply.
    async fn make_failure(deps: &ActorDeps, op: &CommitOperation) -> super::BroadcastFailure {
        try_broadcast_commit(deps, &ctx_hex(), b"commit-bytes".to_vec(), op)
            .await
            .expect("failing transport yields Some(BroadcastFailure)")
    }

    // -- Test 1: normal enqueue -------------------------------------------

    /// At normal capacity `apply_broadcast_failure` pushes exactly one retry
    /// entry, leaves `commit_fault` clear, and surfaces the local
    /// `CommitBroadcastPending` event.
    #[tokio::test]
    async fn apply_broadcast_failure_enqueues_at_normal_capacity() {
        let deps = build_deps(
            Box::new(RecordingTransport {
                sends: Arc::new(AtomicUsize::new(0)),
                fail: true,
            }),
            Box::new(FailPersistence),
        )
        .await;
        let op = remove_op();
        let failure = make_failure(&deps, &op).await;

        let mut pending: VecDeque<PendingCommit> = VecDeque::new();
        let mut commit_fault: Option<CommitFaultMarker> = None;
        let mut receive_buffer = ReceiveBuffer::new();

        apply_broadcast_failure(
            CommitBroadcastBorrows {
                pending_commits: &mut pending,
                commit_fault: &mut commit_fault,
                receive_buffer: &mut receive_buffer,
            },
            &deps,
            &ctx_hex(),
            failure,
        );

        assert_eq!(pending.len(), 1, "exactly one retry entry enqueued");
        assert_eq!(
            pending[0].operation, op,
            "the enqueued entry carries the source operation"
        );
        assert_eq!(pending[0].retry_count, 1, "first failure ⇒ retry_count 1");
        assert!(
            commit_fault.is_none(),
            "commit_fault stays clear below the queue cap"
        );
        assert!(
            receive_buffer
                .drain()
                .iter()
                .any(|e| matches!(e, ContextEvent::CommitBroadcastPending { .. })),
            "a local CommitBroadcastPending event is surfaced"
        );
    }

    // -- Test 2: queue-full → commit_fault --------------------------------

    /// A full queue converts the enqueue into a fail-close `CommitFaultMarker`
    /// (queue-full reason) WITHOUT growing the queue — pins the cap logic that
    /// moved into `apply_broadcast_failure`.
    #[tokio::test]
    async fn apply_broadcast_failure_full_queue_sets_commit_fault() {
        let deps = build_deps(
            Box::new(RecordingTransport {
                sends: Arc::new(AtomicUsize::new(0)),
                fail: true,
            }),
            Box::new(FailPersistence),
        )
        .await;
        let failure = make_failure(&deps, &remove_op()).await;

        // Pre-fill the queue to exactly the cap. The fillers carry a DIFFERENT
        // operation variant (`RotateContentKeys`) than the injected failure
        // (`RemoveMember`), so the `commit_fault` marker's `operation` assertion
        // below actually proves provenance — that the marker carries the DROPPED
        // operation, not a filler.
        let filler = PendingCommit {
            commit_bytes: vec![0x01, 0x02, 0x03],
            routing_id: [0u8; 32],
            operation: CommitOperation::RotateContentKeys { reason: None },
            first_attempt_at: 1_700_000_000,
            retry_count: 1,
            last_error: None,
            next_attempt_at: 1_700_000_001,
        };
        let mut pending: VecDeque<PendingCommit> = VecDeque::new();
        for _ in 0..MAX_PENDING_COMMITS {
            pending.push_back(filler.clone());
        }
        assert_eq!(
            pending.len(),
            MAX_PENDING_COMMITS,
            "queue seeded at the cap"
        );

        let mut commit_fault: Option<CommitFaultMarker> = None;
        let mut receive_buffer = ReceiveBuffer::new();

        apply_broadcast_failure(
            CommitBroadcastBorrows {
                pending_commits: &mut pending,
                commit_fault: &mut commit_fault,
                receive_buffer: &mut receive_buffer,
            },
            &deps,
            &ctx_hex(),
            failure,
        );

        assert_eq!(
            pending.len(),
            MAX_PENDING_COMMITS,
            "a full queue must NOT grow past the cap"
        );
        let marker = commit_fault.expect("a full queue converts the enqueue to a commit_fault");
        assert!(
            marker.reason.contains("queue full"),
            "the fault records the queue-full reason; got {:?}",
            marker.reason
        );
        assert_eq!(
            marker.operation,
            remove_op(),
            "the fault carries the DROPPED operation (RemoveMember), not a filler \
             (RotateContentKeys) — proving marker provenance"
        );
        assert!(
            receive_buffer
                .drain()
                .iter()
                .any(|e| matches!(e, ContextEvent::CommitBroadcastFailed { .. })),
            "a local CommitBroadcastFailed event is surfaced on queue-full"
        );
    }

    // -- Test 3: try_broadcast_commit outcomes ----------------------------

    /// A transport-send error yields `Some(BroadcastFailure)` whose label
    /// matches the operation, after exactly one send attempt.
    #[tokio::test]
    async fn try_broadcast_commit_returns_failure_on_transport_error() {
        let sends = Arc::new(AtomicUsize::new(0));
        let deps = build_deps(
            Box::new(RecordingTransport {
                sends: Arc::clone(&sends),
                fail: true,
            }),
            Box::new(FailPersistence),
        )
        .await;
        let op = CommitOperation::RotateContentKeys { reason: None };

        let failure = try_broadcast_commit(&deps, &ctx_hex(), b"bytes".to_vec(), &op)
            .await
            .expect("transport error yields Some(BroadcastFailure)");

        assert_eq!(
            failure.label,
            op.label(),
            "the surfaced label matches operation.label()"
        );
        assert_eq!(
            failure.pending.operation, op,
            "the retry payload carries the source operation"
        );
        assert_eq!(
            sends.load(Ordering::SeqCst),
            1,
            "exactly one send attempted"
        );
    }

    /// A successful send yields `None` after exactly one send attempt.
    #[tokio::test]
    async fn try_broadcast_commit_returns_none_on_success() {
        let sends = Arc::new(AtomicUsize::new(0));
        let deps = build_deps(
            Box::new(RecordingTransport {
                sends: Arc::clone(&sends),
                fail: false,
            }),
            Box::new(FailPersistence),
        )
        .await;

        let out = try_broadcast_commit(
            &deps,
            &ctx_hex(),
            b"bytes".to_vec(),
            &CommitOperation::RecoveryAdvanceEpoch,
        )
        .await;

        assert!(out.is_none(), "a successful broadcast yields None");
        assert_eq!(
            sends.load(Ordering::SeqCst),
            1,
            "exactly one send attempted"
        );
    }

    /// Empty commit bytes short-circuit to `None` WITHOUT attempting any send
    /// (the `cfg(test)` no-crypto pipeline).
    #[tokio::test]
    async fn try_broadcast_commit_skips_empty_bytes_without_sending() {
        let sends = Arc::new(AtomicUsize::new(0));
        let deps = build_deps(
            Box::new(RecordingTransport {
                sends: Arc::clone(&sends),
                fail: true,
            }),
            Box::new(FailPersistence),
        )
        .await;

        let out = try_broadcast_commit(&deps, &ctx_hex(), Vec::new(), &remove_op()).await;

        assert!(out.is_none(), "empty commit bytes is a no-op");
        assert_eq!(
            sends.load(Ordering::SeqCst),
            0,
            "no send is attempted for empty commit bytes"
        );
    }

    // -- Test 4: keep_broadcast_failure fail-closed durability ------------

    /// `keep_broadcast_failure` persists the retry entry FAIL-CLOSED: when the
    /// persist succeeds it returns `Ok`, the marker is durable (persist ran),
    /// and the entry is enqueued in the cell's `pending_commits`.
    #[tokio::test]
    async fn keep_broadcast_failure_persists_retry_entry_before_ok() {
        let persists = Arc::new(AtomicUsize::new(0));
        let last_snapshot = Arc::new(Mutex::new(None));
        let deps = build_deps(
            Box::new(RecordingTransport {
                sends: Arc::new(AtomicUsize::new(0)),
                fail: true,
            }),
            Box::new(CountingOkPersistence {
                persists: Arc::clone(&persists),
                last_snapshot: Arc::clone(&last_snapshot),
            }),
        )
        .await;
        let failure = make_failure(&deps, &remove_op()).await;
        let mut cell = ClassSCell::new(fresh_state());

        let result = keep_broadcast_failure(&mut cell, &deps, &ctx_hex(), failure).await;

        assert!(
            result.is_ok(),
            "a successful fail-closed persist returns Ok"
        );
        assert_eq!(
            persists.load(Ordering::SeqCst),
            1,
            "the retry entry was persisted (fail-closed) before returning Ok"
        );
        let snapshot = last_snapshot
            .lock()
            .unwrap()
            .clone()
            .expect("a snapshot was captured by the persist");
        assert_eq!(
            snapshot.pending_commits.len(),
            1,
            "the retry entry is actually IN the persisted snapshot, not merely \
             that a persist happened"
        );
        assert_eq!(
            cell.pending_commits.len(),
            1,
            "the retry entry is enqueued in the cell"
        );
        assert!(
            cell.commit_fault.is_none(),
            "a normal enqueue leaves commit_fault clear"
        );
    }

    /// A FAILING persist inside `keep_broadcast_failure` surfaces
    /// `PersistenceFailed` (never a silent `Ok`) AND retains the retry entry in
    /// memory (keep-direction) so the coalesced tick re-attempts the write —
    /// the fail-closed guarantee the async-broadcast split had to restore.
    #[tokio::test]
    async fn keep_broadcast_failure_surfaces_persist_error_and_retains_entry() {
        let deps = build_deps(
            Box::new(RecordingTransport {
                sends: Arc::new(AtomicUsize::new(0)),
                fail: true,
            }),
            Box::new(FailPersistence),
        )
        .await;
        let failure = make_failure(&deps, &remove_op()).await;
        let mut cell = ClassSCell::new(fresh_state());

        let result = keep_broadcast_failure(&mut cell, &deps, &ctx_hex(), failure).await;

        assert!(
            matches!(result, Err(ContextError::PersistenceFailed(_))),
            "a failing fail-closed persist must surface PersistenceFailed, not Ok; got {result:?}"
        );
        assert_eq!(
            cell.pending_commits.len(),
            1,
            "the retry entry is RETAINED in memory (keep-direction) after the persist failure"
        );
        assert!(
            cell.commit_fault.is_none(),
            "a persist failure must NOT spuriously trip the safety gate — only a \
             full retry queue or retry exhaustion sets commit_fault (parity with \
             the normal-capacity path)"
        );
    }

    // -- Test 5 (unit-level recovery fail-close) --------------------------

    /// The §9.12 post-compromise recovery epoch-advance commit rides the SAME
    /// retry queue: a failed `RecoveryAdvanceEpoch` broadcast enqueues a pending
    /// entry tagged `RecoveryAdvanceEpoch`. (The full `recovery_advance_epoch`
    /// call site cannot be driven under the `cfg(test)` no-crypto pipeline — the
    /// Commit serializes to empty bytes and short-circuits before the enqueue;
    /// see the module NOTE. This pins the operation-tag invariant on the path
    /// that IS reachable.)
    #[tokio::test]
    async fn recovery_advance_epoch_failure_enqueues_recovery_tagged_entry() {
        let deps = build_deps(
            Box::new(RecordingTransport {
                sends: Arc::new(AtomicUsize::new(0)),
                fail: true,
            }),
            Box::new(FailPersistence),
        )
        .await;
        let failure = try_broadcast_commit(
            &deps,
            &ctx_hex(),
            b"recovery-commit".to_vec(),
            &CommitOperation::RecoveryAdvanceEpoch,
        )
        .await
        .expect("failing transport yields Some(BroadcastFailure)");

        let mut pending: VecDeque<PendingCommit> = VecDeque::new();
        let mut commit_fault: Option<CommitFaultMarker> = None;
        let mut receive_buffer = ReceiveBuffer::new();

        apply_broadcast_failure(
            CommitBroadcastBorrows {
                pending_commits: &mut pending,
                commit_fault: &mut commit_fault,
                receive_buffer: &mut receive_buffer,
            },
            &deps,
            &ctx_hex(),
            failure,
        );

        assert_eq!(
            pending.len(),
            1,
            "the recovery commit is enqueued for retry"
        );
        assert_eq!(
            pending[0].operation,
            CommitOperation::RecoveryAdvanceEpoch,
            "the enqueued retry entry is tagged RecoveryAdvanceEpoch"
        );
        assert!(
            commit_fault.is_none(),
            "commit_fault stays clear below the queue cap"
        );
    }

    // -- F1: promotion persists FAIL-CLOSED, keep-direction -----------------

    /// F1 (promotion persists FAIL-CLOSED): a promotion whose durable persist
    /// FAILS must SURFACE the error to the caller (not swallow it best-effort),
    /// while KEEPING the promotion in memory (keep-direction). The retired
    /// best-effort path returned `Ok` on a silent persist failure, leaving a
    /// stale `params.ttl = Some` snapshot on disk that a crash+restart would
    /// re-arm — destroying the keys of a context members unanimously voted
    /// permanent (ADR-049 §9 fail-DANGEROUS direction). Routing the mutation
    /// through `commit_class_s_keep` makes the failure observable AND retains the
    /// disarmed/promoted in-memory state so a successful re-persist carries it.
    #[tokio::test]
    async fn promote_context_persist_failure_is_fail_closed_and_kept() {
        use scp_protocol::context::ContextState;
        use scp_protocol::context::params::{MemoryScope, PromotionPolicy};

        let deps = build_deps(
            Box::new(RecordingTransport {
                sends: Arc::new(AtomicUsize::new(0)),
                fail: false,
            }),
            Box::new(FailPersistence),
        )
        .await;

        // Active, Promotable, finite ttl with an armed absolute deadline — the
        // exact shape whose promotion, if lost, would re-arm on restart.
        let mut state = fresh_state();
        state.handle = crate::context::ContextHandle::new(
            ctx_hex(),
            ContextParams {
                promotion_policy: PromotionPolicy::Promotable,
                ttl: Some(std::time::Duration::from_secs(500)),
                ..Default::default()
            },
        );
        state
            .handle
            .transition_to(&ContextState::Active)
            .expect("Creating → Active is a valid transition");
        state.ttl.timer.deadline_unix_secs = Some(1_700_000_500);
        let mut cell = ClassSCell::new(state);

        let meta = super::CommitMeta {
            pid: [0u8; 32],
            actor_did: ADMIN,
            timestamp_secs: 1_700_000_000,
        };
        // Empty membership ⇒ unanimity is trivially satisfied with no approvals.
        let result = super::execute_promote_context(&mut cell, &deps, &ctx_hex(), &[], meta).await;

        assert!(
            matches!(result, Err(ContextError::PersistenceFailed(_))),
            "a promotion whose persist fails must surface fail-closed (F1), got {result:?}"
        );
        // Keep-direction: the promotion is RETAINED in memory so a re-persist
        // carries it — it is NOT rolled back to a re-armable `ttl = Some` state.
        assert_eq!(
            cell.handle.params().ttl,
            None,
            "promotion kept: params.ttl cleared (the SOLE prune-immune disarm authority)"
        );
        assert_eq!(
            cell.handle.params().memory_scope,
            MemoryScope::Full,
            "promotion kept: memory_scope → Full"
        );
        assert_eq!(
            cell.ttl.timer.deadline_unix_secs, None,
            "promotion kept: the armed absolute deadline is disarmed in memory"
        );
    }
}
