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
//! Phase 2A.8 lands as a multi-commit ladder. The opening commit
//! scaffolds a complete byte-identical legacy twin module
//! ([`crate::context::governance_helpers_legacy`]) and rewires every
//! shim caller (handler `dispatch_from_shim`, supervisor passthroughs,
//! lifecycle helpers, messaging helpers legacy) to consume the legacy
//! variants. This module gradually fills with actor-shape helpers as
//! each entry-point is migrated. Subsequent commits in this Phase 2A.8
//! ladder migrate the remaining transitive helpers + entry points and
//! rewire the actor-shape `handlers::governance::dispatch` arm to call
//! them.
//!
//! # Currently-migrated helpers (this commit)
//!
//! - [`check_commit_fault_marker`] — fail-close gate for any helper
//!   that touches per-context state. The actor-shape `messaging_helpers`
//!   already calls it via `state.commit_fault.as_ref()`.
//! - [`get_proposal`] — read a single proposal from the engine.
//! - [`list_proposals`] — enumerate every proposal tracked by the
//!   engine.
//! - [`migration_state`] — snapshot the current migration metadata, if
//!   any.
//! - [`tombstone_migrated_context`] — terminal state transition after
//!   migration grace expiry.
//! - [`acknowledge_commit_fault`] — clear the fail-close marker.
//!
//! Once all 14 entry points + transitive helpers are migrated,
//! Phase 2A finalization deletes
//! [`crate::context::governance_helpers_legacy`] and the supervisor's
//! `dispatch_from_shim` fallback in one swoop.

use scp_protocol::context::ContextError;
use scp_protocol::context::ContextState;
use scp_protocol::context::governance::{GovernanceProposal, ProposalId};
use scp_protocol::context::membership::ContextEvent;
use tracing::instrument;

use crate::context::actor::deps::ActorDeps;
use crate::context::actor::state::PerContextState;
use crate::context::state::{CommitFaultMarker, MigrationState, context_id_to_bytes};

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

// ---------------------------------------------------------------------------
// get_proposal (entry point — read)
// ---------------------------------------------------------------------------

/// Fetch a single governance proposal by ID.
///
/// Actor-shape: reads directly from `state.governance.engine`. Sync —
/// the handler wraps the call in `async {...}` to keep the per-call
/// transport-timeout budget.
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

// ---------------------------------------------------------------------------
// list_proposals (entry point — read)
// ---------------------------------------------------------------------------

/// Enumerate every governance proposal tracked by the context's engine.
///
/// Returns both pending and resolved proposals. Engines only retain
/// proposals in memory; for durable access, proposals should be
/// queried from the event log.
///
/// Actor-shape: reads directly from `state.governance.engine`. Sync.
#[must_use]
pub fn list_proposals(state: &PerContextState) -> Vec<GovernanceProposal> {
    state.governance.engine.list_proposals()
}

// ---------------------------------------------------------------------------
// migration_state (entry point — read)
// ---------------------------------------------------------------------------

/// Snapshot the current migration metadata for the context, if any.
///
/// Actor-shape: reads directly from `state.migration_state`. Sync —
/// no provider lookups, no locks. Returns `None` when no migration is
/// in flight.
#[must_use]
pub fn migration_state(state: &PerContextState) -> Option<MigrationState> {
    state.migration_state.clone()
}

// ---------------------------------------------------------------------------
// tombstone_migrated_context (entry point — mutation)
// ---------------------------------------------------------------------------

/// Tombstone a context after migration grace period expiry (§5.11A.5).
///
/// Transitions the context from `MigratingOut` to `Tombstoned`,
/// cancels timers, drops broadcast state, clears migration metadata,
/// and emits both a receive-buffer event and a durable Merkle log
/// entry. Called by the application layer when grace expiry is
/// detected.
///
/// Actor-shape: actor owns `state` for the entire operation, so the
/// legacy two-phase lock dance collapses to a single linear sequence.
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

    // Check grace period has expired.
    if now < migration.grace_period_end {
        return Err(ContextError::PermissionDenied(format!(
            "migration grace period has not expired (ends at {}, now {})",
            migration.grace_period_end, now
        )));
    }

    let destination_id = migration.destination_context_id.clone();
    let migration_pid = migration.proposal_id;

    // Transition to Tombstoned. Actor owns state — no relock needed.
    state
        .handle
        .transition_to(&ContextState::Tombstoned)
        .await
        .map_err(|_| {
            ContextError::PermissionDenied(
                "cannot transition from MigratingOut to Tombstoned".to_owned(),
            )
        })?;

    // Emit tombstone event into the actor-owned receive buffer.
    let tombstone_event = ContextEvent::ContextTombstoned {
        destination_context_id: destination_id.clone(),
        migration_proposal_id: migration_pid,
    };
    crate::context::state::emit_event_into(
        &mut state.receive_buffer,
        tombstone_event,
        context_id,
        deps.event_tx.as_ref(),
    );

    // Cancel TTL timer and governance timeout task.
    state.ttl.timer.cancel();
    state.governance.timeout_task.cancel();
    // Drop broadcast context state.
    state.broadcast_context = None;
    // Clear migration state.
    state.migration_state = None;
    // M7: Participation decay on tombstone (#1530).
    state.governance.decay_participation();

    // Best-effort persist before logging — keeps the durable log entry
    // strictly after any storage flush, mirroring the legacy ordering.
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
/// Operator-driven recovery path. Does NOT re-attempt the failed
/// commit — that data is already lost (or unrecoverable from the
/// local node's perspective). Callers SHOULD reach out to remaining
/// members through an out-of-band channel to verify whether the
/// failed commit's effect needs to be re-applied.
///
/// Actor-shape: takes the marker straight off `state.commit_fault`.
/// Sync.
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
