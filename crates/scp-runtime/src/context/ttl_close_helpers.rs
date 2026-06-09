// Read-only actor helpers still take `&mut PerContextState` so their
// handler futures capture `&mut T` (`T: Send`) rather than `&T`
// (`T: Sync` required). `PerContextState` is intentionally Send + !Sync.
#![allow(clippy::needless_pass_by_ref_mut)]

//! TTL-close helpers — actor-shape signatures
//! (ADR-049 Phase 2A.6, TTL subset of `lifecycle_helpers.rs`).
//!
//! # Purpose
//!
//! This module hosts the TTL-domain helpers that the actor handler in
//! [`crate::context::actor::handlers::ttl_close`] calls to implement
//! [`TtlCloseCommand`](crate::context::actor::commands::TtlCloseCommand).
//! Helpers operate on actor-owned
//! [`PerContextState`](crate::context::actor::state::PerContextState)
//! and capability-reduced
//! [`ActorDeps`](crate::context::actor::deps::ActorDeps); the legacy
//! `&Supervisor` lock-and-call bodies live in
//! [`crate::context::ttl_close_helpers_legacy`] for the supervisor
//! shim-fallback path.
//!
//! # `spawn_ttl_timer` ownership (actor registry + mailbox tick)
//!
//! [`spawn_ttl_timer`] owns the per-context TTL timer task end-to-end on
//! actor-owned state. It runs against `&mut state` (so it owns the
//! `state.ttl.timer` cancel `Notify` + `AbortHandle`), spawns the timer
//! task onto the supervisor's tracked `task_set` via
//! [`SupervisorHandle::tracked_spawn`](crate::context::supervisor::handle::SupervisorHandle::tracked_spawn),
//! and the task — holding no `&Supervisor` and reading no `DashMap` —
//! resolves the owning actor through
//! [`SupervisorHandle::lookup`](crate::context::supervisor::handle::SupervisorHandle::lookup)
//! on each wake and mailboxes
//! [`TtlCloseCommand::FireTimer`](crate::context::actor::commands::TtlCloseCommand::FireTimer).
//! A `lookup → None` (actor despawned: context gone / recreated) stops
//! the task cleanly — this replaces the legacy stale-generation gate, as
//! the actor owns its state for the whole dispatch turn so there is no
//! concurrent close-and-recreate window. This removes the
//! `spawn_ttl_timer_legacy` `DashMap` reads and the
//! [`SupervisorHandle::shim_supervisor`](crate::context::supervisor::handle::SupervisorHandle::shim_supervisor)
//! escape that [`start_ttl_timer`] / [`reset_ttl_timer`] previously used.

use std::sync::Arc;

use scp_identity::DID;
use scp_protocol::context::membership::ContextEvent;
use scp_protocol::context::{ContextError, ContextState};
use tokio::sync::Notify;

use crate::context::ContextHandle;
use crate::context::actor::deps::ActorDeps;
use crate::context::actor::state::PerContextState;
use crate::context::state::{context_id_to_bytes, strip_event_payload};
use crate::context::ttl::{self, TtlExtension};

// ---------------------------------------------------------------------------
// 1. handle_ttl_expiry
// ---------------------------------------------------------------------------

/// Handles automatic TTL expiry on actor-owned state.
///
/// State-owning signature: reads `state.handle` for the lifecycle FSM,
/// mutates `state.governance.timeout_task` and the participation cache
/// on completion, and emits `ContextExpired` / `ExpiryFailed` events
/// into `state.receive_buffer` (and the optional event-tx fan-out).
/// The MLS / transport / event-log work flows through
/// `deps.crypto` / `deps.transport` / `deps.event_log`.
///
/// # No relock / generation gate
///
/// The legacy version captured `generation` before the async cleanup,
/// dropped the per-context lock, then relocked with a generation check
/// after the cleanup. The actor owns `state` for the entire dispatch
/// turn, so the generation gate is no longer required — there is no
/// concurrent close-and-recreate window for a sibling actor to slip a
/// new context into. Persistence after the expiry is best-effort and
/// runs synchronously here (the actor's coalesced persist tick will
/// catch any subsequent mutations).
pub async fn handle_ttl_expiry(
    state: &mut PerContextState,
    deps: &ActorDeps,
    handle: &ContextHandle,
) -> Result<(), ContextError> {
    let context_id = handle.context_id().to_owned();

    // Async TTL expiry logic. Pass transport for best-effort relay
    // ciphertext deletion (§5.11).
    let result = ttl::try_ttl_expiry_cleanup(
        handle,
        deps.crypto.as_ref(),
        Some(deps.transport.as_ref()),
        deps.event_log.as_ref(),
        0,
    )
    .await;

    // Cancel governance timeout task, decay participation, and emit
    // appropriate event onto the actor's owned state. Matches the legacy
    // single-lock-acquisition shape; the actor owns `state` so no
    // re-locking is required.
    state.governance.timeout_task.cancel();
    // Participation decay on TTL expiry (#1530): clear participation
    // cache and cooldown state so stale data does not carry over if the
    // context is later restored.
    state.governance.decay_participation();
    if result.is_complete() {
        let event = ContextEvent::Expired;
        emit_event(state, event, &context_id, deps.event_tx.as_ref());
    } else {
        let event = ContextEvent::ExpiryFailed {
            reason: result.to_string(),
            state_transitioned: result.state_transitioned(),
            mls_destroyed: result.mls_destroyed(),
            sender_key_destroyed: result.sender_key_destroyed(),
            event_logged: result.event_logged(),
        };
        emit_event(state, event, &context_id, deps.event_tx.as_ref());
    }

    // Persist context state after TTL expiry (best-effort).
    persist_state_best_effort(state, deps, &context_id);

    if result.has_failures() {
        let msg = result.errors().join("; ");
        return Err(
            if !result.mls_destroyed() || !result.sender_key_destroyed() {
                ContextError::CryptoFailed(msg)
            } else {
                ContextError::EventLogFailed(msg)
            },
        );
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// 2. propose_ttl_extension
// ---------------------------------------------------------------------------

/// Proposes a TTL extension on actor-owned state.
///
/// Records consent from the given member. Returns `true` iff every
/// member has now consented (unanimous); the caller should then call
/// [`reset_ttl_timer`] with the new duration.
///
/// State-owning signature: reads `state.membership` for membership /
/// member-count lookups and mutates `state.ttl.extension` to record
/// consents. Best-effort persistence on success runs through
/// `deps.persistence`.
///
/// Synchronous because the actor owns `state` for the entire dispatch
/// turn — no lock acquisition is needed and the persistence call is
/// best-effort fire-and-forget. The handler wraps this in
/// `async { ... }` for the dispatcher's `tokio::time::timeout` budget.
pub fn propose_ttl_extension(
    state: &mut PerContextState,
    deps: &ActorDeps,
    context_id: &str,
    member_did: &DID,
    proposed_duration: std::time::Duration,
) -> Result<bool, ContextError> {
    if !state.membership.contains(member_did) {
        return Err(ContextError::MemberNotFound(member_did.to_string()));
    }

    let member_count = state.membership.count();

    // Initialize extension proposal if not already in progress.
    let extension = state
        .ttl
        .extension
        .get_or_insert_with(|| TtlExtension::new(proposed_duration, member_count));

    extension.add_consent(member_did.clone());
    let unanimous = extension.is_unanimous();

    // Persist context state after proposal consent (best-effort).
    persist_state_best_effort(state, deps, context_id);

    Ok(unanimous)
}

// ---------------------------------------------------------------------------
// 3. reset_ttl_timer
// ---------------------------------------------------------------------------

/// Resets the TTL timer after a successful unanimous extension on
/// actor-owned state.
///
/// Cancels the old timer and spawns a new one with the given duration.
/// Clears the extension proposal state.
///
/// Timer ownership is actor-local: [`spawn_ttl_timer`] aborts the prior
/// `state.ttl.timer` task and installs the replacement onto the
/// supervisor's tracked `task_set`. See the module-level doc.
pub async fn reset_ttl_timer(
    state: &mut PerContextState,
    deps: &ActorDeps,
    context_id: &str,
    new_duration: std::time::Duration,
    handle: ContextHandle,
) {
    // Clear extension state; `spawn_ttl_timer` aborts the prior task and
    // resets the cancel signal (mutate owned state).
    state.ttl.extension = None;

    spawn_ttl_timer(state, deps, context_id, new_duration, handle).await;

    // Persist context state after TTL reset (best-effort).
    persist_state_best_effort(state, deps, context_id);
}

// ---------------------------------------------------------------------------
// 4. start_ttl_timer
// ---------------------------------------------------------------------------

/// Installs a TTL timer for the given context on actor-owned state.
///
/// Delegates to [`spawn_ttl_timer`], which owns the timer task on
/// `state.ttl.timer` and reaches the supervisor's tracked `task_set` /
/// actor registry through `deps.supervisor` — see the module doc.
pub async fn start_ttl_timer(
    state: &mut PerContextState,
    deps: &ActorDeps,
    context_id: &str,
    duration: std::time::Duration,
    handle: ContextHandle,
) {
    spawn_ttl_timer(state, deps, context_id, duration, handle).await;
}

// ---------------------------------------------------------------------------
// spawn_ttl_timer (actor-owned timer task; registry + mailbox tick)
// ---------------------------------------------------------------------------

/// Spawns (or respawns) the per-context TTL timer on actor-owned state.
///
/// The actor-shape TTL timer holds no `&Supervisor` and reads no
/// `contexts` `DashMap`. On wake it resolves the owning actor via
/// [`SupervisorHandle::lookup`](crate::context::supervisor::handle::SupervisorHandle::lookup)
/// and mailboxes
/// [`TtlCloseCommand::FireTimer`](crate::context::actor::commands::TtlCloseCommand::FireTimer),
/// which runs the actor-shape expiry pipeline on the actor's owned
/// `&mut state`. A `lookup → None` (actor despawned) stops the task —
/// this is the registry-based replacement for the legacy
/// stale-generation gate.
///
/// # Cancel / reset semantics
///
/// The cancel `Notify` and task `AbortHandle` live on actor-owned
/// `state.ttl.timer`. A reset (or a fresh start) aborts the prior task
/// and installs a fresh `Notify` so the replacement timer is cancellable
/// independently of the old one — preserving the legacy
/// abort-old + spawn-new behaviour.
///
/// # Degraded config
///
/// If the supervisor has no `task_set` (built without
/// [`with_providers`](crate::context::supervisor::Supervisor::with_providers)),
/// `tracked_spawn` returns `None` and no timer is installed — matching
/// the legacy `task_set_ref() == None` early-return.
async fn spawn_ttl_timer(
    state: &mut PerContextState,
    deps: &ActorDeps,
    context_id: &str,
    duration: std::time::Duration,
    // The legacy timer task captured `handle` to run the expiry pipeline
    // inline. The actor-shape `FireTimer` handler now clones
    // `state.handle` itself, so the task no longer needs it. Retained on
    // the signature so `start_ttl_timer` / `reset_ttl_timer` callers
    // (and their handler call sites) are unchanged.
    _handle: ContextHandle,
) {
    // Abort any prior timer task and install a fresh cancel signal so
    // the replacement timer can be cancelled independently of the old
    // one (mirrors the legacy reset's `cancel = Arc::new(Notify::new())`
    // + `task = None`).
    if let Some(prior) = state.ttl.timer.task.take() {
        prior.abort();
    }
    let cancel = Arc::new(Notify::new());
    state.ttl.timer.cancel = Arc::clone(&cancel);

    // Record absolute deadline for persistence snapshots (mirrors
    // `TtlTimer::spawn_with_transport`).
    let now_secs = deps.clock.now_secs();
    state.ttl.timer.deadline_unix_secs = Some(now_secs.saturating_add(duration.as_secs()));

    // Clone the cross-actor providers the FireTimer pipeline needs. The
    // timer task itself only resolves the actor + mailboxes FireTimer;
    // the expiry work (crypto destroy / relay delete / event log) runs
    // inside the actor handler against owned state.
    let task_supervisor = deps.supervisor.clone();
    let context_id_owned = context_id.to_owned();

    let abort_handle = deps
        .supervisor
        .tracked_spawn(async move {
            tokio::select! {
                () = tokio::time::sleep(duration) => {
                    // Timer fired. Resolve the owning actor; a despawned
                    // actor (context gone / recreated) means nothing to
                    // tick — stop cleanly (registry-based replacement for
                    // the legacy stale-generation gate).
                    let Some(actor) = task_supervisor.lookup(&context_id_owned) else {
                        return;
                    };
                    let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
                    let cmd = crate::context::actor::commands::ContextCommand::TtlClose(
                        crate::context::actor::commands::TtlCloseCommand::FireTimer {
                            reply: reply_tx,
                        },
                    );
                    if actor
                        .send_with_timeout(cmd, crate::context::actor::SEND_TIMEOUT)
                        .await
                        .is_ok()
                    {
                        // Await the actor's reply so the expiry pipeline
                        // has completed before the task exits. The bool
                        // is informational (one-shot timer — always
                        // stops after firing).
                        let _ = reply_rx.await;
                    }
                }
                () = cancel.notified() => {
                    // Timer cancelled (reset / close).
                }
            }
        })
        .await;

    // Store the abort handle for cancel / is_active checks on owned
    // state. `None` only in the degraded no-task-set config.
    state.ttl.timer.task = abort_handle;
}

// ---------------------------------------------------------------------------
// 5. finalize_close
// ---------------------------------------------------------------------------

/// Completes context closure on actor-owned state.
///
/// Destroys MLS group state and sender keys, issues relay deletion
/// requests for ephemeral/summary scopes, transitions from `Closing` to
/// `Closed`, and appends the final `ContextClosed` event.
///
/// Persisted snapshot is deleted on success (best-effort) so a later
/// restore does not resurrect the closed context.
///
/// `state` is currently not read on the success path (the lifecycle
/// transition runs through `handle.transition_to`), but is part of the
/// actor-shape contract so a future expansion can mutate per-context
/// state without changing the signature.
pub async fn finalize_close(
    _state: &mut PerContextState,
    deps: &ActorDeps,
    handle: &ContextHandle,
) -> Result<(), ContextError> {
    let context_id = handle.context_id().to_owned();

    ttl::finalize_close(
        handle,
        deps.crypto.as_ref(),
        deps.transport.as_ref(),
        deps.event_log.as_ref(),
    )
    .await?;

    // Delete persisted state after finalize (best-effort). Mirrors
    // the legacy path which only ran the delete when a persistence
    // provider was attached; ContextPersistence is always present on
    // ActorDeps so we always issue the delete.
    let _ = deps.persistence.delete_context(&context_id);

    Ok(())
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Pushes `event` onto the actor's `receive_buffer` and, when
/// configured, fans out a sanitized copy on the optional event-tx
/// channel. Mirrors the structure of
/// `broadcast_helpers::emit_event` and `state::PerContextState::emit_event`
/// — kept local so this module does not depend on the broadcast
/// helpers' private surface.
fn emit_event(
    state: &mut PerContextState,
    event: ContextEvent,
    context_id: &str,
    tx: Option<&tokio::sync::broadcast::Sender<(String, ContextEvent)>>,
) {
    if matches!(event, ContextEvent::WelcomeGenerated { .. }) {
        let _ = state.receive_buffer.push(event);
        return;
    }

    let _ = state.receive_buffer.push(event.clone());
    if let Some(tx) = tx {
        let sanitized = strip_event_payload(&event);
        let _ = tx.send((context_id.to_owned(), sanitized));
    }
}

/// Best-effort persist of the current actor state. Mirrors the legacy
/// context-snapshot persistence path, but reads fields off the actor's
/// `PerContextState` rather than the legacy lock-shaped type.
fn persist_state_best_effort(state: &PerContextState, deps: &ActorDeps, context_id: &str) {
    let mut snapshot = build_snapshot_from_state(state);

    // Export MLS crypto state alongside the context snapshot (#645).
    // On export failure, mark the snapshot `needs_reconnect = true` and
    // persist an empty crypto blob so a later restore fires the §23.11
    // reconnection pipeline.
    let ctx_id_bytes = context_id_to_bytes(context_id);
    match deps.crypto.export_crypto_state(&ctx_id_bytes) {
        Ok(crypto_state) => snapshot.mls_crypto_state = crypto_state,
        Err(e) => {
            snapshot.needs_reconnect = true;
            snapshot.mls_crypto_state = Vec::new();
            tracing::warn!(
                context_id = %context_id,
                error = %e,
                "failed to export MLS crypto state for persistence; \
                 snapshot marked needs_reconnect=true so restore \
                 fires the §23.11 reconnection pipeline"
            );
        }
    }

    if let Err(e) = deps.persistence.persist_context(context_id, &snapshot) {
        crate::metrics::record_persistence_failure();
        tracing::warn!(
            context_id = %context_id,
            error = %e,
            "failed to persist context snapshot"
        );
    }
}

/// Builds a [`ContextSnapshot`](crate::context::state::ContextSnapshot)
/// from the actor's [`PerContextState`]. Field-for-field parallel to
/// [`crate::context::manager_methods::snapshot_context`]; consumes the
/// actor-owned `PerContextState` rather than the legacy lock-shaped
/// type.
fn build_snapshot_from_state(state: &PerContextState) -> crate::context::state::ContextSnapshot {
    use crate::context::state::VelocityTrackerSnapshot;

    let context_state_value = state
        .handle
        .try_read_state()
        .unwrap_or(ContextState::Active);
    let ttl_remaining_secs = state.ttl.timer.remaining_secs();
    let grace_entries = state.epoch.grace_store.to_grace_entries();

    crate::context::state::ContextSnapshot {
        context_id: state.handle.context_id().to_owned(),
        state: context_state_value,
        context_params: state.handle.params().clone(),
        membership: state.membership.clone(),
        role_state: state.role_state.clone(),
        event_log_merkle_root: [0u8; 32],
        executed_proposals: state
            .governance
            .executed_proposals
            .keys()
            .copied()
            .collect(),
        ttl_remaining_secs,
        registered_tools: state.governance.registered_tools.clone(),
        read_exclusion_list: state.access.read_exclusion_list.clone(),
        tool_interfaces: state.governance.tool_interfaces.clone(),
        threshold_signers: state.governance.threshold_signers.clone(),
        threshold_value: state.governance.threshold_value,
        pruning_policy: state.governance.pruning_policy.clone(),
        governance_model_config: Some(state.governance.engine.model_config()),
        economic_policy: state.governance.economic_policy.clone(),
        budget_tracker: state.governance.budget_tracker.clone(),
        approved_proposals: state.governance.approved_proposals.clone(),
        next_proposal_seq: state.governance.next_proposal_seq,
        governance_freeze: state.governance.freeze,
        pending_ceiling_modification: state.governance.pending_ceiling_modification.clone(),
        pending_economic_policy_change: state.governance.pending_economic_policy_change.clone(),
        mls_epoch: state.epoch.mls_epoch,
        epoch_coordination_records: state.epoch.coordinator.records().to_vec(),
        grace_entries,
        needs_reconnect: state.epoch.needs_reconnect,
        // MLS crypto state is populated in `persist_state_best_effort`
        // where the crypto provider is available. Initialized empty here.
        mls_crypto_state: Vec::new(),
        migration_state: state.migration_state.clone(),
        access_key_store: state.access.access_key_store.clone(),
        consequence_rules: state.governance.consequence_rules.clone(),
        participation_cache: state.governance.participation_cache.clone(),
        velocity_tracker: Some(state.governance.velocity_tracker.window_secs()),
        velocity_tracker_state: Some(VelocityTrackerSnapshot {
            window_secs: state.governance.velocity_tracker.window_secs(),
            entries: state.governance.velocity_tracker.snapshot_entries(),
        }),
        cooldown_until: state.governance.cooldown_until.clone(),
        proposal_timestamps: state.governance.proposal_timestamps.clone(),
        message_pricing: state.governance.message_pricing.clone(),
        hard_rate_limit_config: Some(state.governance.hard_rate_limit.config().clone()),
        hard_rate_limit_state: state.governance.hard_rate_limit.snapshot_entries(),
        spending_nonce_tracker_state: state.governance.spending_nonce_tracker.snapshot_entries(),
        pending_commits: state.pending_commits.clone(),
        commit_fault: state.commit_fault.clone(),
        checkpoint_events_since: state.checkpoint_events_since,
        checkpoint_last_time_secs: state.checkpoint_last_time_secs,
        generation: state.generation,
        local_pseudonym: state.local_pseudonym,
        pseudonym_registry: state
            .pseudonym_registry
            .iter()
            .map(|(did, p)| (did.to_string(), *p))
            .collect(),
    }
}
