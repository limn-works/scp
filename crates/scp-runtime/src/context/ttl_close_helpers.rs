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
//! `spawn_ttl_timer_legacy` `DashMap` reads and the full-`Supervisor`
//! escape hatch that [`start_ttl_timer`] / [`reset_ttl_timer`]
//! previously used.

use std::sync::Arc;

use scp_did::DID;
use scp_protocol::context::ContextError;
use scp_protocol::context::membership::ContextEvent;
use tokio::sync::Notify;

use crate::context::ContextHandle;
use crate::context::actor::class_s::ClassSCell;
use crate::context::actor::deps::ActorDeps;
use crate::context::actor::state::PerContextState;
use crate::context::state::{context_id_to_bytes, strip_event_payload};
use crate::context::ttl::{self, TtlExtension, TtlTimer};

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
    cell: &mut ClassSCell,
    deps: &ActorDeps,
    handle: &ContextHandle,
) -> Result<(), ContextError> {
    let context_id = handle.context_id().to_owned();

    // Timer-triggered expiry: the convergent leaf timestamp is the pre-computed
    // TTL deadline held in convergent state (every member holds the identical
    // value), never local `now()` (§7.3.1, §9.9.3). Fall back to the clock only
    // if no deadline was recorded (defensive; the timer fires off a deadline).
    let expiry_deadline_secs = cell
        .ttl
        .timer
        .deadline_unix_secs
        .unwrap_or_else(|| deps.clock.now_secs());

    // Async TTL expiry logic. Pass transport for best-effort relay
    // ciphertext deletion (§5.11). Drives the lifecycle transition through
    // the `ContextHandle` FSM (Class-C; NOT a `PerContextState` Class-S
    // field), so the subsequent in-state mutations are Class-C with the
    // best-effort persist below — no Class-S combinator (ADR-049 §9).
    let result = ttl::try_ttl_expiry_cleanup(
        handle,
        deps.crypto.as_ref(),
        Some(deps.transport.as_ref()),
        deps.event_log.as_ref(),
        0,
        expiry_deadline_secs,
    )
    .await;

    // Cancel governance timeout task, decay participation, and emit
    // appropriate event onto the actor's owned state. Matches the legacy
    // single-lock-acquisition shape; the actor owns `state` so no
    // re-locking is required. All Class-C with the coalesced (best-effort)
    // persist below — routed through the non-persisting Class-C view.
    {
        let mut view = cell.class_c_view();
        let gov = view.governance_class_c_mut();
        gov.timeout_task_mut().cancel();
        // Participation decay on TTL expiry (#1530): clear participation
        // cache and cooldown state so stale data does not carry over if the
        // context is later restored. Inlines `GovernanceState::decay_participation`
        // (not exposed on the Class-C governance view) over its four Class-C
        // fields.
        gov.participation_cache_mut().clear();
        gov.cooldown_until_mut().clear();
        gov.proposal_timestamps_mut().clear();
        gov.velocity_tracker_mut().clear();
    }
    let event = if result.is_complete() {
        ContextEvent::Expired
    } else {
        ContextEvent::ExpiryFailed {
            reason: result.to_string(),
            state_transitioned: result.state_transitioned(),
            mls_destroyed: result.mls_destroyed(),
            sender_key_destroyed: result.sender_key_destroyed(),
            event_logged: result.event_logged(),
        }
    };
    emit_event(
        cell.class_c_view().receive_buffer_mut(),
        event,
        &context_id,
        deps.event_tx.as_ref(),
    );

    // Persist context state after TTL expiry (best-effort).
    persist_state_best_effort(cell, deps, &context_id);

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
    cell: &mut ClassSCell,
    deps: &ActorDeps,
    context_id: &str,
    member_did: &DID,
    proposed_duration: std::time::Duration,
) -> Result<bool, ContextError> {
    if !cell.membership.contains(member_did) {
        return Err(ContextError::MemberNotFound(member_did.to_string()));
    }

    let member_count = cell.membership.count();

    // Initialize extension proposal if not already in progress, then record
    // the consent. `ttl.extension` is Class-C with the coalesced (best-effort)
    // persist below — route through the non-persisting Class-C view (ADR-049 §9).
    let unanimous = {
        let mut view = cell.class_c_view();
        let extension = view
            .ttl_mut()
            .extension
            .get_or_insert_with(|| TtlExtension::new(proposed_duration, member_count));

        extension.add_consent(member_did.clone());
        extension.is_unanimous()
    };

    // Persist context state after proposal consent (best-effort).
    persist_state_best_effort(cell, deps, context_id);

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
    cell: &mut ClassSCell,
    deps: &ActorDeps,
    context_id: &str,
    new_duration: std::time::Duration,
    handle: ContextHandle,
) {
    // Clear extension state; `spawn_ttl_timer` aborts the prior task and
    // resets the cancel signal (mutate owned state). Both `ttl.extension`
    // and `ttl.timer` are Class-C with the coalesced (best-effort) persist
    // below — route through the non-persisting Class-C view (ADR-049 §9).
    // The view borrow spans the `spawn_ttl_timer` await (it borrows only the
    // timer) and ends before the persist's shared read.
    //
    // Reset (consensual TTL extension via `reset_ttl_timer`): no convergent
    // deadline is threaded here, so arm relative to the local clock (the prior
    // behaviour). The governance ExtendTtl path computes the convergent
    // extended deadline itself (`old_deadline + additional`) and installs it
    // through `start_ttl_timer` with an explicit override; cross-member
    // convergence of a freshly-proposed extension duration is a forward step
    // under ADR-051.
    {
        let mut view = cell.class_c_view();
        let ttl = view.ttl_mut();
        ttl.extension = None;
        spawn_ttl_timer(&mut ttl.timer, deps, context_id, new_duration, None, handle).await;
    }

    // Persist context state after TTL reset (best-effort).
    persist_state_best_effort(cell, deps, context_id);
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
    // SHARED across domains: the ttl_close actor handler passes
    // `cell.class_c_view().ttl_mut().timer` (no `state_mut`); the governance
    // `execute_extend_ttl` path passes `&mut state.ttl.timer`. Taking the
    // narrow `&mut TtlTimer` (the only state it touches, all Class-C) lets
    // both reach it without a whole `&mut PerContextState` (ADR-049 §9).
    timer: &mut TtlTimer,
    deps: &ActorDeps,
    context_id: &str,
    duration: std::time::Duration,
    // Convergent absolute expiry deadline (Unix seconds), if the caller can
    // supply one. The initial-create path passes
    // `Some(creation_timestamp_secs + params.ttl)`; the governance ExtendTtl
    // path passes its already-convergent extended deadline; the restore/import
    // path now also passes `Some(creation_timestamp_secs + ttl)`, since the
    // signed snapshot carries the convergent creator-assigned creation time and
    // both paths arm with `anchor_deadline_to_creation = true`. `None` arms
    // relative to the local clock (used only when no convergent creation time is
    // available). `duration` is always the local sleep interval.
    deadline_override: Option<u64>,
    handle: ContextHandle,
) {
    spawn_ttl_timer(timer, deps, context_id, duration, deadline_override, handle).await;
}

/// Computes the CONVERGENT initial-TTL expiry deadline (Unix seconds) for a
/// context: `creation_timestamp_secs + params.ttl`.
///
/// Both inputs are convergent across members — `creation_timestamp_secs` is the
/// creator-assigned `ContextCreated` value copied onto every member's state,
/// and `ttl_secs` is the TTL in the context params (legible to every member) —
/// so every member computes the IDENTICAL absolute deadline regardless of when
/// (or with what local clock) it armed its timer. This is the value recorded on
/// `ContextExpired`/`ContextClosed` leaves, making them convergent-by-
/// construction (§7.3.1, §9.9.3).
///
/// Returns `None` when the context has no finite TTL.
#[must_use]
pub const fn convergent_ttl_deadline_secs(
    creation_timestamp_secs: u64,
    ttl_secs: Option<u64>,
) -> Option<u64> {
    match ttl_secs {
        Some(ttl) => Some(creation_timestamp_secs.saturating_add(ttl)),
        None => None,
    }
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
    // Takes ONLY the `&mut TtlTimer` it mutates (Class-C timer state),
    // not a whole `&mut PerContextState` / `&mut ClassSCell`. This is the
    // shared-helper seam: the ttl_close actor handler reaches it through
    // `cell.class_c_view().ttl_mut()` (no `state_mut`), while the
    // governance `execute_extend_ttl` path (out of this domain's scope)
    // passes `&mut state.ttl.timer` directly — neither needs a whole
    // `&mut` (ADR-049 §9). FLAG: the narrowing changed the shared
    // `start_ttl_timer` signature, so the one governance call site is
    // updated to match.
    timer: &mut TtlTimer,
    deps: &ActorDeps,
    context_id: &str,
    duration: std::time::Duration,
    // The absolute expiry deadline (Unix seconds) to record on
    // `state.ttl.timer.deadline_unix_secs`, which becomes the
    // `ContextExpired`/`ContextClosed` leaf timestamp when the timer fires.
    // `Some(d)` installs a CONVERGENT deadline (e.g. the initial-start
    // `creation_timestamp_secs + params.ttl`, or a TTL-extension's
    // already-convergent `old_deadline + additional`); `None` falls back to
    // local arm-time `now + duration` (the prior behaviour, used only where
    // no convergent deadline is available). See each caller for which
    // applies. The local sleep below always fires after `duration` on the
    // local clock — only the recorded leaf timestamp is the convergent value.
    deadline_override: Option<u64>,
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
    let cancel = Arc::new(Notify::new());
    let deadline_secs = deadline_override
        .unwrap_or_else(|| deps.clock.now_secs().saturating_add(duration.as_secs()));
    if let Some(prior) = timer.task.take() {
        prior.abort();
    }
    timer.cancel = Arc::clone(&cancel);
    // Record the absolute expiry deadline that the timer fire will stamp
    // on the `ContextExpired`/`ContextClosed` leaf. A `deadline_override`
    // is the CONVERGENT value (see the parameter doc); only when it is
    // absent do we fall back to local arm-time `now + duration`.
    timer.deadline_unix_secs = Some(deadline_secs);

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
    timer.task = abort_handle;
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
    cell: &mut ClassSCell,
    deps: &ActorDeps,
    handle: &ContextHandle,
) -> Result<(), ContextError> {
    let context_id = handle.context_id().to_owned();

    // Convergent `ContextClosed` leaf timestamp: the pre-computed TTL deadline
    // held in convergent state when this is a timer-driven close; fall back to
    // the closer's clock for a governance/explicit close with no TTL deadline.
    // Never a per-member local `now()` for the timer case (§7.3.1, §9.9.3).
    let close_ts = cell
        .ttl
        .timer
        .deadline_unix_secs
        .unwrap_or_else(|| deps.clock.now_secs());

    ttl::finalize_close(
        handle,
        deps.crypto.as_ref(),
        deps.transport.as_ref(),
        deps.event_log.as_ref(),
        close_ts,
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
    receive_buffer: &mut scp_protocol::context::membership::ReceiveBuffer,
    event: ContextEvent,
    context_id: &str,
    tx: Option<&tokio::sync::broadcast::Sender<(String, ContextEvent)>>,
) {
    if matches!(event, ContextEvent::WelcomeGenerated { .. }) {
        let _ = receive_buffer.push(event);
        return;
    }

    let _ = receive_buffer.push(event.clone());
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
    // Single source of truth (ADR-049 §9): delegate to the canonical builder so
    // the broadcast Class-S fold and the field-round-trip tripwire cover every
    // persist path. This copy was value-identical to the canonical one.
    crate::context::messaging_helpers::build_snapshot_from_state(state)
}

#[cfg(test)]
mod tests {
    use super::convergent_ttl_deadline_secs;

    /// Two members with WILDLY different local arm-time clocks must compute the
    /// IDENTICAL absolute TTL expiry deadline, because it is derived from the
    /// convergent creation timestamp + the params TTL — not local `now()`. This
    /// is the property that makes the `ContextExpired`/`ContextClosed` leaf
    /// timestamp convergent-by-construction (§7.3.1, §9.9.3).
    #[test]
    fn ttl_deadline_converges_independent_of_arm_time_clock() {
        // Convergent inputs every member shares: the creator-assigned creation
        // timestamp and the TTL duration from the (legible) context params.
        let creation_timestamp_secs = 1_700_000_000_u64;
        let ttl_secs = 3_600_u64; // 1 hour

        // The function takes ONLY convergent inputs — there is no local-clock
        // parameter, so two members necessarily agree.
        let alice_deadline = convergent_ttl_deadline_secs(creation_timestamp_secs, Some(ttl_secs));
        let bob_deadline = convergent_ttl_deadline_secs(creation_timestamp_secs, Some(ttl_secs));

        assert_eq!(alice_deadline, bob_deadline);
        assert_eq!(alice_deadline, Some(creation_timestamp_secs + ttl_secs));
    }

    /// Negative control: deriving the deadline from each member's local
    /// arm-time clock (`now + ttl`) — the OLD behaviour — diverges when the two
    /// members' clocks differ, which is exactly what the convergent base fixes.
    #[test]
    fn local_arm_time_base_diverges_across_members() {
        let ttl_secs = 3_600_u64;
        // Two honest members arm their timers at different local wall-clock
        // instants (clock skew + arm-time staggering).
        let alice_arm_now = 1_700_000_000_u64;
        let bob_arm_now = 1_700_000_042_u64;

        let alice_local_deadline = alice_arm_now + ttl_secs;
        let bob_local_deadline = bob_arm_now + ttl_secs;

        // The discredited local-now base does NOT converge...
        assert_ne!(alice_local_deadline, bob_local_deadline);
        // ...whereas the convergent base anchored on a shared creation time does.
        let creation = 1_699_999_900_u64;
        assert_eq!(
            convergent_ttl_deadline_secs(creation, Some(ttl_secs)),
            convergent_ttl_deadline_secs(creation, Some(ttl_secs)),
        );
    }

    /// No finite TTL ⇒ no deadline.
    #[test]
    fn no_ttl_yields_no_deadline() {
        assert_eq!(convergent_ttl_deadline_secs(1_700_000_000, None), None);
    }

    /// Saturating add: a pathological creation time near `u64::MAX` cannot
    /// panic the deadline computation.
    #[test]
    fn deadline_saturates_instead_of_overflowing() {
        assert_eq!(
            convergent_ttl_deadline_secs(u64::MAX, Some(10)),
            Some(u64::MAX)
        );
    }
}
