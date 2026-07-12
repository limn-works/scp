//! TTL-close handlers — see
//! [`TtlCloseCommand`](crate::context::actor::commands::TtlCloseCommand)
//! and spec §5.8.
//!
//! # Phase 2A — actor-shape dispatch
//!
//! The handler's entry point [`dispatch`] takes
//! `(&mut PerContextState, &ActorDeps, TtlCloseCommand)` and routes
//! every variant through [`crate::context::ttl_close_helpers`] (the
//! actor-shape TTL-domain helpers). Phase 2A finalization deleted the
//! supervisor-receiver shim — every command's target actor must be
//! spawned before
//! [`Supervisor::dispatch_ttl_close_command`](crate::context::supervisor::supervisor::Supervisor::dispatch_ttl_close_command)
//! routes it here.
//!
//! # Timer ownership (ADR-049 Decision-1 / finding A3)
//!
//! The TTL timer is an ACTOR-OWNED arm. The actor-shape `start_ttl_timer`
//! / `reset_ttl_timer` record the convergent
//! `state.ttl.timer.deadline_unix_secs` on actor-owned state via
//! [`ttl_close_helpers::start_ttl_timer`](crate::context::ttl_close_helpers)
//! — they no longer spawn a supervisor `task_set` timer task. The actor's
//! own `run()` loop reconciles a one-shot `sleep` against that deadline
//! (`ContextActor::reconcile_timers`) and runs the expiry pipeline
//! (`on_ttl_tick` → [`ttl_close_helpers::handle_ttl_expiry`](crate::context::ttl_close_helpers))
//! on wake, with no `&Supervisor` / mailbox hop. See the
//! [`crate::context::ttl_close_helpers`] module-level doc for the full
//! rationale.
//!
//! # Transport-timeout budget
//!
//! [`HANDLER_TIMEOUT`] is the handler-level budget. The predecessor
//! monolithic context methods did not carry their own deadline — this is
//! the new behaviour introduced by ADR-049 §7. 30 seconds matches the
//! plan's "every transport and storage call inside a handler wraps
//! `tokio::time::timeout(30s, ...)`" contract.

use std::time::Duration;

use scp_protocol::context::ContextError;
use tokio::sync::oneshot;

use crate::context::actor::class_s::ClassSCell;
use crate::context::actor::commands::TtlCloseCommand;
use crate::context::actor::deps::ActorDeps;
use crate::context::actor::outcome::Outcome;

/// Per-call transport budget for TTL-close handlers. Plan §"Transport
/// timeouts inside actor handlers": 30 seconds.
pub const HANDLER_TIMEOUT: Duration = Duration::from_secs(30);

/// Dispatch a [`TtlCloseCommand`] against actor-owned state and deps.
///
/// Plan-conforming dispatch signature: matches the post-refactor actor
/// `run()` loop's call shape
/// (`handlers::ttl_close::dispatch(&mut state, &deps, cmd).await`).
/// Each variant routes through [`crate::context::ttl_close_helpers`]
/// (the actor-shape TTL-domain helpers).
pub(crate) async fn dispatch(
    cell: &mut ClassSCell,
    deps: &ActorDeps,
    cmd: TtlCloseCommand,
) -> Outcome<()> {
    match cmd {
        TtlCloseCommand::StartTtlTimer { payload, reply } => {
            let p = *payload;
            handle_start_ttl_timer(cell, &p.params, p.deadline_override, reply)
        }
        TtlCloseCommand::ExtendTtl {
            context_id,
            member_did,
            proposed_duration,
            reply,
        } => handle_extend_ttl(cell, deps, context_id, member_did, proposed_duration, reply).await,
        TtlCloseCommand::ResetTtlTimer { payload, reply } => {
            let p = *payload;
            handle_reset_ttl_timer(cell, deps, p.context_id, p.duration, reply).await
        }
        TtlCloseCommand::ExecuteTtlClose { payload, reply } => {
            let p = *payload;
            handle_execute_ttl_close(cell, deps, p.context_id, reply).await
        }
        TtlCloseCommand::FinalizeClose { payload, reply } => {
            let p = *payload;
            handle_finalize_close(cell, deps, p.context_id, reply).await
        }
    }
}

// ---------------------------------------------------------------------------
// Actor-shape handlers — route through `ttl_close_helpers` (PerContextState).
// ---------------------------------------------------------------------------

/// Handle [`TtlCloseCommand::StartTtlTimer`] against actor-owned state.
///
/// Records the convergent TTL expiry deadline on `state.ttl.timer` via
/// [`crate::context::ttl_close_helpers::start_ttl_timer`]. This is a
/// SYNCHRONOUS deadline write (ADR-049 finding A3): the actor's
/// `reconcile_timers` derives the one-shot expiry sleep from the recorded
/// deadline, so there is no transport/task work to time-bound here.
fn handle_start_ttl_timer(
    cell: &mut ClassSCell,
    params: &scp_protocol::context::params::ContextParams,
    deadline_override: Option<crate::context::ttl_close_helpers::ConvergentDeadline>,
    reply: oneshot::Sender<Result<(), ContextError>>,
) -> Outcome<()> {
    // Resolve the ABSOLUTE convergent expiry deadline to record, as a
    // [`ConvergentDeadline`](crate::context::ttl_close_helpers::ConvergentDeadline)
    // (the arming-seam newtype). `Some` is the explicit deadline supplied by the
    // restore/import paths — derived from the SINGLE authoritative source (the
    // log) via `convergent_ttl_deadline`, so a prior extension survives and a
    // `None`-remaining Active snapshot still re-arms (D1/D2). `None` (the
    // initial-create / spawn-from-Welcome path) falls back to the convergent
    // create base `creation_timestamp_secs + params.ttl`: at create there is no
    // log yet, but the just-written `ContextCreated` leaf carries the identical
    // value, so arming via the create-base primitive is convergent (§7.3.1,
    // §9.9.3). `creation_timestamp_secs` is the authentic creator-assigned value
    // on every path (verbatim from the creator-signed snapshot on import).
    let deadline = deadline_override.or_else(|| {
        crate::context::ttl_close_helpers::convergent_ttl_deadline_secs(
            cell.creation_timestamp_secs,
            params.ttl.map(|ttl| ttl.as_secs()),
        )
    });

    // The TTL timer is Class-C; record the deadline through the non-persisting
    // Class-C view (no `state_mut`, ADR-049 §9). A `None` here means the context
    // carries no finite TTL, so there is nothing to arm.
    if let Some(deadline) = deadline {
        crate::context::ttl_close_helpers::start_ttl_timer(
            &mut cell.class_c_view().ttl_mut().timer,
            deadline,
        );
    }

    let _ = reply.send(Ok(()));
    Outcome::ok_mutated(())
}

/// Handle [`TtlCloseCommand::ExtendTtl`] against actor-owned state.
async fn handle_extend_ttl(
    cell: &mut ClassSCell,
    deps: &ActorDeps,
    context_id: String,
    member_did: scp_did::DID,
    proposed_duration: std::time::Duration,
    reply: oneshot::Sender<Result<bool, ContextError>>,
) -> Outcome<()> {
    // `propose_ttl_extension` awaits its best-effort persist (async
    // `ContextPersistence`, ADR-049 Decision 7); wrap in `async { ... }`
    // so the timeout budget still bounds the persist + any mutex contention.
    let extend_fut = async {
        crate::context::ttl_close_helpers::propose_ttl_extension(
            cell,
            deps,
            &context_id,
            &member_did,
            proposed_duration,
        )
        .await
    };

    let (outcome, reply_result) = match tokio::time::timeout(HANDLER_TIMEOUT, extend_fut).await {
        Ok(Ok(unanimous)) => (Outcome::ok_mutated(()), Ok(unanimous)),
        Ok(Err(e)) => {
            let sketch = outcome_error_sketch(&e);
            (Outcome::err_mutated(sketch), Err(e))
        }
        Err(_elapsed) => {
            let err = ContextError::TransportTimeout(format!(
                "propose_ttl_extension exceeded {HANDLER_TIMEOUT:?} budget for context {context_id}"
            ));
            let sketch = outcome_error_sketch(&err);
            (Outcome::err_mutated(sketch), Err(err))
        }
    };

    let _ = reply.send(reply_result);
    outcome
}

/// Handle [`TtlCloseCommand::ResetTtlTimer`] against actor-owned state.
///
/// Re-records the TTL deadline (a Class-C write) and persists best-effort via
/// [`crate::context::ttl_close_helpers::reset_ttl_timer`]. The persist is the
/// only I/O, so the `HANDLER_TIMEOUT` wrap bounds it (ADR-049 finding A3 — the
/// deadline itself is re-derived into a one-shot sleep by the actor's
/// `reconcile_timers`, no task is spawned).
async fn handle_reset_ttl_timer(
    cell: &mut ClassSCell,
    deps: &ActorDeps,
    context_id: String,
    new_duration: std::time::Duration,
    reply: oneshot::Sender<Result<(), ContextError>>,
) -> Outcome<()> {
    let reset_fut =
        crate::context::ttl_close_helpers::reset_ttl_timer(cell, deps, &context_id, new_duration);

    let (outcome, reply_result) = match tokio::time::timeout(HANDLER_TIMEOUT, reset_fut).await {
        Ok(()) => (Outcome::ok_mutated(()), Ok(())),
        Err(_elapsed) => {
            let err = ContextError::TransportTimeout(format!(
                "reset_ttl_timer exceeded {HANDLER_TIMEOUT:?} budget for context {context_id}"
            ));
            let sketch = outcome_error_sketch(&err);
            (Outcome::err_mutated(sketch), Err(err))
        }
    };

    let _ = reply.send(reply_result);
    outcome
}

/// Handle [`TtlCloseCommand::ExecuteTtlClose`] against actor-owned state.
///
/// # B10 — operates on the actor's REAL handle
///
/// The prior implementation built a THROWAWAY `ContextHandle::new(context_id,
/// params)`, transitioned IT to `Active`, and ran `handle_ttl_expiry` against
/// that detached handle — so an FFI `context_handle_ttl_expiry` transitioned a
/// disconnected FSM while the actor's OWN persisted state stayed `Active`. This
/// version drives the actor's real `cell.handle` (a clone shares the same
/// `Arc<ArcSwap<ContextState>>`), so the FFI path transitions and FAIL-CLOSED
/// persists the actor's own terminal `Expired` state — the same SEC-1 treatment
/// as [`on_ttl_tick`](crate::context::actor). No `transition_to(Active)`: the
/// live actor is already `Active`, and `apply_ttl_terminal_transition` moves
/// `Active`/`Expired` → `Expired`.
///
/// No timeout wraps the whole call: `handle_ttl_expiry` bounds ONLY its
/// relay/event-log I/O internally, running the fail-closed terminal persist
/// OUTSIDE that bound (SEC-1). A single command dispatch threads no on-actor
/// retry state, so `prior_completed` starts at `0`.
async fn handle_execute_ttl_close(
    cell: &mut ClassSCell,
    deps: &ActorDeps,
    context_id: String,
    reply: oneshot::Sender<Result<(), ContextError>>,
) -> Outcome<()> {
    let handle = cell.handle.clone();

    let outcome =
        crate::context::ttl_close_helpers::handle_ttl_expiry(cell, deps, &handle, 0).await;

    // Surface the inner error the prior second discard-the-error path swallowed
    // (B10 / Risk 5): a fail-closed terminal-persist failure OR an incomplete
    // cleanup is reported to the FFI caller (and logged), rather than silently
    // reporting success.
    let reply_result: Result<(), ContextError> = if let Err(e) = outcome.persist_result {
        Err(e)
    } else if outcome.result.has_failures() {
        let msg = outcome.result.errors().join("; ");
        Err(
            if !outcome.result.mls_destroyed() || !outcome.result.sender_key_destroyed() {
                ContextError::CryptoFailed(msg)
            } else {
                ContextError::EventLogFailed(msg)
            },
        )
    } else {
        Ok(())
    };

    if let Err(ref e) = reply_result {
        tracing::error!(
            context_id = %context_id,
            error = %e,
            "ExecuteTtlClose did not fully complete (fail-closed persist and/or \
             cleanup); FSM not rolled back (SEC-1 / B10)"
        );
    }

    let outcome_sink = match &reply_result {
        Ok(()) => Outcome::ok_mutated(()),
        Err(e) => Outcome::err_mutated(outcome_error_sketch(e)),
    };
    let _ = reply.send(reply_result);
    outcome_sink
}

/// Handle [`TtlCloseCommand::FinalizeClose`] against actor-owned state.
///
/// # Operates on the actor's REAL handle
///
/// The prior implementation built a THROWAWAY `ContextHandle::new(context_id,
/// params)`, force-transitioned IT to `Closing`, and ran `finalize_close`
/// against that detached handle — so an FFI `context_finalize_close` mutated a
/// disconnected FSM while the actor's OWN persisted state stayed unchanged
/// (the same detached-handle bug class the pass-2 `handle_execute_ttl_close`
/// fix cured; in fact `Creating → Closing` is an INVALID transition, so the
/// detached path could only ever error). This version drives the actor's real
/// `cell.handle` (a clone shares the same `Arc<ArcSwap<ContextState>>`), so the
/// cooperative-close finalization transitions the actor's own `Closing →
/// Closed` state and destroys keys / deletes the snapshot against the live
/// context.
///
/// No forced `transition_to(Closing)` on a detached handle: per the documented
/// FFI contract the context must ALREADY be in `Closing` (a prior
/// `close_context`), and [`ttl_close_helpers::finalize_close`] —
/// via [`ttl::finalize_close`](crate::context::ttl::finalize_close) — performs
/// the `Closing → Closed` transition itself, returning `InvalidTransition` if
/// the context is not in `Closing`, exactly the FFI error contract.
/// `ttl::finalize_close` validates that transition BEFORE destroying any key
/// material, so a non-`Closing` context destroys nothing.
async fn handle_finalize_close(
    cell: &mut ClassSCell,
    deps: &ActorDeps,
    context_id: String,
    reply: oneshot::Sender<Result<(), ContextError>>,
) -> Outcome<()> {
    // Drive the actor's REAL handle (a clone shares the same
    // `Arc<ArcSwap<ContextState>>` as `cell.handle`), NOT a detached throwaway,
    // so the `Closing → Closed` transition lands on the live context.
    let handle = cell.handle.clone();

    let finalize_fut = crate::context::ttl_close_helpers::finalize_close(cell, deps, &handle);

    let (outcome, reply_result) = match tokio::time::timeout(HANDLER_TIMEOUT, finalize_fut).await {
        Ok(Ok(())) => (Outcome::ok_mutated(()), Ok(())),
        Ok(Err(e)) => {
            let sketch = outcome_error_sketch(&e);
            (Outcome::err_mutated(sketch), Err(e))
        }
        Err(_elapsed) => {
            let err = ContextError::TransportTimeout(format!(
                "finalize_close exceeded {HANDLER_TIMEOUT:?} budget for context {context_id}"
            ));
            let sketch = outcome_error_sketch(&err);
            (Outcome::err_mutated(sketch), Err(err))
        }
    };

    let _ = reply.send(reply_result);
    outcome
}

/// Produce a best-effort clone-equivalent `ContextError` for the
/// handler's [`Outcome`] sink. Mirrors the pattern used in
/// [`handlers::messaging`](crate::context::actor::handlers::messaging)
/// and
/// [`handlers::lifecycle`](crate::context::actor::handlers::lifecycle).
fn outcome_error_sketch(err: &ContextError) -> ContextError {
    match err {
        ContextError::TransportTimeout(msg) => ContextError::TransportTimeout(msg.clone()),
        ContextError::TransportFailed(msg) => ContextError::TransportFailed(msg.clone()),
        ContextError::CryptoFailed(msg) => ContextError::CryptoFailed(msg.clone()),
        ContextError::PermissionDenied(msg) => ContextError::PermissionDenied(msg.clone()),
        ContextError::MemberNotFound(msg) => ContextError::MemberNotFound(msg.clone()),
        ContextError::ContextNotRegistered(msg) => ContextError::ContextNotRegistered(msg.clone()),
        ContextError::ContextNotActive => ContextError::ContextNotActive,
        ContextError::MembershipFailed(msg) => ContextError::MembershipFailed(msg.clone()),
        ContextError::EventLogFailed(msg) => ContextError::EventLogFailed(msg.clone()),
        other => ContextError::CryptoFailed(format!("{other}")),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use std::sync::Arc;

    use scp_did::DID;
    use tokio::sync::oneshot;

    use crate::context::actor::class_s::ClassSCell;
    use crate::context::actor::deps::ActorDeps;
    use crate::context::actor::state::PerContextState;
    use crate::context::builder::ContextEventLogProvider;
    use crate::context::providers::MerkleEventLogProvider;

    const ADMIN: &str = "did:dht:z6MkTtlFinalizeAdmin";
    const CTX_BYTE: u8 = 0xfc;

    /// Builds a minimal `ActorDeps` with an in-memory Merkle event log so the
    /// real-handle `finalize_close` path can append its `ContextClosed` leaf.
    async fn build_deps() -> ActorDeps {
        use crate::context::supervisor::supervisor::Supervisor;
        use scp_platform::testing::InMemoryStorage;

        let crypto = Arc::new(crate::crypto::mls::provider::MlsCryptoProvider::new(
            ADMIN.to_owned(),
            Arc::new(scp_clock::SystemClock),
        ));
        let transport: Box<dyn crate::context::builder::ContextTransportProvider> =
            Box::new(crate::context::builder::NotConfiguredTransportProvider);
        let event_log: Box<dyn ContextEventLogProvider> = Box::new(MerkleEventLogProvider::new());
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
            None,
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

    /// B10-sibling regression: `FinalizeClose` MUST drive the actor's REAL
    /// `cell.handle` (the shared `Arc<ArcSwap<ContextState>>`), transitioning the
    /// LIVE context `Closing → Closed` — not a detached throwaway handle.
    ///
    /// Pre-fix the handler built a `ContextHandle::new(context_id, params)` in
    /// `Creating` and force-transitioned IT to `Closing` (an INVALID
    /// `Creating → Closing` transition, so the handler errored), while the
    /// actor's own `cell.handle` stayed in `Closing`. This test seeds the real
    /// handle in `Closing`, dispatches `FinalizeClose`, and asserts the reply is
    /// `Ok` AND the REAL handle is now `Closed` — both of which fail pre-fix.
    #[tokio::test]
    async fn finalize_close_transitions_real_context_state() {
        let deps = build_deps().await;

        let context_id_bytes = [CTX_BYTE; 32];

        let state = PerContextState::new_for_test_encrypted(
            context_id_bytes,
            1_700_000_000,
            DID(ADMIN.to_owned()),
        );
        // The handle's own context-id string (the 64-hex of `context_id_bytes`);
        // `finalize_close` re-derives the same keying bytes from it.
        let context_id = state.handle.context_id().to_owned();
        // Real cooperative-close precondition: the live context is in `Closing`
        // (a prior `close_context` drove `Active → Closing`).
        state
            .handle
            .transition_to(&crate::context::ContextState::Active)
            .unwrap();
        state
            .handle
            .transition_to(&crate::context::ContextState::Closing)
            .unwrap();

        // The real-handle path appends a `ContextClosed` leaf; init the log so
        // the Merkle append succeeds.
        deps.event_log
            .init_event_log(&context_id_bytes)
            .await
            .expect("init event log");

        let mut cell = ClassSCell::new(state);

        let (reply_tx, reply_rx) = oneshot::channel();
        let _outcome = super::handle_finalize_close(&mut cell, &deps, context_id, reply_tx).await;

        let reply = reply_rx.await.expect("handler replies");
        assert!(
            reply.is_ok(),
            "FinalizeClose on a real Closing handle must succeed: {reply:?}"
        );
        assert_eq!(
            cell.handle.state(),
            crate::context::ContextState::Closed,
            "FinalizeClose MUST transition the actor's REAL handle to Closed \
             (pre-fix it mutated a detached throwaway and left the live handle \
             in Closing)"
        );
    }
}
