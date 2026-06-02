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
//! # Timer ownership
//!
//! Spawning the TTL timer still requires the supervisor's `task_set`
//! and contexts map (cross-actor mutation on timer fire); neither
//! resource is on `ActorDeps`. The actor-shape `start_ttl_timer` /
//! `reset_ttl_timer` reach
//! [`crate::context::ttl_close_helpers_legacy::spawn_ttl_timer_legacy`]
//! through
//! [`SupervisorHandle::shim_supervisor`](crate::context::supervisor::handle::SupervisorHandle::shim_supervisor)
//! — see the [`crate::context::ttl_close_helpers`] module-level doc for
//! the full rationale (Option B of the Phase 2A.6 plan). Phase 2A.9
//! (lifecycle migration) revisits timer ownership so the TTL timer
//! becomes a `select!` arm in
//! [`ContextActor::run`](crate::context::actor::ContextActor).
//!
//! # Transport-timeout budget
//!
//! [`HANDLER_TIMEOUT`] is the handler-level budget. The legacy
//! `ContextManager` methods do not carry their own deadline — this is
//! the new behaviour introduced by ADR-049 §7. 30 seconds matches the
//! plan's "every transport and storage call inside a handler wraps
//! `tokio::time::timeout(30s, ...)`" contract.

use std::time::Duration;

use scp_protocol::context::ContextError;
use tokio::sync::oneshot;

use crate::context::ContextHandle;
use crate::context::actor::commands::TtlCloseCommand;
use crate::context::actor::deps::ActorDeps;
use crate::context::actor::outcome::Outcome;
use crate::context::actor::state::PerContextState;

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
pub async fn dispatch(
    state: &mut PerContextState,
    deps: &ActorDeps,
    cmd: TtlCloseCommand,
) -> Outcome<()> {
    match cmd {
        TtlCloseCommand::Placeholder { reply } => reply_not_implemented(reply),
        TtlCloseCommand::FireTimer { reply } => handle_fire_timer(state, deps, reply).await,
        TtlCloseCommand::StartTtlTimer { payload, reply } => {
            let p = *payload;
            handle_start_ttl_timer(state, deps, p.context_id, p.params, p.duration, reply).await
        }
        TtlCloseCommand::ExtendTtl {
            context_id,
            member_did,
            proposed_duration,
            reply,
        } => {
            handle_extend_ttl(
                state,
                deps,
                context_id,
                member_did,
                proposed_duration,
                reply,
            )
            .await
        }
        TtlCloseCommand::ResetTtlTimer { payload, reply } => {
            let p = *payload;
            handle_reset_ttl_timer(state, deps, p.context_id, p.params, p.duration, reply).await
        }
        TtlCloseCommand::ExecuteTtlClose { payload, reply } => {
            let p = *payload;
            handle_execute_ttl_close(state, deps, p.context_id, p.params, reply).await
        }
        TtlCloseCommand::FinalizeClose { payload, reply } => {
            let p = *payload;
            handle_finalize_close(state, deps, p.context_id, p.params, reply).await
        }
    }
}

// ---------------------------------------------------------------------------
// Actor-shape handlers — route through `ttl_close_helpers` (PerContextState).
// ---------------------------------------------------------------------------

/// Handle [`TtlCloseCommand::StartTtlTimer`] against actor-owned state.
///
/// Routes to
/// [`crate::context::ttl_close_helpers::start_ttl_timer`] which reaches
/// [`crate::context::ttl_close_helpers_legacy::spawn_ttl_timer_legacy`]
/// via the supervisor shim (Option B of the Phase 2A.6 plan). The
/// timer itself has no inherent timeout, but we still wrap it so a
/// pathological mutex contention storm cannot block the dispatcher
/// indefinitely.
async fn handle_start_ttl_timer(
    state: &mut PerContextState,
    deps: &ActorDeps,
    context_id: String,
    params: scp_protocol::context::params::ContextParams,
    duration: std::time::Duration,
    reply: oneshot::Sender<Result<(), ContextError>>,
) -> Outcome<()> {
    let handle = ContextHandle::new(context_id.clone(), params);
    if let Err(e) = handle
        .transition_to(&scp_protocol::context::ContextState::Active)
        .await
    {
        let sketch = outcome_error_sketch(&e);
        let _ = reply.send(Err(e));
        return Outcome::err(sketch);
    }

    let spawn_fut = crate::context::ttl_close_helpers::start_ttl_timer(
        state,
        deps,
        &context_id,
        duration,
        handle,
    );

    let (outcome, reply_result) = match tokio::time::timeout(HANDLER_TIMEOUT, spawn_fut).await {
        Ok(()) => (Outcome::ok_mutated(()), Ok(())),
        Err(_elapsed) => {
            let err = ContextError::TransportTimeout(format!(
                "start_ttl_timer exceeded {HANDLER_TIMEOUT:?} budget for context {context_id}"
            ));
            let sketch = outcome_error_sketch(&err);
            (Outcome::err_mutated(sketch), Err(err))
        }
    };

    let _ = reply.send(reply_result);
    outcome
}

/// Handle [`TtlCloseCommand::ExtendTtl`] against actor-owned state.
async fn handle_extend_ttl(
    state: &mut PerContextState,
    deps: &ActorDeps,
    context_id: String,
    member_did: scp_identity::DID,
    proposed_duration: std::time::Duration,
    reply: oneshot::Sender<Result<bool, ContextError>>,
) -> Outcome<()> {
    // `propose_ttl_extension` is synchronous (the actor owns `state`
    // and persistence is fire-and-forget); wrap in `async { ... }` so
    // the timeout budget still fires on pathological mutex contention.
    let extend_fut = async {
        crate::context::ttl_close_helpers::propose_ttl_extension(
            state,
            deps,
            &context_id,
            &member_did,
            proposed_duration,
        )
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
async fn handle_reset_ttl_timer(
    state: &mut PerContextState,
    deps: &ActorDeps,
    context_id: String,
    params: scp_protocol::context::params::ContextParams,
    new_duration: std::time::Duration,
    reply: oneshot::Sender<Result<(), ContextError>>,
) -> Outcome<()> {
    let handle = ContextHandle::new(context_id.clone(), params);
    if let Err(e) = handle
        .transition_to(&scp_protocol::context::ContextState::Active)
        .await
    {
        let sketch = outcome_error_sketch(&e);
        let _ = reply.send(Err(e));
        return Outcome::err(sketch);
    }

    let reset_fut = crate::context::ttl_close_helpers::reset_ttl_timer(
        state,
        deps,
        &context_id,
        new_duration,
        handle,
    );

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
async fn handle_execute_ttl_close(
    state: &mut PerContextState,
    deps: &ActorDeps,
    context_id: String,
    params: scp_protocol::context::params::ContextParams,
    reply: oneshot::Sender<Result<(), ContextError>>,
) -> Outcome<()> {
    let handle = ContextHandle::new(context_id.clone(), params);
    if let Err(e) = handle
        .transition_to(&scp_protocol::context::ContextState::Active)
        .await
    {
        let sketch = outcome_error_sketch(&e);
        let _ = reply.send(Err(e));
        return Outcome::err(sketch);
    }

    let expiry_fut = crate::context::ttl_close_helpers::handle_ttl_expiry(state, deps, &handle);

    let (outcome, reply_result) = match tokio::time::timeout(HANDLER_TIMEOUT, expiry_fut).await {
        Ok(Ok(())) => (Outcome::ok_mutated(()), Ok(())),
        Ok(Err(e)) => {
            let sketch = outcome_error_sketch(&e);
            (Outcome::err_mutated(sketch), Err(e))
        }
        Err(_elapsed) => {
            let err = ContextError::TransportTimeout(format!(
                "handle_ttl_expiry exceeded {HANDLER_TIMEOUT:?} budget for context {context_id}"
            ));
            let sketch = outcome_error_sketch(&err);
            (Outcome::err_mutated(sketch), Err(err))
        }
    };

    let _ = reply.send(reply_result);
    outcome
}

/// Handle [`TtlCloseCommand::FireTimer`] against actor-owned state.
///
/// Per-context TTL-timer tick. Sent by the per-context timer task on
/// each wake (see
/// [`ttl_close_helpers::spawn_ttl_timer`](crate::context::ttl_close_helpers::spawn_ttl_timer))
/// once the configured TTL duration elapses. Runs the actor-shape
/// expiry pipeline
/// ([`ttl_close_helpers::handle_ttl_expiry`](crate::context::ttl_close_helpers::handle_ttl_expiry))
/// against owned `&mut state`: it cancels the governance-timeout task,
/// decays participation, emits the `Expired` / `ExpiryFailed` event, and
/// persists best-effort.
///
/// Replaces the legacy `spawn_ttl_timer_legacy` task's inline expiry tail
/// that locked the `contexts` DashMap entry and applied a stale-generation
/// gate (ADR-049 Phase 2A finalization — DashMap removal). The
/// generation gate is gone: the timer task resolves the actor via
/// [`Supervisor::lookup`](crate::context::supervisor::Supervisor::lookup),
/// so a despawned actor (context gone / recreated) is never reached, and
/// the actor owns its state for the whole turn (no concurrent
/// close-and-recreate window).
///
/// Reply: `Ok(false)` — the expiry pipeline has fired, so the timer task
/// stops after this tick. (The reply currently always reports "do not
/// continue"; a future repeating-timer variant would return `Ok(true)`.)
async fn handle_fire_timer(
    state: &mut PerContextState,
    deps: &ActorDeps,
    reply: oneshot::Sender<Result<bool, ContextError>>,
) -> Outcome<()> {
    let handle = state.handle.clone();
    let expiry_fut = crate::context::ttl_close_helpers::handle_ttl_expiry(state, deps, &handle);

    match tokio::time::timeout(HANDLER_TIMEOUT, expiry_fut).await {
        Ok(Ok(())) => {
            let _ = reply.send(Ok(false));
            Outcome::ok_mutated(())
        }
        Ok(Err(e)) => {
            let sketch = outcome_error_sketch(&e);
            let _ = reply.send(Err(e));
            Outcome::err_mutated(sketch)
        }
        Err(_elapsed) => {
            let context_id = handle.context_id().to_owned();
            let err = ContextError::TransportTimeout(format!(
                "TTL FireTimer expiry exceeded {HANDLER_TIMEOUT:?} budget for context {context_id}"
            ));
            let sketch = outcome_error_sketch(&err);
            let _ = reply.send(Err(err));
            Outcome::err_mutated(sketch)
        }
    }
}

/// Handle [`TtlCloseCommand::FinalizeClose`] against actor-owned state.
async fn handle_finalize_close(
    state: &mut PerContextState,
    deps: &ActorDeps,
    context_id: String,
    params: scp_protocol::context::params::ContextParams,
    reply: oneshot::Sender<Result<(), ContextError>>,
) -> Outcome<()> {
    let handle = ContextHandle::new(context_id.clone(), params);
    if let Err(e) = handle
        .transition_to(&scp_protocol::context::ContextState::Closing)
        .await
    {
        let sketch = outcome_error_sketch(&e);
        let _ = reply.send(Err(e));
        return Outcome::err(sketch);
    }

    let finalize_fut = crate::context::ttl_close_helpers::finalize_close(state, deps, &handle);

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

fn reply_not_implemented(reply: oneshot::Sender<Result<(), ContextError>>) -> Outcome<()> {
    const MSG: &str = "TtlCloseCommand::Placeholder — real variants \
                       StartTtlTimer/ExtendTtl/ResetTtlTimer/ExecuteTtlClose/\
                       FinalizeClose are wired; Placeholder retained for actor \
                       run-loop skeleton-handshake stability and deleted in \
                       Phase 2A finalization with the shim";
    let _ = reply.send(Err(ContextError::NotImplemented(MSG.to_owned())));
    Outcome::err(ContextError::NotImplemented(MSG.to_owned()))
}
