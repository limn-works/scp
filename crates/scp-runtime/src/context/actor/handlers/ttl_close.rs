//! TTL-close handlers — see
//! [`TtlCloseCommand`](crate::context::actor::commands::TtlCloseCommand)
//! and spec §5.8.
//!
//! # Phase 2A.6 — actor-shape dispatch
//!
//! The handler's primary entry point [`dispatch`] takes
//! `(&mut PerContextState, &ActorDeps, TtlCloseCommand)` and routes
//! every variant through [`crate::context::ttl_close_helpers`] (the
//! actor-shape TTL-domain helpers). The shim entry point
//! [`dispatch_from_shim`] remains during Phase 2A and routes through
//! [`crate::context::ttl_close_helpers_legacy`] for callers that arrive
//! via the supervisor mailbox-fallback path before a per-context actor
//! exists.
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
//! during Phase 2A.6 — see the
//! [`crate::context::ttl_close_helpers`] module-level doc for the full
//! rationale (Option B of the Phase 2A.6 plan). Phase 2A.9 (lifecycle
//! migration) revisits timer ownership so the TTL timer becomes a
//! `select!` arm in [`ContextActor::run`](crate::context::actor::ContextActor).
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
use crate::context::supervisor::Supervisor;

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

/// Shim-callable dispatch. Used by
/// [`Supervisor::dispatch_ttl_close_command`](crate::context::supervisor::supervisor::Supervisor::dispatch_ttl_close_command)
/// during the Phase 2A migration window when no per-context actor
/// exists for the target context — every variant routes through
/// [`crate::context::ttl_close_helpers_legacy`]. Removed in Phase 2A
/// finalization with the rest of the supervisor shim.
pub(crate) async fn dispatch_from_shim(
    supervisor: &Supervisor,
    cmd: TtlCloseCommand,
) -> Outcome<()> {
    match cmd {
        TtlCloseCommand::Placeholder { reply } => reply_not_implemented(reply),
        TtlCloseCommand::StartTtlTimer { payload, reply } => {
            let p = *payload;
            shim_handle_start_ttl_timer(supervisor, p.context_id, p.params, p.duration, reply).await
        }
        TtlCloseCommand::ExtendTtl {
            context_id,
            member_did,
            proposed_duration,
            reply,
        } => {
            shim_handle_extend_ttl(supervisor, context_id, member_did, proposed_duration, reply)
                .await
        }
        TtlCloseCommand::ResetTtlTimer { payload, reply } => {
            let p = *payload;
            shim_handle_reset_ttl_timer(supervisor, p.context_id, p.params, p.duration, reply).await
        }
        TtlCloseCommand::ExecuteTtlClose { payload, reply } => {
            let p = *payload;
            shim_handle_execute_ttl_close(supervisor, p.context_id, p.params, reply).await
        }
        TtlCloseCommand::FinalizeClose { payload, reply } => {
            let p = *payload;
            shim_handle_finalize_close(supervisor, p.context_id, p.params, reply).await
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

// ---------------------------------------------------------------------------
// Shim-fallback handlers — route through `ttl_close_helpers_legacy`
// (Supervisor lock-and-call). Used when no per-context actor exists.
// ---------------------------------------------------------------------------

async fn shim_handle_start_ttl_timer(
    supervisor: &Supervisor,
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

    let spawn_fut = crate::context::ttl_close_helpers_legacy::start_ttl_timer(
        supervisor,
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

async fn shim_handle_extend_ttl(
    supervisor: &Supervisor,
    context_id: String,
    member_did: scp_identity::DID,
    proposed_duration: std::time::Duration,
    reply: oneshot::Sender<Result<bool, ContextError>>,
) -> Outcome<()> {
    let extend_fut = crate::context::ttl_close_helpers_legacy::propose_ttl_extension(
        supervisor,
        &context_id,
        &member_did,
        proposed_duration,
    );

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

async fn shim_handle_reset_ttl_timer(
    supervisor: &Supervisor,
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

    let reset_fut = crate::context::ttl_close_helpers_legacy::reset_ttl_timer(
        supervisor,
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

async fn shim_handle_execute_ttl_close(
    supervisor: &Supervisor,
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

    let expiry_fut =
        crate::context::ttl_close_helpers_legacy::handle_ttl_expiry(supervisor, &handle);

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

async fn shim_handle_finalize_close(
    supervisor: &Supervisor,
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

    let finalize_fut =
        crate::context::ttl_close_helpers_legacy::finalize_close(supervisor, &handle);

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
