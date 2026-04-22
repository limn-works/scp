//! TTL-close handlers — see
//! [`TtlCloseCommand`](crate::context::actor::commands::TtlCloseCommand)
//! and spec §5.8 / plan row 9 of the commit ladder.
//!
//! # Commit 9 scope
//!
//! Migrates the dispatch shape: the handler takes
//! [`MutationStateView`](crate::context::actor::mutation_state_view::MutationStateView)
//! + [`ActorDeps`] + [`TtlCloseCommand`], returns `Outcome<()>`.
//!
//! The underlying byte-identical implementation still lives on
//! [`ContextManager`](crate::context::manager::ContextManager): each
//! handler delegates to
//! [`ContextManager::spawn_ttl_timer`](crate::context::manager::ContextManager)
//! (via an internal helper),
//! [`ContextManager::propose_ttl_extension`](crate::context::manager::ContextManager::propose_ttl_extension),
//! [`ContextManager::reset_ttl_timer`](crate::context::manager::ContextManager::reset_ttl_timer),
//! [`ContextManager::handle_ttl_expiry`](crate::context::manager::ContextManager::handle_ttl_expiry),
//! or
//! [`ContextManager::finalize_close`](crate::context::manager::ContextManager::finalize_close).
//!
//! **TTL timer specifics (commit 9 scope).** The post-refactor
//! architecture turns the TTL timer into a `select!` arm in
//! [`ContextActor::run`](crate::context::actor::ContextActor). Commit 9
//! keeps the timer spawned from the legacy
//! [`ContextManager`](crate::context::manager::ContextManager) internals;
//! the handler variants here respond to caller-initiated TTL commands
//! (extend, finalize, explicit expiry, timer start / reset)
//! synchronously. Full timer-owning actor logic migrates with plan row
//! 11.
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
use crate::context::actor::mutation_state_view::MutationStateView;
use crate::context::actor::outcome::Outcome;

/// Per-call transport budget for TTL-close handlers. Plan §"Transport
/// timeouts inside actor handlers": 30 seconds.
pub const HANDLER_TIMEOUT: Duration = Duration::from_secs(30);

/// Dispatch a [`TtlCloseCommand`] against a mutation state view + deps
/// bundle.
///
/// Plan-conforming dispatch signature: matches the post-refactor actor
/// `run()` loop's call shape
/// (`handlers::ttl_close::dispatch(&mut self.state, &self.deps, cmd).await`).
/// `deps` is accepted for symmetry — the ttl-close handler does not yet
/// touch deps during the shim period. Commit 12 rewires these paths.
// `needless_pass_by_ref_mut` allow — matches the `&mut` contract
// used by every migrated handler dispatch
// (`handlers::{messaging,lifecycle,ttl_close}::dispatch`) so the
// post-refactor actor `run()` loop can call each one uniformly.
// Commit 9's TTL handlers delegate to
// [`ContextManager`](crate::context::manager::ContextManager) and
// do not mutate the view; commit 12 replaces those delegations with
// direct state mutations on the actor's owned
// [`PerContextState`](crate::context::actor::state::PerContextState).
#[allow(clippy::needless_pass_by_ref_mut)]
pub async fn dispatch(
    view: &mut MutationStateView<'_>,
    _deps: &ActorDeps,
    cmd: TtlCloseCommand,
) -> Outcome<()> {
    dispatch_inner(view, cmd).await
}

/// Shim-callable dispatch. Used by
/// [`Supervisor::dispatch_command`](crate::context::supervisor::supervisor::Supervisor::dispatch_command)
/// during the commits-9-to-11 migration window — deleted in commit 12
/// when the shim dissolves and the actor's `run()` loop is the only
/// caller of [`dispatch`].
///
/// `needless_pass_by_ref_mut` allow — see the comment on [`dispatch`].
#[allow(clippy::needless_pass_by_ref_mut)]
pub(crate) async fn dispatch_from_shim(
    view: &mut MutationStateView<'_>,
    cmd: TtlCloseCommand,
) -> Outcome<()> {
    dispatch_inner(view, cmd).await
}

async fn dispatch_inner(view: &MutationStateView<'_>, cmd: TtlCloseCommand) -> Outcome<()> {
    match cmd {
        TtlCloseCommand::Placeholder { reply } => reply_not_implemented(reply),
        TtlCloseCommand::StartTtlTimer { payload, reply } => {
            let p = *payload;
            handle_start_ttl_timer(view, p.context_id, p.params, p.duration, reply).await
        }
        TtlCloseCommand::ExtendTtl {
            context_id,
            member_did,
            proposed_duration,
            reply,
        } => handle_extend_ttl(view, context_id, member_did, proposed_duration, reply).await,
        TtlCloseCommand::ResetTtlTimer { payload, reply } => {
            let p = *payload;
            handle_reset_ttl_timer(view, p.context_id, p.params, p.duration, reply).await
        }
        TtlCloseCommand::ExecuteTtlClose { payload, reply } => {
            let p = *payload;
            handle_execute_ttl_close(view, p.context_id, p.params, reply).await
        }
        TtlCloseCommand::FinalizeClose { payload, reply } => {
            let p = *payload;
            handle_finalize_close(view, p.context_id, p.params, reply).await
        }
    }
}

/// Handle [`TtlCloseCommand::StartTtlTimer`]: delegate to
/// [`ContextManager::spawn_ttl_timer`](crate::context::manager::ContextManager)
/// via the public
/// [`ContextManager::start_ttl_timer`](crate::context::manager::ContextManager::start_ttl_timer)
/// shim accessor added by this commit.
///
/// `spawn_ttl_timer` itself has no inherent timeout (it returns once
/// the task is spawned), but we still wrap it so a pathological mutex
/// contention storm cannot block the dispatcher indefinitely.
async fn handle_start_ttl_timer(
    view: &MutationStateView<'_>,
    context_id: String,
    params: scp_protocol::context::params::ContextParams,
    duration: std::time::Duration,
    reply: oneshot::Sender<Result<(), ContextError>>,
) -> Outcome<()> {
    let manager = std::sync::Arc::clone(view.manager());

    let handle = ContextHandle::new(context_id.clone(), params);
    if let Err(e) = handle
        .transition_to(&scp_protocol::context::ContextState::Active)
        .await
    {
        let sketch = outcome_error_sketch(&e);
        let _ = reply.send(Err(e));
        return Outcome::err(sketch);
    }

    let spawn_fut =
        crate::context::lifecycle_helpers::start_ttl_timer(&manager, &context_id, duration, handle);

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

/// Handle [`TtlCloseCommand::ExtendTtl`]: delegate to
/// [`ContextManager::propose_ttl_extension`](crate::context::manager::ContextManager::propose_ttl_extension)
/// under a 30s timeout.
async fn handle_extend_ttl(
    view: &MutationStateView<'_>,
    context_id: String,
    member_did: scp_identity::DID,
    proposed_duration: std::time::Duration,
    reply: oneshot::Sender<Result<bool, ContextError>>,
) -> Outcome<()> {
    let manager = std::sync::Arc::clone(view.manager());
    let extend_fut = crate::context::lifecycle_helpers::propose_ttl_extension(
        &manager,
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

/// Handle [`TtlCloseCommand::ResetTtlTimer`]: delegate to
/// [`ContextManager::reset_ttl_timer`](crate::context::manager::ContextManager::reset_ttl_timer)
/// under a 30s timeout.
async fn handle_reset_ttl_timer(
    view: &MutationStateView<'_>,
    context_id: String,
    params: scp_protocol::context::params::ContextParams,
    new_duration: std::time::Duration,
    reply: oneshot::Sender<Result<(), ContextError>>,
) -> Outcome<()> {
    let manager = std::sync::Arc::clone(view.manager());

    let handle = ContextHandle::new(context_id.clone(), params);
    if let Err(e) = handle
        .transition_to(&scp_protocol::context::ContextState::Active)
        .await
    {
        let sketch = outcome_error_sketch(&e);
        let _ = reply.send(Err(e));
        return Outcome::err(sketch);
    }

    let reset_fut = crate::context::lifecycle_helpers::reset_ttl_timer(
        &manager,
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

/// Handle [`TtlCloseCommand::ExecuteTtlClose`]: delegate to
/// [`ContextManager::handle_ttl_expiry`](crate::context::manager::ContextManager::handle_ttl_expiry)
/// under a 30s timeout.
async fn handle_execute_ttl_close(
    view: &MutationStateView<'_>,
    context_id: String,
    params: scp_protocol::context::params::ContextParams,
    reply: oneshot::Sender<Result<(), ContextError>>,
) -> Outcome<()> {
    let manager = std::sync::Arc::clone(view.manager());

    let handle = ContextHandle::new(context_id.clone(), params);
    if let Err(e) = handle
        .transition_to(&scp_protocol::context::ContextState::Active)
        .await
    {
        let sketch = outcome_error_sketch(&e);
        let _ = reply.send(Err(e));
        return Outcome::err(sketch);
    }

    let expiry_fut = crate::context::lifecycle_helpers::handle_ttl_expiry(&manager, &handle);

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

/// Handle [`TtlCloseCommand::FinalizeClose`]: delegate to
/// [`ContextManager::finalize_close`](crate::context::manager::ContextManager::finalize_close)
/// under a 30s timeout.
async fn handle_finalize_close(
    view: &MutationStateView<'_>,
    context_id: String,
    params: scp_protocol::context::params::ContextParams,
    reply: oneshot::Sender<Result<(), ContextError>>,
) -> Outcome<()> {
    let manager = std::sync::Arc::clone(view.manager());

    let handle = ContextHandle::new(context_id.clone(), params);
    if let Err(e) = handle
        .transition_to(&scp_protocol::context::ContextState::Closing)
        .await
    {
        let sketch = outcome_error_sketch(&e);
        let _ = reply.send(Err(e));
        return Outcome::err(sketch);
    }

    let finalize_fut = crate::context::lifecycle_helpers::finalize_close(&manager, &handle);

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
                       FinalizeClose land in commit 9 of ADR-049; \
                       Placeholder retained for commit-6 compile stability and \
                       deleted in commit 12 with the shim";
    let _ = reply.send(Err(ContextError::NotImplemented(MSG.to_owned())));
    Outcome::err(ContextError::NotImplemented(MSG.to_owned()))
}
