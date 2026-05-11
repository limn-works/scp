//! Lifecycle handlers — see
//! [`LifecycleCommand`](crate::context::actor::commands::LifecycleCommand)
//! and ADR-049 Phase 2A.9 (`lifecycle` domain migration).
//!
//! # Single dispatch entry point
//!
//! - [`dispatch`] — actor-shape entry point. Takes `(&mut state,
//!   &deps, cmd)` and routes to actor-shape helpers in
//!   [`crate::context::lifecycle_helpers`] for per-context variants
//!   (Join / Leave / Close / Export), and to actor-shape helpers in
//!   [`crate::context::queries_helpers`] for access-key variants
//!   (Generate / Revoke / Restore). Used from the actor's
//!   [`dispatch_state`](crate::context::actor::ContextActor::dispatch_state)
//!   loop.
//!
//! Bootstrap variants (`CreateContext`, `ImportContext`, `RestoreContext`)
//! construct fresh `PerContextState` and cannot be routed against a
//! per-context actor that does not yet exist. They are handled by
//! [`Supervisor::dispatch_lifecycle_direct`](crate::context::supervisor::supervisor::Supervisor)
//! which delegates to the designated-legacy bootstrap helpers in
//! [`crate::context::lifecycle_helpers_legacy`]. If a bootstrap variant
//! reaches this actor-shape dispatch (because an actor is already
//! registered for the target context_id — a re-create attempt), the
//! handler surfaces `ContextError::InvalidState` on the reply oneshot.
//!
//! The prior `dispatch_from_shim` entry point (`&Supervisor`-shape, used
//! by `Supervisor::dispatch_lifecycle_command`'s shim fallback) was
//! deleted in the Phase 2A finalization queries+lifecycle session.
//! Bootstrap routing now lands on `Supervisor::dispatch_lifecycle_direct`;
//! per-context and access-key routing lands on this method through the
//! actor mailbox.
//!
//! Each entry point carries a 30-second per-call transport budget per
//! ADR-049 §7.

use std::time::Duration;

use scp_protocol::context::ContextError;
use tokio::sync::oneshot;

use crate::context::ContextHandle;
use crate::context::actor::commands::{CloseContextReply, ExportContextReply, LifecycleCommand};
use crate::context::actor::deps::ActorDeps;
use crate::context::actor::outcome::Outcome;
use crate::context::actor::state::PerContextState;

/// Per-call transport budget for lifecycle handlers. Plan §"Transport
/// timeouts inside actor handlers": 30 seconds.
pub const HANDLER_TIMEOUT: Duration = Duration::from_secs(30);

// ---------------------------------------------------------------------------
// Actor-shape dispatch (used from `dispatch_state`)
// ---------------------------------------------------------------------------

/// Actor-shape dispatch — routes `LifecycleCommand` against actor-owned
/// state.
///
/// Bootstrap commands (`CreateContext`, `RestoreContext`,
/// `ImportContext`) do NOT take `&mut state` — they construct fresh
/// state. They reach
/// [`Supervisor::dispatch_lifecycle_direct`](crate::context::supervisor::supervisor::Supervisor)
/// via the supervisor's lifecycle dispatch and never enter this actor
/// path; if one does reach the actor (re-create attempt against an
/// already-registered context), the handler surfaces
/// `ContextError::InvalidState` on the reply oneshot.
///
/// Per-context commands (`JoinContext`, `LeaveContext`, `CloseContext`,
/// `ExportContext`) operate against `&mut state` directly via the
/// actor-shape helpers in [`crate::context::lifecycle_helpers`].
///
/// Access-key commands (`GenerateContextAccessKey`,
/// `RevokeContextAccessKey`, `RestoreContextAccessKey`) call the
/// actor-shape helpers in [`crate::context::queries_helpers`] (Phase
/// 2A.10) directly on `&mut state` — no supervisor shim involved.
pub async fn dispatch(
    state: &mut PerContextState,
    deps: &ActorDeps,
    cmd: LifecycleCommand,
) -> Outcome<()> {
    Box::pin(dispatch_actor_inner(state, deps, cmd)).await
}

#[allow(clippy::too_many_lines)]
async fn dispatch_actor_inner(
    state: &mut PerContextState,
    deps: &ActorDeps,
    cmd: LifecycleCommand,
) -> Outcome<()> {
    match cmd {
        LifecycleCommand::Placeholder { reply } => reply_not_implemented(reply),
        LifecycleCommand::CreateContext { payload, reply } => {
            // Bootstrap variant must not reach the actor. The
            // supervisor routes Create / Import / Restore through
            // `dispatch_lifecycle_direct` before mailbox-first checks
            // run. If it gets here, an actor is already registered for
            // the target context_id — re-create against a live actor is
            // an invariant violation.
            let err = ContextError::InvalidState(format!(
                "CreateContext reached actor mailbox — context `{}` already has a registered actor",
                payload.context_id
            ));
            let sketch = outcome_error_sketch(&err);
            let _ = reply.send(Err(
                scp_protocol::context::builder::ContextCreationError::CreationFailed(format!(
                    "{err}"
                )),
            ));
            Outcome::err(sketch)
        }
        LifecycleCommand::JoinContext { payload, reply } => {
            let p = *payload;
            handle_join_context_actor(
                state,
                deps,
                p.context_id,
                p.params,
                p.key_package,
                p.spending_ucan.as_ref(),
                p.local_pseudonym,
                reply,
            )
            .await
        }
        LifecycleCommand::LeaveContext { payload, reply } => {
            let p = *payload;
            handle_leave_context_actor(
                state,
                deps,
                p.context_id,
                p.params,
                p.caller_did,
                p.member_did,
                reply,
            )
            .await
        }
        LifecycleCommand::CloseContext { payload, reply } => {
            let p = *payload;
            handle_close_context_actor(state, deps, p.context_id, p.params, p.initiator_did, reply)
                .await
        }
        LifecycleCommand::ExportContext {
            context_id,
            exporter_did,
            reply,
        } => handle_export_context_actor(state, deps, context_id, exporter_did, reply),
        LifecycleCommand::ImportContext { export, reply } => {
            // Bootstrap variant — see `CreateContext` arm comment.
            let err = ContextError::InvalidState(format!(
                "ImportContext reached actor mailbox — context `{}` already has a registered actor",
                export.snapshot.context_id
            ));
            let sketch = outcome_error_sketch(&err);
            let _ = reply.send(Err(err));
            Outcome::err(sketch)
        }
        LifecycleCommand::RestoreContext { payload, reply } => {
            // Bootstrap variant — see `CreateContext` arm comment.
            let err = ContextError::InvalidState(format!(
                "RestoreContext reached actor mailbox — context `{}` already has a registered actor",
                payload.context_id
            ));
            let sketch = outcome_error_sketch(&err);
            let _ = reply.send(Err(err));
            Outcome::err(sketch)
        }
        LifecycleCommand::GenerateContextAccessKey {
            context_id,
            member_did,
            caller_did,
            reply,
        } => handle_generate_context_access_key_actor(
            state,
            &context_id,
            &member_did,
            &caller_did,
            reply,
        ),
        LifecycleCommand::RevokeContextAccessKey {
            context_id,
            member_did,
            caller_did,
            reply,
        } => handle_revoke_context_access_key_actor(
            state,
            &context_id,
            &member_did,
            &caller_did,
            reply,
        ),
        LifecycleCommand::RestoreContextAccessKey {
            context_id,
            member_did,
            caller_did,
            reply,
        } => handle_restore_context_access_key_actor(
            state,
            &context_id,
            &member_did,
            &caller_did,
            reply,
        ),
    }
}

// ---------------------------------------------------------------------------
// Actor-shape per-context handlers
// ---------------------------------------------------------------------------

#[allow(clippy::too_many_arguments)]
async fn handle_join_context_actor(
    state: &mut PerContextState,
    deps: &ActorDeps,
    context_id: String,
    params: scp_protocol::context::params::ContextParams,
    key_package: scp_protocol::context::membership::KeyPackage,
    spending_ucan: Option<&scp_protocol::crypto::ucan::UcanToken>,
    local_pseudonym: Option<[u8; 32]>,
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

    let join_fut = crate::context::lifecycle_helpers::join_context(
        state,
        deps,
        &handle,
        key_package,
        spending_ucan,
        local_pseudonym,
    );

    let (outcome, reply_result) = match tokio::time::timeout(HANDLER_TIMEOUT, join_fut).await {
        Ok(Ok(())) => (Outcome::ok_mutated(()), Ok(())),
        Ok(Err(e)) => {
            let sketch = outcome_error_sketch(&e);
            (Outcome::err_mutated(sketch), Err(e))
        }
        Err(_elapsed) => {
            let err = ContextError::TransportTimeout(format!(
                "join_context exceeded {HANDLER_TIMEOUT:?} budget for context {context_id}"
            ));
            let sketch = outcome_error_sketch(&err);
            (Outcome::err_mutated(sketch), Err(err))
        }
    };

    let _ = reply.send(reply_result);
    outcome
}

async fn handle_leave_context_actor(
    state: &mut PerContextState,
    deps: &ActorDeps,
    context_id: String,
    params: scp_protocol::context::params::ContextParams,
    caller_did: scp_identity::DID,
    member_did: scp_identity::DID,
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

    let leave_fut = crate::context::lifecycle_helpers::leave_context(
        state,
        deps,
        &handle,
        &caller_did,
        &member_did,
    );

    let (outcome, reply_result) = match tokio::time::timeout(HANDLER_TIMEOUT, leave_fut).await {
        Ok(Ok(())) => (Outcome::ok_mutated(()), Ok(())),
        Ok(Err(e)) => {
            let sketch = outcome_error_sketch(&e);
            (Outcome::err_mutated(sketch), Err(e))
        }
        Err(_elapsed) => {
            let err = ContextError::TransportTimeout(format!(
                "leave_context exceeded {HANDLER_TIMEOUT:?} budget for context {context_id}"
            ));
            let sketch = outcome_error_sketch(&err);
            (Outcome::err_mutated(sketch), Err(err))
        }
    };

    let _ = reply.send(reply_result);
    outcome
}

async fn handle_close_context_actor(
    state: &mut PerContextState,
    deps: &ActorDeps,
    context_id: String,
    params: scp_protocol::context::params::ContextParams,
    initiator_did: scp_identity::DID,
    reply: CloseContextReply,
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

    let close_fut =
        crate::context::lifecycle_helpers::close_context(state, deps, &handle, &initiator_did);

    let (outcome, reply_result) = match tokio::time::timeout(HANDLER_TIMEOUT, close_fut).await {
        Ok(Ok(result)) => (Outcome::ok_mutated(()), Ok(result)),
        Ok(Err(e)) => {
            let sketch = outcome_error_sketch(&e);
            (Outcome::err_mutated(sketch), Err(e))
        }
        Err(_elapsed) => {
            let err = ContextError::TransportTimeout(format!(
                "close_context exceeded {HANDLER_TIMEOUT:?} budget for context {context_id}"
            ));
            let sketch = outcome_error_sketch(&err);
            (Outcome::err_mutated(sketch), Err(err))
        }
    };

    let _ = reply.send(reply_result);
    outcome
}

fn handle_export_context_actor(
    state: &PerContextState,
    deps: &ActorDeps,
    _context_id: String,
    exporter_did: scp_identity::DID,
    reply: ExportContextReply,
) -> Outcome<()> {
    // Export is sync and read-only — no timeout wrapping needed.
    let result = crate::context::lifecycle_helpers::export_context(state, deps, exporter_did);
    let outcome = match &result {
        Ok(_) => Outcome::ok(()),
        Err(e) => Outcome::err(outcome_error_sketch(e)),
    };
    let _ = reply.send(result);
    outcome
}

// ---------------------------------------------------------------------------
// Actor-shape access-key handlers (delegate to queries_helpers actor-shape)
// ---------------------------------------------------------------------------

fn handle_generate_context_access_key_actor(
    state: &mut PerContextState,
    context_id: &str,
    member_did: &str,
    caller_did: &str,
    reply: oneshot::Sender<Result<(), ContextError>>,
) -> Outcome<()> {
    let result = crate::context::queries_helpers::generate_context_access_key(
        state, context_id, member_did, caller_did,
    );
    let outcome = match &result {
        Ok(()) => Outcome::ok_mutated(()),
        Err(e) => Outcome::err_mutated(outcome_error_sketch(e)),
    };
    let _ = reply.send(result);
    outcome
}

fn handle_revoke_context_access_key_actor(
    state: &mut PerContextState,
    context_id: &str,
    member_did: &str,
    caller_did: &str,
    reply: oneshot::Sender<Result<(), ContextError>>,
) -> Outcome<()> {
    let result = crate::context::queries_helpers::revoke_context_access_key(
        state, context_id, member_did, caller_did,
    );
    let outcome = match &result {
        Ok(()) => Outcome::ok_mutated(()),
        Err(e) => Outcome::err_mutated(outcome_error_sketch(e)),
    };
    let _ = reply.send(result);
    outcome
}

fn handle_restore_context_access_key_actor(
    state: &mut PerContextState,
    context_id: &str,
    member_did: &str,
    caller_did: &str,
    reply: oneshot::Sender<Result<(), ContextError>>,
) -> Outcome<()> {
    let result = crate::context::queries_helpers::restore_context_access_key(
        state, context_id, member_did, caller_did,
    );
    let outcome = match &result {
        Ok(()) => Outcome::ok_mutated(()),
        Err(e) => Outcome::err_mutated(outcome_error_sketch(e)),
    };
    let _ = reply.send(result);
    outcome
}

// ---------------------------------------------------------------------------
// Shared utilities
// ---------------------------------------------------------------------------

/// Produce a best-effort clone-equivalent `ContextError` for the
/// handler's [`Outcome`] sink given a borrowed error that cannot be
/// cloned. Mirrors the pattern used in
/// [`handlers::messaging`](crate::context::actor::handlers::messaging).
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
        ContextError::InvalidState(msg) => ContextError::InvalidState(msg.clone()),
        other => ContextError::CryptoFailed(format!("{other}")),
    }
}

fn reply_not_implemented(reply: oneshot::Sender<Result<(), ContextError>>) -> Outcome<()> {
    const MSG: &str = "LifecycleCommand::Placeholder — placeholder variant; \
                       real variants land in commit 9 / Phase 2A.9 of \
                       ADR-049";
    let _ = reply.send(Err(ContextError::NotImplemented(MSG.to_owned())));
    Outcome::err(ContextError::NotImplemented(MSG.to_owned()))
}
