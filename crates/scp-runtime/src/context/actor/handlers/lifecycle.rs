//! Lifecycle handlers — see
//! [`LifecycleCommand`](crate::context::actor::commands::LifecycleCommand)
//! and ADR-049 Phase 2A.9 (`lifecycle` domain migration).
//!
//! # Two dispatch entry points
//!
//! - [`dispatch`] — actor-shape entry point. Takes `(&mut state,
//!   &deps, cmd)` and routes to actor-shape helpers in
//!   [`crate::context::lifecycle_helpers`]. Used from the actor's
//!   [`dispatch_state`](crate::context::actor::ContextActor::dispatch_state)
//!   loop once the per-context actor owns state.
//! - [`dispatch_from_shim`] — legacy shim entry point. Takes
//!   `(supervisor, cmd)` and routes to the legacy `&Supervisor`-shaped
//!   helpers in
//!   [`crate::context::lifecycle_helpers_legacy`]. Used during the
//!   Phase 2A migration window for callers without an attached actor
//!   (FFI fallback, integration tests).
//!
//! Each entry point carries a 30-second per-call transport budget per
//! ADR-049 §7. Bootstrap commands (`CreateContext`,
//! `RestoreContext`, `ImportContext`) construct fresh `PerContextState`
//! and register through
//! [`SupervisorHandle`](crate::context::supervisor::handle::SupervisorHandle)
//! on the actor path; on the shim path they call the legacy `_legacy`
//! twin directly against the supervisor's contexts map.

use std::time::Duration;

use scp_protocol::context::ContextError;
use tokio::sync::oneshot;

use crate::context::ContextHandle;
use crate::context::actor::commands::{
    CloseContextReply, CreateContextReply, ExportContextReply, ImportContextReply, LifecycleCommand,
};
use crate::context::actor::deps::ActorDeps;
use crate::context::actor::outcome::Outcome;
use crate::context::actor::state::PerContextState;
use crate::context::supervisor::Supervisor;

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
/// state. They cannot be routed against a per-context actor that does
/// not yet exist; they remain on the shim path until the supervisor's
/// actor-spawn pipeline lands.
///
/// Per-context commands (`JoinContext`, `LeaveContext`, `CloseContext`,
/// `ExportContext`) operate against `&mut state` directly.
///
/// Access-key commands (`GenerateContextAccessKey`,
/// `RevokeContextAccessKey`, `RestoreContextAccessKey`) live in
/// `queries_helpers` (Phase 2A.10) and continue to route through the
/// shim until that domain migrates.
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
            // Bootstrap — constructs new state, no per-actor mutation.
            // Route through the shim; the actor model spawns a fresh
            // actor for the new context after registration.
            let p = *payload;
            handle_create_context_shim(
                deps.supervisor.shim_supervisor().as_ref(),
                p.context_id,
                p.params,
                p.creator_did,
                p.local_pseudonym,
                reply,
            )
            .await
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
            // Bootstrap — constructs new state. Route through the shim.
            Box::pin(handle_import_context_shim(
                deps.supervisor.shim_supervisor().as_ref(),
                export,
                reply,
            ))
            .await
        }
        LifecycleCommand::RestoreContext { payload, reply } => {
            // Bootstrap — constructs new state. Route through the shim.
            let p = *payload;
            Box::pin(handle_restore_context_shim(
                deps.supervisor.shim_supervisor().as_ref(),
                p.context_id,
                p.params,
                reply,
            ))
            .await
        }
        LifecycleCommand::GenerateContextAccessKey {
            context_id,
            member_did,
            caller_did,
            reply,
        } => {
            handle_generate_context_access_key_shim(
                deps.supervisor.shim_supervisor().as_ref(),
                context_id,
                member_did,
                caller_did,
                reply,
            )
            .await
        }
        LifecycleCommand::RevokeContextAccessKey {
            context_id,
            member_did,
            caller_did,
            reply,
        } => {
            handle_revoke_context_access_key_shim(
                deps.supervisor.shim_supervisor().as_ref(),
                context_id,
                member_did,
                caller_did,
                reply,
            )
            .await
        }
        LifecycleCommand::RestoreContextAccessKey {
            context_id,
            member_did,
            caller_did,
            reply,
        } => {
            handle_restore_context_access_key_shim(
                deps.supervisor.shim_supervisor().as_ref(),
                context_id,
                member_did,
                caller_did,
                reply,
            )
            .await
        }
    }
}

// ---------------------------------------------------------------------------
// Shim dispatch (used by Supervisor::dispatch_command for callers without
// an attached per-context actor)
// ---------------------------------------------------------------------------

/// Shim dispatch entry point. Routes every `LifecycleCommand` variant
/// through the legacy `&Supervisor`-shaped helpers in
/// [`crate::context::lifecycle_helpers_legacy`].
///
/// Removed when the actor model owns every per-context entry point and
/// the supervisor's contexts-map fallback path goes away in Phase 2A
/// finalization.
pub(crate) async fn dispatch_from_shim(
    supervisor: &Supervisor,
    cmd: LifecycleCommand,
) -> Outcome<()> {
    Box::pin(dispatch_shim_inner(supervisor, cmd)).await
}

#[allow(clippy::too_many_lines)]
async fn dispatch_shim_inner(supervisor: &Supervisor, cmd: LifecycleCommand) -> Outcome<()> {
    match cmd {
        LifecycleCommand::Placeholder { reply } => reply_not_implemented(reply),
        LifecycleCommand::CreateContext { payload, reply } => {
            let p = *payload;
            handle_create_context_shim(
                supervisor,
                p.context_id,
                p.params,
                p.creator_did,
                p.local_pseudonym,
                reply,
            )
            .await
        }
        LifecycleCommand::JoinContext { payload, reply } => {
            let p = *payload;
            handle_join_context_shim(
                supervisor,
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
            handle_leave_context_shim(
                supervisor,
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
            handle_close_context_shim(supervisor, p.context_id, p.params, p.initiator_did, reply)
                .await
        }
        LifecycleCommand::ExportContext {
            context_id,
            exporter_did,
            reply,
        } => handle_export_context_shim(supervisor, context_id, exporter_did, reply).await,
        LifecycleCommand::ImportContext { export, reply } => {
            Box::pin(handle_import_context_shim(supervisor, export, reply)).await
        }
        LifecycleCommand::RestoreContext { payload, reply } => {
            let p = *payload;
            Box::pin(handle_restore_context_shim(
                supervisor,
                p.context_id,
                p.params,
                reply,
            ))
            .await
        }
        LifecycleCommand::GenerateContextAccessKey {
            context_id,
            member_did,
            caller_did,
            reply,
        } => {
            handle_generate_context_access_key_shim(
                supervisor, context_id, member_did, caller_did, reply,
            )
            .await
        }
        LifecycleCommand::RevokeContextAccessKey {
            context_id,
            member_did,
            caller_did,
            reply,
        } => {
            handle_revoke_context_access_key_shim(
                supervisor, context_id, member_did, caller_did, reply,
            )
            .await
        }
        LifecycleCommand::RestoreContextAccessKey {
            context_id,
            member_did,
            caller_did,
            reply,
        } => {
            handle_restore_context_access_key_shim(
                supervisor, context_id, member_did, caller_did, reply,
            )
            .await
        }
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
// Shim per-context handlers (delegate to lifecycle_helpers_legacy)
// ---------------------------------------------------------------------------

async fn handle_create_context_shim(
    supervisor: &Supervisor,
    context_id: String,
    params: scp_protocol::context::params::ContextParams,
    creator_did: scp_identity::DID,
    local_pseudonym: Option<[u8; 32]>,
    reply: CreateContextReply,
) -> Outcome<()> {
    let create_fut = crate::context::lifecycle_helpers_legacy::create_context_legacy(
        supervisor,
        context_id.clone(),
        params,
        creator_did,
        local_pseudonym,
    );

    let (outcome, reply_result) = match tokio::time::timeout(HANDLER_TIMEOUT, create_fut).await {
        Ok(Ok(handle)) => (Outcome::ok_mutated(()), Ok(handle)),
        Ok(Err(e)) => {
            let sketch = ContextError::CryptoFailed(format!("create_context: {e}"));
            (Outcome::err_mutated(sketch), Err(e))
        }
        Err(_elapsed) => {
            let err =
                scp_protocol::context::builder::ContextCreationError::CreationFailed(format!(
                    "create_context exceeded {HANDLER_TIMEOUT:?} budget for context {context_id}"
                ));
            let sketch = ContextError::TransportTimeout(format!(
                "create_context exceeded {HANDLER_TIMEOUT:?} budget for context {context_id}"
            ));
            (Outcome::err_mutated(sketch), Err(err))
        }
    };

    let _ = reply.send(reply_result);
    outcome
}

#[allow(clippy::too_many_arguments)]
async fn handle_join_context_shim(
    supervisor: &Supervisor,
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

    let join_fut = crate::context::lifecycle_helpers_legacy::join_context_legacy(
        supervisor,
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

async fn handle_leave_context_shim(
    supervisor: &Supervisor,
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

    let leave_fut = crate::context::lifecycle_helpers_legacy::leave_context_legacy(
        supervisor,
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

async fn handle_close_context_shim(
    supervisor: &Supervisor,
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

    let close_fut = crate::context::lifecycle_helpers_legacy::close_context_legacy(
        supervisor,
        &handle,
        &initiator_did,
    );

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

async fn handle_export_context_shim(
    supervisor: &Supervisor,
    context_id: String,
    exporter_did: scp_identity::DID,
    reply: ExportContextReply,
) -> Outcome<()> {
    let export_fut = crate::context::lifecycle_helpers_legacy::export_context_legacy(
        supervisor,
        &context_id,
        exporter_did,
    );

    let (outcome, reply_result) = match tokio::time::timeout(HANDLER_TIMEOUT, export_fut).await {
        Ok(Ok(export)) => (Outcome::ok(()), Ok(export)),
        Ok(Err(e)) => {
            let sketch = outcome_error_sketch(&e);
            (Outcome::err(sketch), Err(e))
        }
        Err(_elapsed) => {
            let err = ContextError::TransportTimeout(format!(
                "export_context exceeded {HANDLER_TIMEOUT:?} budget for context {context_id}"
            ));
            let sketch = outcome_error_sketch(&err);
            (Outcome::err(sketch), Err(err))
        }
    };

    let _ = reply.send(reply_result);
    outcome
}

async fn handle_import_context_shim(
    supervisor: &Supervisor,
    export: Box<crate::context::export_import::ContextExport>,
    reply: ImportContextReply,
) -> Outcome<()> {
    let context_id = export.snapshot.context_id.clone();

    // Box::pin — the per-variant import future crosses clippy's 16 KB
    // stack budget (ContextExport ~2 KB + the full PerContextState-
    // construction locals inside the legacy `import_context` body).
    let import_fut = Box::pin(
        crate::context::lifecycle_helpers_legacy::import_context_legacy(supervisor, *export),
    );

    let (outcome, reply_result) = match tokio::time::timeout(HANDLER_TIMEOUT, import_fut).await {
        Ok(Ok(handle)) => (Outcome::ok_mutated(()), Ok(handle)),
        Ok(Err(e)) => {
            let sketch = outcome_error_sketch(&e);
            (Outcome::err_mutated(sketch), Err(e))
        }
        Err(_elapsed) => {
            let err = ContextError::TransportTimeout(format!(
                "import_context exceeded {HANDLER_TIMEOUT:?} budget for context {context_id}"
            ));
            let sketch = outcome_error_sketch(&err);
            (Outcome::err_mutated(sketch), Err(err))
        }
    };

    let _ = reply.send(reply_result);
    outcome
}

async fn handle_restore_context_shim(
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

    let restore_fut = crate::context::lifecycle_helpers_legacy::restore_context_legacy(
        supervisor,
        &context_id,
        &handle,
    );

    let (outcome, reply_result) = match tokio::time::timeout(HANDLER_TIMEOUT, restore_fut).await {
        Ok(Ok(())) => (Outcome::ok_mutated(()), Ok(())),
        Ok(Err(e)) => {
            let sketch = outcome_error_sketch(&e);
            (Outcome::err_mutated(sketch), Err(e))
        }
        Err(_elapsed) => {
            let err = ContextError::TransportTimeout(format!(
                "restore_context exceeded {HANDLER_TIMEOUT:?} budget for context {context_id}"
            ));
            let sketch = outcome_error_sketch(&err);
            (Outcome::err_mutated(sketch), Err(err))
        }
    };

    let _ = reply.send(reply_result);
    outcome
}

async fn handle_generate_context_access_key_shim(
    supervisor: &Supervisor,
    context_id: String,
    member_did: String,
    caller_did: String,
    reply: oneshot::Sender<Result<(), ContextError>>,
) -> Outcome<()> {
    let fut = crate::context::queries_helpers_legacy::generate_context_access_key_legacy(
        supervisor,
        &context_id,
        &member_did,
        &caller_did,
    );

    let (outcome, reply_result) = match tokio::time::timeout(HANDLER_TIMEOUT, fut).await {
        Ok(Ok(())) => (Outcome::ok_mutated(()), Ok(())),
        Ok(Err(e)) => {
            let sketch = outcome_error_sketch(&e);
            (Outcome::err_mutated(sketch), Err(e))
        }
        Err(_elapsed) => {
            let err = ContextError::TransportTimeout(format!(
                "generate_context_access_key exceeded {HANDLER_TIMEOUT:?} budget for context {context_id}"
            ));
            let sketch = outcome_error_sketch(&err);
            (Outcome::err_mutated(sketch), Err(err))
        }
    };

    let _ = reply.send(reply_result);
    outcome
}

async fn handle_revoke_context_access_key_shim(
    supervisor: &Supervisor,
    context_id: String,
    member_did: String,
    caller_did: String,
    reply: oneshot::Sender<Result<(), ContextError>>,
) -> Outcome<()> {
    let fut = crate::context::queries_helpers_legacy::revoke_context_access_key_legacy(
        supervisor,
        &context_id,
        &member_did,
        &caller_did,
    );

    let (outcome, reply_result) = match tokio::time::timeout(HANDLER_TIMEOUT, fut).await {
        Ok(Ok(())) => (Outcome::ok_mutated(()), Ok(())),
        Ok(Err(e)) => {
            let sketch = outcome_error_sketch(&e);
            (Outcome::err_mutated(sketch), Err(e))
        }
        Err(_elapsed) => {
            let err = ContextError::TransportTimeout(format!(
                "revoke_context_access_key exceeded {HANDLER_TIMEOUT:?} budget for context {context_id}"
            ));
            let sketch = outcome_error_sketch(&err);
            (Outcome::err_mutated(sketch), Err(err))
        }
    };

    let _ = reply.send(reply_result);
    outcome
}

async fn handle_restore_context_access_key_shim(
    supervisor: &Supervisor,
    context_id: String,
    member_did: String,
    caller_did: String,
    reply: oneshot::Sender<Result<(), ContextError>>,
) -> Outcome<()> {
    let fut = crate::context::queries_helpers_legacy::restore_context_access_key_legacy(
        supervisor,
        &context_id,
        &member_did,
        &caller_did,
    );

    let (outcome, reply_result) = match tokio::time::timeout(HANDLER_TIMEOUT, fut).await {
        Ok(Ok(())) => (Outcome::ok_mutated(()), Ok(())),
        Ok(Err(e)) => {
            let sketch = outcome_error_sketch(&e);
            (Outcome::err_mutated(sketch), Err(e))
        }
        Err(_elapsed) => {
            let err = ContextError::TransportTimeout(format!(
                "restore_context_access_key exceeded {HANDLER_TIMEOUT:?} budget for context {context_id}"
            ));
            let sketch = outcome_error_sketch(&err);
            (Outcome::err_mutated(sketch), Err(err))
        }
    };

    let _ = reply.send(reply_result);
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
