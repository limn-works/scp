//! Lifecycle handlers — see
//! [`LifecycleCommand`](crate::context::actor::commands::LifecycleCommand).
//!
//! # ADR-049 Phase 2A.9 — actor-shape dispatch
//!
//! After Phase 2A.9 the lifecycle handler exposes two dispatch entry
//! points:
//!
//! - [`dispatch`] takes
//!   `(&mut PerContextState, &ActorDeps, LifecycleCommand)` and is the
//!   actor mailbox path. Wired from `actor/mod.rs::dispatch_state`.
//! - [`dispatch_from_shim`] takes `(&Supervisor, LifecycleCommand)` and
//!   is the supervisor direct-shim fallback. Wired from
//!   [`Supervisor::dispatch_lifecycle_command`](crate::context::supervisor::supervisor::Supervisor::dispatch_lifecycle_command)
//!   for callers without a per-context actor (the major Create / Join /
//!   Leave / Close / Import / Restore variants — see
//!   [`Supervisor::lifecycle_command_context_id`](crate::context::supervisor::supervisor::Supervisor)
//!   which returns `None` for those payloads). Removed at Phase 2A
//!   finalization with the rest of the supervisor shim.
//!
//! Both entry points wrap each delegated call in
//! [`tokio::time::timeout`] with a 30s budget per ADR-049 §7 / plan
//! §"Transport timeouts inside actor handlers". Timeout maps to
//! [`ContextError::TransportTimeout`](scp_protocol::context::ContextError::TransportTimeout).
//!
//! # Behavior preservation
//!
//! Both paths invoke byte-identical bodies:
//!
//! - `dispatch_from_shim` calls the
//!   [`crate::context::lifecycle_helpers_legacy`] / `_legacy` twins
//!   directly (legacy `&Supervisor` lock-and-call shape).
//! - `dispatch` calls the actor-shape thin wrappers in
//!   [`crate::context::lifecycle_helpers`], which themselves delegate
//!   to the same `_legacy` body via
//!   [`SupervisorHandle::shim_supervisor`](crate::context::supervisor::handle::SupervisorHandle::shim_supervisor)
//!   (Phase 2A.6 TTL pattern). The legacy body is the only authoritative
//!   implementation until Phase 2A finalization dissolves the contexts
//!   `DashMap`.

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
// Actor-shape entry — used by actor/mod.rs::dispatch_state
// ---------------------------------------------------------------------------

/// Dispatch a [`LifecycleCommand`] against actor-owned state + deps.
///
/// Plan-conforming dispatch signature: matches the post-refactor actor
/// `run()` loop's call shape. Every variant routes through the
/// actor-shape [`crate::context::lifecycle_helpers`] thin wrappers,
/// which currently delegate to the legacy `_legacy` bodies via
/// [`SupervisorHandle::shim_supervisor`](crate::context::supervisor::handle::SupervisorHandle::shim_supervisor)
/// because the contexts `DashMap` still owns the authoritative state
/// for the major Create / Join / Leave / Close / Import / Restore
/// payloads.
///
/// `state` is reserved for handler-uniformity — Phase 2A.9 wires the
/// actor-shape signature; full per-actor state ownership for lifecycle
/// payloads lands at Phase 2A finalization when the contexts map
/// dissolves.
pub async fn dispatch(
    state: &mut PerContextState,
    deps: &ActorDeps,
    cmd: LifecycleCommand,
) -> Outcome<()> {
    // `Box::pin` the dispatch future — the total size of the
    // per-variant locals (ContextParams ~1KB, ContextExport ~2KB, the
    // rebuilt ContextHandle, a signing key, and the 30s-timeout future
    // inside each handler) crosses clippy's 16-KB stack budget for
    // async futures. Boxing here moves the per-variant state onto the
    // heap once per dispatch.
    Box::pin(dispatch_state(state, deps, cmd)).await
}

#[allow(clippy::too_many_lines)] // Flat match over every LifecycleCommand variant.
async fn dispatch_state(
    state: &mut PerContextState,
    deps: &ActorDeps,
    cmd: LifecycleCommand,
) -> Outcome<()> {
    match cmd {
        LifecycleCommand::Placeholder { reply } => reply_not_implemented(reply),
        LifecycleCommand::CreateContext { payload, reply } => {
            let p = *payload;
            handle_create_context_actor(
                deps,
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
            handle_close_context_actor(
                state,
                deps,
                p.context_id,
                p.params,
                p.initiator_did,
                reply,
            )
            .await
        }
        LifecycleCommand::ExportContext {
            context_id,
            exporter_did,
            reply,
        } => handle_export_context_actor(state, deps, context_id, exporter_did, reply).await,
        LifecycleCommand::ImportContext { export, reply } => {
            // Box::pin — the per-variant import future crosses clippy's
            // 16 KB stack budget (ContextExport ~2 KB + the full
            // PerContextState-construction locals inside the hoisted
            // `lifecycle_helpers_legacy::import_context_legacy` body).
            // Boxing moves the state onto the heap for this variant only.
            Box::pin(handle_import_context_actor(deps, export, reply)).await
        }
        LifecycleCommand::RestoreContext { payload, reply } => {
            let p = *payload;
            // Box::pin — restore_context's body is large (rebuilds the
            // full PerContextState from the persisted snapshot,
            // including governance / membership / broadcast / MLS
            // crypto state). The per-variant locals plus the timeout
            // future cross clippy's 16 KB stack-future budget.
            Box::pin(handle_restore_context_actor(
                deps,
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
            handle_generate_context_access_key_actor(
                deps, context_id, member_did, caller_did, reply,
            )
            .await
        }
        LifecycleCommand::RevokeContextAccessKey {
            context_id,
            member_did,
            caller_did,
            reply,
        } => {
            handle_revoke_context_access_key_actor(
                deps, context_id, member_did, caller_did, reply,
            )
            .await
        }
        LifecycleCommand::RestoreContextAccessKey {
            context_id,
            member_did,
            caller_did,
            reply,
        } => {
            handle_restore_context_access_key_actor(
                deps, context_id, member_did, caller_did, reply,
            )
            .await
        }
    }
}

// ---------------------------------------------------------------------------
// Shim-callable dispatch — used by Supervisor::dispatch_lifecycle_command
// ---------------------------------------------------------------------------

/// Shim-callable dispatch. Used by
/// [`Supervisor::dispatch_lifecycle_command`](crate::context::supervisor::supervisor::Supervisor::dispatch_lifecycle_command)
/// during the Phase 2A migration window when no per-context actor
/// exists for the target context — every variant routes through the
/// legacy [`crate::context::lifecycle_helpers_legacy`] /
/// [`crate::context::queries_helpers`] supervisor-shape twins.
/// Removed at Phase 2A finalization with the rest of the supervisor
/// shim.
pub(crate) async fn dispatch_from_shim(
    supervisor: &Supervisor,
    cmd: LifecycleCommand,
) -> Outcome<()> {
    // See the comment on [`dispatch`] for the `Box::pin` rationale.
    Box::pin(dispatch_inner(supervisor, cmd)).await
}

#[allow(clippy::too_many_lines)] // Flat match over every LifecycleCommand variant.
async fn dispatch_inner(supervisor: &Supervisor, cmd: LifecycleCommand) -> Outcome<()> {
    match cmd {
        LifecycleCommand::Placeholder { reply } => reply_not_implemented(reply),
        LifecycleCommand::CreateContext { payload, reply } => {
            let p = *payload;
            handle_create_context(
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
            handle_join_context(
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
            handle_leave_context(
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
            handle_close_context(supervisor, p.context_id, p.params, p.initiator_did, reply).await
        }
        LifecycleCommand::ExportContext {
            context_id,
            exporter_did,
            reply,
        } => handle_export_context(supervisor, context_id, exporter_did, reply).await,
        LifecycleCommand::ImportContext { export, reply } => {
            // Box::pin — same 16 KB stack-future budget rationale as
            // the actor-shape `dispatch_state` arm above.
            Box::pin(handle_import_context(supervisor, export, reply)).await
        }
        LifecycleCommand::RestoreContext { payload, reply } => {
            let p = *payload;
            // Box::pin — same 16 KB stack-future budget rationale.
            Box::pin(handle_restore_context(
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
            handle_generate_context_access_key(
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
            handle_revoke_context_access_key(supervisor, context_id, member_did, caller_did, reply)
                .await
        }
        LifecycleCommand::RestoreContextAccessKey {
            context_id,
            member_did,
            caller_did,
            reply,
        } => {
            handle_restore_context_access_key(supervisor, context_id, member_did, caller_did, reply)
                .await
        }
    }
}

// ---------------------------------------------------------------------------
// Supervisor-shape handlers — used by dispatch_from_shim
// ---------------------------------------------------------------------------

/// Handle [`LifecycleCommand::CreateContext`] (supervisor-shape):
/// delegate to [`crate::context::lifecycle_helpers_legacy::create_context_legacy`]
/// under a 30s timeout.
async fn handle_create_context(
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

/// Handle [`LifecycleCommand::JoinContext`] (supervisor-shape).
#[allow(clippy::too_many_arguments)] // mirrors the legacy method's signature surface
async fn handle_join_context(
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

/// Handle [`LifecycleCommand::LeaveContext`] (supervisor-shape).
async fn handle_leave_context(
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

/// Handle [`LifecycleCommand::CloseContext`] (supervisor-shape).
async fn handle_close_context(
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

/// Handle [`LifecycleCommand::ExportContext`] (supervisor-shape).
async fn handle_export_context(
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

/// Handle [`LifecycleCommand::ImportContext`] (supervisor-shape).
async fn handle_import_context(
    supervisor: &Supervisor,
    export: Box<crate::context::export_import::ContextExport>,
    reply: ImportContextReply,
) -> Outcome<()> {
    let context_id = export.snapshot.context_id.clone();

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

/// Handle [`LifecycleCommand::RestoreContext`] (supervisor-shape).
async fn handle_restore_context(
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

/// Handle [`LifecycleCommand::GenerateContextAccessKey`] (supervisor-shape).
async fn handle_generate_context_access_key(
    supervisor: &Supervisor,
    context_id: String,
    member_did: String,
    caller_did: String,
    reply: oneshot::Sender<Result<(), ContextError>>,
) -> Outcome<()> {
    let fut = crate::context::queries_helpers::generate_context_access_key(
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

/// Handle [`LifecycleCommand::RevokeContextAccessKey`] (supervisor-shape).
async fn handle_revoke_context_access_key(
    supervisor: &Supervisor,
    context_id: String,
    member_did: String,
    caller_did: String,
    reply: oneshot::Sender<Result<(), ContextError>>,
) -> Outcome<()> {
    let fut = crate::context::queries_helpers::revoke_context_access_key(
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

/// Handle [`LifecycleCommand::RestoreContextAccessKey`] (supervisor-shape).
async fn handle_restore_context_access_key(
    supervisor: &Supervisor,
    context_id: String,
    member_did: String,
    caller_did: String,
    reply: oneshot::Sender<Result<(), ContextError>>,
) -> Outcome<()> {
    let fut = crate::context::queries_helpers::restore_context_access_key(
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
// Actor-shape handlers — used by dispatch
// ---------------------------------------------------------------------------

/// Handle [`LifecycleCommand::CreateContext`] (actor-shape):
/// bootstrap entry — `lifecycle_helpers::create_context` takes only
/// `&ActorDeps` and constructs a fresh PerContextState in the legacy
/// contexts map via the shim escape.
async fn handle_create_context_actor(
    deps: &ActorDeps,
    context_id: String,
    params: scp_protocol::context::params::ContextParams,
    creator_did: scp_identity::DID,
    local_pseudonym: Option<[u8; 32]>,
    reply: CreateContextReply,
) -> Outcome<()> {
    let create_fut = crate::context::lifecycle_helpers::create_context(
        deps,
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

/// Handle [`LifecycleCommand::JoinContext`] (actor-shape).
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

/// Handle [`LifecycleCommand::LeaveContext`] (actor-shape).
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

/// Handle [`LifecycleCommand::CloseContext`] (actor-shape).
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

/// Handle [`LifecycleCommand::ExportContext`] (actor-shape).
async fn handle_export_context_actor(
    state: &mut PerContextState,
    deps: &ActorDeps,
    context_id: String,
    exporter_did: scp_identity::DID,
    reply: ExportContextReply,
) -> Outcome<()> {
    let export_fut = crate::context::lifecycle_helpers::export_context(
        state,
        deps,
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

/// Handle [`LifecycleCommand::ImportContext`] (actor-shape):
/// bootstrap entry — `lifecycle_helpers::import_context` takes only
/// `&ActorDeps`.
async fn handle_import_context_actor(
    deps: &ActorDeps,
    export: Box<crate::context::export_import::ContextExport>,
    reply: ImportContextReply,
) -> Outcome<()> {
    let context_id = export.snapshot.context_id.clone();

    let import_fut =
        Box::pin(crate::context::lifecycle_helpers::import_context(deps, *export));

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

/// Handle [`LifecycleCommand::RestoreContext`] (actor-shape):
/// bootstrap entry — `lifecycle_helpers::restore_context` takes only
/// `&ActorDeps`.
async fn handle_restore_context_actor(
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

    let restore_fut =
        crate::context::lifecycle_helpers::restore_context(deps, &context_id, &handle);

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

/// Handle [`LifecycleCommand::GenerateContextAccessKey`] (actor-shape).
///
/// `queries_helpers::generate_context_access_key` is still
/// supervisor-shape (queries domain has not migrated yet), so we
/// reach it via the
/// [`SupervisorHandle::shim_supervisor`](crate::context::supervisor::handle::SupervisorHandle::shim_supervisor)
/// escape.
async fn handle_generate_context_access_key_actor(
    deps: &ActorDeps,
    context_id: String,
    member_did: String,
    caller_did: String,
    reply: oneshot::Sender<Result<(), ContextError>>,
) -> Outcome<()> {
    let supervisor = deps.supervisor.shim_supervisor();
    let fut = crate::context::queries_helpers::generate_context_access_key(
        supervisor.as_ref(),
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

/// Handle [`LifecycleCommand::RevokeContextAccessKey`] (actor-shape).
async fn handle_revoke_context_access_key_actor(
    deps: &ActorDeps,
    context_id: String,
    member_did: String,
    caller_did: String,
    reply: oneshot::Sender<Result<(), ContextError>>,
) -> Outcome<()> {
    let supervisor = deps.supervisor.shim_supervisor();
    let fut = crate::context::queries_helpers::revoke_context_access_key(
        supervisor.as_ref(),
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

/// Handle [`LifecycleCommand::RestoreContextAccessKey`] (actor-shape).
async fn handle_restore_context_access_key_actor(
    deps: &ActorDeps,
    context_id: String,
    member_did: String,
    caller_did: String,
    reply: oneshot::Sender<Result<(), ContextError>>,
) -> Outcome<()> {
    let supervisor = deps.supervisor.shim_supervisor();
    let fut = crate::context::queries_helpers::restore_context_access_key(
        supervisor.as_ref(),
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
// Helpers shared by both dispatch paths
// ---------------------------------------------------------------------------

/// Produce a best-effort clone-equivalent `ContextError` for the
/// handler's [`Outcome`] sink given a borrowed error that cannot be
/// cloned. Mirrors the pattern used in
/// [`crate::context::actor::handlers::messaging`].
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
    const MSG: &str = "LifecycleCommand::Placeholder — real variants \
                       CreateContext/JoinContext/LeaveContext/CloseContext/\
                       ExportContext/ImportContext/RestoreContext/\
                       GenerateContextAccessKey/RevokeContextAccessKey/\
                       RestoreContextAccessKey are wired in Phase 2A.9 of \
                       ADR-049; Placeholder retained for commit-6 mailbox \
                       handshake compatibility and deleted at Phase 2A \
                       finalization with the shim";
    let _ = reply.send(Err(ContextError::NotImplemented(MSG.to_owned())));
    Outcome::err(ContextError::NotImplemented(MSG.to_owned()))
}
