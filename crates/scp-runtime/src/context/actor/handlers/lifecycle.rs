//! Lifecycle handlers — see
//! [`LifecycleCommand`](crate::context::actor::commands::LifecycleCommand)
//! and plan §"Submodule organization" / row 9 of the commit ladder.
//!
//! # Commit 9 scope
//!
//! Migrates the dispatch shape: the handler takes
//! [`MutationStateView`](crate::context::actor::mutation_state_view::MutationStateView)
//! + [`ActorDeps`] + [`LifecycleCommand`], returns `Outcome<()>`.
//!
//! The underlying byte-identical implementation still lives on
//! [`ContextManager`](crate::context::manager::ContextManager): each
//! handler delegates to
//! [`ContextManager::create_context`](crate::context::manager::ContextManager::create_context),
//! [`ContextManager::join_context`](crate::context::manager::ContextManager::join_context),
//! [`ContextManager::leave_context`](crate::context::manager::ContextManager::leave_context),
//! [`ContextManager::close_context`](crate::context::manager::ContextManager::close_context),
//! [`ContextManager::export_context`](crate::context::manager::ContextManager::export_context),
//! or
//! [`ContextManager::import_context`](crate::context::manager::ContextManager::import_context).
//! The shim's job is:
//!
//! 1. Wrap every delegated call in [`tokio::time::timeout`] with a 30s
//!    budget per ADR-049 §7 / plan §"Transport timeouts inside actor
//!    handlers". Timeout maps to
//!    [`ContextError::TransportTimeout`](scp_protocol::context::ContextError::TransportTimeout).
//! 2. Preserve byte-identical on-the-wire behaviour — creation,
//!    membership, close, and export/import bytes are produced by the
//!    legacy method unchanged.
//!
//! **Create-as-prepare.** `create_context` and `join_context` are
//! legitimate saga entry points in later commits (standing-pair
//! creation, migration). In commit 9 the handler still goes through
//! `ContextManager::create_context` / `join_context` directly — saga
//! wiring lands with `handlers/standing.rs` in commit 11.
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
use crate::context::actor::commands::{
    CloseContextReply, CreateContextReply, ExportContextReply, ImportContextReply, LifecycleCommand,
};
use crate::context::actor::deps::ActorDeps;
use crate::context::actor::mutation_state_view::MutationStateView;
use crate::context::actor::outcome::Outcome;

/// Per-call transport budget for lifecycle handlers. Plan §"Transport
/// timeouts inside actor handlers": 30 seconds.
pub const HANDLER_TIMEOUT: Duration = Duration::from_secs(30);

/// Dispatch a [`LifecycleCommand`] against a mutation state view + deps
/// bundle.
///
/// Plan-conforming dispatch signature: matches the post-refactor actor
/// `run()` loop's call shape
/// (`handlers::lifecycle::dispatch(&mut self.state, &self.deps, cmd).await`).
/// `deps` is accepted for symmetry — the lifecycle handler does not yet
/// touch deps during the shim period (the transport, event log, crypto
/// providers, and persistence live on the legacy
/// [`ContextManager`](crate::context::manager::ContextManager) the view
/// borrows). Commit 12 rewires these paths to use `deps` directly once
/// the manager surface is deleted.
// `needless_pass_by_ref_mut` allow — the handler's dispatch shape
// takes `&mut MutationStateView` by contract to match the
// post-refactor actor `run()` loop's call signature
// (`handlers::lifecycle::dispatch(&mut self.state, &self.deps, cmd).await`).
// Commit 9's shim body only delegates to
// [`ContextManager`](crate::context::manager::ContextManager) and
// never reads the tracker — the legacy method still owns the per-
// context mutation paths — but switching the parameter to `&` would
// force a signature change at the shim's callers that we would have
// to revert when commit 12 lands the real state mutations on the
// actor's owned [`PerContextState`](crate::context::actor::state::PerContextState).
#[allow(clippy::needless_pass_by_ref_mut)]
pub async fn dispatch(
    view: &mut MutationStateView<'_>,
    _deps: &ActorDeps,
    cmd: LifecycleCommand,
) -> Outcome<()> {
    // `Box::pin` the dispatch future — the total size of the
    // per-variant locals (ContextParams ~1KB, ContextExport ~2KB, the
    // rebuilt ContextHandle, a signing key, and the 30s-timeout future
    // inside each handler) crosses clippy's 16-KB stack budget for
    // async futures. Boxing here moves the per-variant state onto the
    // heap once per dispatch.
    Box::pin(dispatch_inner(view, cmd)).await
}

/// Shim-callable dispatch. Used by
/// [`Supervisor::dispatch_command`](crate::context::supervisor::supervisor::Supervisor::dispatch_command)
/// during the commits-9-to-11 migration window — deleted in commit 12
/// when the shim dissolves and the actor's `run()` loop is the only
/// caller of [`dispatch`].
///
/// Lifecycle commands do not yet touch [`ActorDeps`] during the shim
/// period (every resource the legacy lifecycle methods need lives on
/// the [`ContextManager`](crate::context::manager::ContextManager) the
/// view borrows). This entry point exists so callers can route
/// lifecycle operations through the shim without synthesizing an
/// [`ActorDeps`] — matching the pattern established for queries (commit
/// 7) and messaging (commit 8).
// `needless_pass_by_ref_mut` allow — see the comment on
// [`dispatch`] above. `dispatch_from_shim` shares the `&mut`
// contract with the actor-side entry point for signature stability
// across the commit ladder.
#[allow(clippy::needless_pass_by_ref_mut)]
pub(crate) async fn dispatch_from_shim(
    view: &mut MutationStateView<'_>,
    cmd: LifecycleCommand,
) -> Outcome<()> {
    // See the comment on [`dispatch`] for the `Box::pin` rationale.
    Box::pin(dispatch_inner(view, cmd)).await
}

async fn dispatch_inner(view: &MutationStateView<'_>, cmd: LifecycleCommand) -> Outcome<()> {
    match cmd {
        LifecycleCommand::Placeholder { reply } => reply_not_implemented(reply),
        LifecycleCommand::CreateContext { payload, reply } => {
            let p = *payload;
            handle_create_context(
                view,
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
                view,
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
                view,
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
            handle_close_context(view, p.context_id, p.params, p.initiator_did, reply).await
        }
        LifecycleCommand::ExportContext {
            context_id,
            exporter_did,
            reply,
        } => handle_export_context(view, context_id, exporter_did, reply).await,
        LifecycleCommand::ImportContext { export, reply } => {
            // Box::pin — the per-variant import future crosses clippy's
            // 16 KB stack budget (ContextExport ~2 KB + the full
            // PerContextState-construction locals inside the hoisted
            // `lifecycle_helpers::import_context` body). Boxing moves the
            // state onto the heap for this variant only.
            Box::pin(handle_import_context(view, export, reply)).await
        }
    }
}

/// Handle [`LifecycleCommand::CreateContext`]: delegate to
/// [`ContextManager::create_context`](crate::context::manager::ContextManager::create_context)
/// under a 30s timeout.
///
/// Saga-compatible: create-as-prepare support lands with
/// `handlers/standing.rs` in commit 11; commit 9's shim routes the
/// command through the legacy method directly.
async fn handle_create_context(
    view: &MutationStateView<'_>,
    context_id: String,
    params: scp_protocol::context::params::ContextParams,
    creator_did: scp_identity::DID,
    local_pseudonym: Option<[u8; 32]>,
    reply: CreateContextReply,
) -> Outcome<()> {
    let manager = std::sync::Arc::clone(view.manager());
    let create_fut = crate::context::lifecycle_helpers::create_context(
        &manager,
        context_id.clone(),
        params,
        creator_did,
        local_pseudonym,
    );

    let (outcome, reply_result) = match tokio::time::timeout(HANDLER_TIMEOUT, create_fut).await {
        Ok(Ok(handle)) => (Outcome::ok_mutated(()), Ok(handle)),
        Ok(Err(e)) => {
            // Creation errors carry their own dedicated `ContextCreationError`
            // type. The Outcome sink translates them into the generic
            // `ContextError::CryptoFailed(..)` bucket — the actor's dirty
            // tracking cares only about `mutated`. Callers observe the
            // typed `ContextCreationError` through the oneshot reply.
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

/// Handle [`LifecycleCommand::JoinContext`]: delegate to
/// [`ContextManager::join_context`](crate::context::manager::ContextManager::join_context)
/// under a 30s timeout.
#[allow(clippy::too_many_arguments)] // mirrors the legacy method's signature surface
async fn handle_join_context(
    view: &MutationStateView<'_>,
    context_id: String,
    params: scp_protocol::context::params::ContextParams,
    key_package: scp_protocol::context::membership::KeyPackage,
    spending_ucan: Option<&scp_protocol::crypto::ucan::UcanToken>,
    local_pseudonym: Option<[u8; 32]>,
    reply: oneshot::Sender<Result<(), ContextError>>,
) -> Outcome<()> {
    let manager = std::sync::Arc::clone(view.manager());

    // Rebuild an ephemeral handle for the legacy method's signature.
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
        &manager,
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

/// Handle [`LifecycleCommand::LeaveContext`]: delegate to
/// [`ContextManager::leave_context`](crate::context::manager::ContextManager::leave_context)
/// under a 30s timeout.
async fn handle_leave_context(
    view: &MutationStateView<'_>,
    context_id: String,
    params: scp_protocol::context::params::ContextParams,
    caller_did: scp_identity::DID,
    member_did: scp_identity::DID,
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

    let leave_fut = crate::context::lifecycle_helpers::leave_context(
        &manager,
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

/// Handle [`LifecycleCommand::CloseContext`]: delegate to
/// [`ContextManager::close_context`](crate::context::manager::ContextManager::close_context)
/// under a 30s timeout. Only valid on `SingleAdmin` governance
/// contexts; multi-admin contexts must use the governance path
/// (`GovernanceAction::CloseContext`) — the legacy method enforces
/// that gate, we just delegate.
async fn handle_close_context(
    view: &MutationStateView<'_>,
    context_id: String,
    params: scp_protocol::context::params::ContextParams,
    initiator_did: scp_identity::DID,
    reply: CloseContextReply,
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

    let close_fut =
        crate::context::lifecycle_helpers::close_context(&manager, &handle, &initiator_did);

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

/// Handle [`LifecycleCommand::ExportContext`]: delegate to
/// [`ContextManager::export_context`](crate::context::manager::ContextManager::export_context)
/// under a 30s timeout.
async fn handle_export_context(
    view: &MutationStateView<'_>,
    context_id: String,
    exporter_did: scp_identity::DID,
    reply: ExportContextReply,
) -> Outcome<()> {
    let manager = std::sync::Arc::clone(view.manager());

    let export_fut =
        crate::context::lifecycle_helpers::export_context(&manager, &context_id, exporter_did);

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

/// Handle [`LifecycleCommand::ImportContext`]: delegate to
/// [`ContextManager::import_context`](crate::context::manager::ContextManager::import_context)
/// under a 30s timeout. The C3 per-instance wipe policy is enforced
/// by the legacy method; the handler passes the parsed export through
/// verbatim.
async fn handle_import_context(
    view: &MutationStateView<'_>,
    export: Box<crate::context::export_import::ContextExport>,
    reply: ImportContextReply,
) -> Outcome<()> {
    let manager = std::sync::Arc::clone(view.manager());
    let context_id = export.snapshot.context_id.clone();

    // Unbox at the last possible moment to minimize stack-held size
    // across the delegated await. `Box::pin` the inner future so the
    // hoisted `lifecycle_helpers::import_context` body's 12 KB+ locals
    // do not inflate `handle_import_context`'s own future past clippy's
    // 16 KB stack budget (ADR-049 commit 12c.2).
    let import_fut = Box::pin(crate::context::lifecycle_helpers::import_context(
        &manager, *export,
    ));

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
    const MSG: &str = "LifecycleCommand::Placeholder — real variants \
                       CreateContext/JoinContext/LeaveContext/CloseContext/\
                       ExportContext/ImportContext land in commit 9 of ADR-049; \
                       Placeholder retained for commit-6 compile stability and \
                       deleted in commit 12 with the shim";
    let _ = reply.send(Err(ContextError::NotImplemented(MSG.to_owned())));
    Outcome::err(ContextError::NotImplemented(MSG.to_owned()))
}
