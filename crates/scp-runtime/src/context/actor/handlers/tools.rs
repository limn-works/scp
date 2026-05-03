//! Tools handlers — see
//! [`ToolsCommand`](crate::context::actor::commands::ToolsCommand)
//! and spec §5.16 / §19.7.
//!
//! # Phase 2A.4 -- actor-shape dispatch
//!
//! The handler's primary entry point [`dispatch`] takes
//! `(&mut PerContextState, &ActorDeps, ToolsCommand)` and routes the
//! actor-owned hard-rate-limit helpers through
//! [`crate::context::tools_helpers`]. The shim entry point remains for
//! missing-actor fallback and routes through
//! [`crate::context::tools_helpers_legacy`].
//!
//! # SAGA WIRING DEFERRED — see
//! `.docs/adrs/DEFERRED-commit-11-saga-use-cases.md`.
//!
//! The `InitiateCrossContextToolInvocation` saga-initiator variant
//! returns [`ContextError::NotImplemented`](scp_protocol::context::ContextError::NotImplemented)
//! because cross-context tool-invocation transport is spec-gapped — the
//! spec does not yet define:
//!   - the wire format for forwarding a tool invocation from the
//!     calling context to the target context,
//!   - which party is responsible for presenting the UCAN proof at the
//!     target (caller forwards vs. target fetches from UCAN store),
//!   - how the tool's `ToolInvokedEvent` is relayed back to the caller
//!     and whether the caller's event log records it separately from
//!     the target's event log.
//!
//! Until those land, the saga-initiator path returns
//! `ContextError::NotImplemented`. Non-saga commands are fully migrated
//! in this commit (ADR-049 commit 11). Note:
//! [`ContextManager::invoke_tool_with_economy`](crate::context::supervisor::Supervisor::invoke_tool_with_economy)
//! takes a generic executor closure that cannot cross the actor
//! mailbox; it is not migrated to a command variant and continues to
//! run on the direct manager surface (FFI bridges invoke it inline).

use std::time::Duration;

use scp_protocol::context::ContextError;
use tokio::sync::oneshot;

use crate::context::actor::commands::ToolsCommand;
use crate::context::actor::deps::ActorDeps;
use crate::context::actor::outcome::Outcome;
use crate::context::actor::state::PerContextState;
use crate::context::supervisor::Supervisor;

/// Per-call transport budget for tools handlers. Plan §"Transport
/// timeouts inside actor handlers": 30 seconds.
pub const HANDLER_TIMEOUT: Duration = Duration::from_secs(30);

/// Dispatch a [`ToolsCommand`] against actor-owned state and
/// capability-reduced dependencies.
pub async fn dispatch(
    state: &mut PerContextState,
    _deps: &ActorDeps,
    cmd: ToolsCommand,
) -> Outcome<()> {
    dispatch_inner(state, cmd).await
}

/// Shim-callable dispatch. Used by
/// [`Supervisor::dispatch_tools_command`](crate::context::supervisor::supervisor::Supervisor::dispatch_tools_command).
///
/// # Supervisor receiver (ADR-049 commit 12)
pub(crate) async fn dispatch_from_shim(supervisor: &Supervisor, cmd: ToolsCommand) -> Outcome<()> {
    dispatch_from_shim_inner(supervisor, cmd).await
}

async fn dispatch_inner(state: &mut PerContextState, cmd: ToolsCommand) -> Outcome<()> {
    match cmd {
        ToolsCommand::Placeholder { reply } => reply_not_implemented(reply),
        ToolsCommand::TryConsumeHardRateLimit {
            did,
            now_secs,
            reply,
            ..
        } => handle_try_consume_hard_rate_limit(state, &did, now_secs, reply).await,
        ToolsCommand::RefundHardRateLimit { did, reply, .. } => {
            handle_refund_hard_rate_limit(state, &did, reply).await
        }
        ToolsCommand::InitiateCrossContextToolInvocation { reply, .. } => {
            reply_saga_deferred(reply)
        }
    }
}

async fn dispatch_from_shim_inner(supervisor: &Supervisor, cmd: ToolsCommand) -> Outcome<()> {
    match cmd {
        ToolsCommand::Placeholder { reply } => reply_not_implemented(reply),
        ToolsCommand::TryConsumeHardRateLimit {
            context_id,
            did,
            now_secs,
            reply,
        } => {
            shim_handle_try_consume_hard_rate_limit(supervisor, &context_id, &did, now_secs, reply)
                .await
        }
        ToolsCommand::RefundHardRateLimit {
            context_id,
            did,
            reply,
        } => shim_handle_refund_hard_rate_limit(supervisor, &context_id, &did, reply).await,
        ToolsCommand::InitiateCrossContextToolInvocation { reply, .. } => {
            reply_saga_deferred(reply)
        }
    }
}

/// Handle [`ToolsCommand::TryConsumeHardRateLimit`] — delegates to
/// [`tools_helpers::try_consume_hard_rate_limit`](crate::context::tools_helpers::try_consume_hard_rate_limit)
/// under a 30s timeout.
///
/// The legacy method is infallible and returns `bool`. Under timeout we
/// return `Err(TransportTimeout)` — callers cannot distinguish between
/// "token consumed" and "context unknown" without the real answer, so a
/// refund attempt on a timed-out consume is unsafe. Surfacing the
/// timeout is the correct defensive move.
async fn handle_try_consume_hard_rate_limit(
    state: &mut PerContextState,
    did: &scp_identity::DID,
    now_secs: u64,
    reply: oneshot::Sender<Result<bool, ContextError>>,
) -> Outcome<()> {
    let consume_fut =
        async { crate::context::tools_helpers::try_consume_hard_rate_limit(state, did, now_secs) };

    let (outcome, reply_result) = match tokio::time::timeout(HANDLER_TIMEOUT, consume_fut).await {
        Ok(consumed) => {
            // `consumed == true` ⇒ token taken from the bucket OR the
            // context is unknown (legacy pass-through contract). Both
            // cases mutate observable state iff the context was known,
            // so flag `ok_mutated` to be safe: a successful `true` on
            // a known context is the dominant path.
            let outcome = if consumed {
                Outcome::ok_mutated(())
            } else {
                Outcome::ok(())
            };
            (outcome, Ok(consumed))
        }
        Err(_elapsed) => {
            let err = ContextError::TransportTimeout(format!(
                "try_consume_hard_rate_limit exceeded {HANDLER_TIMEOUT:?} budget"
            ));
            let sketch = outcome_error_sketch(&err);
            (Outcome::err_mutated(sketch), Err(err))
        }
    };

    let _ = reply.send(reply_result);
    outcome
}

/// Handle [`ToolsCommand::RefundHardRateLimit`] — delegates to
/// [`tools_helpers::refund_hard_rate_limit`](crate::context::tools_helpers::refund_hard_rate_limit)
/// under a 30s timeout.
async fn handle_refund_hard_rate_limit(
    state: &mut PerContextState,
    did: &scp_identity::DID,
    reply: oneshot::Sender<Result<(), ContextError>>,
) -> Outcome<()> {
    let refund_fut = async { crate::context::tools_helpers::refund_hard_rate_limit(state, did) };

    let (outcome, reply_result) = match tokio::time::timeout(HANDLER_TIMEOUT, refund_fut).await {
        Ok(()) => (Outcome::ok_mutated(()), Ok(())),
        Err(_elapsed) => {
            let err = ContextError::TransportTimeout(format!(
                "refund_hard_rate_limit exceeded {HANDLER_TIMEOUT:?} budget"
            ));
            let sketch = outcome_error_sketch(&err);
            (Outcome::err_mutated(sketch), Err(err))
        }
    };

    let _ = reply.send(reply_result);
    outcome
}

async fn shim_handle_try_consume_hard_rate_limit(
    supervisor: &Supervisor,
    context_id: &str,
    did: &scp_identity::DID,
    now_secs: u64,
    reply: oneshot::Sender<Result<bool, ContextError>>,
) -> Outcome<()> {
    let consume_fut = crate::context::tools_helpers_legacy::try_consume_hard_rate_limit_legacy(
        supervisor, context_id, did, now_secs,
    );

    let (outcome, reply_result) = match tokio::time::timeout(HANDLER_TIMEOUT, consume_fut).await {
        Ok(consumed) => {
            let outcome = if consumed {
                Outcome::ok_mutated(())
            } else {
                Outcome::ok(())
            };
            (outcome, Ok(consumed))
        }
        Err(_elapsed) => {
            let err = ContextError::TransportTimeout(format!(
                "try_consume_hard_rate_limit exceeded {HANDLER_TIMEOUT:?} budget for context {context_id}"
            ));
            let sketch = outcome_error_sketch(&err);
            (Outcome::err_mutated(sketch), Err(err))
        }
    };

    let _ = reply.send(reply_result);
    outcome
}

async fn shim_handle_refund_hard_rate_limit(
    supervisor: &Supervisor,
    context_id: &str,
    did: &scp_identity::DID,
    reply: oneshot::Sender<Result<(), ContextError>>,
) -> Outcome<()> {
    let refund_fut = crate::context::tools_helpers_legacy::refund_hard_rate_limit_legacy(
        supervisor, context_id, did,
    );

    let (outcome, reply_result) = match tokio::time::timeout(HANDLER_TIMEOUT, refund_fut).await {
        Ok(()) => (Outcome::ok_mutated(()), Ok(())),
        Err(_elapsed) => {
            let err = ContextError::TransportTimeout(format!(
                "refund_hard_rate_limit exceeded {HANDLER_TIMEOUT:?} budget for context {context_id}"
            ));
            let sketch = outcome_error_sketch(&err);
            (Outcome::err_mutated(sketch), Err(err))
        }
    };

    let _ = reply.send(reply_result);
    outcome
}

/// Produce a best-effort clone-equivalent `ContextError` for the
/// handler's [`Outcome`] sink.
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
        ContextError::NotImplemented(msg) => ContextError::NotImplemented(msg.clone()),
        other => ContextError::CryptoFailed(format!("{other}")),
    }
}

fn reply_not_implemented(reply: oneshot::Sender<Result<(), ContextError>>) -> Outcome<()> {
    const MSG: &str = "ToolsCommand::Placeholder — real variants migrate in commit 11 of \
                       ADR-049; Placeholder retained for commit-6 compile stability and \
                       deleted in commit 12 with the shim";
    let _ = reply.send(Err(ContextError::NotImplemented(MSG.to_owned())));
    Outcome::err(ContextError::NotImplemented(MSG.to_owned()))
}

fn reply_saga_deferred(
    reply: oneshot::Sender<Result<crate::context::supervisor::saga_journal::SagaId, ContextError>>,
) -> Outcome<()> {
    const MSG: &str = "tools::initiate_cross_context_tool_invocation — saga wiring deferred \
                       to commit 11.5 per 5 enumerated spec gaps; see \
                       .docs/adrs/DEFERRED-commit-11-saga-use-cases.md (gap 2: cross-context \
                       tool invocation transport)";
    let _ = reply.send(Err(ContextError::NotImplemented(MSG.to_owned())));
    Outcome::err(ContextError::NotImplemented(MSG.to_owned()))
}
