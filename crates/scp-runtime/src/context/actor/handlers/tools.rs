//! Tools handlers — see
//! [`ToolsCommand`](crate::context::actor::commands::ToolsCommand)
//! and spec §5.16 / §19.7.
//!
//! # Phase 2A.4 + Phase 2A finalization -- actor-shape dispatch
//!
//! The handler's primary entry point [`dispatch`] takes
//! `(&mut PerContextState, &ActorDeps, ToolsCommand)` and routes the
//! actor-owned hard-rate-limit helpers plus the tool-economy reserve /
//! settle phases through [`crate::context::tools_helpers`]. The economy
//! pipeline's non-`Send` executor runs supervisor-side between the
//! [`ToolsCommand::ReserveToolEconomy`] and [`ToolsCommand::SettleToolEconomy`]
//! mailbox round-trips (see
//! [`crate::context::tools_helpers::invoke_tool_with_economy`]).
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
//! `ContextError::NotImplemented`. All other tool commands run on the
//! actor:
//! [`Supervisor::invoke_tool_with_economy`](crate::context::supervisor::Supervisor::invoke_tool_with_economy)
//! takes a generic non-`Send` executor closure that cannot cross the
//! actor mailbox, so its economy bookkeeping is split into the
//! [`ToolsCommand::ReserveToolEconomy`] / [`ToolsCommand::SettleToolEconomy`]
//! mailbox commands (which run on owned state) while the executor itself
//! runs supervisor-side between the two round-trips.

use std::time::Duration;

use scp_protocol::context::ContextError;
use tokio::sync::oneshot;

use crate::context::actor::commands::ToolsCommand;
use crate::context::actor::deps::ActorDeps;
use crate::context::actor::outcome::{Outcome, outcome_error_sketch};
use crate::context::actor::state::PerContextState;

/// Per-call transport budget for tools handlers. Plan §"Transport
/// timeouts inside actor handlers": 30 seconds.
pub const HANDLER_TIMEOUT: Duration = Duration::from_secs(30);

/// Dispatch a [`ToolsCommand`] against actor-owned state and
/// capability-reduced dependencies.
pub async fn dispatch(
    state: &mut PerContextState,
    deps: &ActorDeps,
    cmd: ToolsCommand,
) -> Outcome<()> {
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
        ToolsCommand::ReserveToolEconomy {
            context_id,
            invoker_did,
            spending_ucan,
            now_secs,
            reply,
        } => {
            handle_reserve_tool_economy(
                state,
                deps,
                &context_id,
                &invoker_did,
                spending_ucan.as_deref(),
                now_secs,
                reply,
            )
            .await
        }
        ToolsCommand::SettleToolEconomy {
            context_id,
            invoker_did,
            request,
            reply,
        } => {
            handle_settle_tool_economy(state, deps, &context_id, &invoker_did, *request, reply)
                .await
        }
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

/// Handle [`ToolsCommand::ReserveToolEconomy`] — Phase 1 of the tool
/// economy pipeline. Delegates to
/// [`tools_helpers::reserve_tool_economy`](crate::context::tools_helpers::reserve_tool_economy)
/// on owned state under a 30s timeout. On success replies with the
/// `Send` reservation the supervisor carries across the executor.
#[allow(clippy::too_many_arguments)]
async fn handle_reserve_tool_economy(
    state: &mut PerContextState,
    deps: &ActorDeps,
    context_id: &str,
    invoker_did: &scp_identity::DID,
    spending_ucan: Option<&scp_protocol::crypto::ucan::UcanToken>,
    now_secs: u64,
    reply: oneshot::Sender<
        Result<Box<crate::context::tools_helpers::ToolEconomyReservation>, ContextError>,
    >,
) -> Outcome<()> {
    let reserve_fut = crate::context::tools_helpers::reserve_tool_economy(
        state,
        deps,
        context_id,
        invoker_did,
        spending_ucan,
        now_secs,
    );

    let (outcome, reply_result) = match tokio::time::timeout(HANDLER_TIMEOUT, reserve_fut).await {
        Ok(Ok(reservation)) => (Outcome::ok_mutated(()), Ok(Box::new(reservation))),
        Ok(Err(err)) => {
            // A rejected reservation refunds/rolls back inline, but the
            // observable state (rate-limit bucket touched then refunded)
            // is mutated during the attempt — flag mutated so the actor
            // persists if persistence is wired.
            let sketch = outcome_error_sketch(&err);
            (Outcome::err_mutated(sketch), Err(err))
        }
        Err(_elapsed) => {
            let err = ContextError::TransportTimeout(format!(
                "reserve_tool_economy exceeded {HANDLER_TIMEOUT:?} budget"
            ));
            let sketch = outcome_error_sketch(&err);
            (Outcome::err_mutated(sketch), Err(err))
        }
    };

    let _ = reply.send(reply_result);
    outcome
}

/// Handle [`ToolsCommand::SettleToolEconomy`] — Phase 3 of the tool
/// economy pipeline. Delegates to
/// [`tools_helpers::settle_tool_economy`](crate::context::tools_helpers::settle_tool_economy)
/// on owned state under a 30s timeout.
async fn handle_settle_tool_economy(
    state: &mut PerContextState,
    deps: &ActorDeps,
    context_id: &str,
    invoker_did: &scp_identity::DID,
    request: crate::context::tools_helpers::ToolSettleRequest,
    reply: oneshot::Sender<Result<crate::context::tools_helpers::ToolSettleOutcome, ContextError>>,
) -> Outcome<()> {
    let settle_fut = crate::context::tools_helpers::settle_tool_economy(
        state,
        deps,
        context_id,
        invoker_did,
        request,
    );

    let (outcome, reply_result) = match tokio::time::timeout(HANDLER_TIMEOUT, settle_fut).await {
        Ok(Ok(settle_outcome)) => (Outcome::ok_mutated(()), Ok(settle_outcome)),
        Ok(Err(err)) => {
            let sketch = outcome_error_sketch(&err);
            (Outcome::err_mutated(sketch), Err(err))
        }
        Err(_elapsed) => {
            let err = ContextError::TransportTimeout(format!(
                "settle_tool_economy exceeded {HANDLER_TIMEOUT:?} budget"
            ));
            let sketch = outcome_error_sketch(&err);
            (Outcome::err_mutated(sketch), Err(err))
        }
    };

    let _ = reply.send(reply_result);
    outcome
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
