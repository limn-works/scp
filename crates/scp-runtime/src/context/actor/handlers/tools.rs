//! Tools handlers — see
//! [`ToolsCommand`](crate::context::actor::commands::ToolsCommand)
//! and spec §19 (economic governance) / §19.7 (anti-spam cost
//! escalation); hard rate limits §6.2.0.2.
//!
//! # Phase 2A.4 + Phase 2A finalization -- actor-shape dispatch
//!
//! The handler's primary entry point [`dispatch`] takes
//! `(&mut ClassSCell, &ActorDeps, ToolsCommand)` and routes the
//! actor-owned hard-rate-limit helpers plus the tool-economy reserve /
//! settle phases through [`crate::context::tools_helpers`] (the Class-C
//! mutations flow through the cell's non-persisting `class_c_view()`). The
//! economy
//! pipeline's non-`Send` executor runs supervisor-side between the
//! [`ToolsCommand::ReserveToolEconomy`] and [`ToolsCommand::SettleToolEconomy`]
//! mailbox round-trips (see
//! [`crate::context::tools_helpers::invoke_tool_with_economy`]).
//!
//! The cross-context tool invocation saga (§6.2.4) is produced directly by
//! [`Supervisor::start_cross_context_tool_invocation_saga`](crate::context::supervisor::Supervisor::start_cross_context_tool_invocation_saga) — it does not
//! cross the actor mailbox because its
//! [`SagaSigningKeys`](crate::context::supervisor::SagaSigningKeys) are
//! borrowed (non-`'static`) `&ed25519_dalek::SigningKey` references that
//! cannot move into a `'static` mailbox message (its executor, by
//! contrast, is `Send + 'static`). A distinct constraint keeps the
//! tool-economy executor off the mailbox:
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

/// Per-call transport budget for tools handlers. Plan §"Transport
/// timeouts inside actor handlers": 30 seconds.
pub const HANDLER_TIMEOUT: Duration = Duration::from_secs(30);

/// Dispatch a [`ToolsCommand`] against actor-owned state and
/// capability-reduced dependencies.
pub(crate) async fn dispatch(
    cell: &mut crate::context::actor::class_s::ClassSCell,
    deps: &ActorDeps,
    cmd: ToolsCommand,
) -> Outcome<()> {
    match cmd {
        ToolsCommand::TryConsumeHardRateLimit {
            did,
            now_secs,
            reply,
            ..
        } => handle_try_consume_hard_rate_limit(cell, &did, now_secs, reply).await,
        ToolsCommand::RefundHardRateLimit { did, reply, .. } => {
            handle_refund_hard_rate_limit(cell, &did, reply).await
        }
        ToolsCommand::ReserveToolEconomy {
            context_id,
            invoker_did,
            spending_ucan,
            now_secs,
            reply,
        } => {
            handle_reserve_tool_economy(
                cell,
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
            handle_settle_tool_economy(cell, deps, &context_id, &invoker_did, *request, reply).await
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
    cell: &mut crate::context::actor::class_s::ClassSCell,
    did: &scp_did::DID,
    now_secs: u64,
    reply: oneshot::Sender<Result<bool, ContextError>>,
) -> Outcome<()> {
    // Class-C hard-rate consume through the non-persisting `class_c_view()` —
    // this dispatch arm reports `ok_mutated`/`err_mutated` and the run loop
    // coalesce-persists; no per-site persist is injected.
    let consume_fut = async {
        crate::context::tools_helpers::try_consume_hard_rate_limit(
            cell.class_c_view(),
            did,
            now_secs,
        )
    };

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
    cell: &mut crate::context::actor::class_s::ClassSCell,
    did: &scp_did::DID,
    reply: oneshot::Sender<Result<(), ContextError>>,
) -> Outcome<()> {
    // Class-C hard-rate refund through the non-persisting `class_c_view()` (run
    // loop coalesce-persists; no per-site persist injected).
    let refund_fut =
        async { crate::context::tools_helpers::refund_hard_rate_limit(cell.class_c_view(), did) };

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
    cell: &mut crate::context::actor::class_s::ClassSCell,
    deps: &ActorDeps,
    context_id: &str,
    invoker_did: &scp_did::DID,
    spending_ucan: Option<&scp_protocol::crypto::ucan::UcanToken>,
    now_secs: u64,
    reply: oneshot::Sender<
        Result<Box<crate::context::tools_helpers::ToolEconomyReservation>, ContextError>,
    >,
) -> Outcome<()> {
    let reserve_fut = crate::context::tools_helpers::reserve_tool_economy(
        cell,
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
    cell: &mut crate::context::actor::class_s::ClassSCell,
    deps: &ActorDeps,
    context_id: &str,
    invoker_did: &scp_did::DID,
    request: crate::context::tools_helpers::ToolSettleRequest,
    reply: oneshot::Sender<Result<crate::context::tools_helpers::ToolSettleOutcome, ContextError>>,
) -> Outcome<()> {
    let settle_fut = crate::context::tools_helpers::settle_tool_economy(
        cell,
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
