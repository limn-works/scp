//! Outlets handlers — see
//! [`OutletsCommand`](crate::context::actor::commands::OutletsCommand)
//! and spec §19 (economic governance) / §19.7 (anti-spam cost
//! escalation); hard rate limits §6.2.0.2.
//!
//! # Phase 2A.4 + Phase 2A finalization -- actor-shape dispatch
//!
//! The handler's primary entry point [`dispatch`] takes
//! `(&mut ClassSCell, &ActorDeps, OutletsCommand)` and routes the
//! actor-owned hard-rate-limit helpers plus the outlet-economy reserve /
//! settle phases through [`crate::context::outlets_helpers`] (the Class-C
//! mutations flow through the cell's non-persisting `class_c_view()`). The
//! economy
//! pipeline's non-`Send` executor runs supervisor-side between the
//! [`OutletsCommand::ReserveOutletEconomy`] and [`OutletsCommand::SettleOutletEconomy`]
//! mailbox round-trips (see
//! [`crate::context::outlets_helpers::invoke_outlet_with_economy`]).
//!
//! The cross-context outlet invocation saga (§6.2.4) is produced directly by
//! [`Supervisor::start_cross_context_outlet_invocation_saga`](crate::context::supervisor::Supervisor::start_cross_context_outlet_invocation_saga) — it does not
//! cross the actor mailbox because its
//! [`SagaSigningKeys`](crate::context::supervisor::SagaSigningKeys) are
//! borrowed (non-`'static`) `&ed25519_dalek::SigningKey` references that
//! cannot move into a `'static` mailbox message (its executor, by
//! contrast, is `Send + 'static`). A distinct constraint keeps the
//! outlet-economy executor off the mailbox:
//! [`Supervisor::invoke_outlet_with_economy`](crate::context::supervisor::Supervisor::invoke_outlet_with_economy)
//! takes a generic non-`Send` executor closure that cannot cross the
//! actor mailbox, so its economy bookkeeping is split into the
//! [`OutletsCommand::ReserveOutletEconomy`] / [`OutletsCommand::SettleOutletEconomy`]
//! mailbox commands (which run on owned state) while the executor itself
//! runs supervisor-side between the two round-trips.

use std::time::Duration;

use scp_protocol::context::ContextError;
use tokio::sync::oneshot;

use crate::context::actor::commands::OutletsCommand;
use crate::context::actor::deps::ActorDeps;
use crate::context::actor::outcome::{Outcome, outcome_error_sketch};

/// Per-call transport budget for outlets handlers. Plan §"Transport
/// timeouts inside actor handlers": 30 seconds.
pub const HANDLER_TIMEOUT: Duration = Duration::from_secs(30);

/// Dispatch a [`OutletsCommand`] against actor-owned state and
/// capability-reduced dependencies.
pub(crate) async fn dispatch(
    cell: &mut crate::context::actor::class_s::ClassSCell,
    deps: &ActorDeps,
    cmd: OutletsCommand,
) -> Outcome<()> {
    match cmd {
        OutletsCommand::TryConsumeHardRateLimit {
            did,
            now_secs,
            reply,
            ..
        } => handle_try_consume_hard_rate_limit(cell, &did, now_secs, reply).await,
        OutletsCommand::RefundHardRateLimit { did, reply, .. } => {
            handle_refund_hard_rate_limit(cell, &did, reply).await
        }
        OutletsCommand::ReserveOutletEconomy {
            context_id,
            invoker_did,
            spending_ucan,
            caveat_binding,
            input,
            now_secs,
            reply,
        } => {
            handle_reserve_outlet_economy(
                cell,
                deps,
                &context_id,
                &invoker_did,
                spending_ucan.as_deref(),
                caveat_binding.as_deref(),
                &input,
                now_secs,
                reply,
            )
            .await
        }
        OutletsCommand::SettleOutletEconomy {
            context_id,
            invoker_did,
            request,
            reply,
        } => {
            handle_settle_outlet_economy(cell, deps, &context_id, &invoker_did, *request, reply)
                .await
        }
        OutletsCommand::ReserveOutletStreamEconomy {
            context_id,
            invoker_did,
            cost_per_chunk,
            estimated_chunk_count,
            max_per_action,
            now_secs,
            reply,
        } => {
            handle_reserve_outlet_stream_economy(
                cell,
                deps,
                &context_id,
                &invoker_did,
                cost_per_chunk,
                estimated_chunk_count,
                max_per_action,
                now_secs,
                reply,
            )
            .await
        }
    }
}

/// Handle [`OutletsCommand::TryConsumeHardRateLimit`] — delegates to
/// [`outlets_helpers::try_consume_hard_rate_limit`](crate::context::outlets_helpers::try_consume_hard_rate_limit)
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
        crate::context::outlets_helpers::try_consume_hard_rate_limit(
            cell.class_c_view(),
            did,
            now_secs,
        )
    };

    let (outcome, reply_result) = match tokio::time::timeout(HANDLER_TIMEOUT, consume_fut).await {
        Ok(consumed) => {
            // `try_consume` writes Class-C on BOTH branches: a `true` consume
            // debits the bucket; a `false` DENY still lazily materializes the
            // limiter window and advances `last_refill` (a token refill). Both
            // writes are idempotently re-derivable from the persisted anchor + the
            // wall clock (never a loss, never fail-open), so the deny branch is
            // durability-SAFE regardless of the flag. We still report `ok_mutated`
            // UNCONDITIONALLY — mirroring `prepare_a`'s defensive reject posture —
            // so the coalesced flush captures the refill write and a future audit
            // does not re-flag the deny branch as a `mutated:false` Class-C site.
            (Outcome::ok_mutated(()), Ok(consumed))
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

/// Handle [`OutletsCommand::RefundHardRateLimit`] — delegates to
/// [`outlets_helpers::refund_hard_rate_limit`](crate::context::outlets_helpers::refund_hard_rate_limit)
/// under a 30s timeout.
async fn handle_refund_hard_rate_limit(
    cell: &mut crate::context::actor::class_s::ClassSCell,
    did: &scp_did::DID,
    reply: oneshot::Sender<Result<(), ContextError>>,
) -> Outcome<()> {
    // Class-C hard-rate refund through the non-persisting `class_c_view()` (run
    // loop coalesce-persists; no per-site persist injected).
    let refund_fut =
        async { crate::context::outlets_helpers::refund_hard_rate_limit(cell.class_c_view(), did) };

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

/// Handle [`OutletsCommand::ReserveOutletEconomy`] — Phase 1 of the outlet
/// economy pipeline. Delegates to
/// [`outlets_helpers::reserve_outlet_economy`](crate::context::outlets_helpers::reserve_outlet_economy)
/// on owned state under a 30s timeout. On success replies with the
/// `Send` reservation the supervisor carries across the executor.
#[allow(clippy::too_many_arguments)]
async fn handle_reserve_outlet_economy(
    cell: &mut crate::context::actor::class_s::ClassSCell,
    deps: &ActorDeps,
    context_id: &str,
    invoker_did: &scp_did::DID,
    spending_ucan: Option<&scp_protocol::crypto::ucan::UcanToken>,
    caveat_binding: Option<&crate::context::outlets_helpers::InvocationCaveatBinding>,
    input: &serde_json::Value,
    now_secs: u64,
    reply: oneshot::Sender<
        Result<Box<crate::context::outlets_helpers::OutletEconomyReservation>, ContextError>,
    >,
) -> Outcome<()> {
    let reserve_fut = crate::context::outlets_helpers::reserve_outlet_economy(
        cell,
        deps,
        context_id,
        invoker_did,
        spending_ucan,
        caveat_binding,
        input,
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
                "reserve_outlet_economy exceeded {HANDLER_TIMEOUT:?} budget"
            ));
            let sketch = outcome_error_sketch(&err);
            (Outcome::err_mutated(sketch), Err(err))
        }
    };

    let _ = reply.send(reply_result);
    outcome
}

/// Handle [`OutletsCommand::ReserveOutletStreamEconomy`] — the streaming
/// open-time economy reserve. Delegates to
/// [`outlets_helpers::reserve_outlet_stream_economy`](crate::context::outlets_helpers::reserve_outlet_stream_economy)
/// on owned state under a 30s timeout. On success replies with the `Send`
/// [`StreamEconomyReservation`](crate::context::outlets_helpers::StreamEconomyReservation)
/// the supervisor carries across the off-mailbox pump.
#[allow(clippy::too_many_arguments)]
async fn handle_reserve_outlet_stream_economy(
    cell: &mut crate::context::actor::class_s::ClassSCell,
    deps: &ActorDeps,
    context_id: &str,
    invoker_did: &scp_did::DID,
    cost_per_chunk: scp_protocol::economy::types::Amount,
    estimated_chunk_count: u32,
    max_per_action: Option<scp_protocol::economy::types::Amount>,
    now_secs: u64,
    reply: oneshot::Sender<
        Result<Box<crate::context::outlets_helpers::StreamEconomyReservation>, ContextError>,
    >,
) -> Outcome<()> {
    let reserve_fut = crate::context::outlets_helpers::reserve_outlet_stream_economy(
        cell,
        deps,
        context_id,
        invoker_did,
        cost_per_chunk,
        estimated_chunk_count,
        max_per_action,
        now_secs,
    );

    let (outcome, reply_result) = match tokio::time::timeout(HANDLER_TIMEOUT, reserve_fut).await {
        Ok(Ok(reservation)) => (Outcome::ok_mutated(()), Ok(Box::new(reservation))),
        Ok(Err(err)) => {
            // A rejected reservation refunds/rolls back inline, but the
            // observable state (rate-limit bucket touched then refunded,
            // sequence bumped then reversed) is mutated during the attempt —
            // flag mutated so the actor persists if persistence is wired.
            let sketch = outcome_error_sketch(&err);
            (Outcome::err_mutated(sketch), Err(err))
        }
        Err(_elapsed) => {
            let err = ContextError::TransportTimeout(format!(
                "reserve_outlet_stream_economy exceeded {HANDLER_TIMEOUT:?} budget"
            ));
            let sketch = outcome_error_sketch(&err);
            (Outcome::err_mutated(sketch), Err(err))
        }
    };

    let _ = reply.send(reply_result);
    outcome
}

/// Handle [`OutletsCommand::SettleOutletEconomy`] — Phase 3 of the outlet
/// economy pipeline. Delegates to
/// [`outlets_helpers::settle_outlet_economy`](crate::context::outlets_helpers::settle_outlet_economy)
/// on owned state under a 30s timeout.
async fn handle_settle_outlet_economy(
    cell: &mut crate::context::actor::class_s::ClassSCell,
    deps: &ActorDeps,
    context_id: &str,
    invoker_did: &scp_did::DID,
    request: crate::context::outlets_helpers::OutletSettleRequest,
    reply: oneshot::Sender<
        Result<crate::context::outlets_helpers::OutletSettleOutcome, ContextError>,
    >,
) -> Outcome<()> {
    let settle_fut = crate::context::outlets_helpers::settle_outlet_economy(
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
                "settle_outlet_economy exceeded {HANDLER_TIMEOUT:?} budget"
            ));
            let sketch = outcome_error_sketch(&err);
            (Outcome::err_mutated(sketch), Err(err))
        }
    };

    let _ = reply.send(reply_result);
    outcome
}
