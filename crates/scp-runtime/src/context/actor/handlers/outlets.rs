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
#[allow(
    clippy::too_many_lines,
    reason = "a flat command-dispatch match — one arm per OutletsCommand variant; \
              splitting it would obscure the 1:1 variant→handler routing"
)]
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
        OutletsCommand::ReserveStreamGrantEscrow {
            context_id,
            member_did,
            request_id,
            cost_per_chunk,
            grant,
            reply,
        } => {
            handle_reserve_stream_grant_escrow(
                cell,
                deps,
                &context_id,
                &member_did,
                request_id,
                cost_per_chunk,
                grant,
                reply,
            )
            .await
        }
        OutletsCommand::ReverseStreamGrantEscrow {
            context_id,
            member_did,
            request_id,
            amount,
            reply,
        } => {
            handle_reverse_stream_grant_escrow(
                cell,
                deps,
                &context_id,
                &member_did,
                request_id,
                amount,
                reply,
            )
            .await
        }
        OutletsCommand::ReserveStreamCaveatCounter {
            context_id,
            ucan_cid,
            kind,
            amount,
            cap,
            window_secs,
            now_secs,
            reply,
        } => {
            handle_reserve_stream_caveat_counter(
                cell,
                deps,
                &context_id,
                &ucan_cid,
                kind,
                amount,
                cap,
                window_secs,
                now_secs,
                reply,
            )
            .await
        }
        OutletsCommand::ReleaseStreamCaveatCounter {
            context_id,
            ucan_cid,
            kind,
            amount,
            reply,
        } => {
            handle_release_stream_caveat_counter(
                cell,
                deps,
                &context_id,
                &ucan_cid,
                kind,
                amount,
                reply,
            )
            .await
        }
        OutletsCommand::ReverseStreamEscrow {
            context_id,
            member_did,
            amount,
            reply,
        } => {
            handle_reverse_stream_escrow(cell, deps, &context_id, &member_did, amount, reply).await
        }
        OutletsCommand::SettleOutletStream {
            settlement,
            generation,
            witness_saga_id,
            reply,
        } => {
            handle_settle_outlet_stream(cell, deps, settlement, generation, witness_saga_id, reply)
                .await
        }
        OutletsCommand::PersistStreamReservation {
            context_id,
            request_id,
            record,
            reply,
        } => {
            handle_persist_stream_reservation(cell, deps, &context_id, request_id, record, reply)
                .await
        }
        OutletsCommand::ReconcileStreamReservations { context_id, reply } => {
            handle_reconcile_stream_reservations(cell, deps, &context_id, reply).await
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

/// Handle [`OutletsCommand::ReverseStreamEscrow`] — the off-mailbox streaming
/// §5.4.5 open-time escrow REVERSAL.
///
/// The actor-mailbox port of the reference
/// `ContextManager::outlet_stream_reverse_spend`: the
/// [`StreamEscrowTicket`](crate::context::outlets::dispatch::StreamEscrowTicket)
/// Drop-guard runs supervisor-side (it cannot take `&mut` to actor-owned
/// state), so its refund of a debited-but-never-settled hold routes here.
/// Runs
/// [`MemberBudgetTracker::reverse_spend`](scp_protocol::economy::budget::MemberBudgetTracker::reverse_spend)
/// — infallible / SATURATING at `0`, so a double-refund (a Drop after an
/// explicit settlement already returned the hold) is a safe no-op — against the
/// owned budget tracker under a fail-closed
/// [`commit_class_s_keep`](crate::context::actor::class_s::ClassSCell::commit_class_s_keep),
/// so the returned budget survives a coalesce-window crash the same way the
/// original debit does. Reverse never rejects; the reply carries only the
/// persist / transport infrastructure outcome.
async fn handle_reverse_stream_escrow(
    cell: &mut crate::context::actor::class_s::ClassSCell,
    deps: &ActorDeps,
    context_id: &str,
    member_did: &scp_did::DID,
    amount: scp_protocol::economy::types::Amount,
    reply: oneshot::Sender<Result<(), ContextError>>,
) -> Outcome<()> {
    // A zero-amount refund (Query / zero-cost stream) touches nothing and
    // needs no persist — reply success without a spurious durable write.
    if amount.value() == 0 {
        let _ = reply.send(Ok(()));
        return Outcome::ok(());
    }

    let commit_fut = crate::context::outlets_helpers::reverse_stream_escrow(
        cell, deps, context_id, member_did, amount,
    );

    let (outcome, reply_result) = match tokio::time::timeout(HANDLER_TIMEOUT, commit_fut).await {
        Ok(Ok(())) => (Outcome::ok_mutated(()), Ok(())),
        Ok(Err(err)) => {
            // KEEP semantics: the in-memory budget IS credited even though the
            // persist failed — flag mutated so the actor's coalesced persist
            // retries the durable write.
            let sketch = outcome_error_sketch(&err);
            (Outcome::err_mutated(sketch), Err(err))
        }
        Err(_elapsed) => {
            let err = ContextError::TransportTimeout(format!(
                "reverse_stream_escrow exceeded {HANDLER_TIMEOUT:?} budget"
            ));
            let sketch = outcome_error_sketch(&err);
            (Outcome::err_mutated(sketch), Err(err))
        }
    };

    let _ = reply.send(reply_result);
    outcome
}

/// Handle [`OutletsCommand::SettleOutletStream`] — the off-mailbox streaming
/// §5.4.5 close-time economic settlement.
///
/// The actor-mailbox port of the reference `ContextManager::outlet_stream_settle`.
/// The confused-deputy generation guard (drop-on-mismatch), the
/// release→refund→capture ordering, and the service-rendered capture-failure
/// handling all live in
/// [`outlets_helpers::settle_outlet_stream`](crate::context::outlets_helpers::settle_outlet_stream);
/// this handler maps its
/// [`StreamSettleOutcome`](crate::context::outlets_helpers::StreamSettleOutcome)
/// onto the reply + the actor
/// [`Outcome`]. Fix-D: a generation-mismatch settle CAPTURES the receipt for
/// rendered service but touches no owned state (`Outcome::ok` — no coalesced
/// persist; the durable reserves are left for the restore-time reconcile
/// sweep); a matching-instance settlement mutated owned state
/// (`Outcome::ok_mutated`). Either way the reply carries the (possibly `None`)
/// receipt. The helper never returns `Err` (a persist failure is KEEP'd +
/// logged, service-rendered capture runs regardless).
async fn handle_settle_outlet_stream(
    cell: &mut crate::context::actor::class_s::ClassSCell,
    deps: &ActorDeps,
    settlement: Box<crate::context::outlets::invoke::StreamSettlement>,
    generation: u64,
    witness_saga_id: Option<crate::context::supervisor::saga_journal::SagaId>,
    reply: oneshot::Sender<
        Result<crate::context::actor::commands::StreamSettleApplication, ContextError>,
    >,
) -> Outcome<()> {
    use crate::context::actor::commands::StreamSettleApplication;
    use crate::context::outlets_helpers::StreamSettleOutcome;
    match crate::context::outlets_helpers::settle_outlet_stream(
        cell,
        deps,
        *settlement,
        generation,
        witness_saga_id.as_ref(),
    )
    .await
    {
        StreamSettleOutcome::CapturedWithoutMutation(receipt) => {
            // Fix-D / SCP-OUT-046: generation mismatch — DEFERRED. No owned state
            // was touched (durable reserves left for the restore-time reconcile
            // sweep / crash recovery), and for a witness-bearing xctx settle no
            // capture ran either. Reply `applied: false` so the caller leaves the
            // journal `Committing` for recovery to complete exactly once.
            let _ = reply.send(Ok(StreamSettleApplication {
                receipt,
                applied: false,
            }));
            Outcome::ok(())
        }
        StreamSettleOutcome::Settled(receipt) => {
            let _ = reply.send(Ok(StreamSettleApplication {
                receipt,
                applied: true,
            }));
            Outcome::ok_mutated(())
        }
    }
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

/// Handle [`OutletsCommand::ReserveStreamGrantEscrow`] — the mid-stream
/// §5.4.5 GRANT-time escrow top-up. Delegates to
/// [`outlets_helpers::reserve_stream_grant_escrow`](crate::context::outlets_helpers::reserve_stream_grant_escrow)
/// on owned state under a 30s timeout, replying with the reserved (DEBITED)
/// hold `Amount` the FFI bridge threads into `apply_credit_grant`.
#[allow(clippy::too_many_arguments)]
async fn handle_reserve_stream_grant_escrow(
    cell: &mut crate::context::actor::class_s::ClassSCell,
    deps: &ActorDeps,
    context_id: &str,
    member_did: &scp_did::DID,
    request_id: scp_protocol::context::outlets::stream::RequestId,
    cost_per_chunk: scp_protocol::economy::types::Amount,
    grant: u32,
    reply: oneshot::Sender<Result<scp_protocol::economy::types::Amount, ContextError>>,
) -> Outcome<()> {
    let reserve_fut = crate::context::outlets_helpers::reserve_stream_grant_escrow(
        cell,
        deps,
        context_id,
        member_did,
        request_id,
        cost_per_chunk,
        grant,
    );

    let (outcome, reply_result) = match tokio::time::timeout(HANDLER_TIMEOUT, reserve_fut).await {
        Ok(Ok(reserved)) => (Outcome::ok_mutated(()), Ok(reserved)),
        Ok(Err(err)) => {
            // A rejected reserve rolls back its own debit + record bump inline
            // (the `commit_class_s_compensating` snapshot-restore + Class-C
            // compensation on persist-failure; a pure balance/overflow reject
            // never debited), but the attempt may have touched owned state —
            // flag mutated so the actor persists if persistence is wired.
            let sketch = outcome_error_sketch(&err);
            (Outcome::err_mutated(sketch), Err(err))
        }
        Err(_elapsed) => {
            let err = ContextError::TransportTimeout(format!(
                "reserve_stream_grant_escrow exceeded {HANDLER_TIMEOUT:?} budget"
            ));
            let sketch = outcome_error_sketch(&err);
            (Outcome::err_mutated(sketch), Err(err))
        }
    };

    let _ = reply.send(reply_result);
    outcome
}

/// Handle [`OutletsCommand::ReverseStreamGrantEscrow`] — the grant reverse-on-
/// reject. Delegates to
/// [`outlets_helpers::reverse_stream_grant_escrow`](crate::context::outlets_helpers::reverse_stream_grant_escrow)
/// (CREDIT budget + un-bump the durable record atomically) under a 30s timeout.
async fn handle_reverse_stream_grant_escrow(
    cell: &mut crate::context::actor::class_s::ClassSCell,
    deps: &ActorDeps,
    context_id: &str,
    member_did: &scp_did::DID,
    request_id: scp_protocol::context::outlets::stream::RequestId,
    amount: scp_protocol::economy::types::Amount,
    reply: oneshot::Sender<Result<(), ContextError>>,
) -> Outcome<()> {
    let reverse_fut = crate::context::outlets_helpers::reverse_stream_grant_escrow(
        cell, deps, context_id, member_did, request_id, amount,
    );

    let (outcome, reply_result) = match tokio::time::timeout(HANDLER_TIMEOUT, reverse_fut).await {
        Ok(Ok(())) => (Outcome::ok_mutated(()), Ok(())),
        Ok(Err(err)) => {
            // KEEP semantics: the in-memory credit + un-bump ARE applied even on
            // persist failure — flag mutated so the run loop retries the write.
            let sketch = outcome_error_sketch(&err);
            (Outcome::err_mutated(sketch), Err(err))
        }
        Err(_elapsed) => {
            let err = ContextError::TransportTimeout(format!(
                "reverse_stream_grant_escrow exceeded {HANDLER_TIMEOUT:?} budget"
            ));
            let sketch = outcome_error_sketch(&err);
            (Outcome::err_mutated(sketch), Err(err))
        }
    };

    let _ = reply.send(reply_result);
    outcome
}

/// Handle [`OutletsCommand::ReserveStreamCaveatCounter`] — the off-mailbox
/// streaming §7.3.8 value-caveat counter reservation.
///
/// Mirrors the unary `consume_caveat_counters` gate for ONE counter kind, but
/// split across the mailbox: the supervisor-side stream pump cannot take `&mut`
/// to actor-owned Class-S state, so its per-kind
/// [`CaveatCounters::try_consume`](crate::trust::CaveatCounters::try_consume)
/// runs here on the owned record keyed by `ucan_cid`.
///
/// The admission check runs on a CLONE first, so a rejection mutates nothing
/// and performs NO persist (mirroring the unary "reject before persist"
/// semantics — and avoiding a spurious durable write on a rate-limited open).
/// Only an ADMITTED consume writes the mutated record back under a fail-closed
/// [`commit_class_s_keep`](crate::context::actor::class_s::ClassSCell::commit_class_s_keep)
/// (durable via the ADR-049 §9 snapshot). The structured
/// [`CounterExhausted`](crate::trust::CounterExhausted) is threaded through the
/// reply's inner `Result` so the pump can map the precise §7.3.8 slug; the
/// outer `Result` carries only persist / transport infrastructure failures.
#[allow(clippy::too_many_arguments)]
async fn handle_reserve_stream_caveat_counter(
    cell: &mut crate::context::actor::class_s::ClassSCell,
    deps: &ActorDeps,
    context_id: &str,
    ucan_cid: &str,
    kind: scp_protocol::trust::CaveatKind,
    amount: u64,
    cap: u64,
    window_secs: u32,
    now_secs: u64,
    reply: oneshot::Sender<Result<Result<(), crate::trust::CounterExhausted>, ContextError>>,
) -> Outcome<()> {
    // Phase 1 — pure admission on a clone. `try_consume` leaves the record
    // unchanged on exhaustion; consuming a clone means a rejection touches no
    // owned state and triggers no persist.
    let mut record = cell
        .class_s
        .caveat_counters
        .get(ucan_cid)
        .cloned()
        .unwrap_or_default();

    if let Err(exhausted) = record.try_consume(kind, amount, cap, window_secs, now_secs) {
        // Rejected: owned state untouched, nothing to persist.
        let _ = reply.send(Ok(Err(exhausted)));
        return Outcome::ok(());
    }

    // Phase 2 — ADMITTED: write the mutated record back under a fail-closed
    // persist. A consumed cap must never un-consume, so `commit_class_s_keep`
    // (KEEP-on-persist-failure) is the correct combinator: the reservation is
    // kept in memory even if the durable write fails, and the persist error is
    // surfaced to the caller.
    let ucan_cid_owned = ucan_cid.to_owned();
    let commit_fut = cell.commit_class_s_keep(deps, context_id, move |mut view| {
        view.rest_mut()
            .class_s
            .caveat_counters
            .insert(ucan_cid_owned, record);
        Ok(())
    });

    let (outcome, reply_result) = match tokio::time::timeout(HANDLER_TIMEOUT, commit_fut).await {
        Ok(Ok(())) => (Outcome::ok_mutated(()), Ok(Ok(()))),
        Ok(Err(err)) => {
            // The in-memory record IS mutated (KEEP semantics) even though the
            // persist failed — flag mutated so the actor's coalesced persist
            // retries the write.
            let sketch = outcome_error_sketch(&err);
            (Outcome::err_mutated(sketch), Err(err))
        }
        Err(_elapsed) => {
            let err = ContextError::TransportTimeout(format!(
                "reserve_stream_caveat_counter exceeded {HANDLER_TIMEOUT:?} budget"
            ));
            let sketch = outcome_error_sketch(&err);
            (Outcome::err_mutated(sketch), Err(err))
        }
    };

    let _ = reply.send(reply_result);
    outcome
}

/// Handle [`OutletsCommand::ReleaseStreamCaveatCounter`] — the off-mailbox
/// streaming §7.3.8 counter RELEASE.
///
/// Returns the unspent portion of a stream's open-time reservation (SCP R4
/// HIGH-1), or rolls back an earlier-kind increment when a later kind rejects
/// the open. Runs [`CaveatCounters::release`](crate::trust::CaveatCounters::release)
/// — infallible / saturating at `0` — on the owned record keyed by `ucan_cid`
/// under a fail-closed
/// [`commit_class_s_keep`](crate::context::actor::class_s::ClassSCell::commit_class_s_keep),
/// so the returned capacity survives a coalesce-window crash the same way the
/// original consume does. Release itself never rejects; the reply carries only
/// the persist / transport infrastructure outcome.
async fn handle_release_stream_caveat_counter(
    cell: &mut crate::context::actor::class_s::ClassSCell,
    deps: &ActorDeps,
    context_id: &str,
    ucan_cid: &str,
    kind: scp_protocol::trust::CaveatKind,
    amount: u64,
    reply: oneshot::Sender<Result<(), ContextError>>,
) -> Outcome<()> {
    let ucan_cid_owned = ucan_cid.to_owned();
    let commit_fut = cell.commit_class_s_keep(deps, context_id, move |mut view| {
        view.rest_mut()
            .class_s
            .caveat_counters
            .entry(ucan_cid_owned)
            .or_default()
            .release(kind, amount);
        Ok(())
    });

    let (outcome, reply_result) = match tokio::time::timeout(HANDLER_TIMEOUT, commit_fut).await {
        Ok(Ok(())) => (Outcome::ok_mutated(()), Ok(())),
        Ok(Err(err)) => {
            let sketch = outcome_error_sketch(&err);
            (Outcome::err_mutated(sketch), Err(err))
        }
        Err(_elapsed) => {
            let err = ContextError::TransportTimeout(format!(
                "release_stream_caveat_counter exceeded {HANDLER_TIMEOUT:?} budget"
            ));
            let sketch = outcome_error_sketch(&err);
            (Outcome::err_mutated(sketch), Err(err))
        }
    };

    let _ = reply.send(reply_result);
    outcome
}

/// Handle [`OutletsCommand::PersistStreamReservation`] — Fix-D durable
/// crash-recovery record insert at pump open.
///
/// Inserts the
/// [`StreamReservationRecord`](crate::context::outlets::invoke::StreamReservationRecord)
/// (keyed by the hex `request_id`) into the owned `ClassSState.stream_reservations`
/// under a fail-closed
/// [`commit_class_s_keep`](crate::context::actor::class_s::ClassSCell::commit_class_s_keep)
/// (durable via the ADR-049 §9 snapshot), stamping the record's `generation`
/// with the live cell generation — the authoritative reservation generation,
/// since this persist runs on the same instance the reserve did (absent a crash
/// in between). The reply carries only the persist / transport infra outcome.
async fn handle_persist_stream_reservation(
    cell: &mut crate::context::actor::class_s::ClassSCell,
    deps: &ActorDeps,
    context_id: &str,
    request_id: scp_protocol::context::outlets::stream::RequestId,
    record: Box<crate::context::outlets::invoke::StreamReservationRecord>,
    reply: oneshot::Sender<Result<(), ContextError>>,
) -> Outcome<()> {
    let key = hex::encode(request_id);
    let mut record = *record;
    // Stamp the authoritative live generation (diagnostic only — the reconcile
    // sweep ignores generation).
    record.generation = cell.generation;
    let commit_fut = cell.commit_class_s_keep(deps, context_id, move |mut view| {
        view.rest_mut()
            .class_s
            .stream_reservations
            .insert(key, record);
        Ok(())
    });

    let (outcome, reply_result) = match tokio::time::timeout(HANDLER_TIMEOUT, commit_fut).await {
        Ok(Ok(())) => (Outcome::ok_mutated(()), Ok(())),
        Ok(Err(err)) => {
            // KEEP semantics: the in-memory insert IS applied even though the
            // persist failed — flag mutated so the run loop retries the write.
            let sketch = outcome_error_sketch(&err);
            (Outcome::err_mutated(sketch), Err(err))
        }
        Err(_elapsed) => {
            let err = ContextError::TransportTimeout(format!(
                "persist_stream_reservation exceeded {HANDLER_TIMEOUT:?} budget"
            ));
            let sketch = outcome_error_sketch(&err);
            (Outcome::err_mutated(sketch), Err(err))
        }
    };

    let _ = reply.send(reply_result);
    outcome
}

/// Handle [`OutletsCommand::ReconcileStreamReservations`] — Fix-D restore-time
/// crash-recovery sweep.
///
/// Drains `ClassSState.stream_reservations` under ONE fail-closed
/// [`commit_class_s_keep`](crate::context::actor::class_s::ClassSCell::commit_class_s_keep).
/// For each unresolved record it REFUNDS the full `reserved_escrow` to the
/// invoker's `MemberBudgetTracker` (`reverse_spend`, saturating) and RELEASES the
/// full `amount_cumulative_reserved` back to the §7.3.8 `AmountCumulative` counter
/// keyed by `ucan_cid` (`release`, saturating). The billed count is unknown once
/// the pump is gone, so the FULL reserved amounts are returned — conservative:
/// the invoker is never over-charged and the cumulative cap is never
/// over-consumed (any bill for actually-rendered service was already captured by
/// the generation-mismatch settle's `CapturedWithoutMutation` path). Runs
/// REGARDLESS of generation (a restore overwrites `PerContextState::generation`
/// with a fresh spawn generation; the reserves are this restored context's OWN
/// state). The releases + the clear land in the SAME persist, so the sweep is
/// idempotent across restarts: a persist failure re-runs from the restored
/// record; a success removes it.
async fn handle_reconcile_stream_reservations(
    cell: &mut crate::context::actor::class_s::ClassSCell,
    deps: &ActorDeps,
    context_id: &str,
    reply: oneshot::Sender<Result<usize, ContextError>>,
) -> Outcome<()> {
    // Nothing to reconcile — reply without a spurious durable write. The common
    // case: a clean restart where every stream settled cleanly (its record was
    // cleared at close).
    if cell.class_s.stream_reservations.is_empty() {
        let _ = reply.send(Ok(0));
        return Outcome::ok(());
    }

    // The refund/release/clear core lives in `outlets_helpers` (mirroring
    // `settle_outlet_stream`), so it is unit-testable against a bare
    // `ClassSCell` harness without standing up the full mailbox.
    let commit_fut =
        crate::context::outlets_helpers::reconcile_stream_reservations(cell, deps, context_id);

    let (outcome, reply_result) = match tokio::time::timeout(HANDLER_TIMEOUT, commit_fut).await {
        Ok(Ok(count)) => (Outcome::ok_mutated(()), Ok(count)),
        Ok(Err(err)) => {
            // KEEP semantics: the in-memory releases + clear ARE applied even
            // though the persist failed — the run loop retries the durable write,
            // and a restart before it lands re-runs the sweep from the restored
            // record (idempotent).
            let sketch = outcome_error_sketch(&err);
            (Outcome::err_mutated(sketch), Err(err))
        }
        Err(_elapsed) => {
            let err = ContextError::TransportTimeout(format!(
                "reconcile_stream_reservations exceeded {HANDLER_TIMEOUT:?} budget"
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
