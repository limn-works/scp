//! Off-mailbox streaming §5.4.5 economic-settlement sinks.
//!
//! The §5.4.5 streaming pump ([`crate::context::outlets::dispatch`]) runs
//! supervisor-side, OFF the per-context actor mailbox. Two of its economic
//! seams are `Sync` fire-and-forget callbacks the pump invokes without an
//! `.await`:
//!
//! - [`StreamEscrowRefundSink::refund`](crate::context::outlets::dispatch::StreamEscrowRefundSink::refund) — fired from the
//!   [`StreamEscrowTicket`](crate::context::outlets::dispatch::StreamEscrowTicket)
//!   Drop-guard when a debited-but-never-settled open-time escrow HOLD must be
//!   returned. A `Drop` cannot `.await`.
//! - [`StreamSettlementSink::settle`] — fired once at stream close (terminal
//!   chunk delivered) to release the unspent cumulative reserve, refund the
//!   unspent escrow, and capture the §19.15.5 `PaymentReceipt`. It runs ON the
//!   pump's tokio task, which MUST NOT block.
//!
//! The settlement and close-event sinks below hold a `Weak<Supervisor>` plus
//! a [`tokio::runtime::Handle`] captured at construction, and translate the
//! sync callback into a task on the Supervisor's task tracker that routes the
//! work back ONTO the actor mailbox via
//! [`Supervisor::settle_outlet_stream_via_actor`] (the analog of the
//! reference's `ContextManager` method calls). [`ActorEscrowRefundSink`] is
//! not a [`StreamEscrowRefundSink`](crate::context::outlets::dispatch::StreamEscrowRefundSink):
//! its `refund` is async and awaits
//! [`Supervisor::reverse_stream_escrow_via_actor`], and the Supervisor's
//! escrow-ticket sink runs it in a task on the open's spawner.
//!
//! # Tracked spawns
//!
//! Each callback spawns its work on the Supervisor's tracker,
//! so `shutdown_all_contexts` waits for an in-flight refund, settlement, or
//! close-event append before the owner closes storage. These callbacks are
//! fire-and-forget `()` seams with no caller to return an error to: when the
//! Supervisor has dropped or shutdown has refused the spawn, the work does not
//! run and the callback logs at error.

use std::future::Future;
use std::sync::{Arc, Weak};

use scp_did::DID;
use scp_protocol::economy::types::Amount;

use scp_protocol::context::outlets::lifecycle::OutletInvokedEvent;

use crate::context::outlets::invoke::{
    OutletInvokedEventSink, StreamSettlement, StreamSettlementSink,
};
use crate::context::supervisor::supervisor::{SinkHandoff, Supervisor};

/// Runs `op`, a hand-off of kind `kind`, against the Supervisor in a task on its tracker (ADR-049
/// Decision 16), on `runtime`.
///
/// The task holds only the `Weak` and upgrades it when it starts. When the Supervisor has dropped,
/// or shutdown refuses the spawn, `op` does not run and the failure logs at error naming `kind`.
pub fn spawn_supervisor_op<F, Fut>(
    supervisor: &Weak<Supervisor>,
    runtime: &tokio::runtime::Handle,
    kind: SinkHandoff,
    op: F,
) where
    F: FnOnce(Arc<Supervisor>) -> Fut + Send + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    let operation = kind.label();
    let Some(owner) = supervisor.upgrade() else {
        tracing::error!(
            operation,
            "streaming sink: supervisor dropped; operation not run"
        );
        return;
    };
    let weak = Weak::clone(supervisor);
    let task = async move {
        match weak.upgrade() {
            Some(sup) => op(sup).await,
            None => {
                tracing::error!(
                    operation,
                    "streaming sink: supervisor dropped; operation not run"
                );
            }
        }
    };
    if let Err(e) = owner.spawn_tracked_on(kind, task, runtime) {
        tracing::error!(operation, error = %e, "streaming sink: operation not run");
    }
}

/// Routes an open-time escrow reversal to the actor-owned budget tracker via the supervisor
/// mailbox.
///
/// It spawns nothing: the caller awaits [`Self::refund`] in a task it already holds, which for a
/// streaming open is a task on the open's spawner, so a refund fired after shutdown began still
/// runs (ADR-049 Decision 16, item 2, second exception).
pub struct ActorEscrowRefundSink {
    /// The supervisor whose mailbox owns the target context's budget tracker.
    supervisor: Weak<Supervisor>,
}

impl ActorEscrowRefundSink {
    /// Wrap a `Weak` supervisor reference as the streaming escrow-refund sink.
    #[must_use]
    pub const fn new(supervisor: Weak<Supervisor>) -> Self {
        Self { supervisor }
    }

    /// Reverses `amount` of `member_did`'s open-time hold in `context_id`.
    /// When the Supervisor has dropped, the refund does not run and logs at
    /// error; a reversal error logs at warn.
    pub async fn refund(&self, context_id: &str, member_did: &DID, amount: Amount) {
        let Some(supervisor) = self.supervisor.upgrade() else {
            tracing::error!(
                context_id,
                member_did = %member_did,
                amount = amount.value(),
                "stream escrow refund: supervisor dropped; refund not run"
            );
            return;
        };
        if let Err(e) = supervisor
            .reverse_stream_escrow_via_actor(context_id, member_did, amount)
            .await
        {
            // Best-effort: a missing actor (context torn down) or a persist
            // failure leaves the operator log the only record. The refund
            // itself saturates, so there is no correctness hazard on retry.
            tracing::warn!(
                context_id,
                member_did = %member_did,
                amount = amount.value(),
                "stream escrow reverse-spend failed: {e}"
            );
        }
    }
}

/// Concrete [`StreamSettlementSink`] routing a stream's close-time economic
/// settlement to the actor via the supervisor mailbox.
///
/// Held as `Arc<dyn StreamSettlementSink>` inside the streaming pump;
/// constructed by the streaming open orchestrator with a `Weak` to the
/// supervisor and the reservation's spawn-`generation` (captured in the
/// adapter, NOT in the settlement payload — the confused-deputy guard compares
/// it to the live actor's generation at settle time).
pub struct ActorStreamSettlementSink {
    /// The supervisor whose mailbox owns the target context's Class-S/economy
    /// state (and the payment adapter for the no-actor fallback capture).
    supervisor: Weak<Supervisor>,
    /// Spawn-generation the reservation was made against. Threaded into the
    /// [`SettleOutletStream`](crate::context::actor::commands::OutletsCommand::SettleOutletStream)
    /// command so the handler drops the settlement on a generation mismatch
    /// (despawn/respawn between reserve and settle).
    generation: u64,
    /// Runtime handle captured at construction (the pump fires `settle` on a
    /// runtime task, but capturing at construction keeps the two sinks uniform
    /// and robust to a future off-runtime caller).
    runtime: tokio::runtime::Handle,
}

impl ActorStreamSettlementSink {
    /// Wrap a `Weak` supervisor reference + the reservation's spawn-`generation` as the
    /// streaming settlement sink, capturing the current runtime handle.
    ///
    /// The non-test constructor is the streaming open orchestrator
    /// (`Supervisor::open_outlet_stream<E>`, chunk 3e).
    #[must_use]
    pub fn new(supervisor: Weak<Supervisor>, generation: u64) -> Self {
        Self {
            supervisor,
            generation,
            runtime: tokio::runtime::Handle::current(),
        }
    }
}

impl StreamSettlementSink for ActorStreamSettlementSink {
    fn settle(&self, settlement: StreamSettlement) {
        let generation = self.generation;
        spawn_supervisor_op(
            &self.supervisor,
            &self.runtime,
            SinkHandoff::StreamSettlement,
            move |supervisor| async move {
                // Same-context streaming pump: no cross-context witness (its double-
                // release guard is the `stream_reservations` record), so
                // `witness_saga_id: None`. The captured receipt is fire-and-forget.
                if let Err(e) = supervisor
                    .settle_outlet_stream_via_actor(settlement, generation, None)
                    .await
                {
                    // A dispatch failure (reply channel closed / residual not-
                    // registered TOCTOU) is surfaced to the operator log — the
                    // settlement is fire-and-forget from the pump's perspective.
                    tracing::warn!("outlet stream settlement dispatch failed: {e}");
                }
            },
        );
    }

    fn persist_reservation<'a>(
        &'a self,
        context_id: &str,
        request_id: scp_protocol::context::outlets::stream::RequestId,
        mut record: crate::context::outlets::invoke::StreamReservationRecord,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<Output = Result<(), scp_protocol::context::ContextError>>
                + Send
                + 'a,
        >,
    > {
        // Stamp the reservation's spawn-generation (this sink's captured
        // generation is exactly the generation the reserve was made against).
        record.generation = self.generation;
        let supervisor = Weak::clone(&self.supervisor);
        let context_id = context_id.to_owned();
        Box::pin(async move {
            let supervisor = supervisor.upgrade().ok_or_else(|| {
                scp_protocol::context::ContextError::SupervisorShutDown(
                    "ActorStreamSettlementSink::persist_reservation — supervisor dropped"
                        .to_owned(),
                )
            })?;
            let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
            let cmd = crate::context::actor::commands::OutletsCommand::PersistStreamReservation {
                context_id,
                request_id,
                record: Box::new(record),
                reply: reply_tx,
            };
            supervisor.dispatch_outlets_command(cmd).await?;
            reply_rx.await.map_err(|_| {
                scp_protocol::context::ContextError::TransportFailed(
                    "ActorStreamSettlementSink::persist_reservation — actor reply channel closed"
                        .to_owned(),
                )
            })?
        })
    }
}

/// Concrete [`OutletInvokedEventSink`] routing a stream's close-time §5.4.5
/// `OutletInvokedEvent` to the durable context event log via the supervisor's
/// append boundary
/// ([`Supervisor::append_streaming_outlet_invoked_event`]), which persists
/// through plain `append_event` and its durable event-local `<=` backstop
/// (same-context integrity is enforced inline in the pump before `record`).
///
/// Constructed INTERNALLY by the streaming open orchestrator
/// (`Supervisor::open_outlet_stream`) — the FFI bridges pass `None` for the
/// caller-facing `invoked_event_sink`, so wiring this sink supervisor-side is
/// what makes the §5.4.5 "ONE event per stream at close" record durable in
/// production (mirrors the internally-wired [`ActorStreamSettlementSink`]). The
/// `record` callback is `Sync` fire-and-forget: it spawns the async append onto
/// the captured runtime handle. A missing/torn-down event log or a persist
/// failure is surfaced to the operator log (the money-moving settlement is a
/// separate sink; this one carries the audit record).
pub(crate) struct ActorOutletInvokedEventSink {
    /// The supervisor whose shared event-log provider owns the target context's
    /// durable log.
    supervisor: Weak<Supervisor>,
    /// The canonical event-log key for the hosting context
    /// (`context_id_to_bytes`), pinned at open.
    context_id_bytes: [u8; 32],
    /// The §5.4.5 stream `invoker_did`, recorded as the event-log leaf's
    /// `actor_did`.
    actor_did: String,
    /// Runtime handle captured at construction (the pump fires `record` on a
    /// runtime task; capturing keeps this uniform with the sibling sinks).
    runtime: tokio::runtime::Handle,
}

impl ActorOutletInvokedEventSink {
    /// Wrap a `Weak` supervisor reference + the hosting context's event-log key + the
    /// stream `invoker_did` as the durable close-event sink, capturing the
    /// current runtime handle. Sole non-test constructor: the streaming open
    /// orchestrator (`Supervisor::open_outlet_stream`).
    pub(crate) fn new(
        supervisor: Weak<Supervisor>,
        context_id_bytes: [u8; 32],
        actor_did: String,
    ) -> Self {
        Self {
            supervisor,
            context_id_bytes,
            actor_did,
            runtime: tokio::runtime::Handle::current(),
        }
    }
}

impl OutletInvokedEventSink for ActorOutletInvokedEventSink {
    fn record(&self, event: OutletInvokedEvent) {
        let context_id_bytes = self.context_id_bytes;
        let actor_did = self.actor_did.clone();
        spawn_supervisor_op(
            &self.supervisor,
            &self.runtime,
            SinkHandoff::OutletInvokedEventAppend,
            move |supervisor| async move {
                if let Err(e) = supervisor
                    .append_streaming_outlet_invoked_event(context_id_bytes, event, actor_did)
                    .await
                {
                    // Best-effort: a torn-down context or persist failure leaves the
                    // operator log the only record of the durable-append failure.
                    tracing::warn!("streaming OutletInvokedEvent durable append failed: {e}");
                }
            },
        );
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {

    use scp_did::DID;

    use scp_protocol::economy::types::Amount;

    use super::ActorStreamSettlementSink;

    use crate::context::outlets::invoke::{StreamReservationRecord, StreamSettlementSink};

    const INVOKER: &str = "did:dht:z6MkStreamSettleInvoker";
    const CTX_BYTE: u8 = 0x5D;
    const UCAN_CID: &str = "cid-stream-settle";

    fn ctx_key() -> String {
        hex::encode([CTX_BYTE; 32])
    }
    fn invoker() -> DID {
        DID(INVOKER.to_owned())
    }

    /// A reservation persist against a dropped Supervisor returns the typed
    /// `SupervisorShutDown` error, not success.
    #[tokio::test]
    async fn persist_reservation_after_supervisor_drop_is_typed_error() {
        let sink = ActorStreamSettlementSink::new(std::sync::Weak::new(), 1);
        let result = sink
            .persist_reservation(
                &ctx_key(),
                [3u8; 16],
                StreamReservationRecord {
                    invoker_did: invoker(),
                    ucan_cid: UCAN_CID.to_owned(),
                    cost_per_chunk: Amount::new(10),
                    amount_cumulative_reserved: 50,
                    reserved_escrow: Amount::new(100),
                    generation: 0,
                },
            )
            .await;
        assert!(
            matches!(
                result,
                Err(scp_protocol::context::ContextError::SupervisorShutDown(_))
            ),
            "got {result:?}"
        );
    }
}
