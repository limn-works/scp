//! Off-mailbox streaming §5.4.5 economic-settlement sinks.
//!
//! The §5.4.5 streaming pump ([`crate::context::outlets::dispatch`]) runs
//! supervisor-side, OFF the per-context actor mailbox. Two of its economic
//! seams are `Sync` fire-and-forget callbacks the pump invokes without an
//! `.await`:
//!
//! - [`StreamEscrowRefundSink::refund`] — fired from the
//!   [`StreamEscrowTicket`](crate::context::outlets::dispatch::StreamEscrowTicket)
//!   Drop-guard when a debited-but-never-settled open-time escrow HOLD must be
//!   returned. A `Drop` cannot `.await`.
//! - [`StreamSettlementSink::settle`] — fired once at stream close (terminal
//!   chunk delivered) to release the unspent cumulative reserve, refund the
//!   unspent escrow, and capture the §19.15.5 `PaymentReceipt`. It runs ON the
//!   pump's tokio task, which MUST NOT block.
//!
//! Both concrete sinks below hold an `Arc<Supervisor>` plus a
//! [`tokio::runtime::Handle`] captured at construction, and translate the sync
//! callback into a `Handle::spawn`ed task that routes the work back ONTO the
//! actor mailbox via [`Supervisor::reverse_stream_escrow_via_actor`] /
//! [`Supervisor::settle_outlet_stream_via_actor`] (the analog of the
//! reference's `ContextManager` method calls). The captured handle is essential
//! for the escrow-refund sink: its `refund` may run from a `Drop` on a thread
//! with no ambient runtime (e.g. the open path's own thread), where
//! `Handle::current()` would panic.

use std::sync::Arc;

use scp_did::DID;
use scp_protocol::economy::types::Amount;

use crate::context::outlets::dispatch::StreamEscrowRefundSink;
use crate::context::outlets::invoke::{StreamSettlement, StreamSettlementSink};
use crate::context::supervisor::supervisor::Supervisor;

/// Concrete [`StreamEscrowRefundSink`] routing an open-time escrow reversal to
/// the actor-owned budget tracker via the supervisor mailbox.
///
/// Held as `Arc<dyn StreamEscrowRefundSink>` inside the streaming pump's
/// [`StreamEscrowTicket`](crate::context::outlets::dispatch::StreamEscrowTicket);
/// constructed by the streaming open orchestrator with a clone of the
/// supervisor `Arc`.
pub(crate) struct ActorEscrowRefundSink {
    /// The supervisor whose mailbox owns the target context's budget tracker.
    supervisor: Arc<Supervisor>,
    /// Runtime handle captured at construction, so the `Drop`-fired `refund`
    /// can spawn even when it runs off a runtime thread.
    runtime: tokio::runtime::Handle,
}

impl ActorEscrowRefundSink {
    /// Wrap a supervisor `Arc` as the streaming escrow-refund sink, capturing
    /// the CURRENT runtime handle (the sole construction site — the streaming
    /// open orchestrator — always runs on the runtime; the captured handle then
    /// outlives it into the `Drop` that may run off-runtime).
    ///
    /// `dead_code` allow: the sole non-test constructor is the streaming open
    /// orchestrator (`Supervisor::open_outlet_stream<E>`), landed in a later
    /// sub-chunk of the outlet-streaming runtime port. Exercised by this
    /// module's unit tests today.
    #[allow(
        dead_code,
        reason = "streaming escrow-refund seam (sub-chunk 3c): the sole non-test caller is the \
                  streaming open orchestrator, landed in a later sub-chunk. Exercised by unit \
                  tests now."
    )]
    pub(crate) fn new(supervisor: Arc<Supervisor>) -> Self {
        Self {
            supervisor,
            runtime: tokio::runtime::Handle::current(),
        }
    }
}

impl StreamEscrowRefundSink for ActorEscrowRefundSink {
    fn refund(&self, context_id: &str, member_did: &DID, amount: Amount) {
        let supervisor = Arc::clone(&self.supervisor);
        let context_id = context_id.to_owned();
        let member_did = member_did.clone();
        self.runtime.spawn(async move {
            if let Err(e) = supervisor
                .reverse_stream_escrow_via_actor(&context_id, &member_did, amount)
                .await
            {
                // Best-effort: a missing actor (context torn down) or a persist
                // failure leaves the operator log the only record. The refund
                // itself saturates, so there is no correctness hazard on retry.
                tracing::warn!(
                    context_id = %context_id,
                    member_did = %member_did,
                    amount = amount.value(),
                    "stream escrow reverse-spend failed: {e}"
                );
            }
        });
    }
}

/// Concrete [`StreamSettlementSink`] routing a stream's close-time economic
/// settlement to the actor via the supervisor mailbox.
///
/// Held as `Arc<dyn StreamSettlementSink>` inside the streaming pump;
/// constructed by the streaming open orchestrator with a clone of the
/// supervisor `Arc` and the reservation's spawn-`generation` (captured in the
/// adapter, NOT in the settlement payload — the confused-deputy guard compares
/// it to the live actor's generation at settle time).
pub(crate) struct ActorStreamSettlementSink {
    /// The supervisor whose mailbox owns the target context's Class-S/economy
    /// state (and the payment adapter for the no-actor fallback capture).
    supervisor: Arc<Supervisor>,
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
    /// Wrap a supervisor `Arc` + the reservation's spawn-`generation` as the
    /// streaming settlement sink, capturing the current runtime handle.
    ///
    /// `dead_code` allow: the sole non-test constructor is the streaming open
    /// orchestrator (`Supervisor::open_outlet_stream<E>`), landed in a later
    /// sub-chunk of the outlet-streaming runtime port. Exercised by this
    /// module's unit tests today.
    #[allow(
        dead_code,
        reason = "streaming settlement seam (sub-chunk 3c): the sole non-test caller is the \
                  streaming open orchestrator, landed in a later sub-chunk. Exercised by unit \
                  tests now."
    )]
    pub(crate) fn new(supervisor: Arc<Supervisor>, generation: u64) -> Self {
        Self {
            supervisor,
            generation,
            runtime: tokio::runtime::Handle::current(),
        }
    }
}

impl StreamSettlementSink for ActorStreamSettlementSink {
    fn settle(&self, settlement: StreamSettlement) {
        let supervisor = Arc::clone(&self.supervisor);
        let generation = self.generation;
        self.runtime.spawn(async move {
            if let Err(e) = supervisor
                .settle_outlet_stream_via_actor(settlement, generation)
                .await
            {
                // A dispatch failure (reply channel closed / residual not-
                // registered TOCTOU) is surfaced to the operator log — the
                // settlement is fire-and-forget from the pump's perspective.
                tracing::warn!("outlet stream settlement dispatch failed: {e}");
            }
        });
    }
}
