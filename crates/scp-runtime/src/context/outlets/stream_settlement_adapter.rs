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
    /// The non-test constructor is the streaming open orchestrator
    /// (`Supervisor::open_outlet_stream<E>`, chunk 3e).
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
    /// The non-test constructor is the streaming open orchestrator
    /// (`Supervisor::open_outlet_stream<E>`, chunk 3e).
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
        let supervisor = Arc::clone(&self.supervisor);
        let context_id = context_id.to_owned();
        Box::pin(async move {
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

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use scp_did::DID;
    use scp_platform::testing::InMemoryStorage;
    use scp_protocol::economy::types::{
        Amount, CostSchedule, CurrencyCode, EconomicPolicy, PaidActionType,
    };

    use super::{ActorEscrowRefundSink, ActorStreamSettlementSink};
    use crate::context::ContextState;
    use crate::context::actor::class_s::ClassSCell;
    use crate::context::actor::deps::ActorDeps;
    use crate::context::actor::state::PerContextState;
    use crate::context::outlets::dispatch::StreamEscrowRefundSink;
    use crate::context::outlets::invoke::{
        EconomicPolicySnapshot, StreamSettlement, StreamSettlementSink,
    };
    use crate::context::outlets_helpers::{
        StreamSettleOutcome, reverse_stream_escrow, settle_outlet_stream,
    };
    use crate::context::supervisor::supervisor::Supervisor;
    use crate::economy::adapter::{
        AdapterCapabilities, CountingPaymentAdapter, PaymentAdapter, PaymentAdapterDyn,
        PaymentAuthorization, PaymentError, PaymentMetadata, PaymentReceipt, RefundConfirmation,
        VerificationResult,
    };
    use crate::trust::caveat_counters::CaveatCounters;

    const INVOKER: &str = "did:dht:z6MkStreamSettleInvoker";
    const CTX_BYTE: u8 = 0x5D;
    const NOW: u64 = 1_700_000_000;
    const UCAN_CID: &str = "cid-stream-settle";

    fn ctx_key() -> String {
        hex::encode([CTX_BYTE; 32])
    }
    fn invoker() -> DID {
        DID(INVOKER.to_owned())
    }

    /// A payment adapter whose `capture` ALWAYS fails (authorize succeeds first),
    /// driving the settlement's service-rendered capture-failure arm.
    struct FailCaptureAdapter;
    #[allow(clippy::similar_names)] // payer/payee is the domain language
    impl PaymentAdapter for FailCaptureAdapter {
        fn adapter_id(&self) -> &'static str {
            "fail-capture"
        }
        fn capabilities(&self) -> AdapterCapabilities {
            AdapterCapabilities {
                supported_currencies: vec![CurrencyCode::from("USD")],
                supports_streaming: false,
                supports_batch_auth: false,
                supports_single_step: false,
                min_amount: None,
                max_amount: None,
                typical_settlement_ms: 0,
                requires_facilitator: false,
            }
        }
        async fn authorize(
            &self,
            payer: &DID,
            payee: &DID,
            amount: Amount,
            currency: CurrencyCode,
            _metadata: PaymentMetadata,
        ) -> Result<PaymentAuthorization, PaymentError> {
            Ok(PaymentAuthorization {
                auth_id: [4u8; 32],
                payer: payer.clone(),
                payee: payee.clone(),
                amount,
                currency,
                adapter_id: "fail-capture".to_owned(),
                created_at: 1_000_000,
                expires_at: 2_000_000,
                adapter_state: Vec::new(),
            })
        }
        async fn verify_authorization(
            &self,
            _auth: &PaymentAuthorization,
        ) -> Result<(), PaymentError> {
            Ok(())
        }
        async fn capture(
            &self,
            _auth: &PaymentAuthorization,
        ) -> Result<PaymentReceipt, PaymentError> {
            Err(PaymentError::AdapterError("induced capture failure".into()))
        }
        async fn void(&self, _auth: &PaymentAuthorization) -> Result<(), PaymentError> {
            Ok(())
        }
        async fn verify(&self, _r: &PaymentReceipt) -> Result<VerificationResult, PaymentError> {
            Ok(VerificationResult {
                valid: true,
                adapter_id: "fail-capture".to_owned(),
                verified_amount: Amount(0),
                verified_currency: CurrencyCode::from("USD"),
                verification_timestamp: 0,
            })
        }
        async fn refund(
            &self,
            _r: &PaymentReceipt,
            _amount: Option<Amount>,
        ) -> Result<RefundConfirmation, PaymentError> {
            Ok(RefundConfirmation {
                refund_id: [0u8; 32],
                original_receipt_id: [0u8; 32],
                refunded_amount: Amount(0),
                currency: CurrencyCode::from("USD"),
                adapter_proof: Vec::new(),
            })
        }
    }

    fn build_supervisor(adapter: Option<Arc<dyn PaymentAdapterDyn>>) -> Arc<Supervisor> {
        let crypto = Arc::new(crate::crypto::mls::provider::MlsCryptoProvider::new(
            INVOKER.to_owned(),
            Arc::new(scp_clock::SystemClock),
        ));
        let transport: Box<dyn crate::context::builder::ContextTransportProvider> =
            Box::new(crate::context::builder::NotConfiguredTransportProvider);
        let event_log: Box<dyn crate::context::builder::ContextEventLogProvider> =
            Box::new(crate::context::providers::MerkleEventLogProvider::new());
        let key_resolver: scp_protocol::context::governance::KeyResolver = Arc::new(|_, _| None);
        let mls_storage: Arc<dyn crate::crypto::mls::storage_adapter::OpenMlsStorageAdapter> =
            Arc::new(
                crate::crypto::mls::storage_adapter::SpawnBlockingStorageAdapter::new(Arc::new(
                    InMemoryStorage::new(),
                )),
            );
        let clock: Arc<dyn scp_clock::Clock> = Arc::new(scp_clock::TestClock::new(NOW));
        Supervisor::with_providers(
            crypto,
            transport,
            event_log,
            key_resolver,
            Some(Box::new(
                crate::context::persistence::NoopContextPersistence,
            )),
            adapter,
            None,
            Some(clock),
            mls_storage,
        )
    }

    async fn deps_for(supervisor: &Arc<Supervisor>) -> ActorDeps {
        supervisor
            .build_actor_deps(&invoker())
            .await
            .expect("build_actor_deps")
    }

    /// Active context with `INVOKER` a member holding a large budget, `spent`
    /// already recorded (the open-time escrow debit), and `reserved_counter`
    /// standing in the §7.3.8 cumulative counter under [`UCAN_CID`].
    fn member_state(spent: u64, reserved_counter: u64) -> PerContextState {
        let mut state = PerContextState::new_for_test_encrypted([CTX_BYTE; 32], NOW, invoker());
        state
            .handle
            .transition_to(&ContextState::Active)
            .expect("active");
        state
            .membership
            .add_member(invoker(), "member".to_owned(), Vec::new());
        state
            .governance
            .budget_tracker
            .grant(&invoker(), Amount::new(1_000_000));
        if spent > 0 {
            state
                .governance
                .budget_tracker
                .record_spend(&invoker(), Amount::new(spent))
                .expect("record open-time escrow debit");
        }
        if reserved_counter > 0 {
            state.class_s.caveat_counters.insert(
                UCAN_CID.to_owned(),
                CaveatCounters {
                    amount_cumulative_used: reserved_counter,
                    ..Default::default()
                },
            );
        }
        state
    }

    fn policy() -> EconomicPolicy {
        EconomicPolicy {
            locked: false,
            cost_schedule: CostSchedule {
                currency: CurrencyCode::from("USD"),
                per_message: None,
                per_outlet_call: Some(Amount::new(10)),
                per_join: None,
                per_period: None,
                per_byte_stored: None,
            },
            payment_adapters: vec![],
            pricing_formula: None,
            payee: DID::from("did:key:stream-settle-payee"),
        }
    }

    fn settlement(
        billed_amount: u64,
        refund_amount: u64,
        billed_count: u32,
        cost_per_chunk: u64,
        amount_cumulative_reserved: u64,
        snapshot: Option<EconomicPolicySnapshot>,
    ) -> StreamSettlement {
        StreamSettlement {
            context_id: ctx_key(),
            invoker_did: invoker(),
            reserved: Amount::new(billed_amount + refund_amount),
            billed_amount: Amount::new(billed_amount),
            refund_amount: Amount::new(refund_amount),
            billed_count,
            request_id: [3u8; 16],
            outlet_id: "outlet-x".to_owned(),
            economic_policy_snapshot: snapshot,
            amount_cumulative_reserved,
            reserved_chunks: 0,
            ucan_cid: UCAN_CID.to_owned(),
            cost_per_chunk: Amount::new(cost_per_chunk),
        }
    }

    fn counting(captured: &Arc<AtomicUsize>) -> Arc<dyn PaymentAdapterDyn> {
        Arc::new(CountingPaymentAdapter {
            captured: Arc::clone(captured),
            ..Default::default()
        })
    }

    /// Happy path: generations match → the unspent cumulative reserve is
    /// released (`50 − billed 3×10 = 20` back to the counter, leaving `30` = the
    /// billed cumulative spend), the unspent escrow is refunded (`spent 100 −
    /// refund 70 = 30`), and the §19.15.5 receipt captures the EXACT billed `30`.
    #[tokio::test]
    async fn settle_releases_refunds_and_captures() {
        let captured = Arc::new(AtomicUsize::new(0));
        let supervisor = build_supervisor(Some(counting(&captured)));
        let deps = deps_for(&supervisor).await;

        let mut state = member_state(100, 50);
        state.governance.economic_policy = Some(policy());
        let mut cell = ClassSCell::new(state);
        let live_gen = cell.generation;

        let outcome = settle_outlet_stream(
            &mut cell,
            &deps,
            settlement(30, 70, 3, 10, 50, None),
            live_gen,
        )
        .await;

        match outcome {
            StreamSettleOutcome::Settled(Some(receipt)) => {
                assert_eq!(
                    receipt.amount,
                    Amount::new(30),
                    "the receipt captures the exact billed amount"
                );
            }
            other => panic!("expected Settled(Some(receipt)), got {other:?}"),
        }
        assert_eq!(captured.load(Ordering::SeqCst), 1, "exactly one capture");
        assert_eq!(
            cell.governance.budget_tracker.total_spent(&invoker()),
            Amount::new(30),
            "escrow refund of 70 applied: spent 100 − 70 = 30"
        );
        assert_eq!(
            cell.class_s.caveat_counters[UCAN_CID].amount_cumulative_used, 30,
            "counter released the unspent 20 of the 50 reserved: 50 − 20 = 30 billed spend"
        );
    }

    /// Fix-D confused-deputy guard: a generation MISMATCH touches NO owned state
    /// (no release, no refund). With no open-time policy SNAPSHOT there is
    /// nothing to capture either, so the outcome is
    /// `CapturedWithoutMutation(None)` and the durable reserves are left intact
    /// for the restore-time reconcile sweep.
    #[tokio::test]
    async fn generation_mismatch_captures_without_mutation() {
        let captured = Arc::new(AtomicUsize::new(0));
        let supervisor = build_supervisor(Some(counting(&captured)));
        let deps = deps_for(&supervisor).await;

        let mut state = member_state(100, 50);
        state.governance.economic_policy = Some(policy());
        let mut cell = ClassSCell::new(state);
        let live_gen = cell.generation;

        let outcome = settle_outlet_stream(
            &mut cell,
            &deps,
            settlement(30, 70, 3, 10, 50, None),
            live_gen.wrapping_add(1),
        )
        .await;

        assert!(
            matches!(outcome, StreamSettleOutcome::CapturedWithoutMutation(None)),
            "a generation mismatch with no policy snapshot captures nothing and mutates nothing"
        );
        assert_eq!(
            captured.load(Ordering::SeqCst),
            0,
            "no capture without an open-time policy snapshot on a replaced instance"
        );
        assert_eq!(
            cell.governance.budget_tracker.total_spent(&invoker()),
            Amount::new(100),
            "budget untouched on a generation mismatch (reserves left for the sweep)"
        );
        assert_eq!(
            cell.class_s.caveat_counters[UCAN_CID].amount_cumulative_used, 50,
            "counter untouched on a generation mismatch (reserves left for the sweep)"
        );
    }

    /// Unspent-release reconciliation is AMOUNT-based and SATURATES: when the
    /// billed cumulative spend meets or exceeds the reserve, nothing is released
    /// (the counter is left conservatively over-charged, never under-charged). A
    /// degenerate `billed × cost` overflow fails closed the same way.
    #[tokio::test]
    async fn unspent_release_saturates_and_overflow_fails_closed() {
        let supervisor = build_supervisor(None);
        let deps = deps_for(&supervisor).await;

        // billed 10 × cost 10 = 100 > reserved 40 → unspent saturates to 0.
        let mut cell = ClassSCell::new(member_state(0, 40));
        let live_gen = cell.generation;
        let outcome = settle_outlet_stream(
            &mut cell,
            &deps,
            settlement(0, 0, 10, 10, 40, None),
            live_gen,
        )
        .await;
        assert!(matches!(outcome, StreamSettleOutcome::Settled(None)));
        assert_eq!(
            cell.class_s.caveat_counters[UCAN_CID].amount_cumulative_used, 40,
            "billed ≥ reserve → release nothing"
        );

        // billed 2 × cost u64::MAX overflows checked_mul → release nothing.
        let mut cell = ClassSCell::new(member_state(0, 40));
        let live_gen = cell.generation;
        let outcome = settle_outlet_stream(
            &mut cell,
            &deps,
            settlement(0, 0, 2, u64::MAX, 40, None),
            live_gen,
        )
        .await;
        assert!(matches!(outcome, StreamSettleOutcome::Settled(None)));
        assert_eq!(
            cell.class_s.caveat_counters[UCAN_CID].amount_cumulative_used, 40,
            "billed × cost overflow → release nothing (conservatively over-charged)"
        );
    }

    /// The open-time escrow reversal SATURATES at zero (reversing more than was
    /// spent does not underflow) and a DOUBLE refund is a safe no-op — the
    /// property the [`StreamEscrowTicket`](crate::context::outlets::dispatch::StreamEscrowTicket)
    /// Drop-guard relies on when it fires after an explicit settlement.
    #[tokio::test]
    async fn escrow_refund_saturates_and_double_refund_is_noop() {
        let supervisor = build_supervisor(None);
        let deps = deps_for(&supervisor).await;
        let mut cell = ClassSCell::new(member_state(40, 0));

        reverse_stream_escrow(&mut cell, &deps, &ctx_key(), &invoker(), Amount::new(100))
            .await
            .expect("reverse persists");
        assert_eq!(
            cell.governance.budget_tracker.total_spent(&invoker()),
            Amount::new(0),
            "reversing more than spent saturates at 0"
        );

        reverse_stream_escrow(&mut cell, &deps, &ctx_key(), &invoker(), Amount::new(100))
            .await
            .expect("second reverse persists");
        assert_eq!(
            cell.governance.budget_tracker.total_spent(&invoker()),
            Amount::new(0),
            "a double-refund is a no-op"
        );
    }

    /// Capture failure after service was rendered (H8): the unspent escrow refund
    /// STILL applies, the BILLED amount is NOT reversed, and a
    /// `PaymentCaptureFailed` local event is surfaced for reconciliation.
    #[tokio::test]
    async fn capture_failure_records_event_without_reversing_billed() {
        let supervisor = build_supervisor(Some(Arc::new(FailCaptureAdapter)));
        let deps = deps_for(&supervisor).await;

        let mut state = member_state(100, 0);
        state.governance.economic_policy = Some(policy());
        let mut cell = ClassSCell::new(state);
        let live_gen = cell.generation;

        let outcome = settle_outlet_stream(
            &mut cell,
            &deps,
            settlement(30, 70, 3, 10, 0, None),
            live_gen,
        )
        .await;

        assert!(
            matches!(outcome, StreamSettleOutcome::Settled(None)),
            "capture failed → no receipt"
        );
        assert_eq!(
            cell.governance.budget_tracker.total_spent(&invoker()),
            Amount::new(30),
            "the unspent refund (70) applied; the billed 30 is NOT reversed (H8)"
        );
        let events = cell.class_c_view().receive_buffer_mut().drain();
        assert!(
            events.iter().any(|e| matches!(
                e,
                scp_protocol::context::membership::ContextEvent::PaymentCaptureFailed {
                    action,
                    cost: Some(30),
                    ..
                } if action == "outlet_stream"
            )),
            "a PaymentCaptureFailed(outlet_stream, cost 30) local event is surfaced"
        );
    }

    /// No-actor fallback: when the hosting context was torn down mid-stream, the
    /// billed receipt is STILL captured supervisor-side against the open-time
    /// economic snapshot (release + refund are moot — the owned state is gone).
    #[tokio::test]
    async fn no_actor_fallback_captures_against_snapshot() {
        let captured = Arc::new(AtomicUsize::new(0));
        let supervisor = build_supervisor(Some(counting(&captured)));
        assert!(
            supervisor.lookup(&ctx_key()).is_none(),
            "context is unregistered — exercises the no-actor path"
        );

        let snap = EconomicPolicySnapshot { policy: policy() };
        let receipt = supervisor
            .settle_outlet_stream_via_actor(settlement(30, 70, 3, 10, 50, Some(snap)), 0)
            .await
            .expect("the no-actor fallback never errors");
        let receipt = receipt.expect("captured against the open-time snapshot");
        assert_eq!(receipt.amount, Amount::new(30));
        assert_eq!(receipt.action_type, PaidActionType::OutletCall);
        assert_eq!(captured.load(Ordering::SeqCst), 1);
    }

    /// The [`ActorStreamSettlementSink`] forwards a sync `settle` all the way
    /// through the mailbox to the registered actor's handler, capturing the
    /// receipt (proves the sink → supervisor → mailbox → handler wiring end to
    /// end, with generations matching).
    #[tokio::test]
    async fn settlement_sink_forwards_to_actor() {
        let captured = Arc::new(AtomicUsize::new(0));
        let supervisor = build_supervisor(Some(counting(&captured)));
        let deps = deps_for(&supervisor).await;

        let mut state = member_state(100, 50);
        state.governance.economic_policy = Some(policy());
        supervisor
            .spawn_actor_with_state(state, deps, None)
            .await
            .expect("register the actor");
        // `spawn_actor_with_watchdog` stamps a fresh spawn-generation via
        // `spawn_generation.fetch_add(1) + 1`; this is the ONLY spawn on this
        // fresh supervisor, so the live actor's generation is deterministically
        // 1. The sink threads it into the settle so the confused-deputy guard
        // MATCHES (a wrong generation would drop the settlement — no capture).
        let generation = 1;

        let sink = ActorStreamSettlementSink::new(Arc::clone(&supervisor), generation);
        sink.settle(settlement(30, 70, 3, 10, 50, None));

        // The sink spawns the dispatch; poll until the capture lands (bounded).
        for _ in 0..200 {
            if captured.load(Ordering::SeqCst) == 1 {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
        assert_eq!(
            captured.load(Ordering::SeqCst),
            1,
            "the settlement sink drove exactly one capture through the actor"
        );
    }

    /// The [`ActorEscrowRefundSink`] routes a refund to the registered actor;
    /// the underlying `reverse_stream_escrow_via_actor` returns `Ok` on the
    /// happy path (persist landed).
    #[tokio::test]
    async fn reverse_stream_escrow_via_actor_routes_ok() {
        let supervisor = build_supervisor(None);
        let deps = deps_for(&supervisor).await;
        supervisor
            .spawn_actor_with_state(member_state(40, 0), deps, None)
            .await
            .expect("register the actor");

        supervisor
            .reverse_stream_escrow_via_actor(&ctx_key(), &invoker(), Amount::new(100))
            .await
            .expect("reverse routes to the actor and persists");

        // Construct the sink to exercise its `Handle::current()` capture + the
        // sync fire-and-forget `refund` (best-effort; asserted not to panic).
        let sink = ActorEscrowRefundSink::new(Arc::clone(&supervisor));
        sink.refund(&ctx_key(), &invoker(), Amount::new(10));
    }
}
