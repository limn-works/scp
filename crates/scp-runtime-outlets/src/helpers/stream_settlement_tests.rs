//! Stream-settlement tests for the outlets domain (moved from `scp-runtime-core`
//! `context::outlets::stream_settlement_adapter`, ADR-070 §6.1): they drive the
//! outlets-private settlement functions against a `Supervisor`.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use scp_did::DID;
use scp_platform::in_memory::InMemoryStorage;
use scp_protocol::economy::types::{
    Amount, CostSchedule, CurrencyCode, EconomicPolicy, PaidActionType,
};

use super::{
    StreamSettleOutcome, reconcile_stream_reservations, reverse_stream_escrow, settle_outlet_stream,
};
use scp_protocol::context::ContextState;
use scp_runtime_core::context::actor::class_s::ClassSCell;
use scp_runtime_core::context::actor::deps::ActorDeps;
use scp_runtime_core::context::actor::state::PerContextState;
use scp_runtime_core::context::outlets::invoke::{
    EconomicPolicySnapshot, StreamReservationRecord, StreamSettlement, StreamSettlementSink,
};
use scp_runtime_core::context::outlets::stream_settlement_adapter::{
    ActorEscrowRefundSink, ActorStreamSettlementSink,
};
use scp_runtime_core::context::supervisor::supervisor::{SinkHandoff, Supervisor};
use scp_runtime_core::trust::caveat_counters::CaveatCounters;
use scp_runtime_types::economy::adapter::{
    AdapterCapabilities, CountingPaymentAdapter, PaymentAdapter, PaymentAdapterDyn,
    PaymentAuthorization, PaymentError, PaymentMetadata, PaymentReceipt, RefundConfirmation,
    VerificationResult,
};

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
    async fn verify_authorization(&self, _auth: &PaymentAuthorization) -> Result<(), PaymentError> {
        Ok(())
    }
    async fn capture(&self, _auth: &PaymentAuthorization) -> Result<PaymentReceipt, PaymentError> {
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

/// A [`ContextPersistence`](scp_runtime_core::context::persistence::ContextPersistence)
/// whose `persist_context` ALWAYS fails — models a storage-layer write error
/// on a Class-S commit so a settle's fail-closed persist returns `Err`. Loads
/// / lists / deletes still succeed (the test only exercises the write path).
struct FailPersistence;
#[async_trait::async_trait]
impl scp_runtime_core::context::persistence::ContextPersistence for FailPersistence {
    async fn persist_context(
        &self,
        _context_id: &str,
        _snapshot: &scp_runtime_core::context::state::ContextSnapshot,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        Err("induced persist failure".into())
    }
    async fn load_context(
        &self,
        _context_id: &str,
    ) -> Result<
        Option<scp_runtime_core::context::state::ContextSnapshot>,
        Box<dyn std::error::Error + Send + Sync>,
    > {
        Ok(None)
    }
    async fn delete_context(
        &self,
        _context_id: &str,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        Ok(())
    }
    async fn list_persisted_contexts(
        &self,
    ) -> Result<Vec<String>, Box<dyn std::error::Error + Send + Sync>> {
        Ok(Vec::new())
    }
}

fn build_supervisor(adapter: Option<Arc<dyn PaymentAdapterDyn>>) -> Arc<Supervisor> {
    build_supervisor_with_persistence(
        adapter,
        Box::new(scp_runtime_core::context::persistence::NoOpContextPersistence),
    )
}

fn build_supervisor_with_persistence(
    adapter: Option<Arc<dyn PaymentAdapterDyn>>,
    persistence: Box<dyn scp_runtime_core::context::persistence::ContextPersistence>,
) -> Arc<Supervisor> {
    let crypto = Arc::new(
        scp_runtime_core::crypto::mls::provider::NodeMlsFactory::new(
            INVOKER.to_owned(),
            Arc::new(scp_clock::SystemClock),
        ),
    );
    let transport: Box<dyn scp_runtime_core::context::builder::ContextTransportProvider> =
        Box::new(scp_runtime_core::context::builder::NotConfiguredTransportProvider);
    let event_log: Box<dyn scp_runtime_core::context::builder::ContextEventLogProvider> =
        Box::new(scp_runtime_core::context::providers::MerkleEventLogProvider::new());
    let key_resolver: scp_protocol::context::governance::KeyResolver = Arc::new(|_, _| None);
    let mls_storage: Arc<
        dyn scp_runtime_types::crypto::mls::storage_adapter::OpenMlsStorageAdapter,
    > = Arc::new(
        scp_runtime_types::crypto::mls::storage_adapter::SpawnBlockingStorageAdapter::new(
            Arc::new(InMemoryStorage::new()),
        ),
    );
    let clock: Arc<dyn scp_clock::Clock> = Arc::new(scp_clock::TestClock::new(NOW));
    Supervisor::with_providers(
        crypto,
        transport,
        event_log,
        key_resolver,
        Some(persistence),
        adapter,
        None,
        Some(clock),
        mls_storage,
        crate::test_support::test_domain_handlers(),
    )
}

async fn deps_for(supervisor: &Arc<Supervisor>) -> ActorDeps {
    supervisor
        .build_actor_deps_loaded(&invoker())
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
        None,
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

/// SCP-OUT-046 PASS-3 REGRESSION — the pass-2 fix carried the "already
/// settled" decision as the `bool` RETURN of the `commit_class_s_keep`
/// closure. `commit_class_s_keep` runs `persist_state_fail_closed(..).map(|()|
/// value)`, so on a persist FAILURE the closure's `bool` is DISCARDED (mapped
/// only on `Ok`) and the caller's `already_settled` stayed `false` → the
/// capture-skip was bypassed → a SECOND `PaymentReceipt` was captured
/// (double-bill; the xctx path has NO `stream_reservations` reconcile net to
/// dedup the capture). The concurrent test in `supervisor.rs` misses this: its
/// `InMemoryStorage` never fails a persist.
///
/// This test seeds an ALREADY-settled witness and drives a late/concurrent
/// second settle against a FAILING storage backend. The pass-3 AUTHORITATIVE
/// PRE-COMMIT read short-circuits to `AlreadySettled` BEFORE any persist or
/// capture, so the capture is NOT re-run despite the persist `Err`
/// (`captured == 0`) — the introduced double-capture is closed. Pre-fix this
/// asserts `captured == 1` and FAILS.
#[tokio::test]
async fn already_settled_witness_with_failing_store_does_not_recapture() {
    use scp_runtime_core::context::supervisor::saga_prepared_state::CommittedStreamingOutletInvocation;
    use scp_runtime_types::context::supervisor::saga_journal::SagaId;

    let captured = Arc::new(AtomicUsize::new(0));
    // Counting payment adapter + a FAILING persistence backend: the settle's
    // fail-closed Class-S persist returns `Err` on this call.
    let supervisor =
        build_supervisor_with_persistence(Some(counting(&captured)), Box::new(FailPersistence));
    let deps = deps_for(&supervisor).await;

    let saga_id = SagaId("saga-already-settled-failstore".to_owned());
    let mut state = member_state(100, 50);
    state.governance.economic_policy = Some(policy());

    // Seed the durable witness ALREADY settled — a prior settle moved the money
    // exactly once. Only `settled == true` + the `SagaId` key are load-bearing
    // for the pre-commit idempotency read; the rest mirrors a real seal.
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&[9u8; 32]);
    let receipt =
            scp_protocol::context::outlets::cross_context_saga::CrossContextOutletStreamReceipt::sign(
                &signing_key,
                scp_protocol::context::outlets::cross_context_saga::CrossContextOutletStreamReceiptFields {
                    caller_context_id: [0x3Au8; 32],
                    target_context_id: [CTX_BYTE; 32],
                    caller_did: INVOKER.to_owned(),
                    nonce: [0x8Fu8; 16],
                    outlet_registration_id: "outlet-x".to_owned(),
                    stream_manifest_hash: [0x55u8; 32],
                    outlet_invoked_event_id: "evt-x".to_owned(),
                    chain_depth: 3,
                    timestamp_ms: NOW.saturating_mul(1000),
                },
            )
            .expect("receipt signs");
    state.class_s.xctx_committed_stream_outputs.insert(
        saga_id.clone(),
        CommittedStreamingOutletInvocation {
            receipt,
            stream_manifest_hash: [0x55u8; 32],
            billed: Amount::new(30),
            refund: Amount::new(70),
            billed_count: 3,
            stream_chunk_count: 3,
            outlet_invoked_event_id: "evt-x".to_owned(),
            settled: true,
            target_context_id: [CTX_BYTE; 32],
            invoker_did: invoker(),
            reserved: Amount::new(100),
            request_id: [3u8; 16],
            outlet_registration_id: "outlet-x".to_owned(),
            economic_policy: Some(policy()),
            amount_cumulative_reserved: 50,
            reserved_chunks: 3,
            ucan_cid: UCAN_CID.to_owned(),
            cost_per_chunk: Amount::new(10),
        },
    );

    let mut cell = ClassSCell::new(state);
    let live_gen = cell.generation;
    let spent_before = cell.governance.budget_tracker.total_spent(&invoker());
    let counter_before = cell.class_s.caveat_counters[UCAN_CID].amount_cumulative_used;

    let outcome = settle_outlet_stream(
        &mut cell,
        &deps,
        settlement(30, 70, 3, 10, 50, None),
        live_gen,
        Some(&saga_id),
    )
    .await;

    assert!(
        matches!(outcome, StreamSettleOutcome::AlreadySettled),
        "an already-settled witness short-circuits to AlreadySettled \
             (no persist, no capture): {outcome:?}"
    );
    assert_eq!(
        captured.load(Ordering::SeqCst),
        0,
        "CRITICAL: the capture is NOT re-run for an already-settled witness even \
             when the persist would fail — no double-bill"
    );
    assert_eq!(
        cell.governance.budget_tracker.total_spent(&invoker()),
        spent_before,
        "no refund / reverse_spend ran (money untouched)"
    );
    assert_eq!(
        cell.class_s.caveat_counters[UCAN_CID].amount_cumulative_used, counter_before,
        "no §7.3.8 counter release ran (money untouched)"
    );
    assert!(
        cell.class_s
            .xctx_committed_stream_outputs
            .get(&saga_id)
            .is_some_and(|w| w.settled),
        "the witness stays settled"
    );
}

/// A zero-escrow-open stream whose only credit grant was REJECTED (apply
/// error) creates a crash-recovery record and then un-bumps its
/// `reserved_escrow` back to `0`. A clean settle — `reserved == 0`, no
/// refund, no counter release — must STILL remove that lingering `0`-record
/// from durable `stream_reservations`, so it never survives to the next
/// restart's reconcile sweep. Removing an already-zero, fully-settled record
/// changes no budget.
#[tokio::test]
async fn clean_settle_removes_lingering_zero_record() {
    let supervisor = build_supervisor(None);
    let deps = deps_for(&supervisor).await;

    let mut state = member_state(0, 0);
    // Model the grant-created-then-reverse-zeroed crash-recovery record for
    // the settlement's `request_id` ([3u8; 16]).
    state.class_s.stream_reservations.insert(
        hex::encode([3u8; 16]),
        scp_runtime_core::context::outlets::invoke::StreamReservationRecord {
            invoker_did: invoker(),
            ucan_cid: String::new(),
            cost_per_chunk: Amount::new(10),
            amount_cumulative_reserved: 0,
            reserved_escrow: Amount::new(0),
            generation: 0,
        },
    );
    let mut cell = ClassSCell::new(state);
    let live_gen = cell.generation;
    assert!(
        cell.class_s
            .stream_reservations
            .contains_key(&hex::encode([3u8; 16])),
        "precondition: the lingering 0-record exists before settle"
    );

    // reserved = 0 (open reserved nothing; the grant's apply rejected so the
    // ledger never extended), billed = 0, refund = 0, cumulative = 0.
    let outcome = settle_outlet_stream(
        &mut cell,
        &deps,
        settlement(0, 0, 0, 0, 0, None),
        live_gen,
        None,
    )
    .await;

    assert!(
        matches!(outcome, StreamSettleOutcome::Settled(None)),
        "a zero-cost clean settle settles with no receipt: {outcome:?}"
    );
    assert!(
        cell.class_s.stream_reservations.is_empty(),
        "the lingering 0-record is REMOVED on clean settle (no leak to the reconcile sweep)"
    );
    assert_eq!(
        cell.governance.budget_tracker.total_spent(&invoker()),
        Amount::new(0),
        "removing the fully-settled 0-record changes no budget"
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
        None,
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

/// Fix-D Part 1 (H8) — a generation MISMATCH on a stream whose off-mailbox
/// pump SURVIVED a crash-respawn STILL captures the §19.15.5 receipt for the
/// rendered bill (against the OPEN-TIME policy snapshot, since the live policy
/// may belong to a different context), while touching NO owned state: the
/// durable escrow hold + cumulative counter reserve are left intact for the
/// restore-time reconcile sweep.
#[tokio::test]
async fn generation_mismatch_with_snapshot_captures_rendered_bill() {
    let captured = Arc::new(AtomicUsize::new(0));
    let supervisor = build_supervisor(Some(counting(&captured)));
    let deps = deps_for(&supervisor).await;

    let mut state = member_state(100, 50);
    // Live policy present — Part 1 MUST ignore it (wrong instance) and use
    // the open-time SNAPSHOT instead.
    state.governance.economic_policy = Some(policy());
    let mut cell = ClassSCell::new(state);
    let live_gen = cell.generation;

    let snapshot = EconomicPolicySnapshot { policy: policy() };
    let outcome = settle_outlet_stream(
        &mut cell,
        &deps,
        settlement(30, 70, 3, 10, 50, Some(snapshot)),
        live_gen.wrapping_add(1),
        None,
    )
    .await;

    match outcome {
        StreamSettleOutcome::CapturedWithoutMutation(Some(receipt)) => {
            assert_eq!(
                receipt.amount,
                Amount::new(30),
                "the rendered bill is captured at the exact billed amount"
            );
        }
        other => panic!("expected CapturedWithoutMutation(Some(receipt)), got {other:?}"),
    }
    assert_eq!(
        captured.load(Ordering::SeqCst),
        1,
        "the rendered bill is captured even on a replaced instance (H8)"
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

/// Fix-D — a CLEAN settle (matching generation) CLEARS the crash-recovery
/// record in the same persist as the release/refund, so no stale record is
/// left for the reconcile sweep to double-release.
#[tokio::test]
async fn clean_settle_clears_recovery_record() {
    let supervisor = build_supervisor(None);
    let deps = deps_for(&supervisor).await;

    let mut state = member_state(100, 50);
    // A record persisted at open for this in-flight stream (keyed by the
    // settlement's request_id `[3u8; 16]`).
    state.class_s.stream_reservations.insert(
        hex::encode([3u8; 16]),
        StreamReservationRecord {
            invoker_did: invoker(),
            ucan_cid: UCAN_CID.to_owned(),
            cost_per_chunk: Amount::new(10),
            amount_cumulative_reserved: 50,
            reserved_escrow: Amount::new(100),
            generation: 0,
        },
    );
    let mut cell = ClassSCell::new(state);
    let live_gen = cell.generation;

    let outcome = settle_outlet_stream(
        &mut cell,
        &deps,
        settlement(30, 70, 3, 10, 50, None),
        live_gen,
        None,
    )
    .await;

    assert!(
        matches!(outcome, StreamSettleOutcome::Settled(_)),
        "a matching-generation settle runs on owned state"
    );
    assert!(
        cell.class_s.stream_reservations.is_empty(),
        "the clean settle cleared the crash-recovery record"
    );
}

/// Fix-D — the restore-time reconcile sweep drains an ORPHANED record (its
/// pump survived a crash and its settle was dropped on the bumped
/// generation): it refunds the FULL escrow hold, releases the FULL cumulative
/// reserve, and clears the record. Runs regardless of generation.
#[tokio::test]
async fn reconcile_sweep_refunds_releases_and_clears() {
    let supervisor = build_supervisor(None);
    let deps = deps_for(&supervisor).await;

    // Open-time state: escrow hold of 210 debited, cumulative counter at 350.
    let mut state = member_state(210, 350);
    state.class_s.stream_reservations.insert(
        hex::encode([7u8; 16]),
        StreamReservationRecord {
            invoker_did: invoker(),
            ucan_cid: UCAN_CID.to_owned(),
            cost_per_chunk: Amount::new(7),
            amount_cumulative_reserved: 350,
            reserved_escrow: Amount::new(210),
            // A STALE (pre-crash) generation — the sweep reconciles regardless
            // (a restore overwrites the live generation with a fresh one).
            generation: 99,
        },
    );
    let mut cell = ClassSCell::new(state);

    let reconciled = reconcile_stream_reservations(&mut cell, &deps, &ctx_key())
        .await
        .expect("reconcile persists");

    assert_eq!(reconciled, 1, "one orphaned record reconciled");
    assert_eq!(
        cell.governance.budget_tracker.total_spent(&invoker()),
        Amount::new(0),
        "the FULL escrow hold (210) was refunded"
    );
    assert_eq!(
        cell.class_s.caveat_counters[UCAN_CID].amount_cumulative_used, 0,
        "the FULL cumulative reserve (350) was released"
    );
    assert!(
        cell.class_s.stream_reservations.is_empty(),
        "the reconciled record was cleared (no double-release on a later restart)"
    );

    // Idempotent: a second sweep (empty map) reconciles zero and does not
    // over-refund / over-release.
    let again = reconcile_stream_reservations(&mut cell, &deps, &ctx_key())
        .await
        .expect("second reconcile is a no-op");
    assert_eq!(again, 0, "the second sweep finds no records");
    assert_eq!(
        cell.governance.budget_tracker.total_spent(&invoker()),
        Amount::new(0),
        "no over-refund on the idempotent re-run"
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
        None,
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
        None,
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
/// property the [`StreamEscrowTicket`](scp_runtime_core::context::outlets::dispatch::StreamEscrowTicket)
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
        None,
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
    let application = supervisor
        .settle_outlet_stream_via_actor_for_test(settlement(30, 70, 3, 10, 50, Some(snap)), 0, None)
        .await
        .expect("the no-actor fallback never errors");
    let receipt = application
        .receipt
        .expect("captured against the open-time snapshot");
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
        .spawn_actor_with_state_for_test(state, deps, None)
        .await
        .expect("register the actor");
    // `spawn_actor_with_watchdog` stamps a fresh spawn-generation via
    // `spawn_generation.fetch_add(1) + 1`; this is the ONLY spawn on this
    // fresh supervisor, so the live actor's generation is deterministically
    // 1. The sink threads it into the settle so the confused-deputy guard
    // MATCHES (a wrong generation would drop the settlement — no capture).
    let generation = 1;

    let sink = ActorStreamSettlementSink::new(Arc::downgrade(&supervisor), generation);
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
/// happy path (persist landed). A sink whose Supervisor dropped returns
/// without running the refund.
#[tokio::test]
async fn reverse_stream_escrow_via_actor_routes_ok() {
    let supervisor = build_supervisor(None);
    let deps = deps_for(&supervisor).await;
    supervisor
        .spawn_actor_with_state_for_test(member_state(40, 0), deps, None)
        .await
        .expect("register the actor");

    supervisor
        .reverse_stream_escrow_via_actor_for_test(&ctx_key(), &invoker(), Amount::new(100))
        .await
        .expect("reverse routes to the actor and persists");

    let sink = ActorEscrowRefundSink::new(Arc::downgrade(&supervisor));
    sink.refund(&ctx_key(), &invoker(), Amount::new(10)).await;

    let orphan = ActorEscrowRefundSink::new(std::sync::Weak::new());
    orphan.refund(&ctx_key(), &invoker(), Amount::new(10)).await;
}

/// ADR-049 Decision 16: a sink operation spawned before shutdown runs on
/// the tracker and the drain waits for it; one fired after shutdown, or
/// against a dropped Supervisor, does not run.
#[tokio::test]
async fn sink_op_is_drained_by_shutdown_and_refused_after_it() {
    let supervisor = build_supervisor(None);
    let weak = Arc::downgrade(&supervisor);
    let runtime = tokio::runtime::Handle::current();

    let (release_tx, release_rx) = tokio::sync::oneshot::channel::<()>();
    let ran = Arc::new(AtomicUsize::new(0));
    let ran_in = Arc::clone(&ran);
    scp_runtime_core::context::outlets::stream_settlement_adapter::spawn_supervisor_op(
        &weak,
        &runtime,
        SinkHandoff::StreamSettlement,
        move |_sup| async move {
            let _ = release_rx.await;
            ran_in.fetch_add(1, Ordering::SeqCst);
        },
    );
    let shutdown = tokio::spawn({
        let supervisor = Arc::clone(&supervisor);
        async move { supervisor.shutdown_all_contexts().await }
    });
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    assert!(
        !shutdown.is_finished(),
        "shutdown waits for a sink operation spawned before it"
    );
    release_tx.send(()).expect("the probe is still waiting");
    shutdown.await.expect("shutdown task");
    assert_eq!(ran.load(Ordering::SeqCst), 1, "the in-flight operation ran");

    let late = Arc::new(AtomicUsize::new(0));
    let late_in = Arc::clone(&late);
    scp_runtime_core::context::outlets::stream_settlement_adapter::spawn_supervisor_op(
        &weak,
        &runtime,
        SinkHandoff::StreamSettlement,
        move |_sup| async move {
            late_in.fetch_add(1, Ordering::SeqCst);
        },
    );
    let gone = Arc::new(AtomicUsize::new(0));
    let gone_in = Arc::clone(&gone);
    scp_runtime_core::context::outlets::stream_settlement_adapter::spawn_supervisor_op(
        &std::sync::Weak::new(),
        &runtime,
        SinkHandoff::StreamSettlement,
        move |_sup| async move {
            gone_in.fetch_add(1, Ordering::SeqCst);
        },
    );
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    assert_eq!(
        late.load(Ordering::SeqCst),
        0,
        "shutdown refuses a sink operation fired after it"
    );
    assert_eq!(
        gone.load(Ordering::SeqCst),
        0,
        "a dropped Supervisor runs no sink operation"
    );
}
