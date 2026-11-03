//! Chunk 3e integration crux — `Supervisor::open_outlet_stream<E>` end to
//! end through the reserve (mailbox) → off-mailbox pump → settle (mailbox)
//! bracket against a REAL spawned actor: open a stream, grant credit, drain
//! the executor's data chunks, send a signed cancel, and assert the pump's
//! billing split plus that the close-time settlement RAN ON THE ACTOR (its
//! §19.15.5 receipt capture — which, in `outlet_stream_settle`, runs only
//! after the unspent-escrow refund and the cumulative-counter release).

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use ed25519_dalek::SigningKey;
use scp_did::DID;
use scp_platform::in_memory::InMemoryStorage;
use scp_protocol::context::ContextState;
use scp_protocol::context::outlets::registry::{OutletRegistry, register_outlet};
use scp_protocol::context::outlets::stream::{
    ChunkPayload, CreditGrantSigningInputs, OutletStreamCredit, RequestId, compute_caveats_binding,
    sign_credit_grant,
};
use scp_protocol::context::outlets::{OutletId, OutletKind, OutletRegistration, OutletSchema};
use scp_protocol::context::roles::{Capability, ContextRoleState, default_ceiling};
use scp_protocol::economy::types::{Amount, CostSchedule, CurrencyCode, EconomicPolicy};
use scp_protocol::trust::caveats::InvocationCaveats;

use super::Supervisor;
use crate::context::actor::state::PerContextState;
use crate::context::outlets::dispatch::{CancelIdentity, OpenStreamParams};
use crate::context::outlets::invoke::InvocationCaveatBinding;
use crate::context::outlets::invoke::{MutableInvocation, OutletExecutor, OutletExecutorError};
use crate::context::outlets::signer::{InProcessStreamSigner, StreamSigner};
use crate::context::outlets::stream::{AdmissionCaps, StreamIdentity};
use crate::economy::adapter::{CountingPaymentAdapter, PaymentAdapterDyn};

const NOW: u64 = 1_700_000_000;
const CTX_BYTE: u8 = 0x3e;
const COST_PER_CHUNK: u64 = 10;
const DATA_CHUNKS: u32 = 3;
const DECLARED_ESTIMATE: u32 = 5;
const UCAN_CID: &str = "cid-3e-orchestrator";

fn ctx_key() -> String {
    hex::encode([CTX_BYTE; 32])
}
fn invoker() -> DID {
    DID("did:dht:z6MkStreamOrch3e".to_owned())
}

/// Emits `DATA_CHUNKS` `Data` chunks, then blocks forever so the stream
/// stays open until the signed cancel drives the terminal (a natural `End`
/// would race the cancel). The blocked task is aborted at runtime shutdown.
struct BlockingStreamExecutor;
#[async_trait::async_trait]
impl OutletExecutor for BlockingStreamExecutor {
    async fn exec_action_stream(
        &self,
        _ctx: &mut MutableInvocation<'_>,
        _input: serde_json::Value,
        tx: tokio::sync::mpsc::Sender<ChunkPayload>,
    ) -> Result<(), OutletExecutorError> {
        for i in 0..DATA_CHUNKS {
            let _ = tx
                .send(ChunkPayload::Data {
                    value: serde_json::json!({ "tick": i }),
                })
                .await;
        }
        std::future::pending::<()>().await;
        Ok(())
    }
}

fn build_supervisor(captured: &Arc<AtomicUsize>) -> Arc<Supervisor> {
    let crypto = Arc::new(crate::crypto::mls::provider::NodeMlsFactory::new(
        invoker().0,
        Arc::new(scp_clock::SystemClock),
    ));
    let transport: Box<dyn crate::context::builder::ContextTransportProvider> =
        Box::new(crate::context::builder::NotConfiguredTransportProvider);
    let event_log: Box<dyn crate::context::builder::ContextEventLogProvider> =
        Box::new(crate::context::providers::MerkleEventLogProvider::new());
    let key_resolver: scp_protocol::context::governance::KeyResolver = Arc::new(|_, _| None);
    let mls_storage: Arc<dyn crate::crypto::mls::storage_adapter::OpenMlsStorageAdapter> = Arc::new(
        crate::crypto::mls::storage_adapter::SpawnBlockingStorageAdapter::new(Arc::new(
            InMemoryStorage::new(),
        )),
    );
    let payment_adapter: Arc<dyn PaymentAdapterDyn> = Arc::new(CountingPaymentAdapter {
        captured: Arc::clone(captured),
        ..Default::default()
    });
    let clock: Arc<dyn scp_clock::Clock> = Arc::new(scp_clock::TestClock::new(NOW));
    Supervisor::with_providers(
        crypto,
        transport,
        event_log,
        key_resolver,
        Some(Box::new(
            crate::context::persistence::NoOpContextPersistence,
        )),
        Some(payment_adapter),
        None,
        Some(clock),
        mls_storage,
        crate::domain_handlers(),
    )
}

fn policy() -> EconomicPolicy {
    EconomicPolicy {
        locked: false,
        cost_schedule: CostSchedule {
            currency: CurrencyCode::from("USD"),
            per_message: None,
            per_outlet_call: Some(Amount::new(COST_PER_CHUNK)),
            per_join: None,
            per_period: None,
            per_byte_stored: None,
        },
        payment_adapters: vec![],
        pricing_formula: None,
        payee: DID::from("did:key:stream-orch-payee"),
    }
}

fn authorizing_role_state() -> ContextRoleState {
    let mut role_state = ContextRoleState::new(
        ctx_key(),
        &invoker().0,
        default_ceiling(),
        vec![],
        &scp_clock::TestClock::new(NOW),
    )
    .expect("role state");
    role_state.members.insert(invoker().0);
    let caps = role_state
        .member_capabilities
        .entry(invoker().0)
        .or_default();
    caps.insert(Capability::OutletCallAll);
    caps.insert(Capability::OutletRegister);
    role_state
}

fn registration() -> OutletRegistration {
    OutletRegistration {
        outlet_id: "calculator".to_owned(),
        kind: OutletKind::Action,
        name: "Calculator".to_owned(),
        description: "A simple streaming calculator".to_owned(),
        schema: OutletSchema {
            input_schema: serde_json::json!({
                "type": "object",
                "properties": { "a": {"type": "number"}, "b": {"type": "number"} }
            }),
            output_schema: serde_json::json!({
                "type": "object",
                "properties": { "result": {"type": "number"} }
            }),
            aggregate_schema: None,
        },
        implementation_hash: [0xAA; 32],
        test_vectors: vec![],
        operator_did: "did:dht:z6MkOperator".into(),
        cost: None,
        message_catalog: Vec::new(),
        registered_at: 0,
        signature: Vec::new(),
    }
}

/// Open → grant → drain N Data → signed cancel → close → assert the pump's
/// billing split (billed 3×10, refund 50−30=20) AND that the close-time
/// settlement ran on the actor (its receipt capture is observed, proving the
/// preceding escrow refund + cumulative-counter release also executed).
/// The closed flag is set after the open, so the settlement also proves
/// the pump runs on the Supervisor's tracker (ADR-049 Decision 16).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn open_outlet_stream_reserve_pump_settle_end_to_end() {
    let captured = Arc::new(AtomicUsize::new(0));
    let supervisor = build_supervisor(&captured);

    // Spawn a live actor: invoker is the funded, OutletCall-capable owner
    // with the hosting economic policy set (for the close-time receipt).
    let role_state = authorizing_role_state();
    let mut state = PerContextState::new_for_test_encrypted([CTX_BYTE; 32], NOW, invoker());
    // §5.4.5 / SCP-OUT-034 — the stream timing/window policy is AUTHORITATIVE
    // from the hosting context's `ContextParams`, not the caller-supplied
    // `OpenStreamParams`. Pin a 1-second cancel-ack timeout on the CONTEXT so
    // the blocked executor's stream is force-terminated fast after the signed
    // cancel drains to the terminal chunk within the 5s deadline below.
    // (`params.stream_cancel_ack_secs` is set to a large sentinel to prove
    // `ContextParams` — not the caller — is what governs the timeout.)
    state.handle = crate::context::ContextHandle::new(
        ctx_key(),
        scp_protocol::context::ContextParams {
            stream_cancel_ack_secs: 1,
            ..scp_protocol::context::ContextParams::default()
        },
    );
    state
        .handle
        .transition_to(&ContextState::Active)
        .expect("active");
    state.role_state = role_state.clone();
    state
        .membership
        .add_member(invoker(), "owner".to_owned(), Vec::new());
    state
        .governance
        .budget_tracker
        .grant(&invoker(), Amount::new(1_000_000));
    state.governance.economic_policy = Some(policy());
    let deps = supervisor
        .build_actor_deps_loaded(&invoker())
        .await
        .expect("build_actor_deps");
    supervisor
        .spawn_actor_with_state(state, deps, None)
        .await
        .expect("spawn_actor_with_state");

    let mut registry = OutletRegistry::new();
    register_outlet(&mut registry, &role_state, registration(), &invoker().0)
        .expect("register streaming outlet");

    // A counter-bearing caveat so the §7.3.8 cumulative-counter reserve
    // (Step 5.5) is committed at open and RELEASED at settle.
    let mut caveats = InvocationCaveats::empty();
    caveats.amount_max_cumulative = Some(Amount::new(1_000));
    let request_id: RequestId = [CTX_BYTE; 16];
    let caveats_jcs = caveats.to_canonical_json_bytes().expect("jcs");
    let caveats_binding = compute_caveats_binding(
        UCAN_CID.as_bytes(),
        &request_id,
        &invoker().0,
        DECLARED_ESTIMATE,
        &caveats_jcs,
    );
    let identity = StreamIdentity {
        context_id: ctx_key(),
        outlet_id: "calculator".to_owned(),
        stream_epoch: 1,
        caveats_binding,
    };
    let invoker_key = SigningKey::from_bytes(&[0x24; 32]);
    let invoker_pk = invoker_key.verifying_key();
    let operator_signer: Arc<dyn StreamSigner> =
        Arc::new(InProcessStreamSigner::new(invoker_key.clone()));

    let params = OpenStreamParams {
        identity: identity.clone(),
        caps: AdmissionCaps {
            per_invoker: 10,
            per_origin_invoker: 10,
            per_outlet: 10,
        },
        invoker_did: invoker().0,
        origin_invoker_did: invoker().0,
        cost_per_chunk: Amount::new(COST_PER_CHUNK),
        available_balance: Amount::new(1_000_000),
        reserved_escrow: Amount::new(0),
        declared_estimated_chunk_count: Some(DECLARED_ESTIMATE),
        // These four timing/window fields are SERVER POLICY: `open_outlet_stream`
        // OVERWRITES them from the hosting context's `ContextParams`
        // (§5.4.5 / SCP-OUT-034), so the caller-supplied values here are
        // IRRELEVANT. `stream_cancel_ack_secs` in particular is a large
        // sentinel: if the caller value were (wrongly) honored the blocked
        // executor's forced terminal would not fire within the 5s drain
        // deadline and the test would fail — proving `ContextParams` (1s) wins.
        credit_window: 999,
        caveats: caveats.clone(),
        invoker_pk,
        operator_signer: Arc::clone(&operator_signer),
        stream_credit_stall_secs: 999,
        stream_cancel_ack_secs: 3_600,
        stream_ucan_recheck_secs: 999,
        ucan_cid: UCAN_CID.to_owned(),
        request_id,
        revocation_checker: Arc::new(
            scp_protocol::crypto::ucan::validate::InMemoryRevocationChecker::new(),
        ),
        economic_policy_snapshot: None,
    };
    let invocation_binding = Some(InvocationCaveatBinding {
        caveats,
        ucan_cid: UCAN_CID.to_owned(),
    });

    let executor: Arc<dyn OutletExecutor> = Arc::new(BlockingStreamExecutor);
    let outlet_id: OutletId = "calculator".to_owned();
    let mut handle = supervisor
        .open_outlet_stream(
            &ctx_key(),
            &registry,
            &outlet_id,
            serde_json::json!({ "a": 1, "b": 2 }),
            &invoker(),
            None,
            executor,
            None,
            None,
            None,
            invocation_binding,
            params,
        )
        .await
        .expect("open_outlet_stream must accept a well-formed streaming open");

    let mut rx = handle.receiver().expect("receiver");
    let summary_rx = handle.close_summary().expect("close summary");

    // Grant credit via the handle (exercise the control surface).
    let grant = OutletStreamCredit {
        request_id,
        grant: 8,
        monotonic_seq: 1,
        sig: sign_credit_grant(
            &invoker_key,
            &CreditGrantSigningInputs {
                context_id: &ctx_key(),
                outlet_id: "calculator",
                request_id: &request_id,
                grant: 8,
                monotonic_seq: 1,
                stream_epoch: 1,
                caveats_binding: &caveats_binding,
            },
        ),
    };
    handle
        .apply_credit_grant(&grant, Amount::new(0))
        .expect("signed credit grant applies");

    // Drain the executor's DATA_CHUNKS `Data` chunks.
    let mut data_seen = 0u32;
    for _ in 0..DATA_CHUNKS {
        let chunk = tokio::time::timeout(Duration::from_secs(5), rx.recv())
            .await
            .expect("data chunk within 5s")
            .expect("data chunk present");
        match chunk.payload {
            ChunkPayload::Data { .. } => data_seen += 1,
            other => panic!("expected Data, got {other:?}"),
        }
    }
    assert_eq!(data_seen, DATA_CHUNKS, "all executor Data chunks delivered");

    // Send a signed cancel — the runtime derives next_seq from its live
    // cursor (== 3), pinning the billing boundary at the 3 delivered chunks.
    let cancel_signer = InProcessStreamSigner::new(invoker_key.clone());
    let cancel_identity = CancelIdentity {
        context_id: ctx_key(),
        outlet_id: "calculator".to_owned(),
        caveats_binding,
    };
    let cancel_ack_seq = handle
        .apply_outlet_cancel_signed(&cancel_signer, &cancel_identity)
        .await
        .expect("signed cancel applies");
    assert_eq!(
        cancel_ack_seq,
        Some(u64::from(DATA_CHUNKS)),
        "cancel-ack seq pins to the runtime cursor after 3 emissions"
    );

    // ADR-049 Decision 16 — shutdown begins while the stream runs. The
    // shutdown token closes the pump with `ContextClosedMidStream` before
    // the cancel-ack timer fires, and the pump runs on the tracker, so its
    // close-time settlement below is admitted through the closed gate.
    supervisor.close_spawn_gate();

    // Drain to the terminal chunk.
    let terminal_code = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            match rx.recv().await {
                Some(chunk) => match chunk.payload {
                    ChunkPayload::Error {
                        code,
                        terminal: true,
                        ..
                    } => break Some(code),
                    ChunkPayload::End { .. } => break None,
                    _ => {}
                },
                None => break None,
            }
        }
    })
    .await
    .expect("terminal chunk within 5s");
    assert_eq!(
        terminal_code.as_deref(),
        Some(
            scp_protocol::context::outlets::stream::TerminateReason::ContextClosedMidStream.code()
        ),
        "the shutdown token closes the stream"
    );

    // The pump's close summary carries the economic reconciliation.
    let summary = tokio::time::timeout(Duration::from_secs(5), summary_rx)
        .await
        .expect("close summary resolves within 5s")
        .expect("summary channel not dropped");
    assert_eq!(summary.billed_count, DATA_CHUNKS, "3 Data chunks billed");
    assert_eq!(
        summary.billed_amount,
        Amount::new(COST_PER_CHUNK * u64::from(DATA_CHUNKS)),
        "billed amount == 3 × cost_per_chunk"
    );
    assert_eq!(
        summary.refund_amount,
        Amount::new(COST_PER_CHUNK * u64::from(DECLARED_ESTIMATE - DATA_CHUNKS)),
        "unspent escrow refunded: reserved 50 − billed 30 == 20"
    );

    // The close-time settlement RAN ON THE ACTOR (via the mailbox): its
    // §19.15.5 receipt capture is observed. `outlet_stream_settle` releases
    // the unspent cumulative counter and refunds the escrow BEFORE the
    // capture, so an observed capture proves the full settlement executed.
    let settled = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if captured.load(Ordering::SeqCst) >= 1 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await;
    assert!(
        settled.is_ok(),
        "close-time settlement (receipt capture) must run on the actor within 5s"
    );
    assert_eq!(
        captured.load(Ordering::SeqCst),
        1,
        "exactly one §19.15.5 receipt captured for the billed count"
    );
}

/// **SCP-OUT-035 durable persistence (round-9 F2)** — the streaming close
/// event is PERSISTED in production. `open_outlet_stream` wires the durable
/// [`ActorOutletInvokedEventSink`](crate::context::outlets::stream_settlement_adapter::ActorOutletInvokedEventSink)
/// INTERNALLY (the FFI bridges pass `None`), so a streaming close writes
/// EXACTLY ONE `OutletInvokedEvent` to the context event log — routed
/// through the verified `append_outlet_invoked_verified` boundary — carrying
/// the correct `chunks_billed`, `stream_manifest_hash`, and `cancel_ack_seq`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn open_outlet_stream_persists_one_invoked_event_035() {
    let captured = Arc::new(AtomicUsize::new(0));
    let supervisor = build_supervisor(&captured);

    // Initialize the durable event log for the hosting context so the
    // close-event append lands (full context creation normally does this).
    supervisor
        .event_log_ref()
        .expect("event log configured")
        .init_event_log(&[CTX_BYTE; 32])
        .await
        .expect("init event log");

    let role_state = authorizing_role_state();
    let mut state = PerContextState::new_for_test_encrypted([CTX_BYTE; 32], NOW, invoker());
    // 1-second cancel-ack timeout on the CONTEXT so the blocked executor's
    // stream is force-terminated fast after the signed cancel.
    state.handle = crate::context::ContextHandle::new(
        ctx_key(),
        scp_protocol::context::ContextParams {
            stream_cancel_ack_secs: 1,
            ..scp_protocol::context::ContextParams::default()
        },
    );
    state
        .handle
        .transition_to(&ContextState::Active)
        .expect("active");
    state.role_state = role_state.clone();
    state
        .membership
        .add_member(invoker(), "owner".to_owned(), Vec::new());
    state
        .governance
        .budget_tracker
        .grant(&invoker(), Amount::new(1_000_000));
    state.governance.economic_policy = Some(policy());
    let deps = supervisor
        .build_actor_deps_loaded(&invoker())
        .await
        .expect("build_actor_deps");
    supervisor
        .spawn_actor_with_state(state, deps, None)
        .await
        .expect("spawn_actor_with_state");

    let mut registry = OutletRegistry::new();
    register_outlet(&mut registry, &role_state, registration(), &invoker().0)
        .expect("register streaming outlet");

    let mut caveats = InvocationCaveats::empty();
    caveats.amount_max_cumulative = Some(Amount::new(1_000));
    let request_id: RequestId = [CTX_BYTE; 16];
    let caveats_jcs = caveats.to_canonical_json_bytes().expect("jcs");
    let caveats_binding = compute_caveats_binding(
        UCAN_CID.as_bytes(),
        &request_id,
        &invoker().0,
        DECLARED_ESTIMATE,
        &caveats_jcs,
    );
    let identity = StreamIdentity {
        context_id: ctx_key(),
        outlet_id: "calculator".to_owned(),
        stream_epoch: 1,
        caveats_binding,
    };
    let invoker_key = SigningKey::from_bytes(&[0x24; 32]);
    let invoker_pk = invoker_key.verifying_key();
    let operator_signer: Arc<dyn StreamSigner> =
        Arc::new(InProcessStreamSigner::new(invoker_key.clone()));

    let params = OpenStreamParams {
        identity: identity.clone(),
        caps: AdmissionCaps {
            per_invoker: 10,
            per_origin_invoker: 10,
            per_outlet: 10,
        },
        invoker_did: invoker().0,
        origin_invoker_did: invoker().0,
        cost_per_chunk: Amount::new(COST_PER_CHUNK),
        available_balance: Amount::new(1_000_000),
        reserved_escrow: Amount::new(0),
        declared_estimated_chunk_count: Some(DECLARED_ESTIMATE),
        credit_window: 999,
        caveats: caveats.clone(),
        invoker_pk,
        operator_signer: Arc::clone(&operator_signer),
        stream_credit_stall_secs: 999,
        stream_cancel_ack_secs: 3_600,
        stream_ucan_recheck_secs: 999,
        ucan_cid: UCAN_CID.to_owned(),
        request_id,
        revocation_checker: Arc::new(
            scp_protocol::crypto::ucan::validate::InMemoryRevocationChecker::new(),
        ),
        economic_policy_snapshot: None,
    };
    let invocation_binding = Some(InvocationCaveatBinding {
        caveats,
        ucan_cid: UCAN_CID.to_owned(),
    });

    let executor: Arc<dyn OutletExecutor> = Arc::new(BlockingStreamExecutor);
    let outlet_id: OutletId = "calculator".to_owned();
    // `invoked_event_sink` is `None` — exactly what the FFI bridges pass. The
    // supervisor must wire the durable sink itself.
    let mut handle = supervisor
        .open_outlet_stream(
            &ctx_key(),
            &registry,
            &outlet_id,
            serde_json::json!({ "a": 1, "b": 2 }),
            &invoker(),
            None,
            executor,
            None,
            None,
            None,
            invocation_binding,
            params,
        )
        .await
        .expect("open_outlet_stream accepts a well-formed streaming open");

    let mut rx = handle.receiver().expect("receiver");
    let summary_rx = handle.close_summary().expect("close summary");

    let grant = OutletStreamCredit {
        request_id,
        grant: 8,
        monotonic_seq: 1,
        sig: sign_credit_grant(
            &invoker_key,
            &CreditGrantSigningInputs {
                context_id: &ctx_key(),
                outlet_id: "calculator",
                request_id: &request_id,
                grant: 8,
                monotonic_seq: 1,
                stream_epoch: 1,
                caveats_binding: &caveats_binding,
            },
        ),
    };
    handle
        .apply_credit_grant(&grant, Amount::new(0))
        .expect("signed credit grant applies");

    let mut data_seen = 0u32;
    for _ in 0..DATA_CHUNKS {
        let chunk = tokio::time::timeout(Duration::from_secs(5), rx.recv())
            .await
            .expect("data chunk within 5s")
            .expect("data chunk present");
        if matches!(chunk.payload, ChunkPayload::Data { .. }) {
            data_seen += 1;
        }
    }
    assert_eq!(data_seen, DATA_CHUNKS, "all executor Data chunks delivered");

    let cancel_signer = InProcessStreamSigner::new(invoker_key.clone());
    let cancel_identity = CancelIdentity {
        context_id: ctx_key(),
        outlet_id: "calculator".to_owned(),
        caveats_binding,
    };
    let cancel_ack_seq = handle
        .apply_outlet_cancel_signed(&cancel_signer, &cancel_identity)
        .await
        .expect("signed cancel applies");
    assert_eq!(cancel_ack_seq, Some(u64::from(DATA_CHUNKS)));

    // Drain to the terminal chunk.
    let terminal = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            match rx.recv().await {
                Some(chunk)
                    if matches!(
                        chunk.payload,
                        ChunkPayload::End { .. } | ChunkPayload::Error { terminal: true, .. }
                    ) =>
                {
                    break true;
                }
                Some(_) => {}
                None => break false,
            }
        }
    })
    .await
    .expect("terminal chunk within 5s");
    assert!(terminal, "the stream reaches a terminal chunk");

    // Let the close settle.
    let _ = tokio::time::timeout(Duration::from_secs(5), summary_rx)
        .await
        .expect("close summary resolves")
        .expect("summary channel not dropped");

    // The durable sink appends the close event asynchronously at close; poll
    // the log until the ONE OutletInvokedEvent lands.
    let invoked = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let entries = supervisor
                .event_log_ref()
                .expect("event log configured")
                .event_log_entries(&[CTX_BYTE; 32])
                .expect("entries query ok")
                .unwrap_or_default();
            let invoked: Vec<_> = entries
                .into_iter()
                .filter(|e| e.event_type == scp_event_log::EventType::OutletInvoked)
                .collect();
            if !invoked.is_empty() {
                break invoked;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("one OutletInvokedEvent persisted within 5s");

    assert_eq!(
        invoked.len(),
        1,
        "EXACTLY ONE OutletInvokedEvent per stream at close"
    );
    let event: scp_protocol::context::outlets::lifecycle::OutletInvokedEvent =
        serde_json::from_slice(&invoked[0].payload.data)
            .expect("the durable leaf decodes as an OutletInvokedEvent");
    assert_eq!(
        event.chunks_billed, DATA_CHUNKS,
        "durable event records the 3 billable Data chunks"
    );
    assert_eq!(
        event.stream_chunk_count,
        DATA_CHUNKS + 1,
        "3 Data + one terminal chunk"
    );
    assert_eq!(
        event.cancel_ack_seq,
        Some(u64::from(DATA_CHUNKS)),
        "durable event records the pinned cancel-ack sequence"
    );
    assert_ne!(
        event.stream_manifest_hash, [0u8; 32],
        "durable event commits a non-empty manifest root"
    );
}

/// F5 regression — an open that FAILS AFTER the reserve has debited the
/// open-time escrow hold must REFUND that hold via the
/// [`StreamEscrowTicket`](crate::context::outlets::dispatch::StreamEscrowTicket)
/// `Drop` guard. The orchestrator arms the ticket IMMEDIATELY after the
/// reserve returns `Ok` (before the fallible post-input-hook build), so any
/// post-reserve early return — here a Phase-2 admission rejection forced by
/// zero-capacity caps — drops the ticket and reverses the debit.
///
/// The refund is proven by MONEY: the invoker is funded with EXACTLY one
/// reservation's worth of budget (`cost_per_chunk × estimate == 50`). The
/// failed open reserves (debits) the full 50; only if the ticket refunds it
/// can a follow-up reserve of the same 50 succeed. Without the refund the
/// follow-up would stay `InsufficientFunds` forever and the poll times out.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn open_outlet_stream_post_reserve_failure_refunds_escrow() {
    let captured = Arc::new(AtomicUsize::new(0));
    let supervisor = build_supervisor(&captured);

    let role_state = authorizing_role_state();
    let mut state = PerContextState::new_for_test_encrypted([CTX_BYTE; 32], NOW, invoker());
    // §5.4.5 / §9.18.B — the admission caps are AUTHORITATIVE from the
    // hosting context's `ContextParams`, not the caller-supplied
    // `params.caps`. Pin a zero per-invoker ceiling on the context so the
    // Phase-2 admission gate rejects the open AFTER the reserve has debited
    // the hold. (`params.caps` below is set HIGH to prove `ContextParams`
    // wins.)
    state.handle = crate::context::ContextHandle::new(
        ctx_key(),
        scp_protocol::context::ContextParams {
            max_concurrent_inbound_streams_per_invoker: 0,
            ..scp_protocol::context::ContextParams::default()
        },
    );
    state
        .handle
        .transition_to(&ContextState::Active)
        .expect("active");
    state.role_state = role_state.clone();
    state
        .membership
        .add_member(invoker(), "owner".to_owned(), Vec::new());
    // Budget = EXACTLY one reservation (cost 10 × estimate 5 == 50). The
    // follow-up reserve can only succeed once the FIRST (failed) open has
    // refunded its debit.
    let one_reservation = COST_PER_CHUNK * u64::from(DECLARED_ESTIMATE);
    state
        .governance
        .budget_tracker
        .grant(&invoker(), Amount::new(one_reservation));
    state.governance.economic_policy = Some(policy());
    let deps = supervisor
        .build_actor_deps_loaded(&invoker())
        .await
        .expect("build_actor_deps");
    supervisor
        .spawn_actor_with_state(state, deps, None)
        .await
        .expect("spawn_actor_with_state");

    let mut registry = OutletRegistry::new();
    register_outlet(&mut registry, &role_state, registration(), &invoker().0)
        .expect("register streaming outlet");

    // A counter-bearing caveat (mirrors the happy-path fixture) so Step 0's
    // binding recompute matches byte-for-byte and the FIRST rejection is
    // the admission gate — not a binding mismatch.
    let mut caveats = InvocationCaveats::empty();
    caveats.amount_max_cumulative = Some(Amount::new(1_000));
    let request_id: RequestId = [CTX_BYTE; 16];
    let caveats_jcs = caveats.to_canonical_json_bytes().expect("jcs");
    let caveats_binding = compute_caveats_binding(
        UCAN_CID.as_bytes(),
        &request_id,
        &invoker().0,
        DECLARED_ESTIMATE,
        &caveats_jcs,
    );
    let identity = StreamIdentity {
        context_id: ctx_key(),
        outlet_id: "calculator".to_owned(),
        stream_epoch: 1,
        caveats_binding,
    };
    let invoker_key = SigningKey::from_bytes(&[0x24; 32]);
    let invoker_pk = invoker_key.verifying_key();
    let operator_signer: Arc<dyn StreamSigner> = Arc::new(InProcessStreamSigner::new(invoker_key));

    let params = OpenStreamParams {
        identity,
        // Deliberately HIGH: `open_outlet_stream` OVERWRITES `caps` from the
        // context's `ContextParams` (per-invoker == 0, set above), so the
        // Phase-2 admission gate rejects even though these caller-supplied
        // caps would admit. This proves `ContextParams` is authoritative.
        caps: AdmissionCaps {
            per_invoker: 999,
            per_origin_invoker: 999,
            per_outlet: 999,
        },
        invoker_did: invoker().0,
        origin_invoker_did: invoker().0,
        cost_per_chunk: Amount::new(COST_PER_CHUNK),
        available_balance: Amount::new(one_reservation),
        reserved_escrow: Amount::new(0),
        declared_estimated_chunk_count: Some(DECLARED_ESTIMATE),
        // These four timing/window fields are SERVER POLICY: `open_outlet_stream`
        // OVERWRITES them from the hosting context's `ContextParams`
        // (§5.4.5 / SCP-OUT-034), so the caller-supplied values here are
        // IRRELEVANT. This open is rejected at the Phase-2 admission gate
        // (per-invoker == 0) BEFORE the pump ever spawns, so no timer runs —
        // the sentinels below never take effect and simply document the
        // caller-supplied values as non-authoritative.
        credit_window: 999,
        caveats: caveats.clone(),
        invoker_pk,
        operator_signer,
        stream_credit_stall_secs: 999,
        stream_cancel_ack_secs: 3_600,
        stream_ucan_recheck_secs: 999,
        ucan_cid: UCAN_CID.to_owned(),
        request_id,
        revocation_checker: Arc::new(
            scp_protocol::crypto::ucan::validate::InMemoryRevocationChecker::new(),
        ),
        economic_policy_snapshot: None,
    };
    let invocation_binding = Some(InvocationCaveatBinding {
        caveats,
        ucan_cid: UCAN_CID.to_owned(),
    });

    let executor: Arc<dyn OutletExecutor> = Arc::new(BlockingStreamExecutor);
    let outlet_id: OutletId = "calculator".to_owned();
    let open_result = supervisor
        .open_outlet_stream(
            &ctx_key(),
            &registry,
            &outlet_id,
            serde_json::json!({ "a": 1, "b": 2 }),
            &invoker(),
            None,
            executor,
            None,
            None,
            None,
            invocation_binding,
            params,
        )
        .await;
    // `StreamSessionHandle` is not `Debug`, so match rather than `expect_err`.
    match open_result {
        Ok(_) => panic!("a zero-capacity admission cap must reject the open after the reserve"),
        Err(rejection) => assert!(
            matches!(
                rejection,
                crate::context::outlets::invoke::OutletStreamOpenError::Rejected(
                    crate::context::outlets::dispatch::OpenStreamRejection::AdmissionRateLimited { .. }
                )
            ),
            "the open is rejected at the Phase-2 admission gate: {rejection:?}"
        ),
    }

    // The reserve debited the full hold; the ticket `Drop` spawns a mailbox
    // reversal. Prove the refund landed by observing that a follow-up
    // reserve of the SAME entire budget succeeds — impossible unless the
    // debit was returned. Retrying on rejection is token-neutral: the
    // reserve refunds its own hard-rate token on an insufficient-funds
    // reject.
    let restored = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if supervisor
                .reserve_outlet_stream_economy_via_actor(
                    &ctx_key(),
                    &invoker(),
                    Amount::new(COST_PER_CHUNK),
                    DECLARED_ESTIMATE,
                    None,
                    NOW,
                )
                .await
                .is_ok()
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await;
    assert!(
        restored.is_ok(),
        "the StreamEscrowTicket Drop must refund the debited hold — a \
             follow-up reserve of the full budget succeeds only once the \
             refund lands"
    );
}

/// §5.4.5 round-5 per-invoker admission tier + §9.18.B: the concurrent-
/// stream caps enforced in the production `open_outlet_stream` path are
/// sourced from the hosting context's `ContextParams`, NOT from the
/// caller-supplied `params.caps`. With `ContextParams` pinning
/// `max_concurrent_inbound_streams_per_invoker == 1` (and `params.caps`
/// deliberately set to `999` on every open), the second concurrent open by
/// the same invoker is rejected with the per-invoker transport slug —
/// proving the caps come from `ContextParams` and that the caller cannot
/// inflate its own ceiling on the wire (SCP-OUT-034 AC "per-invoker cap").
#[tokio::test]
async fn open_outlet_stream_per_invoker_cap_sourced_from_context_params() {
    use scp_protocol::context::outlets::error_codes::SLUG_TRANSPORT_CONCURRENT_STREAMS_PER_INVOKER;

    let captured = Arc::new(AtomicUsize::new(0));
    let supervisor = build_supervisor(&captured);

    // Host a context whose ContextParams pins per_invoker == 1.
    let role_state = authorizing_role_state();
    let mut state = PerContextState::new_for_test_encrypted([CTX_BYTE; 32], NOW, invoker());
    state.handle = crate::context::ContextHandle::new(
        ctx_key(),
        scp_protocol::context::ContextParams {
            max_concurrent_inbound_streams_per_invoker: 1,
            ..scp_protocol::context::ContextParams::default()
        },
    );
    state
        .handle
        .transition_to(&ContextState::Active)
        .expect("active");
    state.role_state = role_state.clone();
    state
        .membership
        .add_member(invoker(), "owner".to_owned(), Vec::new());
    // Budget for two concurrent holds (2 × cost 10 × estimate 5 == 100),
    // with headroom — the second open still reaches (and debits at) the
    // reserve before the admission gate rejects it.
    state
        .governance
        .budget_tracker
        .grant(&invoker(), Amount::new(1_000_000));
    state.governance.economic_policy = Some(policy());
    let deps = supervisor
        .build_actor_deps_loaded(&invoker())
        .await
        .expect("build_actor_deps");
    supervisor
        .spawn_actor_with_state(state, deps, None)
        .await
        .expect("spawn_actor_with_state");

    let mut registry = OutletRegistry::new();
    register_outlet(&mut registry, &role_state, registration(), &invoker().0)
        .expect("register streaming outlet");

    let invoker_key = SigningKey::from_bytes(&[0x24; 32]);
    let invoker_pk = invoker_key.verifying_key();
    let outlet_id: OutletId = "calculator".to_owned();

    // Builds a well-formed open (params + matching caveat binding) for a
    // distinct request_id. `caps` is HIGH (999) so any admission rejection
    // is attributable ONLY to the context's per_invoker == 1 ceiling.
    let make_open = |req_byte: u8| {
        let mut caveats = InvocationCaveats::empty();
        caveats.amount_max_cumulative = Some(Amount::new(1_000));
        let request_id: RequestId = [req_byte; 16];
        let caveats_jcs = caveats.to_canonical_json_bytes().expect("jcs");
        let caveats_binding = compute_caveats_binding(
            UCAN_CID.as_bytes(),
            &request_id,
            &invoker().0,
            DECLARED_ESTIMATE,
            &caveats_jcs,
        );
        let identity = StreamIdentity {
            context_id: ctx_key(),
            outlet_id: "calculator".to_owned(),
            stream_epoch: 1,
            caveats_binding,
        };
        let operator_signer: Arc<dyn StreamSigner> =
            Arc::new(InProcessStreamSigner::new(invoker_key.clone()));
        let params = OpenStreamParams {
            identity,
            caps: AdmissionCaps {
                per_invoker: 999,
                per_origin_invoker: 999,
                per_outlet: 999,
            },
            invoker_did: invoker().0,
            origin_invoker_did: invoker().0,
            cost_per_chunk: Amount::new(COST_PER_CHUNK),
            available_balance: Amount::new(1_000_000),
            reserved_escrow: Amount::new(0),
            declared_estimated_chunk_count: Some(DECLARED_ESTIMATE),
            credit_window: 32,
            caveats: caveats.clone(),
            invoker_pk,
            operator_signer,
            stream_credit_stall_secs: 30,
            stream_cancel_ack_secs: 1,
            stream_ucan_recheck_secs: 3_600,
            ucan_cid: UCAN_CID.to_owned(),
            request_id,
            revocation_checker: Arc::new(
                scp_protocol::crypto::ucan::validate::InMemoryRevocationChecker::new(),
            ),
            economic_policy_snapshot: None,
        };
        let binding = InvocationCaveatBinding {
            caveats,
            ucan_cid: UCAN_CID.to_owned(),
        };
        (params, binding)
    };

    // First open — admitted (per_invoker count 0 → 1). The blocking
    // executor never emits a terminal chunk, so the admission slot stays
    // occupied for the whole test.
    let (params1, binding1) = make_open(0x11);
    let exec1: Arc<dyn OutletExecutor> = Arc::new(BlockingStreamExecutor);
    let first = supervisor
        .open_outlet_stream(
            &ctx_key(),
            &registry,
            &outlet_id,
            serde_json::json!({ "a": 1, "b": 2 }),
            &invoker(),
            None,
            exec1,
            None,
            None,
            None,
            Some(binding1),
            params1,
        )
        .await;
    assert!(
        first.is_ok(),
        "the first open is admitted under the per_invoker == 1 ceiling"
    );

    // Second open by the SAME invoker while the first is still open — the
    // per-invoker ceiling of 1 (from ContextParams) is saturated. Rejected
    // with the per-invoker transport slug, even though params.caps == 999.
    let (params2, binding2) = make_open(0x22);
    let exec2: Arc<dyn OutletExecutor> = Arc::new(BlockingStreamExecutor);
    let second = supervisor
        .open_outlet_stream(
            &ctx_key(),
            &registry,
            &outlet_id,
            serde_json::json!({ "a": 1, "b": 2 }),
            &invoker(),
            None,
            exec2,
            None,
            None,
            None,
            Some(binding2),
            params2,
        )
        .await;
    match second {
        Ok(_) => {
            panic!("the (N+1)-th open must be rejected by the ContextParams per_invoker cap")
        }
        Err(crate::context::outlets::invoke::OutletStreamOpenError::Rejected(
            crate::context::outlets::dispatch::OpenStreamRejection::AdmissionRateLimited { slug },
        )) => {
            assert_eq!(
                slug, SLUG_TRANSPORT_CONCURRENT_STREAMS_PER_INVOKER,
                "rejection carries the per-invoker concurrent-streams slug \
                     (caps sourced from ContextParams, not params.caps)"
            );
        }
        Err(other) => {
            panic!("expected AdmissionRateLimited per-invoker, got {other:?}")
        }
    }

    // Keep the first stream's admission slot occupied through the assertion.
    drop(first);
}

// =====================================================================
// SCP-OUT-036 — best-effort cross-context bridge, through the real
// `Supervisor::open_outlet_stream_cross_context` entry.
// =====================================================================

/// Builds `OpenStreamParams`, a matching incoming B-side `OutletStreamOpen`,
/// and the matching §7.3.8 [`InvocationCaveatBinding`] for a cross-context
/// open against the spawned `ctx_key()` context. `caveats` are the effective
/// value caveats bound to the invocation UCAN — they drive both the pinned
/// `caveats_binding` and the returned binding, so the two agree at open.
fn xctx_open_inputs(
    cost_per_chunk: Amount,
    chain_depth: u8,
    caveats: InvocationCaveats,
    request_id: RequestId,
) -> (
    crate::context::outlets::dispatch::OpenStreamParams,
    scp_protocol::context::outlets::stream::OutletStreamOpen,
    crate::context::outlets::invoke::InvocationCaveatBinding,
) {
    let caveats_jcs = caveats.to_canonical_json_bytes().expect("jcs");
    let caveats_binding = compute_caveats_binding(
        UCAN_CID.as_bytes(),
        &request_id,
        &invoker().0,
        DECLARED_ESTIMATE,
        &caveats_jcs,
    );
    let identity = StreamIdentity {
        context_id: ctx_key(),
        outlet_id: "calculator".to_owned(),
        stream_epoch: 1,
        caveats_binding,
    };
    let invoker_key = SigningKey::from_bytes(&[0x24; 32]);
    let invoker_pk = invoker_key.verifying_key();
    let operator_signer: Arc<dyn StreamSigner> = Arc::new(InProcessStreamSigner::new(invoker_key));
    let params = OpenStreamParams {
        identity,
        caps: AdmissionCaps {
            per_invoker: 10,
            per_origin_invoker: 10,
            per_outlet: 10,
        },
        invoker_did: invoker().0,
        origin_invoker_did: invoker().0,
        cost_per_chunk,
        available_balance: Amount::new(1_000_000),
        reserved_escrow: Amount::new(0),
        declared_estimated_chunk_count: Some(DECLARED_ESTIMATE),
        credit_window: 32,
        caveats: caveats.clone(),
        invoker_pk,
        operator_signer,
        stream_credit_stall_secs: 999,
        stream_cancel_ack_secs: 999,
        stream_ucan_recheck_secs: 999,
        ucan_cid: UCAN_CID.to_owned(),
        request_id,
        revocation_checker: Arc::new(
            scp_protocol::crypto::ucan::validate::InMemoryRevocationChecker::new(),
        ),
        economic_policy_snapshot: None,
    };
    let incoming_open = scp_protocol::context::outlets::stream::OutletStreamOpen {
        request_id,
        outlet_id: "calculator".to_owned(),
        input: serde_json::json!({ "a": 1, "b": 2 }),
        invoker_did: invoker(),
        ucan: vec![0x01],
        caveats_binding,
        chain_depth,
        credit_window: 32,
        estimated_chunk_count: DECLARED_ESTIMATE,
        session_id: None,
        timeout_ms: 5_000,
    };
    let binding = crate::context::outlets::invoke::InvocationCaveatBinding {
        caveats,
        ucan_cid: UCAN_CID.to_owned(),
    };
    (params, incoming_open, binding)
}

/// AC12 (through the real supervisor entry): a best-effort cross-context
/// open of a PAID Action outlet (`cost.amount > 0`) is rejected zero-escrow
/// and NO receiver is produced.
#[tokio::test]
async fn open_outlet_stream_cross_context_rejects_paid_action() {
    use crate::context::outlets::invoke::{InvocationError, OutletOpenError};

    let captured = Arc::new(AtomicUsize::new(0));
    let supervisor = build_supervisor(&captured);
    let role_state = authorizing_role_state();

    // Register a PAID Action outlet (cost.amount > 0).
    let mut paid = registration();
    paid.cost = Some(scp_protocol::context::outlets::registry::OutletCost {
        amount: Amount::new(10),
        currency: "USD".to_owned(),
        payee: DID::from("did:dht:z6MkPayee"),
        cost_formula: None,
    });
    let mut registry = OutletRegistry::new();
    register_outlet(&mut registry, &role_state, paid, &invoker().0).expect("register paid outlet");

    let mut caveats = InvocationCaveats::empty();
    caveats.amount_max_cumulative = Some(Amount::new(1_000));
    let (params, incoming_open, binding) =
        xctx_open_inputs(Amount::new(10), 1, caveats, [CTX_BYTE; 16]);
    let executor: Arc<dyn OutletExecutor> = Arc::new(BlockingStreamExecutor);
    let outlet_id: OutletId = "calculator".to_owned();

    let result = supervisor
        .open_outlet_stream_cross_context(
            "ctx-a-036-reject",
            &ctx_key(),
            &registry,
            &outlet_id,
            serde_json::json!({ "a": 1, "b": 2 }),
            &invoker(),
            None,
            executor,
            &incoming_open,
            Some(binding),
            params,
        )
        .await;

    assert!(
        matches!(
            result,
            Err(OutletOpenError::Invocation(
                InvocationError::CrossContextPaidActionUnsupported { .. }
            ))
        ),
        "a paid Action best-effort cross-context open must be rejected zero-escrow; \
             got {result:?}"
    );
}

/// AC2 (through the real supervisor entry): a zero-cost cross-context open
/// returns a PLAINTEXT `mpsc::Receiver<OutletStreamChunk>` and forwards the
/// operator-signed chunks to the shared-member invoker in-process.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn open_outlet_stream_cross_context_returns_plaintext_receiver() {
    /// Emits two Data chunks then an explicit terminal `End` carrying a
    /// valid object aggregate (so the crossing's schema check passes on the
    /// happy path — the framework's default null aggregate is exercised as a
    /// violation by AC5/AC9 instead).
    struct FiniteStreamExecutor;
    #[async_trait::async_trait]
    impl OutletExecutor for FiniteStreamExecutor {
        async fn exec_action_stream(
            &self,
            _ctx: &mut crate::context::outlets::invoke::MutableInvocation<'_>,
            _input: serde_json::Value,
            tx: tokio::sync::mpsc::Sender<ChunkPayload>,
        ) -> Result<(), crate::context::outlets::invoke::OutletExecutorError> {
            for i in 0..2u32 {
                let _ = tx
                    .send(ChunkPayload::Data {
                        value: serde_json::json!({ "result": i }),
                    })
                    .await;
            }
            let _ = tx
                .send(ChunkPayload::End {
                    aggregate: serde_json::json!({ "result": 2 }),
                    provenance: scp_protocol::provenance::DataProvenance {
                        source_context: ctx_key(),
                        source_type: scp_protocol::provenance::SourceType::Persistent,
                        counterparties: Vec::new(),
                        purpose: None,
                        discovery_method: scp_protocol::provenance::DiscoveryMethod::OutOfBand,
                        age: std::time::Duration::from_secs(0),
                        memory_scope: scp_protocol::context::params::MemoryScope::Full,
                        chain_depth: 0,
                        chain_path: None,
                        payment_amount: None,
                        payment_adapter: None,
                        payment_receipt_id: None,
                    },
                    execution_time_ms: 1,
                })
                .await;
            Ok(())
        }
    }

    let captured = Arc::new(AtomicUsize::new(0));
    let supervisor = build_supervisor(&captured);

    // Spawn a live actor for the OPERATING context B (`ctx_key()`).
    let role_state = authorizing_role_state();
    let mut state = PerContextState::new_for_test_encrypted([CTX_BYTE; 32], NOW, invoker());
    state.handle = crate::context::ContextHandle::new(
        ctx_key(),
        scp_protocol::context::ContextParams::default(),
    );
    state
        .handle
        .transition_to(&ContextState::Active)
        .expect("active");
    state.role_state = role_state.clone();
    state
        .membership
        .add_member(invoker(), "owner".to_owned(), Vec::new());
    state
        .governance
        .budget_tracker
        .grant(&invoker(), Amount::new(1_000_000));
    state.governance.economic_policy = Some(policy());
    let deps = supervisor
        .build_actor_deps_loaded(&invoker())
        .await
        .expect("build_actor_deps");
    supervisor
        .spawn_actor_with_state(state, deps, None)
        .await
        .expect("spawn_actor_with_state");

    // Register a ZERO-COST Action outlet (cost None ⇒ zero-escrow accept).
    let mut registry = OutletRegistry::new();
    register_outlet(&mut registry, &role_state, registration(), &invoker().0)
        .expect("register zero-cost outlet");

    // Initialise the RECEIVING context A's event log so the bridge's A-side
    // recording succeeds against the shared provider.
    let a_ctx = "ctx-a-036-accept";
    supervisor
        .event_log_ref()
        .expect("event log provider")
        .init_event_log(&crate::context::state::context_id_to_bytes(a_ctx))
        .await
        .expect("init A event log");

    let mut caveats = InvocationCaveats::empty();
    caveats.amount_max_cumulative = Some(Amount::new(1_000));
    let (params, incoming_open, binding) =
        xctx_open_inputs(Amount::new(0), 2, caveats, [CTX_BYTE; 16]);
    let executor: Arc<dyn OutletExecutor> = Arc::new(FiniteStreamExecutor);
    let outlet_id: OutletId = "calculator".to_owned();

    // The Ok variant is a PLAINTEXT `mpsc::Receiver<OutletStreamChunk>`:
    // each item is the unmodified operator-signed chunk, forwarded verbatim
    // (identical to the same-context path).
    let mut rx: tokio::sync::mpsc::Receiver<
        scp_protocol::context::outlets::stream::OutletStreamChunk,
    > = supervisor
        .open_outlet_stream_cross_context(
            a_ctx,
            &ctx_key(),
            &registry,
            &outlet_id,
            serde_json::json!({ "a": 1, "b": 2 }),
            &invoker(),
            None,
            executor,
            &incoming_open,
            Some(binding),
            params,
        )
        .await
        .expect("zero-cost cross-context open must be accepted");

    // Drain the plaintext chunks the bridge forwards to the shared-member
    // invoker: two Data payloads followed by a terminal End. Each chunk is
    // the unmodified operator-signed chunk, forwarded verbatim end-to-end
    // through the supervisor path (AC4).
    let mut data = 0u32;
    let mut saw_end = false;
    while let Some(chunk) = rx.recv().await {
        assert_eq!(
            chunk.request_id, [CTX_BYTE; 16],
            "the pinned request_id rides on every forwarded chunk"
        );
        match chunk.payload {
            ChunkPayload::Data { .. } => data += 1,
            ChunkPayload::End { .. } => {
                saw_end = true;
                break;
            }
            ChunkPayload::Progress { .. } => {}
            ChunkPayload::Error { code, terminal, .. } => {
                panic!("unexpected terminal error on the happy path: {code} (terminal={terminal})")
            }
        }
    }
    assert_eq!(data, 2, "both Data chunks forwarded in plaintext");
    assert!(saw_end, "the stream closes with a plaintext terminal End");
}

/// FIX 1 — durable §7.3.8 counter CAS across cross-context opens. A
/// single-open-per-window `rate_window { max: 1 }` value-caveat binding
/// admits the FIRST cross-context open and REJECTS the SECOND on the same
/// context + UCAN. This proves the binding is THREADED to
/// `open_outlet_stream` (not discarded): the durable cross-invocation counter
/// reserve runs on the best-effort cross-context path, so a rate-capped
/// delegation cannot open unbounded cross-context streams (the per-invoker
/// DoS the finding described).
///
/// `rate_window` (not `max_calls`) is the counter exercised here because for
/// a zero-cost stream `max_calls` ALSO caps the per-stream estimated chunk
/// count (`estimated_chunk_count <= min(credit_window, max_calls)`), which
/// would reject the FIRST open on the estimate bound before the durable
/// cross-open CAS is reached; `rate_window` gates purely on open-count across
/// invocations and leaves the estimate bound untouched, isolating the
/// durable counter under test. Both route through the SAME
/// `commit_counter_reservation` CAS the finding is about.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn open_outlet_stream_cross_context_enforces_durable_counter() {
    use crate::context::outlets::invoke::{InvocationError, OutletOpenError};
    use scp_protocol::trust::caveats::RateWindow;

    let captured = Arc::new(AtomicUsize::new(0));
    let supervisor = build_supervisor(&captured);

    // Spawn a live actor for the OPERATING context B (`ctx_key()`) — the
    // durable caveat-counter store routes the CAS onto B's Class-S state.
    let role_state = authorizing_role_state();
    let mut state = PerContextState::new_for_test_encrypted([CTX_BYTE; 32], NOW, invoker());
    state.handle = crate::context::ContextHandle::new(
        ctx_key(),
        scp_protocol::context::ContextParams::default(),
    );
    state
        .handle
        .transition_to(&ContextState::Active)
        .expect("active");
    state.role_state = role_state.clone();
    state
        .membership
        .add_member(invoker(), "owner".to_owned(), Vec::new());
    state
        .governance
        .budget_tracker
        .grant(&invoker(), Amount::new(1_000_000));
    state.governance.economic_policy = Some(policy());
    let deps = supervisor
        .build_actor_deps_loaded(&invoker())
        .await
        .expect("build_actor_deps");
    supervisor
        .spawn_actor_with_state(state, deps, None)
        .await
        .expect("spawn_actor_with_state");

    // Zero-cost Action outlet (zero-escrow accept).
    let mut registry = OutletRegistry::new();
    register_outlet(&mut registry, &role_state, registration(), &invoker().0)
        .expect("register zero-cost outlet");

    let a_ctx = "ctx-a-036-maxcalls";
    supervisor
        .event_log_ref()
        .expect("event log provider")
        .init_event_log(&crate::context::state::context_id_to_bytes(a_ctx))
        .await
        .expect("init A event log");

    // One open per window: `rate_window { max: 1 }`.
    let mut caveats = InvocationCaveats::empty();
    caveats.rate_window = Some(RateWindow {
        max: 1,
        window_secs: 3600,
    });
    let outlet_id: OutletId = "calculator".to_owned();

    // FIRST open (request_id = [0x01; 16]) — the durable counter goes 0 → 1.
    let (params1, incoming1, binding1) =
        xctx_open_inputs(Amount::new(0), 2, caveats.clone(), [0x01; 16]);
    let exec1: Arc<dyn OutletExecutor> = Arc::new(BlockingStreamExecutor);
    let first = supervisor
        .open_outlet_stream_cross_context(
            a_ctx,
            &ctx_key(),
            &registry,
            &outlet_id,
            serde_json::json!({ "a": 1, "b": 2 }),
            &invoker(),
            None,
            exec1,
            &incoming1,
            Some(binding1),
            params1,
        )
        .await;
    assert!(
        first.is_ok(),
        "the FIRST single-use cross-context open must be admitted; got {:?}",
        first.err()
    );

    // SECOND open — a DISTINCT request_id (a fresh stream, not a duplicate)
    // under the SAME UCAN: the durable `rate_window` counter (keyed on
    // context + ucan_cid, NOT request_id) is already at its cap for the
    // window, so the open is REJECTED by the counter CAS — proving the
    // binding is enforced.
    let (params2, incoming2, binding2) = xctx_open_inputs(Amount::new(0), 2, caveats, [0x02; 16]);
    let exec2: Arc<dyn OutletExecutor> = Arc::new(BlockingStreamExecutor);
    let second = supervisor
        .open_outlet_stream_cross_context(
            a_ctx,
            &ctx_key(),
            &registry,
            &outlet_id,
            serde_json::json!({ "a": 1, "b": 2 }),
            &invoker(),
            None,
            exec2,
            &incoming2,
            Some(binding2),
            params2,
        )
        .await;
    assert!(
        matches!(
            second,
            Err(OutletOpenError::Invocation(
                InvocationError::CaveatViolation { .. }
            ))
        ),
        "the SECOND cross-context open under a rate_window:1 binding must be rejected \
             by the durable counter CAS; got {second:?}"
    );

    drop(first);
}
