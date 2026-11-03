use crate::context::actor::signer::CommandSigner;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use ed25519_dalek::SigningKey;
use scp_did::DID;
use scp_platform::in_memory::InMemoryStorage;
use scp_protocol::context::ContextState;
use scp_protocol::context::outlets::cross_context_saga::CrossContextOutletStreamReceipt;
use scp_protocol::context::outlets::registry::{
    OutletCost, OutletRegistration, OutletRegistry, OutletSchema, register_outlet,
};
use scp_protocol::context::outlets::stream::{
    ChunkPayload, RequestId, compute_caveats_binding, compute_chunk_manifest_root,
};
use scp_protocol::context::outlets::{OutletId, OutletKind};
use scp_protocol::context::roles::{Capability, CapabilityCeiling};
use scp_protocol::economy::types::{Amount, CostSchedule, CurrencyCode, EconomicPolicy};
use scp_protocol::trust::caveats::InvocationCaveats;

use super::{DurableProviders, SagaAbortReason, SagaError, SagaSigners, Supervisor};
use crate::context::actor::ContextCommand;
use crate::context::actor::commands::{QueriesCommand, SagaPhaseMessage};
use crate::context::actor::state::PerContextState;
use crate::context::builder::ContextEventLogProvider;
use crate::context::outlets::dispatch::OpenStreamParams;
use crate::context::outlets::invoke::InvocationCaveatBinding;
use crate::context::outlets::invoke::{
    EconomicPolicySnapshot, MutableInvocation, OutletExecutor, OutletExecutorError,
};
use crate::context::outlets::signer::{InProcessStreamSigner, StreamSigner};
use crate::context::outlets::stream::{AdmissionCaps, StreamIdentity};
use crate::context::supervisor::saga_journal::{
    ProtocolRepositorySagaJournal, SagaId, SagaJournal, SagaState,
};
use crate::economy::adapter::{CountingPaymentAdapter, PaymentAdapterDyn};

const SS_NOW: u64 = 1_700_000_000;
const SS_CALLER: [u8; 32] = [0x51u8; 32];
const SS_TARGET: [u8; 32] = [0x52u8; 32];
/// A third context (the target of the overlapping saga S2 in the AC2 test).
const SS_THIRD: [u8; 32] = [0x53u8; 32];
const SS_OUTLET: &str = "calculator-v1";
const SS_UCAN_CID: &str = "cid-scp-out-046-streaming-saga";
const SS_COST: u64 = 10;
/// Reserve for 20 chunks (declared estimate) — deliberately larger than the
/// 10 chunks actually billed so the seal-close refund is strictly positive.
const SS_ESTIMATE: u32 = 20;
const SS_GRANTED: u64 = 1_000_000;
const SS_RESERVED: u64 = SS_COST * SS_ESTIMATE as u64;

fn ss_invoker() -> DID {
    DID("did:dht:z6MkStreamSagaInvoker".to_owned())
}
fn ss_creator() -> String {
    "did:dht:z6MkStreamSagaCreator".to_owned()
}

/// A recorded event-log append:
/// `(context_id, event_type, actor_did, payload_bytes, timestamp_secs)`.
type SsRecordedEvent = ([u8; 32], scp_event_log::EventType, String, Vec<u8>, u64);

/// An event-log provider that RECORDS every append so the test can assert the
/// dual `OutletInvoked` (target) / `CrossContextOutletInvoked` (caller) leaves
/// landed with the SAME sealed manifest root (§6.2.4 dual event-log recording).
#[derive(Clone, Default)]
struct SsRecordingEventLog {
    events: Arc<std::sync::Mutex<Vec<SsRecordedEvent>>>,
}
impl SsRecordingEventLog {
    fn snapshot(&self) -> Vec<SsRecordedEvent> {
        self.events
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }
}
#[async_trait::async_trait]
impl ContextEventLogProvider for SsRecordingEventLog {
    fn event_log_entries(
        &self,
        _context_id: &[u8; 32],
    ) -> Result<Option<Vec<scp_event_log::Event>>, scp_protocol::context::ContextError> {
        Ok(None)
    }

    async fn init_event_log(
        &self,
        _id: &[u8; 32],
    ) -> Result<(), scp_protocol::context::builder::ContextCreationError> {
        Ok(())
    }
    async fn append_event(
        &self,
        id: &[u8; 32],
        event_type: scp_event_log::EventType,
        actor: &str,
        payload: scp_event_log::EventPayload,
        timestamp_secs: u64,
    ) -> Result<(), scp_protocol::context::builder::ContextCreationError> {
        self.events
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push((
                *id,
                event_type,
                actor.to_owned(),
                payload.data,
                timestamp_secs,
            ));
        Ok(())
    }
    async fn destroy_event_log(
        &self,
        _id: &[u8; 32],
    ) -> Result<(), scp_protocol::context::builder::ContextCreationError> {
        Ok(())
    }
}

/// Emits exactly `data_chunks` `Data` chunks then a clean terminal `End`
/// carrying a valid object aggregate (so the crossing's schema check passes).
/// Increments `invoked` on entry so the test can prove crash recovery does NOT
/// re-invoke (AC7).
struct FiniteChunkExecutor {
    data_chunks: u32,
    invoked: Arc<AtomicUsize>,
}
#[async_trait::async_trait]
impl OutletExecutor for FiniteChunkExecutor {
    async fn exec_action_stream(
        &self,
        _ctx: &mut MutableInvocation<'_>,
        _input: serde_json::Value,
        tx: tokio::sync::mpsc::Sender<ChunkPayload>,
    ) -> Result<(), OutletExecutorError> {
        self.invoked.fetch_add(1, Ordering::SeqCst);
        for i in 0..self.data_chunks {
            if tx
                .send(ChunkPayload::Data {
                    value: serde_json::json!({ "result": i }),
                })
                .await
                .is_err()
            {
                return Ok(());
            }
        }
        let _ = tx
            .send(ChunkPayload::End {
                aggregate: serde_json::json!({ "result": self.data_chunks }),
                provenance: ss_provenance(),
                execution_time_ms: 1,
            })
            .await;
        Ok(())
    }
}

/// Emits exactly `data_chunks` `Data` chunks then BLOCKS forever (no terminal),
/// modelling a mid-stream crash: the seal task forwards + durably captures the
/// prefix, then wedges, so the journal stays `Committing` and no seal witness is
/// written — the truncated-close recovery surface is what seals it (AC7).
struct PrefixThenBlockExecutor {
    data_chunks: u32,
    invoked: Arc<AtomicUsize>,
}
#[async_trait::async_trait]
impl OutletExecutor for PrefixThenBlockExecutor {
    async fn exec_action_stream(
        &self,
        _ctx: &mut MutableInvocation<'_>,
        _input: serde_json::Value,
        tx: tokio::sync::mpsc::Sender<ChunkPayload>,
    ) -> Result<(), OutletExecutorError> {
        self.invoked.fetch_add(1, Ordering::SeqCst);
        for i in 0..self.data_chunks {
            if tx
                .send(ChunkPayload::Data {
                    value: serde_json::json!({ "result": i }),
                })
                .await
                .is_err()
            {
                return Ok(());
            }
        }
        std::future::pending::<()>().await;
        Ok(())
    }
}

fn ss_provenance() -> scp_protocol::provenance::DataProvenance {
    scp_protocol::provenance::DataProvenance {
        source_context: hex::encode(SS_TARGET),
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
    }
}

fn ss_policy() -> EconomicPolicy {
    EconomicPolicy {
        locked: false,
        cost_schedule: CostSchedule {
            currency: CurrencyCode::from("USD"),
            per_message: None,
            per_outlet_call: Some(Amount::new(SS_COST)),
            per_join: None,
            per_period: None,
            per_byte_stored: None,
        },
        payment_adapters: vec![],
        pricing_formula: None,
        payee: DID::from("did:key:stream-saga-payee"),
    }
}

/// Build a supervisor wired for the paid streaming saga: a caller-held journal
/// (so the test reads FSM state), a counting payment adapter (so a billed
/// `PaymentReceipt` capture is observable), a fixed test clock (for freshness),
/// and a recording event log (for the dual-log assertion). Ungated outlet ⇒
/// `key_resolver` returns `None` (no UCAN re-bind proof to resolve).
fn build_ss_supervisor(
    captured: &Arc<AtomicUsize>,
    journal: Arc<dyn SagaJournal>,
    event_log: Box<dyn ContextEventLogProvider>,
) -> Arc<Supervisor> {
    let crypto = Arc::new(crate::crypto::mls::provider::NodeMlsFactory::new(
        ss_creator(),
        Arc::new(scp_clock::SystemClock),
    ));
    let transport: Box<dyn crate::context::builder::ContextTransportProvider> =
        Box::new(crate::context::builder::NotConfiguredTransportProvider);
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
    let clock: Arc<dyn scp_clock::Clock> = Arc::new(scp_clock::TestClock::new(SS_NOW));
    Supervisor::with_providers_and_journal(
        crypto,
        transport,
        event_log,
        key_resolver,
        Box::new(crate::context::persistence::NoOpContextPersistence),
        Some(payment_adapter),
        None,
        Some(clock),
        DurableProviders::for_test(journal, mls_storage),
        crate::crypto::wrapping::single_custody_source(Arc::new(
            scp_platform::testing::InMemoryKeyCustody::new(),
        )),
        crate::domain_handlers(),
    )
}

/// Push an established (both-approved) outbound `source → target` interface for
/// `SS_OUTLET` onto a state's governance, so the driver's target-axis
/// authorize-before-reserve gate passes for a saga with that caller/target.
fn ss_push_interface(st: &mut PerContextState, source: [u8; 32], target: [u8; 32]) {
    st.governance.outlet_interfaces.push(
        scp_protocol::context::outlets::interface::OutletInterface {
            source_context: hex::encode(source),
            target_context: hex::encode(target),
            outlet_id: SS_OUTLET.to_owned(),
            rate_limit: None,
            inbound_rate_limit: None,
            per_caller_rate_limit: None,
            approved_by_source: true,
            approved_by_target: true,
            outbound_policy: None,
            inbound_policy: None,
        },
    );
}

/// Grant `ss_invoker` the outlet capabilities + ceiling on a caller/target state.
fn ss_grant_outlet_caps(st: &mut PerContextState) {
    st.membership
        .add_member(ss_invoker(), "member".to_owned(), Vec::new());
    st.role_state.members.insert(ss_invoker().0);
    let mut caps = std::collections::HashSet::new();
    caps.insert(Capability::OutletInterface);
    caps.insert(Capability::OutletCallAll);
    st.role_state
        .member_capabilities
        .insert(ss_invoker().0, caps);
    st.role_state
        .set_ceiling(CapabilityCeiling::new([
            Capability::OutletInterface,
            Capability::OutletCallAll,
        ]))
        .expect("well-formed built-in ceiling");
}

/// Caller (A) state: `ss_invoker` is a member holding `OutletInterface` +
/// `OutletCallAll` and an established (both-approved) `caller → target` interface
/// for `SS_OUTLET`, so the driver's authorize-before-reserve gates pass.
fn ss_caller_state_for(caller_id: [u8; 32], target_id: [u8; 32]) -> PerContextState {
    let mut st = PerContextState::new_for_test_encrypted(caller_id, SS_NOW, DID(ss_creator()));
    st.handle
        .transition_to(&ContextState::Active)
        .expect("active");
    st.role_state.creator_did = ss_creator();
    ss_grant_outlet_caps(&mut st);
    ss_push_interface(&mut st, caller_id, target_id);
    st
}

/// Target (B) state: a registered PAID streaming outlet, `ss_invoker` granted
/// the outlet capabilities + a budget covering the paid stream, and the hosting
/// economic policy set (payee for the close-time capture).
fn ss_paid_target_state(ctx_id: [u8; 32]) -> PerContextState {
    let mut st = PerContextState::new_for_test_encrypted(ctx_id, SS_NOW, DID(ss_creator()));
    st.handle
        .transition_to(&ContextState::Active)
        .expect("active");
    st.role_state.creator_did = ss_creator();
    ss_grant_outlet_caps(&mut st);
    st.governance.registered_outlets.push(OutletRegistration {
        outlet_id: SS_OUTLET.to_owned(),
        kind: OutletKind::Action,
        name: "Calculator".to_owned(),
        description: "adds".to_owned(),
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
        operator_did: DID("did:dht:z6MkStreamSagaOperator".to_owned()),
        cost: Some(OutletCost {
            amount: Amount::new(SS_COST),
            currency: "USD".to_owned(),
            payee: DID::from("did:key:stream-saga-payee"),
            cost_formula: None,
        }),
        message_catalog: Vec::new(),
        registered_at: 0,
        signature: Vec::new(),
    });
    st.governance
        .budget_tracker
        .grant(&ss_invoker(), Amount::new(SS_GRANTED));
    st.governance.economic_policy = Some(ss_policy());
    st
}

/// The outlet registry the driver reads for the pinned §5.4.5 verification
/// descriptor + validation schemas — a zero-cost registry registration is used
/// (the escrow/billing is driven by `params.cost_per_chunk`, and the operator
/// signature self-verifies against `params.operator_signer`).
fn ss_registry() -> OutletRegistry {
    use scp_protocol::context::roles::{ContextRoleState, default_ceiling};
    let mut role_state = ContextRoleState::new(
        hex::encode(SS_TARGET),
        &ss_invoker().0,
        default_ceiling(),
        vec![],
        &scp_clock::TestClock::new(SS_NOW),
    )
    .expect("role state");
    role_state.members.insert(ss_invoker().0);
    let caps = role_state
        .member_capabilities
        .entry(ss_invoker().0)
        .or_default();
    caps.insert(Capability::OutletCallAll);
    caps.insert(Capability::OutletRegister);
    let mut registry = OutletRegistry::new();
    register_outlet(
        &mut registry,
        &role_state,
        OutletRegistration {
            outlet_id: SS_OUTLET.to_owned(),
            kind: OutletKind::Action,
            name: "Calculator".to_owned(),
            description: "adds".to_owned(),
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
            operator_did: DID("did:dht:z6MkStreamSagaOperator".to_owned()),
            cost: None,
            message_catalog: Vec::new(),
            registered_at: 0,
            signature: Vec::new(),
        },
        &ss_invoker().0,
    )
    .expect("register streaming outlet");
    registry
}

/// `OpenStreamParams` (with a matching operator signer) targeting `SS_TARGET`,
/// plus the §7.3.8 invocation-caveat binding.
fn ss_stream_params(request_id: RequestId) -> (OpenStreamParams, InvocationCaveatBinding) {
    ss_stream_params_for(SS_TARGET, request_id)
}

/// `OpenStreamParams` (with a matching operator signer) targeting `target_id`,
/// plus the §7.3.8 invocation-caveat binding — the streaming sibling of the
/// same-context `open_outlet_stream` params, rebased onto `target_id` with a
/// positive `cost_per_chunk`.
fn ss_stream_params_for(
    target_id: [u8; 32],
    request_id: RequestId,
) -> (OpenStreamParams, InvocationCaveatBinding) {
    let mut caveats = InvocationCaveats::empty();
    caveats.amount_max_cumulative = Some(Amount::new(100_000));
    let caveats_jcs = caveats.to_canonical_json_bytes().expect("jcs");
    let caveats_binding = compute_caveats_binding(
        SS_UCAN_CID.as_bytes(),
        &request_id,
        &ss_invoker().0,
        SS_ESTIMATE,
        &caveats_jcs,
    );
    let identity = StreamIdentity {
        context_id: hex::encode(target_id),
        outlet_id: SS_OUTLET.to_owned(),
        stream_epoch: 1,
        caveats_binding,
    };
    let invoker_key = SigningKey::from_bytes(&[0x24; 32]);
    let invoker_pk = invoker_key.verifying_key();
    let operator_signer: Arc<dyn StreamSigner> = Arc::new(InProcessStreamSigner::new(invoker_key));
    let params = OpenStreamParams {
        identity,
        caps: AdmissionCaps {
            per_invoker: 100,
            per_origin_invoker: 100,
            per_outlet: 100,
        },
        invoker_did: ss_invoker().0,
        origin_invoker_did: ss_invoker().0,
        cost_per_chunk: Amount::new(SS_COST),
        available_balance: Amount::new(SS_GRANTED),
        reserved_escrow: Amount::new(0),
        declared_estimated_chunk_count: Some(SS_ESTIMATE),
        credit_window: 64,
        caveats: caveats.clone(),
        invoker_pk,
        operator_signer,
        stream_credit_stall_secs: 999,
        stream_cancel_ack_secs: 999,
        stream_ucan_recheck_secs: 999,
        ucan_cid: SS_UCAN_CID.to_owned(),
        request_id,
        revocation_checker: Arc::new(
            scp_protocol::crypto::ucan::validate::InMemoryRevocationChecker::new(),
        ),
        economic_policy_snapshot: Some(EconomicPolicySnapshot {
            policy: ss_policy(),
        }),
    };
    let binding = InvocationCaveatBinding {
        caveats,
        ucan_cid: SS_UCAN_CID.to_owned(),
    };
    (params, binding)
}

/// Spawn one context actor with `state` under a per-context owner DID.
async fn spawn_ss_actor(supervisor: &Arc<Supervisor>, owner: &str, state: PerContextState) {
    let deps = supervisor
        .build_actor_deps_loaded(&DID(owner.to_owned()))
        .await
        .expect("actor deps");
    supervisor
        .spawn_actor_with_state(state, deps, None)
        .await
        .expect("spawn actor");
}

async fn spawn_ss_pair(supervisor: &Arc<Supervisor>) {
    spawn_ss_actor(
        supervisor,
        "did:example:ss-caller-owner",
        ss_caller_state_for(SS_CALLER, SS_TARGET),
    )
    .await;
    spawn_ss_actor(
        supervisor,
        "did:example:ss-target-owner",
        ss_paid_target_state(SS_TARGET),
    )
    .await;
}

/// The latest journaled state for `saga_id` while it is unresolved, or `None`
/// once it has been resolved (Committed / Aborted) or was never journaled.
async fn ss_saga_state(journal: &Arc<dyn SagaJournal>, saga_id: &SagaId) -> Option<SagaState> {
    journal
        .load_unresolved()
        .await
        .expect("load_unresolved")
        .into_iter()
        .find(|e| &e.saga_id == saga_id)
        .map(|e| e.state)
}

/// Poll until the saga leaves the unresolved set (the off-mailbox seal resolved
/// it), or the deadline elapses.
async fn ss_await_resolved(journal: &Arc<dyn SagaJournal>, saga_id: &SagaId, budget: Duration) {
    let deadline = tokio::time::Instant::now() + budget;
    loop {
        if ss_saga_state(journal, saga_id).await.is_none() {
            return;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "saga {} was not resolved within {budget:?}",
            saga_id.0
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

async fn ss_remaining_budget(supervisor: &Arc<Supervisor>, ctx_hex: &str, did: &DID) -> Amount {
    let (tx, rx) = tokio::sync::oneshot::channel();
    supervisor
        .dispatch_query(QueriesCommand::RemainingBudgetForTest {
            context_id: ctx_hex.to_owned(),
            member_did: did.clone(),
            reply: tx,
        })
        .await
        .expect("dispatch RemainingBudgetForTest");
    rx.await.expect("budget reply").expect("budget ok")
}

/// Extract the hex `stream_manifest_hash` a recorded dual-log leaf payload
/// carries (both the target `OutletInvoked` and caller `CrossContextOutletInvoked`
/// leaves carry it under this key).
fn ss_leaf_manifest_hex(payload: &[u8]) -> String {
    let json: serde_json::Value = serde_json::from_slice(payload).expect("leaf payload JSON");
    json["stream_manifest_hash"]
        .as_str()
        .expect("stream_manifest_hash present")
        .to_owned()
}

/// COMMIT 1 — AC1 / AC6 / AC3 / AC5 share ONE 10-chunk paid streaming drive.
///
/// - AC1: the receiver yields chunk 0 BEFORE the terminal (returned promptly,
///   non-blocking).
/// - AC6: the journal reads `Committing` between first-recv and stream-close;
///   `Committed` (resolved) only after the terminal.
/// - AC3: the invoker's budget is debited by the FULL reserved escrow during
///   the pump (not yet refunded); at close the refund (`reserved − billed`) is
///   credited exactly once AND a billed `PaymentReceipt` is captured.
/// - AC5: the sealed `stream_manifest_hash == compute_chunk_manifest_root(all
///   forwarded chunks)` and is non-zero; the signed `SCP-XCTX-STREAM-RECEIPT-V1`
///   receipt verifies under B's Active Signing Key; BOTH the target
///   `OutletInvoked` and caller `CrossContextOutletInvoked` leaves are recorded
///   over the SAME root.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn xctx_streaming_saga_paid_drive_ac1_ac3_ac5_ac6() {
    let captured = Arc::new(AtomicUsize::new(0));
    let invoked = Arc::new(AtomicUsize::new(0));
    let storage = Arc::new(InMemoryStorage::new());
    let journal: Arc<dyn SagaJournal> =
        Arc::new(ProtocolRepositorySagaJournal::new(Arc::clone(&storage)));
    let recording = SsRecordingEventLog::default();
    let supervisor =
        build_ss_supervisor(&captured, Arc::clone(&journal), Box::new(recording.clone()));
    spawn_ss_pair(&supervisor).await;

    let registry = ss_registry();
    let (params, binding) = ss_stream_params([0x46; 16]);
    let executor = Arc::new(FiniteChunkExecutor {
        data_chunks: 10,
        invoked: Arc::clone(&invoked),
    });
    let target_signing = SigningKey::from_bytes(&[7u8; 32]);
    let caller_signing = SigningKey::from_bytes(&[8u8; 32]);
    let outlet_id: OutletId = SS_OUTLET.to_owned();

    let mut handle = supervisor
        .start_cross_context_streaming_outlet_invocation_saga(
            SS_CALLER,
            SS_TARGET,
            ss_invoker(),
            SS_OUTLET.to_owned(),
            None,
            &registry,
            &outlet_id,
            serde_json::json!({ "a": 1, "b": 2 }),
            1,
            [0x99u8; 16],
            SS_NOW.saturating_mul(1000),
            Some(5_000),
            executor,
            Some(binding),
            SagaSigners {
                target: CommandSigner::local_ed25519(target_signing.clone()),
                caller: CommandSigner::local_ed25519(caller_signing.clone()),
            },
            params,
        )
        .await
        .expect("the paid streaming saga starts and returns a handle promptly");

    let saga_id = handle.saga_id.clone();
    let target_hex = hex::encode(SS_TARGET);

    // AC1 — the receiver yields chunk 0 before the stream terminates.
    let first = tokio::time::timeout(Duration::from_secs(5), handle.receiver.recv())
        .await
        .expect("first forwarded frame within 5s")
        .expect("first forwarded frame present");
    assert!(
        matches!(first.payload, ChunkPayload::Data { .. }),
        "AC1: the Commit-transition returns the receiver and it yields a Data chunk while \
             the stream is still producing (before any terminal)"
    );
    let mut chunks = vec![first.clone()];

    // AC6 (mid) — the FSM is Committing (sealing), NOT yet Committed.
    assert_eq!(
        ss_saga_state(&journal, &saga_id).await,
        Some(SagaState::Committing),
        "AC6: the journal is Committing between the Commit-transition and stream-close"
    );

    // AC3 (mid) — the escrow is RESERVED during the pump (not released at the
    // Commit-transition).
    let during = ss_remaining_budget(&supervisor, &target_hex, &ss_invoker()).await;
    assert_eq!(
        during,
        Amount::new(SS_GRANTED - SS_RESERVED),
        "AC3: the invoker's budget is debited by the full reserved escrow \
             (cost_per_chunk × estimate) during the pump — not refunded at Commit"
    );

    // Drain the remaining forwarded frames to the terminal End, collecting the
    // full chunk sequence the seal folds into its durable frontier.
    let mut saw_end = false;
    while let Some(frame) = tokio::time::timeout(Duration::from_secs(5), handle.receiver.recv())
        .await
        .expect("forwarded frame within 5s")
    {
        let is_end = matches!(frame.payload, ChunkPayload::End { .. });
        let is_terminal = is_end || matches!(frame.payload, ChunkPayload::Error { .. });
        chunks.push(frame.clone());
        if is_end {
            saw_end = true;
        }
        if is_terminal {
            break;
        }
    }
    assert!(
        saw_end,
        "the paid stream closes with a clean terminal End (no synthesized fault)"
    );
    assert_eq!(
        chunks.len(),
        11,
        "10 Data chunks + 1 terminal End are forwarded to the caller"
    );

    // The off-mailbox seal resolves the journal at stream-close.
    ss_await_resolved(&journal, &saga_id, Duration::from_secs(5)).await;

    // AC6 (post) — Committed (resolved) is reached ONLY at close.
    assert_eq!(
        ss_saga_state(&journal, &saga_id).await,
        None,
        "AC6: the Committed terminal is reached at stream-close (resolved), not at Commit"
    );

    let actor = supervisor
        .lookup(&target_hex)
        .expect("target actor resident");

    // The seal durably captured the streaming witness (sealed = Committed).
    let witness = {
        let sid = saga_id.clone();
        let status = actor
            .send(move |reply| {
                ContextCommand::SagaPhase(SagaPhaseMessage::StreamSettleCheckWitness {
                    saga_id: sid,
                    reply,
                })
            })
            .await
            .expect("witness check");
        !matches!(
            status,
            crate::context::actor::commands::StreamWitnessRecoveryStatus::Absent
        )
    };
    assert!(witness, "the seal durably captured the streaming witness");

    // AC5 — a replayed CommitBStreamSettle re-emits the STORED signed receipt
    // verbatim (settlement None — no double-move), giving the test the sealed
    // receipt bytes to verify.
    let outcome = {
        let sid = saga_id.clone();
        let target_key_signer = CommandSigner::local_ed25519(target_signing.clone());
        actor
            .send(move |reply| {
                ContextCommand::SagaPhase(SagaPhaseMessage::CommitBStreamSettle {
                    saga_id: sid,
                    terminal_status:
                        scp_protocol::context::outlets::stream::StreamTerminalStatus::Ok,
                    cancel_ack_seq: None,
                    target_signer: target_key_signer,
                    reply,
                })
            })
            .await
            .expect("replayed seal returns the stored receipt")
    };
    assert!(
        outcome.settlement.is_none(),
        "a replayed seal must not re-move money (settlement None)"
    );
    let expected_root = compute_chunk_manifest_root(&chunks).expect("manifest root");
    assert_ne!(
        expected_root, [0u8; 32],
        "AC5: the sealed manifest root is non-zero"
    );
    assert_eq!(
        outcome.stream_manifest_hash, expected_root,
        "AC5: the sealed root == RFC-6962 manifest over ALL forwarded chunks"
    );
    assert_eq!(
        outcome.billed_count, 10,
        "the 10 Data chunks are the billable-chunk count sealed at close"
    );
    let receipt: CrossContextOutletStreamReceipt =
        serde_json::from_slice(&outcome.receipt).expect("receipt JCS parses");
    assert_eq!(
        receipt.stream_manifest_hash, expected_root,
        "AC5: the receipt carries the sealed manifest root"
    );
    receipt.verify(&target_signing.verifying_key()).expect(
        "AC5: the SCP-XCTX-STREAM-RECEIPT-V1 receipt verifies under B's Active Signing Key",
    );

    // AC5 — the atomic dual event-log: BOTH B-side OutletInvoked (target) and
    // A-side CrossContextOutletInvoked (caller), over the SAME sealed root.
    let events = recording.snapshot();
    let b_leaf = events
        .iter()
        .find(|(ctx, et, ..)| *ctx == SS_TARGET && *et == scp_event_log::EventType::OutletInvoked)
        .expect("AC5: the B-side OutletInvoked leaf is recorded (target)");
    let a_leaf = events
        .iter()
        .find(|(ctx, et, ..)| {
            *ctx == SS_CALLER && *et == scp_event_log::EventType::CrossContextOutletInvoked
        })
        .expect("AC5: the A-side CrossContextOutletInvoked leaf is recorded (caller)");
    let root_hex = hex::encode(expected_root);
    assert_eq!(
        ss_leaf_manifest_hex(&b_leaf.3),
        root_hex,
        "AC5: the B-side leaf carries the sealed root"
    );
    assert_eq!(
        ss_leaf_manifest_hex(&a_leaf.3),
        root_hex,
        "AC5: the A-side leaf carries the SAME sealed root (atomic dual-log join)"
    );

    // AC3 (post) — the escrow settles at close: refund (reserved − billed)
    // credited so only `billed` remains spent, and exactly one billed
    // PaymentReceipt is captured.
    let after = ss_remaining_budget(&supervisor, &target_hex, &ss_invoker()).await;
    assert_eq!(
        after,
        Amount::new(SS_GRANTED - SS_COST * 10),
        "AC3: at seal-close the escrow settles — the (reserved − billed) refund is credited"
    );
    assert!(
        after.value() > during.value(),
        "AC3: the refund is credited only at close, not at the Commit-transition"
    );
    assert_eq!(
        captured.load(Ordering::SeqCst),
        1,
        "AC3: exactly one billed PaymentReceipt is captured (real close-time settlement)"
    );

    drop(invoked);
}

/// ADR-049 Decision 16 — a same-context streaming open started after
/// shutdown has begun returns
/// `OutletStreamOpenError::SupervisorShutDown`, not the retryable transport
/// rate limit, and debits nothing. The open-gate case is
/// `open_outlet_stream_reserve_pump_settle_end_to_end`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn open_outlet_stream_refused_by_shutdown_is_typed_and_debits_nothing() {
    let captured = Arc::new(AtomicUsize::new(0));
    let invoked = Arc::new(AtomicUsize::new(0));
    let storage = Arc::new(InMemoryStorage::new());
    let journal: Arc<dyn SagaJournal> =
        Arc::new(ProtocolRepositorySagaJournal::new(Arc::clone(&storage)));
    let supervisor =
        build_ss_supervisor(&captured, journal, Box::new(SsRecordingEventLog::default()));
    spawn_ss_pair(&supervisor).await;

    let registry = ss_registry();
    let (params, binding) = ss_stream_params([0x48; 16]);
    let executor = Arc::new(FiniteChunkExecutor {
        data_chunks: 10,
        invoked: Arc::clone(&invoked),
    });
    let outlet_id: OutletId = SS_OUTLET.to_owned();
    let target_hex = hex::encode(SS_TARGET);

    supervisor.close_spawn_gate();

    let result = supervisor
        .open_outlet_stream(
            &target_hex,
            &registry,
            &outlet_id,
            serde_json::json!({ "a": 1, "b": 2 }),
            &ss_invoker(),
            Some(5_000),
            executor,
            None,
            None,
            None,
            Some(binding),
            params,
        )
        .await;
    assert!(
        matches!(
            result,
            Err(crate::context::outlets::invoke::OutletStreamOpenError::SupervisorShutDown { .. })
        ),
        "an open after shutdown began must return SupervisorShutDown"
    );
    assert_eq!(
        ss_remaining_budget(&supervisor, &target_hex, &ss_invoker()).await,
        Amount::new(SS_GRANTED),
        "a refused open debits no escrow"
    );
    assert_eq!(
        invoked.load(Ordering::SeqCst),
        0,
        "a refused open never runs the executor"
    );
}

/// ADR-049 Decision 16 item 2 — `open_outlet_stream_with_spawner` has no
/// shutdown refusal point of its own: given a spawner taken before the
/// closed flag was set, it opens the stream after the flag is set.
/// `open_outlet_stream_refused_by_shutdown_is_typed_and_debits_nothing`
/// covers the refusal at `open_outlet_stream`'s own spawner check.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn open_outlet_stream_with_spawner_taken_before_close_opens_after_close() {
    let captured = Arc::new(AtomicUsize::new(0));
    let invoked = Arc::new(AtomicUsize::new(0));
    let storage = Arc::new(InMemoryStorage::new());
    let journal: Arc<dyn SagaJournal> =
        Arc::new(ProtocolRepositorySagaJournal::new(Arc::clone(&storage)));
    let supervisor =
        build_ss_supervisor(&captured, journal, Box::new(SsRecordingEventLog::default()));
    spawn_ss_pair(&supervisor).await;

    let registry = ss_registry();
    let (params, binding) = ss_stream_params([0x49; 16]);
    let executor = Arc::new(FiniteChunkExecutor {
        data_chunks: 10,
        invoked: Arc::clone(&invoked),
    });
    let outlet_id: OutletId = SS_OUTLET.to_owned();
    let target_hex = hex::encode(SS_TARGET);

    let spawner = supervisor
        .tracked_spawner("operation begun before close")
        .expect("an open gate issues a spawner");
    supervisor.close_spawn_gate();

    let result = supervisor
        .open_outlet_stream_with_spawner(
            &spawner,
            &target_hex,
            &registry,
            &outlet_id,
            serde_json::json!({ "a": 1, "b": 2 }),
            &ss_invoker(),
            Some(5_000),
            executor,
            None,
            None,
            None,
            Some(binding),
            params,
        )
        .await;
    assert!(
        result.is_ok(),
        "an open through a spawner taken before close is not refused: {:?}",
        result.as_ref().err()
    );
}

/// ADR-049 Decision 16 — a streaming saga started after shutdown has begun
/// is refused before it debits any escrow or stages any saga. The
/// open-gate case is `xctx_streaming_saga_paid_drive_ac1_ac3_ac5_ac6`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn xctx_streaming_saga_refused_by_shutdown_debits_nothing() {
    let captured = Arc::new(AtomicUsize::new(0));
    let invoked = Arc::new(AtomicUsize::new(0));
    let storage = Arc::new(InMemoryStorage::new());
    let journal: Arc<dyn SagaJournal> =
        Arc::new(ProtocolRepositorySagaJournal::new(Arc::clone(&storage)));
    let recording = SsRecordingEventLog::default();
    let supervisor =
        build_ss_supervisor(&captured, Arc::clone(&journal), Box::new(recording.clone()));
    spawn_ss_pair(&supervisor).await;

    let registry = ss_registry();
    let (params, binding) = ss_stream_params([0x47; 16]);
    let executor = Arc::new(FiniteChunkExecutor {
        data_chunks: 10,
        invoked: Arc::clone(&invoked),
    });
    let target_signing = SigningKey::from_bytes(&[7u8; 32]);
    let caller_signing = SigningKey::from_bytes(&[8u8; 32]);
    let outlet_id: OutletId = SS_OUTLET.to_owned();

    supervisor.close_spawn_gate();

    let result = supervisor
        .start_cross_context_streaming_outlet_invocation_saga(
            SS_CALLER,
            SS_TARGET,
            ss_invoker(),
            SS_OUTLET.to_owned(),
            None,
            &registry,
            &outlet_id,
            serde_json::json!({ "a": 1, "b": 2 }),
            1,
            [0x9au8; 16],
            SS_NOW.saturating_mul(1000),
            Some(5_000),
            executor,
            Some(binding),
            SagaSigners {
                target: CommandSigner::local_ed25519(target_signing.clone()),
                caller: CommandSigner::local_ed25519(caller_signing.clone()),
            },
            params,
        )
        .await;
    let Err(SagaError::SupervisorShutDown { message }) = result else {
        panic!("a streaming saga started after shutdown began must fail with SupervisorShutDown");
    };
    assert!(
        message.contains("start cross-context streaming saga refused"),
        "the refusal names the saga: {message}"
    );
    let rendered = SagaError::SupervisorShutDown {
        message: message.clone(),
    }
    .to_string();
    assert_eq!(
        rendered.matches("SCP-CTX-2138").count(),
        1,
        "the code appears once in the rendered error: {rendered}"
    );
    assert!(
        !message.contains("SCP-CTX-2138"),
        "the message carries the detail, not the code: {message}"
    );

    let target_hex = hex::encode(SS_TARGET);
    assert_eq!(
        ss_remaining_budget(&supervisor, &target_hex, &ss_invoker()).await,
        Amount::new(SS_GRANTED),
        "a refused saga debits no escrow"
    );
    assert_eq!(
        invoked.load(Ordering::SeqCst),
        0,
        "a refused saga never runs the executor"
    );
    assert!(
        journal
            .load_unresolved()
            .await
            .expect("load_unresolved")
            .is_empty(),
        "a refused saga stages nothing"
    );
}

/// A rejection by shutdown at either step of a streaming saga's B-side open
/// (the Phase-1 escrow reserve and the Phase-2 stream open) keeps
/// `SCP-CTX-2138` as `SagaError::SupervisorShutDown`; any other rejection
/// at either step aborts the saga with `SCP-SAGA-13067`.
#[test]
fn streaming_saga_open_shutdown_rejection_keeps_supervisor_shut_down() {
    use crate::context::outlets::dispatch::OpenStreamRejection;
    use crate::context::outlets::invoke::OutletStreamOpenError;
    use crate::context::supervisor::supervisor::{
        StreamingSagaOpenStep, stream_open_rejection_to_saga_error,
    };

    for (step, named) in [
        (StreamingSagaOpenStep::EscrowReserve, "escrow reserve"),
        (StreamingSagaOpenStep::StreamOpen, "stream open"),
    ] {
        let shut = stream_open_rejection_to_saga_error(
            &OutletStreamOpenError::SupervisorShutDown {
                message: "refused".to_owned(),
            },
            step,
        );
        let SagaError::SupervisorShutDown { message } = &shut else {
            panic!("a shutdown rejection at {step:?} must map to SupervisorShutDown, got {shut:?}");
        };
        assert!(
            message.contains(named),
            "the refusal names the step: {message}"
        );
        assert!(
            shut.to_string().starts_with("SCP-CTX-2138"),
            "{step:?}: {shut}"
        );

        let other = stream_open_rejection_to_saga_error(
            &OutletStreamOpenError::Rejected(OpenStreamRejection::ContextNotActive {
                current_state: "Closing".to_owned(),
            }),
            step,
        );
        assert!(
            matches!(
                other,
                SagaError::Aborted {
                    reason: SagaAbortReason::Rejected,
                    code: 13067,
                    ..
                }
            ),
            "a non-shutdown rejection at {step:?} aborts with 13067, got {other:?}"
        );
    }
}

/// #2196 — a non-active (Closing) TARGET context rejects the cross-context
/// streaming saga at the B-side escrow reserve, BEFORE any escrow debit and
/// BEFORE the seal task spawns. The runtime `ensure_context_active` gate
/// (added to `reserve_outlet_stream_economy`, which the saga runs on the
/// TARGET) is authoritative — no FFI bridge guard is in the loop at the
/// runtime layer, and no earlier saga gate checks lifecycle state (the
/// interface + context-set gates pass for an established, live target).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn xctx_streaming_saga_closing_target_rejected_before_debit_and_seal() {
    let captured = Arc::new(AtomicUsize::new(0));
    let invoked = Arc::new(AtomicUsize::new(0));
    let storage = Arc::new(InMemoryStorage::new());
    let journal: Arc<dyn SagaJournal> =
        Arc::new(ProtocolRepositorySagaJournal::new(Arc::clone(&storage)));
    let recording = SsRecordingEventLog::default();
    let supervisor =
        build_ss_supervisor(&captured, Arc::clone(&journal), Box::new(recording.clone()));

    // Caller Active; TARGET transitioned Active → Closing before spawn. Its
    // actor stays alive, so the interface + membership gates still pass and the
    // active-state reserve gate is the barrier under test.
    spawn_ss_actor(
        &supervisor,
        "did:example:ss-caller-owner",
        ss_caller_state_for(SS_CALLER, SS_TARGET),
    )
    .await;
    let target_state = ss_paid_target_state(SS_TARGET);
    target_state
        .handle
        .transition_to(&ContextState::Closing)
        .expect("Active → Closing");
    spawn_ss_actor(&supervisor, "did:example:ss-target-owner", target_state).await;

    let registry = ss_registry();
    let (params, binding) = ss_stream_params([0x46; 16]);
    let executor = Arc::new(FiniteChunkExecutor {
        data_chunks: 10,
        invoked: Arc::clone(&invoked),
    });
    let target_signing = SigningKey::from_bytes(&[7u8; 32]);
    let caller_signing = SigningKey::from_bytes(&[8u8; 32]);
    let outlet_id: OutletId = SS_OUTLET.to_owned();

    let Err(err) = supervisor
        .start_cross_context_streaming_outlet_invocation_saga(
            SS_CALLER,
            SS_TARGET,
            ss_invoker(),
            SS_OUTLET.to_owned(),
            None,
            &registry,
            &outlet_id,
            serde_json::json!({ "a": 1, "b": 2 }),
            1,
            [0x99u8; 16],
            SS_NOW.saturating_mul(1000),
            Some(5_000),
            executor,
            Some(binding),
            SagaSigners {
                target: CommandSigner::local_ed25519(target_signing.clone()),
                caller: CommandSigner::local_ed25519(caller_signing.clone()),
            },
            params,
        )
        .await
    else {
        panic!("a Closing target must reject the streaming saga at the B-side reserve");
    };

    match &err {
        SagaError::Aborted {
            reason,
            code,
            message,
        } => {
            assert_eq!(*code, 13067, "a B-side reserve rejection aborts with 13067");
            assert!(
                matches!(reason, SagaAbortReason::Rejected),
                "a context-not-active reject is a PERMANENT rejection, not retryable: {reason:?}"
            );
            assert!(
                message.contains("not in Active state") && message.contains("Closing"),
                "the abort surfaces the context-not-active reserve rejection naming the \
                     state (the typed OutletContextNotActive carrier flowed through \
                     reserve_error_to_open_rejection → OpenStreamRejection::ContextNotActive → \
                     to_open_error, preserving current_state for an authorized interface \
                     peer): {message}"
            );
        }
        other => panic!("expected SagaError::Aborted, got {other:?}"),
    }

    // No escrow was debited on the target — the gate fired before the debit.
    assert_eq!(
        ss_remaining_budget(&supervisor, &hex::encode(SS_TARGET), &ss_invoker()).await,
        Amount::new(SS_GRANTED),
        "the invoker's target budget is untouched — the reserve gate fired before any debit"
    );
    // The outlet executor was never invoked and the saga was resolved Aborted
    // (never Committing), so no off-mailbox seal task was spawned.
    assert_eq!(
        invoked.load(Ordering::SeqCst),
        0,
        "no executor invocation on a rejected open"
    );
    assert!(
        journal
            .load_unresolved()
            .await
            .expect("load_unresolved")
            .is_empty(),
        "the rejected saga is resolved Aborted — no Committing entry survives, so no seal \
             task was spawned"
    );

    drop(invoked);
}

/// #2196 — a SAME-context stream OPEN (SCP-OUT-037 path,
/// `Supervisor::open_outlet_stream`) against a Closing context is rejected
/// with `OpenStreamRejection::ContextNotActive` — Protocol class,
/// `SCP-OUTLET-6101`, NON-retryable — at the runtime reserve gate, debiting
/// no escrow and never invoking the executor. No FFI bridge guard exists for
/// this path at either layer historically, so the runtime gate is the sole
/// barrier.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn same_context_stream_open_gated_on_closing_context() {
    use crate::context::outlets::dispatch::OpenStreamRejection;
    use scp_protocol::context::outlets::error_codes;
    use scp_protocol::context::outlets::errors::RetryPolicy;

    let captured = Arc::new(AtomicUsize::new(0));
    let invoked = Arc::new(AtomicUsize::new(0));
    let storage = Arc::new(InMemoryStorage::new());
    let journal: Arc<dyn SagaJournal> =
        Arc::new(ProtocolRepositorySagaJournal::new(Arc::clone(&storage)));
    let supervisor = build_ss_supervisor(
        &captured,
        Arc::clone(&journal),
        Box::new(SsRecordingEventLog::default()),
    );

    // One context, transitioned Active → Closing before spawn.
    let ctx_state = ss_paid_target_state(SS_TARGET);
    ctx_state
        .handle
        .transition_to(&ContextState::Closing)
        .expect("Active → Closing");
    spawn_ss_actor(&supervisor, "did:example:ss-target-owner", ctx_state).await;

    let registry = ss_registry();
    let (params, binding) = ss_stream_params([0x37; 16]);
    let executor = Arc::new(FiniteChunkExecutor {
        data_chunks: 5,
        invoked: Arc::clone(&invoked),
    });
    let outlet_id: OutletId = SS_OUTLET.to_owned();
    let target_hex = hex::encode(SS_TARGET);

    let Err(crate::context::outlets::invoke::OutletStreamOpenError::Rejected(err)) = supervisor
        .open_outlet_stream(
            &target_hex,
            &registry,
            &outlet_id,
            serde_json::json!({ "a": 1, "b": 2 }),
            &ss_invoker(),
            Some(5_000),
            executor,
            None,
            None,
            None,
            Some(binding),
            params,
        )
        .await
    else {
        panic!("a Closing context must reject a same-context stream open with a rejection");
    };

    match &err {
        OpenStreamRejection::ContextNotActive { current_state } => {
            assert!(
                current_state.contains("Closing"),
                "the rejection names the lifecycle state: {current_state}"
            );
        }
        other => panic!("expected OpenStreamRejection::ContextNotActive, got {other:?}"),
    }
    assert_eq!(
        err.error_code(),
        error_codes::CODE_PROTOCOL_SESSION,
        "#2196 maps the same-context open reject to the Protocol class (SCP-OUTLET-6101)"
    );
    assert_eq!(
        error_codes::error_code_to_retry_policy(err.error_code()),
        Some(RetryPolicy::Never),
        "a same-context open reject on a Closing context is NON-retryable"
    );
    assert_eq!(
        ss_remaining_budget(&supervisor, &target_hex, &ss_invoker()).await,
        Amount::new(SS_GRANTED),
        "no escrow debited on a rejected same-context open"
    );
    assert_eq!(
        invoked.load(Ordering::SeqCst),
        0,
        "the executor is never invoked on a rejected open"
    );
    drop(invoked);
}

/// COMMIT 2 — AC7: mid-stream crash seals the durable prefix and closes
/// truncated, never re-invoking the outlet.
///
/// The executor emits 5 `Data` chunks then wedges (no terminal), modelling a
/// crash: the off-mailbox seal forwards + durably captures the prefix, then
/// blocks — the journal stays `Committing` and no seal witness is written.
///
/// - KEYLESS path (`replay_unresolved_sagas`): witness absent ⇒ the autonomous
///   sweep marks the saga `NeedsRepair` and HOLDS the escrow (the runtime has no
///   signing key to seal a truncated prefix).
/// - KEY-BEARING path (`recover_streaming_saga_truncated_close`): given B's
///   Active Signing Key it seals the RESTORED durable prefix — the receipt root
///   is the manifest over the sealed prefix (NOT the full stream), the escrow
///   settles at the prefix `billed_count`, and the outlet exec fn is invoked
///   EXACTLY once (no re-invoke on the replayed close).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn xctx_streaming_saga_truncated_close_ac7() {
    let captured = Arc::new(AtomicUsize::new(0));
    let invoked = Arc::new(AtomicUsize::new(0));
    let storage = Arc::new(InMemoryStorage::new());
    let journal: Arc<dyn SagaJournal> =
        Arc::new(ProtocolRepositorySagaJournal::new(Arc::clone(&storage)));
    let recording = SsRecordingEventLog::default();
    let supervisor =
        build_ss_supervisor(&captured, Arc::clone(&journal), Box::new(recording.clone()));
    spawn_ss_pair(&supervisor).await;

    let registry = ss_registry();
    let (params, binding) = ss_stream_params([0x47; 16]);
    let executor = Arc::new(PrefixThenBlockExecutor {
        data_chunks: 5,
        invoked: Arc::clone(&invoked),
    });
    let target_signing = SigningKey::from_bytes(&[7u8; 32]);
    let caller_signing = SigningKey::from_bytes(&[8u8; 32]);
    let outlet_id: OutletId = SS_OUTLET.to_owned();

    let mut handle = supervisor
        .start_cross_context_streaming_outlet_invocation_saga(
            SS_CALLER,
            SS_TARGET,
            ss_invoker(),
            SS_OUTLET.to_owned(),
            None,
            &registry,
            &outlet_id,
            serde_json::json!({ "a": 1, "b": 2 }),
            1,
            [0xA7u8; 16],
            SS_NOW.saturating_mul(1000),
            Some(5_000),
            executor,
            Some(binding),
            SagaSigners {
                target: CommandSigner::local_ed25519(target_signing.clone()),
                caller: CommandSigner::local_ed25519(caller_signing.clone()),
            },
            params,
        )
        .await
        .expect("the paid streaming saga starts");

    let saga_id = handle.saga_id.clone();
    let target_hex = hex::encode(SS_TARGET);
    let actor = supervisor
        .lookup(&target_hex)
        .expect("target actor resident");

    // Drain the forwarded prefix. The executor emits 5 Data chunks then wedges,
    // so the 6th recv times out — the seal has forwarded + captured the prefix
    // and is blocked (no terminal).
    let mut received: Vec<_> = Vec::new();
    while let Ok(Some(frame)) =
        tokio::time::timeout(Duration::from_secs(1), handle.receiver.recv()).await
    {
        assert!(
            matches!(frame.payload, ChunkPayload::Data { .. }),
            "the wedged executor emits only Data chunks (no terminal)"
        );
        received.push(frame.clone());
    }
    assert_eq!(
        received.len(),
        5,
        "the executor forwarded exactly its 5-chunk prefix before wedging"
    );

    // Settle barrier: force a few B-actor mailbox round-trips so any in-flight
    // durable StreamCaptureAppend for the last forwarded chunk lands before we
    // recover (the fold is FIFO on the same mailbox the roundtrip uses).
    for _ in 0..25 {
        let sid = saga_id.clone();
        let _ = actor
            .send(move |reply| {
                ContextCommand::SagaPhase(SagaPhaseMessage::StreamSettleCheckWitness {
                    saga_id: sid,
                    reply,
                })
            })
            .await;
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    // The journal is still Committing (the wedged seal never sealed) and no
    // witness exists yet.
    assert_eq!(
        ss_saga_state(&journal, &saga_id).await,
        Some(SagaState::Committing),
        "a wedged seal leaves the journal Committing (no seal-close)"
    );
    let witness_before = {
        let sid = saga_id.clone();
        let status = actor
            .send(move |reply| {
                ContextCommand::SagaPhase(SagaPhaseMessage::StreamSettleCheckWitness {
                    saga_id: sid,
                    reply,
                })
            })
            .await
            .expect("witness check");
        !matches!(
            status,
            crate::context::actor::commands::StreamWitnessRecoveryStatus::Absent
        )
    };
    assert!(
        !witness_before,
        "no seal witness before recovery (truncated)"
    );

    // The escrow is HELD during the crash window (reserved, not settled).
    let held = ss_remaining_budget(&supervisor, &target_hex, &ss_invoker()).await;
    assert_eq!(
        held,
        Amount::new(SS_GRANTED - SS_RESERVED),
        "the escrow reservation is HELD across the crash (not auto-refunded)"
    );

    // KEYLESS recovery — the autonomous sweep finds the Committing streaming
    // entry, sees the witness absent, and marks NeedsRepair (escrow HELD; the
    // runtime holds no signing key to seal the prefix).
    supervisor
        .replay_unresolved_sagas(&super::RestoredContexts::new(Vec::new()))
        .await
        .expect("keyless recovery sweep runs");
    assert_eq!(
        ss_saga_state(&journal, &saga_id).await,
        Some(SagaState::NeedsRepair),
        "AC7 (keyless): witness-absent truncated saga is marked NeedsRepair"
    );
    assert_eq!(
        ss_remaining_budget(&supervisor, &target_hex, &ss_invoker()).await,
        Amount::new(SS_GRANTED - SS_RESERVED),
        "AC7 (keyless): the escrow is HELD for the key-bearing close (never auto-voided)"
    );
    assert_eq!(
        invoked.load(Ordering::SeqCst),
        1,
        "keyless recovery never re-invokes the outlet"
    );

    // KEY-BEARING recovery — seal the RESTORED durable prefix with B's Active
    // Signing Key. NEVER re-opens the stream / re-invokes the executor.
    supervisor
        .recover_streaming_saga_truncated_close(
            saga_id.clone(),
            SS_TARGET,
            CommandSigner::local_ed25519(target_signing.clone()),
        )
        .await
        .expect("AC7 (key-bearing): the truncated close seals the durable prefix");

    assert_eq!(
        invoked.load(Ordering::SeqCst),
        1,
        "AC7: the outlet exec fn is invoked EXACTLY once — the truncated close \
             re-emits the sealed prefix, it does NOT re-invoke"
    );

    // The witness is now present and the journal resolved.
    let witness_after = {
        let sid = saga_id.clone();
        let status = actor
            .send(move |reply| {
                ContextCommand::SagaPhase(SagaPhaseMessage::StreamSettleCheckWitness {
                    saga_id: sid,
                    reply,
                })
            })
            .await
            .expect("witness check");
        !matches!(
            status,
            crate::context::actor::commands::StreamWitnessRecoveryStatus::Absent
        )
    };
    assert!(
        witness_after,
        "the key-bearing close durably sealed the prefix"
    );
    assert_eq!(
        ss_saga_state(&journal, &saga_id).await,
        None,
        "the key-bearing close resolves the saga (Committed)"
    );

    // Fetch the sealed receipt via a replayed CommitBStreamSettle and verify it
    // attests the manifest over the durable PREFIX (never the full stream).
    let outcome = {
        let sid = saga_id.clone();
        let target_key_signer = CommandSigner::local_ed25519(target_signing.clone());
        actor
            .send(move |reply| {
                ContextCommand::SagaPhase(SagaPhaseMessage::CommitBStreamSettle {
                    saga_id: sid,
                    terminal_status:
                        scp_protocol::context::outlets::stream::StreamTerminalStatus::Error(
                            "replay".to_owned(),
                        ),
                    cancel_ack_seq: None,
                    target_signer: target_key_signer,
                    reply,
                })
            })
            .await
            .expect("replayed truncated close returns the stored receipt")
    };
    assert!(
        outcome.settlement.is_none(),
        "a replayed truncated close must not re-move money"
    );
    let k = outcome.billed_count as usize;
    assert!(
        (1..=5).contains(&k),
        "the sealed prefix bills a strict, non-empty subset of the 5-chunk prefix (got {k})"
    );
    let prefix_root = compute_chunk_manifest_root(&received[..k]).expect("prefix manifest root");
    assert_ne!(
        prefix_root, [0u8; 32],
        "AC7: the truncated manifest root is non-zero"
    );
    assert_eq!(
        outcome.stream_manifest_hash, prefix_root,
        "AC7: the truncated-close receipt root == manifest over the sealed durable PREFIX"
    );
    let receipt: CrossContextOutletStreamReceipt =
        serde_json::from_slice(&outcome.receipt).expect("receipt JCS parses");
    receipt
        .verify(&target_signing.verifying_key())
        .expect("AC7: the truncated-close receipt verifies under B's Active Signing Key");

    // The escrow settled at the prefix billed_count (refund credited).
    assert_eq!(
        ss_remaining_budget(&supervisor, &target_hex, &ss_invoker()).await,
        Amount::new(SS_GRANTED - SS_COST * k as u64),
        "AC7: the escrow settles at the prefix billed_count (refund = reserved − billed)"
    );

    drop(recording);
}

/// SCP-OUT-046 CRITICAL — the settlement-atomicity gap AC7 misses: a crash /
/// eviction AFTER the durable witness is inserted (seal-close landed) but
/// BEFORE the off-mailbox money move runs. The witness signals "sealed", but
/// the escrow refund + §7.3.8 counter release never happened. Keyless crash
/// recovery MUST complete the settlement (money ops need no signing key) and
/// the money must move EXACTLY once — a second recovery is a no-op.
///
/// Reproduces the window precisely: drive a prefix, then dispatch
/// `CommitBStreamSettle` DIRECTLY to the target actor (the seal HANDLER inserts
/// the `settled = false` witness + returns the settlement) WITHOUT applying the
/// settlement — exactly the state the off-mailbox seal task leaves if it dies
/// between the seal handler's reply and `settle_outlet_stream_via_actor`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn xctx_streaming_crash_after_witness_before_settle_recovers_exactly_once() {
    use crate::context::actor::commands::StreamSettleApplication;

    let captured = Arc::new(AtomicUsize::new(0));
    let invoked = Arc::new(AtomicUsize::new(0));
    let storage = Arc::new(InMemoryStorage::new());
    let journal: Arc<dyn SagaJournal> =
        Arc::new(ProtocolRepositorySagaJournal::new(Arc::clone(&storage)));
    let recording = SsRecordingEventLog::default();
    let supervisor =
        build_ss_supervisor(&captured, Arc::clone(&journal), Box::new(recording.clone()));
    spawn_ss_pair(&supervisor).await;

    let registry = ss_registry();
    let (params, binding) = ss_stream_params([0x46; 16]);
    let executor = Arc::new(PrefixThenBlockExecutor {
        data_chunks: 5,
        invoked: Arc::clone(&invoked),
    });
    let target_signing = SigningKey::from_bytes(&[7u8; 32]);
    let caller_signing = SigningKey::from_bytes(&[8u8; 32]);
    let outlet_id: OutletId = SS_OUTLET.to_owned();

    let mut handle = supervisor
        .start_cross_context_streaming_outlet_invocation_saga(
            SS_CALLER,
            SS_TARGET,
            ss_invoker(),
            SS_OUTLET.to_owned(),
            None,
            &registry,
            &outlet_id,
            serde_json::json!({ "a": 1, "b": 2 }),
            1,
            [0x46u8; 16],
            SS_NOW.saturating_mul(1000),
            Some(5_000),
            executor,
            Some(binding),
            SagaSigners {
                target: CommandSigner::local_ed25519(target_signing.clone()),
                caller: CommandSigner::local_ed25519(caller_signing.clone()),
            },
            params,
        )
        .await
        .expect("the paid streaming saga starts");

    let saga_id = handle.saga_id.clone();
    let target_hex = hex::encode(SS_TARGET);
    let actor = supervisor
        .lookup(&target_hex)
        .expect("target actor resident");

    // Drain the 5-chunk prefix (the executor wedges before a terminal).
    let mut received: Vec<_> = Vec::new();
    while let Ok(Some(frame)) =
        tokio::time::timeout(Duration::from_secs(1), handle.receiver.recv()).await
    {
        received.push(frame.clone());
    }
    assert_eq!(received.len(), 5, "the 5-chunk prefix forwarded");

    // Settle barrier — force the in-flight durable StreamCaptureAppend folds to
    // land before we seal (same FIFO mailbox).
    for _ in 0..25 {
        let sid = saga_id.clone();
        let _ = actor
            .send(move |reply| {
                ContextCommand::SagaPhase(SagaPhaseMessage::StreamSettleCheckWitness {
                    saga_id: sid,
                    reply,
                })
            })
            .await;
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    // Simulate the crash window: dispatch the seal HANDLER directly so the
    // witness is inserted (settled=false) and the settlement is returned — but
    // DO NOT apply it (the seal task "died" before settle_outlet_stream_via_actor).
    let outcome = {
        let sid = saga_id.clone();
        let target_key_signer = CommandSigner::local_ed25519(target_signing.clone());
        actor
            .send(move |reply| {
                ContextCommand::SagaPhase(SagaPhaseMessage::CommitBStreamSettle {
                    saga_id: sid,
                    terminal_status:
                        scp_protocol::context::outlets::stream::StreamTerminalStatus::Error(
                            "crash-window seal".to_owned(),
                        ),
                    cancel_ack_seq: None,
                    target_signer: target_key_signer,
                    reply,
                })
            })
            .await
            .expect("the seal handler inserts the witness + returns the settlement")
    };
    let k = outcome.billed_count as usize;
    assert!((1..=5).contains(&k), "sealed a non-empty prefix (got {k})");
    let rebuilt = outcome
        .settlement
        .as_deref()
        .expect("the FIRST seal returns Some(settlement) — the money has NOT moved")
        .clone();

    // Money has NOT moved: the escrow is still FULLY held and no PaymentReceipt
    // was captured — this is the stranded-window state the CRITICAL flags.
    assert_eq!(
        ss_remaining_budget(&supervisor, &target_hex, &ss_invoker()).await,
        Amount::new(SS_GRANTED - SS_RESERVED),
        "the escrow is fully HELD in the seal→settle window (no refund yet)"
    );
    assert_eq!(
        captured.load(Ordering::SeqCst),
        0,
        "no capture in the window"
    );

    // A witness-bearing settle against the WRONG generation DEFERS entirely
    // (no capture, no owned-state touch) and leaves the witness unsettled —
    // this is the eviction/respawn path; recovery (not this call) completes it.
    let deferred: StreamSettleApplication = supervisor
        .settle_outlet_stream_via_actor(
            rebuilt.clone(),
            outcome.generation.wrapping_add(1),
            Some(saga_id.clone()),
        )
        .await
        .expect("the settle dispatch succeeds");
    assert!(
        !deferred.applied,
        "a generation-mismatch witness-bearing settle DEFERS (applied=false)"
    );
    assert!(
        deferred.receipt.is_none(),
        "the deferred settle captures NOTHING (no double-bill on recovery)"
    );
    assert_eq!(
        ss_remaining_budget(&supervisor, &target_hex, &ss_invoker()).await,
        Amount::new(SS_GRANTED - SS_RESERVED),
        "the deferred settle moved no money (escrow still fully held)"
    );
    assert_eq!(
        captured.load(Ordering::SeqCst),
        0,
        "deferral captured nothing"
    );

    // KEYLESS recovery: the sweep finds the Committing entry, sees the witness
    // PRESENT but UNSETTLED, and COMPLETES the money move against B's current
    // generation — no signing key needed.
    supervisor
        .replay_unresolved_sagas(&super::RestoredContexts::new(Vec::new()))
        .await
        .expect("keyless recovery sweep runs");

    assert_eq!(
        ss_saga_state(&journal, &saga_id).await,
        None,
        "recovery completed the settlement and resolved Committed"
    );
    assert_eq!(
        ss_remaining_budget(&supervisor, &target_hex, &ss_invoker()).await,
        Amount::new(SS_GRANTED - SS_COST * k as u64),
        "CRITICAL: recovery credited the reserved−billed refund (money moves exactly once)"
    );
    assert_eq!(
        captured.load(Ordering::SeqCst),
        1,
        "CRITICAL: recovery captured the billed PaymentReceipt exactly once"
    );
    assert_eq!(
        invoked.load(Ordering::SeqCst),
        1,
        "recovery never re-invokes the outlet"
    );

    // The witness is now SETTLED — a re-read returns settled=true and NO
    // rebuilt settlement, so recovery would move NO further money (the flag is
    // the double-refund guard).
    let status = {
        let sid = saga_id.clone();
        actor
            .send(move |reply| {
                ContextCommand::SagaPhase(SagaPhaseMessage::StreamSettleCheckWitness {
                    saga_id: sid,
                    reply,
                })
            })
            .await
            .expect("witness re-check")
    };
    assert!(
        matches!(
            status,
            crate::context::actor::commands::StreamWitnessRecoveryStatus::Settled
        ),
        "witness present + settled — a settled witness carries NO rebuilt settlement, \
             so recovery moves no money"
    );

    // A SECOND recovery sweep is a no-op — the money never moves twice.
    supervisor
        .replay_unresolved_sagas(&super::RestoredContexts::new(Vec::new()))
        .await
        .expect("second recovery sweep runs");
    assert_eq!(
        ss_remaining_budget(&supervisor, &target_hex, &ss_invoker()).await,
        Amount::new(SS_GRANTED - SS_COST * k as u64),
        "CRITICAL: a second recovery does NOT double-refund"
    );
    assert_eq!(
        captured.load(Ordering::SeqCst),
        1,
        "CRITICAL: a second recovery does NOT double-capture"
    );

    drop(recording);
}

/// SCP-OUT-046 PASS-2 RESIDUAL CRITICAL — the settle handler must be
/// SELF-idempotent, not merely crash-atomic. The
/// `..._recovers_exactly_once` sibling above proves SEQUENTIAL double-recovery
/// is safe; it does NOT prove that TWO settles for the SAME unsettled witness
/// (against the MATCHING generation) move money exactly once. That is the
/// concurrent-double-settle race the residual CRITICAL flags: a mobile
/// `resume()` sweep racing the live seal task, or two overlapping recovery
/// sweeps, both dispatch `settle_outlet_stream_via_actor` for the same witness.
/// Without the `!settled` gate the money move (release + refund + capture)
/// runs UNCONDITIONALLY when the witness is present → double `reverse_spend`,
/// double §7.3.8 `AmountCumulative` release (re-spend past the cap), double
/// capture.
///
/// The per-context actor serializes every settle through its mailbox, so the
/// authoritative PRE-COMMIT flag read is decisive: the FIRST settle moves the
/// money and flips `settled` (in one Class-S persist); the SECOND reads
/// `settled == true` before any persist and is a total no-op (no
/// release/refund/capture) while still resolving `Committed` (`applied ==
/// true`, receipt `None`). The two settles are submitted CONCURRENTLY
/// (`tokio::join!`) to exercise the race, not sequenced. (The failing-store
/// edge — where an in-closure-only gate would double-capture on a persist
/// `Err` — is covered by
/// `already_settled_witness_with_failing_store_does_not_recapture` in
/// `stream_settlement_adapter.rs`.)
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn xctx_streaming_concurrent_double_settle_moves_money_exactly_once() {
    use crate::context::actor::commands::StreamSettleApplication;

    let captured = Arc::new(AtomicUsize::new(0));
    let invoked = Arc::new(AtomicUsize::new(0));
    let storage = Arc::new(InMemoryStorage::new());
    let journal: Arc<dyn SagaJournal> =
        Arc::new(ProtocolRepositorySagaJournal::new(Arc::clone(&storage)));
    let recording = SsRecordingEventLog::default();
    let supervisor =
        build_ss_supervisor(&captured, Arc::clone(&journal), Box::new(recording.clone()));
    spawn_ss_pair(&supervisor).await;

    let registry = ss_registry();
    let (params, binding) = ss_stream_params([0x46; 16]);
    let executor = Arc::new(PrefixThenBlockExecutor {
        data_chunks: 5,
        invoked: Arc::clone(&invoked),
    });
    let target_signing = SigningKey::from_bytes(&[7u8; 32]);
    let caller_signing = SigningKey::from_bytes(&[8u8; 32]);
    let outlet_id: OutletId = SS_OUTLET.to_owned();

    let mut handle = supervisor
        .start_cross_context_streaming_outlet_invocation_saga(
            SS_CALLER,
            SS_TARGET,
            ss_invoker(),
            SS_OUTLET.to_owned(),
            None,
            &registry,
            &outlet_id,
            serde_json::json!({ "a": 1, "b": 2 }),
            1,
            [0x46u8; 16],
            SS_NOW.saturating_mul(1000),
            Some(5_000),
            executor,
            Some(binding),
            SagaSigners {
                target: CommandSigner::local_ed25519(target_signing.clone()),
                caller: CommandSigner::local_ed25519(caller_signing.clone()),
            },
            params,
        )
        .await
        .expect("the paid streaming saga starts");

    let saga_id = handle.saga_id.clone();
    let target_hex = hex::encode(SS_TARGET);
    let actor = supervisor
        .lookup(&target_hex)
        .expect("target actor resident");

    // Drain the 5-chunk prefix (the executor wedges before a terminal).
    let mut received: Vec<_> = Vec::new();
    while let Ok(Some(frame)) =
        tokio::time::timeout(Duration::from_secs(1), handle.receiver.recv()).await
    {
        received.push(frame.clone());
    }
    assert_eq!(received.len(), 5, "the 5-chunk prefix forwarded");

    // Settle barrier — force the in-flight durable StreamCaptureAppend folds to
    // land before we seal (same FIFO mailbox).
    for _ in 0..25 {
        let sid = saga_id.clone();
        let _ = actor
            .send(move |reply| {
                ContextCommand::SagaPhase(SagaPhaseMessage::StreamSettleCheckWitness {
                    saga_id: sid,
                    reply,
                })
            })
            .await;
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    // Seal the witness (settled=false) + get the rebuilt settlement + B's
    // seal-time generation — WITHOUT applying the money move (the seal task's
    // handoff point).
    let outcome = {
        let sid = saga_id.clone();
        let target_key_signer = CommandSigner::local_ed25519(target_signing.clone());
        actor
            .send(move |reply| {
                ContextCommand::SagaPhase(SagaPhaseMessage::CommitBStreamSettle {
                    saga_id: sid,
                    terminal_status:
                        scp_protocol::context::outlets::stream::StreamTerminalStatus::Error(
                            "concurrent-settle seal".to_owned(),
                        ),
                    cancel_ack_seq: None,
                    target_signer: target_key_signer,
                    reply,
                })
            })
            .await
            .expect("the seal handler inserts the witness + returns the settlement")
    };
    let k = outcome.billed_count as usize;
    assert!((1..=5).contains(&k), "sealed a non-empty prefix (got {k})");
    let rebuilt = outcome
        .settlement
        .as_deref()
        .expect("the FIRST seal returns Some(settlement) — the money has NOT moved")
        .clone();
    let generation = outcome.generation;

    // No money has moved yet: escrow fully held, nothing captured.
    assert_eq!(
        ss_remaining_budget(&supervisor, &target_hex, &ss_invoker()).await,
        Amount::new(SS_GRANTED - SS_RESERVED),
        "the escrow is fully HELD in the seal→settle window (no refund yet)"
    );
    assert_eq!(
        captured.load(Ordering::SeqCst),
        0,
        "no capture in the window"
    );

    // THE RACE: two settles for the SAME unsettled witness, MATCHING generation,
    // submitted CONCURRENTLY. The actor mailbox serializes them — one moves the
    // money and flips `settled`; the other reads `settled == true` and no-ops.
    let (r1, r2) = tokio::join!(
        supervisor.settle_outlet_stream_via_actor(
            rebuilt.clone(),
            generation,
            Some(saga_id.clone()),
        ),
        supervisor.settle_outlet_stream_via_actor(
            rebuilt.clone(),
            generation,
            Some(saga_id.clone()),
        ),
    );
    let a1 = r1.expect("first concurrent settle dispatch succeeds");
    let a2 = r2.expect("second concurrent settle dispatch succeeds");

    // BOTH resolve Committed (applied=true): the money moved exactly once, on
    // whichever settle won the mailbox race.
    assert!(
        a1.applied && a2.applied,
        "both concurrent settles resolve Committed (applied=true)"
    );
    // EXACTLY ONE captured a PaymentReceipt — the winner. The loser observed
    // `settled == true` via the authoritative pre-commit read and returned
    // `AlreadySettled` (no persist, no capture).
    assert_eq!(
        usize::from(a1.receipt.is_some()) + usize::from(a2.receipt.is_some()),
        1,
        "exactly ONE of the two concurrent settles captured a receipt \
             (the other is the idempotent no-op)"
    );

    // Money conservation: the escrow refund (reserved − billed) is credited
    // EXACTLY ONCE. Because the §7.3.8 `AmountCumulative` counter release lives
    // in the SAME `commit_class_s_keep` closure behind the SAME `!settled` gate
    // as this refund, refund-exactly-once transitively proves the counter was
    // RELEASED EXACTLY ONCE — a double release cannot occur without a double
    // refund, which this assertion would catch.
    assert_eq!(
        ss_remaining_budget(&supervisor, &target_hex, &ss_invoker()).await,
        Amount::new(SS_GRANTED - SS_COST * k as u64),
        "CRITICAL: the refund (and the coupled §7.3.8 counter release) is applied \
             EXACTLY ONCE across two concurrent settles"
    );
    // The billed PaymentReceipt is captured EXACTLY ONCE — no double-bill.
    assert_eq!(
        captured.load(Ordering::SeqCst),
        1,
        "CRITICAL: exactly ONE PaymentReceipt captured across two concurrent settles"
    );
    assert_eq!(
        invoked.load(Ordering::SeqCst),
        1,
        "the outlet is never re-invoked"
    );

    // The witness is now SETTLED and a re-check rebuilds NO settlement, so any
    // further settle / recovery is a guaranteed no-op.
    let status = {
        let sid = saga_id.clone();
        actor
            .send(move |reply| {
                ContextCommand::SagaPhase(SagaPhaseMessage::StreamSettleCheckWitness {
                    saga_id: sid,
                    reply,
                })
            })
            .await
            .expect("witness re-check")
    };
    assert!(
        matches!(
            status,
            crate::context::actor::commands::StreamWitnessRecoveryStatus::Settled
        ),
        "witness present + settled — a settled witness carries NO rebuilt settlement, \
             so no further money moves"
    );

    // A THIRD settle (a late straggler) is still a total no-op.
    let third: StreamSettleApplication = supervisor
        .settle_outlet_stream_via_actor(rebuilt.clone(), generation, Some(saga_id.clone()))
        .await
        .expect("third settle dispatch succeeds");
    assert!(
        third.applied,
        "the straggler resolves Committed (applied=true)"
    );
    assert!(
        third.receipt.is_none(),
        "the straggler captures nothing (idempotent no-op)"
    );
    assert_eq!(
        ss_remaining_budget(&supervisor, &target_hex, &ss_invoker()).await,
        Amount::new(SS_GRANTED - SS_COST * k as u64),
        "CRITICAL: a third settle does NOT double-refund"
    );
    assert_eq!(
        captured.load(Ordering::SeqCst),
        1,
        "CRITICAL: a third settle does NOT double-capture"
    );

    drop(recording);
}

/// COMMIT 3 — AC2: the Commit-transition RELEASES the per-participant-context-set
/// concurrency slot once the pump is triggered (ADR-049 §3a amendment (b)).
///
/// S1 spans `{A, B}`; S2 spans the OVERLAPPING `{B, C}`. Once S1's Commit-
/// transition returns its receiver and its seal is pumping off-mailbox (its
/// `{A, B}` reservation dropped), S2 must be able to Prepare + Commit over
/// `{B, C}` — it reserves B without a `SagaBusy`/`ActorBusy` wedge, proving the
/// slot is released at Commit (not held until the seal reaches Committed).
///
/// This proof requires two REAL, co-resident streaming sagas driven through
/// spawned actors (`start_cross_context_streaming_outlet_invocation_saga` +
/// off-mailbox seal). It lives here (not in the `actor_saga_concurrent.rs`
/// integration file, whose gate-named primitive tests it complements) because
/// actor residency (`spawn_actor_with_state`) is `pub(in crate::context)` — an
/// external integration test cannot make a context resident, so it cannot hold
/// S1's seal "still pumping" while S2 commits.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn xctx_streaming_commit_releases_slot_overlap_runs() {
    let captured = Arc::new(AtomicUsize::new(0));
    let invoked = Arc::new(AtomicUsize::new(0));
    let storage = Arc::new(InMemoryStorage::new());
    let journal: Arc<dyn SagaJournal> =
        Arc::new(ProtocolRepositorySagaJournal::new(Arc::clone(&storage)));
    let recording = SsRecordingEventLog::default();
    let supervisor =
        build_ss_supervisor(&captured, Arc::clone(&journal), Box::new(recording.clone()));

    // Spawn all three participant actors. B (`SS_TARGET`) doubles as S1's target
    // AND S2's caller: it carries the registered paid outlet (target role) and an
    // established B→C interface (caller role).
    spawn_ss_actor(
        &supervisor,
        "did:example:ss-a-owner",
        ss_caller_state_for(SS_CALLER, SS_TARGET),
    )
    .await;
    let mut b_state = ss_paid_target_state(SS_TARGET);
    ss_push_interface(&mut b_state, SS_TARGET, SS_THIRD);
    spawn_ss_actor(&supervisor, "did:example:ss-b-owner", b_state).await;
    spawn_ss_actor(
        &supervisor,
        "did:example:ss-c-owner",
        ss_paid_target_state(SS_THIRD),
    )
    .await;

    let registry = ss_registry();
    let target_signing = SigningKey::from_bytes(&[7u8; 32]);
    let caller_signing = SigningKey::from_bytes(&[8u8; 32]);
    let outlet_id: OutletId = SS_OUTLET.to_owned();

    // S1 over {A, B} — a prefix-then-wedge executor keeps its seal pumping
    // off-mailbox after the Commit-transition, so the {A, B} slot is under test.
    let (s1_params, s1_binding) = ss_stream_params_for(SS_TARGET, [0x21; 16]);
    let s1_executor = Arc::new(PrefixThenBlockExecutor {
        data_chunks: 3,
        invoked: Arc::clone(&invoked),
    });
    let mut s1 = supervisor
        .start_cross_context_streaming_outlet_invocation_saga(
            SS_CALLER,
            SS_TARGET,
            ss_invoker(),
            SS_OUTLET.to_owned(),
            None,
            &registry,
            &outlet_id,
            serde_json::json!({ "a": 1, "b": 2 }),
            1,
            [0x21u8; 16],
            SS_NOW.saturating_mul(1000),
            Some(5_000),
            s1_executor,
            Some(s1_binding),
            SagaSigners {
                target: CommandSigner::local_ed25519(target_signing.clone()),
                caller: CommandSigner::local_ed25519(caller_signing.clone()),
            },
            s1_params,
        )
        .await
        .expect("S1 starts over the A-B participant set");

    // S1 is past its Commit-transition and pumping: its receiver yields chunk 0,
    // which means the {A, B} reservation was already dropped.
    let s1_first = tokio::time::timeout(Duration::from_secs(5), s1.receiver.recv())
        .await
        .expect("S1 chunk 0 within 5s")
        .expect("S1 chunk 0 present");
    assert!(
        matches!(s1_first.payload, ChunkPayload::Data { .. }),
        "S1 is pumping (receiver returned; reservation released at Commit)"
    );
    assert_eq!(
        ss_saga_state(&journal, &s1.saga_id).await,
        Some(SagaState::Committing),
        "S1's seal is still pumping (Committing) — its A-B slot released, not held"
    );

    // S2 over the OVERLAPPING {B, C} — B is shared with S1. Because S1 released
    // {A, B} at its Commit-transition, S2 reserves {B, C} and drives to a
    // terminal without any SagaBusy/ActorBusy wedge.
    let (s2_params, s2_binding) = ss_stream_params_for(SS_THIRD, [0x22; 16]);
    let s2_executor = Arc::new(FiniteChunkExecutor {
        data_chunks: 3,
        invoked: Arc::clone(&invoked),
    });
    let s2_result = supervisor
        .start_cross_context_streaming_outlet_invocation_saga(
            SS_TARGET,
            SS_THIRD,
            ss_invoker(),
            SS_OUTLET.to_owned(),
            None,
            &registry,
            &outlet_id,
            serde_json::json!({ "a": 3, "b": 4 }),
            1,
            [0x22u8; 16],
            SS_NOW.saturating_mul(1000),
            Some(5_000),
            s2_executor,
            Some(s2_binding),
            SagaSigners {
                target: CommandSigner::local_ed25519(target_signing.clone()),
                caller: CommandSigner::local_ed25519(caller_signing.clone()),
            },
            s2_params,
        )
        .await;

    let mut s2 = match s2_result {
        Ok(handle) => handle,
        Err(super::SagaError::Busy {
            contended_context, ..
        }) => panic!(
            "AC2: S2 over overlapping {{B, C}} was wedged SagaBusy on '{contended_context}' — \
                 S1 did NOT release its slot at the Commit-transition"
        ),
        Err(other) => panic!("AC2: S2 must Prepare+Commit, got {other:?}"),
    };

    // S2 actually Prepared + Committed: it is pumping its own stream (chunk 0
    // delivered), and its journal reached Committing over {B, C}.
    let s2_first = tokio::time::timeout(Duration::from_secs(5), s2.receiver.recv())
        .await
        .expect("S2 chunk 0 within 5s")
        .expect("S2 chunk 0 present");
    assert!(
        matches!(s2_first.payload, ChunkPayload::Data { .. }),
        "AC2: S2 Prepared + Committed over the overlapping set and is pumping"
    );

    // Drain S2 to close so its seal resolves — proving a full overlapping-set
    // saga completes while S1's seal is still pumping off-mailbox.
    while let Ok(Some(frame)) =
        tokio::time::timeout(Duration::from_secs(5), s2.receiver.recv()).await
    {
        if matches!(
            frame.payload,
            ChunkPayload::End { .. } | ChunkPayload::Error { .. }
        ) {
            break;
        }
    }
    ss_await_resolved(&journal, &s2.saga_id, Duration::from_secs(5)).await;
    assert_eq!(
        ss_saga_state(&journal, &s2.saga_id).await,
        None,
        "AC2: the overlapping S2 committed to completion (resolved) with no wedge"
    );

    drop(recording);
}
