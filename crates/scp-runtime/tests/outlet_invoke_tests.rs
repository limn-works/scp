//! Tests moved out of `scp-runtime-core` `context::outlets::invoke` (ADR-070 §6.2): they build a
//! `Supervisor`, which needs the domain handlers only `scp-runtime` assembles.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use scp_did::DID;
use scp_protocol::context::ContextState;
use scp_protocol::context::outlets::OutletId;
use scp_protocol::context::outlets::OutletKind;
use scp_protocol::context::outlets::error_codes::{
    CODE_AUTHORIZATION_DENIED, CODE_OUTPUT_VIOLATION, CODE_TRANSPORT_FAULT,
};
use scp_protocol::context::outlets::lifecycle::OutletInvokedEvent;
use scp_protocol::context::outlets::registration::OutletRegistration;
use scp_protocol::context::outlets::registry::OutletRegistry;
use scp_protocol::context::outlets::stream::{ChunkPayload, OutletStreamChunk, RequestId};
use scp_protocol::context::roles::ContextRoleState;
use scp_runtime_core::context::ContextHandle;
use scp_runtime_types::context::outlets::signer::StreamSigner;
use tokio::sync::mpsc;

use scp_protocol::context::ContextParams;
use scp_protocol::context::outlets::registry::{OutletSchema, register_outlet};
use scp_protocol::context::roles::{Capability, CapabilityCeiling};
use scp_runtime_core::context::outlets::invoke::*;

/// Creates a test capability ceiling with all capabilities.
fn test_ceiling() -> CapabilityCeiling {
    CapabilityCeiling::new([
        Capability::MessagesRead,
        Capability::MessagesWrite,
        Capability::OutletRegister,
        Capability::OutletCallAll,
        Capability::RoleAssign,
        Capability::MemberInvite,
        Capability::MemberRemove,
        Capability::GovernancePropose,
        Capability::GovernanceVote,
        Capability::ContextClose,
    ])
}

/// Creates a `ContextRoleState` with a creator that has admin (all) capabilities.
fn test_role_state(creator_did: &str) -> ContextRoleState {
    ContextRoleState::new(
        "ctx-test",
        creator_did,
        test_ceiling(),
        vec![],
        &scp_clock::SystemClock,
    )
    .unwrap()
}

/// Creates a valid outlet registration and registers it in a fresh registry.
fn setup_registry_with_outlet(
    role_state: &ContextRoleState,
    registrant_did: &str,
) -> OutletRegistry {
    let mut registry = OutletRegistry::new();
    let registration = OutletRegistration {
        outlet_id: "calculator".to_owned(),
        kind: OutletKind::default(),
        name: "Calculator".to_owned(),
        description: "A simple calculator".to_owned(),
        schema: OutletSchema {
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "a": {"type": "number"},
                    "b": {"type": "number"}
                }
            }),
            output_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "result": {"type": "number"}
                }
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
    };
    register_outlet(&mut registry, role_state, registration, registrant_did).unwrap();
    registry
}

/// Creates an active context handle (transitions from Creating to Active).
///
/// `ContextParams::default()` uses `MemoryScope::Ephemeral`, so the
/// terminal `End` chunk's provenance built from this handle carries
/// `Ephemeral` — the item-4 assertion that the scope is the REAL param,
/// not a hardcoded `Full`.
fn active_context() -> ContextHandle {
    let handle = ContextHandle::new("ctx-invoke-test".to_owned(), ContextParams::default());
    handle.transition_to(&ContextState::Active).unwrap();
    handle
}

/// An in-process operator [`StreamSigner`] for tests, backed by a fixed
/// Ed25519 key. Every streaming `invoke_outlet` open in the unit tests
/// wires one of these — the signer is REQUIRED (a stream that cannot sign
/// its chunks must not open), so there is no `None` path to a forged
/// all-zero signature.
fn test_signer() -> std::sync::Arc<dyn StreamSigner> {
    use ed25519_dalek::SigningKey;
    use scp_runtime_types::context::outlets::signer::InProcessStreamSigner;
    std::sync::Arc::new(InProcessStreamSigner::new(SigningKey::from_bytes(
        &[0x5c; 32],
    )))
}

// =======================================================================
// Streaming entry point (SCP-OUT-033 / §5.4.5): the executor-based
// `invoke_outlet<E>` machinery ported in chunk 2a.
// =======================================================================

/// Drains a `mpsc::Receiver<OutletStreamChunk>` into a `Vec` until
/// EOS, asserting that sequence numbers are strictly monotonic
/// starting at `0` (PRD AC4).
async fn drain_stream_with_sequence_invariant(
    mut rx: tokio::sync::mpsc::Receiver<OutletStreamChunk>,
) -> Vec<OutletStreamChunk> {
    let mut chunks = Vec::new();
    let mut expected_seq: u64 = 0;
    while let Some(chunk) = rx.recv().await {
        assert_eq!(
            chunk.sequence, expected_seq,
            "sequence must be strictly monotonic per request_id (PRD AC4)"
        );
        expected_seq = expected_seq.saturating_add(1);
        chunks.push(chunk);
    }
    chunks
}

/// An [`OutletInvokedEventSink`] that forwards each recorded event over an
/// unbounded channel — a Mutex-free capture surface (Mutex is banned in
/// scp-runtime; the reference in-memory sinks live on other crates).
struct ChannelInvokedSink {
    tx: tokio::sync::mpsc::UnboundedSender<OutletInvokedEvent>,
}

impl scp_runtime_core::context::outlets::invoke::OutletInvokedEventSink for ChannelInvokedSink {
    fn record(&self, event: OutletInvokedEvent) {
        let _ = self.tx.send(event);
    }
}

/// Drains every event a [`ChannelInvokedSink`] captured (call after the
/// stream has fully closed and the spawned task has dropped its sink).
fn drain_invoked_events(
    rx: &mut tokio::sync::mpsc::UnboundedReceiver<OutletInvokedEvent>,
) -> Vec<OutletInvokedEvent> {
    let mut events = Vec::new();
    while let Ok(ev) = rx.try_recv() {
        events.push(ev);
    }
    events
}

// =====================================================================
// SCP-OUT-036 — best-effort cross-context re-encrypting streaming bridge
// =====================================================================
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod cross_context_036 {
    use scp_runtime_core::context::outlets::invoke::BridgeFaultProbe;
    use scp_runtime_core::context::outlets::invoke::CrossContextBridgeForTest;
    use scp_runtime_core::context::outlets::invoke::CrossContextVerificationDescriptor;
    use scp_runtime_core::context::outlets::invoke::MAX_CROSS_CONTEXT_STREAM_CHUNKS;
    use scp_runtime_core::context::outlets::invoke::OutletCrossContextInvokeForTest;
    use scp_runtime_core::context::outlets::invoke::StreamingOutletEventForTest;
    use scp_runtime_core::context::outlets::invoke::StreamingSagaSealTaskForTest;
    use scp_runtime_core::context::outlets::invoke::build_onward_a_leg_open_for_test as build_onward_a_leg_open;
    use scp_runtime_core::context::outlets::invoke::cross_context_economy_gate_for_test as cross_context_economy_gate;
    use scp_runtime_core::context::outlets::invoke::verify_forwarded_chunk_for_test as verify_forwarded_chunk;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};

    use ed25519_dalek::{Signer as _, SigningKey};

    use crate::*;
    use scp_protocol::context::outlets::stream::{OutletStreamOpen, compute_chunk_sig_preimage};
    use scp_runtime_core::context::builder::ContextEventLogProvider;
    use scp_runtime_core::context::providers::event_log::MerkleEventLogProvider;
    use scp_runtime_core::context::state::context_id_to_bytes;
    use scp_runtime_types::context::outlets::signer::InProcessStreamSigner;

    const B_CTX: &str = "ctx-b-036";
    const A_CTX: &str = "ctx-a-036";
    const OUTLET: &str = "calculator";
    const CB: [u8; 32] = [0x11; 32];
    const RID: RequestId = [0xAB; 16];
    const INVOKER: &str = "did:dht:z6MkXctxInvoker036";

    /// The operator's deterministic Ed25519 signing key (B-side operator).
    fn operator_key() -> SigningKey {
        SigningKey::from_bytes(&[0x5c; 32])
    }

    /// Signs one chunk under the §5.4.5 `SCP-OUTLET-CHUNK-SIG-V1:` preimage
    /// with the given operator key and pinned `(context_id, outlet_id,
    /// caveats_binding)` — the exact operator-authored shape B produces.
    fn sign_chunk(
        operator: &SigningKey,
        context_id: &str,
        outlet_id: &str,
        caveats_binding: &[u8; 32],
        sequence: u64,
        payload: ChunkPayload,
    ) -> OutletStreamChunk {
        let preimage = compute_chunk_sig_preimage(
            context_id,
            outlet_id,
            &RID,
            sequence,
            caveats_binding,
            &payload,
        )
        .expect("chunk preimage");
        let sig = operator.sign(&preimage).to_bytes();
        OutletStreamChunk {
            request_id: RID,
            sequence,
            payload,
            sig,
        }
    }

    /// The pinned verification descriptor for B's operator over `B_CTX`.
    fn pinned_descriptor(operator: &SigningKey) -> CrossContextVerificationDescriptor {
        CrossContextVerificationDescriptor::new_for_test(
            operator.verifying_key(),
            B_CTX.to_owned(),
            OUTLET.to_owned(),
            CB,
            RID,
        )
    }

    /// The empty JSON Schema — accepts ANY instance (object, array, scalar,
    /// null). Used where the test is not exercising a schema violation, so
    /// the operator's default `End.aggregate` (whatever its shape) passes.
    fn permissive_schema() -> serde_json::Value {
        serde_json::json!({})
    }

    /// An output schema that REQUIRES a numeric `result` and forbids extra
    /// keys — a value lacking a numeric `result` violates it.
    fn strict_output_schema() -> serde_json::Value {
        serde_json::json!({
            "type": "object",
            "properties": { "result": { "type": "number" } },
            "required": ["result"],
            "additionalProperties": false
        })
    }

    /// An aggregate schema that REQUIRES a string `summary` and forbids
    /// extra keys — disjoint from [`strict_output_schema`].
    fn aggregate_schema() -> serde_json::Value {
        serde_json::json!({
            "type": "object",
            "properties": { "summary": { "type": "string" } },
            "required": ["summary"],
            "additionalProperties": false
        })
    }

    fn end_payload(aggregate: serde_json::Value) -> ChunkPayload {
        ChunkPayload::End {
            aggregate,
            provenance: scp_protocol::provenance::DataProvenance {
                source_context: B_CTX.to_owned(),
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
            execution_time_ms: 5,
        }
    }

    /// Initializes a fresh receiving-context (A) event log.
    async fn fresh_a_log() -> (Arc<MerkleEventLogProvider>, [u8; 32]) {
        let provider = Arc::new(MerkleEventLogProvider::new());
        let a_bytes = context_id_to_bytes(A_CTX);
        provider.init_event_log(&a_bytes).await.expect("init A log");
        (provider, a_bytes)
    }

    /// Reads back A's recorded `OutletInvokedEvent`, if any.
    fn read_a_invoked(
        a_log: &MerkleEventLogProvider,
        a_bytes: &[u8; 32],
    ) -> Option<OutletInvokedEvent> {
        a_log.entries(a_bytes)?.into_iter().find_map(|entry| {
            if entry.event_type == scp_event_log::EventType::OutletInvoked {
                serde_json::from_slice::<OutletInvokedEvent>(&entry.payload.data).ok()
            } else {
                None
            }
        })
    }

    /// Drives the bridge core to completion over a pre-built chunk
    /// sequence, returning what A's invoker received plus A's log handle.
    async fn drive_bridge(
        chunks: Vec<OutletStreamChunk>,
        descriptor: CrossContextVerificationDescriptor,
        output_schema: serde_json::Value,
        aggregate_schema: Option<serde_json::Value>,
        fault_probe: Option<BridgeFaultProbe>,
    ) -> (
        Vec<OutletStreamChunk>,
        Arc<MerkleEventLogProvider>,
        [u8; 32],
    ) {
        let (a_log, a_bytes) = fresh_a_log().await;
        let (inner_tx, inner_rx) = mpsc::channel::<OutletStreamChunk>(1);
        let (outer_tx, mut outer_rx) = mpsc::channel::<OutletStreamChunk>(1);
        let a_dyn: Arc<dyn ContextEventLogProvider> = a_log.clone();
        let bridge = tokio::spawn(
            CrossContextBridgeForTest {
                inner_rx,
                outer_tx,
                descriptor,
                output_schema,
                aggregate_schema,
                a_event_log: a_dyn,
                receiving_context_id: A_CTX.to_owned(),
                invoker_did: DID::from(INVOKER),
                request_id: RID,
                outlet_id: OUTLET.to_owned(),
                input_hash: "input-hash".to_owned(),
                governing_chain_depth: 3,
                timestamp_secs: 0,
                max_retained_chunks: MAX_CROSS_CONTEXT_STREAM_CHUNKS,
                fault_probe,
            }
            .run(),
        );
        let producer = tokio::spawn(async move {
            for chunk in chunks {
                if inner_tx.send(chunk).await.is_err() {
                    break;
                }
            }
        });
        // The bridge forwards bare `OutletStreamChunk`s (identical to the
        // same-context path); collect what A's invoker received.
        let mut received = Vec::new();
        while let Some(chunk) = outer_rx.recv().await {
            received.push(chunk);
        }
        producer.await.expect("producer task");
        bridge.await.expect("bridge task");
        (received, a_log, a_bytes)
    }

    fn assert_terminal_error(chunk: &OutletStreamChunk, expected_code: &str) {
        match &chunk.payload {
            ChunkPayload::Error { code, terminal, .. } => {
                assert_eq!(code, expected_code, "terminal error code");
                assert!(*terminal, "must be terminal");
            }
            other => panic!("expected terminal Error, got {other:?}"),
        }
    }

    // ---- AC2: Ok variant is a plaintext mpsc::Receiver<OutletStreamChunk>.

    struct NoOpExecutor;
    #[async_trait::async_trait]
    impl scp_runtime_core::context::outlets::invoke::OutletExecutor for NoOpExecutor {
        async fn exec_action(
            &self,
            _ctx: &mut scp_runtime_core::context::outlets::invoke::MutableInvocation<'_>,
            _input: serde_json::Value,
        ) -> Result<
            serde_json::Value,
            scp_runtime_core::context::outlets::invoke::OutletExecutorError,
        > {
            Ok(serde_json::json!({}))
        }
    }

    /// Compile-level proof that `invoke_outlet_cross_context`'s Ok variant
    /// is exactly `mpsc::Receiver<OutletStreamChunk>` — a bare PLAINTEXT
    /// operator-signed chunk, identical to the same-context path, NOT a
    /// sealed/ciphertext type and NOT a wrapper frame. Never executed — the
    /// explicit type annotation on the awaited result fails to compile if
    /// the return type drifts.
    #[allow(dead_code)]
    async fn ac2_return_type_is_plaintext_receiver(
        supervisor: &Arc<scp_runtime_core::context::supervisor::Supervisor>,
        a_event_log: Arc<dyn scp_runtime_core::context::builder::ContextEventLogProvider>,
        registry: &OutletRegistry,
        outlet_id: &OutletId,
        invoker_did: &DID,
        incoming_open: &OutletStreamOpen,
        params: scp_runtime_core::context::outlets::dispatch::OpenStreamParams,
    ) {
        let out: Result<mpsc::Receiver<OutletStreamChunk>, OutletOpenError> =
            OutletCrossContextInvokeForTest::<NoOpExecutor> {
                supervisor,
                a_event_log,
                receiving_context_id: "a",
                operating_context_id: "b",
                registry,
                outlet_id,
                input: serde_json::json!({}),
                invoker_did,
                timeout_ms: None,
                executor: Arc::new(NoOpExecutor),
                incoming_open,
                caveat_binding: None,
                params,
            }
            .run()
            .await;
        drop(out);
    }

    #[tokio::test]
    async fn ac2_ok_variant_is_plaintext_receiver() {
        // Runtime: a chunk read off the bridge's outer receiver (the exact
        // value `invoke_outlet_cross_context` returns) exposes a PLAINTEXT
        // `ChunkPayload` — never a sealed blob.
        let op = operator_key();
        let chunks = vec![
            sign_chunk(
                &op,
                B_CTX,
                OUTLET,
                &CB,
                0,
                ChunkPayload::Data {
                    value: serde_json::json!({ "result": 1 }),
                },
            ),
            sign_chunk(
                &op,
                B_CTX,
                OUTLET,
                &CB,
                1,
                end_payload(serde_json::json!({ "result": 1 })),
            ),
        ];
        let (received, _a_log, _a_bytes) = drive_bridge(
            chunks,
            pinned_descriptor(&op),
            permissive_schema(),
            None,
            None,
        )
        .await;
        assert!(
            matches!(received[0].payload, ChunkPayload::Data { .. }),
            "first forwarded chunk is a plaintext Data payload"
        );
    }

    // ---- AC3: no buffering — chunk N delivered before N+1 requested.

    #[tokio::test]
    async fn ac3_bridge_forwards_without_buffering() {
        let op = operator_key();
        let (a_log, _a_bytes) = fresh_a_log().await;
        let a_dyn: Arc<dyn ContextEventLogProvider> = a_log.clone();
        let (inner_tx, inner_rx) = mpsc::channel::<OutletStreamChunk>(1);
        let (outer_tx, mut outer_rx) = mpsc::channel::<OutletStreamChunk>(1);

        let bridge = tokio::spawn(
            CrossContextBridgeForTest {
                inner_rx,
                outer_tx,
                descriptor: pinned_descriptor(&op),
                output_schema: permissive_schema(),
                aggregate_schema: None,
                a_event_log: a_dyn,
                receiving_context_id: A_CTX.to_owned(),
                invoker_did: DID::from(INVOKER),
                request_id: RID,
                outlet_id: OUTLET.to_owned(),
                input_hash: "input-hash".to_owned(),
                governing_chain_depth: 3,
                timestamp_secs: 0,
                max_retained_chunks: MAX_CROSS_CONTEXT_STREAM_CHUNKS,
                fault_probe: None,
            }
            .run(),
        );

        // The highest sequence the source has SUCCESSFULLY handed to the
        // inner channel. Because the outer channel is bounded to 1 and the
        // bridge holds at most one chunk in flight, the source can never get
        // more than 2 chunks ahead of an unconsumed receiver — proving the
        // bridge does NOT drain the whole stream into an internal buffer.
        let accepted = Arc::new(AtomicU64::new(0));
        let producer = {
            let accepted = Arc::clone(&accepted);
            let op = op.clone();
            tokio::spawn(async move {
                for seq in 0..6u64 {
                    let payload = ChunkPayload::Data {
                        value: serde_json::json!({ "result": seq }),
                    };
                    let chunk = sign_chunk(&op, B_CTX, OUTLET, &CB, seq, payload);
                    if inner_tx.send(chunk).await.is_err() {
                        break;
                    }
                    accepted.fetch_add(1, Ordering::SeqCst);
                }
            })
        };

        // Let the pipeline reach steady state WITHOUT consuming `outer_rx`.
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        let ahead = accepted.load(Ordering::SeqCst);
        // Steady-state cap = inner(1) + one chunk held in the bridge (blocked
        // forwarding into the full outer channel) + outer(1) = 3. A bridge
        // that accumulated the whole stream into a Vec would let all 6
        // through. `<= 3` with 6 fed proves it forwards-as-produced.
        assert!(
            ahead <= 3,
            "backpressure caps the source at 3 chunks ahead of an unconsumed receiver; \
                 got {ahead} of 6 — the bridge is buffering the stream"
        );

        // Now drain and assert strict in-order delivery with no gaps. The
        // bridge forwards bare `OutletStreamChunk`s.
        let mut received = Vec::new();
        while let Some(chunk) = outer_rx.recv().await {
            received.push(chunk);
        }
        producer.await.expect("producer");
        bridge.await.expect("bridge");
        // The six Data chunks are forwarded in order; because the producer
        // drops its sender WITHOUT emitting a terminal, the bridge now
        // synthesizes a terminal transport-fault (§5.4.5 terminal guarantee)
        // as the final chunk — so A never truncates after a non-terminal
        // Data.
        assert_eq!(
            received.len(),
            7,
            "six Data chunks + one synthesized terminal transport-fault"
        );
        for (i, chunk) in received.iter().take(6).enumerate() {
            assert_eq!(chunk.sequence, i as u64, "Data delivered strictly in order");
            assert!(
                matches!(chunk.payload, ChunkPayload::Data { .. }),
                "the first six forwarded chunks are Data payloads"
            );
        }
        assert_terminal_error(received.last().unwrap(), CODE_TRANSPORT_FAULT);
    }

    // ---- AC4: A-leg open inherits chain_depth; chunks never carry it.

    #[test]
    fn ac4_a_leg_open_inherits_chain_depth_verbatim() {
        let incoming = OutletStreamOpen {
            request_id: RID,
            outlet_id: OUTLET.to_owned(),
            input: serde_json::json!({ "a": 1 }),
            invoker_did: DID::from(INVOKER),
            ucan: vec![0x01, 0x02],
            caveats_binding: CB,
            chain_depth: 3,
            credit_window: 8,
            estimated_chunk_count: 5,
            session_id: None,
            timeout_ms: 1000,
        };
        let a_leg = build_onward_a_leg_open(&incoming);
        assert_eq!(
            a_leg.chain_depth, 3,
            "the onward A-leg open inherits chain_depth == 3 verbatim (no +1)"
        );
        // A forwarded chunk cannot mutate chain_depth: it is structurally
        // absent from OutletStreamChunk (only request_id/sequence/payload/
        // sig). This constructs a chunk and confirms the field set.
        let chunk = sign_chunk(
            &operator_key(),
            B_CTX,
            OUTLET,
            &CB,
            0,
            ChunkPayload::Data {
                value: serde_json::json!({ "result": 1 }),
            },
        );
        // Exhaustive destructure — a future `chain_depth` field would break
        // this compile, enforcing "chunks do not carry chain_depth".
        let OutletStreamChunk {
            request_id: _,
            sequence: _,
            payload: _,
            sig: _,
        } = chunk;
    }

    // ---- AC5: Data violating output_schema → terminal 6140.

    #[tokio::test]
    async fn ac5_data_schema_violation_emits_output_terminal() {
        let op = operator_key();
        let chunks = vec![
            sign_chunk(
                &op,
                B_CTX,
                OUTLET,
                &CB,
                0,
                ChunkPayload::Data {
                    value: serde_json::json!({ "result": 1 }),
                },
            ),
            // Violates strict_output_schema (`result` must be a number).
            sign_chunk(
                &op,
                B_CTX,
                OUTLET,
                &CB,
                1,
                ChunkPayload::Data {
                    value: serde_json::json!({ "result": "not-a-number" }),
                },
            ),
        ];
        let (received, _a_log, _a_bytes) = drive_bridge(
            chunks,
            pinned_descriptor(&op),
            strict_output_schema(),
            None,
            None,
        )
        .await;
        // The valid Data prefix forwarded, then the terminal replaces the
        // offending chunk (ordering preserved).
        assert!(matches!(received[0].payload, ChunkPayload::Data { .. }));
        assert_terminal_error(received.last().unwrap(), CODE_OUTPUT_VIOLATION);
    }

    // ---- AC6: End.aggregate validated against aggregate_schema when set.

    #[tokio::test]
    async fn ac6_end_aggregate_uses_aggregate_schema_when_present() {
        let op = operator_key();
        // The aggregate satisfies aggregate_schema but VIOLATES
        // output_schema (no numeric `result`) — accepted because
        // aggregate_schema is present.
        let chunks = vec![sign_chunk(
            &op,
            B_CTX,
            OUTLET,
            &CB,
            0,
            end_payload(serde_json::json!({ "summary": "done" })),
        )];
        let (received, _a_log, _a_bytes) = drive_bridge(
            chunks,
            pinned_descriptor(&op),
            strict_output_schema(),
            Some(aggregate_schema()),
            None,
        )
        .await;
        assert_eq!(received.len(), 1, "the End is forwarded, not rejected");
        assert!(
            matches!(received[0].payload, ChunkPayload::End { .. }),
            "End satisfying aggregate_schema is accepted"
        );
    }

    // ---- AC7 accept: A's recorded manifest == B's recorded manifest.

    #[tokio::test]
    async fn ac7_accept_both_logs_same_manifest_hash() {
        // B produces the stream through its REAL same-context streaming path
        // (`invoke_outlet`), signing every chunk and recording its own
        // `OutletInvokedEvent` (B's log) via a capture sink.
        const DATA_CHUNKS: u32 = 9;
        struct NineDataExecutor;
        #[async_trait::async_trait]
        impl scp_runtime_core::context::outlets::invoke::OutletExecutor for NineDataExecutor {
            async fn exec_action_stream(
                &self,
                _ctx: &mut scp_runtime_core::context::outlets::invoke::MutableInvocation<'_>,
                _input: serde_json::Value,
                tx: tokio::sync::mpsc::Sender<ChunkPayload>,
            ) -> Result<(), scp_runtime_core::context::outlets::invoke::OutletExecutorError>
            {
                for i in 0..DATA_CHUNKS {
                    let _ = tx
                        .send(ChunkPayload::Data {
                            value: serde_json::json!({ "tick": i }),
                        })
                        .await;
                }
                Ok(())
            }
        }

        let op = operator_key();
        // B's signing context is the same-context handle id — pin the
        // descriptor to it so the bridge's verification accepts B's chunks.
        let context = active_context();
        let b_ctx_id = context.context_id().to_owned();
        let creator_did = "did:dht:z6MkCreator";
        let role_state = test_role_state(creator_did);
        let registry = setup_registry_with_outlet(&role_state, creator_did);
        let outlet_id_owned: OutletId = OUTLET.to_owned();
        let executor: Arc<dyn scp_runtime_core::context::outlets::invoke::OutletExecutor> =
            Arc::new(NineDataExecutor);
        let signer: Arc<dyn scp_runtime_types::context::outlets::signer::StreamSigner> =
            Arc::new(InProcessStreamSigner::new(op.clone()));
        let (tx, mut b_events) = tokio::sync::mpsc::unbounded_channel();
        let b_sink: Arc<dyn scp_runtime_core::context::outlets::invoke::OutletInvokedEventSink> =
            Arc::new(ChannelInvokedSink { tx });

        let b_rx = scp_runtime_core::context::outlets::invoke::invoke_outlet(
            &context,
            &registry,
            &role_state,
            &outlet_id_owned,
            serde_json::json!({ "a": 1, "b": 2 }),
            &DID::from(creator_did),
            None,
            executor,
            None,
            None,
            Some(b_sink),
            signer,
            CB,
            &|task| drop(tokio::spawn(task)),
        )
        .await
        .expect("B open");

        let b_chunks = drain_stream_with_sequence_invariant(b_rx).await;
        assert_eq!(b_chunks.len(), 10, "9 Data + terminal End");
        let b_event = {
            let mut ev = drain_invoked_events(&mut b_events);
            assert_eq!(ev.len(), 1, "exactly one B-side OutletInvoked");
            ev.remove(0)
        };
        let b_hash = b_event.stream_manifest_hash;

        // The bridge reassembles the SAME chunks and records A's log through
        // the verified-append boundary. Pin the descriptor to B's real
        // signing context.
        // `invoke_outlet` mints its own fresh `request_id`; pin the
        // descriptor to the stream B actually produced (all chunks share
        // it) so the §5.4.5 crossing verification accepts B's chunks.
        let descriptor = CrossContextVerificationDescriptor::new_for_test(
            op.verifying_key(),
            b_ctx_id,
            OUTLET.to_owned(),
            CB,
            b_chunks[0].request_id,
        );
        let (received, a_log, a_bytes) = drive_bridge(
            b_chunks.clone(),
            descriptor,
            permissive_schema(),
            None,
            None,
        )
        .await;
        assert_eq!(received.len(), 10, "all 10 chunks forwarded to A");

        let a_event =
            read_a_invoked(&a_log, &a_bytes).expect("A must record its OutletInvoked at close");
        let a_hash = a_event.stream_manifest_hash;

        assert_eq!(
            received, b_chunks,
            "every forwarded chunk is byte-identical to B's (operator sig preserved, \
                 never re-signed, no synthesized terminal on the happy path)"
        );
        assert_eq!(
            a_hash, b_hash,
            "both event logs record the same 32-byte stream_manifest_hash"
        );
        assert_ne!(
            a_hash, [0u8; 32],
            "a 10-chunk stream commits a non-sentinel root"
        );
        assert_eq!(a_event.stream_chunk_count, 10);
        assert_eq!(a_event.chunks_billed, DATA_CHUNKS, "9 billable Data leaves");
        assert_eq!(a_event.chunks_billed, b_event.chunks_billed);
    }

    // ---- AC7 reject: a mismatched chunks_billed is wire-rejected.

    #[tokio::test]
    async fn ac7_reject_chunks_billed_mismatch_refused_at_append() {
        let (a_log, a_bytes) = fresh_a_log().await;
        let op = operator_key();
        let chunks = vec![
            sign_chunk(
                &op,
                A_CTX,
                OUTLET,
                &CB,
                0,
                ChunkPayload::Data {
                    value: serde_json::json!({ "result": 1 }),
                },
            ),
            sign_chunk(
                &op,
                A_CTX,
                OUTLET,
                &CB,
                1,
                end_payload(serde_json::json!({ "result": 1 })),
            ),
        ];
        // A well-formed manifest over these chunks has chunks_billed == 1.
        // Record an event that LIES (chunks_billed == 5) and assert the
        // verified-append boundary refuses it (§5.4.5:566 wire-rejection).
        let manifest =
            scp_protocol::context::outlets::stream::compute_chunk_manifest_root(&chunks).unwrap();
        let mut terminal = StreamTerminalSummary::default();
        for c in &chunks {
            terminal.observe(&c.payload);
        }
        let bad_event =
            StreamingOutletEventForTest { request_id: RID, outlet_id: &OUTLET.to_owned(), invoker_did: &DID::from(INVOKER), input_hash: "input-hash".to_owned(), execution_time_ms: 5, stream_chunk_count: u32::try_from(chunks.len()).unwrap(), chunks_billed: 5, stream_manifest_hash: // WRONG: real billable count is 1.
            manifest, terminal: &terminal, audit_anomaly: None, cancel_ack_seq: None }
            .build();
        let err = a_log
            .append_outlet_invoked_verified(
                scp_runtime_core::context::builder::AppendMode::AfterSideEffect,
                &a_bytes,
                &bad_event,
                &chunks,
                INVOKER,
                0,
            )
            .await
            .expect_err("mismatched chunks_billed must be refused at log-insert");
        assert!(
            err.to_string().contains("ChunksBilled") || err.to_string().contains("chunks_billed"),
            "refusal must surface ChunksBilledMismatch, got: {err}"
        );
    }

    // ---- AC8: mid-stream bridge fault → terminal 6160.

    #[tokio::test]
    async fn ac8_mid_stream_bridge_failure_emits_transport_terminal() {
        let op = operator_key();
        let chunks = vec![
            sign_chunk(
                &op,
                B_CTX,
                OUTLET,
                &CB,
                0,
                ChunkPayload::Data {
                    value: serde_json::json!({ "result": 1 }),
                },
            ),
            sign_chunk(
                &op,
                B_CTX,
                OUTLET,
                &CB,
                1,
                ChunkPayload::Data {
                    value: serde_json::json!({ "result": 2 }),
                },
            ),
        ];
        // Force a bridge fault when processing sequence 1.
        let probe: BridgeFaultProbe = Box::new(|chunk: &OutletStreamChunk| {
            (chunk.sequence == 1).then(|| "injected re-encrypt fault".to_owned())
        });
        let (received, _a_log, _a_bytes) = drive_bridge(
            chunks,
            pinned_descriptor(&op),
            permissive_schema(),
            None,
            Some(probe),
        )
        .await;
        assert!(matches!(received[0].payload, ChunkPayload::Data { .. }));
        assert_terminal_error(received.last().unwrap(), CODE_TRANSPORT_FAULT);
    }

    // ---- AC9: End.aggregate violating aggregate_schema → terminal 6140.

    #[tokio::test]
    async fn ac9_end_aggregate_violation_emits_output_terminal() {
        let op = operator_key();
        // `summary` must be a string; a number violates aggregate_schema.
        let chunks = vec![sign_chunk(
            &op,
            B_CTX,
            OUTLET,
            &CB,
            0,
            end_payload(serde_json::json!({ "summary": 123 })),
        )];
        let (received, _a_log, _a_bytes) = drive_bridge(
            chunks,
            pinned_descriptor(&op),
            strict_output_schema(),
            Some(aggregate_schema()),
            None,
        )
        .await;
        assert_terminal_error(received.last().unwrap(), CODE_OUTPUT_VIOLATION);
    }

    // ---- AC10: seal-for-A over the existing MLS transport (see below).
    // (Implemented as a sibling sync test `ac10_seal_for_a_preserves_operator_sig`.)

    // ---- AC11: verify against the PINNED descriptor, never bridge input.

    #[tokio::test]
    async fn ac11_chunk_verified_against_pinned_descriptor_not_bridge_input() {
        let op = operator_key();
        // Direct helper check: a chunk signed under a DIFFERENT (bridge-
        // supplied) context_id fails verification against the pinned
        // descriptor (which pins B_CTX).
        let forged = sign_chunk(
            &op,
            "attacker-controlled-ctx",
            OUTLET,
            &CB,
            0,
            ChunkPayload::Data {
                value: serde_json::json!({ "result": 1 }),
            },
        );
        assert!(
            !verify_forwarded_chunk(&pinned_descriptor(&op), &forged),
            "a chunk signed under a non-pinned context_id must NOT verify"
        );
        // A correctly-signed chunk verifies.
        let genuine = sign_chunk(
            &op,
            B_CTX,
            OUTLET,
            &CB,
            0,
            ChunkPayload::Data {
                value: serde_json::json!({ "result": 1 }),
            },
        );
        assert!(verify_forwarded_chunk(&pinned_descriptor(&op), &genuine));

        // End-to-end: the bridge rejects the forged chunk with an
        // Authorization-class terminal rather than forwarding it.
        let (received, _a_log, _a_bytes) = drive_bridge(
            vec![forged],
            pinned_descriptor(&op),
            permissive_schema(),
            None,
            None,
        )
        .await;
        assert_terminal_error(received.last().unwrap(), CODE_AUTHORIZATION_DENIED);
    }

    // ---- ADR-049 Decision 16, item 2: a shutdown refusal is typed.

    /// Builds the `OpenStreamParams` + incoming open for a cross-context
    /// call that the gate tests below refuse before any stream opens.
    fn shutdown_gate_inputs() -> (
        scp_runtime_core::context::outlets::dispatch::OpenStreamParams,
        OutletStreamOpen,
    ) {
        let operator = operator_key();
        let params = scp_runtime_core::context::outlets::dispatch::OpenStreamParams {
            identity: scp_runtime_types::context::outlets::stream::StreamIdentity {
                context_id: B_CTX.to_owned(),
                outlet_id: OUTLET.to_owned(),
                stream_epoch: 1,
                caveats_binding: CB,
            },
            caps: scp_runtime_types::context::outlets::stream::AdmissionCaps {
                per_invoker: 10,
                per_origin_invoker: 10,
                per_outlet: 10,
            },
            invoker_did: INVOKER.to_owned(),
            origin_invoker_did: INVOKER.to_owned(),
            cost_per_chunk: scp_protocol::economy::types::Amount::new(0),
            available_balance: scp_protocol::economy::types::Amount::new(0),
            reserved_escrow: scp_protocol::economy::types::Amount::new(0),
            declared_estimated_chunk_count: Some(1),
            credit_window: 8,
            caveats: scp_protocol::trust::caveats::InvocationCaveats::empty(),
            invoker_pk: operator.verifying_key(),
            operator_signer: Arc::new(InProcessStreamSigner::new(operator)),
            stream_credit_stall_secs: 999,
            stream_cancel_ack_secs: 999,
            stream_ucan_recheck_secs: 999,
            ucan_cid: "bafy-shutdown-gate".to_owned(),
            request_id: RID,
            revocation_checker: Arc::new(
                scp_protocol::crypto::ucan::validate::InMemoryRevocationChecker::new(),
            ),
            economic_policy_snapshot: None,
        };
        let incoming = OutletStreamOpen {
            request_id: RID,
            outlet_id: OUTLET.to_owned(),
            input: serde_json::json!({}),
            invoker_did: DID::from(INVOKER),
            ucan: vec![0x01],
            caveats_binding: CB,
            chain_depth: 1,
            credit_window: 8,
            estimated_chunk_count: 1,
            session_id: None,
            timeout_ms: 1000,
        };
        (params, incoming)
    }

    /// Runs `invoke_outlet_cross_context` against an EMPTY registry, with
    /// the Supervisor's spawn gate closed or open.
    async fn cross_context_with_gate(
        gate_closed: bool,
    ) -> Result<mpsc::Receiver<OutletStreamChunk>, OutletOpenError> {
        let crypto = Arc::new(
            scp_runtime_core::crypto::mls::provider::NodeMlsFactory::new(
                INVOKER.to_owned(),
                Arc::new(scp_clock::SystemClock),
            ),
        );
        let supervisor = scp_runtime::test_supervisor(
            crypto,
            Box::new(scp_runtime_core::context::builder::NotConfiguredTransportProvider),
            Box::new(MerkleEventLogProvider::new()),
            Arc::new(|_, _| None),
        );
        if gate_closed {
            supervisor.close_spawn_gate_for_test();
        }
        let (a_log, _a_bytes) = fresh_a_log().await;
        let (params, incoming) = shutdown_gate_inputs();
        OutletCrossContextInvokeForTest::<NoOpExecutor> {
            supervisor: &supervisor,
            a_event_log: a_log,
            receiving_context_id: A_CTX,
            operating_context_id: B_CTX,
            registry: &OutletRegistry::new(),
            outlet_id: &OUTLET.to_owned(),
            input: serde_json::json!({}),
            invoker_did: &DID::from(INVOKER),
            timeout_ms: None,
            executor: Arc::new(NoOpExecutor),
            incoming_open: &incoming,
            caveat_binding: None,
            params,
        }
        .run()
        .await
    }

    /// Once shutdown has begun, a cross-context open is refused before the
    /// registry lookup with `SupervisorShutDown` (`SCP-CTX-2138`), never
    /// `ContextNotActive` or `ExecutionFailed` (the handler-panic surface).
    #[tokio::test]
    async fn closed_spawn_gate_refuses_cross_context_open_as_supervisor_shut_down() {
        let result = cross_context_with_gate(true).await;
        match result {
            Err(err @ OutletOpenError::SupervisorShutDown { .. }) => {
                let text = err.to_string();
                assert!(text.starts_with("SCP-CTX-2138: "), "got {text}");
                assert_eq!(text.matches("SCP-CTX-2138").count(), 1, "got {text}");
            }
            other => panic!("expected SupervisorShutDown, got {other:?}"),
        }
    }

    /// With the spawn gate open the shutdown check passes, and the same
    /// call reaches the registry lookup, which rejects the unknown outlet.
    #[tokio::test]
    async fn open_spawn_gate_passes_shutdown_check_to_registry_lookup() {
        let result = cross_context_with_gate(false).await;
        assert!(
            matches!(
                result,
                Err(OutletOpenError::Invocation(
                    InvocationError::OutletNotFound { .. }
                ))
            ),
            "an open gate must not refuse the open; got {result:?}"
        );
    }

    // ---- AC12: zero-escrow economy gate.

    fn registration_with_cost(kind: OutletKind, amount: u64) -> OutletRegistration {
        OutletRegistration {
            outlet_id: OUTLET.to_owned(),
            kind,
            name: "Calc".to_owned(),
            description: "d".to_owned(),
            schema: OutletSchema {
                input_schema: serde_json::json!({ "type": "object" }),
                output_schema: serde_json::json!({ "type": "object" }),
                aggregate_schema: None,
            },
            implementation_hash: [0u8; 32],
            test_vectors: vec![],
            operator_did: "did:dht:z6MkOperator".into(),
            cost: (amount > 0).then(|| scp_protocol::context::outlets::registry::OutletCost {
                amount: scp_protocol::economy::types::Amount::new(amount),
                currency: "USD".to_owned(),
                payee: "did:dht:z6MkPayee".into(),
                cost_formula: None,
            }),
            message_catalog: Vec::new(),
            registered_at: 0,
            signature: Vec::new(),
        }
    }

    #[test]
    fn ac12_paid_action_rejected_query_and_zero_cost_accepted() {
        use scp_protocol::economy::types::Amount;
        // Paid Action (cost.amount > 0) → rejected, no receiver ever built.
        // (`cost_per_chunk` matches the registered cost here.)
        let paid = registration_with_cost(OutletKind::Action, 10);
        let err = cross_context_economy_gate(&paid, Amount::new(10))
            .expect_err("a paid Action must be rejected zero-escrow");
        assert!(
            matches!(
                err,
                InvocationError::CrossContextPaidActionUnsupported { .. }
            ),
            "got {err:?}"
        );

        // Zero-cost Action + zero cost_per_chunk → accepted.
        cross_context_economy_gate(
            &registration_with_cost(OutletKind::Action, 0),
            Amount::new(0),
        )
        .expect("zero-cost Action proceeds");
        // Query (no cost) + zero cost_per_chunk → accepted.
        cross_context_economy_gate(
            &registration_with_cost(OutletKind::Query, 0),
            Amount::new(0),
        )
        .expect("Query proceeds");
    }

    /// FIX 2 — split-source / paid-best-effort bypass. A registration with
    /// `cost == 0` but a positive BILLED `cost_per_chunk` is REJECTED (not
    /// silently billed): the gate is enforced on the value that actually
    /// drives billing, not only the declared registration cost. The
    /// symmetric case (registered cost > 0 but `cost_per_chunk == 0`) is
    /// likewise rejected — either positive value trips the zero-escrow gate.
    #[test]
    fn fix2_zero_registered_cost_with_positive_cost_per_chunk_rejected() {
        use scp_protocol::economy::types::Amount;

        // Zero registered cost, positive billed cost_per_chunk → REJECTED.
        let zero_cost = registration_with_cost(OutletKind::Action, 0);
        let err = cross_context_economy_gate(&zero_cost, Amount::new(7))
            .expect_err("a zero registered cost with a positive cost_per_chunk must be rejected");
        assert!(
            matches!(
                err,
                InvocationError::CrossContextPaidActionUnsupported { .. }
            ),
            "the billed value drives the zero-escrow gate; got {err:?}"
        );

        // Positive registered cost, zero cost_per_chunk → also REJECTED
        // (paid registration cannot be smuggled through as zero-escrow).
        let paid = registration_with_cost(OutletKind::Action, 5);
        assert!(
            matches!(
                cross_context_economy_gate(&paid, Amount::new(0)),
                Err(InvocationError::CrossContextPaidActionUnsupported { .. })
            ),
            "a positive registered cost is rejected regardless of cost_per_chunk"
        );

        // Both zero → the only accepted shape.
        cross_context_economy_gate(&zero_cost, Amount::new(0))
            .expect("both zero is the only accepted zero-escrow shape");
    }

    // ---- FIX 3: terminal-less truncation — B drops its sender with no
    //             terminal → A's last chunk is a synthesized 6160.

    #[tokio::test]
    async fn fix3_data_only_without_terminal_synthesizes_transport_fault() {
        let op = operator_key();
        // A Data-only sequence whose producer drops the inner sender with NO
        // terminal chunk — models B's pump collapsing at the terminal chunk
        // (`try_build_signed_chunk` → `None` on an operator-signer failure).
        let chunks = vec![
            sign_chunk(
                &op,
                B_CTX,
                OUTLET,
                &CB,
                0,
                ChunkPayload::Data {
                    value: serde_json::json!({ "result": 0 }),
                },
            ),
            sign_chunk(
                &op,
                B_CTX,
                OUTLET,
                &CB,
                1,
                ChunkPayload::Data {
                    value: serde_json::json!({ "result": 1 }),
                },
            ),
        ];
        let (received, _a_log, _a_bytes) = drive_bridge(
            chunks,
            pinned_descriptor(&op),
            permissive_schema(),
            None,
            None,
        )
        .await;
        // A never truncates after a non-terminal Data: the two Data chunks
        // are followed by a SYNTHESIZED terminal transport-fault at the next
        // sequence (§5.4.5 terminal guarantee).
        assert_eq!(received.len(), 3, "two Data + one synthesized terminal");
        assert!(matches!(received[0].payload, ChunkPayload::Data { .. }));
        assert!(matches!(received[1].payload, ChunkPayload::Data { .. }));
        assert_terminal_error(received.last().unwrap(), CODE_TRANSPORT_FAULT);
        assert_eq!(
            received.last().unwrap().sequence,
            2,
            "the synthesized terminal is at last_delivered_sequence + 1"
        );
    }

    // ---- FIX 4: unbounded reassembly — an unbilled Progress flood is
    //             terminated at the retained-chunk cap with a 6160.

    #[tokio::test]
    async fn fix4_overlong_stream_terminated_with_transport_fault() {
        // A deliberately small retained-chunk cap so the test exercises the
        // ceiling without emitting a million chunks.
        const CAP: usize = 3;
        let op = operator_key();
        let (a_log, _a_bytes) = fresh_a_log().await;
        let a_dyn: Arc<dyn ContextEventLogProvider> = a_log.clone();
        let (inner_tx, inner_rx) = mpsc::channel::<OutletStreamChunk>(1);
        let (outer_tx, mut outer_rx) = mpsc::channel::<OutletStreamChunk>(1);
        let bridge = tokio::spawn(
            CrossContextBridgeForTest {
                inner_rx,
                outer_tx,
                descriptor: pinned_descriptor(&op),
                output_schema: permissive_schema(),
                aggregate_schema: None,
                a_event_log: a_dyn,
                receiving_context_id: A_CTX.to_owned(),
                invoker_did: DID::from(INVOKER),
                request_id: RID,
                outlet_id: OUTLET.to_owned(),
                input_hash: "input-hash".to_owned(),
                governing_chain_depth: 3,
                timestamp_secs: 0,
                max_retained_chunks: CAP,
                fault_probe: None,
            }
            .run(),
        );

        // Flood the bridge with UNBILLED Progress chunks (never terminal),
        // far past the cap — the pre-fix bridge would retain all of them.
        let producer = {
            let op = op.clone();
            tokio::spawn(async move {
                for seq in 0..1_000u64 {
                    let chunk = sign_chunk(
                        &op,
                        B_CTX,
                        OUTLET,
                        &CB,
                        seq,
                        ChunkPayload::Progress { pct: 0, note: None },
                    );
                    if inner_tx.send(chunk).await.is_err() {
                        break;
                    }
                }
            })
        };

        let mut received = Vec::new();
        while let Some(chunk) = outer_rx.recv().await {
            received.push(chunk);
        }
        let _ = producer.await;
        bridge.await.expect("bridge");

        // The retained snapshot never grew unboundedly: the stream is
        // terminated with a transport-fault once the cap is reached.
        assert!(
            received.len() <= CAP + 1,
            "retained chunks + terminal are bounded by the cap; got {}",
            received.len()
        );
        assert_terminal_error(received.last().unwrap(), CODE_TRANSPORT_FAULT);
    }

    // ---- FIX 5: cross-stream replay — a chunk validly signed for a
    //             DIFFERENT request_id is rejected at the crossing.

    #[tokio::test]
    async fn fix5_chunk_with_foreign_request_id_rejected() {
        // A chunk VALIDLY signed by B's operator for a DIFFERENT stream
        // (request_id RID2) — same outlet, same caveats_binding, same
        // operator key — i.e. a genuine chunk from another same-outlet stream.
        const RID2: RequestId = [0xCD; 16];
        let op = operator_key();
        let payload = ChunkPayload::Data {
            value: serde_json::json!({ "result": 1 }),
        };
        let preimage =
            compute_chunk_sig_preimage(B_CTX, OUTLET, &RID2, 0, &CB, &payload).expect("preimage");
        let sig = op.sign(&preimage).to_bytes();
        let foreign = OutletStreamChunk {
            request_id: RID2,
            sequence: 0,
            payload,
            sig,
        };

        // Its operator signature IS valid for its own stream (RID2)...
        assert!(
            scp_protocol::context::outlets::stream::verify_chunk_signature(
                &foreign,
                &op.verifying_key(),
                B_CTX,
                OUTLET,
                &CB,
            ),
            "the chunk carries a valid operator signature for its own stream (RID2)"
        );
        // ...but the crossing pins request_id RID, so verification REJECTS it
        // — the rejection is due to the foreign request_id, not a bad sig.
        assert!(
            !verify_forwarded_chunk(&pinned_descriptor(&op), &foreign),
            "a chunk asserting a request_id other than the pinned one must NOT verify"
        );

        // End-to-end: the bridge emits the AC11 Authorization-class terminal.
        let (received, _a_log, _a_bytes) = drive_bridge(
            vec![foreign],
            pinned_descriptor(&op),
            permissive_schema(),
            None,
            None,
        )
        .await;
        assert_terminal_error(received.last().unwrap(), CODE_AUTHORIZATION_DENIED);
    }

    // -----------------------------------------------------------------
    // SCP-OUT-044 — no bridge-minted send-sequence anchor: the cross-
    // context bridge forwards bare `OutletStreamChunk`s and the same-context
    // path is unchanged. A's per-sender MLS send-sequence is the A-context
    // re-seal's, reserved at the §9.16/§5.15.7 encrypt seam over A's
    // persistent counter (SCP-OUT-047) — never a bridge-local counter.
    // -----------------------------------------------------------------

    /// AC5 — the SAME-CONTEXT stream path is UNCHANGED: `invoke_outlet`
    /// still returns a BARE `mpsc::Receiver<OutletStreamChunk>` — identical
    /// to what the cross-context bridge now returns. Compile-level proof: the
    /// explicit annotation fails to compile if the same-context return type
    /// drifts. The existing same-context runtime drain tests are the
    /// behavioural regression.
    #[allow(dead_code)]
    async fn out044_same_context_returns_bare_chunks(
        context: &ContextHandle,
        registry: &OutletRegistry,
        role_state: &ContextRoleState,
        outlet_id: &OutletId,
        invoker_did: &DID,
    ) {
        let out: Result<mpsc::Receiver<OutletStreamChunk>, InvocationError> =
            invoke_outlet::<NoOpExecutor>(
                context,
                registry,
                role_state,
                outlet_id,
                serde_json::json!({}),
                invoker_did,
                None,
                Arc::new(NoOpExecutor),
                None,
                None,
                None,
                test_signer(),
                [0u8; 32],
                &|task| drop(tokio::spawn(task)),
            )
            .await;
        drop(out);
    }

    // -----------------------------------------------------------------
    // SCP-OUT-045 — the cross-context bridge forwards the dispatch pump's
    // contiguously-renumbered, re-signed stream VERBATIM. There is NO
    // runtime-side reassembly gap-detector: `inner_rx` is fed by the
    // dispatch pump (dispatch.rs), which renumbers to its own contiguous
    // cursor and re-signs under it, so `chunk.sequence` at the bridge is
    // contiguous BY CONSTRUCTION. Gap-detection over the lossy A-leg is the
    // receive-side SDK-drain's (`ReceiverSequenceTracker`, SCP-OUT-037;
    // §5.4.5:515). These tests assert the bridge forwards a lossless stream
    // to its operator terminal without synthesizing any error terminal.
    // -----------------------------------------------------------------

    /// SCP-OUT-045 — a contiguous cross-context 10-chunk stream (the
    /// dispatch pump assigns sequence 0..9 consecutively) forwards verbatim:
    /// all ten chunks are delivered and the stream ends in the operator's
    /// own `End`, with no synthesized error terminal.
    #[tokio::test]
    async fn out045_lossless_contiguous_ten_chunk_stream_forwards_verbatim() {
        let op = operator_key();
        // 9 Data (seq 0..=8) + operator End (seq 9) = a contiguous 10-chunk
        // A→B stream.
        let mut chunks = Vec::new();
        for seq in 0..9u64 {
            chunks.push(sign_chunk(
                &op,
                B_CTX,
                OUTLET,
                &CB,
                seq,
                ChunkPayload::Data {
                    value: serde_json::json!({ "n": seq }),
                },
            ));
        }
        chunks.push(sign_chunk(
            &op,
            B_CTX,
            OUTLET,
            &CB,
            9,
            end_payload(serde_json::json!({ "n": 9 })),
        ));

        let (received, _a_log, _a_bytes) = drive_bridge(
            chunks,
            pinned_descriptor(&op),
            permissive_schema(),
            None,
            None,
        )
        .await;

        assert_eq!(
            received.len(),
            10,
            "all ten contiguous chunks forwarded, no synthesized terminal"
        );
        assert!(
            matches!(received.last().unwrap().payload, ChunkPayload::End { .. }),
            "a lossless stream ends in the operator's End, not a synthesized terminal"
        );
        assert!(
            !received
                .iter()
                .any(|c| { matches!(&c.payload, ChunkPayload::Error { .. }) }),
            "a lossless contiguous stream is forwarded verbatim, with no synthesized error \
                 terminal"
        );
    }

    /// Counts the refunds the escrow ticket's `Drop` requests for `B_CTX`.
    #[derive(Default)]
    struct RecordingRefundSink {
        calls: AtomicU64,
        amount: AtomicU64,
    }

    impl scp_runtime_core::context::outlets::dispatch::StreamEscrowRefundSink for RecordingRefundSink {
        fn refund(
            &self,
            context_id: &str,
            _member_did: &DID,
            amount: scp_protocol::economy::types::Amount,
        ) {
            assert_eq!(context_id, B_CTX, "the refund targets the ticket's context");
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.amount.fetch_add(amount.value(), Ordering::SeqCst);
        }
    }

    /// ADR-049 Decision 16: a streaming-saga seal task whose Supervisor has
    /// dropped sends no `CommitBStreamSettle`, drops the escrow ticket
    /// (whose `Drop` asks its sink for the refund), and returns.
    #[tokio::test]
    async fn seal_task_with_dropped_supervisor_drops_the_ticket_and_returns() {
        let (a_log, _) = fresh_a_log().await;
        let sink = Arc::new(RecordingRefundSink::default());
        let ticket = scp_runtime_core::context::outlets::dispatch::StreamEscrowTicket::new(
            Arc::clone(&sink)
                as Arc<dyn scp_runtime_core::context::outlets::dispatch::StreamEscrowRefundSink>,
            B_CTX.to_owned(),
            DID(INVOKER.to_owned()),
            scp_protocol::economy::types::Amount::new(40),
        );
        let (inner_tx, inner_rx) = mpsc::channel::<OutletStreamChunk>(1);
        drop(inner_tx);
        let (outer_tx, mut outer_rx) = mpsc::channel::<OutletStreamChunk>(4);
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            StreamingSagaSealTaskForTest {
                supervisor: std::sync::Weak::new(),
                target_context_hex: B_CTX.to_owned(),
                saga_id: scp_runtime_types::context::supervisor::saga_journal::SagaId(
                    "saga-dropped-sup".to_owned(),
                ),
                target_signer:
                    scp_runtime_core::context::actor::signer::CommandSigner::local_ed25519(
                        operator_key(),
                    ),
                inner_rx,
                outer_tx,
                escrow_ticket: ticket,
                descriptor: pinned_descriptor(&operator_key()),
                output_schema: permissive_schema(),
                aggregate_schema: None,
                a_event_log: a_log as Arc<dyn ContextEventLogProvider>,
            }
            .run(),
        )
        .await
        .expect("the seal task returns when the Supervisor has dropped");
        assert_eq!(
            (
                sink.calls.load(Ordering::SeqCst),
                sink.amount.load(Ordering::SeqCst)
            ),
            (1, 40),
            "the unsealed ticket is dropped unconsumed, so its sink is asked once"
        );
        while outer_rx.recv().await.is_some() {}
    }
}

// =====================================================================
// SCP-OUT-036 AC10 — seal one chunk for A over the EXISTING MLS transport
// =====================================================================
#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod cross_context_036_seal {
    use ed25519_dalek::{Signer as _, SigningKey};

    use scp_protocol::context::outlets::stream::{
        ChunkPayload, OutletStreamChunk, compute_chunk_sig_preimage, verify_chunk_signature,
    };

    const B_CTX: &str = "ctx-b-036-seal";
    const OUTLET: &str = "calculator";
    const CB: [u8; 32] = [0x11; 32];
    const RID: [u8; 16] = [0xAB; 16];

    fn operator_signed_chunk() -> OutletStreamChunk {
        let operator = SigningKey::from_bytes(&[0x5c; 32]);
        let payload = ChunkPayload::Data {
            value: serde_json::json!({ "result": 7 }),
        };
        let preimage = compute_chunk_sig_preimage(B_CTX, OUTLET, &RID, 0, &CB, &payload).unwrap();
        let sig = operator.sign(&preimage).to_bytes();
        OutletStreamChunk {
            request_id: RID,
            sequence: 0,
            payload,
            sig,
        }
    }

    /// AC10 — seal ONE operator-signed chunk as an A-context MLS application
    /// message via the EXISTING `NodeMlsFactory::seal`/`open` (no invented
    /// envelope): (a) a non-A-member cannot decrypt it, (b) an A member
    /// recovers the chunk with B's operator signature INTACT and verifying
    /// against B's pinned `context_id` — never re-signed by the bridge.
    #[test]
    fn ac10_seal_for_a_preserves_operator_sig() {
        use scp_did::DID;
        use scp_protocol::context::builder::OpenResult;
        use scp_runtime_core::context::actor::state::PerContextState;
        use scp_runtime_core::crypto::mls::two_party_test_support::{
            TwoPartyPair, stand_up_two_party,
        };
        use scp_runtime_core::envelope::inner::sign::create_inner_envelope_raw;
        use scp_runtime_core::envelope::inner::{
            InnerEnvelopeParams, MessageType, SCP_INNER_ENVELOPE_VERSION,
        };

        let a_ctx_str = "a-ctx-036-seal";
        let alice_did = "did:dht:z6MkAliceAliceAliceAliceAliceAliceAliceAl";
        let bob_did = "did:dht:z6MkBobBobBobBobBobBobBobBobBobBobBobBobBo";
        // Alice (sealer, A member) + Bob (opener, A member) share a real MLS
        // group for the receiving context A, born DIRECTLY onto actor-owned
        // state via the #2148 owned-return constructors (no provider
        // `take_crypto_state` round-trip) — the actor seal/open seam every
        // other two-party crypto test now drives.
        let TwoPartyPair {
            alice_state: mut alice_a,
            bob_state: mut bob_a,
            ctx_bytes: a_ctx_bytes,
            ..
        } = stand_up_two_party(
            a_ctx_str,
            alice_did,
            bob_did,
            scp_runtime::domain_handlers(),
        );

        let chunk = operator_signed_chunk();
        let operator_pk = SigningKey::from_bytes(&[0x5c; 32]).verifying_key();
        // The chunk bytes are the InnerEnvelope payload — the bridge wraps
        // the still-operator-signed chunk; it does NOT invent a new envelope.
        let chunk_bytes = serde_json::to_vec(&chunk).unwrap();

        // The forwarding member (Alice) signs the OUTER inner-envelope with
        // her own key; the CHUNK inside keeps B's operator signature.
        let sender_key = SigningKey::from_bytes(&[0x24; 32]);
        let build_inner = |seq: u64| {
            let params = InnerEnvelopeParams {
                version: SCP_INNER_ENVELOPE_VERSION,
                context_id: a_ctx_str,
                sender_did: alice_did,
                epoch: 0,
                generation: 0,
                sequence: seq,
                timestamp: 1_700_000_000,
                message_type: MessageType::Content,
                payload: &chunk_bytes,
                provenance: None,
                signing_key_id: scp_did::SigningKeyId::Active,
            };
            create_inner_envelope_raw(&params, &sender_key).unwrap()
        };

        // Two independently-sealed copies (MLS forward secrecy consumes the
        // per-message secret on first open of a given ciphertext). Each actor
        // `seal` advances the send tracker exactly as the provider's
        // `send_sequence` did (AAD sequence 0 then 1).
        let sealed_for_outsider = alice_a.seal(alice_did, &build_inner(0)).unwrap();
        let sealed_for_member = alice_a.seal(alice_did, &build_inner(1)).unwrap();

        // (a) A non-A-member (fresh actor, no A group key) CANNOT decrypt:
        // an empty encrypted-mode `PerContextState` holds no MLS group, so
        // `open` fails closed with "no MLS group for this context".
        let mut outsider_a = PerContextState::new_for_test_encrypted(
            a_ctx_bytes,
            0,
            DID::from("did:dht:z6MkOutsiderOutsiderOutsiderOutsiderOut".to_owned()),
        );
        assert!(
            outsider_a.open(a_ctx_str, &sealed_for_outsider).is_err(),
            "a non-A-member holding no A group key must not decrypt the sealed chunk"
        );

        // (b) An A member decrypts and recovers the chunk with B's operator
        // signature intact and verifying against B's PINNED context_id.
        let opened = bob_a.open(a_ctx_str, &sealed_for_member).unwrap();
        let recovered_bytes = match opened {
            OpenResult::Application(env) => env.inner.payload,
            other => panic!("expected Application, got {other:?}"),
        };
        // The inner-envelope payload is length-padded for traffic-analysis
        // resistance, so stream-deserialize the FIRST JSON value and ignore
        // trailing padding bytes.
        let recovered: OutletStreamChunk = {
            use serde::Deserialize as _;
            let mut de = serde_json::Deserializer::from_slice(&recovered_bytes);
            OutletStreamChunk::deserialize(&mut de).unwrap()
        };
        assert_eq!(
            recovered, chunk,
            "A member recovers the exact operator chunk"
        );
        assert!(
            verify_chunk_signature(&recovered, &operator_pk, B_CTX, OUTLET, &CB),
            "B's operator SCP-OUTLET-CHUNK-SIG-V1 signature is preserved end-to-end \
                 (never re-signed by the bridge) and verifies against B's pinned context_id"
        );
    }
}
