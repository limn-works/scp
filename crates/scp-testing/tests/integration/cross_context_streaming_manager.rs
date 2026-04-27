//! SCP-OUT-036 — production cross-context streaming through the
//! [`ContextManager`] public API.
//!
//! The audit caught `invoke_outlet_cross_context` (the §6.2.0.5 bridge
//! free function) as ghost code: 5 `#[tokio::test]` callers, 0 production
//! callers. Remediation added
//! [`ContextManager::invoke_outlet_streaming_cross_context`] as the public
//! production entry point. These tests verify the production path:
//!
//!  1. End-to-end happy path — a simulated executor in the target context
//!     emits 10 `Data` chunks plus a single `End`, and the source-context
//!     caller invoking through `ContextManager` receives 11 chunks under
//!     a fresh source-side `request_id`. Both event-log records share the
//!     same `stream_manifest_hash`.
//!  2. Mid-stream bridge failure — the executor disconnects without
//!     emitting a terminal chunk. The bridge synthesizes a terminal
//!     `ChunkPayload::Error` whose typed [`OutletError`] envelope carries
//!     `code = "SCP-TOOL-6160"` (slug `transport.cross-context-bridge-failure`,
//!     §5.4.4) and a §6.2.0.5 `ContextHop` chain via the SCP-OUT-029
//!     wrap path.
//!
//! Path A (per §5.4.4 registry): the bridge-failure code is
//! `SCP-TOOL-6160` — `transport.cross-context-bridge-failure` is a slug
//! within the Transport-class shared-code 6160. The reserved gap
//! `SCP-TOOL-6161..=6169` is NOT used here. AC9 in
//! `.docs/prds/outlet.json` was updated from a tentative 6161 to 6160 so
//! spec, registry, and AC are aligned.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};

use ed25519_dalek::SigningKey;
use scp_core::context::builder::{
    ContextCreationError, ContextCryptoProvider, ContextEventLogProvider, ContextTransportProvider,
};
use scp_core::context::governance::KeyResolver;
use scp_core::context::manager::{
    BridgeHopSaltClosure, BridgeMemberClosure, ContextManager, CrossContextInvokeInputs,
    OuterCallerStems,
};
use scp_core::context::{AddMemberOutput, ContextError, ContextParams, RemoveMemberOutput};
use scp_identity::DID;
use scp_protocol::context::outlets::OutletKind;
use scp_protocol::context::outlets::error_codes::{
    CODE_TRANSPORT_FAULT, SLUG_TRANSPORT_CROSS_CONTEXT_BRIDGE_FAILURE,
};
use scp_protocol::context::outlets::errors::{MAX_TRAIL_PAD_DEPTH, OutletError};
use scp_protocol::context::outlets::stream::{
    ChunkPayload, OutletStreamChunk, RequestId, sign_chunk,
};

// ---------------------------------------------------------------------------
// Mock providers — minimal no-op implementations sufficient for
// constructing a ContextManager. The cross-context streaming bridge is
// a self-contained pipeline that does not read from per-context manager
// state, so no-op providers are sufficient to prove the public-API path
// is reachable. Mirrors the mocks in
// `tests/integration/outlet_economy_wiring.rs`.
// ---------------------------------------------------------------------------

#[derive(Default)]
struct MockCrypto;

impl ContextCryptoProvider for MockCrypto {
    fn validate_creator_identity(&self) -> Result<(), ContextCreationError> {
        Ok(())
    }
    fn create_mls_group(&self, _id: &[u8; 32]) -> Result<(), ContextCreationError> {
        Ok(())
    }
    fn generate_sender_key(&self, _id: &[u8; 32]) -> Result<(), ContextCreationError> {
        Ok(())
    }
    fn init_broadcast_key(&self, _id: &[u8; 32]) -> Result<(), ContextCreationError> {
        Ok(())
    }
    fn destroy_mls_group(&self, _id: &[u8; 32]) -> Result<(), ContextCreationError> {
        Ok(())
    }
    fn destroy_sender_key(&self, _id: &[u8; 32]) -> Result<(), ContextCreationError> {
        Ok(())
    }
    fn validate_key_package(
        &self,
        _owner_did: &str,
        _key_package_bytes: Option<&[u8]>,
    ) -> Result<(), ContextError> {
        Ok(())
    }
    fn add_member(
        &self,
        _ctx_id: &[u8; 32],
        _member_did: &str,
        _key_package_bytes: Option<&[u8]>,
    ) -> Result<AddMemberOutput, ContextError> {
        Ok(AddMemberOutput::default())
    }
    fn remove_member(
        &self,
        _ctx_id: &[u8; 32],
        _member_did: &str,
    ) -> Result<RemoveMemberOutput, ContextError> {
        Ok(RemoveMemberOutput::default())
    }
    fn distribute_sender_key(
        &self,
        _ctx_id: &[u8; 32],
        _member_did: &str,
    ) -> Result<(), ContextError> {
        Ok(())
    }
    fn remove_member_sender_key(
        &self,
        _ctx_id: &[u8; 32],
        _member_did: &str,
    ) -> Result<(), ContextError> {
        Ok(())
    }
    fn seal(
        &self,
        _context_id: &[u8; 32],
        inner: &scp_core::envelope::inner::InnerEnvelope,
        _routing_id: &[u8],
        _blob_ttl: u32,
    ) -> Result<Vec<u8>, ContextError> {
        rmp_serde::to_vec_named(inner)
            .map_err(|e| ContextError::CryptoFailed(format!("mock seal: {e}")))
    }
    fn open(
        &self,
        _context_id: &[u8; 32],
        outer_bytes: &[u8],
    ) -> Result<scp_core::context::builder::OpenResult, ContextError> {
        let inner: scp_core::envelope::inner::InnerEnvelope = rmp_serde::from_slice(outer_bytes)
            .map_err(|e| ContextError::CryptoFailed(format!("mock open: {e}")))?;
        let sender_did = inner.sender_did.clone();
        Ok(scp_core::context::builder::OpenResult::Application(
            Box::new(scp_core::context::builder::OpenedEnvelope { inner, sender_did }),
        ))
    }
}

#[derive(Default)]
struct MockTransport {
    connected: AtomicBool,
}

impl MockTransport {
    fn connected() -> Self {
        let t = Self::default();
        t.connected.store(true, Ordering::Relaxed);
        t
    }
}

impl ContextTransportProvider for MockTransport {
    fn is_connected(&self) -> bool {
        self.connected.load(Ordering::Relaxed)
    }
    fn publish_context(
        &self,
        _id: &[u8; 32],
        _params: &ContextParams,
    ) -> Result<(), ContextCreationError> {
        Ok(())
    }
    fn delete_published(&self, _id: &[u8; 32]) -> Result<(), ContextCreationError> {
        Ok(())
    }
    fn send_message(
        &self,
        _ctx_id: &[u8; 32],
        _encrypted_payload: &[u8],
    ) -> Result<(), ContextError> {
        Ok(())
    }
}

#[derive(Default)]
struct MockEventLog {
    events: Mutex<Vec<([u8; 32], String)>>,
}

impl ContextEventLogProvider for MockEventLog {
    fn init_event_log(&self, _id: &[u8; 32]) -> Result<(), ContextCreationError> {
        Ok(())
    }
    fn append_event(
        &self,
        id: &[u8; 32],
        event: &str,
        _actor_did: &str,
        _payload: Option<&serde_json::Value>,
    ) -> Result<(), ContextCreationError> {
        self.events.lock().unwrap().push((*id, event.to_owned()));
        Ok(())
    }
    fn destroy_event_log(&self, _id: &[u8; 32]) -> Result<(), ContextCreationError> {
        Ok(())
    }
}

fn noop_key_resolver() -> KeyResolver {
    std::sync::Arc::new(|_did: &DID| None)
}

const SOURCE_CTX: &str = "ctx-source-out036";
const TARGET_CTX: &str = "ctx-target-out036";
const OUTLET_ID: &str = "outlet-stream-out036";
const INVOKER_DID: &str = "did:dht:z6MkInvokerOUT036";

fn target_signing_key() -> SigningKey {
    SigningKey::from_bytes(&[5u8; 32])
}

fn source_signing_key() -> SigningKey {
    SigningKey::from_bytes(&[6u8; 32])
}

fn output_schema() -> serde_json::Value {
    serde_json::json!({
        "type": "object",
        "properties": {
            "kind": {"type": "string"},
            "n": {"type": "integer"}
        },
        "required": ["kind", "n"]
    })
}

fn data_value(n: i64) -> serde_json::Value {
    serde_json::json!({"kind": "tick", "n": n})
}

/// Builds the production-path bridge inputs. Source observer holds
/// membership in both contexts and both stems on the inner outlet, so
/// errors are observed without §5.4.4 oracle collapse — the test can
/// then assert on the un-collapsed wrapped envelope.
fn full_visibility_inputs() -> CrossContextInvokeInputs {
    let member_of: BridgeMemberClosure = Arc::new(|c: &str| matches!(c, SOURCE_CTX | TARGET_CTX));
    let hop_salts: BridgeHopSaltClosure = Arc::new(|_: &str| Some([0xEE; 32]));
    CrossContextInvokeInputs {
        source_context_id: SOURCE_CTX.to_owned(),
        target_context_id: TARGET_CTX.to_owned(),
        outlet_id: OUTLET_ID.to_owned(),
        source_caveats_binding: [0xAB; 32],
        target_caveats_binding: [0xCD; 32],
        chain_depth: 3,
        stream_epoch: 7,
        source_operator_key: Arc::new(source_signing_key()),
        aggregate_schema: None,
        output_schema: output_schema(),
        invoker_did: INVOKER_DID.to_owned(),
        source_member_of_context: member_of,
        source_hop_salts: hop_salts,
        source_outer_caller_stems: OuterCallerStems {
            holds_query: true,
            holds_call: true,
        },
        inner_outlet_kind: Some(OutletKind::Action),
        max_padded_trail_depth: MAX_TRAIL_PAD_DEPTH,
    }
}

fn build_executor_data_chunk(request_id: &RequestId, sequence: u64, n: i64) -> OutletStreamChunk {
    let key = target_signing_key();
    let payload = ChunkPayload::Data {
        value: data_value(n),
    };
    let sig = sign_chunk(
        &key,
        TARGET_CTX,
        OUTLET_ID,
        request_id,
        sequence,
        &[0xCD; 32],
        &payload,
    )
    .unwrap();
    OutletStreamChunk {
        request_id: *request_id,
        sequence,
        payload,
        sig,
    }
}

fn build_executor_end_chunk(
    request_id: &RequestId,
    sequence: u64,
    final_n: i64,
) -> OutletStreamChunk {
    let key = target_signing_key();
    let payload = ChunkPayload::End {
        aggregate: data_value(final_n),
        provenance: scp_protocol::provenance::DataProvenance {
            source_context: TARGET_CTX.to_owned(),
            source_type: scp_protocol::provenance::SourceType::Persistent,
            counterparties: Vec::new(),
            purpose: None,
            discovery_method: scp_protocol::provenance::DiscoveryMethod::OutOfBand,
            age: std::time::Duration::from_secs(0),
            memory_scope: scp_protocol::context::params::MemoryScope::Full,
            chain_depth: 3,
            chain_path: None,
            payment_amount: None,
            payment_adapter: None,
            payment_receipt_id: None,
        },
        execution_time_ms: 100,
    };
    let sig = sign_chunk(
        &key,
        TARGET_CTX,
        OUTLET_ID,
        request_id,
        sequence,
        &[0xCD; 32],
        &payload,
    )
    .unwrap();
    OutletStreamChunk {
        request_id: *request_id,
        sequence,
        payload,
        sig,
    }
}

/// Decodes a bridge-emitted terminal Error chunk back to its typed
/// [`OutletError`] envelope. The wire form is hex-encoded canonical
/// `MessagePack` of the `OutletError`, per §5.4.4.
fn decode_envelope_from_chunk(chunk: &OutletStreamChunk) -> OutletError {
    let ChunkPayload::Error { message, .. } = &chunk.payload else {
        panic!("expected terminal Error chunk, got {:?}", chunk.payload);
    };
    let bytes = hex::decode(message).expect("envelope hex-encoded");
    rmp_serde::from_slice(&bytes).expect("envelope MessagePack-encoded")
}

fn build_manager() -> ContextManager {
    ContextManager::new(
        Box::new(MockCrypto),
        Box::new(MockTransport::connected()),
        Box::new(MockEventLog::default()),
        noop_key_resolver(),
    )
}

// ---------------------------------------------------------------------------
// AC: cross-context 10-chunk stream A → B completes successfully when
// the caller invokes through the public ContextManager API. Both
// event-log records agree on `stream_manifest_hash`.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn manager_cross_context_stream_completes_round_trip() {
    let manager = build_manager();
    let inputs = full_visibility_inputs();

    let (etx, erx) = tokio::sync::mpsc::channel::<OutletStreamChunk>(64);

    // Production entry point — the new ContextManager method.
    let (request_id, mut bridge) = manager.invoke_outlet_streaming_cross_context(inputs, erx);

    // Simulate the target-context executor emitting 10 Data chunks
    // followed by a terminal End. The chunks are signed by the target
    // operator under the target's caveats_binding; the bridge re-issues
    // them under the source identity.
    let target_request_id: RequestId = *uuid::Uuid::now_v7().as_bytes();
    let exec_task = tokio::spawn(async move {
        for n in 0..10i64 {
            let chunk = build_executor_data_chunk(&target_request_id, n.cast_unsigned(), n);
            etx.send(chunk).await.unwrap();
        }
        let end = build_executor_end_chunk(&target_request_id, 10, 9);
        etx.send(end).await.unwrap();
        drop(etx);
    });

    let mut received: Vec<OutletStreamChunk> = Vec::new();
    while let Some(c) = bridge.receiver.recv().await {
        received.push(c);
    }
    exec_task.await.unwrap();

    assert_eq!(
        received.len(),
        11,
        "10 Data + 1 End forwarded through bridge"
    );
    // Source-side request_id is fresh (not the target's) and bound into
    // every re-issued chunk per §5.4.5.
    assert_ne!(request_id, target_request_id);
    for (i, c) in received.iter().enumerate() {
        assert_eq!(
            c.request_id, request_id,
            "re-issued under source request_id"
        );
        assert_eq!(c.sequence, i as u64, "sequence is monotonic from 0");
    }
    for c in &received[..10] {
        assert!(matches!(&c.payload, ChunkPayload::Data { .. }));
    }
    assert!(matches!(
        &received.last().unwrap().payload,
        ChunkPayload::End { .. }
    ));

    // §6.2.0.5: source and target event-log records must agree on
    // `stream_manifest_hash`.
    let completion = bridge
        .event_handle
        .await_completion()
        .await
        .expect("bridge completion handle resolves");
    assert_eq!(
        completion.source_event.stream_manifest_hash, completion.target_event.stream_manifest_hash,
        "both event logs must agree on stream_manifest_hash per §6.2.0.5"
    );
    assert_ne!(
        completion.stream_manifest_hash, [0u8; 32],
        "manifest hash must be non-zero for a successful 11-chunk stream"
    );
    assert_eq!(completion.source_event.stream_chunk_count, 11);
}

// ---------------------------------------------------------------------------
// AC9 (Path A — code is SCP-TOOL-6160 per §5.4.4 registry): mid-stream
// bridge failure produces a terminal Error chunk whose typed envelope
// carries `code = SCP-TOOL-6160` and the §6.2.0.5 ContextHop chain via
// the SCP-OUT-029 wrap path. The caller invoked through the public
// ContextManager API.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn manager_cross_context_bridge_failure_emits_typed_terminal_error() {
    let manager = build_manager();
    let inputs = full_visibility_inputs();

    let (etx, erx) = tokio::sync::mpsc::channel::<OutletStreamChunk>(64);
    let (_request_id, mut bridge) = manager.invoke_outlet_streaming_cross_context(inputs, erx);

    // Simulate the target executor disconnecting after emitting two
    // Data chunks WITHOUT a terminal chunk. The bridge must synthesize
    // a typed terminal Error envelope with the §5.4.4 round-3 wrap.
    let target_request_id: RequestId = *uuid::Uuid::now_v7().as_bytes();
    let exec_task = tokio::spawn(async move {
        let c0 = build_executor_data_chunk(&target_request_id, 0, 0);
        etx.send(c0).await.unwrap();
        let c1 = build_executor_data_chunk(&target_request_id, 1, 1);
        etx.send(c1).await.unwrap();
        // Drop the sender — the bridge sees disconnect with no
        // terminal chunk and must synthesize a transport-fault terminal.
        drop(etx);
    });

    let mut received: Vec<OutletStreamChunk> = Vec::new();
    while let Some(c) = bridge.receiver.recv().await {
        received.push(c);
    }
    exec_task.await.unwrap();

    // Last chunk must be a terminal Error — the bridge synthesized it
    // on disconnect.
    let terminal = received.last().expect("bridge emits at least one chunk");
    let ChunkPayload::Error {
        code,
        terminal: term,
        ..
    } = &terminal.payload
    else {
        panic!("expected terminal Error chunk, got {:?}", terminal.payload);
    };
    assert!(*term, "synthesized error chunk must be terminal");
    assert_eq!(
        code, CODE_TRANSPORT_FAULT,
        "bridge-failure code is SCP-TOOL-6160 (§5.4.4 transport class — \
         transport.cross-context-bridge-failure shares code 6160; \
         6161 is a §5.4.4 reserved gap, not used here per Path A)"
    );

    // Decode the typed envelope and verify the §6.2.0.5 ContextHop
    // chain from the SCP-OUT-029 wrap. The source observer has full
    // visibility, so the wrapped code is preserved (no oracle
    // collapse).
    let envelope = decode_envelope_from_chunk(terminal);
    assert_eq!(envelope.code, CODE_TRANSPORT_FAULT);
    assert_eq!(
        envelope.slug, SLUG_TRANSPORT_CROSS_CONTEXT_BRIDGE_FAILURE,
        "slug is the §5.4.4 transport.cross-context-bridge-failure"
    );
    // Wrap added a ContextHop for the target boundary the error just
    // crossed — at minimum one hop must be present.
    assert!(
        !envelope.source_chain.is_empty(),
        "wrapped envelope must carry a ContextHop chain per §6.2.0.5"
    );
}
