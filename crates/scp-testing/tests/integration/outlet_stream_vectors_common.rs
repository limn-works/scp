//! SCP-OUT-039 (C12) — shared harness for the outlet-streaming conformance
//! vectors. Included by BOTH runtime tiers via
//! `#[path = "outlet_stream_vectors_common.rs"] mod common;`:
//!
//!   * `outlet_stream_conformance.rs`            — raw `open_stream_session`.
//!   * `outlet_stream_vectors_through_open_path.rs` — `Supervisor::open_outlet_stream`.
//!
//! Each includer keeps ONLY its own `drive_vector` + harness-specific setup and
//! the thin `#[tokio::test]` wrappers; everything harness-agnostic lives here
//! (the `deny_unknown_fields` vector schema, the `ScriptedExecutor`, the
//! `ReceiverSequenceTracker`, the transcript/terminal assertions, the credit-
//! grant signer, the §25.2 reference key, the caveats-binding KAT, and the
//! `sequence_gap` + schema-shape tests). This is the standard cargo shared-test-
//! module pattern: each `[[test]]` binary compiles this file independently.
//!
//! `#![allow(dead_code)]` because each includer uses a subset of the shared
//! surface (e.g. only one tier constructs `AdmissionCaps` directly), and a
//! per-binary compile flags the unused remainder.

#![allow(dead_code)]

use std::time::Duration;

use ed25519_dalek::SigningKey;
use serde::Deserialize;

use scp_protocol::context::outlets::error_codes::CODE_EXECUTION_CREDIT;
use scp_protocol::context::outlets::stream::{
    ChunkPayload, CreditGrantSigningInputs, OutletStreamChunk, OutletStreamCredit, RequestId,
    compute_caveats_binding, sign_chunk, sign_credit_grant, verify_chunk_signature,
};
use scp_protocol::context::outlets::{OutletKind, OutletRegistration, OutletSchema};
use scp_protocol::context::params::MemoryScope;
use scp_protocol::economy::types::Amount;
use scp_protocol::provenance::{DataProvenance, DiscoveryMethod, SourceType};
use scp_protocol::trust::caveats::InvocationCaveats;

use scp_runtime::context::outlets::dispatch::StreamSessionHandle;
use scp_runtime::context::outlets::invoke::{
    MutableInvocation, OutletExecutor, OutletExecutorError, ReadOnlyInvocation,
};

use scp_did::DID;

// ---------------------------------------------------------------------------
// §25.2 reference operator key — RFC 8032 §7.1 Test Vector 1
// ---------------------------------------------------------------------------

/// The §25.2 reference operator seed. Chunk signatures in the gap-transcript
/// test are produced under this key so the vector is reproducible cross-SDK.
pub const REFERENCE_OPERATOR_SEED: [u8; 32] = [
    0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4,
    0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60,
];

/// The §25.2 reference operator PUBLIC key (RFC 8032 §7.1 Test Vector 1). Pinned
/// so a corrupted [`REFERENCE_OPERATOR_SEED`] byte fails loudly rather than
/// silently producing a self-consistent (but wrong) signature.
///
/// This is the value the seed derives under `ed25519-dalek`, and it matches the
/// public key stated in spec §25.2 (`d75a…daa62325af021a68f707511a`, the RFC 8032
/// §7.1 Test Vector 1 public key) and the repo KAT
/// (`crates/scp-runtime/tests/test_vectors.rs` `REF_PUBKEY`). Pinned so a
/// corrupted seed byte fails loudly instead of self-consistently.
pub const EXPECTED_OPERATOR_PK: [u8; 32] = [
    0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07, 0x3a,
    0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07, 0x51, 0x1a,
];

/// `SCP-OUTLET-6131` — the consolidated execution-class code the receiver emits
/// on a missing sequence (slug `execution.stream-gap`). Per §25.21 "two
/// error-code traps", `SCP-OUTLET-6131` (`CODE_EXECUTION_CREDIT`) is SHARED by
/// `execution.stream-gap`, `execution.credit-exhausted`, and
/// `execution.stream-cap-exhausted`; the gap path uses the stream-gap slug. (The
/// distinct credit-STALL code is `SCP-OUTLET-6133`, not this one.)
pub const CODE_STREAM_GAP: &str = CODE_EXECUTION_CREDIT;

/// The §5.4.5 `stream_epoch` pinned into the caveats-binding-adjacent stream
/// record; every credit grant is signed under this same value.
pub const STREAM_EPOCH: u64 = 1;

// ---------------------------------------------------------------------------
// Vector schema — a `deny_unknown_fields` mirror of the JSON contract. A
// missing / renamed field fails deserialization, which is what mechanically
// enforces AC2 (the schema is a hard contract the SDK coder mirrors).
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VectorFile {
    pub version: String,
    pub vectors: Vec<Vector>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Vector {
    pub name: String,
    pub outlet_kind: OutletKindTag,
    pub open: VectorOpen,
    pub chunks: Vec<VectorChunk>,
    pub credits: Vec<VectorCredit>,
    #[serde(default)]
    pub cancel_after_chunk_index: Option<i64>,
    pub expected_end_status: EndStatus,
    pub expected_error_code: Option<String>,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum OutletKindTag {
    Action,
    Query,
}

impl OutletKindTag {
    pub const fn to_kind(self) -> OutletKind {
        match self {
            Self::Action => OutletKind::Action,
            Self::Query => OutletKind::Query,
        }
    }
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
pub enum EndStatus {
    Ok,
    Error,
    Cancelled,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VectorOpen {
    pub request_id: [u8; 16],
    pub outlet_id: String,
    pub input: serde_json::Value,
    pub invoker_did: String,
    pub credit_window: u32,
    pub estimated_chunk_count: u32,
    /// CID of the opening UCAN — a §5.4.5 caveats-binding preimage input. Used
    /// by [`assert_caveats_binding_kat`] and the `sequence_gap` signed transcript
    /// so every tier computes the SAME binding from the vector's declared value.
    pub ucan_cid: String,
    /// The canonical `caveats_binding` (lowercase hex) over the vector's
    /// `(ucan_cid, request_id, invoker_did, estimated_chunk_count, JCS(empty
    /// caveats))`. Pinned so a shared-core binding regression is caught.
    pub expected_caveats_binding: String,
    // Present so `deny_unknown_fields` accepts the vector's `session_id` key and
    // pins the schema; the runtime-layer replay uses stateless opens.
    pub session_id: Option<String>,
    pub timeout_ms: u32,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VectorChunk {
    pub sequence: u64,
    pub payload: VectorPayload,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VectorCredit {
    pub after_chunk_index: i64,
    pub grant: u32,
    pub monotonic_seq: u64,
}

/// The `@type`-tagged payload descriptor as it appears in the JSON. The `end`
/// variant carries NO `provenance` (the vector is a descriptor, not a literal
/// wire chunk); [`VectorPayload::to_chunk_payload`] injects a sample
/// [`DataProvenance`] when a real [`ChunkPayload`] is needed.
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "@type", rename_all = "lowercase", deny_unknown_fields)]
pub enum VectorPayload {
    Data {
        value: serde_json::Value,
    },
    Progress {
        pct: u16,
        #[serde(default)]
        note: Option<String>,
    },
    End {
        aggregate: serde_json::Value,
        execution_time_ms: u64,
    },
    Error {
        code: String,
        message: String,
        terminal: bool,
    },
}

impl VectorPayload {
    pub fn to_chunk_payload(&self) -> ChunkPayload {
        match self {
            Self::Data { value } => ChunkPayload::Data {
                value: value.clone(),
            },
            Self::Progress { pct, note } => ChunkPayload::Progress {
                pct: *pct,
                note: note.clone(),
            },
            Self::End {
                aggregate,
                execution_time_ms,
            } => ChunkPayload::End {
                aggregate: aggregate.clone(),
                provenance: sample_provenance(),
                execution_time_ms: *execution_time_ms,
            },
            Self::Error {
                code,
                message,
                terminal,
            } => ChunkPayload::Error {
                code: code.clone(),
                message: message.clone(),
                terminal: *terminal,
            },
        }
    }
}

/// Sample provenance for `End` chunks the vector describes without one.
pub fn sample_provenance() -> DataProvenance {
    DataProvenance {
        source_context: "ctx-outlet-stream-conformance".into(),
        source_type: SourceType::Persistent,
        counterparties: vec!["did:dht:z6MkConformance".into()],
        purpose: None,
        discovery_method: DiscoveryMethod::OutOfBand,
        age: Duration::from_secs(0),
        memory_scope: MemoryScope::Full,
        chain_depth: 0,
        chain_path: None,
        payment_amount: None,
        payment_adapter: None,
        payment_receipt_id: None,
    }
}

// ---------------------------------------------------------------------------
// Vector loading
// ---------------------------------------------------------------------------

pub const VECTORS_JSON: &str =
    include_str!("../../../../tests/conformance/vectors/outlet_stream_vectors.json");

pub fn load_vectors() -> VectorFile {
    serde_json::from_str(VECTORS_JSON).expect("outlet_stream_vectors.json parses under the schema")
}

pub fn vector<'a>(file: &'a VectorFile, name: &str) -> &'a Vector {
    file.vectors
        .iter()
        .find(|v| v.name == name)
        .unwrap_or_else(|| panic!("vector `{name}` present"))
}

/// Lowercase-hex encode a byte slice.
pub fn to_hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

// ---------------------------------------------------------------------------
// ScriptedExecutor — emits the vector's non-terminal payloads, then performs a
// terminal action. Per the §5.4.5 executor contract, it NEVER emits a terminal
// chunk (End / Error{terminal:true}); the framework appends the terminal:
//   * `TerminalAction::EndOk`     — return Ok(())     → framework appends `End`.
//   * `TerminalAction::FailFault` — return Err(Failed) → framework appends a
//                                   terminal `Error{code: SCP-OUTLET-6130}`
//                                   (executor_error_to_terminal_payload maps
//                                   Failed → CODE_EXECUTION_FAULT).
//   * `TerminalAction::Block`     — park forever so the framework drives the
//                                   terminal (credit-stall / cancel-ack-timeout).
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub enum TerminalAction {
    EndOk,
    FailFault(String),
    Block,
}

pub struct ScriptedExecutor {
    pub emit: Vec<ChunkPayload>,
    pub terminal: TerminalAction,
}

impl ScriptedExecutor {
    async fn run(
        &self,
        tx: tokio::sync::mpsc::Sender<ChunkPayload>,
    ) -> Result<(), OutletExecutorError> {
        for payload in &self.emit {
            // `send` errs only if the receiver was dropped (cancelled stream);
            // the framework owns terminal emission in that case, so drop it.
            let _ = tx.send(payload.clone()).await;
        }
        match &self.terminal {
            TerminalAction::EndOk => Ok(()),
            TerminalAction::FailFault(msg) => Err(OutletExecutorError::Failed(msg.clone())),
            TerminalAction::Block => {
                std::future::pending::<()>().await;
                Ok(())
            }
        }
    }
}

#[async_trait::async_trait]
impl OutletExecutor for ScriptedExecutor {
    async fn exec_query_stream(
        &self,
        _ctx: &ReadOnlyInvocation<'_>,
        _input: serde_json::Value,
        tx: tokio::sync::mpsc::Sender<ChunkPayload>,
    ) -> Result<(), OutletExecutorError> {
        self.run(tx).await
    }

    async fn exec_action_stream(
        &self,
        _ctx: &mut MutableInvocation<'_>,
        _input: serde_json::Value,
        tx: tokio::sync::mpsc::Sender<ChunkPayload>,
    ) -> Result<(), OutletExecutorError> {
        self.run(tx).await
    }
}

/// Builds the executor's emit list + terminal action from a vector's transcript.
///
/// The emit list is every NON-terminal payload; the terminal is inferred from
/// `expected_end_status`. `credit_stall` is special-cased: the executor
/// must ATTEMPT more Data chunks than `credit_window` so the pump parks the
/// excess and the credit-stall timer fires (the vector's terminal `Error` chunk
/// is framework-emitted, not executor-emitted).
pub fn build_script(vec: &Vector) -> (Vec<ChunkPayload>, TerminalAction) {
    if vec.expected_error_code.as_deref() == Some("SCP-OUTLET-6133") {
        // credit_stall: send credit_window + 1 Data chunks so the (window+1)th
        // parks with credit at zero; never terminate — the framework drives the
        // credit-stall terminal.
        let extra = (vec.open.credit_window + 1) as usize;
        let emit = (0..extra)
            .map(|i| ChunkPayload::Data {
                value: serde_json::json!({ "n": i }),
            })
            .collect();
        return (emit, TerminalAction::Block);
    }

    let mut emit = Vec::new();
    let mut terminal = TerminalAction::EndOk;
    for chunk in &vec.chunks {
        match &chunk.payload {
            VectorPayload::End { .. } => terminal = TerminalAction::EndOk,
            VectorPayload::Error {
                terminal: true,
                message,
                ..
            } => terminal = TerminalAction::FailFault(message.clone()),
            other => emit.push(other.to_chunk_payload()),
        }
    }
    // The cancellation vector's terminal `end` is the framework cancel-ack chunk
    // — the executor must stay open until the signed cancel drives it.
    if vec.expected_end_status == EndStatus::Cancelled {
        terminal = TerminalAction::Block;
    }
    (emit, terminal)
}

// ---------------------------------------------------------------------------
// ReceiverSequenceTracker — the §5.4.5 receiver-side gap detector.
//
// NOTE: this is a TEST ORACLE for the §5.4.5 receiver rule, not production code.
// Why a receiver tracker rather than a pump: the same-context mpsc channel the
// runtime pump writes into is LOSSLESS and the pump renumbers emissions
// consecutively, so it structurally CANNOT produce a gap. §5.4.5 places the
// obligation on the RECEIVER — "A receiver that observes a gap (missing sequence)
// MUST cancel the stream with Execution::StreamGap and SHOULD rerun." Per the
// §5.4.5 receiver-locus paragraph, the PRODUCTION receiver is the invoker-side
// SDK InvocationHandle drain, which is the permanent, transport-agnostic home of
// this invariant (dormant over the lossless same-context channel, load-bearing
// when the invoker consumes chunks over a lossy transport). The live wire trigger
// (a relay-dropped chunk over transport) lands in slice-3, where any cross-context
// reassembly detector is reconciled with the SDK-drain check as defense-in-depth
// — NOT as a replacement. This oracle synthesizes the exact receiver rule at the
// Rust tier by replaying the vector's gapped, per-chunk-signed transcript, until a
// lossy transport can drive the SDK drain live.
// ---------------------------------------------------------------------------

/// Outcome of observing one chunk against the running sequence expectation.
#[derive(Debug, PartialEq, Eq)]
pub enum GapOutcome {
    /// Sequence was consecutive; keep going.
    Continue,
    /// A gap was observed — the receiver MUST cancel with this code
    /// ([`CODE_STREAM_GAP`] == `SCP-OUTLET-6131`, slug `execution.stream-gap`).
    Cancelled { code: String },
}

pub struct ReceiverSequenceTracker {
    expected: u64,
}

impl ReceiverSequenceTracker {
    pub const fn new() -> Self {
        Self { expected: 0 }
    }

    /// Observes one chunk's `sequence`. Returns [`GapOutcome::Cancelled`] the
    /// first time a non-consecutive sequence is seen.
    pub fn observe(&mut self, sequence: u64) -> GapOutcome {
        if sequence != self.expected {
            return GapOutcome::Cancelled {
                code: CODE_STREAM_GAP.to_owned(),
            };
        }
        self.expected += 1;
        GapOutcome::Continue
    }
}

// ---------------------------------------------------------------------------
// Shared outlet registration
// ---------------------------------------------------------------------------

pub fn registration(outlet_id: &str, kind: OutletKind, operator: &DID) -> OutletRegistration {
    OutletRegistration {
        outlet_id: outlet_id.to_owned(),
        kind,
        name: "Conformance outlet".to_owned(),
        description: "SCP-OUT-039 streaming conformance outlet".to_owned(),
        // The §5.4.2 schema-specificity floor requires >= 2 declared fields.
        schema: OutletSchema {
            input_schema: serde_json::json!({
                "type": "object",
                "properties": { "a": { "type": "number" }, "b": { "type": "number" } }
            }),
            output_schema: serde_json::json!({
                "type": "object",
                "properties": { "n": { "type": "number" }, "result": { "type": "number" } }
            }),
            aggregate_schema: None,
        },
        implementation_hash: [0xAA; 32],
        test_vectors: vec![],
        operator_did: operator.clone(),
        // Zero-cost: Query outlets forbid cost; Action outlets are free here so
        // escrow is `Amount(0)` and no funding fixture is needed.
        cost: None,
        message_catalog: Vec::new(),
        registered_at: 0,
        signature: Vec::new(),
    }
}

// ---------------------------------------------------------------------------
// Drain outcome + credit-grant signer
// ---------------------------------------------------------------------------

/// The result of draining a dispatched stream to its terminal chunk.
pub struct DrainOutcome {
    /// Every chunk the receiver observed, in order (terminal included).
    pub chunks: Vec<OutletStreamChunk>,
    /// `Some(seq)` iff a signed cancel was accepted (the §5.4.5 Cancelled
    /// signal, read from the close summary).
    pub cancel_ack_seq: Option<u64>,
}

/// Signs and applies one credit grant. The grant preimage binds the PINNED
/// `(context_id, outlet_id, stream_epoch, caveats_binding)` — `outlet_id` /
/// `context_id` must be the real pinned values or `apply_credit_grant` rejects
/// the signature.
pub fn apply_grant(
    handle: &StreamSessionHandle,
    key: &SigningKey,
    ctx_id: &str,
    outlet_id: &str,
    request_id: &RequestId,
    caveats_binding: &[u8; 32],
    credit: &VectorCredit,
) {
    let grant = OutletStreamCredit {
        request_id: *request_id,
        grant: credit.grant,
        monotonic_seq: credit.monotonic_seq,
        sig: sign_credit_grant(
            key,
            &CreditGrantSigningInputs {
                context_id: ctx_id,
                outlet_id,
                request_id,
                grant: credit.grant,
                monotonic_seq: credit.monotonic_seq,
                stream_epoch: STREAM_EPOCH,
                caveats_binding,
            },
        ),
    };
    handle
        .apply_credit_grant(&grant, Amount::new(0))
        .expect("signed credit grant applies");
}

// ---------------------------------------------------------------------------
// Assertions
// ---------------------------------------------------------------------------

/// Asserts the drained transcript matches the vector's declared chunks in order
/// (variant + Data value + Error code/terminal), with sequences 0..N.
pub fn assert_transcript_matches(vec: &Vector, outcome: &DrainOutcome) {
    // Sequences strictly monotonic from 0 (the framework renumbers).
    for (i, chunk) in outcome.chunks.iter().enumerate() {
        assert_eq!(
            chunk.sequence, i as u64,
            "vector `{}`: chunk {i} sequence must be the renumbered {i}",
            vec.name
        );
    }
    assert_eq!(
        outcome.chunks.len(),
        vec.chunks.len(),
        "vector `{}`: drained {} chunks, vector declares {}",
        vec.name,
        outcome.chunks.len(),
        vec.chunks.len()
    );
    for (i, (got, want)) in outcome.chunks.iter().zip(vec.chunks.iter()).enumerate() {
        match (&got.payload, &want.payload) {
            (ChunkPayload::Data { value: g }, VectorPayload::Data { value: w }) => {
                assert_eq!(g, w, "vector `{}`: chunk {i} Data value", vec.name);
            }
            (
                ChunkPayload::Progress { pct: gp, note: gn },
                VectorPayload::Progress { pct: wp, note: wn },
            ) => {
                assert_eq!(
                    (gp, gn),
                    (wp, wn),
                    "vector `{}`: chunk {i} Progress",
                    vec.name
                );
            }
            // The framework End's aggregate/provenance are framework-derived; only
            // the variant is asserted (the vector's aggregate is a descriptor).
            (ChunkPayload::End { .. }, VectorPayload::End { .. }) => {}
            (
                ChunkPayload::Error {
                    code: gc,
                    terminal: gt,
                    ..
                },
                VectorPayload::Error {
                    code: wc,
                    terminal: wt,
                    ..
                },
            ) => {
                assert_eq!(gc, wc, "vector `{}`: chunk {i} Error code", vec.name);
                assert_eq!(gt, wt, "vector `{}`: chunk {i} Error terminal", vec.name);
            }
            (g, w) => panic!(
                "vector `{}`: chunk {i} variant mismatch: got {g:?}, want {w:?}",
                vec.name
            ),
        }
    }
}

pub fn assert_terminal_status(vec: &Vector, outcome: &DrainOutcome) {
    let last = outcome.chunks.last().expect("at least one chunk");
    match vec.expected_end_status {
        EndStatus::Ok => assert!(
            matches!(last.payload, ChunkPayload::End { .. }),
            "vector `{}`: Ok status ⇒ terminal End, got {:?}",
            vec.name,
            last.payload
        ),
        EndStatus::Error => {
            let ChunkPayload::Error { code, terminal, .. } = &last.payload else {
                panic!(
                    "vector `{}`: Error status ⇒ terminal Error, got {:?}",
                    vec.name, last.payload
                );
            };
            assert!(
                terminal,
                "vector `{}`: terminal Error must set terminal",
                vec.name
            );
            assert_eq!(
                Some(code.as_str()),
                vec.expected_error_code.as_deref(),
                "vector `{}`: terminal error code",
                vec.name
            );
        }
        EndStatus::Cancelled => {
            assert!(
                outcome.cancel_ack_seq.is_some(),
                "vector `{}`: Cancelled status ⇒ close summary records a cancel-ack seq",
                vec.name
            );
            assert!(
                last.payload.is_terminal(),
                "vector `{}`: cancelled stream still reaches a terminal chunk",
                vec.name
            );
        }
    }
}

/// Asserts the delivered Data-chunk values are a PREFIX of the vector's declared
/// Data values (used by the timing-dependent cancellation drain, where the
/// forced terminal races the executor's remaining chunks).
pub fn assert_data_prefix(vec: &Vector, outcome: &DrainOutcome) {
    let want_data: Vec<&serde_json::Value> = vec
        .chunks
        .iter()
        .filter_map(|c| match &c.payload {
            VectorPayload::Data { value } => Some(value),
            _ => None,
        })
        .collect();
    let got_data: Vec<&serde_json::Value> = outcome
        .chunks
        .iter()
        .filter_map(|c| match &c.payload {
            ChunkPayload::Data { value } => Some(value),
            _ => None,
        })
        .collect();
    assert!(
        got_data.len() <= want_data.len(),
        "vector `{}`: delivered {} Data chunks, vector declares {}",
        vec.name,
        got_data.len(),
        want_data.len()
    );
    for (i, g) in got_data.iter().enumerate() {
        assert_eq!(
            *g, want_data[i],
            "vector `{}`: Data chunk {i} value prefix",
            vec.name
        );
    }
}

// ---------------------------------------------------------------------------
// caveats_binding KAT — pins the §5.4.5 binding to a canonical value so the
// vectors are genuinely cross-SDK reproducible (and the vector's declared
// `ucan_cid` / `invoker_did` are load-bearing, not dead fields).
// ---------------------------------------------------------------------------

/// Computes the §5.4.5 `caveats_binding` over the VECTOR'S declared
/// `(ucan_cid, request_id, invoker_did, estimated_chunk_count, JCS(empty
/// caveats))` and asserts it equals the pinned `expected_caveats_binding` hex.
/// This is a PURE known-answer computation independent of the live open (which
/// legitimately uses the real member DID / cid); it pins the shared-core binding
/// so any preimage-construction regression is caught at every tier.
pub fn assert_caveats_binding_kat(vec: &Vector) {
    let caveats_jcs = InvocationCaveats::empty()
        .to_canonical_json_bytes()
        .expect("empty-caveats JCS");
    let binding = compute_caveats_binding(
        vec.open.ucan_cid.as_bytes(),
        &vec.open.request_id,
        &vec.open.invoker_did,
        vec.open.estimated_chunk_count,
        &caveats_jcs,
    );
    assert_eq!(
        to_hex(&binding),
        vec.open.expected_caveats_binding,
        "vector `{}`: caveats_binding must equal the pinned canonical value",
        vec.name
    );
}

// ---------------------------------------------------------------------------
// Shared tests — compiled into BOTH includer binaries (each runs them once).
// ---------------------------------------------------------------------------

/// AC1/AC2 — the vector file loads under the `deny_unknown_fields` schema, has
/// exactly 7 vectors, and the exact expected name set.
#[test]
fn vectors_load_and_have_the_seven_named_scenarios() {
    let file = load_vectors();
    assert_eq!(file.version, "1.0", "version pinned");
    assert_eq!(file.vectors.len(), 7, "exactly 7 vectors");
    let mut names: Vec<&str> = file.vectors.iter().map(|v| v.name.as_str()).collect();
    names.sort_unstable();
    let mut expected = vec![
        "cancellation",
        "credit_stall",
        "error_recoverable",
        "error_terminal",
        "multi_chunk",
        "non_streaming",
        "sequence_gap",
    ];
    expected.sort_unstable();
    assert_eq!(names, expected, "exact vector name set");
}

/// The caveats-binding KAT holds for all 7 vectors (cross-SDK reproducibility).
#[test]
fn caveats_binding_kat_pins_all_seven() {
    let file = load_vectors();
    assert_eq!(file.vectors.len(), 7);
    for vec in &file.vectors {
        assert_caveats_binding_kat(vec);
    }
}

/// `sequence_gap`: run the receiver tracker over the vector's gapped, per-chunk-
/// signed transcript. The tracker MUST fire `Cancelled` with `SCP-OUTLET-6131`
/// at the first non-consecutive sequence (the third chunk, sequence 3 after 0,1).
#[test]
fn sequence_gap_receiver_tracker_cancels_with_6131() {
    let file = load_vectors();
    let vec = vector(&file, "sequence_gap");

    let operator = SigningKey::from_bytes(&REFERENCE_OPERATOR_SEED);
    // Defense-in-depth: a corrupted seed byte would still sign/verify
    // self-consistently, so pin the derived public key to §25.2.
    assert_eq!(
        operator.verifying_key().to_bytes(),
        EXPECTED_OPERATOR_PK,
        "REFERENCE_OPERATOR_SEED must derive the §25.2 public key"
    );
    let operator_pk = operator.verifying_key();
    let request_id: RequestId = vec.open.request_id;

    // §5.4.5 caveats_binding for the signed transcript, from the vector's own
    // declared ucan_cid so it matches the pinned expected_caveats_binding.
    let caveats = InvocationCaveats::empty();
    let caveats_jcs = caveats.to_canonical_json_bytes().expect("jcs");
    let caveats_binding = compute_caveats_binding(
        vec.open.ucan_cid.as_bytes(),
        &request_id,
        &vec.open.invoker_did,
        vec.open.estimated_chunk_count,
        &caveats_jcs,
    );
    assert_eq!(
        to_hex(&caveats_binding),
        vec.open.expected_caveats_binding,
        "gap-transcript binding matches the pinned canonical value"
    );

    // Build the gapped, per-chunk-signed transcript from the vector.
    let signed: Vec<OutletStreamChunk> = vec
        .chunks
        .iter()
        .map(|c| {
            let payload = c.payload.to_chunk_payload();
            let sig = sign_chunk(
                &operator,
                &vec.open.outlet_id, // context/outlet ids only need to be self-consistent here
                &vec.open.outlet_id,
                &request_id,
                c.sequence,
                &caveats_binding,
                &payload,
            )
            .expect("sign chunk under the §25.2 reference operator key");
            OutletStreamChunk {
                request_id,
                sequence: c.sequence,
                payload,
                sig,
            }
        })
        .collect();

    // Each signed chunk verifies under the reference operator key (wire integrity).
    for chunk in &signed {
        assert!(
            verify_chunk_signature(
                chunk,
                &operator_pk,
                &vec.open.outlet_id,
                &vec.open.outlet_id,
                &caveats_binding,
            ),
            "gap-transcript chunk seq {} verifies under the §25.2 operator key",
            chunk.sequence
        );
    }

    // The receiver observes 0, 1, then 3 → a gap at the third chunk.
    let mut tracker = ReceiverSequenceTracker::new();
    let mut fired_at: Option<usize> = None;
    for (i, chunk) in signed.iter().enumerate() {
        if let GapOutcome::Cancelled { code } = tracker.observe(chunk.sequence) {
            assert_eq!(
                code,
                vec.expected_error_code
                    .clone()
                    .expect("gap has an error code"),
                "gap cancel code is execution.stream-gap / SCP-OUTLET-6131"
            );
            assert_eq!(code, "SCP-OUTLET-6131", "gap code is 6131");
            fired_at = Some(i);
            break;
        }
    }
    assert_eq!(
        fired_at,
        Some(2),
        "the receiver tracker cancels at the third chunk (sequence 3 after 0,1)"
    );
    assert_eq!(vec.expected_end_status, EndStatus::Cancelled);
}
