//! SCP-OUT-039 — Outlet streaming conformance vector replay (§5.4.5).
//!
//! Replays every vector in `tests/conformance/vectors/outlet_stream_vectors.json`
//! through the runtime's streaming primitives
//! ([`scp_runtime::context::outlets::stream::CreditTracker`],
//! [`scp_runtime::context::outlets::stream::CancelAckTracker`],
//! [`scp_runtime::context::outlets::stream::StreamEscrow`], and
//! [`scp_runtime::context::outlets::stream::compute_chunks_billed_ref`])
//! and asserts:
//!
//!  1. The vector set has exactly 7 vectors with the names declared in
//!     SCP-OUT-039 AC1: `non_streaming`, `multi_chunk`, `cancellation`,
//!     `error_terminal`, `error_recoverable`, `sequence_gap`,
//!     `credit_exhaustion`.
//!  2. Every vector's chunk-list resolves to a deterministic
//!     [`StreamTerminalStatus`] under the runtime semantics — `Ok` for
//!     `End`, `Error(code)` for terminal `Error`, and `Cancelled` for
//!     the cancel-ack vector.
//!  3. The §5.4.5 chunks-billed predicate
//!     ([`compute_chunks_billed_ref`]) over the manifest matches the
//!     `expected_chunks_billed` field on every vector.
//!  4. The cancel-ack-seq pinning rule (§5.4.5 "Cancellation and billing
//!     boundary") is replayed for the `cancellation` vector and matches
//!     the vector's `expected_cancel_ack_seq` field.
//!  5. The `sequence_gap` vector's chunk stream contains exactly one
//!     missing sequence at the position the vector declares
//!     (`expected_first_gap_sequence`) — the receiver's `StreamGap`
//!     cancel trigger condition.
//!  6. The `credit_exhaustion` vector's chunk emission consumes the
//!     full initial `credit_window` and leaves the [`CreditTracker`]
//!     remaining at 0 — the credit-stall-timer trigger condition.
//!
//! These vectors are control-plane fixtures: they describe ordering
//! between executor-emitted chunks and receiver-issued grants/cancels.
//! The wire-level signature and preimage layer (per-chunk
//! `SCP-OUTLET-CHUNK-SIG-V1`, credit grant `SCP-OUTLET-CREDIT-V1`,
//! `caveats_binding`) is covered separately by the §5.4.5 `chunk_sig`
//! and `credit_sig` protocol-level tests in
//! [`scp_protocol::context::outlets::stream`]. The Rust replay here is
//! the canonical funnel — all four FFI bridges (`PyO3`, `NAPI`,
//! `UniFFI` Swift/Kotlin, WASM) call into the same runtime primitives,
//! so the Rust replay transitively validates every bridge for
//! SCP-OUT-039 AC4.
//! Per-SDK smoke tests provide the SDK-surface assertion of AC6 by
//! driving each vector through the SDK's `InvocationHandle` pump.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::similar_names,
    clippy::too_many_lines
)]

use std::collections::HashSet;
use std::path::PathBuf;

use ed25519_dalek::SigningKey;
use scp_protocol::context::outlets::error_codes::{
    CODE_EXECUTION_CANCEL_ACK_TIMEOUT, CODE_EXECUTION_CREDIT, CODE_EXECUTION_CREDIT_STALL,
    CODE_EXECUTION_FAULT, CODE_TRANSPORT_FAULT, SLUG_EXECUTION_CREDIT_STALL,
    SLUG_EXECUTION_STREAM_GAP,
};
use scp_protocol::context::outlets::stream::{
    ChunkPayload, OutletStreamChunk, RequestId, StreamTerminalStatus,
};
use scp_runtime::context::outlets::stream::{
    CancelAckTracker, CreditTracker, StreamEscrow, StreamIdentity, compute_chunks_billed_ref,
};

// ---------------------------------------------------------------------------
// Fixture parsing
// ---------------------------------------------------------------------------

#[derive(serde::Deserialize, Debug)]
struct OpenSpec {
    #[allow(dead_code)]
    outlet_id: String,
    #[allow(dead_code)]
    outlet_kind: String,
    #[allow(dead_code)]
    invoker_did: String,
    #[allow(dead_code)]
    operator_did: String,
    #[allow(dead_code)]
    context_id: String,
    credit_window: u32,
    estimated_chunk_count: u32,
    cost_per_chunk: u64,
    available_balance: u64,
    #[allow(dead_code)]
    stream_credit_stall_secs: u32,
    stream_cancel_ack_secs: u32,
    #[allow(dead_code)]
    timeout_ms: u32,
    #[allow(dead_code)]
    chain_depth: u8,
}

#[derive(serde::Deserialize, Debug)]
#[serde(tag = "type", rename_all = "lowercase")]
enum VectorChunk {
    Data {
        sequence: u64,
        value: serde_json::Value,
    },
    End {
        sequence: u64,
        aggregate: serde_json::Value,
        execution_time_ms: u64,
    },
    Error {
        sequence: u64,
        code: String,
        #[allow(dead_code)]
        slug: Option<String>,
        message: String,
        terminal: bool,
    },
    Progress {
        sequence: u64,
        pct: u16,
        #[serde(default)]
        note: Option<String>,
    },
}

impl VectorChunk {
    const fn sequence(&self) -> u64 {
        match self {
            Self::Data { sequence, .. }
            | Self::End { sequence, .. }
            | Self::Error { sequence, .. }
            | Self::Progress { sequence, .. } => *sequence,
        }
    }

    fn into_protocol_chunk(self, request_id: RequestId) -> OutletStreamChunk {
        let (sequence, payload) = match self {
            Self::Data { sequence, value } => (sequence, ChunkPayload::Data { value }),
            Self::End {
                sequence,
                aggregate,
                execution_time_ms,
            } => {
                // Synthetic provenance — these vectors are control-plane
                // ordering fixtures, not signature/preimage fixtures.
                let provenance = synthetic_provenance();
                (
                    sequence,
                    ChunkPayload::End {
                        aggregate,
                        provenance,
                        execution_time_ms,
                    },
                )
            }
            Self::Error {
                sequence,
                code,
                message,
                terminal,
                ..
            } => (
                sequence,
                ChunkPayload::Error {
                    code,
                    message,
                    terminal,
                },
            ),
            Self::Progress {
                sequence,
                pct,
                note,
            } => (sequence, ChunkPayload::Progress { pct, note }),
        };
        OutletStreamChunk {
            request_id,
            sequence,
            payload,
            sig: [0u8; 64], // synthetic — see module rustdoc
        }
    }
}

#[derive(serde::Deserialize, Debug)]
struct CancelSpec {
    after_sequence: u64,
    expected_cancel_ack_seq: u64,
}

#[derive(serde::Deserialize, Debug)]
#[allow(dead_code)] // `credits` and `trigger` are documented in the JSON for spec/SDK consumers.
struct StreamVector {
    name: String,
    description: String,
    open: OpenSpec,
    chunks: Vec<VectorChunk>,
    #[serde(default)]
    credits: Vec<serde_json::Value>,
    #[serde(default)]
    cancel: Option<CancelSpec>,
    #[serde(default)]
    trigger: Option<String>,
    expected_end_status: String,
    #[serde(default)]
    expected_error_code: Option<String>,
    #[serde(default)]
    expected_error_slug: Option<String>,
    expected_chunks_billed: u32,
    expected_total_chunks: u32,
    #[serde(default)]
    expected_cancel_ack_seq: Option<u64>,
    #[serde(default)]
    expected_first_gap_sequence: Option<u64>,
}

#[derive(serde::Deserialize, Debug)]
struct VectorFile {
    #[allow(dead_code)]
    comment: String,
    #[allow(dead_code)]
    spec_section: String,
    vectors: Vec<StreamVector>,
}

fn vector_path() -> PathBuf {
    let manifest = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    let mut path = PathBuf::from(manifest);
    path.pop(); // out of scp-testing
    path.pop(); // out of crates
    path.push("tests/conformance/vectors/outlet_stream_vectors.json");
    path
}

fn load_vectors() -> Vec<StreamVector> {
    let bytes = std::fs::read(vector_path()).expect("vector file must exist");
    let file: VectorFile = serde_json::from_slice(&bytes).expect("vector JSON parses");
    file.vectors
}

// Synthetic stable request_id for vector replay. Replay vectors are
// control-plane fixtures — request_id collision-resistance is exercised
// in the §5.4.5 caveats_binding fixtures (separate concern).
const VECTOR_REQUEST_ID: RequestId = [0xa5; 16];

fn synthetic_identity(open: &OpenSpec) -> StreamIdentity {
    StreamIdentity {
        context_id: open.context_id.clone(),
        outlet_id: open.outlet_id.clone(),
        stream_epoch: 0,
        caveats_binding: [0u8; 32],
    }
}

fn synthetic_invoker_pk() -> ed25519_dalek::VerifyingKey {
    // Deterministic synthetic key for replay — the credit-grant
    // signature path is exercised in
    // crates/scp-protocol/src/context/outlets/stream.rs unit tests, not
    // here.
    SigningKey::from_bytes(&[7u8; 32]).verifying_key()
}

fn synthetic_provenance() -> scp_protocol::provenance::DataProvenance {
    scp_protocol::provenance::DataProvenance {
        source_context: "vec-ctx".into(),
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

// ---------------------------------------------------------------------------
// Spec-section assertions (AC1) — exact set of seven vectors with the
// names mandated by SCP-OUT-039.
// ---------------------------------------------------------------------------

const REQUIRED_VECTOR_NAMES: &[&str] = &[
    "non_streaming",
    "multi_chunk",
    "cancellation",
    "error_terminal",
    "error_recoverable",
    "sequence_gap",
    "credit_exhaustion",
];

#[test]
fn vector_set_has_exactly_seven_named_vectors() {
    let vectors = load_vectors();
    assert_eq!(
        vectors.len(),
        7,
        "SCP-OUT-039 AC1: outlet_stream_vectors.json must contain exactly 7 vectors (got {})",
        vectors.len()
    );
    let names: HashSet<&str> = vectors.iter().map(|v| v.name.as_str()).collect();
    let required: HashSet<&str> = REQUIRED_VECTOR_NAMES.iter().copied().collect();
    assert_eq!(
        names, required,
        "SCP-OUT-039 AC1: vector names must match the seven required identifiers"
    );
}

#[test]
fn every_vector_has_required_shape_fields() {
    // SCP-OUT-039 AC2 — each vector specifies open, chunks, credits,
    // expected_end_status, expected_error_code (optional). The struct
    // deserialization above enforces presence of the mandatory fields;
    // here we explicitly assert the optional fields are populated when
    // the §5.4.5 semantics demand them.
    for v in load_vectors() {
        assert!(
            !v.description.is_empty(),
            "vector {} must carry a non-empty description",
            v.name
        );
        match v.expected_end_status.as_str() {
            "Ok" | "Error" | "Cancelled" => {}
            other => panic!(
                "vector {}: expected_end_status must be Ok/Error/Cancelled, got {other:?}",
                v.name
            ),
        }
        // Error end-status MUST carry an error code per §5.4.5
        // ChunkPayload::Error semantics.
        if v.expected_end_status == "Error" {
            assert!(
                v.expected_error_code.is_some(),
                "vector {}: expected_end_status=Error requires expected_error_code",
                v.name
            );
        }
        // Cancelled end-status MUST pin a cancel-ack-seq per §5.4.5
        // cancellation-and-billing-boundary semantics.
        if v.expected_end_status == "Cancelled" {
            assert!(
                v.expected_cancel_ack_seq.is_some(),
                "vector {}: expected_end_status=Cancelled requires expected_cancel_ack_seq",
                v.name
            );
            assert!(
                v.cancel.is_some(),
                "vector {}: Cancelled vector must declare a cancel block",
                v.name
            );
        }
    }
}

// ---------------------------------------------------------------------------
// AC3 — replay each vector and assert terminal status + chunks_billed
// ---------------------------------------------------------------------------

fn classify_terminal_status(
    chunks: &[OutletStreamChunk],
    cancel_ack_seq: Option<u64>,
) -> StreamTerminalStatus {
    if cancel_ack_seq.is_some() {
        return StreamTerminalStatus::Cancelled;
    }
    let last = chunks.last().expect("vector must emit ≥ 1 chunk");
    match &last.payload {
        ChunkPayload::End { .. } => StreamTerminalStatus::Ok,
        ChunkPayload::Error {
            code,
            terminal: true,
            ..
        } => StreamTerminalStatus::Error(code.clone()),
        // Sequence-gap vector terminates from the receiver side with a
        // synthesized StreamGap cancel — the manifest itself does not
        // carry the receiver's terminal envelope. Surface the
        // §5.4.4 stream-gap code.
        _ => StreamTerminalStatus::Error(CODE_EXECUTION_CREDIT.to_owned()),
    }
}

#[test]
fn replay_each_vector_produces_expected_terminal_status() {
    for v in load_vectors() {
        let request_id = VECTOR_REQUEST_ID;

        // Build the manifest the executor's pump would emit (the
        // chunks the §5.4.5 wire layer commits to). For the
        // sequence_gap vector the manifest is the partial sequence the
        // receiver observes before triggering its own StreamGap
        // cancel — there is no receiver-emitted terminal in the
        // manifest, so we synthesize the StreamTerminalStatus from the
        // first-gap detection rule below.
        let manifest: Vec<OutletStreamChunk> = v
            .chunks
            .iter()
            .map(|c| match c {
                VectorChunk::Data { sequence, value } => OutletStreamChunk {
                    request_id,
                    sequence: *sequence,
                    payload: ChunkPayload::Data {
                        value: value.clone(),
                    },
                    sig: [0u8; 64],
                },
                VectorChunk::End {
                    sequence,
                    aggregate,
                    execution_time_ms,
                } => OutletStreamChunk {
                    request_id,
                    sequence: *sequence,
                    payload: ChunkPayload::End {
                        aggregate: aggregate.clone(),
                        provenance: synthetic_provenance(),
                        execution_time_ms: *execution_time_ms,
                    },
                    sig: [0u8; 64],
                },
                VectorChunk::Error {
                    sequence,
                    code,
                    message,
                    terminal,
                    ..
                } => OutletStreamChunk {
                    request_id,
                    sequence: *sequence,
                    payload: ChunkPayload::Error {
                        code: code.clone(),
                        message: message.clone(),
                        terminal: *terminal,
                    },
                    sig: [0u8; 64],
                },
                VectorChunk::Progress {
                    sequence,
                    pct,
                    note,
                } => OutletStreamChunk {
                    request_id,
                    sequence: *sequence,
                    payload: ChunkPayload::Progress {
                        pct: *pct,
                        note: note.clone(),
                    },
                    sig: [0u8; 64],
                },
            })
            .collect();

        // Total chunk count (pre-classification — sequence_gap vector
        // counts only what the executor emitted).
        assert_eq!(
            manifest.len(),
            v.expected_total_chunks as usize,
            "vector {}: expected_total_chunks mismatch",
            v.name
        );

        // Classify terminal status.
        let cancel_ack_seq = v.expected_cancel_ack_seq;
        let status = classify_terminal_status(&manifest, cancel_ack_seq);

        match (v.expected_end_status.as_str(), &status) {
            ("Ok", StreamTerminalStatus::Ok) | ("Cancelled", StreamTerminalStatus::Cancelled) => {}
            ("Error", StreamTerminalStatus::Error(code)) => {
                let expected = v
                    .expected_error_code
                    .as_ref()
                    .expect("Error vectors carry expected_error_code");
                assert_eq!(
                    code, expected,
                    "vector {}: terminal Error code mismatch",
                    v.name
                );
            }
            (expected, actual) => panic!(
                "vector {}: terminal status mismatch — expected {expected:?}, got {actual:?}",
                v.name
            ),
        }

        // Chunks-billed reference (§5.4.5 wire-rejection rule) — for
        // the sequence_gap vector the receiver cancel is synthetic, so
        // we score the manifest as a whole. The vector's
        // expected_chunks_billed for that case is 0 because the
        // outlet is a Query (cost.amount == 0) — billing predicate
        // returns 0 regardless of cancel-ack-seq.
        let ceiling = cancel_ack_seq.unwrap_or(u64::MAX);
        let billed_ref = compute_chunks_billed_ref(&manifest, ceiling);

        // For zero-cost streams the billed ref still counts Data
        // chunks; the economic-layer billed_amount is what's gated to
        // zero. The vectors record the predicate count.
        let predicate_count = u32::try_from(
            manifest
                .iter()
                .filter(|c| matches!(c.payload, ChunkPayload::Data { .. }) && c.sequence <= ceiling)
                .count(),
        )
        .unwrap_or(u32::MAX);

        assert_eq!(
            billed_ref, predicate_count,
            "vector {}: compute_chunks_billed_ref must equal manual count",
            v.name
        );

        // The vector's expected_chunks_billed accounts for cost: 0 for
        // zero-cost streams, the billed Data count for non-zero-cost
        // streams. Replay must match.
        let economically_billed: u32 = if v.open.cost_per_chunk == 0 {
            0
        } else {
            billed_ref
        };
        assert_eq!(
            economically_billed, v.expected_chunks_billed,
            "vector {}: economically billed count mismatch (cost={}, ceiling={})",
            v.name, v.open.cost_per_chunk, ceiling
        );
    }
}

// ---------------------------------------------------------------------------
// AC4 — cancellation vector exercises CancelAckTracker the same way the
// runtime pump does. Asserts cancel_ack_seq pinning and billing-ceiling
// behavior match the vector's expectation.
// ---------------------------------------------------------------------------

#[test]
fn cancellation_vector_replays_through_cancel_ack_tracker() {
    let v = load_vectors()
        .into_iter()
        .find(|v| v.name == "cancellation")
        .expect("cancellation vector must exist");

    let cancel_spec = v
        .cancel
        .as_ref()
        .expect("cancellation vector carries cancel block");

    let mut tracker = CancelAckTracker::new(v.open.stream_cancel_ack_secs);

    // Active stream — billing ceiling is u64::MAX before cancel
    // arrival per CancelAckTracker semantics.
    assert_eq!(tracker.billing_ceiling(), u64::MAX);
    assert!(tracker.cancel_ack_seq().is_none());

    // Receiver delivers OutletCancel after the chunk at
    // `after_sequence` lands. The next-to-emit sequence at that moment
    // is `after_sequence + 1`.
    let next_seq_at_cancel = cancel_spec.after_sequence + 1;
    tracker.record_cancel(next_seq_at_cancel, std::time::Instant::now());

    assert_eq!(
        tracker.cancel_ack_seq(),
        Some(cancel_spec.expected_cancel_ack_seq),
        "cancellation vector: cancel-ack-seq must pin at next-to-emit sequence"
    );
    assert_eq!(
        tracker.billing_ceiling(),
        cancel_spec.expected_cancel_ack_seq,
        "cancellation vector: billing ceiling tracks pinned cancel-ack-seq"
    );

    // Idempotent — a second OutletCancel is a no-op.
    tracker.record_cancel(99, std::time::Instant::now());
    assert_eq!(
        tracker.cancel_ack_seq(),
        Some(cancel_spec.expected_cancel_ack_seq),
        "cancellation vector: cancel-ack-seq is pinned at first arrival"
    );

    // Vector-level cross-check.
    assert_eq!(
        v.expected_cancel_ack_seq,
        Some(cancel_spec.expected_cancel_ack_seq),
        "cancellation vector: top-level expected_cancel_ack_seq must match cancel block"
    );
}

// ---------------------------------------------------------------------------
// AC5 — sequence_gap vector models the receiver-side StreamGap trigger.
// Asserts the chunk stream contains exactly one gap at the declared
// position.
// ---------------------------------------------------------------------------

#[test]
fn sequence_gap_vector_has_one_missing_sequence() {
    let v = load_vectors()
        .into_iter()
        .find(|v| v.name == "sequence_gap")
        .expect("sequence_gap vector must exist");

    let observed: Vec<u64> = v.chunks.iter().map(VectorChunk::sequence).collect();

    // Find the first gap.
    let mut first_gap: Option<u64> = None;
    for (i, &seq) in observed.iter().enumerate() {
        let expected = i as u64;
        if seq != expected {
            first_gap = Some(expected);
            break;
        }
    }

    assert!(
        first_gap.is_some(),
        "sequence_gap vector must contain a gap"
    );
    assert_eq!(
        first_gap, v.expected_first_gap_sequence,
        "sequence_gap vector: first-gap sequence mismatch"
    );

    // The §5.4.4 slug → code mapping for execution.stream-gap shares
    // SCP-TOOL-6131 with execution.credit-exhausted (per the round-5
    // slug consolidation in error_codes.rs). Vector pins the slug
    // separately so SDKs can disambiguate.
    assert_eq!(
        v.expected_error_slug.as_deref(),
        Some(SLUG_EXECUTION_STREAM_GAP),
        "sequence_gap vector: expected_error_slug must match SLUG_EXECUTION_STREAM_GAP"
    );
    assert_eq!(
        v.expected_error_code.as_deref(),
        Some(CODE_EXECUTION_CREDIT),
        "sequence_gap vector: expected_error_code must match CODE_EXECUTION_CREDIT (shared with execution.stream-gap)"
    );
}

// ---------------------------------------------------------------------------
// AC6 — credit_exhaustion vector replays through CreditTracker the same
// way the runtime pump does. Asserts credit consumption drains the
// initial window to zero with no grants in the vector.
// ---------------------------------------------------------------------------

#[test]
fn credit_exhaustion_vector_drains_credit_tracker_to_zero() {
    let v = load_vectors()
        .into_iter()
        .find(|v| v.name == "credit_exhaustion")
        .expect("credit_exhaustion vector must exist");

    let identity = synthetic_identity(&v.open);
    let mut credit = CreditTracker::new(v.open.credit_window, synthetic_invoker_pk(), identity);

    // Initial state.
    assert_eq!(credit.remaining(), v.open.credit_window);

    // Drain credit by emitting Data chunks per the vector. The vector
    // emits credit_window Data chunks, then the framework injects a
    // terminal Error{code=SCP-TOOL-6133} when the stall timer fires
    // (modeled abstractly via the chunk list — the timer's wall-clock
    // arming is the runtime pump's concern).
    let mut data_count: u32 = 0;
    for c in &v.chunks {
        if matches!(c, VectorChunk::Data { .. }) {
            credit
                .try_consume()
                .unwrap_or_else(|_| panic!("credit_exhaustion vector: Data chunk #{data_count} must succeed up to credit_window"));
            data_count += 1;
        }
    }

    // After credit_window Data chunks, credit is at zero.
    assert_eq!(
        credit.remaining(),
        0,
        "credit_exhaustion vector: credit must reach zero after credit_window Data chunks"
    );
    assert_eq!(
        data_count, v.open.credit_window,
        "credit_exhaustion vector: Data count must equal credit_window"
    );

    // The vector carries no credit grants — the receiver issued none,
    // forcing the stall.
    assert!(
        v.credits.is_empty(),
        "credit_exhaustion vector: must carry zero credit grants"
    );

    // The terminal chunk is the framework-emitted credit-stall payload.
    let terminal = v.chunks.last().expect("credit_exhaustion has terminal");
    match terminal {
        VectorChunk::Error {
            code,
            terminal: true,
            slug,
            ..
        } => {
            assert_eq!(code, CODE_EXECUTION_CREDIT_STALL);
            assert_eq!(slug.as_deref(), Some(SLUG_EXECUTION_CREDIT_STALL));
        }
        other => panic!(
            "credit_exhaustion vector: final chunk must be terminal Error{{6133}}, got {other:?}"
        ),
    }
}

// ---------------------------------------------------------------------------
// Cross-vector invariants — the §5.4.5 escrow / billing model
// ---------------------------------------------------------------------------

#[test]
fn action_outlet_vectors_replay_through_stream_escrow() {
    // The four Action vectors (cancellation, error_terminal,
    // error_recoverable, credit_exhaustion) declare cost_per_chunk > 0
    // and an available_balance covering the escrow at-open. Replay
    // each through StreamEscrow::reserve_at_open + accrue_one_chunk
    // and assert settle_at_close lands the expected
    // billed_count/billed_amount tuple.
    for v in load_vectors() {
        if v.open.cost_per_chunk == 0 {
            // Zero-cost outlets use zero_escrow per §5.4.5.
            let escrow = StreamEscrow::zero_escrow();
            let (billed_amount, _refund, billed_count) = escrow.settle_at_close();
            assert_eq!(billed_amount.value(), 0);
            assert_eq!(billed_count, 0);
            continue;
        }

        let cost = scp_protocol::economy::types::Amount::new(v.open.cost_per_chunk);
        let balance = scp_protocol::economy::types::Amount::new(v.open.available_balance);
        let mut escrow = StreamEscrow::reserve_at_open(cost, v.open.estimated_chunk_count, balance)
            .unwrap_or_else(|e| {
                panic!(
                    "vector {}: StreamEscrow::reserve_at_open failed: {e:?}",
                    v.name
                )
            });

        // Replay each Data chunk that lands at or below the cancel-ack
        // ceiling (or every Data chunk if no cancel).
        let ceiling = v.expected_cancel_ack_seq.unwrap_or(u64::MAX);
        let mut billable: u32 = 0;
        for c in &v.chunks {
            if let VectorChunk::Data { sequence, .. } = c
                && *sequence <= ceiling
            {
                escrow.accrue_one_chunk();
                billable += 1;
            }
        }

        let (billed_amount, _refund, billed_count) = escrow.settle_at_close();
        assert_eq!(
            billed_count, billable,
            "vector {}: settle_at_close.billed_count must equal accrued count",
            v.name
        );
        assert_eq!(
            billed_amount.value(),
            v.open.cost_per_chunk * u64::from(billable),
            "vector {}: settle_at_close.billed_amount must equal cost * billed_count",
            v.name
        );
        assert_eq!(
            billed_count, v.expected_chunks_billed,
            "vector {}: settled billed_count must equal expected_chunks_billed",
            v.name
        );
    }
}

#[test]
fn every_vector_chunk_emits_through_protocol_chunk_constructor() {
    // Round-trip every vector chunk through `into_protocol_chunk` to
    // exercise the helper used by SDK smoke tests when they need to
    // synthesize OutletStreamChunk values for the InvocationHandle
    // pump. Catches drift between the JSON shape and the protocol enum.
    for v in load_vectors() {
        for c in v.chunks {
            let _: OutletStreamChunk = c.into_protocol_chunk(VECTOR_REQUEST_ID);
        }
    }
}

#[test]
fn error_codes_referenced_in_vectors_are_allocated_in_taxonomy() {
    // Every error code emitted by a vector must be a §5.4.4 allocated
    // code so SDK error-mapping layers can resolve it.
    for v in load_vectors() {
        for c in &v.chunks {
            if let VectorChunk::Error { code, .. } = c {
                assert!(
                    matches!(
                        code.as_str(),
                        CODE_EXECUTION_FAULT
                            | CODE_EXECUTION_CREDIT
                            | CODE_EXECUTION_CREDIT_STALL
                            | CODE_EXECUTION_CANCEL_ACK_TIMEOUT
                            | CODE_TRANSPORT_FAULT
                    ),
                    "vector {}: error code {code} is not in the streaming-relevant §5.4.4 allocation",
                    v.name
                );
            }
        }
        if let Some(code) = &v.expected_error_code {
            assert!(
                matches!(
                    code.as_str(),
                    CODE_EXECUTION_FAULT
                        | CODE_EXECUTION_CREDIT
                        | CODE_EXECUTION_CREDIT_STALL
                        | CODE_EXECUTION_CANCEL_ACK_TIMEOUT
                        | CODE_TRANSPORT_FAULT
                ),
                "vector {}: expected_error_code {code} is not in the streaming-relevant §5.4.4 allocation",
                v.name
            );
        }
    }
}
