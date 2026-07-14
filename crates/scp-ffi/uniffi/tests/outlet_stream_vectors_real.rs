//! SCP-OUT-039 (§5.4.5) — outlet streaming conformance vectors replayed through
//! the ACTUAL UniFFI bridge exports.
//!
//! # Coverage split (read this before extending)
//!
//! This EXTERNAL integration test drives the UniFFI bridge's public streaming
//! exports over all 7 vectors at `tests/conformance/vectors/outlet_stream_vectors.json`:
//!
//! - **Wire integrity (all 7 vectors, every chunk):** each chunk is signed under
//!   the §25.2 reference operator key and replayed through the bridge's public
//!   pure-wrapper exports [`Scp::outlet_stream_verify_chunk_signature`] (true
//!   under the operator key, false under a wrong key) and
//!   [`Scp::outlet_stream_compute_caveats_binding`] (equals the core helper
//!   byte-for-byte). This proves the UniFFI verify/binding marshalling matches
//!   the core §5.4.5 wire contract across the Swift/Kotlin async surface.
//! - **`sequence_gap` (receiver tracker):** the vector's gapped `[0,1,3]`
//!   transcript is signed under the §25.2 key and run through a
//!   `ReceiverSequenceTracker` which fires `Cancelled` with `SCP-OUTLET-6131`
//!   (`execution.stream-gap`) at the third chunk (§5.4.5 "Ordering and gaps" —
//!   a receiver obligation over a lossless same-context channel; the live
//!   trigger is slice-3 transport).
//!
//! # Why the LIVE control plane is NOT driven here (mechanical block, documented)
//!
//! A live open→poll→drain replay (the single-shot-seam vectors: `non_streaming`,
//! `cancellation`, `error_terminal`) requires registering a Rust-side outlet
//! handler, seeding the invoker as a member, granting `OutletCall`, and seeding
//! the creator's DID document — every one of those seams takes the per-bridge
//! `&UniffiBridgeInstance`, reached only through `Scp.inner`, which is
//! `pub(crate)` (crates/scp-ffi/uniffi/src/scp.rs:61), unreachable from an
//! external `tests/` file. The UniFFI crate exposes no public Rust-side
//! handler-registration / member-seeding seam (its own external
//! `tests/e2e_bridge.rs` likewise never drives a live stream). `credit_stall` is
//! NOT a single-shot-seam vector: like §25.21 and the PyO3 header classify it, it
//! is runtime-tier-only — it needs a real `stream_credit_stall_secs` timer to
//! fire the framework credit-stall terminal, which a pure-wrapper/bridge replay
//! cannot drive. The live terminal-status behaviour of all of these vectors is
//! covered by the runtime tiers (SCP-OUT-039 deliverables 2/3 in scp-testing).
//! This file adds the UniFFI bridge's own pure-wrapper wire-integrity tier and
//! does NOT fake a live drive it cannot mechanically perform.

#![cfg(feature = "allow_in_memory_custody")]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::doc_markdown,
    clippy::missing_const_for_fn,
    clippy::format_collect,
    clippy::too_many_lines
)]

use scp_core::context::outlets::stream::{
    ChunkPayload, OutletStreamChunk, compute_caveats_binding, sign_chunk,
};
use scp_core::trust::caveats::InvocationCaveats;
use scp_ffi_uniffi::Scp;

/// The §25.2 reference operator Ed25519 seed (RFC 8032 §7.1 Test Vector 1).
const REFERENCE_OPERATOR_SEED: [u8; 32] = [
    0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4,
    0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60,
];
const VECTOR_CONTEXT_ID: &str = "scp-out-039-ctx";
/// The Ed25519 public key the §25.2 seed above actually derives (verified via
/// `ed25519_dalek`, OpenSSL, and a standalone RFC-8032 impl). Pinned so a
/// corrupted seed byte fails loudly. Matches the §25.2 public key
/// (`…daa62325af021a68f707511a`, RFC 8032 §7.1 TV1) and the repo KAT `REF_PUBKEY`.
const EXPECTED_OPERATOR_PK: [u8; 32] = [
    0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07, 0x3a,
    0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07, 0x51, 0x1a,
];
/// §5.4.5 stream-gap code (shared `CODE_EXECUTION_CREDIT`, slug
/// `execution.stream-gap`).
const CODE_STREAM_GAP: &str = "SCP-OUTLET-6131";

fn vectors() -> serde_json::Value {
    let raw = include_str!("../../../../tests/conformance/vectors/outlet_stream_vectors.json");
    serde_json::from_str(raw).expect("vectors JSON parses")
}

fn sample_provenance() -> scp_core::provenance::DataProvenance {
    use scp_core::context::params::MemoryScope;
    use scp_core::provenance::{DataProvenance, DiscoveryMethod, SourceType};
    DataProvenance {
        source_context: "scp-out-039-source".to_owned(),
        source_type: SourceType::Persistent,
        counterparties: Vec::new(),
        purpose: None,
        discovery_method: DiscoveryMethod::OutOfBand,
        age: std::time::Duration::from_secs(0),
        memory_scope: MemoryScope::Full,
        chain_depth: 0,
        chain_path: None,
        payment_amount: None,
        payment_adapter: None,
        payment_receipt_id: None,
    }
}

fn payload_from_vector(payload: &serde_json::Value) -> ChunkPayload {
    match payload["@type"].as_str().expect("payload @type") {
        "data" => ChunkPayload::Data {
            value: payload["value"].clone(),
        },
        "progress" => ChunkPayload::Progress {
            pct: u16::try_from(payload["pct"].as_u64().expect("pct")).expect("pct u16"),
            note: payload["note"].as_str().map(str::to_owned),
        },
        "end" => ChunkPayload::End {
            aggregate: payload["aggregate"].clone(),
            provenance: sample_provenance(),
            execution_time_ms: payload["execution_time_ms"].as_u64().expect("exec ms"),
        },
        "error" => ChunkPayload::Error {
            code: payload["code"].as_str().expect("code").to_owned(),
            message: payload["message"].as_str().expect("message").to_owned(),
            terminal: payload["terminal"].as_bool().expect("terminal"),
        },
        other => panic!("unknown payload @type: {other}"),
    }
}

fn request_id_from_open(open: &serde_json::Value) -> [u8; 16] {
    let arr = open["request_id"].as_array().expect("request_id array");
    assert_eq!(arr.len(), 16, "request_id is 16 bytes");
    let mut id = [0u8; 16];
    for (i, byte) in arr.iter().enumerate() {
        id[i] = u8::try_from(byte.as_u64().expect("byte")).expect("byte u8");
    }
    id
}

/// Outcome of observing one chunk against the running sequence expectation.
/// Uniform `GapOutcome` enum shape shared across the runtime-layer harness
/// (`outlet_stream_vectors_common.rs`) and the `PyO3` / `NAPI` per-bridge
/// trackers — a single canonical shape so the receiver rule cannot drift.
#[derive(Debug, PartialEq, Eq)]
enum GapOutcome {
    Continue,
    Cancelled { code: String },
}

/// Receiver-side ordering check (§5.4.5 "Ordering and gaps").
struct ReceiverSequenceTracker {
    expected: u64,
}
impl ReceiverSequenceTracker {
    fn new() -> Self {
        Self { expected: 0 }
    }
    fn observe(&mut self, sequence: u64) -> GapOutcome {
        if sequence == self.expected {
            self.expected += 1;
            GapOutcome::Continue
        } else {
            GapOutcome::Cancelled {
                code: CODE_STREAM_GAP.to_owned(),
            }
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn vectors_load_and_have_the_seven_named_scenarios() {
    let doc = vectors();
    let mut names: Vec<&str> = doc["vectors"]
        .as_array()
        .expect("vectors array")
        .iter()
        .map(|v| v["name"].as_str().expect("name"))
        .collect();
    names.sort_unstable();
    assert_eq!(
        names,
        vec![
            "cancellation",
            "credit_stall",
            "error_recoverable",
            "error_terminal",
            "multi_chunk",
            "non_streaming",
            "sequence_gap",
        ],
        "the 7 named streaming vectors are present"
    );
}

/// Every chunk of every vector replayed through the ACTUAL UniFFI bridge
/// pure-wrapper exports.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn all_seven_vectors_wire_integrity_through_uniffi_exports() {
    let scp = Scp::new_in_memory_for_test();
    let operator = ed25519_dalek::SigningKey::from_bytes(&REFERENCE_OPERATOR_SEED);
    assert_eq!(
        operator.verifying_key().as_bytes(),
        &EXPECTED_OPERATOR_PK,
        "the §25.2 reference seed must derive its ground-truth public key"
    );
    let operator_pk = operator.verifying_key().as_bytes().to_vec();
    let wrong_pk = ed25519_dalek::SigningKey::from_bytes(&[0x11u8; 32])
        .verifying_key()
        .as_bytes()
        .to_vec();
    let caveats_jcs = InvocationCaveats::empty()
        .to_canonical_json_bytes()
        .expect("empty caveats JCS");

    let doc = vectors();
    let mut total_chunks = 0usize;
    for vector in doc["vectors"].as_array().expect("vectors array") {
        let open = &vector["open"];
        let outlet_id = open["outlet_id"].as_str().expect("outlet_id").to_owned();
        let invoker_did = open["invoker_did"]
            .as_str()
            .expect("invoker_did")
            .to_owned();
        let estimated_chunk_count =
            u32::try_from(open["estimated_chunk_count"].as_u64().expect("estimate"))
                .expect("estimate u32");
        let request_id = request_id_from_open(open);
        let ucan_cid = open["ucan_cid"].as_str().expect("ucan_cid").to_owned();

        // caveats_binding uses the vector's declared ucan_cid, so it equals the
        // vector's pinned KAT (§25.21) at every SDK tier byte-for-byte.
        let binding_wrapper = scp
            .outlet_stream_compute_caveats_binding(
                ucan_cid.clone().into_bytes(),
                request_id.to_vec(),
                invoker_did.clone(),
                estimated_chunk_count,
                caveats_jcs.clone(),
            )
            .await
            .expect("uniffi binding wrapper");
        let binding_core = compute_caveats_binding(
            ucan_cid.as_bytes(),
            &request_id,
            &invoker_did,
            estimated_chunk_count,
            &caveats_jcs,
        );
        assert_eq!(
            binding_wrapper.as_slice(),
            binding_core.as_slice(),
            "vector {}: UniFFI caveats-binding export must match the core helper",
            vector["name"]
        );
        let binding = <[u8; 32]>::try_from(binding_wrapper.as_slice()).expect("32 bytes");
        let binding_hex = {
            use std::fmt::Write as _;
            let mut h = String::with_capacity(64);
            for b in binding {
                let _ = write!(h, "{b:02x}");
            }
            h
        };
        assert_eq!(
            binding_hex,
            open["expected_caveats_binding"]
                .as_str()
                .expect("expected_caveats_binding"),
            "vector {}: computed caveats_binding must equal the vector's pinned KAT",
            vector["name"]
        );

        for chunk_desc in vector["chunks"].as_array().expect("chunks array") {
            let sequence = chunk_desc["sequence"].as_u64().expect("sequence");
            let payload = payload_from_vector(&chunk_desc["payload"]);
            let sig = sign_chunk(
                &operator,
                VECTOR_CONTEXT_ID,
                &outlet_id,
                &request_id,
                sequence,
                &binding,
                &payload,
            )
            .expect("chunk signs under §25.2 key");
            let chunk = OutletStreamChunk {
                request_id,
                sequence,
                payload,
                sig,
            };
            let chunk_bytes = serde_json::to_vec(&chunk).expect("chunk serializes");
            assert!(
                scp.outlet_stream_verify_chunk_signature(
                    chunk_bytes.clone(),
                    operator_pk.clone(),
                    VECTOR_CONTEXT_ID.to_owned(),
                    outlet_id.clone(),
                    binding.to_vec(),
                )
                .await
                .expect("uniffi verify Ok"),
                "vector {} seq {sequence}: UniFFI verify accepts the §25.2-signed chunk",
                vector["name"]
            );
            assert!(
                !scp.outlet_stream_verify_chunk_signature(
                    chunk_bytes,
                    wrong_pk.clone(),
                    VECTOR_CONTEXT_ID.to_owned(),
                    outlet_id.clone(),
                    binding.to_vec(),
                )
                .await
                .expect("uniffi verify false under wrong key"),
                "vector {} seq {sequence}: UniFFI verify rejects a wrong key",
                vector["name"]
            );
            total_chunks += 1;
        }
    }
    // 2 + 12 + 4 + 2 + 5 + 3 + 2 == 30 chunk descriptors across the 7 vectors
    // (multi_chunk carries an interleaved Progress chunk — §5.4.5).
    assert_eq!(total_chunks, 30, "every chunk descriptor exercised");
}

/// `sequence_gap`: the receiver tracker cancels with `SCP-OUTLET-6131` at the
/// third chunk of the gapped `[0,1,3]` transcript (each chunk authentically
/// §25.2-signed and accepted by the UniFFI verify export).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sequence_gap_receiver_tracker_cancels_with_6131_through_uniffi() {
    let scp = Scp::new_in_memory_for_test();
    let operator = ed25519_dalek::SigningKey::from_bytes(&REFERENCE_OPERATOR_SEED);
    assert_eq!(
        operator.verifying_key().as_bytes(),
        &EXPECTED_OPERATOR_PK,
        "the §25.2 reference seed must derive its ground-truth public key"
    );
    let operator_pk = operator.verifying_key().as_bytes().to_vec();
    let caveats_jcs = InvocationCaveats::empty()
        .to_canonical_json_bytes()
        .expect("empty caveats JCS");

    let doc = vectors();
    let vector = doc["vectors"]
        .as_array()
        .expect("vectors array")
        .iter()
        .find(|v| v["name"] == "sequence_gap")
        .expect("sequence_gap vector");
    let open = &vector["open"];
    let outlet_id = open["outlet_id"].as_str().expect("outlet_id").to_owned();
    let invoker_did = open["invoker_did"]
        .as_str()
        .expect("invoker_did")
        .to_owned();
    let estimated_chunk_count =
        u32::try_from(open["estimated_chunk_count"].as_u64().expect("estimate"))
            .expect("estimate u32");
    let request_id = request_id_from_open(open);
    let ucan_cid = open["ucan_cid"].as_str().expect("ucan_cid").to_owned();

    // The tracker is a test-local reimplementation of the §5.4.5 receiver
    // gap-cancel rule (a lossless same-context pump cannot produce a gap; the
    // live trigger is slice-3 transport). It replays the vector's gapped
    // transcript over a really-signed chunk sequence.
    let binding = compute_caveats_binding(
        ucan_cid.as_bytes(),
        &request_id,
        &invoker_did,
        estimated_chunk_count,
        &caveats_jcs,
    );

    let mut tracker = ReceiverSequenceTracker::new();
    let mut cancelled_at: Option<(u64, String)> = None;
    for chunk_desc in vector["chunks"].as_array().expect("chunks array") {
        let sequence = chunk_desc["sequence"].as_u64().expect("sequence");
        let payload = payload_from_vector(&chunk_desc["payload"]);
        let sig = sign_chunk(
            &operator,
            VECTOR_CONTEXT_ID,
            &outlet_id,
            &request_id,
            sequence,
            &binding,
            &payload,
        )
        .expect("gap chunk signs");
        let chunk = OutletStreamChunk {
            request_id,
            sequence,
            payload,
            sig,
        };
        let chunk_bytes = serde_json::to_vec(&chunk).expect("serializes");
        assert!(
            scp.outlet_stream_verify_chunk_signature(
                chunk_bytes,
                operator_pk.clone(),
                VECTOR_CONTEXT_ID.to_owned(),
                outlet_id.clone(),
                binding.to_vec(),
            )
            .await
            .expect("uniffi verify Ok"),
            "gap transcript chunk seq {sequence} is authentically signed"
        );
        if cancelled_at.is_none()
            && let GapOutcome::Cancelled { code } = tracker.observe(sequence)
        {
            cancelled_at = Some((sequence, code));
        }
    }
    assert_eq!(
        cancelled_at,
        Some((3, CODE_STREAM_GAP.to_owned())),
        "receiver tracker cancels with SCP-OUTLET-6131 at gapped sequence 3"
    );
    assert_eq!(vector["expected_end_status"], "Cancelled");
    assert_eq!(vector["expected_error_code"], CODE_STREAM_GAP);
}
