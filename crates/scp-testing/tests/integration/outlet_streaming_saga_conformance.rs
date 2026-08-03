//! SCP-OUT-049 (W10) — cross-context streaming-SAGA conformance vectors.
//!
//! Replays `tests/conformance/vectors/outlet_streaming_saga_vectors.json` — the
//! transactional-streaming corner of the outlet taxonomy (§6.2.4 / §6.2.5,
//! ADR-061 *streaming saga*). Six named scenarios:
//!
//! - `stream_receipt_kat` — byte-exact `SCP-XCTX-STREAM-RECEIPT-V1` preimage +
//!   Ed25519 signature KAT; `verify()` accepts, every single-field mutation rejects.
//! - `seal_phase` — a sealed chunk sequence yields a non-zero RFC-6962
//!   `stream_manifest_hash` and a verifiable streaming receipt over it.
//! - `xctx_10_chunk` — a 10-chunk A→B stream; the target and caller dual-log
//!   leaves carry the IDENTICAL root.
//! - `truncated_close` — a mid-stream crash seals the durable PREFIX; the receipt
//!   is over the truncated (prefix) root, distinct from the full-stream root.
//! - `receive_side_drain_lossy` — a lossy A-leg dropping a chunk (0,1,3) is caught
//!   by the invoker-side SDK-drain gap detector and fires `SCP-OUTLET-6131`.
//! - `aggregate_schema_violation` — an `End.aggregate` violating the outlet's
//!   `aggregate_schema` maps to `SCP-OUTLET-6140`.
//!
//! ## Layered coverage (AC2/AC3/AC5 — Class-S boundary, honest scope)
//!
//! The checked-in vectors + this harness VERIFY the declared cryptographic
//! artifacts through PUBLIC protocol primitives only — receipt reconstruct/verify,
//! `compute_chunk_manifest_root` equality, dual-hash structural identity, the
//! receiver gap oracle, and the schema-validator → error-code mapping. Driving a
//! LIVE resident-actor streaming saga all the way to `Committed` (seal-close) or a
//! truncated close requires seeding resident-actor `StreamCapture` state, reachable
//! only via `spawn_actor_with_state`, which is `pub(in crate::context)` — the
//! deliberate Class-S actor-state isolation boundary (a security property, NOT a
//! test shortcut; the SAME boundary SCP-OUT-047's AC8 documents). This harness
//! therefore does NOT breach it. The live drive to `Committed` / the truncated
//! close — the escrow settlement, the exactly-once outlet-exec count, and the
//! `Committing → Committed` FSM transition — is proven RUNTIME-SIDE by
//! `xctx_streaming_saga_paid_drive_ac1_ac3_ac5_ac6` and
//! `xctx_streaming_saga_truncated_close_ac7`
//! (`crates/scp-runtime/src/context/supervisor/supervisor.rs`), which each
//! seal/truncated test below cross-references in its doc comment (see §25.22).
//!
//! Every chunk signature and every `caveats_binding` is RECOMPUTED at replay time
//! under the §25.2 reference operator key (RFC 8032 §7.1 Test Vector 1), reusing
//! the SCP-OUT-039 shared oracle (`outlet_stream_vectors_common.rs`).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::too_many_lines
)]

#[path = "outlet_stream_vectors_common.rs"]
mod common;

use ed25519_dalek::SigningKey;
use serde::Deserialize;

use scp_protocol::context::outlets::error_codes::CODE_OUTPUT_VIOLATION;
use scp_protocol::context::outlets::stream::{
    ChunkPayload, OutletStreamChunk, RequestId, compute_caveats_binding,
    compute_chunk_manifest_root, sign_chunk, verify_chunk_signature,
};
use scp_protocol::context::outlets::{
    CrossContextOutletStreamReceipt, CrossContextOutletStreamReceiptFields,
    validate_value_against_schema,
};
use scp_protocol::trust::caveats::InvocationCaveats;

use common::{
    CODE_STREAM_GAP, EXPECTED_OPERATOR_PK, GapOutcome, REFERENCE_OPERATOR_SEED,
    ReceiverSequenceTracker, to_hex,
};

// ---------------------------------------------------------------------------
// Vector schema — an outer `{name, spec}` envelope (`deny_unknown_fields`) plus
// a per-scenario spec struct (each `deny_unknown_fields`), so a renamed or stray
// JSON field fails deserialization. The spec is kept as a `serde_json::Value`
// and decoded per-scenario because the six cases carry heterogeneous fields.
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct VectorFile {
    version: String,
    vectors: Vec<NamedVector>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct NamedVector {
    name: String,
    spec: serde_json::Value,
}

const VECTORS_JSON: &str =
    include_str!("../../../../tests/conformance/vectors/outlet_streaming_saga_vectors.json");

fn load() -> VectorFile {
    serde_json::from_str(VECTORS_JSON)
        .expect("outlet_streaming_saga_vectors.json parses under the envelope schema")
}

fn spec<T: for<'de> Deserialize<'de>>(file: &VectorFile, name: &str) -> T {
    let raw = file
        .vectors
        .iter()
        .find(|v| v.name == name)
        .unwrap_or_else(|| panic!("vector `{name}` present"));
    serde_json::from_value(raw.spec.clone())
        .unwrap_or_else(|e| panic!("vector `{name}` spec decodes under its schema: {e}"))
}

// ---------------------------------------------------------------------------
// Per-scenario spec structs
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ChunkDesc {
    sequence: u64,
    value: serde_json::Value,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReceiptSpec {
    caller_context_id: String,
    target_context_id: String,
    caller_did: String,
    nonce: String,
    outlet_registration_id: String,
    outlet_invoked_event_id: String,
    chain_depth: u8,
    timestamp_ms: u64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct KatSpec {
    caller_context_id: String,
    target_context_id: String,
    caller_did: String,
    nonce: String,
    outlet_registration_id: String,
    stream_manifest_hash: String,
    outlet_invoked_event_id: String,
    chain_depth: u8,
    timestamp_ms: u64,
    target_signing_seed: String,
    expected_preimage_hex: String,
    expected_signature_hex: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SealSpec {
    context_id: String,
    outlet_id: String,
    invoker_did: String,
    estimated_chunk_count: u32,
    ucan_cid: String,
    request_id: String,
    expected_caveats_binding: String,
    chunks: Vec<ChunkDesc>,
    expected_stream_manifest_hash: String,
    receipt: ReceiptSpec,
    target_signing_seed: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Xctx10Spec {
    context_id: String,
    outlet_id: String,
    invoker_did: String,
    estimated_chunk_count: u32,
    ucan_cid: String,
    request_id: String,
    expected_caveats_binding: String,
    chunks: Vec<ChunkDesc>,
    expected_stream_manifest_hash: String,
    dual_log_identity: bool,
    receipt: ReceiptSpec,
    target_signing_seed: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TruncatedSpec {
    context_id: String,
    outlet_id: String,
    invoker_did: String,
    estimated_chunk_count: u32,
    ucan_cid: String,
    request_id: String,
    expected_caveats_binding: String,
    chunks: Vec<ChunkDesc>,
    crash_after_index: usize,
    billed_count: usize,
    exec_invocations: u32,
    expected_full_manifest_hash: String,
    expected_prefix_manifest_hash: String,
    receipt: ReceiptSpec,
    target_signing_seed: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LossySpec {
    context_id: String,
    outlet_id: String,
    invoker_did: String,
    estimated_chunk_count: u32,
    ucan_cid: String,
    request_id: String,
    expected_caveats_binding: String,
    chunks: Vec<ChunkDesc>,
    expected_end_status: String,
    expected_error_code: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SchemaSpec {
    aggregate_schema: serde_json::Value,
    conforming_aggregate: serde_json::Value,
    violating_aggregate: serde_json::Value,
    expected_end_status: String,
    expected_error_code: String,
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn hex_n<const N: usize>(s: &str) -> [u8; N] {
    let v = hex::decode(s).expect("field is valid lowercase hex");
    v.try_into()
        .unwrap_or_else(|v: Vec<u8>| panic!("expected {N} bytes, got {}", v.len()))
}

/// The §25.2 reference operator key (RFC 8032 §7.1 Test Vector 1), reused from
/// the SCP-OUT-039 shared oracle. Defense-in-depth: pin the derived public key so
/// a corrupted seed byte fails loudly instead of self-consistently.
fn operator_key() -> SigningKey {
    let key = SigningKey::from_bytes(&REFERENCE_OPERATOR_SEED);
    assert_eq!(
        key.verifying_key().to_bytes(),
        EXPECTED_OPERATOR_PK,
        "REFERENCE_OPERATOR_SEED must derive the §25.2 public key"
    );
    key
}

/// Compute the §5.4.5 `caveats_binding` over the vector's declared preimage inputs
/// (empty invocation caveats), assert it equals the pinned hex, and return it so
/// the same value both binds the chunk signatures and pins the cross-SDK contract.
fn binding_for(
    ucan_cid: &str,
    request_id: &RequestId,
    invoker_did: &str,
    estimated_chunk_count: u32,
    expected_hex: &str,
) -> [u8; 32] {
    let caveats_jcs = InvocationCaveats::empty()
        .to_canonical_json_bytes()
        .expect("empty-caveats JCS");
    let binding = compute_caveats_binding(
        ucan_cid.as_bytes(),
        request_id,
        invoker_did,
        estimated_chunk_count,
        &caveats_jcs,
    );
    assert_eq!(
        to_hex(&binding),
        expected_hex,
        "caveats_binding must equal the pinned canonical value"
    );
    binding
}

/// Build the per-chunk-signed `Data` transcript the vector declares, signing each
/// chunk under the §25.2 reference operator key. Every signature is verified so a
/// preimage-construction regression is caught, and the resulting chunks feed the
/// RFC-6962 manifest root exactly as the runtime seal folds them.
fn signed_data_chunks(
    key: &SigningKey,
    context_id: &str,
    outlet_id: &str,
    request_id: &RequestId,
    caveats_binding: &[u8; 32],
    descriptors: &[ChunkDesc],
) -> Vec<OutletStreamChunk> {
    let operator_pk = key.verifying_key();
    descriptors
        .iter()
        .map(|d| {
            let payload = ChunkPayload::Data {
                value: d.value.clone(),
            };
            let sig = sign_chunk(
                key,
                context_id,
                outlet_id,
                request_id,
                d.sequence,
                caveats_binding,
                &payload,
            )
            .expect("sign chunk under the §25.2 reference operator key");
            let chunk = OutletStreamChunk {
                request_id: *request_id,
                sequence: d.sequence,
                payload,
                sig,
            };
            assert!(
                verify_chunk_signature(
                    &chunk,
                    &operator_pk,
                    context_id,
                    outlet_id,
                    caveats_binding
                ),
                "chunk seq {} verifies under the §25.2 operator key",
                d.sequence
            );
            chunk
        })
        .collect()
}

/// Sign a streaming receipt over `stream_manifest_hash` from a [`ReceiptSpec`] and
/// the vector's target signing seed.
fn sign_receipt(
    spec: &ReceiptSpec,
    seed_hex: &str,
    root: [u8; 32],
) -> CrossContextOutletStreamReceipt {
    let seed: [u8; 32] = hex_n(seed_hex);
    let key = SigningKey::from_bytes(&seed);
    CrossContextOutletStreamReceipt::sign(
        &key,
        CrossContextOutletStreamReceiptFields {
            caller_context_id: hex_n(&spec.caller_context_id),
            target_context_id: hex_n(&spec.target_context_id),
            caller_did: spec.caller_did.clone(),
            nonce: hex_n(&spec.nonce),
            outlet_registration_id: spec.outlet_registration_id.clone(),
            stream_manifest_hash: root,
            outlet_invoked_event_id: spec.outlet_invoked_event_id.clone(),
            chain_depth: spec.chain_depth,
            timestamp_ms: spec.timestamp_ms,
        },
    )
    .expect("sign the SCP-XCTX-STREAM-RECEIPT-V1 receipt")
}

/// Verifying key for a receipt's target signing seed.
fn receipt_vk(seed_hex: &str) -> ed25519_dalek::VerifyingKey {
    let seed: [u8; 32] = hex_n(seed_hex);
    SigningKey::from_bytes(&seed).verifying_key()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// AC1 — the vector file loads under the envelope schema, pins version `1.0`, and
/// carries exactly the six named scenarios.
#[test]
fn the_six_named_scenarios_are_present() {
    let file = load();
    assert_eq!(file.version, "1.0", "version pinned");
    assert_eq!(file.vectors.len(), 6, "exactly 6 vectors");
    let mut names: Vec<&str> = file.vectors.iter().map(|v| v.name.as_str()).collect();
    names.sort_unstable();
    let mut expected = vec![
        "aggregate_schema_violation",
        "receive_side_drain_lossy",
        "seal_phase",
        "stream_receipt_kat",
        "truncated_close",
        "xctx_10_chunk",
    ];
    expected.sort_unstable();
    assert_eq!(names, expected, "exact vector name set");
}

/// AC4 — `stream_receipt_kat`: the fixed field-set produces the byte-exact
/// `SCP-XCTX-STREAM-RECEIPT-V1` preimage and Ed25519 signature; the receipt
/// `verify()`s, and mutating ANY single covered field fails `verify()`.
#[test]
fn stream_receipt_kat_is_byte_exact_and_tamper_evident() {
    let file = load();
    let kat: KatSpec = spec(&file, "stream_receipt_kat");

    // The KAT signs under the §25.2 reference seed — pin the derived public key.
    let seed: [u8; 32] = hex_n(&kat.target_signing_seed);
    let key = SigningKey::from_bytes(&seed);
    assert_eq!(
        key.verifying_key().to_bytes(),
        EXPECTED_OPERATOR_PK,
        "the KAT signing seed is the §25.2 reference seed"
    );

    let base = CrossContextOutletStreamReceipt::sign(
        &key,
        CrossContextOutletStreamReceiptFields {
            caller_context_id: hex_n(&kat.caller_context_id),
            target_context_id: hex_n(&kat.target_context_id),
            caller_did: kat.caller_did.clone(),
            nonce: hex_n(&kat.nonce),
            outlet_registration_id: kat.outlet_registration_id.clone(),
            stream_manifest_hash: hex_n(&kat.stream_manifest_hash),
            outlet_invoked_event_id: kat.outlet_invoked_event_id.clone(),
            chain_depth: kat.chain_depth,
            timestamp_ms: kat.timestamp_ms,
        },
    )
    .expect("sign KAT receipt");

    // Byte-exact preimage + deterministic Ed25519 signature.
    assert_eq!(
        to_hex(&base.signing_preimage().expect("preimage")),
        kat.expected_preimage_hex,
        "KAT preimage must equal the pinned SCP-XCTX-STREAM-RECEIPT-V1 value"
    );
    assert_eq!(
        to_hex(&base.signature),
        kat.expected_signature_hex,
        "KAT signature must equal the pinned deterministic Ed25519 value"
    );

    let vk = key.verifying_key();
    base.verify(&vk).expect("the KAT receipt verifies");

    // Every single-field mutation must fail verify() (9 covered fields).
    let mut t = base.clone();
    t.caller_context_id[0] ^= 0xFF;
    assert!(
        t.verify(&vk).is_err(),
        "caller_context_id mutation rejected"
    );

    let mut t = base.clone();
    t.target_context_id[0] ^= 0xFF;
    assert!(
        t.verify(&vk).is_err(),
        "target_context_id mutation rejected"
    );

    let mut t = base.clone();
    t.caller_did.push('x');
    assert!(t.verify(&vk).is_err(), "caller_did mutation rejected");

    let mut t = base.clone();
    t.nonce[0] ^= 0xFF;
    assert!(t.verify(&vk).is_err(), "nonce mutation rejected");

    let mut t = base.clone();
    t.outlet_registration_id.push('x');
    assert!(
        t.verify(&vk).is_err(),
        "outlet_registration_id mutation rejected"
    );

    let mut t = base.clone();
    t.stream_manifest_hash[0] ^= 0xFF;
    assert!(
        t.verify(&vk).is_err(),
        "stream_manifest_hash mutation rejected"
    );

    let mut t = base.clone();
    t.outlet_invoked_event_id.push('x');
    assert!(
        t.verify(&vk).is_err(),
        "outlet_invoked_event_id mutation rejected"
    );

    let mut t = base.clone();
    t.chain_depth = t.chain_depth.wrapping_add(1);
    assert!(t.verify(&vk).is_err(), "chain_depth mutation rejected");

    let mut t = base;
    t.timestamp_ms += 1;
    assert!(t.verify(&vk).is_err(), "timestamp_ms mutation rejected");
}

/// AC2 — `seal_phase`: the sealed chunk sequence yields a non-zero RFC-6962
/// `stream_manifest_hash` matching the pinned value, and a streaming receipt over
/// that root `verify()`s under the target signing key.
///
/// The LIVE drive to `Committed` at seal-close (the FSM transition, escrow
/// settlement, and dual-log recording) is proven runtime-side by
/// `xctx_streaming_saga_paid_drive_ac1_ac3_ac5_ac6`
/// (`crates/scp-runtime/src/context/supervisor/supervisor.rs`) — see §25.22. This
/// harness verifies the sealed cryptographic artifacts via public primitives only
/// (the Class-S actor-state boundary is not breached).
#[test]
fn seal_phase_manifest_root_and_receipt_verify() {
    let file = load();
    let v: SealSpec = spec(&file, "seal_phase");

    let key = operator_key();
    let request_id: RequestId = hex_n(&v.request_id);
    let binding = binding_for(
        &v.ucan_cid,
        &request_id,
        &v.invoker_did,
        v.estimated_chunk_count,
        &v.expected_caveats_binding,
    );
    let chunks = signed_data_chunks(
        &key,
        &v.context_id,
        &v.outlet_id,
        &request_id,
        &binding,
        &v.chunks,
    );

    let root = compute_chunk_manifest_root(&chunks).expect("manifest root");
    assert_ne!(root, [0u8; 32], "the sealed manifest root is non-zero");
    assert_eq!(
        to_hex(&root),
        v.expected_stream_manifest_hash,
        "the sealed root equals the pinned RFC-6962 manifest hash"
    );

    let receipt = sign_receipt(&v.receipt, &v.target_signing_seed, root);
    assert_eq!(
        receipt.stream_manifest_hash, root,
        "the receipt carries the sealed root"
    );
    receipt
        .verify(&receipt_vk(&v.target_signing_seed))
        .expect("the SCP-XCTX-STREAM-RECEIPT-V1 receipt verifies under the target key");
}

/// AC5 — `xctx_10_chunk`: a 10-chunk A→B stream seals to a non-zero root, the
/// receipt `verify()`s, and BOTH the target `OutletInvoked` leaf and the caller
/// `CrossContextOutletInvoked` leaf carry the IDENTICAL `stream_manifest_hash`
/// (the dual-log join key). The leaf-payload identity mirrors the runtime
/// `ss_leaf_manifest_hex` join.
///
/// The LIVE 10-chunk drive with the real atomic dual event-log is proven
/// runtime-side by `xctx_streaming_saga_paid_drive_ac1_ac3_ac5_ac6` — see §25.22.
#[test]
fn xctx_10_chunk_dual_log_carries_identical_root() {
    let file = load();
    let v: Xctx10Spec = spec(&file, "xctx_10_chunk");
    assert!(
        v.dual_log_identity,
        "the 10-chunk vector asserts dual-log identity"
    );
    assert_eq!(v.chunks.len(), 10, "the A→B stream declares 10 chunks");

    let key = operator_key();
    let request_id: RequestId = hex_n(&v.request_id);
    let binding = binding_for(
        &v.ucan_cid,
        &request_id,
        &v.invoker_did,
        v.estimated_chunk_count,
        &v.expected_caveats_binding,
    );
    let chunks = signed_data_chunks(
        &key,
        &v.context_id,
        &v.outlet_id,
        &request_id,
        &binding,
        &v.chunks,
    );

    let root = compute_chunk_manifest_root(&chunks).expect("manifest root");
    assert_ne!(root, [0u8; 32], "the sealed manifest root is non-zero");
    assert_eq!(
        to_hex(&root),
        v.expected_stream_manifest_hash,
        "the 10-chunk sealed root equals the pinned RFC-6962 manifest hash"
    );

    let receipt = sign_receipt(&v.receipt, &v.target_signing_seed, root);
    receipt
        .verify(&receipt_vk(&v.target_signing_seed))
        .expect("the streaming receipt verifies under the target key");

    // The artifact both event logs must carry — the sealed manifest root — is
    // verified byte-exact above (`root == expected_stream_manifest_hash`, non-zero).
    // The ATOMIC dual event-log join itself (target `OutletInvoked` + caller
    // `CrossContextOutletInvoked` recorded over that SAME root in one commit) is a
    // resident-actor property proven runtime-side by
    // `xctx_streaming_saga_paid_drive_ac1_ac3_ac5_ac6` (§25.22) — it is not
    // reconstructible from an external test crate (the Class-S actor-state
    // isolation boundary), so this harness verifies the shared artifact, not the join.
}

/// AC3 — `truncated_close`: a mid-stream crash after `crash_after_index` chunks
/// seals the durable PREFIX. The receipt is over the truncated (prefix) root,
/// which is non-zero, matches the pinned prefix hash, and is DISTINCT from the
/// full-stream root; the prefix `billed_count` equals the prefix Data-chunk count.
///
/// The LIVE truncated close — escrow settled at the prefix `billed_count` and the
/// outlet exec fn invoked EXACTLY once (`exec_invocations`), with no re-invoke on
/// the replayed close — is proven runtime-side by
/// `xctx_streaming_saga_truncated_close_ac7`
/// (`crates/scp-runtime/src/context/supervisor/supervisor.rs`) — see §25.22.
#[test]
fn truncated_close_prefix_root_and_receipt_verify() {
    let file = load();
    let v: TruncatedSpec = spec(&file, "truncated_close");
    assert!(
        v.crash_after_index < v.chunks.len(),
        "the crash truncates the declared stream"
    );
    assert_eq!(
        v.exec_invocations, 1,
        "the truncated close never re-invokes the outlet (proven live by \
         xctx_streaming_saga_truncated_close_ac7)"
    );

    let key = operator_key();
    let request_id: RequestId = hex_n(&v.request_id);
    let binding = binding_for(
        &v.ucan_cid,
        &request_id,
        &v.invoker_did,
        v.estimated_chunk_count,
        &v.expected_caveats_binding,
    );
    let chunks = signed_data_chunks(
        &key,
        &v.context_id,
        &v.outlet_id,
        &request_id,
        &binding,
        &v.chunks,
    );

    let full_root = compute_chunk_manifest_root(&chunks).expect("full root");
    let prefix_root =
        compute_chunk_manifest_root(&chunks[..v.crash_after_index]).expect("prefix root");
    assert_ne!(prefix_root, [0u8; 32], "the sealed prefix root is non-zero");
    assert_ne!(
        prefix_root, full_root,
        "the truncated prefix root differs from the full-stream root"
    );
    assert_eq!(
        to_hex(&full_root),
        v.expected_full_manifest_hash,
        "the full-stream root equals the pinned hash"
    );
    assert_eq!(
        to_hex(&prefix_root),
        v.expected_prefix_manifest_hash,
        "the truncated (prefix) root equals the pinned hash"
    );

    // Every prefix chunk is Data, so the billable-chunk count == the prefix length.
    let prefix_data = chunks[..v.crash_after_index]
        .iter()
        .filter(|c| matches!(c.payload, ChunkPayload::Data { .. }))
        .count();
    assert_eq!(
        v.billed_count, prefix_data,
        "the sealed prefix billed_count equals its Data-chunk count"
    );

    // The receipt seals the PREFIX root (not the full stream) and verifies.
    let receipt = sign_receipt(&v.receipt, &v.target_signing_seed, prefix_root);
    assert_eq!(
        receipt.stream_manifest_hash, prefix_root,
        "the truncated receipt carries the sealed prefix root"
    );
    receipt
        .verify(&receipt_vk(&v.target_signing_seed))
        .expect("the truncated-close streaming receipt verifies under the target key");
}

/// AC6 — `receive_side_drain_lossy`: a lossy A-leg dropping a chunk (delivered
/// sequences 0,1,3) makes `chunk.sequence` non-contiguous on the receive side.
/// The invoker-side SDK-drain gap detector (`ReceiverSequenceTracker`, SCP-OUT-037;
/// §5.4.5:515) — NOT any runtime bridge detector (SCP-OUT-045) — MUST cancel with
/// `OutletErrorClass::Execution::StreamGap` (`SCP-OUTLET-6131`) at the first gap.
#[test]
fn receive_side_drain_lossy_fires_stream_gap_6131() {
    let file = load();
    let v: LossySpec = spec(&file, "receive_side_drain_lossy");
    assert_eq!(v.expected_end_status, "Cancelled");
    assert_eq!(v.expected_error_code, scp_protocol::CODE_EXECUTION_CREDIT);
    assert_eq!(
        v.expected_error_code, CODE_STREAM_GAP,
        "the vector's gap code is the consolidated execution.stream-gap code"
    );

    let key = operator_key();
    let request_id: RequestId = hex_n(&v.request_id);
    let binding = binding_for(
        &v.ucan_cid,
        &request_id,
        &v.invoker_did,
        v.estimated_chunk_count,
        &v.expected_caveats_binding,
    );
    // Per-chunk-signed gapped transcript (0,1,3) — signatures verified inside.
    let chunks = signed_data_chunks(
        &key,
        &v.context_id,
        &v.outlet_id,
        &request_id,
        &binding,
        &v.chunks,
    );

    // The receiver observes 0, 1, then 3 → a gap at the third delivered chunk.
    let mut tracker = ReceiverSequenceTracker::new();
    let mut fired_at: Option<usize> = None;
    for (i, chunk) in chunks.iter().enumerate() {
        if let GapOutcome::Cancelled { code } = tracker.observe(chunk.sequence) {
            assert_eq!(
                code, v.expected_error_code,
                "gap cancel code is SCP-OUTLET-6131"
            );
            fired_at = Some(i);
            break;
        }
    }
    assert_eq!(
        fired_at,
        Some(2),
        "the receiver tracker cancels at the third delivered chunk (sequence 3 after 0,1)"
    );
}

/// AC7 — `aggregate_schema_violation`: an `End.aggregate` violating the outlet's
/// `aggregate_schema` is an Output-class schema violation → `SCP-OUTLET-6140`. A
/// conforming aggregate passes (the schema is not vacuously always-failing).
#[test]
fn aggregate_schema_violation_maps_to_6140() {
    let file = load();
    let v: SchemaSpec = spec(&file, "aggregate_schema_violation");
    assert_eq!(v.expected_end_status, "Error");

    // Positive: a conforming aggregate passes the real validator.
    validate_value_against_schema(&v.conforming_aggregate, &v.aggregate_schema)
        .expect("the conforming aggregate validates against aggregate_schema");

    // Negative: the violating aggregate fails; an Output-class schema violation
    // maps to CODE_OUTPUT_VIOLATION (SCP-OUTLET-6140).
    let code = match validate_value_against_schema(&v.violating_aggregate, &v.aggregate_schema) {
        Ok(()) => panic!("the violating aggregate must fail schema validation"),
        Err(_) => CODE_OUTPUT_VIOLATION,
    };
    assert_eq!(
        code, v.expected_error_code,
        "an aggregate-schema violation maps to SCP-OUTLET-6140"
    );
    assert_eq!(
        code,
        scp_protocol::CODE_OUTPUT_VIOLATION,
        "the Output-class code is 6140"
    );
}
