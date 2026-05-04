//! Cross-SDK byte-equivalence conformance fixture for the §5.4.5
//! streaming preimages: `caveats_binding`, `chunk_sig_preimage`, and
//! `credit_sig_preimage`.
//!
//! Spec §5.4.5 line 635 (and ADR-049 §5/round-5/JCS-Option-rule, line 207)
//! promises that the four SDKs (PyO3, NAPI, UniFFI Swift / Kotlin, WASM)
//! produce **byte-identical** 32-byte hashes for the same inputs. That
//! invariant has no in-tree fixture before this module — the alignment
//! review for SCP-OUT-039 surfaced the gap. This module ships the
//! reference inputs and the goldens; the conformance tests in
//! `scp-testing` and the per-SDK replay tests in `bindings/*` consume
//! them.
//!
//! # Vector classes
//!
//! - **caveats_binding** — `compute_caveats_binding(ucan_cid, request_id,
//!   invoker_did, estimated_chunk_count, canonical_jcs(effective_caveats))`
//!   per §5.4.5 / ADR-049 §5. Three vectors covering: minimal caveats
//!   (only `amount_max_per_call`), a multi-field narrowing
//!   (`amount_max_per_call`, `max_calls`, `valid_until`, `origin_kind`),
//!   and the `empty()` caveat set with the §5.4.5 omit-none rule
//!   producing `canonical_jcs == "{}"`.
//! - **chunk_sig_preimage** — `compute_chunk_sig_preimage` over `Data`
//!   and `End` payloads. Two vectors so the JCS canonicalization of
//!   distinct `ChunkPayload` variants is also pinned (the `@type`
//!   discriminator + variant-specific body keys must round-trip in the
//!   same canonical order across SDKs).
//! - **credit_sig_preimage** — `compute_credit_sig_preimage(context_id,
//!   outlet_id, request_id, grant, monotonic_seq, stream_epoch,
//!   caveats_binding)`. Two vectors covering distinct `(grant,
//!   monotonic_seq, stream_epoch)` tuples.
//!
//! All goldens are 32-byte SHA-256 outputs encoded as 64-char lowercase
//! hex in the JSON file. The Rust generator computes them once via the
//! protocol-level helpers and pins them; the per-SDK replay tests
//! verify byte-for-byte equality.
//!
//! # On-disk fixture
//!
//! `tests/conformance/vectors/outlet_caveats_binding_fixtures.json`
//! (workspace-root path returned by [`vectors_path`]). Regenerate with:
//!
//! ```bash
//! cargo test -p scp-testing --test outlet_caveats_binding_conformance \
//!   conf_outlet_caveats_binding_regen -- --ignored --nocapture
//! ```

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::too_many_lines,
    clippy::doc_markdown,
    clippy::doc_overindented_list_items,
    clippy::missing_panics_doc,
    clippy::missing_const_for_fn,
    clippy::too_long_first_doc_paragraph
)]

use std::path::PathBuf;

use ed25519_dalek::SigningKey;
use scp_primitives::DID;
use scp_protocol::context::outlets::stream::{
    ChunkPayload, RequestId, compute_caveats_binding, compute_chunk_sig_preimage,
    compute_credit_sig_preimage,
};
use scp_protocol::economy::types::Amount;
use scp_protocol::trust::caveats::InvocationCaveats;
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// On-disk schema
// ---------------------------------------------------------------------------

/// One input-and-expected-output triple for a `caveats_binding` vector.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaveatsBindingVector {
    /// Stable case identifier.
    pub name: String,
    /// Human-readable narrative cross-referenced to the spec.
    pub description: String,
    /// `ucan_cid` raw bytes encoded as lowercase hex.
    pub ucan_cid_hex: String,
    /// 16-byte `request_id` encoded as 32-char lowercase hex.
    pub request_id_hex: String,
    /// `invoker_did` string.
    pub invoker_did: String,
    /// Invoker-declared billable-chunk ceiling.
    pub estimated_chunk_count: u32,
    /// JCS-canonical `effective_caveats` JSON string. SDKs MUST produce
    /// this exact string after applying the §5.4.5 omit-none rule
    /// (absent `Option` fields omitted, NOT serialized as explicit
    /// `null`). Length-prefixed in the preimage per §9.5.1.
    pub effective_caveats_jcs: String,
    /// Expected 32-byte hash encoded as 64-char lowercase hex.
    pub expected_caveats_binding_hex: String,
}

/// One input-and-expected-output triple for a `chunk_sig_preimage` vector.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChunkSigPreimageVector {
    /// Stable case identifier.
    pub name: String,
    /// Human-readable narrative cross-referenced to the spec.
    pub description: String,
    /// Hosting context id committed into the preimage.
    pub context_id: String,
    /// Outlet id committed into the preimage.
    pub outlet_id: String,
    /// 16-byte `request_id` encoded as 32-char lowercase hex.
    pub request_id_hex: String,
    /// Strictly-monotonic chunk sequence number.
    pub sequence: u64,
    /// 32-byte `caveats_binding` encoded as 64-char lowercase hex.
    pub caveats_binding_hex: String,
    /// JSON-encoded `ChunkPayload` (the typed enum the Rust crate
    /// serializes — SDKs reconstruct the same payload from this JSON).
    pub payload_json: serde_json::Value,
    /// Expected 32-byte preimage hash encoded as 64-char lowercase hex.
    pub expected_chunk_sig_preimage_hex: String,
}

/// One input-and-expected-output triple for a `credit_sig_preimage` vector.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreditSigPreimageVector {
    /// Stable case identifier.
    pub name: String,
    /// Human-readable narrative cross-referenced to the spec.
    pub description: String,
    /// Hosting context id committed into the preimage.
    pub context_id: String,
    /// Outlet id committed into the preimage.
    pub outlet_id: String,
    /// 16-byte `request_id` encoded as 32-char lowercase hex.
    pub request_id_hex: String,
    /// Number of additional billable chunks granted.
    pub grant: u32,
    /// Per-stream monotonic grant counter.
    pub monotonic_seq: u64,
    /// MLS epoch counter pinned at stream open.
    pub stream_epoch: u64,
    /// 32-byte `caveats_binding` encoded as 64-char lowercase hex.
    pub caveats_binding_hex: String,
    /// Expected 32-byte preimage hash encoded as 64-char lowercase hex.
    pub expected_credit_sig_preimage_hex: String,
}

/// Top-level fixture file shape.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaveatsBindingFixtureFile {
    /// Free-form provenance / narrative comment.
    pub comment: String,
    /// Canonical spec section reference.
    pub spec_section: String,
    /// PRD story id this fixture lands under.
    pub story: String,
    /// `caveats_binding` vectors.
    pub caveats_binding: Vec<CaveatsBindingVector>,
    /// `chunk_sig_preimage` vectors.
    pub chunk_sig_preimage: Vec<ChunkSigPreimageVector>,
    /// `credit_sig_preimage` vectors.
    pub credit_sig_preimage: Vec<CreditSigPreimageVector>,
}

// ---------------------------------------------------------------------------
// Path
// ---------------------------------------------------------------------------

/// Workspace-root path to the canonical fixture JSON.
#[must_use]
pub fn vectors_path() -> PathBuf {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    // crates/scp-testing → workspace root: pop twice.
    p.pop();
    p.pop();
    p.push("tests");
    p.push("conformance");
    p.push("vectors");
    p.push("outlet_caveats_binding_fixtures.json");
    p
}

// ---------------------------------------------------------------------------
// Reference inputs — pinned at module level so the generator and the
// runtime checks consume the same constants.
// ---------------------------------------------------------------------------

/// Reference `ucan_cid` bytes for `cb_minimal` and `chunk_sig_data` vectors.
const REF_UCAN_CID_A: &[u8] = b"bafyreigh1234567890abcdef-cb-vector-a";
/// Reference `ucan_cid` bytes for `cb_multifield` vector.
const REF_UCAN_CID_B: &[u8] = b"bafyreih7777777777777777-cb-vector-b";
/// Reference `ucan_cid` bytes for `cb_empty` vector.
const REF_UCAN_CID_C: &[u8] = b"bafkreif0000000000000000-cb-vector-c";

/// Reference `request_id` (16 bytes) for vector A.
const REF_REQUEST_ID_A: RequestId = [
    0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77,
];
/// Reference `request_id` (16 bytes) for vector B.
const REF_REQUEST_ID_B: RequestId = [
    0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf, 0xb0,
];
/// Reference `request_id` (16 bytes) for vector C.
const REF_REQUEST_ID_C: RequestId = [
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
];

/// Reference invoker DID strings.
const REF_INVOKER_DID_A: &str = "did:dht:zCAVEATS-BINDING-INVOKER-A";
const REF_INVOKER_DID_B: &str = "did:dht:zCAVEATS-BINDING-INVOKER-B";
const REF_INVOKER_DID_C: &str = "did:dht:zCAVEATS-BINDING-INVOKER-C";

/// Reference 32-byte `caveats_binding` for the `chunk_sig` and `credit_sig`
/// vectors — derived deterministically so the goldens are reproducible.
fn ref_caveats_binding_for_chunk_sig() -> [u8; 32] {
    [0xab; 32]
}

fn ref_caveats_binding_for_credit_sig() -> [u8; 32] {
    [0xcd; 32]
}

// ---------------------------------------------------------------------------
// Caveats reference values
// ---------------------------------------------------------------------------

/// Vector `cb_minimal`: only `amount_max_per_call` set. Exercises the
/// §5.4.5 omit-none rule on every other `Option`-typed field of
/// [`InvocationCaveats`] — none of them appear in the JCS bytes.
#[must_use]
pub fn caveats_minimal() -> InvocationCaveats {
    let mut c = InvocationCaveats::empty();
    c.amount_max_per_call = Some(Amount::new(100));
    c
}

/// Vector `cb_multifield`: a realistic delegation-narrowing shape with
/// `amount_max_per_call`, `max_calls`, `valid_until`, and `origin_kind`
/// all populated. Exercises the JCS lexicographic key ordering
/// invariant — the four field names sort as
/// `amountMaxPerCall < maxCalls < originKind < validUntil` (ASCII
/// lexicographic).
#[must_use]
pub fn caveats_multifield() -> InvocationCaveats {
    let mut c = InvocationCaveats::empty();
    c.amount_max_per_call = Some(Amount::new(500));
    c.max_calls = Some(64);
    c.valid_until = Some(2_000_000_000); // arbitrary unix timestamp
    c.origin_kind = Some(scp_protocol::context::outlets::OutletKind::Action);
    c
}

/// Vector `cb_empty`: the [`InvocationCaveats::empty`] / "no
/// constraints" shape. Per §5.4.5 the JCS canonicalization MUST
/// produce the empty JSON object `{}` (NOT `{"...":null,...}` for every
/// `Option`-typed field). The generator commits the binding for this
/// shape so an SDK that implements `null`-on-`None` instead of
/// `omit-on-None` produces a different binding and fails this test.
#[must_use]
pub const fn caveats_empty() -> InvocationCaveats {
    InvocationCaveats::empty()
}

// ---------------------------------------------------------------------------
// Generator
// ---------------------------------------------------------------------------

/// Builds the full fixture file from the in-tree reference inputs.
///
/// # Panics
///
/// Panics if JCS canonicalization fails (unreachable for valid
/// [`InvocationCaveats`]).
#[must_use]
pub fn build_fixture_file() -> CaveatsBindingFixtureFile {
    let cb_vectors = build_caveats_binding_vectors();
    let chunk_vectors = build_chunk_sig_preimage_vectors();
    let credit_vectors = build_credit_sig_preimage_vectors();
    CaveatsBindingFixtureFile {
        comment: "SCP-OUT-039 cross-SDK byte-equivalence fixture per §5.4.5 line 635 / \
                  ADR-049 §5 round-5 JCS Option rule. Three caveats_binding vectors cover: \
                  minimal (single field), multifield (lexicographic ordering across \
                  amountMaxPerCall < maxCalls < originKind < validUntil), and empty \
                  (omit-none JCS rule produces `{}`). Two chunk_sig_preimage vectors \
                  cover Data and End payload variants (the @type discriminator must sort \
                  to JCS position 0 in every variant). Two credit_sig_preimage vectors \
                  cover distinct (grant, monotonic_seq, stream_epoch) tuples to pin the \
                  big-endian encoding rule. All four SDKs (PyO3, NAPI, UniFFI Swift/Kotlin, \
                  WASM) MUST reproduce the goldens byte-for-byte. SDKs that emit explicit \
                  `null` for absent Option fields will fail the cb_empty case immediately."
            .to_owned(),
        spec_section: ".docs/specs/05-contexts.md §5.4.5 caveats_binding / chunk_sig / credit_sig"
            .to_owned(),
        story: "SCP-OUT-039 (alignment-review remediation)".to_owned(),
        caveats_binding: cb_vectors,
        chunk_sig_preimage: chunk_vectors,
        credit_sig_preimage: credit_vectors,
    }
}

fn build_caveats_binding_vectors() -> Vec<CaveatsBindingVector> {
    vec![
        build_caveats_binding_vector(
            "cb_minimal",
            "Single-field narrowing — only `amountMaxPerCall` populated. Exercises the \
             §5.4.5 omit-none rule: every other `Option`-typed InvocationCaveats field \
             is absent and MUST be omitted from the JCS encoding (NOT serialized as \
             explicit `null`). An SDK that emits `null` for absent fields produces a \
             distinct caveats_binding and fails this vector immediately.",
            REF_UCAN_CID_A,
            &REF_REQUEST_ID_A,
            REF_INVOKER_DID_A,
            16,
            &caveats_minimal(),
        ),
        build_caveats_binding_vector(
            "cb_multifield",
            "Realistic delegation-narrowing shape — `amountMaxPerCall`, `maxCalls`, \
             `validUntil`, and `originKind` all populated. Exercises RFC 8785 JCS \
             lexicographic key ordering: the four field names sort as \
             amountMaxPerCall < maxCalls < originKind < validUntil. SDKs whose serde \
             default does not lexicographically sort keys produce a distinct binding.",
            REF_UCAN_CID_B,
            &REF_REQUEST_ID_B,
            REF_INVOKER_DID_B,
            128,
            &caveats_multifield(),
        ),
        build_caveats_binding_vector(
            "cb_empty",
            "InvocationCaveats::empty() — every Option field is None. Per §5.4.5 the \
             JCS canonicalization MUST produce the literal `{}` (a two-byte JSON \
             object with no keys). This is the canonical regression for the omit-none \
             rule: SDKs that emit `{\"amountMaxPerCall\":null,...}` for the empty \
             caveat set produce a distinct binding and fail this vector.",
            REF_UCAN_CID_C,
            &REF_REQUEST_ID_C,
            REF_INVOKER_DID_C,
            1,
            &caveats_empty(),
        ),
    ]
}

fn build_caveats_binding_vector(
    name: &str,
    description: &str,
    ucan_cid: &[u8],
    request_id: &RequestId,
    invoker_did: &str,
    estimated_chunk_count: u32,
    caveats: &InvocationCaveats,
) -> CaveatsBindingVector {
    let caveats_jcs = scp_protocol::jcs::to_vec(caveats).expect("JCS canonicalization");
    let caveats_jcs_str = std::str::from_utf8(&caveats_jcs)
        .expect("JCS output is UTF-8")
        .to_owned();
    let binding = compute_caveats_binding(
        ucan_cid,
        request_id,
        invoker_did,
        estimated_chunk_count,
        &caveats_jcs,
    );
    CaveatsBindingVector {
        name: name.to_owned(),
        description: description.to_owned(),
        ucan_cid_hex: hex::encode(ucan_cid),
        request_id_hex: hex::encode(request_id),
        invoker_did: invoker_did.to_owned(),
        estimated_chunk_count,
        effective_caveats_jcs: caveats_jcs_str,
        expected_caveats_binding_hex: hex::encode(binding),
    }
}

fn build_chunk_sig_preimage_vectors() -> Vec<ChunkSigPreimageVector> {
    let caveats_binding = ref_caveats_binding_for_chunk_sig();

    let context_id = "ctx-cs-vector";
    let outlet_id = "outlet-cs-vector";
    let request_id = REF_REQUEST_ID_A;

    let data_payload = ChunkPayload::Data {
        value: serde_json::json!({"sample": "data", "n": 42}),
    };
    let end_payload = ChunkPayload::End {
        aggregate: serde_json::json!({"total": 100, "ok": true}),
        provenance: synthetic_provenance(),
        execution_time_ms: 250,
    };

    let data_preimage = compute_chunk_sig_preimage(
        context_id,
        outlet_id,
        &request_id,
        7,
        &caveats_binding,
        &data_payload,
    )
    .expect("Data chunk preimage");

    let end_preimage = compute_chunk_sig_preimage(
        context_id,
        outlet_id,
        &request_id,
        8,
        &caveats_binding,
        &end_payload,
    )
    .expect("End chunk preimage");

    vec![
        ChunkSigPreimageVector {
            name: "chunk_sig_data".to_owned(),
            description: "Data variant — the most common chunk shape. Exercises the \
                          @type discriminator sort-to-position-0 invariant in JCS \
                          (`@` is 0x40, sorts before lowercase `value` 0x76)."
                .to_owned(),
            context_id: context_id.to_owned(),
            outlet_id: outlet_id.to_owned(),
            request_id_hex: hex::encode(request_id),
            sequence: 7,
            caveats_binding_hex: hex::encode(caveats_binding),
            payload_json: serde_json::to_value(&data_payload).expect("payload to JSON"),
            expected_chunk_sig_preimage_hex: hex::encode(data_preimage),
        },
        ChunkSigPreimageVector {
            name: "chunk_sig_end".to_owned(),
            description: "End variant — terminal aggregate + provenance. Exercises the \
                          full provenance block in JCS canonicalization. The four End \
                          body keys sort as @type < aggregate < execution_time_ms < \
                          provenance under JCS."
                .to_owned(),
            context_id: context_id.to_owned(),
            outlet_id: outlet_id.to_owned(),
            request_id_hex: hex::encode(request_id),
            sequence: 8,
            caveats_binding_hex: hex::encode(caveats_binding),
            payload_json: serde_json::to_value(&end_payload).expect("payload to JSON"),
            expected_chunk_sig_preimage_hex: hex::encode(end_preimage),
        },
    ]
}

fn build_credit_sig_preimage_vectors() -> Vec<CreditSigPreimageVector> {
    let caveats_binding = ref_caveats_binding_for_credit_sig();
    let context_id = "ctx-credit-vector";
    let outlet_id = "outlet-credit-vector";

    let case_a = CreditSigPreimageVector {
        name: "credit_sig_first_grant".to_owned(),
        description: "First grant on a fresh stream — monotonic_seq=1 (the §5.4.5 \
                      invariant: monotonic_seq starts at 0 in the runtime tracker, \
                      first grant uses 1). Exercises the (grant, monotonic_seq, \
                      stream_epoch) big-endian encoding."
            .to_owned(),
        context_id: context_id.to_owned(),
        outlet_id: outlet_id.to_owned(),
        request_id_hex: hex::encode(REF_REQUEST_ID_A),
        grant: 32,
        monotonic_seq: 1,
        stream_epoch: 0,
        caveats_binding_hex: hex::encode(caveats_binding),
        expected_credit_sig_preimage_hex: hex::encode(compute_credit_sig_preimage(
            context_id,
            outlet_id,
            &REF_REQUEST_ID_A,
            32,
            1,
            0,
            &caveats_binding,
        )),
    };

    let case_b = CreditSigPreimageVector {
        name: "credit_sig_later_grant_post_epoch_advance".to_owned(),
        description: "Later grant after several MLS epoch advances and prior grants. \
                      monotonic_seq=42, stream_epoch=7. Exercises distinct big-endian \
                      encodings of u32(grant) and u64(monotonic_seq, stream_epoch) \
                      relative to the first vector. SDKs that confuse little- and \
                      big-endian for any of the three integers fail this vector."
            .to_owned(),
        context_id: context_id.to_owned(),
        outlet_id: outlet_id.to_owned(),
        request_id_hex: hex::encode(REF_REQUEST_ID_B),
        grant: 1024,
        monotonic_seq: 42,
        stream_epoch: 7,
        caveats_binding_hex: hex::encode(caveats_binding),
        expected_credit_sig_preimage_hex: hex::encode(compute_credit_sig_preimage(
            context_id,
            outlet_id,
            &REF_REQUEST_ID_B,
            1024,
            42,
            7,
            &caveats_binding,
        )),
    };

    vec![case_a, case_b]
}

/// Synthetic provenance block — deterministic so the End-chunk preimage
/// vector reproduces. Fields chosen to match the simplest legal shape
/// `DataProvenance` accepts.
fn synthetic_provenance() -> scp_protocol::provenance::DataProvenance {
    scp_protocol::provenance::DataProvenance {
        source_context: "vec-ctx-credit-binding".into(),
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
// Verifier — used by the conformance test to assert each vector
// reproduces under the in-tree code path.
// ---------------------------------------------------------------------------

/// Re-runs every vector through the protocol-level helpers and returns
/// `Ok(())` if every recorded golden matches what the in-tree code
/// produces today; otherwise returns a `Vec<String>` of diagnostics.
///
/// # Errors
///
/// Returns the first hash mismatch encountered, or a JCS canonicalization
/// failure (unreachable for valid inputs).
pub fn verify_fixture_against_helpers(
    fixture: &CaveatsBindingFixtureFile,
) -> Result<(), Vec<String>> {
    let mut errors: Vec<String> = Vec::new();

    for v in &fixture.caveats_binding {
        let ucan_cid = match hex::decode(&v.ucan_cid_hex) {
            Ok(b) => b,
            Err(e) => {
                errors.push(format!("{}: ucan_cid_hex is not valid hex: {e}", v.name));
                continue;
            }
        };
        let request_id = match decode_request_id(&v.request_id_hex) {
            Ok(r) => r,
            Err(e) => {
                errors.push(format!("{}: {e}", v.name));
                continue;
            }
        };
        let actual = compute_caveats_binding(
            &ucan_cid,
            &request_id,
            &v.invoker_did,
            v.estimated_chunk_count,
            v.effective_caveats_jcs.as_bytes(),
        );
        let expected = match decode_hash_32(&v.expected_caveats_binding_hex) {
            Ok(h) => h,
            Err(e) => {
                errors.push(format!("{}: {e}", v.name));
                continue;
            }
        };
        if actual != expected {
            errors.push(format!(
                "{}: caveats_binding mismatch — expected {}, got {}",
                v.name,
                hex::encode(expected),
                hex::encode(actual)
            ));
        }
    }

    for v in &fixture.chunk_sig_preimage {
        let request_id = match decode_request_id(&v.request_id_hex) {
            Ok(r) => r,
            Err(e) => {
                errors.push(format!("{}: {e}", v.name));
                continue;
            }
        };
        let caveats_binding = match decode_hash_32(&v.caveats_binding_hex) {
            Ok(h) => h,
            Err(e) => {
                errors.push(format!("{}: {e}", v.name));
                continue;
            }
        };
        let payload: ChunkPayload =
            match serde_json::from_value::<ChunkPayload>(v.payload_json.clone()) {
                Ok(p) => p,
                Err(e) => {
                    errors.push(format!("{}: payload deserialise failed: {e}", v.name));
                    continue;
                }
            };
        let actual = match compute_chunk_sig_preimage(
            &v.context_id,
            &v.outlet_id,
            &request_id,
            v.sequence,
            &caveats_binding,
            &payload,
        ) {
            Ok(h) => h,
            Err(e) => {
                errors.push(format!(
                    "{}: chunk_sig_preimage compute failed: {e}",
                    v.name
                ));
                continue;
            }
        };
        let expected = match decode_hash_32(&v.expected_chunk_sig_preimage_hex) {
            Ok(h) => h,
            Err(e) => {
                errors.push(format!("{}: {e}", v.name));
                continue;
            }
        };
        if actual != expected {
            errors.push(format!(
                "{}: chunk_sig_preimage mismatch — expected {}, got {}",
                v.name,
                hex::encode(expected),
                hex::encode(actual)
            ));
        }
    }

    for v in &fixture.credit_sig_preimage {
        let request_id = match decode_request_id(&v.request_id_hex) {
            Ok(r) => r,
            Err(e) => {
                errors.push(format!("{}: {e}", v.name));
                continue;
            }
        };
        let caveats_binding = match decode_hash_32(&v.caveats_binding_hex) {
            Ok(h) => h,
            Err(e) => {
                errors.push(format!("{}: {e}", v.name));
                continue;
            }
        };
        let actual = compute_credit_sig_preimage(
            &v.context_id,
            &v.outlet_id,
            &request_id,
            v.grant,
            v.monotonic_seq,
            v.stream_epoch,
            &caveats_binding,
        );
        let expected = match decode_hash_32(&v.expected_credit_sig_preimage_hex) {
            Ok(h) => h,
            Err(e) => {
                errors.push(format!("{}: {e}", v.name));
                continue;
            }
        };
        if actual != expected {
            errors.push(format!(
                "{}: credit_sig_preimage mismatch — expected {}, got {}",
                v.name,
                hex::encode(expected),
                hex::encode(actual)
            ));
        }
    }

    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors)
    }
}

fn decode_request_id(s: &str) -> Result<RequestId, String> {
    let bytes = hex::decode(s).map_err(|e| format!("request_id_hex decode: {e}"))?;
    bytes.try_into().map_err(|got: Vec<u8>| {
        format!(
            "request_id must decode to exactly 16 bytes, got {}",
            got.len()
        )
    })
}

fn decode_hash_32(s: &str) -> Result<[u8; 32], String> {
    let bytes = hex::decode(s).map_err(|e| format!("32-byte hash hex decode: {e}"))?;
    bytes
        .try_into()
        .map_err(|got: Vec<u8>| format!("hash must decode to exactly 32 bytes, got {}", got.len()))
}

// ---------------------------------------------------------------------------
// Cross-SDK signing reference — used by the per-SDK chunk-signature
// round-trip tests so each SDK can verify a chunk Rust signed.
// ---------------------------------------------------------------------------

/// Reference signing key used for the `chunk_sig_data` round-trip.
/// SDKs verify against this key to prove their `verify_chunk_signature`
/// path consumes the same preimage bytes the protocol layer produces.
#[must_use]
pub fn reference_chunk_signing_key() -> SigningKey {
    SigningKey::from_bytes(&[0x42; 32])
}

/// Reference DID for the `chunk_sig` vectors.
#[must_use]
pub fn reference_invoker_did() -> DID {
    REF_INVOKER_DID_A.into()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    /// The fixture file must regenerate to a stable byte-for-byte
    /// identical shape. Any drift between two consecutive
    /// [`build_fixture_file`] calls is a bug.
    #[test]
    fn build_fixture_file_is_deterministic() {
        let a = build_fixture_file();
        let b = build_fixture_file();
        let a_json = serde_json::to_string_pretty(&a).unwrap();
        let b_json = serde_json::to_string_pretty(&b).unwrap();
        assert_eq!(a_json, b_json, "fixture builder must be deterministic");
    }

    /// `verify_fixture_against_helpers` MUST pass against a freshly
    /// generated fixture (the helpers built it; round-tripping is
    /// trivially required).
    #[test]
    fn verify_fixture_round_trips() {
        let fixture = build_fixture_file();
        match verify_fixture_against_helpers(&fixture) {
            Ok(()) => {}
            Err(errs) => panic!("fresh fixture must verify; errors: {errs:#?}"),
        }
    }

    /// The empty caveats vector MUST canonicalize to `{}`. Any other
    /// output indicates the omit-none rule has regressed.
    #[test]
    fn empty_caveats_canonicalizes_to_empty_object() {
        let bytes = scp_protocol::jcs::to_vec(&caveats_empty()).expect("JCS");
        assert_eq!(
            std::str::from_utf8(&bytes).unwrap(),
            "{}",
            "empty caveats MUST produce literal `{{}}` under JCS"
        );
    }

    /// Multifield caveats MUST canonicalize with keys in lexicographic
    /// order: amountMaxPerCall < maxCalls < originKind < validUntil.
    #[test]
    fn multifield_caveats_canonicalizes_in_lexicographic_order() {
        let bytes = scp_protocol::jcs::to_vec(&caveats_multifield()).expect("JCS");
        let s = std::str::from_utf8(&bytes).unwrap();
        let amount_pos = s.find("amountMaxPerCall").expect("present");
        let max_calls_pos = s.find("maxCalls").expect("present");
        let origin_kind_pos = s.find("originKind").expect("present");
        let valid_until_pos = s.find("validUntil").expect("present");
        assert!(
            amount_pos < max_calls_pos,
            "amountMaxPerCall < maxCalls: {s}"
        );
        assert!(
            max_calls_pos < origin_kind_pos,
            "maxCalls < originKind: {s}"
        );
        assert!(
            origin_kind_pos < valid_until_pos,
            "originKind < validUntil: {s}"
        );
    }

    /// Empty caveats vector binding must NOT equal a binding produced
    /// by an SDK that emits `null` for absent Option fields. Because
    /// we don't have a literal "with-nulls" caveats type to JCS, we
    /// pin the discriminator differently: the binding for
    /// `effective_caveats_jcs == "{}"` (correct omit-none) MUST NOT
    /// equal the binding for `effective_caveats_jcs ==
    /// "{\"amountMaxPerCall\":null}"` (incorrect null-on-None) when
    /// every other input is identical.
    #[test]
    fn omit_none_binding_differs_from_null_on_none_binding() {
        let omit_none_bytes = b"{}";
        let null_on_none_bytes = b"{\"amountMaxPerCall\":null}";
        let request_id = REF_REQUEST_ID_C;
        let omit_none = compute_caveats_binding(
            REF_UCAN_CID_C,
            &request_id,
            REF_INVOKER_DID_C,
            1,
            omit_none_bytes,
        );
        let null_on_none = compute_caveats_binding(
            REF_UCAN_CID_C,
            &request_id,
            REF_INVOKER_DID_C,
            1,
            null_on_none_bytes,
        );
        assert_ne!(
            omit_none, null_on_none,
            "omit-none and null-on-none MUST produce distinct caveats_binding values; \
             this is the entire point of the §5.4.5 cross-SDK rule"
        );
    }
}
