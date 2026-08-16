//! SCP-OUT-039 (C12) — outlet-streaming conformance vectors, `PyO3` bridge layer.
//!
//! Replays `tests/conformance/vectors/outlet_stream_vectors.json` through the
//! ACTUAL `PyO3` bridge exports (`outlet_stream_open` → `outlet_stream_poll_next`
//! → `outlet_stream_grant_credit` / `outlet_stream_cancel`) against the
//! in-memory runtime.
//!
//! ## Live vs. runtime-layer coverage
//!
//! The `PyO3` registered-handler seam is SINGLE-SHOT: `BridgeStreamExecutor`
//! (`crates/scp-ffi/src/outlet_stream.rs`) wraps an
//! `Fn(Value) -> Result<Value, String>` handler that returns ONE aggregate
//! value, which the default `exec_*_stream` turns into a degenerate
//! one-`Data`-chunk stream (framework appends the terminal `End`). A handler
//! therefore CANNOT emit the multi-chunk transcripts of `multi_chunk` or
//! `error_recoverable` (a non-terminal `Error` followed by more `Data`), so
//! those two are NOT faked here — they are covered at the runtime layer
//! (`crates/scp-testing/tests/integration/outlet_stream_conformance.rs` and
//! `..._through_open_path.rs`, i.e. 2 of the 3 runtime tiers). `credit_stall`
//! likewise cannot be produced by a single-shot handler (it emits exactly one
//! billable chunk and closes `Ok`, never stalling), so its `SCP-OUTLET-6133`
//! terminal is covered at the runtime layer too.
//!
//! Driven LIVE through the real bridge here:
//!
//! * `non_streaming` — handler returns an aggregate; drain `Data` → `End` (Ok).
//! * `error_terminal` — handler faults; framework terminal `Error{6130}`.
//! * `cancellation` — the real cancel control plane: CRITICAL #1 (a non-invoker
//!   caller is rejected `SCP-PERM-3001`), the pinned invoker's bridge-signed
//!   cancel is NOT a signature/auth failure (`SCP-OUTLET-6110`), and the stream
//!   drains to a framework terminal. (The clean `StreamTerminalStatus::Cancelled`
//!   cancel-ack chunk is asserted deterministically at the runtime layer.)
//! * `sequence_gap` — a lossless same-context channel CANNOT emit a gap (§5.4.5
//!   "Ordering and gaps": receiver cancel-and-rerun; the live wire trigger is
//!   slice-3 transport). Exercised via a `ReceiverSequenceTracker` over the
//!   vector's gapped, per-chunk-signed transcript, asserting the §5.4.5
//!   receiver-MUST-cancel rule fires with `execution.stream-gap` /
//!   `SCP-OUTLET-6131`.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::too_many_lines,
    clippy::format_collect
)]

use ed25519_dalek::SigningKey;

use scp_core::context::outlets::error_codes::CODE_EXECUTION_CREDIT;
use scp_core::context::outlets::stream::{
    ChunkPayload, OutletStreamChunk, compute_caveats_binding, sign_chunk, verify_chunk_signature,
};
use scp_core::context::params::MemoryScope;
use scp_core::provenance::{DataProvenance, DiscoveryMethod, SourceType};
use scp_core::trust::caveats::InvocationCaveats;

// ---------------------------------------------------------------------------
// §25.2 reference operator key — RFC 8032 §7.1 Test Vector 1. Chunk signatures
// in the gap-transcript test are produced under this key so the vector is
// reproducible cross-SDK.
// ---------------------------------------------------------------------------

const REFERENCE_OPERATOR_SEED: [u8; 32] = [
    0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4,
    0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60,
];

/// The Ed25519 public key the §25.2 seed above actually derives (verified via
/// `ed25519_dalek`, OpenSSL, and a standalone RFC-8032 impl). Pinned so a
/// corrupted seed byte fails loudly. Matches the §25.2 public key
/// (`…daa62325af021a68f707511a`, RFC 8032 §7.1 TV1) and the repo KAT `REF_PUBKEY`.
const EXPECTED_OPERATOR_PK: [u8; 32] = [
    0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07, 0x3a,
    0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07, 0x51, 0x1a,
];

const VECTORS_JSON: &str =
    include_str!("../../../tests/conformance/vectors/outlet_stream_vectors.json");

// ---------------------------------------------------------------------------
// Vector accessors (serde_json::Value — scp-ffi has no `serde` derive dep; the
// `deny_unknown_fields` typed-schema enforcement lives in the runtime-layer
// test, `outlet_stream_conformance.rs`).
// ---------------------------------------------------------------------------

fn vectors_doc() -> serde_json::Value {
    serde_json::from_str(VECTORS_JSON).expect("outlet_stream_vectors.json parses")
}

fn vector_named(doc: &serde_json::Value, name: &str) -> serde_json::Value {
    doc["vectors"]
        .as_array()
        .expect("vectors is an array")
        .iter()
        .find(|v| v["name"].as_str() == Some(name))
        .unwrap_or_else(|| panic!("vector `{name}` present"))
        .clone()
}

fn request_id_from_open(open: &serde_json::Value) -> [u8; 16] {
    let arr = open["request_id"].as_array().expect("request_id array");
    assert_eq!(arr.len(), 16, "request_id is 16 bytes");
    let mut id = [0u8; 16];
    for (i, b) in arr.iter().enumerate() {
        id[i] = u8::try_from(b.as_u64().expect("request_id byte")).expect("byte fits u8");
    }
    id
}

/// Sample provenance for `End` chunks the vector describes without one.
fn sample_provenance() -> DataProvenance {
    DataProvenance {
        source_context: "ctx-outlet-stream-vectors-pyo3".into(),
        source_type: SourceType::Persistent,
        counterparties: vec!["did:dht:z6MkConformance".into()],
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

/// Converts one vector payload descriptor into a real [`ChunkPayload`], injecting
/// a sample [`DataProvenance`] for the `End` variant (the vector omits it).
fn payload_from_vector(payload: &serde_json::Value) -> ChunkPayload {
    match payload["@type"].as_str().expect("payload @type") {
        "data" => ChunkPayload::Data {
            value: payload["value"].clone(),
        },
        "progress" => ChunkPayload::Progress {
            pct: u16::try_from(payload["pct"].as_u64().expect("pct")).expect("pct fits u16"),
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

// ---------------------------------------------------------------------------
// ReceiverSequenceTracker — the §5.4.5 receiver-side gap detector (shared shape
// with the runtime-layer test).
// ---------------------------------------------------------------------------

#[derive(Debug, PartialEq, Eq)]
enum GapOutcome {
    Continue,
    Cancelled { code: String },
}

struct ReceiverSequenceTracker {
    expected: u64,
}

impl ReceiverSequenceTracker {
    const fn new() -> Self {
        Self { expected: 0 }
    }

    fn observe(&mut self, sequence: u64) -> GapOutcome {
        if sequence != self.expected {
            return GapOutcome::Cancelled {
                code: CODE_EXECUTION_CREDIT.to_owned(),
            };
        }
        self.expected += 1;
        GapOutcome::Continue
    }
}

// ---------------------------------------------------------------------------
// Pure tests (no bridge) — run under the binary's `testing`.
// ---------------------------------------------------------------------------

#[test]
fn vectors_json_has_the_seven_named_scenarios() {
    let doc = vectors_doc();
    let vectors = doc["vectors"].as_array().expect("vectors array");
    assert_eq!(vectors.len(), 7, "exactly 7 streaming conformance vectors");
    let mut names: Vec<&str> = vectors
        .iter()
        .map(|v| v["name"].as_str().unwrap())
        .collect();
    names.sort_unstable();
    let mut expected = [
        "cancellation",
        "credit_stall",
        "error_recoverable",
        "error_terminal",
        "multi_chunk",
        "non_streaming",
        "sequence_gap",
    ];
    expected.sort_unstable();
    assert_eq!(names, expected, "the seven named scenarios are present");
}

/// `sequence_gap`: the receiver observes the vector's gapped, per-chunk-signed
/// transcript `[0, 1, 3]` and MUST cancel with `execution.stream-gap` /
/// `SCP-OUTLET-6131` the moment sequence 3 arrives where 2 was expected. Each
/// chunk is signed under the §25.2 reference operator key and verified, so the
/// transcript is a real signed sequence, not a bare index list.
#[test]
fn sequence_gap_receiver_tracker_cancels_with_6131() {
    let doc = vectors_doc();
    let v = vector_named(&doc, "sequence_gap");
    let open = &v["open"];
    let outlet_id = open["outlet_id"].as_str().expect("outlet_id");
    let invoker_did = open["invoker_did"].as_str().expect("invoker_did");
    let estimated =
        u32::try_from(open["estimated_chunk_count"].as_u64().expect("est")).expect("est fits u32");
    let request_id = request_id_from_open(open);

    let operator = SigningKey::from_bytes(&REFERENCE_OPERATOR_SEED);
    assert_eq!(
        operator.verifying_key().as_bytes(),
        &EXPECTED_OPERATOR_PK,
        "the §25.2 reference seed must derive its ground-truth public key"
    );
    let operator_pk = operator.verifying_key();
    let caveats_jcs = InvocationCaveats::empty()
        .to_canonical_json_bytes()
        .expect("caveats JCS");
    let context_id = "scp-out-039-gap-ctx";
    // caveats_binding uses the vector's declared ucan_cid, so it equals the
    // vector's pinned KAT (§25.21) — the same binding every tier reproduces.
    let ucan_cid = open["ucan_cid"].as_str().expect("ucan_cid");
    let binding = compute_caveats_binding(
        ucan_cid.as_bytes(),
        &request_id,
        invoker_did,
        estimated,
        &caveats_jcs,
    );
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
        "computed caveats_binding must equal the vector's pinned KAT"
    );

    // The tracker is a test-local reimplementation of the §5.4.5 receiver
    // gap-cancel rule (a lossless same-context pump cannot produce a gap; the
    // live trigger is slice-3 transport). It replays the vector's gapped
    // transcript over a really-signed chunk sequence.
    let mut tracker = ReceiverSequenceTracker::new();
    let mut cancelled_at: Option<u64> = None;
    for chunk_desc in v["chunks"].as_array().expect("chunks array") {
        let sequence = chunk_desc["sequence"].as_u64().expect("sequence");
        let payload = payload_from_vector(&chunk_desc["payload"]);
        let sig = sign_chunk(
            &operator,
            context_id,
            outlet_id,
            &request_id,
            sequence,
            &binding,
            &payload,
        )
        .expect("chunk signs under §25.2 operator key");
        let chunk = OutletStreamChunk {
            request_id,
            sequence,
            payload,
            sig,
        };
        assert!(
            verify_chunk_signature(&chunk, &operator_pk, context_id, outlet_id, &binding),
            "seq {sequence}: signed chunk verifies under the operator key"
        );
        if let GapOutcome::Cancelled { code } = tracker.observe(chunk.sequence) {
            assert_eq!(
                code,
                scp_core::context::outlets::error_codes::CODE_EXECUTION_CREDIT,
                "gap cancels with the consolidated code"
            );
            cancelled_at = Some(chunk.sequence);
            break;
        }
    }
    assert_eq!(
        cancelled_at,
        Some(3),
        "the receiver cancels at the gapped sequence 3 (2 missing)"
    );
}

// ---------------------------------------------------------------------------
// Live bridge tests — require the in-memory harness + the capability-grant seam.
// ---------------------------------------------------------------------------

#[cfg(all(feature = "testing", feature = "outlet-capability-test-grant"))]
mod live {
    use std::sync::Once;

    use pyo3::prelude::*;
    use pyo3::types::{PyDict, PyList};

    use _scp_core::context::PyContextHandle;
    use _scp_core::runtime::{self, PyBridgeInstance};
    use scp_core::context::outlets::stream::{ChunkPayload, OutletStreamChunk};

    static INIT: Once = Once::new();

    fn setup() {
        INIT.call_once(|| {
            pyo3::prepare_freethreaded_python();
            _scp_core::init_runtime().unwrap();
        });
    }

    /// Shared, process-lifetime multi-thread tokio runtime (see `e2e_bridge.rs`:
    /// a per-call runtime would abort the spawned context actor).
    fn test_runtime() -> &'static tokio::runtime::Runtime {
        static RT: std::sync::OnceLock<tokio::runtime::Runtime> = std::sync::OnceLock::new();
        RT.get_or_init(|| {
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_all()
                .build()
                .unwrap()
        })
    }

    fn published_identity_did(py: Python<'_>, scp: &_scp_core::scp::PyScp) -> String {
        scp.identity_create(py, "in_memory", None)
            .unwrap()
            .into_pyobject(py)
            .unwrap()
            .getattr("did")
            .unwrap()
            .extract::<String>()
            .unwrap()
    }

    fn handle_context_id(py: Python<'_>, handle: &PyContextHandle) -> String {
        handle
            .clone()
            .into_pyobject(py)
            .unwrap()
            .getattr("context_id")
            .unwrap()
            .extract::<String>()
            .unwrap()
    }

    /// Builds an outlet registration `PyDict` with a valid (2+ property) schema.
    fn build_outlet_reg<'py>(
        py: Python<'py>,
        name: &str,
        operator_did: &str,
    ) -> Bound<'py, PyDict> {
        let reg = PyDict::new(py);
        reg.set_item("name", name).unwrap();
        reg.set_item("description", format!("Outlet: {name}"))
            .unwrap();
        reg.set_item("operator_did", operator_did).unwrap();
        let schema = PyDict::new(py);
        let is = PyDict::new(py);
        is.set_item("type", "object").unwrap();
        let is_props = PyDict::new(py);
        let s_type = PyDict::new(py);
        s_type.set_item("type", "string").unwrap();
        is_props.set_item("a", s_type.clone()).unwrap();
        is_props.set_item("b", s_type).unwrap();
        is.set_item("properties", is_props).unwrap();
        let os = PyDict::new(py);
        os.set_item("type", "object").unwrap();
        let os_props = PyDict::new(py);
        let n_type = PyDict::new(py);
        n_type.set_item("type", "number").unwrap();
        os_props.set_item("sum", n_type.clone()).unwrap();
        os_props.set_item("ok", n_type).unwrap();
        os.set_item("properties", os_props).unwrap();
        schema.set_item("input_schema", is).unwrap();
        schema.set_item("output_schema", os).unwrap();
        reg.set_item("schema", schema).unwrap();

        let tv = PyDict::new(py);
        let tv_input = PyDict::new(py);
        tv_input.set_item("a", "hello").unwrap();
        tv_input.set_item("b", "world").unwrap();
        let tv_output = PyDict::new(py);
        tv_output.set_item("sum", 42).unwrap();
        tv_output.set_item("ok", 1).unwrap();
        tv.set_item("input", tv_input).unwrap();
        tv.set_item("expected_output", tv_output).unwrap();
        tv.set_item("description", "test vector").unwrap();
        let tv_list = PyList::new(py, &[tv]).unwrap();
        reg.set_item("test_vectors", tv_list).unwrap();
        reg
    }

    /// Opens a live stream against a freshly-created context + outlet with the
    /// given Python `handler_src` registered. Returns
    /// `(context_id, outlet_id, invoker_did, handle_id)`. The invoker is seeded
    /// as a member with `outlet_call:*` (mirrors `e2e_bridge.rs` setup).
    fn open_live(
        py: Python<'_>,
        scp: &_scp_core::scp::PyScp,
        bi: &PyBridgeInstance,
        outlet_name: &str,
        handler_src: &std::ffi::CStr,
        est: Option<u32>,
    ) -> (String, String, String, String) {
        let creator = published_identity_did(py, scp);
        let invoker = published_identity_did(py, scp);

        let ctx = {
            let params = PyDict::new(py);
            let handle = scp.context_create(&creator, &params.as_borrowed()).unwrap();
            handle_context_id(py, &handle)
        };

        let reg = build_outlet_reg(py, outlet_name, &creator);
        let outlet_id = scp.outlet_register(&ctx, &reg.as_borrowed()).unwrap();

        let handler: PyObject = py.eval(handler_src, None, None).unwrap().unbind();
        scp.py_register_outlet_handler(py, &ctx, &outlet_id, handler)
            .unwrap();

        {
            let rt = test_runtime();
            let supervisor = runtime::supervisor(bi).unwrap().clone();
            rt.block_on(supervisor.test_insert_member(
                &ctx,
                scp_did::DID(invoker.clone()),
                "member",
            ))
            .expect("seed invoker as member");
            rt.block_on(supervisor.test_grant_member_capability(
                &ctx,
                scp_did::DID(invoker.clone()),
                "outlet_call:*",
            ))
            .expect("grant OutletCallAll to invoker");
        }

        let ucan = scp
            .ucan_mint(&ctx, &invoker, vec!["outlet_call:*".to_owned()], None)
            .unwrap();

        let input = PyDict::new(py);
        input.set_item("a", "1").unwrap();
        input.set_item("b", "2").unwrap();

        let handle_id = scp
            .outlet_stream_open(
                &ctx,
                &outlet_id,
                &input.as_borrowed(),
                &invoker,
                &ucan.encoded,
                None,
                None,
                None,
                est,
            )
            .expect("member invoker opens the stream");

        (ctx, outlet_id, invoker, handle_id)
    }

    /// Drains `poll_next` to the first terminal chunk, returning the ordered
    /// chunks observed (including the terminal). Stops on `None` / not-found
    /// (abnormal close) or after a generous poll budget.
    fn drain_to_terminal(
        py: Python<'_>,
        scp: &_scp_core::scp::PyScp,
        handle_id: &str,
    ) -> Vec<OutletStreamChunk> {
        let mut chunks = Vec::new();
        for _ in 0..64 {
            match scp.outlet_stream_poll_next(py, handle_id) {
                Ok(Some(bytes)) => {
                    let chunk: OutletStreamChunk = serde_json::from_slice(&bytes).unwrap();
                    let terminal = chunk.payload.is_terminal();
                    chunks.push(chunk);
                    if terminal {
                        break;
                    }
                }
                // Channel closed without a terminal, or the entry was evicted at
                // a prior terminal — either way the drain is done.
                Ok(None) | Err(_) => break,
            }
        }
        chunks
    }

    /// `non_streaming`: a handler returning an aggregate drains to a `Data` chunk
    /// followed by the framework's terminal `End` (Ok).
    #[test]
    fn non_streaming_drains_data_then_end_ok() {
        Python::with_gil(|py| {
            setup();
            let scp = _scp_core::scp::PyScp::new_in_memory_for_test();
            let bi = scp.bridge_instance();
            runtime::init_context_manager_for_test(bi);

            let (_ctx, _outlet, _invoker, handle_id) = open_live(
                py,
                &scp,
                bi,
                "vec_non_streaming",
                c"lambda i: {'sum': 3, 'ok': 1}",
                Some(1),
            );

            let chunks = drain_to_terminal(py, &scp, &handle_id);
            assert!(
                chunks
                    .iter()
                    .any(|c| matches!(c.payload, ChunkPayload::Data { .. })),
                "at least one Data chunk was delivered"
            );
            let last = chunks.last().expect("at least a terminal chunk");
            assert!(
                matches!(last.payload, ChunkPayload::End { .. }),
                "the stream closes Ok with a framework End, got {:?}",
                last.payload
            );
        });
    }

    /// `error_terminal`: a faulting handler is mapped by the framework to a
    /// terminal `Error{terminal:true}` carrying `SCP-OUTLET-6130`
    /// (`CODE_EXECUTION_FAULT`, execution.handler-panic).
    #[test]
    fn error_terminal_maps_handler_fault_to_6130() {
        Python::with_gil(|py| {
            setup();
            let scp = _scp_core::scp::PyScp::new_in_memory_for_test();
            let bi = scp.bridge_instance();
            runtime::init_context_manager_for_test(bi);

            let (_ctx, _outlet, _invoker, handle_id) = open_live(
                py,
                &scp,
                bi,
                "vec_error_terminal",
                c"lambda i: 1 / 0",
                Some(1),
            );

            let chunks = drain_to_terminal(py, &scp, &handle_id);
            let last = chunks.last().expect("a terminal chunk arrives");
            match &last.payload {
                ChunkPayload::Error { code, terminal, .. } => {
                    assert!(*terminal, "the error chunk is terminal");
                    assert_eq!(
                        code,
                        scp_core::context::outlets::error_codes::CODE_EXECUTION_FAULT,
                        "handler fault maps to CODE_EXECUTION_FAULT"
                    );
                }
                other => panic!("expected terminal Error, got {other:?}"),
            }
        });
    }

    /// §5.4.5 "Signature refusal" step 2: when the operator key refuses a chunk
    /// AND refuses the terminal `Error` chunk that would have reported that
    /// refusal, the pump hands its receiver a typed `ChunkSignatureRefused`
    /// instead of a chunk. `outlet_stream_poll_next` RAISES `SCP-OUTLET-6137`
    /// for that item and evicts the registry entry. Returning the closed
    /// sentinel instead would tell an iterating caller the stream completed,
    /// which is the reading §5.4.5 step 2 exists to prevent.
    ///
    /// The refusal is armed on the live stream's receiver rather than produced
    /// by a failing custody call: no bridge export makes the operator's custody
    /// backend refuse a chosen signature mid-pump. Everything downstream of the
    /// item is the production path — the live registry entry, `poll_next`, the
    /// error it builds, and the eviction it performs.
    #[test]
    fn signature_refusal_raises_6137_and_evicts_the_entry() {
        use scp_core::context::outlets::error_codes::CODE_EXECUTION_SIGNING_REFUSED;
        use scp_core::context::outlets::{
            ChunkSignatureRefused, StreamSignerCustodyCategory, StreamSignerError,
        };

        Python::with_gil(|py| {
            setup();
            let scp = _scp_core::scp::PyScp::new_in_memory_for_test();
            let bi = scp.bridge_instance();
            runtime::init_context_manager_for_test(bi);

            let (_ctx, _outlet, _invoker, handle_id) = open_live(
                py,
                &scp,
                bi,
                "vec_signature_refusal",
                c"lambda i: {'sum': 3, 'ok': 1}",
                Some(1),
            );

            // The canonicalizer message is derived from the executor's payload,
            // so this marker must NOT reach the caller's exception text.
            let payload_marker = "outlet-payload-fragment-7c3d";
            assert!(
                scp.arm_test_stream_signature_refusal(
                    &handle_id,
                    ChunkSignatureRefused {
                        refused_chunk: StreamSignerError::Custody {
                            category: StreamSignerCustodyCategory::KeyNotFound,
                        },
                        refused_terminal: StreamSignerError::Jcs(format!(
                            "key must be a string: {payload_marker}"
                        )),
                    },
                ),
                "the live open registered a stream entry to arm"
            );

            let err = scp
                .outlet_stream_poll_next(py, &handle_id)
                .expect_err("a signature refusal raises instead of returning the closed sentinel");
            let rendered = err.to_string();
            assert!(
                rendered.contains(CODE_EXECUTION_SIGNING_REFUSED),
                "the raised error carries the §5.4.4 signing-refused code: {rendered}"
            );
            assert!(
                rendered.contains(StreamSignerCustodyCategory::KeyNotFound.as_str()),
                "the message names the custody category the key refused with: {rendered}"
            );
            assert!(
                !rendered.contains(payload_marker),
                "the canonicalizer's payload-derived text stays out of the message: {rendered}"
            );

            assert!(
                !scp.test_stream_entry_present(&handle_id),
                "the refusal evicted the registry entry, as the terminal and \
                 closed paths do"
            );

            // The evicted handle now reads as the distinct not-found error the
            // control plane uses — never `Ok(None)`, which would still look like
            // a clean close.
            let after = scp
                .outlet_stream_poll_next(py, &handle_id)
                .expect_err("the evicted handle is a not-found error, not a clean close");
            assert!(
                after.to_string().contains("no active outlet stream"),
                "the post-refusal poll is the not-found error: {after}"
            );
        });
    }

    /// `cancellation`: exercises the real cancel control plane end-to-end.
    /// CRITICAL #1 — a non-invoker caller is rejected `SCP-PERM-3001` before any
    /// signing. The pinned invoker's bridge-signed cancel is never a
    /// signature/auth failure (`SCP-OUTLET-6110`) — that would mean the bridge
    /// built a bad preimage or signed under the wrong key. The stream drains to
    /// a framework terminal. (The deterministic `StreamTerminalStatus::Cancelled`
    /// cancel-ack chunk is asserted at the runtime layer via
    /// `apply_outlet_cancel_signed`; the single-shot bridge seam closes too fast
    /// to pin it here.)
    #[test]
    fn cancellation_control_plane_and_terminal() {
        Python::with_gil(|py| {
            setup();
            let scp = _scp_core::scp::PyScp::new_in_memory_for_test();
            let bi = scp.bridge_instance();
            runtime::init_context_manager_for_test(bi);

            let (_ctx, _outlet, invoker, handle_id) = open_live(
                py,
                &scp,
                bi,
                "vec_cancellation",
                c"lambda i: {'sum': 3, 'ok': 1}",
                Some(1),
            );

            // CRITICAL #1: a caller that is not the pinned invoker cannot steer
            // the stream. This gate fires on the registry lookup BEFORE any
            // signing, so it is deterministic regardless of pump progress.
            let stranger = published_identity_did(py, &scp);
            let stranger_err = scp
                .outlet_stream_cancel(py, &handle_id, &stranger)
                .expect_err("a non-invoker cancel must be rejected");
            assert!(
                stranger_err.to_string().contains("SCP-PERM-3001"),
                "non-invoker cancel is SCP-PERM-3001, got: {stranger_err}"
            );

            // The pinned invoker's bridge-signed cancel must NEVER be rejected as
            // a signature/authorization failure. The single-shot stream may have
            // already closed (a benign lifecycle race) — that is a not-found, not
            // a 6110.
            if let Err(e) = scp.outlet_stream_cancel(py, &handle_id, &invoker) {
                let msg = e.to_string();
                assert!(
                    !msg.contains(
                        scp_core::context::outlets::error_codes::CODE_AUTHORIZATION_DENIED
                    ),
                    "a correctly bridge-signed cancel must not be a signature/auth failure: {msg}"
                );
            }

            // The stream reaches a framework terminal (End on the benign race, or
            // a cancel-driven terminal) without hanging.
            let chunks = drain_to_terminal(py, &scp, &handle_id);
            // Any chunk we DID drain must not stop on a non-terminal — a mid-stream
            // stall with no terminal is a real defect.
            if let Some(last) = chunks.last() {
                assert!(
                    last.payload.is_terminal(),
                    "a non-empty drain must end on a terminal chunk, got: {:?}",
                    last.payload
                );
            }
            // Prove the stream genuinely terminated + evicted rather than hanging
            // live: a subsequent poll is a distinct not-found (the entry is gone).
            // This holds whether the terminal was drained above or the single-shot
            // stream already closed and evicted before the drain (benign race).
            let after = scp
                .outlet_stream_poll_next(py, &handle_id)
                .expect_err("a terminated+evicted stream's handle is not found");
            assert!(
                after.to_string().contains("no active outlet stream"),
                "the stream is evicted after reaching its terminal, got: {after}"
            );
        });
    }
}
