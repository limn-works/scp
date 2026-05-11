//! SCP-OUT-039 AC4 — NAPI bridge conformance vector parameter
//! marshalling assertions.
//!
//! Per AC4 every bridge must replay every vector through its own FFI
//! entry. The canonical runtime funnel
//! `crates/scp-testing/tests/integration/outlet_stream_vectors_through_open_path.rs`
//! pins each vector through `ContextManager::open_outlet_stream` — the
//! single method every FFI bridge converges on. `pipeline_wiring.rs`
//! mechanically enforces that every bridge's `outlet_invoke_stream`
//! body calls `manager.open_outlet_stream(` (string-search assertion at
//! `crates/scp-testing/tests/integration/pipeline_wiring.rs`). The NAPI
//! bridge's `context_outlet_invoke_stream`
//! (`crates/scp-ffi/napi/src/outlet_stream.rs`) is covered by that
//! enforcement.
//!
//! ## Infrastructure gap (NAPI-specific)
//!
//! Driving the NAPI bridge's `context_outlet_invoke_stream`
//! `#[napi]`-annotated entry point from a cargo integration test fails
//! to link. `napi-rs`'s proc-macro emits unwrap/wrap/threadsafe-function
//! glue against ~43 Node.js runtime symbols (`napi_call_function`,
//! `napi_create_promise`, `napi_unwrap`, `napi_wrap`, etc.) that exist
//! only inside a running Node.js / Bun process. The crate's `build.rs`
//! ships a partial stub list (`napi_delete_reference`,
//! `napi_reference_unref`, `napi_throw`, etc.) sized to what the cdylib
//! Drop paths reference at link time — exhaustive stubs for every napi
//! entry point would require ~40 additional symbol stubs that no-op
//! into invalid pointers, and even with the stubs in place
//! `NapiContextHandle`-typed reference parameters cannot be validly
//! constructed without `napi_wrap` allocating a real V8 object.
//!
//! What the `UniFFI` bridge can do (drive vectors through
//! `outlet_invoke_stream`, see
//! `crates/scp-ffi/uniffi/tests/outlet_stream_vectors_real.rs`) does
//! not transpose to NAPI — `UniFFI` proc-macros generate FFI metadata
//! around plain async Rust fns whose signatures are usable from any
//! Rust caller. The NAPI bridge funcs do not have this property; they
//! are intrinsically Node.js-runtime callable, with all parameters
//! crossing the V8/N-API boundary.
//!
//! ## Coverage parity for NAPI
//!
//! AC4 for the NAPI bridge is enforced by these load-bearing surfaces
//! *outside* this file:
//!
//! 1. `crates/scp-testing/tests/integration/pipeline_wiring.rs` — the
//!    bridge-source string-search assertion that the NAPI bridge's
//!    `outlet_invoke_stream.rs` body calls
//!    `manager.open_outlet_stream(`. Removing the call breaks the
//!    pipeline-wiring test.
//! 2. `crates/scp-testing/tests/integration/outlet_stream_vectors_through_open_path.rs`
//!    — drives every vector through the funnel that every bridge
//!    (including NAPI) converges on. The NAPI bridge's
//!    parameter-validation layer is exercised through its `#[cfg(test)]`
//!    in-source tests that call `ContextManager` directly via
//!    `init_context_manager_for_test()` (see e.g.
//!    `crates/scp-ffi/napi/src/context.rs` async tests).
//! 3. `crates/scp-testing/tests/integration/ffi_conformance.rs`
//!    `PARITY_OPERATIONS` pins the NAPI bridge's `context_outlet_invoke_stream`
//!    export against the shared streaming-ops matrix.
//! 4. `bindings/typescript/test/` end-to-end suites — these are the
//!    *only* tests that drive the napi-rs entry point through a real
//!    Node.js/Bun runtime. They are the SDK-level AC4 surface (AC5).
//!
//! ## What this file does
//!
//! This file pins SCP-OUT-039 vector-shape invariants from the NAPI
//! crate's test scope so a vector edit (renamed field, type change,
//! count drift) is caught at `cargo test -p scp-ffi-napi` time without
//! requiring a Node.js process. The assertions cover:
//!
//! - Every vector loads as 7 named records.
//! - Every vector's `(credit_window, estimated_chunk_count)` fits the
//!   bridge's `u32` signature.
//! - The relational invariant `estimated_chunk_count <= credit_window`
//!   holds across the fixture set (the bridge would reject a violation
//!   as `input.estimate-exceeds-bound`).
//!
//! See the agent-memory note alongside this file for the gap
//! documentation and the path forward when napi-rs in-process testing
//! becomes available.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::PathBuf;

#[derive(serde::Deserialize, Debug, Clone)]
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
    #[allow(dead_code)]
    cost_per_chunk: u64,
    #[allow(dead_code)]
    available_balance: u64,
    #[allow(dead_code)]
    stream_credit_stall_secs: u32,
    #[allow(dead_code)]
    stream_cancel_ack_secs: u32,
    #[allow(dead_code)]
    timeout_ms: u32,
    #[allow(dead_code)]
    chain_depth: u8,
}

#[derive(serde::Deserialize, Debug, Clone)]
struct StreamVector {
    name: String,
    #[allow(dead_code)]
    description: String,
    open: OpenSpec,
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
    let manifest = std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR");
    let mut path = PathBuf::from(manifest);
    // crates/scp-ffi/napi → workspace root
    path.pop(); // out of napi
    path.pop(); // out of scp-ffi
    path.pop(); // out of crates
    path.push("tests/conformance/vectors/outlet_stream_vectors.json");
    path
}

fn load_vectors() -> Vec<StreamVector> {
    let bytes = std::fs::read(vector_path()).expect("vector file must exist");
    let file: VectorFile = serde_json::from_slice(&bytes).expect("vector JSON parses");
    file.vectors
}

/// SCP-OUT-039 AC4 — fixture sanity check from the NAPI crate's test
/// scope. Pins that the conformance vector file the NAPI bridge
/// (transitively) replays from has the seven §5.4.5 named vectors.
#[test]
fn napi_vector_fixture_has_seven_named_vectors() {
    let vectors = load_vectors();
    assert_eq!(vectors.len(), 7, "expected 7 SCP-OUT-039 vectors");

    let names: std::collections::HashSet<&str> = vectors.iter().map(|v| v.name.as_str()).collect();
    for required in [
        "non_streaming",
        "multi_chunk",
        "cancellation",
        "error_terminal",
        "error_recoverable",
        "sequence_gap",
        "credit_exhaustion",
    ] {
        assert!(
            names.contains(required),
            "vector {required} missing — AC4 coverage for the NAPI bridge depends on it"
        );
    }
}

/// SCP-OUT-039 AC4 — cross-vector schema invariant. The bridge's
/// `context_outlet_invoke_stream` signature accepts `u32` for
/// `credit_window` and `estimated_chunk_count`, and the bridge rejects
/// `estimated_chunk_count > credit_window` at the runtime layer as
/// `input.estimate-exceeds-bound`. Pin the bound at the fixture level
/// so a vector edit that violates it doesn't silently break the open
/// path for every vector that flows through the NAPI bridge.
#[test]
fn napi_every_vector_open_spec_marshals_to_napi_parameter_types() {
    for v in load_vectors() {
        assert!(
            v.open.estimated_chunk_count <= v.open.credit_window,
            "vector {}: estimated_chunk_count ({}) > credit_window ({}); \
             update this assertion if a vector explicitly exercises \
             the EstimateExceedsBound rejection.",
            v.name,
            v.open.estimated_chunk_count,
            v.open.credit_window
        );
    }
}
