# SCP-OUT-039 (C12) outlet-streaming conformance harnesses — CLEAN review

Branch feat/outlet-streaming-ffi @b3a1dd3dc. 6 test files reviewed. NO correctness bugs.

Files: crates/scp-testing/tests/integration/outlet_stream_conformance.rs (runtime-direct raw open_stream_session),
..._through_open_path.rs (live Supervisor::open_outlet_stream), scp-ffi/tests/outlet_stream_vectors_real.rs (PyO3),
napi/src/outlet_stream/tests.rs, uniffi/src/outlet_stream/tests.rs, uniffi/tests/outlet_stream_vectors_real.rs,
scp-client-wasm/src/lib.rs (sign/verify). Vectors: tests/conformance/vectors/outlet_stream_vectors.json (7 vectors, 29 chunks).

Verified sound:
- caveats_binding recompute matches verify_caveats_binding_at_open (dispatch.rs:1650) inputs; open uses .expect() so a
  mismatch PANICS (never a silent rejection-mislabeled-success). Ran both runtime tiers: 16/16 pass.
- ReceiverSequenceTracker: expected=0, fires at first seq!=expected → gap at index 2 / seq 3. Off-by-one correct.
- Gap code: tracker returns CODE_EXECUTION_CREDIT which == "SCP-OUTLET-6131" (stream-gap SHARES the 6131 execution-class
  code per error_codes.rs:36-37,149). Confusingly named but value-correct. napi/uniffi use CODE_STREAM_GAP="SCP-OUTLET-6131".
- credit_exhaustion: initial credit == credit_window (=1) confirmed by passing test; build_script emits window+1 → 1 data
  delivered + framework Error 6133. assert_transcript_matches happens to align (n:0==vector n:0).
- cancellation: assert_terminal_status(Cancelled) asserts cancel_ack_seq.is_some() — STRONG (cancel preimage must be right).
- PyO3 outlet_stream_poll_next uses py.allow_threads(|| block_on) (outlet_stream.rs:686) — prior GIL-deadlock BLOCKER FIXED.
- WASM/FFI wire-integrity: self-consistent sign/verify roundtrip with load-bearing wrong-key negative (not vacuous). 29 chunks.

LOW (coverage gap, not a bug): the vectors are documented "reproducible cross-SDK" but caveats_binding is NEVER pinned to a
canonical value in the JSON. Each tier invents its OWN ucan_cid + invoker_did (runtime tiers use hardcoded local DID
z6MkConformanceInvoker/CREATOR_DID + cid-outlet-stream-conformance/cid-through-open-path; wire tiers use the vector's
invoker_did z6MkStreamVectorInvokerReference + VECTOR_UCAN_CID / scp-out-039-vector-ucan-cid). All internally consistent →
all pass, but no two tiers agree on binding bytes, and the vector's declared invoker_did is ignored by the runtime tiers.
Wire tests only assert wrapper==core (catches a bridge mangling preimage field order/drop — real value), not equality to an
independent pinned constant. Defense-in-depth acceptable; core helper has its own unit tests.
