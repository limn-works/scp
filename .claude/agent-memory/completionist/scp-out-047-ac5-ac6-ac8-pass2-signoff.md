---
name: scp-out-047-ac5-ac6-ac8-pass2-signoff
description: SCP-OUT-047 pass-2 AC5/AC6/AC8 FINAL ruling — all three genuinely met at PyO3 layer; layered-coverage reconciliation honest; story correctly pending
metadata:
  type: project
---

SCP-OUT-047 streaming-saga FFI pass-2 (@d6abe0907, feat/outlet-xctx-047-streaming-saga-ffi, wt /Users/alec/Developer/limn/scp-wt-047). Ruling: AC5/AC6/AC8 GENUINELY MET at the PyO3 layer (the pass-2 deliverable). Story correctly stays `pending`.

**Why:** verifies the three ACs I previously ruled GAPS are now real, and captures the layered-coverage reconciliation pattern.

**How to apply:**
- **AC6** — `xctx_streaming_saga_open_returns_before_committed_non_blocking` (e2e_bridge.rs:2530) is a REAL behavioral FFI drive: blocking single-shot handler (`Arc<Mutex<mpsc::Receiver>>`) held open, asserts `test_saga_journal_state == Some(Committing)` (pre-Committed) after the real `outlet_streaming_saga_open` returns, then releases + drains via real `outlet_streaming_saga_poll_next` (saw_data+saw_terminal+eviction). Race-free: blocked handler → seal can't reach Committed. RAN → passes. `test_saga_journal_state` is additive `#[cfg(any(test,feature="testing"))]` read-only journal accessor (no enforcement file touched). AC6 reword to single-shot 037 primitive is honest (spec mandates no multi-chunk FFI executor; multi-chunk = future SDK scope).
- **AC8** — amended to HONEST layered coverage, no papered gap. FFI driver auth = 4 real rejection drives (unhosted→ContextError; hosted-non-member→SAGA-13050; recover unhosted→ContextError; recover hosted-non-invoker→PERM-3001 + entry left intact). Wiring = pipeline_wiring `out047_pyo3_streaming_saga_recover_reaches_truncated_close` (extract_fn_body checks `drive_recover_truncated_close`+`identity_registry_contains`). OUTCOME (billed_count=sealed-prefix, exec-once, receipt verifies under B key) = runtime `xctx_streaming_saga_truncated_close_ac7` (real crashed 5-chunk PrefixThenBlockExecutor). RAN → passes. Class-S isolation constraint REAL: `spawn_actor_with_state` is `pub(in crate::context)` (supervisor.rs:4368 + handle.rs:561) → external test crate cannot make a context resident → full FFI-through-Committed drive genuinely unconstructible. No fabricated refs; phantom-provenance docstring in test_outlets_streaming_saga.py fixed.
- **AC5** — PyO3 open runs `enforce_caller_principal_binding` at step (b) BEFORE saga runs; SDK threads caller_did (outlets.py streaming-saga async iterator). Full "each non-WASM bridge" completes pass 3.
- **Pending justified:** NAPI/UniFFI streaming_saga_open = absent (AC3), matrix rows = 0 (AC10), WASM fence correct (0, AC4). Passes 3-4 remain.

LESSON: when a money-moving FFI recovery's OUTCOME can't be driven end-to-end from an external test crate because the resident-actor Class-S state seam (`spawn_actor_with_state`) is `pub(in crate::context)`, the honest close is layered — prove auth+wiring FFI-side, prove billed/exec-once OUTCOME runtime-side against a REAL crashed saga — NOT a mock or an `#[ignore]`. Verify the isolation seam's visibility literally before accepting the "not constructible externally" justification.
