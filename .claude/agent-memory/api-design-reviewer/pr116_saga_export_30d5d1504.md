---
name: pr116-saga-export-30d5d1504
description: API review of feat/116-ffi-saga-export tool_invoke_cross_context_saga across 3 bridges @30d5d1504 — APPROVED
metadata:
  type: project
---

PR feat/116-ffi-saga-export (HEAD 30d5d1504, rebased on main 29b87c8a5: TS NAPI-only, WASM removed). Adds FFI op `tool_invoke_cross_context_saga` across PyO3/NAPI/UniFFI. Verdict: APPROVED, no blocking findings.

**Why APPROVED:** cross-bridge SHAPE identical (9 params, same order/semantics); type diffs are pure established binding idiom mirroring the non-saga sibling `tool_invoke_cross_context`. SagaResult{saga_id, receipt:Option<bytes>, output:Option<bytes>} identical across 3. Errors SagaAborted{retry_after_ms:Option<u64>}/SagaNeedsRepair{saga_id}/SagaBusy{contended_context} identical, classification guaranteed by shared `scp_ffi_common::saga_errors::decompose_saga_error` (resolvers-gated; WASM excluded by construction). retry_after_ms stays Option<u64>, None NEVER coerced to 0 (NAPI renders literal "null" suffix since napi collapses to one string, structured field preserved). saga_id output-only (no input param anywhere). NAPI timestamp_ms=BigInt validated non-negative+lossless (good misuse-resistance). Nonce decode fail-closed both arms (non-hex + wrong-length), VALID_7001. Tip commit 30d5d1504 test-only (3 NAPI decode_asserted_nonce tests, no API change — confirmed).

**Matrix honesty:** all 4 SDK cells false + per-SDK exemptions citing #1939 (PR-6c wrapper slice). Matrix is SDK-language-keyed not bridge-keyed → NO wasm key exists anywhere (0 occurrences) so no stale WASM cell. Name `invoke_cross_context_saga` matches sibling `invoke_cross_context`. bridge-aliases lists rust fn name ×3.

**How to apply (non-blocking, for #1939 wrapper layer):** vocabulary drift — saga op uses `caller_did` (PyO3 also `caller_context_id`) tracing spec §6.2.4 "Caller authentication", but non-saga sibling uses `invoker_did`/`source_context_id`. NAPI/UniFFI saga mixes `source_handle` (handle-sibling parity) with `caller_did`. Each locally justified, shape identical. Harmonize the public-facing initiating-actor label (caller/source/invoker) to ONE vocabulary at the SDK-wrapper layer. Supporting changes (resolve_signing_key→pub(crate), identity_registry_contains pub(crate)) are internal, not public surface.
