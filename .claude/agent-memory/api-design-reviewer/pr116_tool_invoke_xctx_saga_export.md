---
name: pr116-tool-invoke-xctx-saga-export
description: API review of FFI op tool_invoke_cross_context_saga across PyO3/NAPI/UniFFI (PR #116 / branch feat/116-ffi-saga-export) — APPROVED
metadata:
  type: project
---

Reviewed branch `feat/116-ffi-saga-export` HEAD `9611159f6` (newest commit test-only, 337 ins). Verdict: APPROVED, no blocking changes.

Op `tool_invoke_cross_context_saga` (§6.2.4 / ADR-049 §3a) added to 3 native bridges. Public shape identical across PyO3/NAPI/UniFFI:
- 9-field flat envelope in (agent-first named params, no builder; `#[allow(too_many_arguments)]` justified inline).
- `SagaResult{ saga_id, receipt: Option<bytes>, output: Option<bytes> }` out — `saga_id` OUTPUT-ONLY (supervisor-minted, never a param).
- 3 typed terminal errors `SagaAborted{retry_after_ms}` / `SagaNeedsRepair{saga_id}` / `SagaBusy{contended_context}`, datum read STRUCTURALLY off variant.

Per-SDK idiom divergences (all correct, not findings): PyO3 = context-id strings + `input: dict`; NAPI/UniFFI = instance-affine handles + `input_json: String`. NAPI `timestamp_ms` as BigInt (fail-closed on signed/non-lossless). Error field label `message:` (PyO3/NAPI) vs `msg:` (UniFFI). NAPI encodes structured datum as machine-parseable message suffix `(retry_after_ms=null)` because napi::Error is single-string — TS wrapper reverses it; `None`→literal `null` never `0`.

retry_after_ms Option None-never-0 rule: lives ONCE in `crates/scp-ffi/common/src/saga_errors.rs:112` `decompose_saga_error`, unit-tested there; each bridge propagates faithfully (PyO3 args[2]=Python None tested; NAPI `null`; UniFFI Option<u64> on variant). Confirmed never coerced to Some(0).

Only NON-blocking observation: public param naming asymmetry — nonce is `asserted_nonce_hex` but adjacent freshness fields exposed as bare `timestamp_ms`/`chain_depth` (internal envelope/impls use `asserted_` prefix on all three). All 3 public surfaces AGREE with each other; purely a self-evidence nicety. Doc-comments already clarify all three are caller-asserted.

WASM N/A (no Supervisor, ADR-034); saga_errors module feature-gated off WASM. Capability matrix entry `invoke_cross_context_saga` honestly false×4 with #1939 (PR-6c SDK-wrapper slice) exemptions — reviewed surface is the bridge op, not the SDK wrapper. Consistent with prior [[pr116_saga_ffi_export]] memory and [[saga_error_typed_terminal_surface]].
