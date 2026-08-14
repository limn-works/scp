---
name: pr116-ffi-saga-export-rebased-3bridge
description: API review of feat/116-ffi-saga-export at 4c4e3171f — tool_invoke_cross_context_saga across 3 bridges (WASM-removed rebase); APPROVED
metadata:
  type: project
---

PR #116 (PR-6b) FFI saga export `tool_invoke_cross_context_saga`, reviewed @4c4e3171f (rebased onto WASM-removed main — 3 FFI targets now: PyO3/NAPI/UniFFI; browser TS = remote thin client per ADR-055). API-design verdict: APPROVED, no blocking findings.

**Why APPROVED:**
- Cross-bridge shape identity holds. All three return a SagaResult record `{saga_id: String, receipt: Option<bytes>, output: Option<bytes>}` faithfully mirroring producer `supervisor::SagaOutput` (supervisor.rs:309). Option is honest (producer genuinely emits None, e.g. NeedsRepair driver).
- saga_id is output-only everywhere (supervisor-minted, get-only `#[pyo3(get)]` / napi object field / uniffi Record field). Never an input param.
- retry_after_ms stays `Option<u64>` through shared classifier `scp_ffi_common::saga_errors::decompose_saga_error` (saga_errors.rs:105) — single home of None-never-coerced-to-0 rule, unit-tested there once for all 3 bridges. PyO3 surfaces None→Python None (args[2]); NAPI renders literal `null` in `(retry_after_ms=null)` Display suffix; UniFFI keeps Option on the typed variant.
- Typed terminals identical: SagaAborted{retry_after_ms} / SagaNeedsRepair{saga_id} / SagaBusy{contended_context}; fixed codes SAGA_13065 (repair) / SAGA_13066 (busy); Aborted code formatted inline `SCP-SAGA-{numeric}`.
- Per-binding idiom divergence is correct, not drift: PyO3 takes context-id STRINGS (caller_context_id/target_context_id); NAPI/UniFFI take ContextHandle (source_handle/target_handle, instance-affine pre-check SCP-PERM-3030). All take caller_did free-string + identical freshness fields (asserted_nonce_hex/timestamp_ms/chain_depth/ucan_proof_id). Public param names consistent (timestamp_ms/chain_depth; impls use asserted_*).
- NAPI single-string napi::Error collapse: structured datum rides `#[error(...)]` Display suffix `(retry_after_ms=…)`/`(saga_id=…)`/`(contended_context=…)`; `From<ScpNapiError>` = `e.to_string()` preserves it. Best available mechanism (napi::Error is one string). Tested at raw addon level (real-napi.test.ts:2236-2268), NOT yet on SDK Bridge wrapper (correct — wrapper = #1939 PR-6c).
- Capability-matrix honesty: invoke_cross_context_saga all 4 SDK cells false + per-SDK exemptions citing #1939; NO stale WASM cell after rebase (matrix has no wasm column structurally). bridge-aliases.json lists pyo3/uniffi/napi only (no wasm). pipeline_wiring saga assertions = PyO3/NAPI/UniFFI only, no stale WASM assertion.

**Non-blocking observations worth noting (already raised on prior #116 reviews or minor):** receipt/output as raw bytes (not a typed Receipt record) is deliberate — caller verifies signature + recomputes output_hash without re-serialization (documented). UniFFI SagaResult.receipt doc carries the strong integrity-only/governance-resolution downstream caveat.
