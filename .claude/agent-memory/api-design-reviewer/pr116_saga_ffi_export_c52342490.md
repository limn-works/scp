---
name: pr116-saga-ffi-export-c52342490
description: APPROVED — feat/116-ffi-saga-export tool_invoke_cross_context_saga across PyO3/NAPI/UniFFI; cross-bridge shape identity confirmed, retry_after_ms Option never-0, saga_id output-only, matrix honest
metadata:
  type: project
---

Re-review of `feat/116-ffi-saga-export` @ `c52342490` (rebased onto main `29b87c8a5`, TS NAPI-only, WASM removed). APPROVED, no blocking findings.

**What shipped:** FFI op `tool_invoke_cross_context_saga` (§6.2.4 / ADR-049 §3a) across 3 native bridges. Returns `SagaResult{saga_id, receipt: Option, output: Option}`; typed terminals `SagaAborted{retry_after_ms: Option<u64>}` / `SagaNeedsRepair{saga_id}` / `SagaBusy{contended_context}`. Shared classification = `crates/scp-ffi/common/src/saga_errors.rs::decompose_saga_error` (single home; the `RateLimited→Option`, `None`-never-`0`, `SCP-SAGA-{code}` rules unit-tested once).

**Cross-bridge shape identity (confirmed):** identical 9-arg flat envelope, identical arg order, identical SagaResult, identical 3 typed errors with identical structured fields and identical SAGA_13050/None pre-flight caller-binding rejection (byte-identical message text). Only idiomatic deltas: PyO3 string context-id vs NAPI/UniFFI ContextHandle; PyO3 `input: PyDict` vs NAPI/UniFFI `input_json: String`; `message:` (PyO3/NAPI) vs `msg:` (UniFFI surfaces Rust field name); NAPI BigInt timestamp vs u64.

**Verified:** retry_after_ms Option never coerced to 0 (shared fn + per-bridge tests + NAPI literal `null` suffix). saga_id output-only — appears in NO signature, only in SagaResult/NeedsRepair (structurally enforced; PyO3 `#[pyo3(get)]` read-only). Matrix honest: all 4 SDK cells `false` + per-SDK exemptions citing #1939 (PR-6c wrapper slice); no WASM cell (matrix tracks SDK langs not bridges — no stale cell post-#1945 cleanup); bridge-aliases has pyo3/uniffi/napi only (no wasm key — correct, no Supervisor per ADR-034). cfg-gating commit `c52342490` is test-only (`#[cfg(feature=allow_in_memory_custody)]` on test-mod fns) — no public API change.

**Non-blocking observations (same as prior #116 reviews):** (1) NAPI message-suffix `(retry_after_ms=null)` is the one place structure rides in prose — forced by napi single-string Error; PyO3 carries args[2] structured, UniFFI typed field; only NAPI degrades, reverse-parse owned by #1939 TS wrapper. (2) `_saga` op coexists with synchronous `tool_invoke_cross_context` (spec §6.2.4:244 mandates both); `_saga` suffix + cross-referencing doc-comment is the right disambiguator. (3) input-type asymmetry (PyDict vs input_json) matches the sibling op's established per-bridge idiom.
