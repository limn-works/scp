---
name: pr116-ffi-saga-export-round-49402beae
description: API review of feat/116-ffi-saga-export (tool_invoke_cross_context_saga across PyO3/NAPI/UniFFI) at HEAD 49402beae — APPROVED with naming + Option-always-Some observations
metadata:
  type: project
---

# PR #116 FFI saga export — tool_invoke_cross_context_saga (HEAD 49402beae)

Branch feat/116-ffi-saga-export, rebased on main 29b87c8a5 (TS SDK NAPI-only, WASM removed). Verdict: APPROVED, observations only.

Op exported across 3 bridges (WASM N/A per ADR-034 — no Supervisor). Shared classification in `crates/scp-ffi/common/src/saga_errors.rs::decompose_saga_error` → `SagaErrorParts{kind,code,message}`; each bridge maps via thin 3-arm `map_saga_error`. Strong by-construction symmetry.

**Confirmed good:**
- Typed terminals exhaustive: SagaAborted{retry_after_ms:Option<u64>} / SagaNeedsRepair{saga_id} / SagaBusy{contended_context}. Core `SagaError` is non-Committed terminal enum; Ok(SagaOutput)=Committed. Bridge match forced exhaustive.
- retry_after_ms Option<u64> never coerced to 0: PyO3 → Python None at args[2] (tested); NAPI → Display renders literal "null" suffix (Option stays structural in variant up to Display; suffix forced by single-string napi::Error, best available); UniFFI → native Option.
- saga_id OUTPUT-ONLY: absent from all 3 op param lists; only in SagaResult + NeedsRepair error. Supervisor-minted.
- Result record identical shape all 3: {saga_id:String, receipt:Option<bytes>, output:Option<bytes>}. pyclass name="SagaResult", UniFFI `SagaResult`, NAPI `NapiSagaResult` (raw-bridge Napi-prefix; SDK wrapper #1939 normalizes).
- Param order identical all 3. idiom diffs accepted: PyO3 string ids + PyDict input; NAPI/UniFFI typed handles + input_json string; NAPI timestamp_ms=BigInt (validated signed/lossless fail-closed) vs u64.
- Capability matrix honest: new row invoke_cross_context_saga, all 4 SDK cells false + per-SDK exemptions citing #1939 + §6.2.4/ADR-049§3a; notes cite bridge exports + pipeline_wiring assertions. No WASM column/stale cell. bridge-aliases canonical lists only pyo3/uniffi/napi.
- error_codes: SAGA_13050 (caller-axis reject) / 13065 (NeedsRepair fixed) / 13066 (Busy fixed); Aborted sub-code formatted inline from producer numeric discriminant.

**Observations (non-blocking):**
1. Param naming drift on caller axis. PyO3 saga op = `caller_context_id`; NAPI/UniFFI saga = `source_handle`; PyO3 SYNC SIBLING tool_invoke_cross_context = `source_context_id`. So PyO3 saga renamed source→caller, diverging from BOTH its own sync sibling AND the other two bridges. Recommend PyO3 saga `caller_context_id`→`source_context_id` (pairs with caller_did exactly like NAPI/UniFFI's source_handle+caller_did; unifies on `source`).
2. SagaResult.receipt/output are Option but for THIS op are ALWAYS Some on Ok(Committed) terminal. Option is artifact of generic core SagaOutput (None only for test-only NeedsRepair driver, which this op never drives). Faithful mirror, but weakens caller contract — a None can't occur on success yet caller must handle it. Consider unwrap-or-error to non-optional bytes, or keep+document (currently doc'd "or None").
3. Trust boundary (co-resident single-tenant; "hosted identity = authenticated principal") is runtime-enforced via enforce_caller_principal_binding + documented as ADR-049§3a forward obligation, NOT type-enforced. Acceptable — deployment boundary, not expressible in types.
