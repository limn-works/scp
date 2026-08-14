---
name: pr116-2-ffi-saga-export-feat116
description: API review of feat/116-ffi-saga-export (HEAD 506da562b) — tool_invoke_cross_context_saga across PyO3/NAPI/UniFFI; APPROVED with naming-consistency observation
metadata:
  type: project
---

Reviewed branch `feat/116-ffi-saga-export` HEAD `506da562b` (worktree ffi-saga-116), op `tool_invoke_cross_context_saga`. Verdict APPROVED. This is the rebuilt/expanded sibling of the earlier #116 PR (see [[pr116_saga_ffi_export]]) — same canonical op, now with a richer `SagaResult` (saga_id + receipt + output bytes) vs the earlier flat envelope.

**Why:** PR-6b slice of #105/#116 (FFI export of §6.2.4 xctx-tool saga). Wraps `Supervisor::start_cross_context_tool_invocation_saga`. SDK wrappers deferred to #1939 (PR-6c), documented via matrix exemptions.

**How to apply (durable facts about this surface):**
- Cross-bridge shape IS identical by construction: all three route terminal `SagaError` through the SINGLE `scp_ffi_common::saga_errors::decompose_saga_error` → `SagaErrorParts{kind,code,message}`; each bridge's `map_saga_error` is a thin 3-arm tail. retry_after_ms is `Option<u64>` end-to-end, None NEVER coerced to 0 (unit-tested in common + per-bridge).
- Result type identical: PyO3 `PySagaResult{saga_id:String, receipt:Option<Vec<u8>>, output:Option<Vec<u8>>}`; NAPI `#[napi(object)] NapiSagaResult{saga_id, receipt:Option<Buffer>, output:Option<Buffer>}`; UniFFI `#[derive(uniffi::Record)] SagaResult{saga_id, receipt:Option<Vec<u8>>, output:Option<Vec<u8>>}`. saga_id output-only (supervisor-minted, never input).
- Error surface idiom differs by binding (correct per-SDK idiom): PyO3 = 3 typed exceptions w/ structured datum on positional `args` (args[2]); UniFFI = 3 typed `ScpError` enum variants w/ structured fields; NAPI = single napi::Error string w/ machine-parseable `(retry_after_ms=null)`/`(saga_id=…)`/`(contended_context=…)` suffix (forced by napi single-string Error). TS test pins `/\(retry_after_ms=null\)/`.
- Input idiom differs by binding (correct): PyO3 takes string context ids (caller_context_id/target_context_id) + caller_did, enforces principal binding via per-instance identity registry; NAPI/UniFFI take instance-affine handles (source_handle/target_handle) + caller_did, enforce SCP-PERM-3030 handle affinity. timestamp_ms: PyO3 u64, NAPI BigInt (fail-closed on signed/non-lossless), UniFFI u64.
- Codes: SAGA_13050 (caller-auth reject, Aborted-flavored), SAGA_13065 (NeedsRepair fixed), SAGA_13066 (Busy fixed); Aborted sub-code formatted inline `SCP-SAGA-{code}` from producer numeric discriminant.

**Sole observation (non-blocking):** param-name drift vs the sibling synchronous `tool_invoke_cross_context`. Sync op uses `source_context_id`/`tool_id`/`invoker_did`; saga op uses `caller_context_id`(PyO3)/`tool_registration_id`/`caller_did`. NAPI saga keeps `source_handle` (matches sync) but renames `tool_id`→`tool_registration_id` and `invoker_did`→`caller_did`. New names are arguably clearer + match §6.2.4 spec vocabulary, but an agent toggling between the two ops sees different labels for the same role. Capability-matrix name `invoke_cross_context_saga` (no tool_ prefix) is CONSISTENT with sibling `invoke_cross_context` (tools-category implicit prefix) — not a defect.
