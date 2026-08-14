---
name: pr1939-pr6c-saga-sdk-python
description: APPROVED — Python SDK wrapper for §6.2.4 cross-context tool saga (PR-6c slice PY, #1939); typed SagaResult + 3 typed terminals, faithful nullable pass-through, structural datum read
metadata:
  type: project
---

PR-6c slice PY (#1939), branch feat/1939-pr6c-saga-sdk-python @13ecd25f3 — Python SDK wrapper for `SCP.tool_invoke_cross_context_saga`. This is the SDK-wrapper follow-up to PR #116 (6b FFI export); see [[pr116_saga_ffi_export]] and [[saga_error_typed_terminal_surface]].

**Verdict: APPROVED**, no blocking findings.

Surface: `async tool_invoke_cross_context_saga(...) -> SagaResult`; frozen dataclass `SagaResult{saga_id:str, receipt:bytes|None, output:bytes|None}`; three `ToolError` subclasses `SagaAbortedError(retry_after_ms:int|None, default SCP-SAGA-13067)` / `SagaNeedsRepairError(saga_id, 13065)` / `SagaBusyError(contended_context, 13066)`. Translation via `errors._saga_terminal_from_bridge` dispatches on `type(exc).__name__` and reads structured datum positionally from `exc.args[2]` — never message-parse.

Verified good:
- retry_after_ms None≠0: `datum if isinstance(int) and not isinstance(bool) else None` — None preserved, 0 passes through faithfully (correct, not coerced). bool excluded.
- SagaResult faithful pass-through: receipt/output forwarded verbatim, None never synthesized.
- Default codes match spec (13067 generic Aborted, 13065 NeedsRepair, 13066 Busy); specific bridge codes (e.g. 13050) flow through unchanged.
- Exports present in __init__/errors/tools __all__. chain_depth+timestamp_ms reject bool/float/negative (SCP-VALID-7002) before side-effect.

Non-blocking observations:
- Naming divergence from sibling `tool_invoke_cross_context`: `caller_context_id`/`caller_did` vs sibling `source_context_id`/`invoker_did`; `ucan_proof_id` vs `ucan_token`+`proof_tokens`; `tool_registration_id` vs `tool_id`. Proof-by-id and registration-id are spec-driven (§6.2.4); caller_ vs source_/invoker_ is gratuitous lexical drift.
- chain_depth required in saga but defaults to 0 in sibling — consider `chain_depth:int=0` for cross-op + agent-first authorability.
- Sibling returns `Any`; saga returns typed `SagaResult` (saga is the better pattern — sibling is the laggard).
- SDK saga errors subclass ToolError (so `except ToolError` catches them) yet carry SCP-SAGA-* codes — reasonable two-axis classification, prefix/parent-category mismatch worth noting.
- Strongest finding: name-based dispatch in `_saga_terminal_from_bridge` depends on real `_scp_core` class names equalling literals "SagaAbortedError"/etc. Tests use synthetic same-named classes; nothing pins the literal to the real bridge module. .pyi declares those names so they're contract, but a conformance test would close the silent-degradation gap (translation returns None → raw bridge exc surfaces, losing typed attrs). Consistent with established BRIDGE_ERROR_MAP name-string idiom.
