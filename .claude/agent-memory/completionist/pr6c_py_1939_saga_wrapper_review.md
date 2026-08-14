---
name: pr6c-py-1939-saga-wrapper-review
description: Completeness verdict on worktree pr6c-py (PR-6c slice PY, #1939) — Python SDK wrapper for §6.2.4 saga; verdict COMPLETE
metadata:
  type: project
---

Worktree `pr6c-py` HEAD `c0797758d` (rebased; re-verified 2026-06-29 — findings unchanged; prior passes at `c7149be15`/`561da74a3`/`13ecd25f3`). Tip `c7149be15` adds the NeedsRepair-13065 + Busy-13066 default-code pin tests on top of `561da74a3`'s Aborted-13067 pin — so all THREE typed-terminal default-code fall-backs now exercise the `code is None` translation branch. PR-6c slice PY (#1939): Python SDK wrapper for the §6.2.4 cross-context tool-invocation saga. Verdict **COMPLETE**, correctly python-scoped. 25 saga tests in test_tools.py all green; check-sdk-coverage 0 errors; pipeline_wiring `pyo3_saga_export_*` assertion + bridge export confirmed present (chain core→bridge→SDK→tests→matrix intact).

Scope = integration-checklist item 3 (SDK wrapper) + item 5 (matrix, python cell only). Items 1/2/4 (core producer, 3 native bridge exports, pipeline_wiring assertions) landed PR-6b #1950 (commit 050b05ba7). ts/swift/kotlin wrappers correctly still `false` + exempted, tracked by #1939.

All cells real:
- Wrapper `SCP.tool_invoke_cross_context_saga` (scp.py:2039) dispatches to `self._native.tool_invoke_cross_context_saga` — bridge export CONFIRMED at origin/main crates/scp-ffi/src/tools.rs:1942 (`#[pyo3(name="tool_invoke_cross_context_saga")]`, identical 9-param flat envelope). asyncio.to_thread, forwards all 9 args.
- `SagaResult` frozen dataclass (tools.py) — faithful pass-through of native PySagaResult (pyclass name "SagaResult", saga_id/receipt/output); None never synthesized.
- 3 typed error classes (errors.py) subclass ToolError, default codes match task: Aborted=SCP-SAGA-13067 (generic), NeedsRepair=13065, Busy=13066. Commit 13ecd25f3 fixed Aborted default 13050→13067 (13050 is specific caller-axis sub-code, not generic).
- `_saga_terminal_from_bridge` dispatches on `type(exc).__name__` and reads datum positionally args[2]. Bridge raises matching class names (error.rs:898-903 register SagaAbortedError/SagaNeedsRepairError/SagaBusyError) via `new_err((formatted, code, datum))` — args=(message,code,datum) EXACTLY. retry_after_ms None-preserved (never 0), bool-guarded.
- pyi stubs (native SagaResult + 3 exc classes + SCP method, 9 params).
- __init__ exports all 4 symbols + ordered __all__.
- Tests: 47 pass (happy committed + null receipt/output passthrough + arg-forwarding + ucan_proof_id 9th-positional + per-error translation + non-saga passthrough + chain_depth/timestamp validation incl bool/float/neg/boundary + fail-fast assert_not_called on every validation reject).
- matrix python false→true, python exemption removed, ts/kotlin/swift retained, note updated. check-sdk-coverage.py PASS 0 errors. New alias entry ("Tools","invoke_cross_context_saga") additive, python alias matches method name; ts/kotlin/swift aliases inert until those cells flip.

No unwired/dead code (translation fn called scp.py:361, SagaResult used, all 3 errors exported+used). No issue-number leak in PR-ADDED source (only pre-existing #1549/#1690/#1678 in unrelated docstrings/comments). ruff clean.

Validation pattern mirrors the sync `tool_invoke_cross_context` wrapper (chain_depth 0..255 u8, timestamp_ms non-neg u64, both reject bool/float). Bridge owns nonce-hex + caller-principal-binding (SagaAborted 13050) fail-closed.

Related: [[pr6b_116_ffi_saga_export_review]], [[saga-count-one]].
