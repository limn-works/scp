---
name: py-saga-wrapper-tests-pr6c
description: PR-6c Python SDK tool_invoke_cross_context_saga wrapper tests — mutation-verified default-code coverage + 4 surviving-mutation defensive gaps
metadata:
  type: project
---

# PR-6c Python saga wrapper tests (test_tools.py, +362 lines)

Covers `SCP.tool_invoke_cross_context_saga` (scp.py) + 3 typed saga errors
(`SagaAbortedError`/`SagaNeedsRepairError`/`SagaBusyError`, errors.py) +
`_saga_terminal_from_bridge` translator + `SagaResult` (tools.py).

**Why:** #105/#117 §6.2.4 cross-context tool-invocation saga SDK wrapper layer.
**How to apply:** reference when reviewing the Swift/Kotlin/TS sibling wrappers for parity.

## Strong, mutation-CONFIRMED coverage
- 3 default-code fallback tests (`*_without_code_falls_back_to_generic_default`)
  are load-bearing: mutating each `_default_code` constant (13067/13065/13066)
  → matching test FAILS. Verified with `python3.12 -B` (pyc cache defeats
  same-byte mutations otherwise).
- 9-arg positional forwarding pinned with distinct values (ts=42, depth=7) →
  arg-order swap caught. ucan_proof_id non-default forwarding tested separately.
- receipt vs output distinct sentinels → field-swap caught. Null pass-through tested.
- retry_after_ms None-vs-int preservation tested. saga_id/contended_context "" default tested.
- Validation fail-fast: `assert_not_called()` proves reject-before-dispatch.
- Non-saga passthrough: `exc_info.value is sentinel` identity assertion (not swallowed).

## Surviving mutations (gaps — all DEFENSIVE/taxonomy, non-blocking)
- A: drop `and not isinstance(datum, bool)` on retry_after_ms → survives (no test
  feeds a bool datum to SagaAborted). Asymmetric: input side bool-rejection is
  heavily tested, output side bool-guard is not. Docstring makes "never bool/0" load-bearing.
- B: drop `isinstance(args[1], str)` code guard → survives (no non-str args[1] test).
- C: drop `from exc` chaining → survives (no `__cause__` assertion). Cosmetic.
- D: `SagaAbortedError(ToolError)` → `(ScpError)` survives — base class not pinned.
  Meaningful: saga errors belong to the tool family; a `pytest.raises(ToolError)`
  or `assert issubclass(SagaAbortedError, ToolError)` would pin it.

Verdict was SHIP — core contract thoroughly mutation-resistant; gaps are edges.
