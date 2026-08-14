# #117 PR-6c Python tool_invoke_cross_context_saga wrapper tests

`bindings/python/tests/test_tools.py` — exemplary mutation-resistant SDK-wrapper test suite. SHIP verdict.

## What it covers (all mutation-proven load-bearing)
- 3 typed terminal translations (SagaAborted/NeedsRepair/Busy) by bridge class NAME + structured datum from `exc.args[2]` (never message-parsed)
- retry_after_ms bool-guard: `isinstance(int) and not isinstance(bool)` — pins that `True` datum does NOT become bogus 1ms backoff (bool subclasses int)
- None-vs-0 retry_after_ms preservation (0 = "retry immediately" footgun)
- 3 default-code fallbacks (13067/13065/13066) via `code is None` branch — guards `_default_code` typos
- non-string code guard: `isinstance(args[1], str)` — malformed 2-tuple arity doesn't surface datum as code
- empty-args IndexError guard: `if len(args)>0 else str(exc)`
- `raise translated from exc` cause-chain (asserts `__cause__ is bridge_exc`)
- non-saga re-raise IDENTITY (`exc_info.value is sentinel`) — translator returns None → re-raise unchanged
- chain_depth 0/255 boundary + bool/float/negative/256 reject; timestamp_ms bool/float/negative reject — both pin u8/u64 bridge boundary, bool rejected by TYPE not value
- fail-fast: validation rejects BEFORE side-effectful saga via `assert_not_called()`
- 9-arg forwarding incl non-default ucan_proof_id (assert_called_once_with full positional tuple — catches arg reorder)
- null receipt/output pass-through (never synthesized)
- taxonomy: 3 terminals are ToolError subclasses (catch-all contract)

## Good patterns worth replicating
- `SimpleNamespace` (not bare MagicMock) for committed result so wrapper reads concrete values, not auto-mock attrs
- Bridge-shaped exceptions built via `type("SagaAbortedError",(Exception,),{})` — dispatch-by-name works without native ext
- Shared `_invoke_saga` / `_committed_native` / `_native_raising` helpers — minimal duplication
- Docstrings on each defensive test explain the exact mutation they pin

## Surviving mutations (NON-blocking, bridge-contract-unreachable)
- `str(datum)` coercion on saga_id (NeedsRepair) and contended_context (Busy) — drop survives; bridge always sends str
- `str(args[0])` message coercion — drop survives
Optional: add one non-str-datum test per field to pin coercion. Not ship-blocking (defensive on trusted bridge wire).
