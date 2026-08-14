# PR-6c Python SDK saga wrapper tests (test_tools.py)

Reviewed `SCP.tool_invoke_cross_context_saga` wrapper + `_saga_terminal_from_bridge` translator (§6.2.4). VERDICT: SHIP. 14/14 mutations caught.

## Exemplary patterns worth replicating
- **Unbound-method-with-mock-self**: `SCP.tool_invoke_cross_context_saga(scp, ...)` where `scp` is a `MagicMock` with only `_native` set. Runs the REAL wrapper logic (validation/translate/SagaResult build) against a mocked bridge — genuine behavior testing, not mock-echo. This is the right way to test an SDK wrapper without the native extension.
- **Bridge terminal mocks by class NAME**: `type("SagaAbortedError", (Exception,), {})` — translator dispatches on `type(exc).__name__`, so a name-shaped fake works without native. Structured datum carried positionally in `args[2]`, read structurally (never re-parsed from message text).
- **SimpleNamespace (not bare MagicMock) for committed result** so wrapper reads concrete saga_id/receipt/output, not auto-generated mock attrs. (Bare MagicMock would make every attr truthy and pass-through assertions vacuous.)
- **Disambiguation done right**: code-preservation pinned by using a NON-default bridge code (`SCP-SAGA-13050`, the producer/bridge code) and asserting `code == 13050` — distinguishes "read from args[1]" from "fell back to class default 13067". Default-fallback tests use 1-tuple args to hit the `code is None` branch.
- **bool-subclass-of-int guard pinned twice**: validation side (chain_depth/timestamp reject `True`/`False`) AND translate side (`retry_after_ms` bool datum NOT coerced to 1). Both have dedicated tests with rationale docstrings.
- **Fail-fast ordering pinned**: validation-rejection tests assert `_native.tool_invoke_cross_context_saga.assert_not_called()` — proves validation precedes the side-effectful bridge call.
- **Cause chain pinned**: `assert exc_info.value.__cause__ is bridge_exc` catches dropping `raise ... from exc`.

## Minor observations (non-blocking)
- NeedsRepair/Busy code-preservation tests assert the DEFAULT code (13065/13066), so they don't independently pin "code read from args[1]" for those classes — but it's a SHARED translator branch covered by the abort test (M13 proved it). Acceptable.
- `test_abort_with_backoff_preserves_int` uses default code 13067 → slightly redundant on code axis, but uniquely pins the int-datum-preserved path.
- Wrapper signature default `ucan_proof_id=None` never exercised via omission (helper always passes it positionally); functionally equivalent since None is forwarded and asserted.
