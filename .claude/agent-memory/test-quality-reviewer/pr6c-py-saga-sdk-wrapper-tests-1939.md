# PR-6c slice PY (#1939) — SCP.tool_invoke_cross_context_saga SDK wrapper tests

File: `bindings/python/tests/test_tools.py`. Wrapper `scp.py:2042`;
translator `errors.py _saga_terminal_from_bridge`; `SagaResult` (frozen, 3 fields:
saga_id/receipt/output). Verdict: Ship (non-blocking refinements).

## UPDATE — re-review at HEAD 561da74a3 (2026-06-29): now 24 new / 47 pass
Branch evolved since the prior review below (commits 894b2f936 fail-fast +
13ecd25f3/561da74a3 default-code). Prior gaps 1, 2, 3 + abort-part of 4 are now CLOSED:
- Gap 1 (assert_not_called) CLOSED — every chain_depth + timestamp rejection test now
  asserts `scp._native.tool_invoke_cross_context_saga.assert_not_called()`. Rejection
  fixtures use `_committed_native()` (would-succeed-if-reached) so the proof is meaningful.
- Gap 2 (timestamp False) CLOSED — `test_timestamp_bool_false_rejected` added.
- Gap 3 (non-default ucan_proof_id) CLOSED — `test_native_forwards_ucan_proof_id`.
- Gap 4 PARTIAL — new `test_abort_without_code_falls_back_to_generic_default` pins
  `SagaAbortedError._default_code=="SCP-SAGA-13067"` via the `code is None` branch
  (generic, distinct from explicit Prepare codes; prior bug defaulted 13050).
RESIDUAL gap (still open, NON-BLOCKING): `SagaNeedsRepairError._default_code`(13065) and
`SagaBusyError._default_code`(13066) are NEVER pinned via their None branch — both tests
pass an EXPLICIT args[1] code that OVERRIDES the default, so a typo in either constant
passes every test. Abort got a None-branch test for parity; the other two should too
(2 lines each: None/short-tuple bridge exc → assert code==13065/13066). Lower practical
risk (default == the single canonical code the bridge always sends) but constant unverified.
Also still minor: `retry_after_ms` bool-exclusion guard untested; package-level
`scp_sdk.__all__` additions untested (tests import from submodules directly).

PROCESS GOTCHA: run pytest from the WORKTREE path
(`.claude/worktrees/pr6c-py/bindings/python`), NOT repo-root `bindings/python` — the
latter is the main worktree on a different branch (collects 24, saga block absent).

--- ORIGINAL REVIEW (19 new / 44 pass) below; gaps 1-3 + abort-4 now resolved ---

## Exemplary patterns (replicate)
- Bridge-shaped exceptions via `type("SagaAbortedError",(Exception,),{})` — models the
  translator's real key (class `__name__` + positional `args[2]` datum), exercises the
  REAL dispatch path through the wrapper without the native ext. Right fidelity.
- Each typed terminal asserts SPECIFIC SDK class AND structured attr (retry_after_ms /
  saga_id / contended_context), never `pytest.raises(Exception)`. Mutation-resistant.
- `retry_after_ms is None` (NOT `== 0`) explicitly pinned + rationale comment (0 = "retry
  immediately" re-trips limiter). The headline assertion.
- `SimpleNamespace` (not bare MagicMock) for committed-terminal mock so auto-attrs can't
  mask a field-read bug — documented in helper docstring.
- `test_native_called_with_forwarded_arguments`: distinct values chain_depth=7 timestamp=42
  catch arg transposition; asserts trailing None ucan_proof_id + exact order.
- Non-saga passthrough `is sentinel` proves translator returns None → wrapper re-raises
  unchanged (doesn't swallow). Essential negative case for a translator.

## Gaps found (all non-blocking)
1. STRONGEST: no `native.tool_invoke_cross_context_saga.assert_not_called()` in any of the
   11 validation-rejection tests. A mutation moving validation AFTER the to_thread native
   call would pass every test yet already commit a side-effectful cross-context saga.
   For sagas, fail-fast-before-side-effect ordering must be pinned. One line per test.
2. `timestamp_ms=False` untested (chain_depth tests both bool values; timestamp only True).
   False==0 "looks valid" → bool guard is sole rejecter.
3. ucan_proof_id only ever default None (_invoke_saga hardcodes it); no non-None forward test.
4. translator datum=None→"" for NeedsRepair/Busy + code=None branches unexercised (Aborted
   datum=None IS covered).

## DRY observation
chain_depth/timestamp validation copy-pasted between tool_invoke_cross_context (scp.py:2021)
and _saga (scp.py:2080); TestSagaChainDepthValidation duplicates TestChainDepthValidation
(7 near-identical). Lowest-ROI part. Real fix = shared `_validate_chain_depth` helper in
production → one parametrized test covers both. Test blocker: no.
