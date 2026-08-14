---
name: ts-test-guard-coverage-gap
description: bindings/typescript/src/internal/test-guard.ts gates bridge-swap seam but has zero unit tests; hardening can silently regress
metadata:
  type: project
---

# TS test-guard.ts coverage gap (branch fix/sdk-coverage-fail-closed-and-parity)

`bindings/typescript/src/internal/test-guard.ts` gates `__setBridgeForTests` (swaps the native bridge — a security seam). It was hardened on this branch with three properties, NONE tested:

1. `isTestEnvironment()` frozen at import (`_IS_TEST_ENVIRONMENT` IIFE) — runtime `process.env.NODE_ENV` mutation must not flip it.
2. Prototype-pollution guard via `Object.hasOwn(env, "NODE_ENV")` — inherited NODE_ENV must be ignored (commit 4c14360cd).
3. `assertTestEnvironment` error reports `_NODE_ENV_AT_LOAD` (frozen value), not a live read (commit 17d220611).

**Why it matters:** freeze-at-load and the `Object.hasOwn` fix can both silently regress to a live `process.env` read and every existing test stays green. The freeze makes post-load testing hard — recommend refactoring the IIFE body into a pure helper `_evaluateTestEnv(env)` and testing that directly.

**How to apply:** When reviewing TS SDK PRs, check that any module under `internal/` gating a bridge/native swap has tests for its env-guard hardening. A modified security seam with zero coverage violates CLAUDE.md "tests for every change."

**RESOLVED at HEAD 02cf55597:** the IIFE was refactored into pure `_evaluateTestEnv(env)` exactly as recommended, and `tests/test-guard.test.ts` now has 13 tests (prototype-pollution, NODE_ENV matrix, BUN_TEST presence, undefined env). Coverage gap closed. TWO residual nits found in review:
1. `test-guard.test.ts:82-86` comment is FACTUALLY WRONG — claims `isTestEnvironment()` is true "because BUN_TEST is set at test-suite load", but under `bun test` `BUN_TEST` is `undefined` and `NODE_ENV` is `"test"` (verified empirically). The assertion passes via NODE_ENV; the documented rationale misattributes the cause. If a future bun stops setting NODE_ENV=test, the test relies on the false premise and the security-guard coverage silently degrades. Fix the comment to cite NODE_ENV.
2. No test asserts `assertTestEnvironment` THROWS when frozen value is false — untestable directly due to module-load freeze; `_evaluateTestEnv({NODE_ENV:"production"})===false` is the accepted proxy. Fine.

Related: [[ts_sdk_bridge_error_shape]] (same branch's trust.ts seam).

## Gate ALIASES table coverage (scripts/check-sdk-coverage.py)
The ~400-line `ALIASES` table (lines 79–537) is the largest correctness surface in the gate and is only covered transitively by `test_gate_passes_on_real_matrix`. test_check_sdk_coverage.py Test 5 only exercises the auto-generated camelCase candidate path, NOT the alias path. Recommend a test that patches `_mod.ALIASES` (same wrapper mechanism as `SDK_PATHS`) to assert an alias-only hit passes and a removed alias fails. The wrapper builder `_build_wrapper` already supports patching module globals.
