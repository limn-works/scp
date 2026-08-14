---
name: pr2141-typed-errors-nonhermetic
description: PR#2141 — BOTH r2 HIGHs RESOLVED @78b6aae58 (SHIP). r1 @d2c056ea4 findings below for provenance.
metadata:
  type: project
---

## SECOND-PASS RESOLUTION @78b6aae58 — SHIP
Both r1 HIGHs fixed and I VERIFIED them:
- Hermeticity: rewrote the 5 async tests to `__setBridgeForTests(scp, makeSpyBridge(method, rawErr))` where `makeSpyBridge = wrapBridgeErrors(Proxy-that-Promise.reject(rawErr))`. `getBridge(scp)` hits the WeakMap BEFORE `import("./native.js")`, so injected bridge short-circuits addon load. PROVEN hermetic: physically `mv`'d node_modules/@limn-works/scp-ts-napi-darwin-arm64 away → still 8/8 pass. Test path == prod: `createNativeBridge` returns `wrapBridgeErrors(bridge)` (native.ts:2127), so the spy exercises the real `mapBridgeError` seam. Both dispatch surfaces covered: async→getBridge/wrapBridgeErrors; sync (identityRemove/identityExecuteRecovery) + eventLogQuery→`#native` w/ manual `try/catch{throw mapBridgeError}` via `native.__stub`.
- Fallback: now `expect((thrown).constructor).toBe(ScpError)` (strict base, discriminates TransportError-extends-ScpError vacuity) + `.code === "SCP-UNKNOWN-9999"` (proves bracket-extraction threaded actual code, not defaulted to -0000). Non-vacuous. `SCP-UNKNOWN-9999` matches no ERROR_PREFIX_MAP prefix → base `new ScpError`.
- MEDIUM (embedded-code): my `assert result.code is None` suggestion was WRONG and correctly REVERTED (commit c1a7b49d4). `ScpError.__init__` (errors.py:50) assigns `_default_code` when code=None, so code is NEVER None; ContextError default = `SCP-CTX-2000`. Kept `assert result.code != "SCP-CTX-2076"` is correct+discriminating. Minor strengthen available: `== "SCP-CTX-2000"` to positively pin default path.
- `isTestEnvironment` KEPT w/ JSDoc (test-guard.ts:38-50) explaining it exists for test-guard.test.ts; genuinely tested (77-91) + heavy logic via `_evaluateTestEnv` directly. Defensible.
No remaining blockers.

# PR #2141 (fix/sdk-coverage-fail-closed-and-parity) @d2c056ea4 — typed-error test review (FIRST PASS, superseded above)

Worktree `/tmp/scp-2141`. NOTE: since the r25 review the branch was reworked:
`test_ts_prefix_parity.py` REMOVED (commit e78795e90); trust.test.ts revocation-prefix
tests + browser Buffer test are now IDENTICAL to main (not in this PR's diff). Focus
items 2 & 3 from the task are stale — not in scope at this HEAD.

Test files actually in diff vs main: scripts/test_check_sdk_coverage.py (NEW, 23 subcases),
bindings/typescript/tests/{identity-lifecycle,scp-typed-errors,test-guard}.test.ts (NEW),
bindings/python/tests/test_sdk_parity_additions.py (NEW), test_outlets.py + test_real_ffi.py (mod).

## HIGH — scp-typed-errors.test.ts is NON-HERMETIC (verified by running)
4 of 8 tests FAIL in any env without a built napi addon: contextSend, contextGovernancePropose,
outletInvoke, ucanValidate. Root cause: these SCP methods route through `bridge.X` = `getBridge(scp)`,
and `mountMockScp` only sets `#native` (NOT the getBridge WeakMap — its own doc says so). So
getBridge→createNativeBridge→`loadNativeAddon()` THROWS TransportError(SCP-TRANS-5001) BEFORE the
mock #native is consulted. The tests catch that TransportError, assert `instanceof ContextError` etc → fail.
- CI MASKS it: ci.yml `typescript-check` (lines 697-743) builds scp-ffi-napi + stages index.node into
  node_modules before `bun test`, so loadNativeAddon succeeds; then createNativeBridge STILL dispatches
  to the mock #native (__getNativeScp), wrapBridgeErrors maps the thrown error → tests pass & are valid.
- So the addon dependency is INCIDENTAL (tests mock #native; never need real native), contradicts the
  mock-bridge charter ("run even when no platform addon installed"), and breaks local `bun test`.
- FIX (pattern already in sibling identity-lifecycle.test.ts): inject via
  `__setBridgeForTests(scp, wrapBridgeErrors(spyBridge))` so the mapBridgeError seam runs addon-free.
  identity-lifecycle surface tests + test-guard tests are HERMETIC (7pass/1skip, 13pass).

## HIGH — "falls back to base ScpError" test (contextMemberCount) VACUOUS-PASSES
Assertion is ONLY `expect(thrown).toBeInstanceOf(ScpError)`. TransportError EXTENDS ScpError, so the
loadNativeAddon TransportError satisfies it → PASSES locally for the WRONG reason (never reaches the
`[SCP-UNKNOWN-9999]` stub, never exercises the fallback mapping). Even in CI it's weak: name says
"base ScpError" but assertion accepts ANY subclass and doesn't pin `.code`. Should assert
`thrown.constructor === ScpError` (exactly base) AND `.code === "SCP-UNKNOWN-9999"`.

## Passing/hermetic + genuine
- 4 #native-direct typed-error tests (identityRemove, identityExecuteRecovery both sync; eventLogQuery;
  ucanValidate-consumer eventLogQuery) pass addon-free, pin `.code` + preserved message. Good.
- mock #native seam is REAL: createNativeBridge does `__getNativeScp(scp)` = the mounted mock, wraps in
  `wrapBridgeErrors` (native.ts:2127); strict-mode mock throws on unstubbed methods (crypto finding M-1).
- identity-lifecycle surface tests: single-arg wrappers; Proxy throws on any unexpected Bridge.method →
  catches method-MISROUTING (rotateKey wrongly calling migrate would throw). Load-bearing.

## MEDIUM — test_embedded_code_is_not_captured weak negative
`assert result.code != "SCP-CTX-2076"` is trivially true (code is None). Stronger + equally targeted:
`assert result.code is None`. Still load-bearing against "unanchor the `^\s*\[` regex" mutation because
search-with-`^` vs bare `\[...\]` is the discriminator. `_SCP_CODE_RE = ^\s*\[(SCP-[A-Z]+-\d+)\]`.

## check-sdk-coverage self-tests (scripts/test_check_sdk_coverage.py) — STRONG
23 subcases pass in 2.4s. Fail-closed shape guards (empty caps→"zero operations"; missing key; non-dict
caps/ops/op-entry/coverage_exemptions; malformed JSON→no traceback; list top-level). All direction-pinned
on exact error PHRASES not just returncode. Mutation-oriented: Test 2 rebuilt to isolate unmatched-true
from missing-SDK-key (doc explains the prior masking). Test 9 pins domain-prefix-only enforcement
(bare camel must NOT satisfy). Private-symbol exclusion tests (3b) pin the diff's `not name.startswith("_")`.
tmp_path-isolated subprocess wrappers, no time/random/order deps, tree-sitter tests skip gracefully. Test 1
(real matrix) is a slow full-tree integration smoke but deterministic. Verdict: SHIP for this file.
