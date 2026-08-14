---
name: pr2141-d2c056ea4-economy-unwrapped
description: PR #2141 re-review at d2c056ea4 — MEDIUM economy_verify_payment_receipts unwrapped; LOW getBridge test fragility
metadata:
  type: project
---

# PR #2141 (fix/sdk-coverage-fail-closed-and-parity) @ d2c056ea4 re-review

Supersedes earlier CLEAN note (28623a226) — later commits added a new economy method with a parity gap.

**Why:** Re-review after error-parity work landed on more commits.
**How to apply:** These are the only two live findings at this HEAD; the gate + TS/Py parity core remain CLEAN (see pr2141-sdk-coverage-parity.md).

## MEDIUM — `SCP.economy_verify_payment_receipts` (bindings/python/scp_sdk/scp.py ~2226) leaks raw native errors
- New method added in this PR. Unlike every other economy/identity/outlet method (all wrapped with `_coded_bridge_error`), it does NOT wrap.
- PyO3 `economy_verify_payment_receipts` (crates/scp-ffi/src/economy.rs:470) raises bare `PyValueError` ("invalid receipts JSON", "receipt batch too large") and `PyRuntimeError` ("supervisor dispatch...failed", "shim reply dropped") — NOT ScpPyError variants, and messages do NOT start with `[SCP-...]`.
- SDK method docstring promises "Raises: ScpError" but callers doing `except ScpError` will MISS these — raw ValueError/RuntimeError propagate. Also `json.dumps(receipts)` / `json.loads(raw)` unguarded.
- Fix: wrap the `to_thread` call (and ideally the json) in `try/except Exception: raise _coded_bridge_error(exc) from exc`. Note "ValueError"/"RuntimeError" are NOT in BRIDGE_ERROR_MAP → would map to ContextError default, but at least catchable as ScpError. Deeper fix: PyO3 should raise coded ScpValidationError instead of bare PyValueError.

## LOW — 4 new tests in tests/scp-typed-errors.test.ts fragile (addon-coupled)
- contextSend/governancePropose/outletInvoke/ucanValidate were migrated in this PR from `this.#native.X` to `getBridge(this).X`. `createNativeBridge` (native.ts:175) calls `loadNativeAddon()` UNCONDITIONALLY before using the mock `native`.
- The 4 tests use `mountMockScp` + `native.__stub(...)` — which the mock-bridge.ts NOTE explicitly says is WRONG for getBridge-routed methods (should use `__setBridgeForTests`). They pass in CI only because typescript-check job builds+wires the real napi addon (ci.yml:710-737) so loadNativeAddon() succeeds and `__getNativeScp` returns the mock. Fail in any addon-free env, contradicting mountMockScp's "runs without addon" design intent. NOT CI-breaking.

## Verified CLEAN this pass
- `_coded_bridge_error` moved trust.py→errors.py: anchored `^\s*\[(SCP-[A-Z]+-\d+)\]` + prefix-strip → ScpError.__str__ reconstructs `[code] msg`, no double-bracket. CancelledError (BaseException) not caught by `except Exception`. Good.
- NAPI (error.rs Display `[{code}] ...` via Self::new(GenericFailure, e.to_string())) + PyO3 (write! `[{code}] ...`) + WASM (to_js `[{code}] {err}`) all put code at position 0 → anchored regex OK on all 3, no regression vs old unanchored.
- Private-symbol exclusion in check-sdk-coverage.py: no ALIASES reference underscore names; gate runs PASS 0 errors; 23 self-tests pass.
- wrapBridgeErrors Proxy applied at createNativeBridge return (native.ts:2127); getBridge-routed methods get mapping; 3 #native-direct (identityRemove/identityExecuteRecovery/eventLogQuery) get explicit try/catch mapBridgeError. contextSend Uint8Array→number[] conversion done inside bridge. identity key-op bridge methods call same handle.X() as before (behavior-equiv + now typed).
- Kotlin/Swift diffs are doc-citation only (§3.2.1→§9.12).
