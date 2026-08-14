---
name: ts-sdk-test-seams
description: TypeScript SDK convention for test-only hooks exported from production source, and the shared guard to reuse
metadata:
  type: project
---

The TS SDK (`bindings/typescript/src/`) exposes test seams as `__xxxForTests` functions exported from production source files (they ship in the build output). Examples in `scp.ts`: `__clampShutdownMillisForTests`, `__serializeStorageConfigForTests`, `__constructScpWithNativeForTests`. In `internal/bridge.ts`: `__setBridgeForTests`.

Each must be guarded so the seam can't be abused at runtime. As of branch `fix/sdk-coverage-fail-closed-and-parity` the canonical guard is `assertTestEnvironment(hookName)` in `internal/test-guard.ts` — a single shared module with `_evaluateTestEnv(env)` (positive allowlist: `NODE_ENV` in {test, development} OR non-empty `BUN_TEST`, using `Object.hasOwn` for prototype-pollution resistance), a module-load `process.env` snapshot wrapped in try/catch (frozen at import — runtime mutation can't flip it), plus `isTestEnvironment()`/`assertTestEnvironment()`. Both `scp.ts` (`__constructScpWithNativeForTests`) and `internal/bridge.ts` (`__setBridgeForTests`) import it. Security rationale cites red-hat RED-PR5-001/007.

**Why:** The seam ships in production, so a runtime guard is the only barrier. The try/catch matters because `internal/bridge.ts` has the browser WASM path where `process` is genuinely absent — a bare `process.env.BUN_TEST` read there throws ReferenceError. Centralizing in one module prevents the guard from drifting weaker per-callsite.

**How to apply:** When reviewing a new `__xxxForTests`, check it imports/calls `assertTestEnvironment` from `internal/test-guard.ts` rather than inlining a fresh env check. An inlined copy is a DRY violation that can drift weaker (e.g. dropping the try/catch). Flag MED. RESOLVED on this branch: the prior duplication where `__setBridgeForTests` inlined a weaker guard is gone — both callsites now share the helper.
