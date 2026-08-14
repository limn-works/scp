---
name: ts-typed-error-exemption
description: branch fix/sdk-coverage-fail-closed-and-parity — ucanValidate/eventLogQuery mapBridgeError exemption is unnecessary; the per-method try/catch pattern at 201 is correct
metadata:
  type: project
---

Branch `fix/sdk-coverage-fail-closed-and-parity` (@d34097078) wraps all ~201 `SCP`-class methods in `bindings/typescript/src/scp.ts` with `try { ... } catch (err) { throw mapBridgeError(err); }`. Reviewed for simplicity.

**Per-method try/catch at 201 is CORRECT — not over-engineered.** A helper wrapper would erase each forwarder's per-call return type (each narrows `this.#native.X as (…)=>Promise<T>` against the Rust source of truth), reintroduce an async/sync split (suspend/identityRemove are sync), and add indirection — to save 3 regular (not complex) boilerplate lines. Uniform + greppable + type-exact wins. Same verdict the simplifier gave at 14 identity methods. Do NOT recommend a helper.

**THE finding (MAJOR): the `ucanValidate`/`eventLogQuery` mapping exemption is unnecessary and self-undermining.**
- Why: `mapBridgeError` (`errors.ts:265`) builds `new ErrorClass(message, code)` — it PRESERVES the full original message verbatim (including the `[SCP-...]` prefix) AND surfaces typed `.code`. So a mapped typed error carries strictly MORE than the raw `Error`. The exemption's stated reason ("trust.ts classifies the raw `[SCP-...]` message prefix and re-throws by identity, so these must bypass mapping") is FALSE — typed errors support all of it better: `instanceof UcanPermissionError`/`ContextError`, `error.code === "SCP-PERM-3030"`, and `throw error` re-throws by identity regardless of type.
- Fix: wrap both methods like every other; convert `trust.ts:444-512` Layer-1/Layer-2 from message-regex (`/^\[SCP-PERM-\d+\]/` etc.) to `instanceof`/`.code`; delete the 2 pass-through tests + guard comment in `tests/scp-typed-errors.test.ts:140-174`. Brings TS in line with the Python port (catches `UcanError`/`ContextError` by type). Eliminates the only asymmetry in an otherwise-uniform 201-method surface.
- How to apply: if a future round still has the exemption, re-raise as MAJOR. If trust.ts switched to typed-error classification, the exemption should be GONE — verify it was actually removed, not just the tests deleted.

**Not findings:** scp-typed-errors.test.ts 6 substantive tests each pin a distinct mapBridgeError path (lean, keep). ADR-053 4×6 canonical method-name table is load-bearing (names dynamically dispatched by string across FFI via bridge-aliases.json) — correct even for Proposed status. No non-convergent enforcement in this branch (check-sdk-coverage.py already converged per [[project_sdk_coverage_failclosed_converged]]).

**Observation:** ADR-053 (pre-rotation custody substrate isolation) is scope-unrelated to the error-wrapping work — mixed logical unit if this becomes one PR.
