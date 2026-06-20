---
name: pr-sdk-coverage-fail-closed-parity
description: Red-team assessment of branch fix/sdk-coverage-fail-closed-and-parity (TS test-guard, trust facade, coverage gate, receipt verify)
metadata:
  type: project
---

# PR `fix/sdk-coverage-fail-closed-and-parity` (commit 6f356f8dc, assessed 2026-06-20)

**Why:** Offensive review of TS SDK test-bridge swap guard, trust facade error classification, SDK coverage gate, and receipt verification.
**How to apply:** Reference when reviewing `bindings/typescript/src/internal/test-guard.ts`, `trust.ts`, `scripts/check-sdk-coverage.py`, or receipt/JSON paths.

## RED-1101 (LOW) — test-guard freeze-order
- `_IS_TEST_ENVIRONMENT` frozen at `test-guard.ts` first-eval (IIFE). PoC scenario B: a module that sets `process.env.NODE_ENV="test"` BEFORE test-guard evaluates flips the guard to true. Runtime mutation AFTER freeze cannot flip (scenario C correct). Proto pollution defeated by `Object.hasOwn` (scenario D correct).
- NOT exploitable in practice: `__setBridgeForTests` is NOT re-exported from `index.ts`; `package.json` `exports` map exposes only `"."` -> Node blocks subpath import of `internal/bridge` (ERR_PACKAGE_PATH_NOT_EXPORTED). tsup bundles it module-internal. Attacker also needs the victim's `SCP` instance reference. Collapses to supply-chain (already-inside) where direct guard edit is easier.
- Residual real risk: a prod deployment that leaks `NODE_ENV=test` (CI image bleed) opens the seam. Config-hardening gap, not remote exploit.

## RED-1102 (LOW, original premise DISPROVEN) — trust facade `[SCP-PERM-0000]`
- Posed concern: does `[SCP-PERM-0000]` on a normally-rejected op elevate trust? NO. `0000` matches no prefix -> classify returns "unknown" -> `__PASSED_BEFORE.unknown = empty set` -> ALL SIX fields go false. Crafted-unknown-code = fail-closed. Confirmed via PoC Attack2.
- REAL residual (requires compromised bridge): if bridge `ucanValidate` RESOLVES on a forged token, Layer1 reports all-true (Attack1). A late-stage error like `token expired` elevates everything before expiry to true (Attack3). This is inherent to trusting the bridge — a compromised native addon has far more direct attacks. The facade adds no NEW elevation primitive beyond "trust the bridge's verdict".

## RED-1103 (MEDIUM) — coverage gate: existence != reachability
- PROVEN: added `Economy/apply_refund_override = true` x4 SDKs routed via ALIASES to dead stub `economyApplyRefundOverride` (never calls bridge) + unrelated `estimate_cost` for py/kt/swift. Gate PASSED (0 errors). Gate checks symbol EXISTENCE only, never reachability/wiring/semantics. Stale ALIASES entry + a real-but-orphaned export = green gate over a dead capability. The matrix-only variant (auto-name matching an unrelated existing symbol) doesn't even require editing the gate.
- Mitigation: gate is defense-in-depth; reachability must be enforced by `pipeline_wiring.rs` assertions + per-op SDK tests, not this gate. sdk-coverage-verifier agent should spot-check reachability on matrix changes.

## RED-1104 (NON-ISSUE) — receipt JSON injection / proto pollution
- DISPROVEN. `economyVerifyPaymentReceipts`: `JSON.stringify(receipts)` escapes embedded quotes (no stream injection); `__proto__` object-literal key is the prototype slot, dropped by stringify. Response `JSON.parse(raw)`: native parse does NOT pollute Object.prototype via `__proto__` (becomes own key literally named `__proto__`); `constructor.prototype` injection also inert. Only risk needs already-compromised bridge.

## Reusable patterns
- **JS env-guard freeze pattern**: freeze-at-import defeats runtime mutation + proto pollution, but is hostage to whatever set the env BEFORE first eval. Always pair with package `exports` encapsulation (only `"."`) so test-only seams are unreachable by deep import.
- **AST coverage gates verify NAME, not REACHABILITY** — same class as OwnedIdentityDid gate lesson. Existence-check gates are alias-evadable to dead code. Prefer compile-time/pipeline-assertion enforcement of actual wiring.
- **Trust facade error-classification is fail-closed on unknown codes** (empty PASSED set) — good. Its ceiling is "trust the bridge verdict"; not a new primitive.
