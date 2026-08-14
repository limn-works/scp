---
name: out048-wasm-invoker-stream-session-951d7cba4
description: SCP-OUT-048 BrowserInvokerStreamSession (typescript-wasm) round-4 convergence APPROVED — asyncDispose blocker fixed, seed-lifecycle honesty, raw-predicate grant guard
metadata:
  type: project
---

# SCP-OUT-048 wasm BrowserInvokerStreamSession — R4 APPROVED (convergence)

Branch feat/outlet-xctx-048-wasm-session @951d7cba4. Files:
`bindings/typescript-wasm/src/outlet-stream-session.ts` + `client.ts`.
Browser INVOKER side of §5.4.5 cross-context outlet streaming saga, ADR-057
scope-fence (browser participates/signs+decrypts in-tab; node coordinates
saga/pump/escrow/receipts behind injected `NodeStreamCoordinator`).

**Why (R4 delta 755ee122c..951d7cba4):** resolved my R3 findings.
- R3 BLOCKER: `[Symbol.asyncDispose](): void` broke `await using` (TS2851) + class
  advertised `using` with no `[Symbol.dispose]`. FIXED: asyncDispose now
  `async → Promise<void>` (AsyncDisposable), NEW sync `[Symbol.dispose](): void`
  (Disposable); both defer to idempotent `#markClosed`. Verified: tsc clean on
  src+test tsconfig (target/lib ESNext), 15/15 tests pass incl new `await using`
  block-exit test proving claim release (no SCP-VALID-7028 on next session).
- R4-2: dropped the `invokerSigningSeed.fill(0)` zeroize-on-close; doc now honest
  that seed is caller-owned long-lived identity key (zeroizing would corrupt a
  reusing caller); comprehensive key protection deferred to #1980.
- R4-4: NEW `assertGrantU32` guards raw `outletStreamSignCredit` /
  `outletStreamComputeCreditPreimage` (fail-fast InvalidGrant) — parity with
  branded `Credit`. Bounds VERIFIED identical to credit.ts `[1, 2**32)` +
  same InvalidGrant. Blocks wasm-bindgen silent u32 coercion. @throws updated.

**How to apply (future rounds):** blocker resolved, surface coherent, one-canonical-
pattern + LLM-authorable intact. Verdict APPROVED. Residual OBS only (non-blocking,
do NOT re-block): class-level JSDoc states the 7028 single-live-session lockout but
does not tie it at class level to the release remedy (close()/`using`/`break`/drain-
to-terminal) — remedy IS documented on close()/return()/[Symbol.dispose]/#markClosed
method docs (autocomplete-discoverable). `Credit` is deliberately re-implemented in
wasm tier (not imported) to keep node:-free guard; kept behaviorally byte-identical
to NAPI `bindings/typescript/src/outlets.ts` sibling.
