---
name: outlet-out048-r3-wasm-session
description: SCP-OUT-048 round-3 confirming review — BrowserInvokerStreamSession wasm; both round-2 findings fixed, 2 LOW residuals
metadata:
  type: project
---

# SCP-OUT-048 round-3 (feat/outlet-xctx-048-wasm-session @755ee122c)

File: `bindings/typescript-wasm/src/outlet-stream-session.ts` + tests `outlets-streaming-invoker.test.ts`.

**Verdict: both round-2 findings FIXED, no new code bug. 10/10 tests pass.**

- Finding B FIXED (correct by ECMAScript spec): `return()`/`close()`/`[Symbol.asyncDispose]` all call idempotent `#markClosed` (guarded by `#closed`), which releases the WeakMap `(client,contextId)` claim. Idempotency correctly prevents "release a claim a successor re-took" (successor only exists after A closed → A's re-close no-ops). `for await ... break` → runtime calls `iterator.return()` (iterator=this, return() defined) → claim released. No `#draining` corruption (for-await only calls return() after next() settled).
- Finding A FIXED: `Credit` value-imported; `if(!(grant instanceof Credit)) throw InvalidGrant` at grantCredit entry (line 375) BEFORE throwIfClosed/open/grant.value. JS `{value:3.5}` throws InvalidGrant (default code SCP-OUTLET-6100).
- Multi-chunk 6110 test GENUINE + discriminating: pre-decrypts valid frame so ONE `#ingestFrame` drains both events → chunk0 pushed then wrong-key fails verify → `#pending.length=0` + throw. Without the clear, `session.next()` after throw returns `{done:false,value:chunk0}` (leak) → the `expect(next()).toEqual({done:true})` assertion fails. Coder reasoning correct.
- Error-chunk KAT self-validating: operatorSeedHex (RFC8032 vec1 9d61b1…) DERIVES operatorPkHex d75a98… (verified); wrong preimage → verify fails → 6110 not 6130. JCS-via-JSON.stringify valid (payload keys @type<code<message<terminal already sorted).
- 7029 reentrancy test sound: reentrant next() throws at `if(#draining)` BEFORE setting #draining/entering try → no corruption; first's finally resets. 7027→7029 recode correct (7027 was Governance; 7028/7029 new dedicated consts, no dup).

## Round-4 convergence (@951d7cba4) — both LOW residuals FIXED, 0 new bugs. 15/15 pass, tsc+biome clean.
- R4-2: `.fill(0)` DELETED entirely (grep-confirmed gone from #markClosed/close; only remaining invokerSigningSeed refs = read at :414 + docs). Caller can now reuse seed across sequential sessions. wasm-side transient-copy zeroize in signing_key_from_seed untouched. Docs updated (caller-owned lifecycle, in-tab key protection → #1980).
- R4-1: `[Symbol.asyncDispose]` now `async ...: Promise<void>` (PromiseLike, fixes TS2851 for `await using`); NEW sync `[Symbol.dispose](): void` added. Both call idempotent #markClosed → no double-close/successor-steal (same reasoning as return()/close()). `await using` picks asyncDispose, `using` picks dispose.
- R4-3: 4 new tests all GENUINE (fail if release regresses — 2nd construction on same (client,ctx) throws 7028 if claim not released): break-releases (return() hook), close()-releases, `await using`-releases (asyncDispose), grantCredit rejects {value:3.5}/{value:0} at runtime + asserts openCalls===0 (guard before lazy open).
- R4-4: `assertGrantU32` guards BOTH outletStreamSignCredit + outletStreamComputeCreditPreimage (client.ts). Bound `< 1 || >= 2**32` + !Number.isInteger + typeof — EXACT parity with Credit ctor. Rejects 0/-1/3.5/2**32. Sole callers of raw wasmSignCredit/wasmComputeCreditPreimage → NO bypass to u32 coercion.

## FINAL merge-gate pass — post-rebase @4d54f107c (was 951d7cba4). CLEAN, 0 bugs, ship it.
- Rebase = NO-OP semantically: `git range-diff 7e05ed15..951d7cba4 origin/main..4d54f107c` → all 11 commits `=` (patch-identical). Rebase introduced nothing.
- Cross-package rebase risk cleared: errors.ts re-exports InvalidGrant/OutletError/ValidationError from sibling `@scp-core/errors` (bindings/typescript/src/errors.ts) — InvalidGrant class still at :148, branch did NOT touch sibling (empty diff-stat). index.ts exports Credit + session + credit-sign fns present. client helpers (handleRelayFrame :363, drainEvents :389, assertInitialized :105, call :172) all present.
- Rust exports match TS arity: outlet_stream_sign_credit(8 args) / compute_credit_preimage(7) / verify / caveats — order & bigint(u64) marshalling exact. grant:u32 guarded TS-side by assertGrantU32 before wasm coercion.
- error_codes.rs additions (7028/7029/6100/7025/7026) no collision; scp-ffi-common + scp-client-wasm compile.
- GREEN: Rust KAT out048_ts_invoker_fixture_kat 1/1; ts-wasm outlets-streaming-invoker 15/15; `bun run check` (tsc x2) clean.
- Holistic re-scan confirmed sound: @type lowercase (serde rename_all="lowercase") matches toChunkView cast; isTerminal = end || (error&&terminal); monotonic_seq no double-use under concurrent grantCredit (read-sign-increment synchronous, no await between); MAX_SAFE_INTEGER seq check BEFORE verify+push (no lossy chunk buffered); verify over exact event.payload bytes (no JCS re-canon mismatch); #pending cleared on gap/verify-fail (no residual chunk leak); #expectedSequence from 0; wasm-side seed zeroize is a by-value copy (caller Uint8Array untouched — R4-2 correct).

## Two LOW residuals (round-3, now FIXED — see above)
- **Seed zeroize footgun**: `#markClosed` does `#opts.invokerSigningSeed?.fill(0)` — mutates the CALLER-owned buffer. Guarded (no throw). BUT invokerSigningSeed is the invoker IDENTITY key (long-lived, naturally reused), not per-stream. A caller reusing the same seed buffer for a second session → that session's grantCredit signs with zeros → invalid sig (silent). Directly answers "doesn't break later legitimate use" = it CAN. Tests unaffected (each sessionOpts mints fresh hexToBytes). Was the round-2-approved fix.
- **Coverage gap**: the exact Finding-B scenario (`for await … break`, and public close()/return()/[Symbol.asyncDispose]) has NO test — 7028 test releases only via drain-to-terminal (`await first.aggregate()`). grantCredit's runtime `instanceof` guard also untested (only Credit ctor tested). Fix is correct-by-construction; scenario just unverified.
