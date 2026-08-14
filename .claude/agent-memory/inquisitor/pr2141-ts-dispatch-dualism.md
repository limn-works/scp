---
name: pr2141-ts-dispatch-dualism
description: PR#2141 TS SDK error-mapping dualism — getBridge Proxy auto-map vs this.#native manual try/catch; root-cause coherence finding
metadata:
  type: project
---

PR#2141 (fix/sdk-coverage-fail-closed-and-parity) branch-specific TS changes reviewed @ /tmp/scp-review-r25 (merge-base bc4464566).

Fact: the TS SDK has TWO dispatch surfaces to the SAME per-instance NAPI handle, with two divergent error-mapping disciplines:
- `getBridge(this)` returns a `wrapBridgeErrors` Proxy (bridge.ts:821) → every function member auto-mapped via `mapBridgeError` (idempotent: early-returns on `instanceof ScpError`). Automatic, can't-forget.
- `this.#native.foo(...)` = raw addon, NO mapping unless a manual `try/catch { throw mapBridgeError(e) }` is hand-written.

Both reach the identical per-instance handle (createNativeBridge's `identityRotateKey(handle)` internally calls `handle.rotateKey()` — same call main did inline). ALL the direct-#native methods (identityRemove, identityExecuteRecovery, contextSend, contextMemberCount, contextGovernancePropose, outletInvoke, ucanValidate, eventLogQuery) ARE declared on the `Bridge` interface — so they are routable through the auto-mapping path.

**Why (root):** PR migrated 5 async identity lifecycle methods FROM main's handle-direct `identity._rawHandle as unknown as {rotateKey()}.rotateKey()` (type-erased, unmapped) TO `getBridge(this).identityRotateKey(handle)` (typed + auto-mapped) — fixing a real regression. But 6 OTHER async methods got manual try/catch bolted onto the #native path instead of the same migration. Symptom-driven (add mapping where missing), not root-driven (converge on getBridge). Only 2 of the 8 (identityRemove, identityExecuteRecovery) are genuinely SYNC and legitimately can't `await getBridge` (async).

**How to apply:** Root fix = route all ASYNC SCP-class dispatch through `getBridge(this)` so error mapping is structural (impossible to forget), reserving #native+try/catch ONLY for the 2 sync methods. The manual try/catch additions in this PR are CORRECT and improve on main (which had zero mapping) — NOT a blocker — but the dualism is unconverged drift and a new #native async method can silently leak raw FFI errors. Verdict was SOUND w/ 1 SHOULD-FIX. See [[pr2141-coverage-gate-private-exclusion]], [[pr2141-layer1-trust-display-reconstruction]].

## R25 re-review resolution (HEAD 28623a226) — SHOULD-FIX RESOLVED, dualism minimized 6→3
The R3 SHOULD-FIX landed correctly. 5 async methods (contextSend/contextMemberCount/contextGovernancePropose/outletInvoke/ucanValidate) MIGRATED to `getBridge(this).X(...)` — type/arg-order-verified against Bridge iface, now auto-mapped by the wrapBridgeErrors Proxy (strictly better than main; typed handles, no `as unknown` cast). 3 residual methods keep manual try/catch and ALL THREE are STRUCTURALLY FORCED, not lazy:
- eventLogQuery: public sig `filterJson?: string` (raw JSON) mismatches Bridge `eventLogQuery(filter: EventFilter|undefined)` (structured camelCase object, native.ts:1173 does snake_case conversion). Routing a string through → `filter.eventType`=undefined → `JSON.stringify({})` → SILENTLY DROPS the filter. try/catch is the correct workaround. VERIFIED.
- identityExecuteRecovery: public SCP method is SYNC (returns `string`); Bridge iface (bridge.ts:590) is ASYNC (`Promise<string>`). Routing would change the PUBLIC return type sync→async = breaking. Forced to #native.
- identityRemove: same void sig as Bridge (bridge.ts:577) so getBridgeSync migration is TYPE-possible, BUT getBridgeSync (bridge.ts:892) THROWS "Bridge not initialized" if no async SCP method ran first; #native has no such ordering precondition. Keeping #native avoids a first-call-ordering regression. Justified.
Net: dualism now reduced to exactly the cases where public-API SHAPE divergence blocks migration. CONSIDER (pre-existing, out of scope): clean end-state reconciles those 3 public signatures (structured filter / async recovery / lazy-load-tolerant remove) so ALL route through the can't-forget Proxy.

Python side (a20eb5314): 8 methods wrap native calls in `try/except Exception: raise _coded_bridge_error(exc) from exc`. SOUND: `_coded_bridge_error` (errors.py:315) idempotent (isinstance ScpError passthrough), anchored `_SCP_CODE_RE = ^\s*\[(SCP-[A-Z]+-\d+)\]`, `except Exception` does NOT catch asyncio.CancelledError (BaseException) so cancellation propagates, `from exc` keeps chain, broad except scoped to single native call. LAZY `from scp_sdk.errors import _coded_bridge_error` inside method bodies = NO circular-import risk (errors.py imports only stdlib `re`; scp.py already top-imports `from scp_sdk.errors import ScpError` @L58 so it's a free sys.modules lookup) — matches existing file convention (lazy per-method error imports @L501/534/671/704/...). CONSIDER: that lazy-import-of-errors pattern is unexamined cargo-cult (no dep reason to not top-import) but harmless + out of scope.
LOW: TS contextMemberCount migration adds `?? 0` mapping Bridge `number|null`→0 (main returned null-as-`number`, a type lie). Type-honest improvement; confirm null (context-not-found?) shouldn't surface as an error rather than "0 members".
Gate self-tests (scripts/test_check_sdk_coverage.py): 23 passed. Verdict: LGTM, no BLOCKER/SHOULD-FIX.
