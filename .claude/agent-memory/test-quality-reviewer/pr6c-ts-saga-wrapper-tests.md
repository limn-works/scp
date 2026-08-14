---
name: pr6c-ts-saga-wrapper-tests
description: PR-6c TS SDK toolInvokeCrossContextSaga wrapper + mapSagaError tests — exemplary anchored-Display-string mutation-resistance pattern, with the one untested anchor gap
metadata:
  type: project
---

# PR-6c TS saga wrapper tests (bindings/typescript/tests/{errors,tools}.test.ts)

§6.2.4 cross-context tool-invocation saga TS SDK wrapper. Reviewed 2026-06-29 (worktree pr6c-ts-tq, HEAD 6e8f6ebda).

**Why:** Bridge collapses typed Rust `SagaError` into ONE napi `Error` whose only payload is the `ScpNapiError` Display string; `mapSagaError` reverses that string back to typed classes (`SagaAbortedError`/`SagaNeedsRepairError`/`SagaBusyError`) preserving the load-bearing datum (retryAfterMs/sagaId/contendedContext). Reversal correctness is the whole contract.

**How to apply (exemplary patterns worth replicating for string-reversal mappers):**
- FOUR anchors in mapSagaError, each defends a confusion class: (1) code regex start-anchored `^\s*\[(SCP-SAGA-\d+)\]`; (2) phrase regex prefix-anchored `^\s*\[SCP-SAGA-\d+\] saga (aborted|needs repair|busy):`; (3/4) datum regexes end-anchored `(…)\s*$` (end-anchored = last-anchored, so a decoy `(retry_after_ms=999)` inside {message} loses to the genuine trailing datum).
- Decoy/confusion test per anchor: "reads LAST retry_after_ms/saga_id/contended_context ignoring embedded decoy"; "dispatches on prefix-anchored phrase not body decoy" for NeedsRepair+Busy carrying embedded `] saga aborted:`.
- null-NEVER-0: retryAfterMs null on both `=null` and absent suffix (a `0` reads as "retry immediately" → re-trips hard limit). `toBeNull()` also rejects `undefined`, so it pins the exact `?? null` passthrough.
- BOTH receipt AND output omission tested separately → null (never synthesized); happy-path asserts `Array.from(buf)` to pin faithful Buffer/Uint8Array pass-through.
- 9-arg in-order forwarding test uses DISTINCT discriminating values for the 4 same-typed string params (caller-DID-aaa / tool-reg-bbb / {"in":"ccc"} / dd*16) so a positional swap can't hide behind a shared literal. `__lastCall().args` toEqual full array.
- Validation fail-fast: fractional chainDepth test asserts `__calls(op).toHaveLength(0)` (rejected before native dispatch). Bounds 0/255 accept, 256/-1/fractional reject SCP-VALID-7002; timestamp negative + non-bigint reject.
- BEHAVIOR not tautology: tools.test stubs ONLY `native.toolInvokeCrossContextSaga`; the wrapper's own validation/mapSagaError/null-passthrough/forwarding are real code. errors.test exercises pure `mapSagaError`. Real-addon marshaling boundary pinned separately in real-napi.test via `__getNativeScp` on the SAME instance (handle-affinity guard).

**Mutation-verified load-bearing (all FAIL when mutated, confirmed):** unanchored phrase `.includes` (2 confusion tests fail), each datum end-anchor drop, null→0, code start-anchor... see gap below; chainDepth 255→256, drop isInteger, drop typeof-bigint, negative-bound, 9-arg swap, both `?? null`→`?? undefined`.

**GAP (optional, non-blocking):** dropping the **code start-anchor** (`^\s*` → unanchored) SURVIVES — no test pins it. It's the one of four anchors lacking a confusion test. A non-saga error whose {message} body embeds a literal `[SCP-SAGA-#####]` would, unanchored, be pulled into the saga branch with the wrong code. Bridge-contract-unreachable (napi Display always emits the real code in the FIRST bracket), so optional defense-in-depth for symmetry — but the code comment explicitly claims the anchor's protective property, and that claim alone is unverified. Suggested test: `mapSagaError(new Error("[SCP-TOOL-6011] tool error: see [SCP-SAGA-13067] note"))` → ToolError, code SCP-TOOL-6011, not a saga subclass.

Flakiness: low. Fixed bigint/nonce literals, deterministic stubs, beforeEach fresh mount + afterEach shutdown, no time/random/order deps.
