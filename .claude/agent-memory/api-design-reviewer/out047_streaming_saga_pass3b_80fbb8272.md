---
name: out047-streaming-saga-pass3b-80fbb8272
description: SCP-OUT-047 pass-3b cross-SDK consistency review of TS/Swift/Kotlin streaming-saga wrappers vs Python reference (StreamingSagaHandle)
metadata:
  type: project
---

# SCP-OUT-047 pass-3b TS/Swift/Kotlin streaming-saga vs Python reference @80fbb8272

APPROVED (1 LOW change recommended). branch feat/outlet-xctx-047-streaming-saga-ffi. Developer-facing SDK wrappers over pass-3a NAPI+UniFFI bridge; models each SDK's `StreamingSagaHandle` on the same-context `InvocationHandle` sibling, MINUS live control plane (no xctx grantCredit/cancel per §6.2.5 SCP-OUT-046, cancel_ack_ceiling=u64::MAX). Async stream lazy-opens at Commit-transition (open returns durable saga_id PROMPTLY, Committed async at seal-close per ADR-049 §3a), drains to terminal-chunk-OR-None, single-consumer guard, `aggregate()` primary drain, `recover...TruncatedClose`.

**Prior C11a MAJORs RESOLVED**: Kotlin `asFlow()` now `flow{ while(true) nextChunk() }` pulls the ONE shared drain (not cold re-execute), docstring says so; `aggregate()` is documented PRIMARY in all 4 with `await handle` as Python/TS sugar only.

**Cross-SDK shape = consistent** (stream: py async-iter / TS AsyncIterable / Swift AsyncSequence actor / Kt Flow). All lazy-open, terminal-or-None, single-consumer ProtocolError-on-2nd-driver, gap→StreamGap 6131 w/ NO bridge cancel (xctx has no cancel plane — correctly omitted all 4).

**LOW CHANGE**: saga_id accessor name drift — Python `saga_id` / TS `sagaId` vs Swift+Kotlin `currentSagaId` (current* prefix only dodges Swift actor private-var collision; Kt copied Swift). No same-context sibling to anchor (InvocationHandle exposes no handle id) → should be uniform `sagaId`. Rename Swift/Kt public accessor to sagaId (Swift private var → memoizedSagaId).

**OBSERVATIONS (house-consistent, mirror unary saga sibling — NOT new problems, blessed by pass-3a)**:
- Swift entry on Context `ctx.invokeOutletCrossContextStreamingSaga(targetContext:...)` (invoke-first) vs py/TS/Kt on SCP `outletInvoke...` (outlet-first). Each mirrors its OWN unary sibling (Swift `invokeOutletCrossContextSaga`; others `outletInvokeCrossContextSaga`). recover name identical ×4.
- Python string ids (caller_context_id/target_context_id) vs TS/Swift/Kt handles — matches unary sibling + pass-3a ruling.
- await/aggregate split (py/TS awaitable, Swift/Kt aggregate-only) — matches InvocationHandle sibling, language idiom.
- SCP-PERM-3001 invoker-gate on recover: type differs (py ContextError / TS UcanPermissionError / Swift+Kt Permission) but ALL carry `.code`; docs say branch on .code. Pre-existing bridge-mapping asymmetry (py reference least-structured), matches sibling.

**MISUSE-RESISTANCE (two-leading-same-typed-handle swap)**: TS genuinely prevents (StreamingSagaOptions named source/targetHandle — actually STRONGER than TS's own unary sibling which is still positional `sourceHandle:unknown,targetHandle:unknown`). Swift genuinely prevents (source=self + labeled targetContext:, never adjacent). **Kotlin = by-convention ONLY** — named params are caller-OPTIONAL, `scp.fn(h1,h2,...)` compiles+swaps 2 ContextHandle; weakest cell, but mirrors Kt unary sibling + no Kt compile-time named-arg enforcement + newtype wrapper=over-eng → acceptable. recover(sagaId,callerDid) 2-string swap: Swift labels prevent, py/TS/Kt positional (#1991-class LOW).
