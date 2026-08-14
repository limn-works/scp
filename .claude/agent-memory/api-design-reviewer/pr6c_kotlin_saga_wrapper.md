---
name: pr6c-kotlin-saga-wrapper
description: APPROVED — #1939 PR-6c slice 4/4 Kotlin SDK wrapper for §6.2.4 cross-context tool saga; closes the 4-SDK arc
metadata:
  type: project
---

#1939 PR-6c slice 4/4 (Kotlin SDK wrapper, §6.2.4 saga / ADR-049 §3a) reviewed @a9c0cdcac, RE-REVIEWED @7c4575dfc (identical diff, same verdict) — APPROVED, no blockers. Closes the 4-SDK wrapper arc (Python/TS/Swift already merged). Confirmed generated SagaResult{sagaId(doc "supervisor-minted, never a caller input"),receipt?,output?} + ScpException.Saga{Aborted(msg,code,retryAfterMs:ULong?)/NeedsRepair(..sagaId)/Busy(..contendedContext)} surfaced DIRECTLY (defined only in internal/uniffi/scp/scp.kt, not redefined). Kotlin `SCP.toolInvokeCrossContextSaga` aligns w/ Py/TS majority + its OWN sync sibling; Swift `Context.invokeToolCrossContextSaga` is the lone outlier (Kotlin on the right side). Bridge layer Int/Long sourceContextHandle (UniFFI-free conformance surface) vs shim ULong/UByte sourceHandle — both mirror sibling exactly.

**Why:** Final Kotlin slice over the merged UniFFI op; Kotlin shares the UniFFI bridge with Swift, so the generated SagaResult/ScpException.Saga* types are identical-by-construction.

**How to apply:** This arc is done. Cross-SDK CONTRACT parity is verified and clean:
- Scp.kt `suspend fun toolInvokeCrossContextSaga(sourceHandle,targetHandle,callerDid,toolRegistrationId,inputJson,assertedNonceHex,timestampMs:ULong,chainDepth:UByte,ucanProofId:String?) -> SagaResult` is BYTE-IDENTICAL in shape to Swift Scp.swift:1049 (ULong↔UInt64, UByte↔UInt8). Forwards 1:1 to `inner`, surfaces generated ScpException.SagaAborted(retryAfterMs:ULong?)/SagaNeedsRepair(sagaId)/SagaBusy(contendedContext) directly (no re-map). SagaResult(sagaId, receipt:ByteArray?, output:ByteArray?) faithful nullable. sagaId is supervisor-minted (no sagaId input param).
- Two surfaces correctly mirror the non-saga sibling `toolInvokeCrossContext`: (a) Scp.kt shim on the `SCP` class (Kotlin has NO Context.kt — sibling lives on SCP too, so saga placement is right), (b) flat ToolBridge.invokeCrossContextSaga conformance scaffold (Long/JSON-String/Int/BridgeException) via `bridge.ffiCall {}`.
- `ffiCall` (NOT ffiCallSuspend) is CORRECT: flat ToolBindings method is a blocking `fun ... : String`; ffiCallSuspend is only for UniFFI-generated suspend fns. Real suspension is the Scp.kt shim awaiting the generated suspend fn. Mirrors sibling.
- NO client-side guards / NO manual range validation is CORRECT consistency-with-sibling (Kotlin sibling has none; ULong/UByte enforce u64/u8 at the type level; inputJson already String). This is intentionally DIFFERENT from Swift (which has Data→String UTF-8 + state guards) because the per-SDK sibling differs — not a gap.
- Matrix flipped kotlin true, exemption block removed; note lists all 4 live wrappers.

**Non-blocking observations only:**
- Cross-SDK dev-facing NAME drift (inherited, not introduced): Swift `Context.invokeToolCrossContextSaga` (word-order + Context-type placement) vs Kotlin/TS `toolInvokeCrossContextSaga` vs Python `tool_invoke_cross_context_saga`. CLAUDE.md "identical shape" = params/types/result/errors (which ARE identical); per-language casing + Swift's Context-type placement are pre-existing sibling idioms. Decline — set elsewhere.
- Happy-path first-hop requires explicit `chainDepth = 0.toUByte()` (no default) — but sibling is identical; consistency wins.
- ucanProofId default=null only on the flat ToolBridge method, not the SCP shim — exactly mirrors sibling proofTokens convention.
