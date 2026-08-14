---
name: pr6c-kotlin-saga-wrapper-a9c0cdcac
description: PR-6c slice 4/4 (#1939, FINAL) Kotlin SDK wrapper for §6.2.4 cross-context tool-invocation saga UniFFI op — ALIGNED, 0 findings @ HEAD 7c4575dfc (prior MINOR resolved)
metadata:
  type: project
---

# RE-REVIEW @ HEAD `7c4575dfc` (worktree pr6c-kotlin) — ALIGNED, 0 findings (FINAL)

HEAD = a9c0cdcac + 2 commits. `d0a01d353` ("drop issue ref from saga test comment") RESOLVES the prior MINOR below — ToolSagaTest header is now "Provenance: PR-6c slice 4/4. §6.2.4 / ADR-049 §3a. ADR-026/ADR-028." (NO `#1939`). `7c4575dfc` strengthens the e2e catch assertion to `e.message!!.contains("code=")`. `git diff origin/main...HEAD | grep '#[0-9]{2,}'` = **NONE anywhere**.

NEW VERIFICATION (inspected the locally-generated gitignored binding `bindings/kotlin/scp-kt/src/main/kotlin/works/limn/scp/internal/uniffi/scp/scp.kt`): generated `NativeScp.toolInvokeCrossContextSaga` (scp.kt:7193) signature is byte-for-byte the Scp.kt shim; `SagaResult(sagaId, receipt:ByteArray?, output:ByteArray?)` (scp.kt:13592); `ScpException.SagaAborted{msg,code,retryAfterMs:ULong?}`/`SagaNeedsRepair{...,sagaId}`/`SagaBusy{...,contendedContext}` with `override val message get() = "msg=…, code=…, …"`. THAT message format makes the e2e `contains("code=")` assertion field-name-derived and GUARANTEED for every reachable fielded terminal/rejection (all carry a `code`). Generated binding confirmed gitignored + absent from the 7-file diff. All prior contract-parity conclusions HOLD. Verdict: ALIGNED, 0 findings.

LESSON (new): for UniFFI SDK-wrapper review, inspect the locally-generated gitignored `scp.kt` to confirm message format / camelCased field names / return type — don't rely on the matrix or bridge .rs alone. The Scp.kt shim's positional fidelity is compile-time-guaranteed by NAMED-arg forwarding (same-typed swap impossible); the flat-path test pins exact lastSagaArgs; the e2e is honestly scoped as a linkage smoke test.

---
# PRIOR @ a9c0cdcac — ALIGNED, 1 MINOR (now resolved by d0a01d353)

FINAL slice (4/4) of #1939, closes the SDK-wrapper sub-slice. Sibling of merged Python/TS/Swift slices ([[pr6c-py-saga-wrapper-1939]], [[pr6c-ts-saga-wrapper-review]], [[pr6c-swift-saga-wrapper-238c133bd]]). Diff = 7 files +576/-5: matrix flip + Scp.kt shim + CoroutineBridge.kt (ToolBindings iface + ToolBridge method) + 3 test files.

## Contract parity (all PASS, verified against live bridge)
- `Scp.toolInvokeCrossContextSaga` forwards 9 params IN ORDER to `inner.toolInvokeCrossContextSaga` (inner: NativeScp generated UniFFI). Order/types EXACT vs bridge.rs:12314 export: sourceHandle/targetHandle(ContextHandle), callerDid, toolRegistrationId, inputJson, assertedNonceHex(String), timestampMs(ULong←u64), chainDepth(UByte←u8), ucanProofId(String?←Option<String>). Returns `SagaResult` DIRECTLY — faithful pass-through, NO re-map.
- **KEY DELTA vs napi/TS (same as Swift slice):** UniFFI typed errors → wrapper surfaces typed `ScpException.Saga*` DIRECT, NO string-parse/mapSagaError in the SDK layer (the napi unanchored-phrase weakness is structurally absent — same as Swift). Bridge's `map_saga_error` (bridge.rs:5424) routes through shared `decompose_saga_error` (common/saga_errors.rs) onto ScpError::Saga* with msg/code/structured-datum; UniFFI codegen → ScpException.Saga*.
- Field names match Rust field names (UniFFI surfaces them): SagaAborted{msg,code,retryAfterMs}, SagaNeedsRepair{msg,code,sagaId}, SagaBusy{msg,code,contendedContext}; SagaResult{sagaId, receipt:ByteArray?, output:ByteArray?} — receipt/output null-never-synthesized (Option<Vec<u8>>→ByteArray?).
- Codes: NeedsRepair=13065, Busy=13066 fixed (saga_errors.rs); Aborted=`SCP-SAGA-{numeric}` from producer (generic default 13067 NOT 13050 — 13050 is the pre-saga membership-reject at bridge.rs:12250, pre-existing, not in diff). retry_after_ms None-never-0 enforced in common, test pins null-preservation.
- block-until-terminal = `suspend` shim over UniFFI async export (spawn+await inside Rust). sagaId supervisor-minted — NO sagaId input param. NO client guards / NO manual range validation — ULong/UByte enforce bounds; mirrors sibling `toolInvokeCrossContext` (Scp.kt:1537) which also has no guards. CONSISTENT.
- Flat `ToolBridge.invokeCrossContextSaga` + `ToolBindings.toolInvokeCrossContextSaga`: flat ffiCall (Long/Int/String, UniFFI-free), returns JSON String, BridgeException propagation — mirrors sibling invoke_cross_context PATTERN (different params, same shape). This is the coverage/conformance symbol.
- Matrix flip HONEST: kotlin false→true, exemptions object REMOVED, notes→"all four SDK wrappers live", scoped to invoke_cross_context_saga entry ONLY (session_create untouched). NO generated UniFFI file in diff (gitignored+Gradle-regenerated, unlike Swift which commits generated binding).

## FINDING (1 MINOR — same class the Swift slice had+fixed pre-merge)
`ToolSagaTest.kt:242` header comment: `// Provenance: #1939 PR-6c slice 4/4.` — `#1939` issue-ref in source, violates no-issue-refs-in-code (PR/commit only; matrix notes/exemptions are the ONLY allowed location). Identical to Swift slice's prior MINOR (ToolSagaTests.swift:5) which was scrubbed at 238c133bd before merge. FIX = drop the `#1939` token (keep §6.2.4/ADR-049 §3a/ADR-026/ADR-028 — those are spec/ADR refs, allowed). Sole #NNNN in added lines outside the matrix (grep-confirmed).

LESSON: every PR-6c saga SDK slice's test-file provenance header re-introduces `#NNNN` — the Swift slice caught+fixed it, Kotlin repeats it. UniFFI SDK slices (Swift/Kotlin) get typed errors → NO string-parse weakness (verify ScpException.Saga* surfaced direct, fields=Rust field names, SagaResult nullable faithful); confirm no generated binding committed (Kotlin) vs committed+faithful (Swift).
