---
name: pr6c-1939-kotlin-saga-wrapper
description: #1939 PR-6c final slice (4/4) — Kotlin SDK wrapper for §6.2.4 cross-context tool-invocation saga; ALIGNED clean pass
metadata:
  type: project
---

# #1939 PR-6c Kotlin Saga Wrapper @ efe9006c4 (2026-06-30) — ALIGNED

Final slice (4/4) of the §6.2.4 cross-context tool-invocation saga FFI chain (PyO3/UniFFI/NAPI exports + SCP-SAGA taxonomy landed in #105/#116; SDK wrappers Python/TS/Swift merged). This slice adds the Kotlin SDK wrapper. Reviewed `origin/main...efe9006c4` (7 files +616/-5). 0 findings.

**Why:** Closes #1939; flips the last `kotlin:false` matrix cell for `invoke_cross_context_saga`.

**How to apply:** If a future slice touches this op, the contract is: `SCP.toolInvokeCrossContextSaga` (Scp.kt) is a pure expression-body 1:1 forward to `inner.toolInvokeCrossContextSaga` (generated UniFFI), 9 named params in order (sourceHandle, targetHandle, callerDid, toolRegistrationId, inputJson, assertedNonceHex, timestampMs: ULong, chainDepth: UByte, ucanProofId: String?), returns generated `SagaResult` directly (sagaId/receipt?/output? — ByteArray? never synthesized), `suspend` = block-until-terminal, typed `ScpException.Saga{Aborted,NeedsRepair,Busy}` propagate with NO string-parse/re-map. sagaId is supervisor-minted (NOT an input param). NO client guards / NO manual range validation — ULong/UByte enforce u64/u8 bounds, consistent with sibling `toolInvokeCrossContext`.

**Key parity notes verified:**
- Flat `ToolBindings.toolInvokeCrossContextSaga` + `ToolBridge.invokeCrossContextSaga` use Long/Int + return JSON String — this is the documented flat-function scaffold abstraction (CLAUDE.md: "Long handles, JSON strings, does NOT match UniFFI output"), mirrors sibling `toolInvokeCrossContext` exactly. The PRODUCTION ship path is Scp.kt→inner (generated ULong binding), not the flat bridge. Two return types (SagaResult typed vs String JSON) across the two layers is intentional and sibling-consistent — NOT a divergence.
- Per-SDK idiom (not a finding): Swift wrapper has `guard state==.active` + `Data` input; Python validates chain_depth/timestamp reject bool/float (no ULong/UByte in Python); Kotlin handle-based shim has no Context-object state to guard and uses native ULong/UByte. All four take the same 9 logical params, return SagaResult. Consistent with per-sdk-idiom feedback.
- Generated UniFFI binding (uniffi.scp.*) is gitignored+Gradle-regenerated — confirmed NONE committed in diff.
- NO #NNNN in any Kotlin source/comment/test-name this slice adds (grep clean). Matrix flip removed the old `#1939` exemption text + `exemptions` object; new notes list all four wrappers live. Scoped to this one op only.
- Three stub NativeBindings impls (StubNativeBindings, ConformanceStubBindings, TestNativeBindings) all add the override — required since the method joins the `ToolBindings` interface.
- ToolSagaTest.kt (416 lines): SagaResult null pass-through, 3 typed Saga* field carriers, flat-bridge 9-arg forwarding (incl. null ucanProofId→"null"), BridgeException propagation, real-bridge linkage smoke test (honestly documents it does NOT assert per-arg positional fidelity — that lives in Rust/integration).
