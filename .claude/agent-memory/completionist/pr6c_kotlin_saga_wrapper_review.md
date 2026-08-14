---
name: pr6c-kotlin-saga-wrapper-review
description: PR-6c slice 4/4 (LAST) Kotlin SDK wrapper for §6.2.4 cross-context tool-invocation saga — COMPLETE, closes #1939
metadata:
  type: project
---

# PR-6c Kotlin saga SDK wrapper (slice 4/4, closes #1939) — COMPLETE

Worktree `pr6c-kotlin` HEAD 7c4575dfc. Three-dot diff = exactly 7 files (== two-dot,
clean rebase). Final slice; Python/TS/Swift already merged.

**Why:** Last layer of the §6.2.4 atomic cross-context tool-invocation saga (ADR-049 §3a)
— the Kotlin SDK wrapper over the already-merged UniFFI bridge export.

**How to apply:** Verdict COMPLETE. Key verification facts for future Kotlin-SDK saga work:
- Two parallel Kotlin paths (established pattern, sibling `toolInvokeCrossContext`):
  (a) typed `SCP.toolInvokeCrossContextSaga` (Scp.kt) → `inner: NativeScp`
  (`import uniffi.scp.Scp as NativeScp`) via NAMED forwarding — positional swap
  structurally impossible; returns generated `SagaResult` directly (faithful, ByteArray?
  receipt/output never synthesized); typed `ScpException.Saga*` propagates with NO re-map
  layer (unlike Python/TS which wrap untyped bridge errors).
  (b) flat coverage path `ToolBindings.toolInvokeCrossContextSaga` (interface) +
  `ToolBridge.invokeCrossContextSaga` (`bridge.ffiCall { bindings... }`, 9 positional args)
  — this is the symbol `check-sdk-coverage.py` recognizes.
- UniFFI export `tool_invoke_cross_context_saga` at `crates/scp-ffi/uniffi/src/bridge.rs:12315`
  returns `Result<SagaResult, ScpError>` (NOT a JSON String like the non-saga sibling) — that's
  why the shim returns typed `SagaResult`, not String. Param-name → camelCase mapping verified
  1:1; `timestamp_ms:u64`→ULong, `chain_depth:u8`→UByte, `ucan_proof_id:Option<String>`→String?.
- THREE (and only three) `NativeBindings` implementors all overridden: ConformanceStubBindings,
  StubNativeBindings (CoroutineBridgeTest), TestNativeBindings (scp-kt-android ScpViewModelTest).
  The `CoroutineBridge.kt:1326 nativeBindings: NativeBindings` hit is a FIELD, not an impl —
  don't miscount it. Missing any override breaks build/android-test compile.
- Positional fidelity: e2e test (real bridge) HONESTLY documents it does NOT assert per-arg
  positional fidelity; that's covered instead by the conformance test's 9-DISTINCT-VALUE
  `lastSagaArgs` assertion on the flat path + compiler-checked named forwarding on the shim.
- Matrix `invoke_cross_context_saga`: kotlin flipped false→true, all four true, `exemptions`
  object REMOVED, notes updated to "All four SDK wrappers are live". No residual false/exemption.
- Clean: no untracked, no committed generated `internal/` (gitignored, build-time), enforcement
  files (check-sdk-coverage.py, bridge-aliases.json, pipeline_wiring.rs, ffi_conformance.rs)
  UNMODIFIED by branch.
- Per-SDK naming differs (Kotlin `SCP.toolInvokeCrossContextSaga` vs Swift
  `Context.invokeToolCrossContextSaga`) — per-SDK idiom, NOT divergence.
