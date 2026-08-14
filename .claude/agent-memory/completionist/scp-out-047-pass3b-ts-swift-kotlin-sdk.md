---
name: scp-out-047-pass3b-ts-swift-kotlin-sdk
description: SCP-OUT-047 pass 3b (TS/Swift/Kotlin streaming-saga SDK wrappers) COMPLETE @80fbb8272 — both verbs all 3 SDKs, honest artifact-gated Swift/Kotlin deferral, recover-test convention diverges by language error model
metadata:
  type: project
---

SCP-OUT-047 pass 3b verification @80fbb8272 (feat/outlet-xctx-047-streaming-saga-ffi, worktree /Users/alec/Developer/limn/scp-wt-047). VERDICT COMPLETE for pass-3b scope.

10 files, all under bindings/ (TS/Swift/Kotlin src+test). NO matrix/WASM/pipeline_wiring/ffi_conformance/check-*/bridge-alias touched (those are pass 4 / SCP-OUT-048). Story status stays `pending` (correct — gated on remaining ACs).

**Both verbs present all 3 SDKs (grep-confirmed, no language skipped):**
- OPEN (returns lazy handle): TS `SCP.outletInvokeCrossContextStreamingSaga` (scp.ts:2254 → StreamingSagaHandle), Swift `Context.invokeOutletCrossContextStreamingSaga` (Outlets+Streaming.swift:1179 → StreamingSagaHandle actor/AsyncSequence), Kotlin `SCP.outletInvokeCrossContextStreamingSaga` (Scp.kt:1840 → StreamingSagaHandle asFlow()+aggregate()).
- RECOVER: TS `recoverStreamingSagaTruncatedClose` (scp.ts:2313), Swift Context:1244, Kotlin Scp.kt:1895.

**Bridge mirror (no fabrication):** every SDK call maps to a real pass-3a bridge export. NAPI `outletStreamingSagaOpen/PollNext/RecoverTruncatedClose` (scp.rs:3102/3160/3178), positional arg order EXACT match to TS `StreamingSagaNative`. UniFFI `outlet_streaming_saga_open/poll_next/recover_truncated_close` inside `#[uniffi::export(async_runtime="tokio")] impl Scp` (outlet_stream.rs:1834/1894/1919) — Swift/Kotlin `inner.*` chain valid.

**Tests real per language (I ran TS: 17/17 pass + `bun run check` clean + biome lint clean):**
- TS (outlets-streaming-saga.test.ts, mock via `__constructScpWithNativeForTests`+FakeSagaNative): lazy-open, progressive drain, await-aggregate, arg-order-forward, caller-mismatch SagaAborted(13050), UCAN-denial, terminal-error-chunk, seq-gap, abnormal-drop, single-consumer, sync validation, recover forward + SCP-PERM-3001→UcanPermissionError + unknown-saga→ContextError.
- Swift (mock FakeSagaNative actor + GatedSagaNative): lazy, progressive, aggregate, terminal-error, gap(6131), abnormal-drop(6100), open-rejection, single-consumer; recover = bridge-linkage smoke over real in-memory SCP (any typed ScpError proves reach).
- Kotlin (mock FakeSagaNative): same 8 handle tests via asFlow; recover = smoke over real bridge guarded by `assumeTrue(nativeAvailable)`.
- ZERO skip/ignore/disable/todo except the single Kotlin `assumeTrue` (line 354) on the recover smoke test — JUnit5 skip-NOT-pass, guards only the native-requiring test; the 8 handle tests always run.

**Honest gate ruling — Swift/Kotlin CI-deferral is ENVIRONMENTAL, not a dodge:** the whole SCP swift module / scp-kt module depend on UniFFI-generated bindings (Kotlin `uniffi.scp.*`) + dylib/xcframework, so build/test can only run in CI where those artifacts are generated. lint/format/detekt operate on source text → pass locally. No fake green, no #[ignore] dodging a real break.

**LESSON (recover test convention diverges by SDK error model):** Python reference + TS test recover MOCK-DRIVEN incl PERM-3001 translation because those SDKs have a translation layer (TS `mapSagaError` try/catch wraps recover). Swift/Kotlin recover is a direct 1:1 forward to the UniFFI object — typed ScpError/ScpException propagates UNTRANSLATED — so there is nothing to mock-translate; a smoke test (typed error surfaces) is the honest+complete verification. Also: the injectable `StreamingSagaNative` mock seam covers ONLY open+pollNext, NOT recover (recover is a thin method on SCP/Context, not routed through the seam) — so Swift/Kotlin recover is smoke-only by construction. When auditing multi-SDK wrapper parity, do NOT flag missing mock-recover-translation tests as a gap when the SDK has no translation layer; verify the wrapper is 1:1 and the bridge-layer (pass-3a) owns the rejection tests + Rust owns the OUTCOME.
