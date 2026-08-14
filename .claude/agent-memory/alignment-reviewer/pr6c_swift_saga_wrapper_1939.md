---
name: pr6c-swift-saga-wrapper-1939
description: #1939 PR-6c slice 3/4 Swift SDK wrapper for §6.2.4 cross-context tool saga at bc2cd5983 — ALIGNED, 1 minor issue-ref finding
metadata:
  type: project
---

# PR-6c Slice 3/4 Swift Saga Wrapper @ bc2cd5983 (2026-06-30) — ALIGNED

`Context.invokeToolCrossContextSaga` wraps UniFFI `toolInvokeCrossContextSaga` (§6.2.4 / ADR-049 §3a). Branch worktree pr6c-swift. THREE-dot diff origin/main...HEAD = 5 files (matrix, generated ScpBindings.swift, Scp.swift forwarder, Tools.swift wrapper, ToolSagaTests.swift).

**Why:** #1939 SDK-wrapper slice series; siblings = Python `SCP.tool_invoke_cross_context_saga` + TS `SCP.toolInvokeCrossContextSaga` already merged. Slice 4/4 = Kotlin (remaining, still matrix `false` + exemption).

**How to apply / verified:**
- 9-param order matches generated bridge sig exactly (sourceHandle,targetHandle,callerDid,toolRegistrationId,inputJson,assertedNonceHex,timestampMs,chainDepth,ucanProofId). Context wrapper supplies source=self.handle.
- Typed `ScpError.Saga*` propagate DIRECTLY (no do/catch, no string-parse, no re-map) — UniFFI gives typed errors. SagaNeedsRepair=13065, SagaBusy=13066 fixed; SagaAborted code is DYNAMIC `SCP-SAGA-{n}` (NOT fixed 13050 — that's only a caller-mismatch example in the bridge's own source doc).
- `SagaResult` returned via direct `return try await` — faithful, receipt/output `Data?` never synthesized.
- Guards mirror sibling `invokeToolCrossContext`: state==.active→SCP-CTX-2001, UTF-8→SCP-TOOL-6001. NO manual UInt8/UInt64 range validation — SOUND, type system enforces bounds (equiv to Python/TS SCP-VALID-7002 which is needed only because Python int is unbounded).
- ucan_evaluate/CapabilityValidationRecord in generated ScpBindings.swift = faithful catch-up only; NO idiomatic ucan wrapper added; matrix UCAN.evaluate swift exemption UNCHANGED; bridge-aliases.json untouched. Matrix change = saga row swift false→true + notes/exemption only.
- Doc-comment `- Throws:` matches bridge surface (SCP-PERM-3030 foreign-handle confirmed = PERM_3030 handle-affinity).

**FINDING (minor, real per [[no-issue-refs-in-code]]):** new file `ToolSagaTests.swift:5` doc-comment introduces `#1939`. Rule: no #NNNN in source/comments/test names. Drop it (keep "PR-6c slice 3/4" + spec/ADR). (Matrix JSON #1939 refs are metadata, acceptable.)

**Observation:** `testSagaForwardsArgumentsToBridge` is an honest bridge-linkage smoke test; explicitly documents it does NOT assert per-arg positional fidelity (same-typed swap callerDid↔toolRegistrationId uncaught) — defers that to Rust/integration. Reasonable for a thin wrapper.
