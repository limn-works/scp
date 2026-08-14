---
name: pr6c-swift-saga-wrapper-db68e80de
description: PR-6c slice 3/4 (#1939) Swift SDK wrapper for §6.2.4 cross-context tool-invocation saga — ALIGNED at db68e80de
metadata:
  type: project
---

# PR-6c Swift saga wrapper (#1939 slice 3/4) @ db68e80de — ALIGNED

Reviewed `git diff origin/main...HEAD` (5 files +1017/-14): Tools.swift (+88 `Context.invokeToolCrossContextSaga`), Scp.swift (+8 forwarding shim), ScpBindings.swift (regen +646/-10), matrix (saga swift flip), ToolSagaTests.swift (+272).

**Why:** Wraps live UniFFI export `tool_invoke_cross_context_saga` (bridge.rs:12315). 0 blocking findings.

**How to apply (verified contract facts, reusable for Kotlin slice 4/4):**
- UniFFI bridge sig = 9 params: source_handle, target_handle, caller_did, tool_registration_id, input_json, asserted_nonce_hex, timestamp_ms(u64), chain_depth(u8), ucan_proof_id(Option<String>). Swift public API takes `targetContext: Context` + `input: Data`, derives both handles from Context objects (instance-affine, SAFER than caller-asserted strings), converts Data→inputJson String; forwards 9 in order. ✓
- Typed errors: UniFFI generates `ScpError.SagaAborted(msg:code:retryAfterMs:UInt64?)`, `.SagaNeedsRepair(msg:code:sagaId:)`, `.SagaBusy(msg:code:contendedContext:)` (ScpBindings.swift:12179-12230). Wrapper surfaces them DIRECTLY — no string-parse, no re-map (contrast: Python `_saga_terminal_from_bridge`, TS `mapSagaError` MUST re-map because PyO3/napi emit generic exceptions). This is the per-SDK idiom — correct.
- SagaResult (Record): saga_id String, receipt Option<Vec<u8>>→Data?, output Option<Vec<u8>>→Data?. Swift returns generated struct DIRECTLY (no reconstruct; Python/TS rebuild their own SagaResult type). True pass-through, nil preserved, never synthesized. ✓
- Range validation: Swift OMITS it — UInt8/UInt64 enforce u8/u64 by construction. Sound, equivalent to Python/TS SCP-VALID-7002 (needed there because Python int / TS number unbounded + bool-is-int). Doc-comment explains it. ✓
- Guards mirror sibling `invokeToolCrossContext`: state==.active→SCP-CTX-2001, UTF-8→SCP-TOOL-6001 (only hardcoded codes; NO saga code hardcoded). ✓
- Codes: 13050=caller-axis preflight (specific, channel-auth), NeedsRepair=13065, Busy=13066, generic Aborted formatted inline (13050/13062/13067 family). Wrapper hardcodes none. binding doc refs to 13050 are faithful generated bridge-rustdoc.

**Scope check (ucan_evaluate catch-up):** commit 3d3e22934 regenerated binding brings in already-merged `ucanEvaluate`/`CapabilityValidationRecord` UniFFI export (committed file had DRIFTED). Confirmed FAITHFUL generated artifact: 10 deletions = doc reflow + 4 UniFFI checksum-guard updates (checksums prove real regen, not hand-strip). NO idiomatic ucanEvaluate SDK wrapper added (only generated binding). UCAN.evaluate swift matrix exemption UNCHANGED vs origin/main. Matrix diff is saga-only swift flip (false→true, swift exemption removed, kotlin kept). No bridge-aliases.json change in this PR.

**Tests:** receipt/output pass-through + nil; all 3 typed-error shapes incl retry_after None-never-0; CTX-2001 + TOOL-6001 guards; argument forwarding (asserts forwards past source-active guard).

Sibling slices: Python fd353751a (#1954), TS 8213672f5 (#1958). Remaining: Kotlin slice 4/4.

## Re-review @ bc2cd5983 (2026-06-30, +2 commits: 1bf944be1 docs, bc2cd5983 nonce-fix) — STILL ALIGNED, 1 MINOR
Increment over db68e80de: (1) test nonce fixture corrected to 16 bytes `String(repeating:"ab",count:16)`=32hex (was 8B); (2) Throws/param docs completed on wrapper — verified matching bridge surface (SCP-CTX-2001, SCP-TOOL-6001, SCP-TOOL-6002 invalid-JSON, Validation nonce-decode, SCP-PERM-3030 foreign-handle confirmed=PERM_3030 handle-affinity). All db68e80de facts hold.
**MINOR FINDING (missed in prior pass, real per [[no-issue-refs-in-code]]):** new file `ToolSagaTests.swift:5` doc-comment contains `#1939` — violates no-#NNNN-in-source/comments/test-names rule. Drop `#1939` (keep "PR-6c slice 3/4" + spec/ADR). Matrix-JSON #1939 refs are metadata, acceptable. Wrapper/forwarder bodies clean of issue refs.
**Observation:** `testSagaForwardsArgumentsToBridge` honestly documents it's a linkage smoke test, does NOT assert positional fidelity (same-typed callerDid↔toolRegistrationId swap uncaught) — defers to Rust/integration. Reasonable for thin wrapper.
