---
name: pr6c-swift-saga-wrapper-238c133bd
description: PR-6c slice 3/4 (#1939) Swift SDK wrapper for §6.2.4 cross-context tool-invocation saga UniFFI op — ALIGNED review at 238c133bd
metadata:
  type: project
---

# PR-6c Swift Saga Wrapper @ `238c133bd` (2026-06-30) — ALIGNED

Slice 3/4 of #1939. Three-dot diff origin/main...HEAD, 5 files +1033/-14: matrix (swift flip false→true, swift exemption removed, kotlin retained), generated `ScpBindings.swift` (+656), `Scp.swift` (thin forwarder), `Tools.swift` (idiomatic `Context.invokeToolCrossContextSaga`), `ToolSagaTests.swift` (+279).

**Why:** wraps live UniFFI export `tool_invoke_cross_context_saga` (bridge.rs:12315). 0 blocking findings.

**How to apply (verified contract facts):**
- Bridge param order (9): source_handle, target_handle, caller_did, tool_registration_id, input_json, asserted_nonce_hex, timestamp_ms(u64), chain_depth(u8), ucan_proof_id(Option). Both Scp.swift forwarder + Context method forward in order. ✓
- Typed errors surfaced DIRECTLY (UniFFI generated `ScpError.Saga*`), NO string-parse, NO re-map — Swift differs from Python/TS which wrap untyped errors. Generated cases match doc: SagaAborted(msg,code,retryAfterMs:UInt64?), SagaNeedsRepair(msg,code,sagaId), SagaBusy(msg,code,contendedContext).
- SagaResult faithful pass-through: sagaId String, receipt Data?, output Data? — returned verbatim, tests assert nil pass-through (never synthesized). Sibling invokeToolCrossContext DOES synthesize a ToolInvocationResult; saga correctly does not.
- Mirrors sibling guards: state==.active→SCP-CTX-2001, UTF-8→SCP-TOOL-6001 (wrapper-local). Bridge codes: invalid-JSON→SCP-TOOL-6002, nonce→SCP-VALID-7001, foreign handle (check_handle)→SCP-PERM-3030, NeedsRepair 13065, Busy 13066. Doc-comment Throws block matches.
- NO manual range validation in Swift (UInt8/UInt64 enforce bounds) — CORRECT per-SDK idiom; Python/TS DO manual-validate (no native bounded ints). Doc-comment explains.
- swiftlint function_parameter_count: Scp.swift forwarder (9 params, NO defaults) needs `// swiftlint:disable`; Context method (8 params, 1 default → 7 non-default; ignores_default_parameters defaults true) does not. Internally consistent.
- ucan_evaluate / CapabilityValidationRecord in generated binding = faithful generated-artifact CATCH-UP to already-merged UniFFI export. NOT scope creep: no idiomatic ucanEvaluate wrapper added; matrix UCAN.evaluate (line 1317-1326) swift exemption UNCHANGED ("no idiomatic public wrapper yet — C3c follow-up"). Generated bindings diff introduces ONLY SagaResult+CapabilityValidationRecord structs/converters + 2 gen methods + 3 saga cases.
- No #NNNN in added swift source/comments/test-names (grep empty); matrix #1939 in notes/exemption = allowed exception.

**Observation (out of scope, pre-existing, NOT a PR-6c finding):** sibling `invokeToolCrossContext` doc-comment carries `Story #322` — a pre-existing #NNNN-in-code, untouched by this diff.
