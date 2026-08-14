---
name: pr6c-ts-saga-wrapper-review
description: PR-6c slice 2/4 TypeScript SDK wrapper for toolInvokeCrossContextSaga §6.2.4 — COMPLETE review at worktree pr6c-ts HEAD 6e8f6ebda
metadata:
  type: project
---

PR-6c slice 2/4 (TypeScript) @6e8f6ebda: TS SDK wrapper `SCP.toolInvokeCrossContextSaga` for NAPI `toolInvokeCrossContextSaga` (§6.2.4 / ADR-049 §3a). Verdict COMPLETE.

**Why:** continues the per-SDK wrapper rollout after slice 1 (Python, merged — see [[pr6c_py_saga_wrapper_review]]). Kotlin/Swift remain deferred to #1939 (matrix cells false WITH exemptions — in-scope-correct, not a gap).

**How to apply (verified facts for future PR-6c work / #1939):**
- Native NAPI signature (scp.rs:2933) = 9 args in order: source_handle, target_handle, caller_did, tool_registration_id, input_json(String, not dict), asserted_nonce_hex, timestamp_ms(BigInt), chain_depth(u8), ucan_proof_id(Option). TS wrapper forwards ALL 9 verbatim — none dropped/hardcoded; 9-arg test uses 4 distinct same-typed strings so a swap is caught.
- NapiSagaResult = {saga_id, receipt:Option<Buffer>, output:Option<Buffer>} → camelCase. TS `SagaResult` maps `receipt ?? null`, `output ?? null` (faithful pass-through, no synthesis); tests cover happy + receipt-null + output-null.
- Error path: NAPI collapses typed SagaError to ONE Error Display string (error.rs:114-170). TS `mapSagaError` reverses it: start-anchored code `/^\s*\[(SCP-SAGA-\d+)\]/` (codes are purely numeric, dynamic for Aborted), prefix-anchored phrase dispatch (aborted|needs repair|busy), end-anchored datum regexes (last-anchored, decoy-proof). Non-SCP-SAGA → mapBridgeError. This is per-bridge idiom (Python uses name-based dispatch — both correct).
- Validation parity with Python: chainDepth integer 0..255, timestampMs non-negative bigint, code SCP-VALID-7002, fail-fast before native dispatch.
- Bridge interface + createNativeBridge adapter both declare/implement the method — NOT called by any consumer, but that exactly matches the sibling `toolInvokeCrossContext` Bridge method (tool family's public path goes direct via `this.#native`; Bridge tool methods are parity stubs). NOT an unwired-code finding.
- check-sdk-coverage.py / pipeline_wiring / bridge-aliases UNMODIFIED. Matrix: ts→true, ts exemption removed, kotlin/swift kept false+exemption, notes updated.
