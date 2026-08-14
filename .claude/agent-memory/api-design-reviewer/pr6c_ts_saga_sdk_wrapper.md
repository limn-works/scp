---
name: pr6c-ts-saga-sdk-wrapper
description: APPROVED — PR-6c TS SDK wrapper for §6.2.4 cross-context saga; parity with Python sibling + NAPI Display
metadata:
  type: project
---

# PR-6c TS saga SDK wrapper (worktree pr6c-ts @9fd9e1427)

APPROVED, no blockers (re-reviewed 2026-06-29). Adds `SCP.toolInvokeCrossContextSaga(sourceHandle, targetHandle, callerDid, toolRegistrationId, inputJson, assertedNonceHex, timestampMs:bigint, chainDepth:number, ucanProofId?): Promise<SagaResult>` + 3 typed errors extending ToolError + SagaResult interface + mapSagaError.

**Why approved:** Faithful mirror of merged Python slice (bindings/python/scp_sdk) + NAPI Rust Display (napi/src/error.rs:115-170).
- Param order identical to Python 9-arg shape. sourceHandle/targetHandle ≙ caller/target_context_id (handle bridge idiom; existing sync toolInvokeCrossContext scp.ts:1716 already uses source/target), inputJson:string ≙ input:dict (NAPI vs PyO3 idiom) — NOT divergence.
- Codes 13067/13065/13066 match Python defaults AND Rust variants.
- retry never 0: null|\d+ ⇒ null mapping reproduces Rust map_or_else null render.
- Nullable result faithful: receipt/output `?? null`, never synthesized.
- mapSagaError anchoring: start-anchored code, phrase anchored after prefix, end-anchored datum `\)\s*$` — decoy-resistant reverse of single-string napi::Error collapse. Unknown-phrase → ToolError fallback (no drop).
- bigint for u64 timestampMs = lossless misuse resistance; chainDepth Number.isInteger 0..255; both SCP-VALID-7002 (parity).

**How to apply:** This completes the per-SDK idiom pattern — handle/JSON-string params are NAPI-bridge-correct, not parity violations. Same structure as [[pr6c_py_saga_sdk_wrapper]] and TS round at [[pr6c_ts_saga_sdk_wrapper]] (this is a re-review).

**Minor observations (non-blocking):** retryAfterMs parsed via Number() narrows u64→number (lossy >2^53, irrelevant for ms backoff; Python keeps int); validation order inverted vs Python (timestamp-first vs chain_depth-first, cosmetic); pre-existing sync sibling uses invokerDid where saga correctly uses callerDid.
