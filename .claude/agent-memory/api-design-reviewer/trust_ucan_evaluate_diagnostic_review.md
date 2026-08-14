---
name: trust-ucan-evaluate-diagnostic-review
description: Review of ucanEvaluate/ucanValidate/evaluateTrust/participationRecord trust-diagnostic API across 4 SDKs + 3 bridges (branch feat/actor-2c-xctx-tool-saga)
metadata:
  type: project
---

Reviewed the trust-diagnostic public API (branch feat/actor-2c-xctx-tool-saga, HEAD 50c7bad60). Developer-facing SDK surface is APPROVED — strongly consistent across Python/TS/Swift/Kotlin.

**Fact:** Across all four SDKs the shape is identical: `ucanValidate(ctx, token, capability, presentingAgentDid, proofTokens?)` (gate, throws), `ucanEvaluate(ctx, token, presentingAgentDid, capability?, proofTokens?)` (diagnostic, returns 6-bool CapabilityValidation, non-throwing on capability outcomes), `evaluateTrust(ctx, subjectDid, capabilityTokens?)`, `participationRecord(ctx, subjectDid, cachedAttestations?) -> 12-field BehavioralRecord`. BehavioralRecord/CapabilityValidation/CachedAttestation(Envelope/Evidence) all typed; casing consistent within each SDK (Python snake, TS/Swift/Kotlin camel with encode→snake wire). `allValid` (property/free-fn per idiom) carries the same SECURITY "diagnostic-never-authorization" docblock in all four. evaluateTrust resolves contextId from the handle and gets BehavioralRecord computed ONCE in Rust (Supervisor::participation_record) — no client-side re-aggregation.

**Why it matters / recurring pattern:** Two cross-BRIDGE asymmetries (not developer-facing — SDK wrappers paper over them):
1. `presenting_agent_did` is compile-time `String` (required) in UniFFI but `Option<&str>`/`Option<String>` + runtime fail-closed in PyO3/NAPI — for BOTH ucan_validate and ucan_evaluate. Same "UniFFI is the most type-safe bridge; PyO3/WASM/NAPI lean on runtime checks" theme seen in PR #86 / #127 reviews. Recommend PyO3/NAPI adopt required `&str`/`String`.
2. capability⇄presentingAgentDid positional SWAP between validate and evaluate (forced by capability's optionality). Safe via labels/kwargs in Swift/Python/Kotlin; TS is positional-only, but the TS JSDoc explicitly documents the order + rationale + per-param, and validate_did fails fast, so residual risk is a single retry-loop at worst.

**How to apply:** If a future PR touches these bridges, push to unify presenting_agent_did to required `String` across all three bridges (matches the "enforce via type system not runtime" tenet). Don't re-flag the dev-facing API — it's solid.
