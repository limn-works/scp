# Standing-Pair "Not a Saga" v2 — allowlist-only auto-accept (43cc189f0) — 2026-06-24

Branch spec/standing-pair-not-a-saga-v2, HEAD 43cc189f0, base f37372b25. Docs-only.
Successor to round-8 a0e02ab3b. Two new commits on top: 40d96d1b1 (allowlist-only) + 43cc189f0 (provenance note).

## HEADLINE CHANGE: auto-accept is ALLOWLIST-ONLY (§5.12.2)
- TrustRequirement arms `shared_context` + `discovery_context` REMOVED from spec; only `known_did(list)` / `Explicit(Vec<DID>)` survives.
- Closes discovery_context Sybil-confederate self-clear BY CONSTRUCTION (candidate can't add self to evaluator's allowlist; no self-clear path).
- No-default = default-deny normative (absent policy → prompt human). MATCHES LIVE CODE: evaluate_invitation `policy: Option` None→PromptAgent step 4 (invitation.rs:259,294).
- tool/paid hard-rules retained as closed-form positive checks (has_tool_capabilities, requires_payment, auto_accept_allowed in policy.rs:98-140). Sound, no weak signal.

## FINDING (LOW/observation): provenance note under-states live divergence — WASM 2nd copy
- §5.12.2 provenance note (05-contexts.md:747) names ONLY `scp-protocol context::policy` as carrying `Any`/`SharedContext`.
- BUT crates/scp-ffi/wasm/src/context.rs:2453 check_trust is a SEPARATE reimplementation with its OWN `Some("Any")=>true` + `Some("SharedContext")` arms (ADR-034 WASM can't dep scp-core).
- Downstream code-correctness PR MUST remove Any/SharedContext in BOTH places (scp-protocol enum+invitation.rs satisfies_trust:333-335 AND wasm check_trust:2459-2465) or WASM silently retains accept-from-anyone. Recurring WASM-divergence class.
- Provenance #4 claim itself ACCURATE+not phantom: live `Any=>true` real (policy.rs:22-30, invitation.rs:333).

## SWEEP RESULT: no sibling silent-default / infer-trust-from-weak-signal found
- shared_context/discovery_context residual greps all in UNRELATED subsystems (§24 provenance source attribution, §22 DiscoveryContextVerified addressing trust level, §00 threshold-independence penalty, sketch.md:1485 discovery_method provenance type). NOT auto-accept arms.
- No alternate auto-accept entry point bypassing evaluate_invitation pipeline.
- existence-oracle (value+timing constant-time), block gate (consent-on-receipt, no sync reply oracle), KeyPackage no-drain (single-use at join, did_lo ignore-rule), length-prefix injectivity, mismatch-guard (a0 re-derive) — ALL still sound, unchanged from round-8.

## VERDICT: allowlist-only model airtight at spec layer. One LOW: extend provenance note to name WASM check_trust as 2nd removal site (completeness of the spec-leads-code disclosure, not a spec defect).
