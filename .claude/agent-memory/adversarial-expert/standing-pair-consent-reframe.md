# Standing-Pair / Auto-Accept Consent Reframe (spec/standing-pair-not-a-saga-v2)

Reviewed 2026-06-24 @ HEAD 43cc189f0 (docs-only). SHIP verdict.

## Auto-accept allowlist-only collapse — verified sound
- §5.12.2 TrustRequirement now `known_did(list)` ONLY. `shared_context`/`discovery_context` arms removed (conflated discoverability/co-membership with trust). No default policy (default-deny). Correct over-correction-free call: co-membership and registry presence ARE NOT trust signals; discovery is how strangers REACH you, not whom you trust.
- Live code (verified): `crates/scp-protocol/src/context/policy.rs` TrustRequirement = {Any, SharedContext, Explicit(Vec<DID>)} — NO Discovery variant (confirms note's "never implemented discovery_context").
- Production decision path: `crates/scp-protocol/src/context/invitation.rs::evaluate_invitation` — auto-accepts ONLY if `policy: Option` is Some; None ⇒ PromptAgent. So **default-deny is ALREADY live behavior** (matches spec "no default").
- Production TrustOracle impls (3 bridges + core trait): `FfiBridgeTrustOracle` (scp-ffi/src/context.rs:1583), napi:4368, uniffi:7546 all `Any => true`. So a configured `from: Any` DOES auto-accept anyone in live code — the real divergence the spec forbids.
- NO `Default` impl for TrustRequirement/AutoAcceptPolicy anywhere. `Any` is opt-in misconfig, NOT a system default. Provenance-note word "default" (line 276) is slightly loose ("silent accept-from-any-identity default") but binding normative text (§5.12.2 security props) is precise. MINOR wording nit, not substantive.

## Spec-leads-code provenance note — HONEST
- §05 line 747 note factually exact: live enum carries Any+SharedContext+Explicit, no discovery_context, removed downstream. Per CLAUDE.md artifact-flow invariant (specs lead code), shipping spec ahead of code is CORRECT process, not a problem. Standing-pair path not yet wired ⇒ no live divergence to reconcile for the derivation change.

## No dangling references
- sketch.md `sharedContext`/`discoveryContext` at 1485/1512/1553/1598 are DataProvenance.discoveryMethod + DiscoveryResult.source — SEPARATE subsystem, correctly untouched. NOT dangling.
- saga-count corrections (3→2) internally consistent across ADR-049/DEFERRED/§5.15.4/§09/§17. §17:970 recovery exception correctly scoped to cross-context tool saga only. §9.18.2 separator entry updated to length-prefixed body.
- All cross-refs resolve (§3.8.1 added this diff, §5.12.5/6, ADR-049 §10/§Follow-ups).

## §5.15.8 (~5k words) implementer-followability
- Has hoisted "Normative contract (implementer summary)" 4-bullet block at top — an implementer CAN build from it. Length-prefix derivation makes injectivity unconditional (retires colon-freedom dependence). Survivor-role/collision-resolution dense but correct.
- Send-gating honest: Welcome-joiner decrypt-but-not-send until Phase-2E; attacker-influenceable collision can push victim onto send-gated path; drop-filter SHOULD (no enforcement) disclosed honestly. Reflected-resolution + un-throttled confirm-bound-creator DoS disclosed honestly.
