---
name: standing-pair-not-saga-v2-spec-review
description: Completeness review of spec/standing-pair-not-a-saga-v2 (HEAD 43cc189f0) — auto-accept allowlist-only + standing-pair reclassified single-context async; verdict COMPLETE
metadata:
  type: project
---

Reviewed branch `spec/standing-pair-not-a-saga-v2` (HEAD `43cc189f0`), a SPEC-ONLY docs change. Verdict: **COMPLETE**, nothing actionable.

**Why:** Verifying the auto-accept arm removal + standing-pair reclassification was consistent across every artifact surface that referenced the removed arms or the old 3-saga framing.

**How to apply (facts established, durable for future standing-pair / auto-accept work):**
- Auto-accept `TrustRequirement` arms `shared_context` and `discovery_context` were dropped from the SDK-facing surface; `known_did`/`Explicit` is the sole trigger. Updated consistently in §5.12.2 (`05-contexts.md`), `sdk-common.md`, `sketch.md`, `technical-overview.md`. §19's "auto-accept never applies to paid contexts" hard rule is orthogonal and correctly untouched.
- **Live Rust enum** `crates/scp-protocol/src/context/policy.rs` `TrustRequirement` has exactly `Any`, `SharedContext`, `Explicit(Vec<DID>)` — NO `DiscoveryContext` variant ever existed. §5.12.2's spec-leads-code provenance note states this accurately (Any/SharedContext removed downstream; discovery_context "never implemented"). Honest disclosure, not a defect — spec-only scope.
- `crates/scp-runtime/src/context/policy.rs` has TEST FIXTURES using `TrustRequirement::Any`/`SharedContext` (lines ~146-493). These are the actual downstream code-PR reconciliation target; not in spec-PR scope.
- **False-positive traps (unrelated subsystems, do NOT flag):** `DiscoveryMethod::SHARED_CONTEXT`/`shared_context` (provenance enum, python types.py:159, ts provenance.ts, swift sharedContext) mirror `scp_core::provenance::DiscoveryMethod`; `DiscoveryContextVerified` (spec §22 human-readable addressing TrustLevel); `ThresholdRequirement.shared_context_penalty` (§00/§22 trust attestation); `DiscoveryMethod::SharedContext(ContextId)` (§24 provenance, phase-4 ADR, prds main.json). None are the auto-accept TrustRequirement.
- `CreationReceipt` appears in TWO unrelated places: (1) the now-removed standing-pair SAGA scaffolding (flagged superseded in DEFERRED-commit-11 + ADR-049), and (2) `create_context` two-phase-commit atomicity (phase-2.md, builder.rs, prds SCP create_context story) — a DIFFERENT struct, correctly distinct.
- SCP-SAGA error codes ARE registered at 13000-13999 in sdk-common.md (13200-13999 reserved, relabeled "Future cross-context saga families"). ADR-049 §3a updated text matches.
- Standing-pair reclassified saga→single-context async consistently across ADR-049 §3/§3a, DEFERRED-commit-11, §5.15.4, §5.15.8, §9.4.3. Genuine sagas remaining: §6.2.4 (cross-context tool invoke) + §5.14.13 (broadcast hosting). New §3.8.1 (canonical DID form) added in 03-identity.md, referenced correctly by §5.15.8/§5.14.13. Length-prefix derivation now uses §9.5.1 len32 framing.
