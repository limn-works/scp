---
name: standing-pair-not-a-saga-v2-review
description: Ship review of spec/standing-pair-not-a-saga-v2 (HEAD 536c6d192) — §5.15.8 standing-pair reclassified saga→single-context-async; precision/honesty edits verdict
metadata:
  type: project
---

# §5.15.8 standing-pair-not-a-saga-v2 — SHIP verdict (2026-06-24)

Branch `spec/standing-pair-not-a-saga-v2`, HEAD `536c6d192`, docs-only. Reviewed FRESH line-by-line.

**Verdict: SHIP.** Revision (536c6d192) precision edits genuinely improved honesty without introducing new over-claims. Verified all load-bearing cross-refs hold against actual files.

**Why:** Reclassifies §5.15.8 standing-pair creation from cross-context saga → single-context async (correct: a 2-member MLS group is ONE context, replica sync is MLS + event-log, no cross-context atomicity). Saga count 3→2 (only §6.2.4 tool-invoke + §5.14.13 broadcast-hosting are real sagas).

**Verified facts (don't re-litigate):**
- Live helper `derive_standing_context_digest` (standing_helpers.rs:62-67) STILL colon-joins `"standing:"||a||":"||b` — spec mandates length-prefixed `len32`. Spec's "no live divergence" claim is TRUE: standing-pair creation path is NotImplemented (`initiate_standing_pair_create` returns NotImplemented, standing.rs:228 / supervisor.rs:4518); helper's only non-test caller is registry-key gen, never a live cross-party derivation. test_standing_pair_context_digest (supervisor.rs:5517) is `#[cfg(test/testing)]`.
- §9.7.1 supports bound-creator check (LeafNode credential=DID, KeyPackage sig verifiable against DID-doc VM). ✓
- §9.3 line 227 has real "(not self-created)" discriminator for participation records — cited precedent is real. ✓
- §5.12.2 (lines 755-758) now covers ALL THREE TrustRequirement arms first-contact disposition (shared_context/discovery_context/known_did). discovery_context self-clear gap genuinely closed. ✓
- InvitationBundle.context_id (§5.12.3.1 line 799) is a creator-asserted String, creator-signed but NOT bound to DID pair — so revised a0 honesty ("malicious A can label bundle with id B derives; a0 is NOT cross-party agreement proof, agreement rests on §9.7.1+MLS") is ACCURATE. ✓
- ADR-049 §3a SCP-SAGA registry claim accurate: sdk-common.md registers 13000-13999, check-error-codes.sh enforces it. Reserved band relabeled "standing-pair handshake"→"Future cross-context saga families." No phantom provenance. ✓

**Disclosed-and-accepted residuals — all genuinely acceptable (not disclosing-its-way-around-a-problem):**
1. did:web DoS dual (§3.8.1) — receive-side a0 guard turns adversarial did:web canon divergence into undiagnosable pairing-denial. Bounded: did:web is fallback-only, did:dht (production) airtight & unaffected.
2. drop-filter SHOULD (§5.15.8 self-heal) — honestly downgraded: suppresses app-surfacing ONLY, MLS still processes traffic (ratchet/resource/presence residual), no mechanical enforcement. Interim until Phase-2E. Honest.
3. anti-spam amplifier — honestly disclosed: convergence-candidate exemption precondition (victim holds self-created group under publicly-computable id) is NOT exotic; any party knowing both DIDs forces 1 un-throttled DID-resolve+sig-verify per Welcome. Bounded CPU-DoS, no fan-out/join/state-change. Honest.

**Only real concern (MEDIUM, not blocking):** §5.15.8 is ~5k words, single massive section. Implementer-followable but dense — step-4(a0) ordering subtlety (a0 subsumes consent gate on convergence path) requires careful reading. Length is cost of honesty here, not padding.
