# Standing-Pair "Not a Saga" §5.15.8 Round-9 (fd3b2fd2a) — 2026-06-24 — ZERO FINDINGS / SOUND

Branch spec/standing-pair-not-a-saga-v2. HEAD=fd3b2fd2a. Docs-only.
SCOPE NOTE: task framed as "round-8 a0e02ab3b + 2 commits" but a0e02ab3b..HEAD = **4** commits
(5a5f7f275, 522e4a135, 1b105b2b3, fd3b2fd2a). Reviewed full a0e02ab3b..HEAD delta.
Files: 03-identity.md (§3.8.1 NEW), 05-contexts.md (§5.15.8/§5.12.2), 09-security-model.md (§9.18.2),
sketch.md, sdk-common.md. ADR-049/DEFERRED touched only in EARLIER rounds — nothing new in this delta.

## What changed vs round-8 (all STRONGER or honesty-improving)
1. **Length-prefix derived_context_id ADOPTED** (was deferred in r8): preimage now
   SHA-256("standing:" ‖ len32(did_lo) ‖ did_lo ‖ len32(did_hi) ‖ did_hi) per §9.5.1.
   Injectivity now UNCONDITIONAL/by-construction for ANY DID grammar; retires the human
   method-admission gate. Old "would add no security" claim retracted, internally consistent
   (colon-join was sole isolation anchor; saga-cut group_id was saga's id, not co-anchor).
2. **§3.8.1 NEW canonical-DID-string section** — narrowed to BYTE-AGREEMENT (not injectivity;
   that's now len32's job). Honest: canonicalization still load-bearing for agreement (two
   encodings of same logical DID → two distinct preimages even under length-prefix). did:dht
   AIRTIGHT (one z-base-32 form); did:web best-effort at exotic margins (fallback-only, §3.8).
3. **Welcome-receipt mismatch guard (step 4(a0))** — B re-derives id from its OWN canonical
   inputs, rejects on mismatch. RESTORES cross-party agreement check removed saga Prepare gave.
   SOUND, NO new DoS: pure symmetric fn ⇒ honest pair never mismatches; computed from B's own
   inputs vs id Welcome binds; routed through generic consent-reject (leaks nothing). Backstop
   §3.8.1 did:web residual relies on.
4. **Active self-heal channel honesty** — §1871 now states PLAINLY: where attacker=did_lo,
   blocking victim=send-gated did_hi, there's PRESENTLY a durable attacker-refreshable
   decrypt-capable did_lo→did_hi content channel until Phase-2E; close_context does NOT escape
   (deterministic id re-derives). Matches crypto reality.
5. **Receive-side drop-filter (normative SHOULD)** — GENUINELY NEW GROUND + within send-gated
   node's power. KEY: §9.16.7 mandated receive-side destruction covers BLOCKED party purging
   BLOCKER's content; does NOT cover BLOCKER dropping BLOCKED party's INBOUND. Self-heal severance
   (§3.7.1 enumerate+sever) is a SEND (sender-key rotation §9.16.3) ⇒ send-gated did_hi CAN'T do
   it. Drop-filter (refuse to surface/decrypt-deliver locally) needs no key op/SEND ⇒ in-power.
   Honest bound right: receive-but-not-sever in that one pair, no cross-pair, no key exposure.
6. **Anti-spam cost disclosed** — convergence-candidate exemption NOT free: confirm-bound-creator
   still does 1 DID-resolve + sig-verify on forged variant, NOT rate-limited. Bounded: exemption
   precondition = victim already holds self-created group under exact id ⇒ victim self-initiated ⇒
   attacker can't manufacture precondition on arbitrary victim. Gate-decidable, local-only.
7. **§9.3 Sybil self-pair cross-ref** — self-pair guard (canonical-distinct from A's own DID) +
   two-distinct-operator-DIDs MUST NOT earn §9.3 participation credit. Faithful to §9.3 line 227
   "(not self-created)". Closes self-deal credit vector.
8. **§9.18.2 separator row** (fd3b2fd2a) — "colon-join non-§9.5.1" → "§9.5.1 length-prefixed body".

## Provenance — ALL verified grounded (no phantom):
§9.5.1 L338, §3.8.1(new), §9.6.1 L519, §9.7.1 L587 (KeyPackage-sig/DID-VM binding — bound-creator
faithful), §9.3 L227 (not-self-created), §5.12.5 L953 (~0ms/~200ms latency), §3.7.1 L536-558
(enumerate+sever + sender-key rotation side-effect), §9.16.3 L1333 (Block Protocol), §9.16.7 L1385
(receive-side destruction — confirms drop-filter is NEW, not redundant). 522e4a135 "fix §9.3 phantom
cite" landed.

## Existence oracle: value+timing safe (unchanged substance, condensed). Consent bundle ordering
correct: {block-list FIRST → confirm-bound-creator → fresh-join(consumes init key) → destroy} under
actor mutex + generation check. Confused-deputy + replay + forged-creator all caught.

## OBSERVATION (impl program, not a finding): drop-filter SHOULD has no named enforcement; downstream
Phase-2E wiring PR needs pipeline_wiring.rs-class assertion for blocker-side inbound drop.

## GOTCHA: round-8 memory file (standing-pair-...-round8-a0e02ab3b.md) lives in MAIN worktree, NOT this
worktree. Use system-prompt MEMORY.md summary for round-8.
