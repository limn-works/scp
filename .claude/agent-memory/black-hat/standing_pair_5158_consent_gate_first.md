---
name: standing-pair-5158-consent-gate-first
description: Confirming pass on §5.15.8 NEW "consent gate runs FIRST in collision atomic sequence" clause — block-listed did_lo cannot force destroy; one disclosure-precision nit
metadata:
  type: project
---

# §5.15.8 consent-gate-first clause (branch spec/standing-pair-not-a-saga-v2 @ a6a2c3ceb)

NEW edit since round-6: paragraph "Consent gate runs FIRST in the collision atomic sequence" (spec line 1842).
Adds consent-gate (block-list mandatory) as FIRST step of atomic `{consent-gate + confirm-creator + fresh-join + destroy}` under per-context actor mutex.

VERDICT: claims HOLD. No undisclosed bypass, no false closure, no new vector. One LOW disclosure-precision nit only.

## Attacks run — all resist
1. **Block-listed did_lo force destroy/join?** Gate reads is_globally_blocked FIRST inside mutex; reject ⇒ no fused-join, no destroy. Block observed at gate-read ⇒ safe. HOLDS.
2. **TOCTOU gate-passes-then-block-lands-before-join?** = DISCLOSED-INHERENT-RESIDUAL of eventually-consistent block-list (§3.7.1 best-effort/propagation). If block lands AFTER gate-read but before destroy, bundle proceeds; but (a) precondition is did_hi ITSELF self-initiated the pair (its own prior consent — self-race, did_lo controls nothing), (b) convergence is to SAME derived_context_id (same pair did_hi opted into, not unrelated group Y), (c) §3.7.1 Tier-1 propagation then enumerates the now-joined standing ctx and severs did_lo (rotate key/destroy cache/delete access key). Self-healing, benign. Spec gestures "(or via a propagation race)".
   - NIT (LOW, disclosure-precision): absolute "can NEVER force destroy" is gate-read-time-conditional in mechanism; a block not yet propagated to did_hi's node at gate-read is not observed. Suggest one clause noting block-list read is point-in-time and a not-yet-propagated block self-heals via §3.7.1 post-join propagation rather than blocking the bundle. NOT a bypass.
3. **Make did_hi appear self-initiated?** NOT forgeable. MLS group state on did_hi's node exists only via local create (self-created) OR Welcome-processing (classified non-self-created per spec). No protocol msg injects "self-created" group remotely. Self-initiation predicate locally-determined. Stranger-satisfied-by-self-init reasoning SOUND: step-1.c create precondition requires peer not-blocked + deliberately named ⇒ non-stranger by construction. HOLDS.
4. **forge/replay/confused-deputy destroy:** unchanged from round-6 (BOUND creator check, live-join init-key freshness, generation/identity check). New clause adds step strictly BEFORE these, weakens nothing. HOLDS.
5. **New ordering hazard from gate-first?** Block-list read = pure no-side-effect read at front of already-held mutex; no new lock edge, no init-key consumed on reject, no orphaning (destroy strictly after successful join; reject ⇒ neither). HOLDS.
6-9. Self-clear 3 arms / oracles / Sybil-drain / injectivity: unchanged from round-6, re-confirmed clean.

## Orphaning check
No path destroys-without-join: destroy strictly after successful fresh-join; gate-reject ⇒ no destroy AND no join; join-fail (replay) ⇒ no destroy. did_hi never ends groupless. HOLDS.

How to apply: §5.15.8 consent-gate-first is settled-clean. If re-reviewed, only the disclosure-precision nit on "never" remains optional. Don't re-litigate the mechanism.
