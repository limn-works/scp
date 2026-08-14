---
name: standing-pair-not-a-saga-v2-522e4a135
description: Re-review of standing-pair NOT-a-saga reframe v2 at 522e4a135 (branch spec/standing-pair-not-a-saga-v2) — ALIGNED, 2 LOW citation-precision nits only
metadata:
  type: project
---

# Standing-Pair NOT-a-Saga reframe v2 @ `522e4a135` — ALIGNED, ship after 2 trivial LOW nits

Branch `spec/standing-pair-not-a-saga-v2`, HEAD `522e4a135`, merge-base `f37372b25`. DOCS-ONLY, 7 files. SIBLING (not ancestor) of the earlier v2 review at `4dab1f296` and v1 `3a161e640` (`git merge-base --is-ancestor 3a161e640 HEAD` → NOT ancestor — evolved/rebased line).

**Why:** Reclassifies "standing-pair creation" from a cross-context two-phase saga into SINGLE-CONTEXT async creation (1 MLS group, 2 members, symmetric `derived_context_id`; sync = MLS epoch-Commits + Welcome + event-log RFC-6962 layer, NOT a saga journal). Asserts genuine sagas are exactly two: §6.2.4 (cross-context tool invoke), §5.14.13 (broadcast hosting handshake). Adds NEW §3.8.1 (canonical DID string form) as the upstream home for deterministic-derivation input, referenced by §5.15.8 + §5.14.13 (replaces prior dangling "§3" anchor).

**How to apply (verification results — all PASS):**
- §3.8.1 EXISTS (03-identity.md:753); §5.15.8 + §5.14.13 both now cite §3.8.1 and it resolves (replaced prior dangling "§3").
- §9.3 softened framing is now ACCURATE: §5.15.8/§5.12.2 say "mirroring §9.3's (not-self-created) qualifier" / "in the spirit of §9.3's not-self-created discriminator" — they NO LONGER claim §9.3 *defines a stranger predicate*. §9.3:227 genuinely carries "(not self-created)". §9.3 "expensive to sustain" framing matches §9.3 verbatim.
- ADR-049 §3a's reframed claim "SCP-SAGA IS registered (13000-13999)" is TRUE — scripts/check-error-codes.sh:19/71-73 register+validate that band. (v1 had claimed NOT-yet-registered; v2 corrects to match repo reality.)
- sdk-common.md `13200-13999` reserved row changed "Future saga families (e.g. standing-pair handshake)" → "Future cross-context saga families" — this FIXES the v1 LOW (stale standing-pair-handshake example) → 0 carried findings.
- All anchors resolve: §5.12.1/2/3.1/3.3/5/6, §3.7.1, §9.5.1, §9.6.1, §9.7.1, §9.16.3, §6.2.0/0.2, §6.2.4 (in 06-cross-context-communication.md), §5.14.13, §17 (Merkle event log), §5.15. ADR-049 §3/§3a/§9/§10/§Follow-ups all exist.
- §5.15.8 FULLY purged of present-tense saga machinery (only negating "no Prepare/Commit/Abort, no CreationReceipt, no reserve-not-consume, no saga journal"). CreationReceipt/StandingPairCreate survive ONLY in explicitly-superseded/historical blocks in ADR-049 + DEFERRED. Code deletion deferred to a separate code-correctness PR (spec-only, zero non-.docs files).
- `register_standing_context` + `derived_context_id` PRESERVED (5 + 9 occurrences in 05) → surviving cross-refs valid (the v1 NAME-COLLISION / symbol-preservation lesson holds).
- NO surviving "three sagas" anywhere; all standing-pair+saga co-occurrences are negating. NO new `#NNNN` refs (the `#636/#710` in §17 are PRE-EXISTING, untouched). Collision-resolution stays in ACTOR MODEL (per-context mutex + fused-join single-use §9 + bound-creator §9.7.1 + Welcome-freshness) — no saga/cross-actor await reintroduced.
- Artifact-flow respected: §3.8.1 in the IDENTITY spec is the correct upstream home, flowing DOWN to §5.15.8/§5.14.13 (consumers).

**2 LOW citation-precision nits (non-blocking, not phantom provenance):**
1. §5.15.8 cites "the event-log RFC-6962 consistency layer (§17, §5.15)". §5.15 ("Runtime Concurrency Model") governs event-log persistence ORDERING/observers (§5.15.3) but does NOT define RFC-6962 consistency — that lives in §17. §5.15 is a loose but defensible co-cite; tightening to §17-only (or §17 + §5.15.3) is the clean fix.
2. §5.15.8 step-4(b) over-attributes to §5.12.2: it calls it "§5.12.2's first-contact **not-self-created-by-either-party** qualifier" / "neither party is its creator/admin", but the §5.12.2 text added by THIS diff (05:754) says only "not self-created and distinct" — silent on by-which-party. Since §5.15.8 explicitly defers residual ownership to §5.12.2 ("owned and disclosed by §5.12.2"), the "either-party" semantics should be added to §5.12.2's wording rather than attributed to it from §5.15.8. Security argument is sound + self-contained; placement nit only.

LESSON reaffirmed: re-reviewing an evolved branch → FIRST `git merge-base --is-ancestor` to learn it's a sibling not ancestor; grep the COMMITTED tree (`git show <sha>:`), never the diff worktree. When a section says "§X's <qualifier>" verify §X's ACTUAL prose carries that exact qualifier strength, not a strengthened paraphrase.
