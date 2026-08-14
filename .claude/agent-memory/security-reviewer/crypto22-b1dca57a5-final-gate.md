---
name: crypto22-b1dca57a5-final-gate
description: CRYPTO-22 final landing artifact b1dca57a5 (2 LOW prose clarifications + main merge + §25.22→25.23 renumber) — CONFIRMED-clean, fail-closed
metadata:
  type: project
---

# CRYPTO-22 FINAL GATE — commit b1dca57a5 (crypto-22-attestation-spec) — 2026-08-02 — CONFIRMED-CLEAN

**FOLLOW-UP commit 161000809 (delta b1dca57a5→161000809) = CONFIRMED-CLEAN, 0 gap.** EXACTLY 1 file / 1 line (+1/-1): §5.9 citation-precision inside the SingleAdmin sentence of the Update-grace bullet, `context-re-creation event (§5.9 migration)` → `(§5.9 governance / §5.11A migration)` — splits the conflated cite so governance semantics point at §5.9, migration/context-re-creation mechanism at §5.11A. Pure documentation-accuracy; no verifier check, field, preimage, Vector 37, Add-vs-Update partition, ≤5-min fail-closed bound, or no-stale-fallback rule touched. Fail-closed posture unchanged. 161000809 inherits b1dca57a5's full clear-to-land; THIS is the landing SHA.

Delta over confirmed round-4 (5d8af939, now amended to spec commit b48dcfa9f) = ONLY 2 things, both verified non-regressing.

**1. Two LOW prose clarifications folded into §9.7.1 "Resolution failure policy" (Update-grace bullet) + mirrored one-liners in ADR-057 Verifier para.** Diff 5d8af939→b48dcfa9f = 2 files, 2 lines. Both prose-only, honesty/precondition additions, ZERO behavior change:
  - (a) governance-Remove precondition: revoking a compromised ADMITTED member via governance Remove "presupposes a governance authority other than the compromised member. In a SingleAdmin context (§5.9) whose sole admin's full MLS state is compromised, no other party can issue the Remove; that is a context-re-creation event (§5.9 migration), not grace-recoverable — compromise of the sole governance authority is game-over regardless." NARROWS the claim, adds no fail-open; the game-over limit was already irreducibly true.
  - (b) rollback-resistance qualifier on the last-known-good retention bound: the §9.10.7 retention bound holds "only under the Rollback-resistance assumption below"; a rollback-capable attacker re-serving equal-`seq` pre-rotation doc under SUSTAINED resolution failure could keep refreshing last-known-good + reset its retention timer, "degrading the effective grace toward MAX_KEYPACKAGE_ATTESTATION_LIFETIME (§9.18.7 — the 84-day backstop is the honest upper bound)"; resolution-layer mitigation = did:dht seq monotonicity §9.6.1 (rejects equal-or-lower-seq once higher seq observed). Honesty about the Update-grace worst case ONLY.
  - Both clarifications: apply to the UPDATE (already-admitted member) grace path ONLY; do NOT touch Add (still fail-closed ≤5min, no stale fallback); do NOT widen the grace mechanism (identical last-known-good-on-FAILURE, override-on-SUCCESS; a success returning rotated key still REJECTS); add NO verifier check, remove none (still 13). Safe-direction: rollback attacker gains only "keep an admitted member's last-known-good doc valid longer" — that member is already in-group, eviction = governance Remove independent of DID resolution, so NO new capability conferred. No fail-open, no downgrade.

**2. Merge with origin/main + §25.22→§25.23 renumber.** Merge b48dcfa9f→b1dca57a5 touched 237 files of unrelated main content (outlet streaming saga, MLS provider #2148, ADR-062 SCPR, SDK parity). Attestation-region impact verified NIL beyond renumber:
  - 25-test-vectors.md: only diff is main INSERTING a new §25.22 (Cross-Context Streaming-Saga Conformance Vectors, SCP-OUT-049) which pushed KeyPackage Attestation vectors to §25.23. Vector 37 BODY (211B preimage, SHA-256, 0xFF03 ext body) BYTE-IDENTICAL (single hunk 937c937,969 = heading swap only, all vector content after unchanged).
  - 09-security-model.md merge hunks @ 478/977/1216/1857: line 478 = §25.22→§25.23 reference in §9.5.2 preimage description (prose ref only); 977/1216/1857 = main's SCPR/metadata-privacy/HKDF-table content, NOT attestation. §9.7.1 13-check verifier list, resolution-failure policy, §9.12 revocation-by-rotation: UNTOUCHED by merge (revocation/9.12/near-immediate grep on merge diff = empty).
  - All §25.23 cross-refs consistent (security-model:481; ADR-057:245,259,269). Zero stale §25.22 attestation reference survives.

VERDICT: fail-closed posture intact — positive-whitelist for prod DIDs, Add resolution-failure=reject/no-stale-fallback, ≤5-min current-key bound, current-key-only, 13-check verifier list. Nothing security-relevant lost/altered in §9.7.1/§9.5.2/§9.12 by the merge. CONFIRMED-clean, 0 fail-closed gap. This is the exact artifact that lands.
