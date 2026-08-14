---
name: standing-pair-not-a-saga-round9-5a5f7f275
description: Security review of §5.15.8 standing-pair single-context-async, ROUND 9 (5a5f7f275) — simplifier-convergence compression pass; ONE LOW provenance finding (§9.3 over-attribution); all normative guarantees preserved
metadata:
  type: project
---

# §5.15.8 Standing-Pair "Not a Saga" Round-9 (5a5f7f275, spec/standing-pair-not-a-saga-v2) — 2026-06-24

Merge-base f37372b25. HEAD=5a5f7f275. Branch = 11 commits (round-1 77e4738e7 .. round-9 5a5f7f275). Round-8 was a0e02ab3b (verified ZERO-FINDINGS/SOUND in prior memory `standing-pair-not-a-saga-round8-a0e02ab3b.md`).

## What round-9 (5a5f7f275) actually did — DOCS-ONLY, 2 files
The simplifier-convergence compression (CLAUDE.md non-convergence guard, simplifier BLOCKER): §5.15.8 had accreted to 6,819 words over rounds 6-8; this commit compresses to 3,592 (measured 3,574). Touched ONLY 05-contexts.md (§5.15.8) + sdk-common.md (§"Standing contexts"). The OTHER 3 files (ADR-049, DEFERRED-commit-11, 09-security) were edited in EARLIER branch commits (rounds 6-8), already covered.

## Compression-loss check — PASS. All 14 load-bearing invariants survive (python substring check on current §5.15.8):
constant-time-wrt-existence; self-pair guard (peer_did distinct from local_did); not-self-created-by-EITHER; Phase-2E send-gate; no create-vs-found discriminant MUST; hard-floor-1s/60s cooldown; block-list-gate-runs-first; generation/identity check; reaper-refresh-on-ignored-Welcome; atomic-under-per-context-actor-mutex bundle; anti-spam MUST-NOT-throttle carve-out; self-heal-severance-requires-send; did_lo-ignores-did_hi-Welcome; KP-drain bound at did_lo inbound cooldown. Every round-8 clean-reviewed guarantee preserved (compressed, not dropped).

## Independent anchor verification (fork) — 5 of 6 SOUND, 1 LOW finding:
- §9.7.1 bound-creator: SUPPORTED. §9.7.1 gives the KeyPackage-sig→DID-VM binding mechanism; §5.15.8 composes the ==did_lo equality on top. Sound composition.
- §3.7.1 block/sever: FULLY SUPPORTED. Line 537/558: severance = "rotate sender key" = a SEND (§9.16.3). Grounds BLACK-SP-03 self-heal-scope EXACTLY. Line 540 best-effort "executes on next connection" grounds the unobserved-block self-heal. is_globally_blocked exists (545).
- §5.12.3.3: SUPPORTED. publicly-computable invitations routing id SHA-256(len||did||"scp-invitations") (861) grounds BLACK-SP-01; "relay TTL 7 days default" (863) = §5.15.8's welcome_ttl (local name, same value).
- §5.12.2: SUPPORTED. arms shared/known_did/discovery present; "non-overridable" tool deny (752).
- ADR-049 §9 fused-join two-anchor / §10 auto-revive standing-id / Follow-up #1 (line 396: Welcome-joined node DECRYPTs but send fails-closed, unidirectional only): FULLY SUPPORTED. Grounds Send-capability caveat + BLACK-SP-03.

## THE ONE FINDING — LOW (provenance / phantom-provenance), NOT a dropped guarantee:
§5.15.8 L1854 ("§9.3's not-self-created-by-EITHER-party predicate") and §5.12.2 L754 ("mirroring §9.3's '(not self-created)' qualifier") attribute to §9.3 a shared-context STRANGER predicate that §9.3 DOES NOT CONTAIN. §9.3's ONLY "(not self-created)" text (09-security L227) is a CAPACITY-TIER PARTICIPATION-RECORD COUNTING rule ("tier*2 participation records from distinct contexts (not self-created) to advance"), nothing about stranger/auto-accept or "either party". The stranger predicate is fully + correctly SELF-DEFINED in-line at both §5.12.2 L754 and §5.15.8 step-4(b) — so NO guarantee is missing. Fix = soften citation to "in the spirit of §9.3's not-self-created discriminator" or drop "§9.3" and present the predicate as locally-defined. CLAUDE.md explicitly flags phantom-provenance as a bug => LOW, not Observation.

VERDICT: APPROVE. One LOW provenance-tightening (non-blocking for security). Compression preserved every normative guarantee. sdk-common sync faithful. SCP-SAGA 13000-13999 band confirmed registered (sdk-common L45 + check-error-codes.sh L71-73) — ADR-049's "IS registered" claim accurate.
