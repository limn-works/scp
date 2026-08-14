---
name: adr062-prerotation-reframe-5482c6917
description: ADR-062 capability-injection docs deliverable — pre-rotation-punt + ZERO-nullifier reframe review at 5482c6917 (branch docs/adr-062-capability-injection)
metadata:
  type: project
---

# ADR-062 Capability-Injection Reframe Review @ `5482c6917` (2026-07-14) — NEEDS DISCUSSION

Branch `docs/adr-062-capability-injection`. Deliverable = ADR-062 + PRD (6 stories 000/001/006/009/010/011) + spec §9.7.4.1 edits + ADR-054 (Proposed). Reviewed against 4 maintainer decisions: (1) pre-rotation realization PUNTED to RFC Discussion #2130, not canonical; ADR-054 stays Proposed; spec §9.7.4.1 keeps only item-3a residence RULE (+3a(c)+at-rest) canonical. (2) ZERO nullifiers in prod, no exceptions. (3) InMemoryPreRotationCustody severed fail-closed (Option B, typed error); Option A rejected→#1553. (4) ADR keeps execute-now core (module split + DHT E1 + four-nullifier severance + G1 + E2/E3/E4).

**Verdict: faithful on all 4 decisions.** Findings are residual scar-tissue + provenance, not divergence.

Findings ranked:
1. [MODERATE] ADR-054:176 "Forward note" still says InMemoryPreRotationCustody must be "compiled-available-but-never-runtime-selected-as-a-server-floor (present-in-binary ≠ runtime-selectable), reconciling with ADR-062's residue framing." ADR-062 no longer has a residue framing — it SEVERS to test-harness-only, ABSENT from shipped binaries. Stale cross-ref / half-applied reframe.
2. [MODERATE] ADR-062:5 header: "the InMemoryPreRotationCustody weld it does not fix is a documented, tracked gap." Contradicts its own decision (E5:17 / §Decision 6): the weld IS severed here; only the real BACKEND is deferred. Residual residue-era phrasing + "documented, tracked gap" wording the decision otherwise rejects.
3. [MEDIUM provenance] Branch does NOT contain PR #2132 (git log HEAD lacks it; it's on origin/main commit 84aa20443). The "standing rule" the ADR/PRD cite ~8x — CLAUDE.md "No dev/test-only stand-ins in production" builder tenet + sdk-common §Stub-and-Placeholder rule text — is absent from this branch's tree. In-branch, the ZERO-nullifier rule cannot be traced to source. Recommend rebase onto current main.
4. [LOW] Citation `docs/no-dev-standins-in-prod` (ADR:5/83/108, PRD:263) names a doc path that does NOT exist even on main. Real home = CLAUDE.md builder tenet + sdk-common.md §Stub and Placeholder Policy (~line 149 on main). Cite real locations.
5. [LOW clarity] spec §9.7.4.1:674 enumerates "approved-methods menu, selection ceremony ... PROPOSED (RFC #2130)" — terms collide with still-canonical item 4 ("Approved custody methods") + item 5 ("SDK presentation"). Per commit 95ae37df5 items 4/5 were intentionally REVERTED to pre-§3a canonical form; only the per-profile *conformance realization* is proposed. Tighten 674 to say "per-profile conformance realization" so base menu/ceremony aren't misread as demoted.

GOTCHA: the "No dev/test-only stand-ins in production" tenet the task told me to read in CLAUDE.md is NOT in the worktree CLAUDE.md (branch predates #2132); it IS on origin/main:26. The Scar-tissue defense IS in worktree CLAUDE.md (lines 192-199).
GOTCHA: spec items 4/5 (menu+ceremony) STAYING canonical is CORRECT (reverted to pre-§3a parent 34d52da16), not a divergence — verified via commit 95ae37df5 message. Only §3a(a)/(b) sub-items removed.
GOTCHA: #2130 404s on gh issues API because it's a Discussion, not an issue — correctly cited as "RFC Discussion #2130", not a finding.
