---
name: adr062-capinject-rebuild-71659b057
description: ADR-062 capability-injection rebuild review — artifact-flow (ADR-054 Proposed dependency) + scar-tissue (residue carve-out reverted); NEEDS DISCUSSION, 1 flow-inversion + 1 un-encoded prerequisite
metadata:
  type: project
---

# ADR-062 capability-injection rebuild @ 71659b057 (docs/adr-062-capability-injection, worktree agent-ae0cddf9d3653e5ef, 2026-07-13) — NEEDS DISCUSSION

Verdict: substance + reframe faithful; 2 real artifact-flow findings gate CAPINJECT-002 code. Slices 0/1 ALIGNED; Slice 2 (and transitively Slice 3) blocked on ADR-054 acceptance.

**Files:** ADR-062-capability-injection-and-prove-absent-dev-backends.md + adr062-capability-injection.json (4 stories CAPINJECT-000/001/002/003). Neither on origin/main (new on branch). Branch reverts a prior "residue reframe" trio (ae4b9fd8d/46aa0751c/b4831f1ba revert the fold; 1ab46c8cd/71659b057 rebuild).

**Upstream:** §17.17 (SCP-CAPSEL-8000..8013) authored on THIS branch (absent origin/main) — spec-leads-ADR within the PR, OK. ADR-054 (pre-rotation seam) is SEPARATE, PRE-EXISTING, byte-identical branch vs origin/main → still Status: Proposed, Q1 resolved-by-ADR-055, Q2 (backend minimum) + Q3 (§9.7.4.1 callback-custody clause?) OPEN.

**PRIMARY / artifact-flow:**
- Q1: ADR-062 may be AUTHORED/Accepted citing ADR-054, and Slices 0/1/3(non-002 parts) don't touch ADR-054. But CAPINJECT-002 CODE cannot begin until ADR-054 is ACCEPTED (Q2+Q3 closed). Proposed≠authoritative; a downstream grounded in an unaccepted upstream = phantom provenance if acceptance changes the seam.
- Q2 INVERSION (finding, MODERATE flow): ADR-062 §Decision 4 self-contradicts in one sentence — "does not re-decide ADR-054's open questions" THEN "resolving ADR-054 Q2's backend minimum toward: encrypted-offline is the mandatory cross-platform floor." Declaring encrypted-offline the *mandatory floor* answers Q2 (upstream normative Q) from downstream. Scheduling "implement encrypted-offline first in Slice 2" IS legitimate downstream; declaring it the mandatory floor is NOT. Fix: amend ADR-054 to close Q2, move to Accepted, then ADR-062 cites the closed decision.
- Q3 prerequisite (finding, MODERATE): correctly identified in PROSE (§Decision 4 prerequisite, Residual #3, PRD description "PREREQUISITE" + action-item-1 + details.prerequisite) but (a) ADR names ONLY Q3 as blocker — omits that ADR-054 must reach Accepted and that Q2 must be resolved upstream; (b) NOT machine-encoded: CAPINJECT-002 blockedBy=["SCP-CAPINJECT-000"] only, status "pending". blockedBy takes story-IDs only so ADR-054-acceptance can't be a literal entry — but then it must be surfaced harder (status "blocked", or a gate-level prereq). As-is, topological execution by blockedBy unblocks Slice-2 code once Slice-0 lands, while ADR-054 still Proposed → exact phantom-provenance risk.
- Correct chain before CAPINJECT-002 code: (1) amend ADR-054 to resolve Q2 (encrypted-offline mandatory floor, hardware additive) — moves the decision upstream; (2) resolve ADR-054 Q3, land §9.7.4.1 callback-custody clause spec-first IF needed; (3) ADR-054 Proposed→Accepted; (4) THEN CAPINJECT-002 cites accepted ADR-054 + any new clause. Slice 3 transitively waits (blockedBy 002) — inherent, correctly modeled.

**SECONDARY / scar-tissue (all mostly clean):**
- No-residue CONFIRMED: §17.17.2 SCP-CAPSEL-8012 has NO backend-pending exception; the 2-line carve-out (5eb5ca71) was reverted by b4831f1ba. All ADR "residue" mentions are rejected-alternative / "no residue" framing. Spec §17 other "exception" hits unrelated (ProtocolRepository, saga recovery). CLEAN.
- Goals faithful: E1 fixed (Slice 1 production-dht unconditional + fail-closed DhtInitError), prove-absent (8012 + G1 positive-whitelist gate), research-validated design (Ecosystem convention: rustls danger/webauthn-rs/OWASP/OpenMLS-MemoryStorage/Signal-SVR → durability-vs-nullifier line). CLEAN.
- #1733 fold (LOW): legitimate as administrative fold (issue→PRD AC-map), but closed in the Slice-0 story while goals 3/4(=G1)/pre-rotation-row complete only in Slices 2/3 → premature-close optics. Prefer closing when Slice 3/G1 lands; close comment must span the full AC-map.
- Device attestation "capability absent until ADR-025" (OBS, CLEAN — NOT a hidden deferral): distinct from pre-rotation. Pre-rotation = real backend buildable now (ADR-054 + encrypted-offline) → build it. Device attestation = no real backend buildable (ADR-025 App Attest/hardware) → capability absent/Unsupported (fail-loud), nullifier removed. No dependency on ADR-025's unresolved design (declines the capability, doesn't build on it). Current shipped "capability" is InMemoryDeviceAttestation=always-valid = a fraud, so no REAL capability lost. Consequence to note: contexts whose admission policy mandates device attestation (§9.3 evaluate_sybil_resistance, §22:1251) can't be satisfied by shipped SDK until ADR-025 — but that "feature" today is fake-valid, so removal is a security win not a regression.
