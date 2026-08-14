---
name: pr-sdk-coverage-fail-closed-parity
description: Alignment review of fix/sdk-coverage-fail-closed-and-parity @ f6caeb5dd — gate fail-closed hardening + cross-SDK parity + ADR-051; verdict ALIGNED w/ 1 MED spec mis-citation
metadata:
  type: project
---

# fix/sdk-coverage-fail-closed-and-parity @ f6caeb5dd (2026-06-20) — ALIGNED

5 commits: (1) MlsCryptoProvider doc-comment fixes (inherent methods, ADR-049 actor not ContextManager mutex — accurate); (2) cross-SDK parity (5 TS identity methods, trust eval, Python economy_verify_payment_receipts, discover_contexts); (3) check-sdk-coverage.py fail-closed (endswith removed, all-exempted check, ALIASES fold); (4) ADR-051 pre-rotation custody substrate isolation (Proposed); (5) fix-commit (9 review findings: identityMigrate NEW-DID semantics, discover_contexts rename, non-tautological trust tests).

**Verdict ALIGNED, ship after 2 citation fixes. 0 blocking.**

## Findings
- **MED (introduced by this PR):** TS `trust.ts:92,:392` cite "(spec §9.3, ADR-017)" for the four-layer trust model. WRONG — §9.3 is Sybil Resistance (THREE-layer: earned capacity / social-economic cost / context thresholds). Four-layer model is spec **§7**: §7.2 L1 Protocol Enforcement, §7.3 L2 Participation Validation, §7.4 L3 Attestation Authenticity, §7.5 L4 Trust Evaluation. Base 0c8f0b065 trust.ts had NO "9.3" → newly introduced. The Python SDK it claims to mirror correctly cites §7.3.2.1, never §9.3 → citation also diverges from reference SDK. Fix: §9.3 → §7.2–7.5.
- **LOW:** identityMigrate doc (identity.ts rotationEventJson getter + scp.ts) cites "spec §3.2.1 step 4b" — non-existent. §3.2.1 case 2 (new-DID migration) is PROSE-ONLY, no enumerated steps; steps 1-5 belong to case 1 (same-DID Active Signing Key), step 4 = attestation transfer. Obligation itself correct (DidRotationEvent to active contexts per §3.2.1 case 2) but "step 4b"/"routing tables" fabricated. Fix: cite "§3.2.1 (Identity Key migration)/ADR-003 §4b".
- **LOW (pre-existing):** `#1531` issue-ref in trust.ts:56 source — violates no-issue-refs-in-code; in touched code, strip while here.
- INFORMATIONAL: Python `discover_contexts(query)` free-fn vs TS `discoverContexts(scp,query)` instance-bound — "mirrors" overstates; per-SDK idiom OK, spec mandates no canonical name.

## Reusable patterns
- **Gate all-exempted check is the canonical bounded-enforcement shape:** `op_true_sdks and not op_verified_sdks and set(op_exempted_sdks)==set(op_true_sdks)` → hard fail. Requires ≥1 statically-verified anchor before honoring any prose coverage_exemptions. Prevents the "unbounded prose bypass / one-more-spelling denylist" non-convergence CLAUDE.md warns about. Positive/bounded/convergent — cite as a good example.
- **ADR-051 = model artifact-flow discipline:** documents a self-admitted §9.7.4.1 substrate-isolation gap (InMemoryPreRotationCustody on callback path) as Proposed ADR with open questions + "spec change lands before code" posture, rather than silently shipping. Correctly Proposed not Accepted; nothing in PR implements it.
- **Spec-citation verification method:** when SDK A claims to "mirror" SDK B, check B's citation too — divergence (B cites §7.3.2.1, A cites §9.3) is a fast tell that A's citation is the error. The reference bridge (PyO3/Python) is usually right.
- Trust four-layer model = spec §7 (§7.2-7.5). Sybil resistance = §9.3 (three-layer). Easy to conflate; they are different subsystems.
