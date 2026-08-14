---
name: pr2141-r6-twin-deletions
description: PR #2141 Round-6 FINAL @ 58f6f06b5 — insecure Swift+Kotlin participation-verifier twins deleted for parity; ALIGNED
metadata:
  type: project
---

# PR #2141 Round-6 FINAL @ 58f6f06b5 (fix/sdk-coverage-fail-closed-and-parity, /tmp/scp-review-r25, 2026-07-15) — ALIGNED

Delta over Round-5 (7c7af56b6) = 4 commits: 14501c98b (swift TrustTests, test-only), 23779139f (swift twin delete), 7097938f5 (kotlin twin delete), 58f6f06b5 (scratch removal).

**Why:** Round-4 FINAL already ALIGNED (see pr2141_r4_final entry). This round removes an insecure-twin coverage-gate ambiguity.

**Verification:**
1. TWIN DELETIONS SERVE PARITY — CONFIRMED. Deleted pure-Swift `verifyParticipationRequirements(requirement:profile:)` (Trust.swift, 90 lines) + pure-Kotlin `verifyParticipationRequirements` free fn (Participation.kt, 127 lines). Both did bare threshold comparison (checkThreshold: total<minimum) with NO signature/freshness/subject-binding/min_contexts. Coverage gate was matching the insecure twin's NAME; deletion forces resolution to Rust-backed UniFFI path. Secure paths CONFIRMED present: Swift ScpBindings.swift:15097 `verifyParticipationRequirements(profileJson:requirementsJson:)`, Kotlin Scp.kt:1714 wrapper delegating to uniffi.scp.verifyParticipationRequirements:1718. Python/TS never had an insecure twin → parity = no language has an insecure path the others lack.
2. NO SCOPE CREEP — CONFIRMED. Non-memory delta = only the 2 twin deletions + Swift TrustTests.swift (+149, test-only, pins Layer-1 all-false convenience-init defaults — directly serves fail-closed goal). Scratch file scratch_trust_old.py (1784 lines) was accidentally committed in 7097938f5 then cleanly removed in 58f6f06b5 (net zero, no longer tracked).
3. SCP-302 TRACKS att[0]-only DEFERRAL — CONFIRMED. main.json: P1/major/pending, blockedBy=[], source real spec §7.2.1 Tier-1 Full UCAN Chain Validation, 11 machine-verifiable ACs (ucan_validate_all_att across PyO3/NAPI/UniFFI bridges + WASM-or-ADR-034-rationale; Py/TS SDK rewire; AC7 withinCeiling true only if every att[i] passes; AC8/9 multi-att att[1]-out-of-ceiling→false tests; AC10 removes limitation comments). validate-prd PASS 13 files/369 stories.
4. GATE CHANGES PRESERVED — CONFIRMED. check-sdk-coverage.py retains private/dunder exclusion (lines 1021/1067/1216/1307) + fail-closed default (line 1250 "the safe failure mode for a fail-closed coverage gate"). 932+/287- vs main = the PR's core purpose, not creep.

**VERDICT: ALIGNED.** Zero deviations. Twin deletions are the correct fix (delete insecure duplicate, not exempt it — matches NEVER-modify-enforcement-to-bypass tenet). Scratch-file round-trip is cosmetic churn, fully reversed.
