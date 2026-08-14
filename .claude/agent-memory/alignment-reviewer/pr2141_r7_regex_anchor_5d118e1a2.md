---
name: pr2141-r7-regex-anchor-5d118e1a2
description: PR #2141 Round-7 final alignment @ 5d118e1a2 — single test-only delta over R6; ALIGNED, all 5 goal points hold
metadata:
  type: project
---

# PR #2141 Round-7 FINAL @ 5d118e1a2 (fix/sdk-coverage-fail-closed-and-parity, /tmp/scp-review-r25, 2026-07-15) — ALIGNED

Delta over R6 (58f6f06b5) = exactly ONE commit: `5d118e1a2 fix(test): anchor _CODES_RETURN_RE to match-arm positions only`. Test-only, 1 file (test_ucan_conformance.py), 9/9 lines = regex + comment.

**The fix (SOUND):** old `_CODES_RETURN_RE = codes::(\w+)` matched illustrative doc-comment mention `codes::PERM_3009` at ucan_errors.rs:114 → sync test `test_every_emitted_code_is_absorbed` asserted `code_values.get("PERM_3009") is not None` → PERM_3009 has NO const in error_codes.rs → HARD-FAIL (CI red). Prior comment's "fail-safe over-coverage" claim (added 5bc56bac1) was FALSE — a spurious match hard-fails, not soft-widens. New regex `=>\s*\{?\s*codes::(\w+)` anchors on `=>` return position: captures only real emitted `PERM_3001` (verified: 7 inline arms lines 55-93 all `=> codes::PERM_3001`), excludes doc comments (114, 28, 107) + test assert (172 `assert_eq!(...codes::PERM_3001)` — no `=>`) + import alias. Verified by re-running both regexes: NEW={PERM_3001}, OLD={PERM_3001,PERM_3009}. PERM_3001→SCP-PERM-3001→"[SCP-PERM-3001]" IS in `_PIPELINE_ABSORBED_CODES` (trust.py:470 closed frozenset) ⇒ test passes AND still catches future arm splits (`=> codes::PERM_3007` captured). Strictly an improvement over broken prior state; not weakening an enforcement assertion (test file NOT in CLAUDE.md enforcement list; the coupling guarantee — every emitted code must be absorbed — is preserved).

**5 goal points re-confirmed at HEAD (unchanged since R6):**
1. Coverage gate check-sdk-coverage.py fail-closed (sys.exit(1) on error, :1250 "safe failure mode") + dunder/private exclusion (:1022).
2. Trust facade fail-closed Py/TS/Swift — verified R5/R6 (Swift TrustEvaluation inits set tokensValid/signaturesValid/withinCeiling/notRevoked=false; Py/TS closed allowlist absorb only [SCP-PERM-3001]).
3. Insecure participation twins DELETED: Swift 23779139f removed 90-line pure-Swift `verifyParticipationRequirements(requirement:profile:)` + Participation types FROM Trust.swift (file remains — holds the separately-reviewed Layer-1 facade lines 1-253, NOT a full-file delete; my initial grep "still exists" was this). Kotlin 7097938f5 removed Participation.kt (127L). Only secure UniFFI-bridged paths remain: ScpBindings.swift:15097 + Scp.kt:1714 both `(profileJson,requirementsJson)→uniffi.scp`. No `func/fun verifyParticipationRequirements` insecure threshold-compare twin anywhere.
4. Test conformance sound — this delta IS the last fix to it; sync test now functional.
5. SCP-302 present in .docs/prds/main.json (multi-att att[0]-only ceiling deferral, filed R4).

**OBS (LOW, non-blocking):** narrowed regex requires const to immediately follow `=>`/`=> {`; a hypothetical future multi-statement block-body arm (`=> { foo(); codes::PERM_3007 }`) would be MISSED by the sync gate. Acceptable bounded narrowing: (a) all current arms single-expression, (b) true exhaustiveness = compiler-enforced match (no `_ =>`) + runtime `all_variants_route_to_perm_3001` value test, (c) sync test is secondary defense-in-depth. Prior form was outright broken so net improvement.

VERDICT: ALIGNED. Zero deviations.
