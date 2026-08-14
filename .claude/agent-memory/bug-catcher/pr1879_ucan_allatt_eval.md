---
name: pr1879-ucan-allatt-eval
description: PR #1879 UCAN all-att ceiling (step 8) + structured evaluate_ucan — bug review CLEAN
metadata:
  type: project
---

# PR #1879 `feat/ucan-all-att-and-structured-eval` (HEAD 63dc89094) — bug review

CLEAN. No bugs found. 3013 scp-protocol tests + 37 ucan_validate_integration pass; clippy clean.

**Why:** ground future re-reviews of this area; the helper-extraction refactor is behavior-preserving and the step-8 tightening is the intended fix.

**How to apply:**
- `validate_ucan` helper extraction (`parse_granted_caps`, `verify_root_issuer`, `verify_audience`) is behavior-preserving — verified line-by-line against origin/main diff. Same checks, same order, same error variants.
- ONLY real behavior change: step 8 ceiling now checks `&granted_caps` (full att set) vs old `std::slice::from_ref(required_capability)`. Intended tightening (spec §7.2.1 step 8 all-attestations). Pinned by new pipeline_wiring.rs structural test `ucan_step8_enforces_ceiling_over_all_att` (ratchet 42→43).
- `evaluate_ucan` runs IDENTICAL checks in IDENTICAL order to `validate_ucan`; only diffs: nonce uses `check_replay` (read-only) not `check_and_record`; `parse_granted_caps` moved into tokens_valid stage (parse failure → tokens_valid:false, vs validate_ucan failing at step 6 — diagnostic-only, both fail-closed, documented).
- 6-field mapping correct: `within_ceiling` requires BOTH step-6 grant-match (inside signatures stage) AND step-8 all-att ceiling. `not_revoked` checks LEAF cid (parent revocation lives in chain → signatures_valid). short-circuit returns NONE (all-false) on first failure.
- roles.rs: `validate_role_definition` runs BEFORE `mint_role_tokens` AND before state mutation on BOTH assign_role (3a) and system_assign_role (2a). No panic/unwrap. Mint-time step-8 counterpart.
- capability.rs change is TEST-ONLY (multi-colon fail-closed test). No prod logic change.
- `evaluate_ucan` has NO production caller yet (tests only) — diagnostic for SDK trust signals, wiring presumably later.

LOW (test coverage, not bugs): no isolated field-mapping test asserting `not_revoked:false` or `time_bounds_valid:false` for evaluate_ucan (only happy-path true + bad-sig + out-of-ceiling). Trivial logic.

GOTCHA confirmed: `extract_fn_body` uses first `find("fn validate_ucan<")`; "validate_ucan" is NOT a substring of "evaluate_ucan" so the structural test correctly isolates validate_ucan's body.
