---
name: sdk-coverage-failclosed-parity-62bbf8e41
description: Alignment re-review @ 62bbf8e41 — WASM PERM-3000→3001 HIGH RESOLVED; NEW HIGH: TS validates all att[i] (AND-intersect), Python regressed to att[0]-only — cross-SDK divergence
metadata:
  type: project
---

Re-review of `fix/sdk-coverage-fail-closed-and-parity` @ `62bbf8e41` (2026-06-22). New HEAD over c0bee8d22. PR #1867.

**Verdict: NEEDS DISCUSSION** — prior HIGH resolved, one NEW HIGH (cross-SDK divergence).

**RESOLVED (prior HIGH from c0bee8d22): WASM ucan_validate now emits PERM-3001.**
- `crates/scp-ffi/wasm/src/ucan.rs`: `run_validate_ucan` return type changed `Result<(),String>` → `Result<(),UcanError>`. Both `ucan_validate` error maps (cap-URI parse + run_validate_ucan) now route through `scp_ffi_common::ucan_errors::ucan_error_code(&e)` → PERM_3001, matching NAPI/PyO3/UniFFI. Verified ucan_error_code is exhaustive-match, every variant→PERM_3001.
- WASM ucan_mint/ucan_delegate KEEP PERM_3000 (lines 511/538) — correct, that's the ADR-034 JS-side-custody-required path documented in sdk-common.md:148. Validate path ≠ mint path; no contradiction.
- TS validateOneCapUri now absorbs ONLY [SCP-PERM-3001]; WASM validate failures now land there. evaluateTrust no longer throws on WASM common case.

**NEW HIGH — TS and Python diverge on multi-att validation:**
- TS `evaluateLayer1` (trust.ts): iterates ALL capUris, AND-intersects per-URI verdicts via `intersectCapabilityValidation`. Catches att[1] ceiling violation → withinCeiling:false. JSDoc accurately says so. Deleted `__extractCapabilityUri` (clean, no dangling refs).
- Python `evaluate_trust` (trust.py:836): REGRESSED to `cap_uri = cap_uris[0]` — att[0] ONLY. Comment: "Full multi-att... not yet implemented."
- Same multi-att token, att[1] out-of-ceiling: TS→withinCeiling:false (correct per §7.2.1 step 8), Python→withinCeiling:true (the exact false-positive prior code prevented).
- Tests CEMENT the divergence: py test_multi_att_token_evaluates_att0_only asserts `uris_seen==["...read"]`, `admin not in`; TS asserts ucanValidate called 2x both att sent. Tests lock opposite behaviors instead of catching drift.
- Violates agent-first tenet "identical shape across all bindings" + the lockstep rule in the very lesson file this PR edits (ucan-validate-needs-real-capability-uri.md). AND-intersect IS spec-correct (§7.2.1 step 8 per-capability ceiling); Python should match TS, not regress.

**OBSERVATION (LOW) — WASM infra errors now absorbed as all-false:**
- run_validate_ucan wraps manager state-lookup/nonce-writeback failures in `UcanError::MalformedToken(...)` → PERM_3001 → TS classifier matches "malformed token:" prefix → token_parse category → __PASSED_BEFORE empty → all-false verdict. Previously PERM_3000 → re-thrown fault. Shift from "fault" to "all-false." Fail-closed (safe direction) and these fire mainly on unknown-context-id (legit untrusted outcome), but MalformedToken is a slight misnomer for infra/state errors. Acceptable; note for honesty.

**ALIGNED:**
- #4 UcanPermissionError canonical: matches sdk-common.md taxonomy; phase-3.md/scaffold/typescript.md stale PermissionError refs corrected. Aligned.
- #5 ADR-053 pre-rotation custody: Status Proposed, Phase 6, docs-only, artifact-flow clean (cites §9.7.4.1 §3-§5, §9.12, ADR-003 §4b/021/025). Internally consistent; open-questions appropriate for Proposed. Aligned.
- sketch.md CapabilityValidation now lists all 6 fields (added nonceValid/timeBoundsValid) — honesty improvement.
- REVOCATION_PREFIXES gained "revocation unauthorized:"/"revocation failed:" in BOTH TS+py lockstep — good.
