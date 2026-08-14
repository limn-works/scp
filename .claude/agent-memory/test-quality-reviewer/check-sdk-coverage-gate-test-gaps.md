---
name: check-sdk-coverage-gate-test-gaps
description: scripts/test_check_sdk_coverage.py — domain-prefix-only matching (the PR's core fix) has NO regression test; Test 7 uses a symbol that doesn't match the expected candidate
metadata:
  type: project
---

# check-sdk-coverage.py gate self-test gaps (branch fix/sdk-coverage-fail-closed-and-parity, HEAD a2caec4a8)

## RESOLVED at HEAD ae3a4238f (Round 26 re-review 2026-07-15) — all gaps below closed
- HIGH (bare-name-bypass regression): CLOSED by NEW Test 9 `test_bare_name_does_not_satisfy_domain_prefixed_op` — exports only bare `verifiedOpZzz` (NOT `fakeVerifiedOpZzz`), typescript:True, no exemption, asserts exit 1 + "no matching SDK symbol was found". Docstring explicitly claims mutation-robustness (re-adding bare candidates → green). Candidate builder still domain-prefixed-only (verified ~check-sdk-coverage.py:1460 comment "Bare op_name/camel/pascal candidates were removed").
- ALIASES gap: CLOSED by NEW Test 10 `test_aliases_enable_non_standard_symbol_names` — patches `_mod.ALIASES[('Fake','custom_op')]`; WITH alias exit 0, WITHOUT exit 1. Bidirectional, non-vacuous.
- MED (Test 7 lucky-pass): FIXED — now exports `fakeInvalidExemptOpZzz` (correct domain-prefixed candidate) so typescript:True IS statically verified and the ONLY failing property is the invalid exemption format; asserts both `exemptions.python`+"must be a non-empty string" AND `exemptions.kotlin`. Comment corrected.
- Gate self-tests now 13 (was 9): added 2b (missing-SDK-key), 9, 10, 12 (empty-capabilities + missing-capabilities-key floor guard). All 13 pass.
- Round 26 = doc-only change (ADR-053) since Round 25; no code/test delta. VERDICT: APPROVED.

## (historical, HEAD a2caec4a8 — now resolved above)

The headline fix of commit `1679a75ac` is removing the **bare-name bypass** in `_op_implemented` (check-sdk-coverage.py ~1442-1467): the gate now matches a true cell ONLY against domain-prefixed candidates (`domain_snake`, `domain_camel`, `Domain.method`) + explicit ALIASES, never bare `op_name`/camel/pascal. Bare matching previously let ~23 fabricated ops pass via name collision.

## HIGH: no regression test for the bare-name-bypass removal
MUTATION-VERIFIED: re-adding `op_name` + `camel` to the `candidates` list (restoring the exact bypass the PR removed) keeps ALL 9 gate self-tests GREEN. The core security property of the PR is untested against regression.
- Root cause: Test 5 (`test_gate_passes_with_valid_coverage_exemption`) and Test 7 export domain-PREFIXED symbols (`fakeVerifiedOpZzz` = `_to_camel("fake_verified_op_zzz")`), which match under BOTH bare and prefixed logic. No test asserts a *bare* symbol is REJECTED for a true cell.
- Fix: add a test where an op's only present SDK symbol is the bare camel form (e.g. export `verifiedOpZzz` but NOT `fakeVerifiedOpZzz`) for a `typescript: True` cell with no exemption → must exit 1 ("no matching SDK symbol"). Deleting the bare candidates keeps it green; re-adding them turns it RED. That is the missing mutation guard.

## MED: Test 7 symbol does not match the gate's expected candidate (confused/lucky-pass)
`test_gate_fails_on_invalid_false_entry_exemption_reason` exports `invalidExemptOpZzz` for domain=`Fake`/op=`invalid_exempt_op_zzz`, but the gate's domain-prefixed candidate is `fakeInvalidExemptOpZzz` (verified via `_to_camel`). So the `typescript: True` cell is NOT statically verified — it becomes an extra unmatched-true error on top of the intended invalid-exemption errors. The test reaches returncode 1 partly by accident (multiple error paths fire). Comment at line 453 ("Provide a real symbol so python=True is statically verified") is wrong: `python` is False in that matrix; `typescript` is the True cell. Same isolation failure that Test 2 was explicitly rewritten to avoid (see test_check_sdk_coverage.py lines 134-143). Fix: export `fakeInvalidExemptOpZzz` and correct the comment, so the only failing property is the invalid exemption format.

## Verified GOOD (non-vacuous, mutation-checked or branch-isolated)
- Test 2 (`unmatched_true`): explicitly isolated — all 4 SDK keys present, 3 false+exempted, only python-true unmatched can fire. Asserts exact phrase "no matching SDK symbol was found".
- Test 6 (`all_exempted_with_none_verified`): both true cells empty-source, asserts "all SDKs claiming coverage"/"all-exempted".
- Test 8 (`unexpected_cell_value`): string `"true"` → asserts "unexpected cell value"; mutation-robust per its own docstring.
- All asserted error phrases confirmed present in check-sdk-coverage.py (missing SDK key / no matching SDK symbol / all-exempted / unexpected cell value / must be a non-empty string).

## ALIASES table still only transitively covered
~700-line ALIASES table (lines 75-790+) covered only by `test_gate_passes_on_real_matrix`. No test patches `_mod.ALIASES` to prove an alias-only hit passes and a removed alias fails. `_build_wrapper` already supports patching module globals (it patches SDK_PATHS/MATRIX_PATH) — same mechanism works for ALIASES.
