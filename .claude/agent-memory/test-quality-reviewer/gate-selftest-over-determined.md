---
name: gate-selftest-over-determined
description: Gate/validator self-tests that assert only exit-code can pass for the wrong reason; pin the specific signal
metadata:
  type: feedback
---

When reviewing self-tests for an enforcement gate (e.g. `scripts/test_check_sdk_coverage.py`
against `scripts/check-sdk-coverage.py`), a "fails on bad input → exit 1" test is **over-determined**
if the synthetic input trips *multiple independent* error branches.

Concrete case (fix/sdk-coverage-fail-closed-and-parity): `test_gate_fails_on_unmatched_true_entry`
fed a matrix op with only `"python": True`. The gate also errors on *missing SDK keys*
(typescript/kotlin/swift absent) — so the run produced 4 errors, only 1 from the unmatched-true
path the test names. Asserting only `returncode == 1` + `"ERROR" in stdout` would still pass if the
unmatched-true branch were deleted entirely.

**Why:** the self-test IS the guarantee for a CLAUDE.md-protected enforcement file. A coincidental
pass means the property can silently rot.

**How to apply:** for any validator self-test, (a) construct the synthetic input so the branch under
test is the ONLY failing branch (fill all other required keys with benign values), and (b) assert on
the *specific* signal (a counter line like `unmatched true:   1`, or the exact error string), not just
the exit code. Also check the gate's escape-hatch / bypass-guard branches have their own tests
(coverage_exemptions flipping fail→pass; all-exempted guard; false-without-exemption).

Related: [[MEMORY]]
