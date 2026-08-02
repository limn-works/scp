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

**UPDATE (2026-06-20 re-review of same branch):** the "fix" RELOCATED the over-determination instead of
removing it. `test_gate_fails_on_unmatched_true_entry` now gives all 4 SDK keys (good) BUT sets the three
false SDKs' `exemptions` values to DICT objects `{"reason": "..."}` instead of strings — which trips the
"must be a non-empty string" branch 3×. So 4 independent errors fire again; mutating away the
unmatched-true branch leaves rc=1. Worse, the assertion `"...symbol was found" in out OR "unmatched true"
in out` is VACUOUS: the gate's summary block ALWAYS prints the static label line `unmatched true:   N`,
so the `or` clause matches on every run including a fully-passing one. Net: the test gives ZERO protection
for the branch it names. Verified by mutation (neuter `unmatched_true += 1; errors += 1` → test still
passes). Fix: false-SDK exemptions must be STRING values; assert on a DISCRIMINATING signal — e.g.
`"marked true for python but no matching SDK symbol" in out` (the actual error line, not the summary
label) — and ideally assert the summary counter reads `unmatched true:   1` with the OTHER counters 0.
**LESSON: when a gate's summary always prints a branch's label, `<label> in stdout` is never a valid
proof that the branch fired.** Tests 5/6/7 by contrast are mutation-robust (each fails when its target
branch is disabled).

**UPDATE (2026-06-20, HEAD ed14e6c77 — FIXED & VERIFIED):** the relocation described above is now
genuinely resolved on `fix/sdk-coverage-fail-closed-and-parity`. `test_gate_fails_on_unmatched_true_entry`
gives all 4 SDK keys with the three false cells carrying STRING exemptions, and asserts on the exact
error-branch phrase `"no matching SDK symbol was found"` (NOT the summary label). The test's own comment
(lines 186-188) explicitly notes it avoids the summary label. Mutation-verified at HEAD: neutering
`unmatched_true += 1; errors += 1` → gate returns 0/PASS → test FAILS (correct). Also mutation-verified
tests 6 (all-exempted guard) and 8 (cell-value else-branch) — both fail when their target branch is
disabled. All gate self-tests at this HEAD are sound and discriminating. The earlier "vacuous" critique
is RESOLVED; do not re-flag it on this branch.

**UPDATE (2026-06-22, HEAD 341df72cc — APPROVED):** re-reviewed at current HEAD (docstring-honesty commit
on top of ed14e6c77). All gate self-tests remain sound. Mutation-verified Test 2 (unmatched-true) AND
Test 9 (bare-name-not-prefixed) both fail when the unmatched-true error phrase is mutated; Test 8
(cell-value else) fails when its phrase is mutated. RESIDUAL NIT (non-blocking): Test 6's phrase
assertion is `("all SDKs claiming coverage" in out.lower()) OR ("all-exempted" in out.lower())`. The
FIRST disjunct matches the real error line (1625) and IS discriminating; the SECOND disjunct matches the
always-printed summary label `all-exempted ops: N` (1649) so it is vacuous on its own. Because it's an OR
and the first disjunct fires on the real branch, the test is still mutation-robust via returncode (disabling
the branch → rc 0 → fails). Tidy-up only: drop the `"all-exempted"` disjunct so the assertion is purely
the discriminating error line. Not a blocker.

Related: [[MEMORY]]
