---
name: gate-selftest-over-determined
description: A gate self-test that asserts only the exit code, or a label the summary always prints, can pass for the wrong reason; isolate the branch and assert its specific signal
metadata:
  type: feedback
---

A "fails on bad input → exit 1" self-test for an enforcement gate (for example
`scripts/test_check_sdk_coverage.py` against `scripts/check-sdk-coverage.py`) is
over-determined when its synthetic input trips more than one error branch. A test named for
the unmatched-true branch fed an operation with only `"python": True`; the missing-SDK-key
branch also fired, so deleting the unmatched-true branch still left exit code 1.

The first fix moved the problem instead of removing it: it filled the other SDK keys but gave
their exemptions dict values, which tripped the "must be a non-empty string" branch three
times. Its assertion also matched `unmatched true` in stdout, a label the gate's summary
prints on every run, so the assertion matched a passing run too.

**Why:** the self-test is the guarantee behind a protected enforcement file. A test that
passes by coincidence lets the property rot unseen.

**How to apply:**
- Build the synthetic input so the branch under test is the only failing branch; give every
  other required field a benign value of the right type.
- Assert on the error line that branch alone prints, not the exit code alone. When the
  summary always prints a branch's label, `<label> in stdout` never proves the branch fired;
  assert the counter's value (`unmatched true:   1`) or the error text.
- Mutation-check each test: disable the branch it names and confirm the test fails.
- Give each escape hatch and bypass guard its own test (an exemption turning fail into pass,
  the all-exempted guard, false without an exemption).
