---
name: lesson-counter-tests-leaf-count-proxy
description: checkpoint_events_since tests that count event-log leaves instead of reading the counter cannot fail; prove discrimination by reverting the fix and re-running.
metadata:
  type: feedback
---

A test claiming to verify `checkpoint_events_since` MUST read the counter. Counting
event-log leaves (`entries.len() - baseline`) is a proxy that does **not** discriminate
the counter bug — leaf emission and counter bumping are separate statements, and every
counter bug in this repo so far has been "N leaves appended, counter bumped by fewer."

**Why:** On PR #2234 all 5 new `*_counter` integration tests passed with the counter fix
fully reverted (verified empirically — reverted the `broadcast_helpers.rs` bumps to main's
behavior, tests still green). ~620 test lines with zero regression value against the bug
they were written for. The in-memory event log also never fails, so no test reaches the
partial-failure path that motivated the inline-bump reshape at all.

**How to apply:**
- When reviewing a test that names an internal counter/accumulator in its assertion
  message, check whether the assertion actually *reads* that counter. If it reads a
  correlated observable instead, flag it — the correlation is exactly what the bug breaks.
- To prove a test discriminates: create a worktree at the PR commit, revert **only** the
  production fix (keep the tests), and re-run. Green = the test cannot fail. This is cheap
  and decisive; prefer it over arguing from inspection.
- If the counter has no read seam for tests, that missing seam is the finding — adding a
  `testing`-gated getter is smaller and higher-value than more proxy tests.

Related: [[project-commit12-helpers-logic-split]]
