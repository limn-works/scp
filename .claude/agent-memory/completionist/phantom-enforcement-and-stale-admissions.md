---
name: phantom-enforcement-and-stale-admissions
description: Two recurring defect classes in this repo — enforcement that gates nothing, and deferral comments describing conditions that were fixed long ago; how to detect both cheaply
metadata:
  type: feedback
---

Two classes recur across SCP and both pass ordinary review because each artifact is
internally consistent. Hunt them explicitly on every audit.

**Why:** found repeatedly at scale during the 2026-08-08 repo-wide excavation
([[repo-wide-excavation-2026-08-08]]) — 44 stale dead-code allows and at least 5 gates that
enforce nothing. Both actively mislead: an agent reading a stale deferral will re-defer work
that is already done, and a phantom gate creates false confidence in coverage.

**How to apply:**

## Class 1 — enforcement that gates nothing

Never accept a gate's existence as evidence it fires. Verify the binding.
- **Ratchet floors:** compare the constant to the ACTUAL count. `MIN_PARITY_OPERATIONS = 109`
  vs 215 real ops = 106 slack, in a test literally named `..._never_decreases`.
- **Protected files that don't exist:** diff CLAUDE.md's enforcement-file list against
  `git ls-tree -r --name-only origin/main`. `bridge_ratchet_baseline.json` is listed and absent.
- **Gates whose subjects are unreachable:** `check-handle-affinity.sh` names 6 PyO3 handle
  types; no function takes them as params, so the gate inspects nothing.
- **`#![cfg(any())]` on test files:** compiles to nothing while remaining a `[[test]]` target,
  so CI reports the suite green. `git grep -ln 'cfg(any())'` — 3 files, 3,370 LOC.
- **Claims in CLAUDE.md itself:** verify each "CI enforces X" against the workflow. Two were
  false (`validate-prd.py` only in a `.disabled` workflow; ruff `FIX` never selected).

## Class 2 — stale deferral comments

Any comment saying "not yet", "test-only until", "first production consumer is the later PR",
"awaits X" is a CLAIM ABOUT CALLERS. Grep the callers; do not read the comment.
- Trace transitively. `ClassSStateSnapshot`'s allow said "first PRODUCTION consumer is the
  later privatization PR" — but `commit_class_s_restore` calls `.snapshot()` and has 7
  production callers. The mirror was live; the comment was 2 refactors stale.
- Check whether a stated BLOCKER has since landed. Three dark test suites all cite "awaits
  backend injection"; `NodeMlsFactory::with_backends` shipped and is already used elsewhere.
- Watch for files that contradict themselves: `scp-ffi/uniffi/src/runtime.rs:1505` states
  "Every caller now accesses these through `Scp::` methods" while those exact methods carry
  `#[allow(dead_code)]` 400 lines above in the SAME file.
- Two gaps can cancel and hide each other (`supervisor.rs:12999`: metadata keys never converge,
  "inert today" only because metadata-routing publish is also unwired). Report both.

## Delegation corollary

Subagent sweeps get this class wrong in BOTH directions. In this audit one sweep reported 4
dead-code sites as live gaps that caller-tracing disproved (it self-corrected), and another
sent a false citation (`outlet_stream_vectors.json:745` — the file is 185 lines) plus an
undercount ("14 of 14 Swift files on XCTest"; actually 14 of 16, two already on swift-testing).
Re-verify every delegated finding against the code before repeating it.
