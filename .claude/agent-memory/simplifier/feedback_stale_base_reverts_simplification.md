---
name: stale-base-reverts-merged-enforcement-simplification
description: A branch off a stale base can silently RE-INTRODUCE an over-engineered artifact that a later main commit deleted; on squash-merge this reverts the simplification — check merge-base before approving
metadata:
  type: feedback
---

When reviewing a docs/ADR diff for over-engineering, also check whether the branch is BEHIND main on the relevant enforcement decision. A branch that forked before a "drop the gate / simplify enforcement" commit landed will still describe (and re-add deps for) the deleted artifact — and squash-merging it REVERTS that simplification.

Concrete case (2026-06-19, ADR-051 review): branch HEAD f438acf0f forked at merge-base 1c0ccbc7d, which predates main's `372ea78a3 ... drop the AST gate (#1826)`. #1826 had DELETED scripts/check-owned-identity-did.py (109KB tree-sitter scanner) + removed tree-sitter-rust dev-dep, replacing it with pure compiler enforcement (type system + `#![deny(non_local_definitions)]` + `#![forbid(unsafe_code)]` + a compile_fail doctest), and KEPT the lesson ast-gate-checks-definition-not-name-resolution.md. The stale branch's ADR-049 §5 still asserted the gate as THE enforcement mechanism, re-added the dep, and deleted the lesson. That is the redundant-enforcement BLOCKER class resurrected — would silently revert #1826 on merge.

**Why:** the scanner re-checked, in AST/source-text form, a property the type system already enforces soundly — negative value, and an insider who can edit the gate gains nothing from it. #1826 is the recorded decision; reverting it is a regression.

**How to apply:** before APPROVE on any ADR/spec diff, run `git merge-base --is-ancestor origin/main HEAD`. If NO, enumerate `git log --oneline origin/main ^HEAD -- <touched files>` and check whether any are enforcement-simplification commits (gate drops, scanner deletions, "enforce via compiler" refactors). If so, flag a rebase as a BLOCKER. The project's own merge protocol already says: worktree branches forked before other PRs merge REVERT them on squash — always rebase before merge.

Related: [[adr051-clock-cut]].
