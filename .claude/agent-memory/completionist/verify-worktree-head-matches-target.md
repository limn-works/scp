---
name: verify-worktree-head-matches-target
description: Before reading files in a PR/commit re-review, confirm the worktree HEAD equals the stated target SHA — it often does not
metadata:
  type: feedback
---

When asked to re-review a specific commit range (e.g. "verify PR-3 at HEAD `21a93a88e`, base `5752cd50a`"), do NOT assume the worktree's checked-out files are that tree. Verify FIRST with `git rev-parse HEAD` and `git merge-base --is-ancestor <base> HEAD`.

**Why:** In the ADR-049 PR-3 TTL re-review, the worktree was detached at `1620de983` (a parallel ceiling branch) while the review target was `21a93a88e` on a different line. Reading the worktree files showed `on_ttl_tick` as a no-op, no `reconcile_timers`, and `ttl_remaining_secs` everywhere — which looked like a massive ADR-vs-code divergence (phantom provenance). It was entirely an artifact of reading the wrong tree. At the real target `21a93a88e`, everything matched. A false INCOMPLETE verdict was one step away.

**How to apply:** For any commit-scoped review, read the exact tree with `git show <target-sha>:<path>` (or dump to /tmp via `git show`), and grep with `git grep <pat> <target-sha> -- <pathspec>`. Never trust `Read` on worktree files until you have confirmed HEAD == target. The Integration-checklist / divergence findings you'd report from the wrong tree are worthless.
