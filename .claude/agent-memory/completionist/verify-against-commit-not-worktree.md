---
name: verify-against-commit-not-worktree
description: When asked to review a specific commit SHA, verify it may not be checked out — read via `git show SHA:path`, not the working tree
metadata:
  type: feedback
---

When a task names a specific commit SHA to review, the working tree / HEAD may be a
DIFFERENT, divergent branch that does not contain that commit. Confirm first:
`git merge-base --is-ancestor <sha> HEAD`. If NO, the commit is a standalone feature
branch — every supplementary read MUST use `git show <sha>:path` (and `git show <sha> --
-- file` for diffs), never plain `Read`/`grep` of the working tree, or you will analyze
the wrong code.

**Why:** Reviewing SCP commit 904f6d3dc (spending-UCAN revocation), HEAD was 1620de983 on
a divergent branch with ZERO of the commit's changes present. Working-tree reads of
supervisor.rs/self_host.rs showed signatures WITHOUT the new param and nearly produced a
false "missing implementation" finding. The commit was fine; my source was wrong.

**How to apply:** At the start of any commit-scoped review: (1) `git rev-parse HEAD`,
(2) `git merge-base --is-ancestor <sha> HEAD`, (3) if not an ancestor, note the merge-base
and read ALL files at the commit via `git show <sha>:...`. Treat the working tree as
untrusted for that review.
