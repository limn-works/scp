---
name: worktree-cwd-trap
description: Bash cwd resets between calls; cd-ing to the main repo reviews the wrong branch — operate in the named worktree
metadata:
  type: feedback
---

When a review task names a worktree path + branch + SHA, do NOT `cd` to the main
repo root (`/Users/alec/Developer/limn/scp`). The main repo is often checked out on
a DIFFERENT branch than the worktree.

**Why:** Agent Bash cwd resets to the worktree between calls, but any `cd
/Users/alec/Developer/limn/scp` silently switches to the main checkout. In PR #2183
this produced a `git diff origin/main..HEAD` that was ceiling-branch-vs-main (138
commits of unrelated noise: removed enforcement jobs, a `testing`→`allow_in_memory_custody`
rename) — total garbage that nearly got reviewed as the PR's changes.

**How to apply:** Run all git/read commands with NO `cd` (stay in the worktree the
harness placed you in), or use absolute paths inside the worktree. First thing:
`git rev-parse --abbrev-ref HEAD` + `git rev-parse HEAD` and confirm they match the
task's branch/SHA. Confirm `git merge-base origin/main HEAD` == origin/main (or use
three-dot `origin/main...HEAD`) so the diff base is the merge-base, not a diverged tip.
This is exactly CLAUDE.md's "verify against the pushed remote, local may be on a
different branch" rule.
