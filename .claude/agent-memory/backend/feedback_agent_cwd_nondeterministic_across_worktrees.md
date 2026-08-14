---
name: agent-cwd-nondeterministic-across-worktrees
description: bash cwd can flip between the agent worktree and the MAIN repo between calls; git checkout/commit may land on the wrong worktree's branch — pin every git op with -C
metadata:
  type: feedback
---

The Bash tool's cwd is NOT stable across calls in an agent thread: it sometimes
resolves to the agent worktree (`.claude/worktrees/agent-<id>`) and sometimes to
the MAIN repo (`/Users/alec/Developer/limn/scp`). A `git checkout -b foo` in one
call does NOT persist to the next call, and a later `git commit` can land on the
MAIN worktree's currently-checked-out branch (someone else's WIP branch), not the
branch you created.

**Why:** verified incident (PR-6b-0 saga-error task) — `git checkout -b
chore/116-pr6b0-saga-error origin/main` reported success, but the very next
`git commit` committed onto `docs/adr-structured-capability-validation-ffi` in
the MAIN worktree (its parent was the right base `e406c15c5`, so content was
correct, but the branch was wrong). The intended branch sat untouched, checked
out in the agent worktree.

**How to apply:** when isolation matters, pin EVERY git invocation with
`git -C <abs-worktree-path>` (the env's "Working directory" is the agent
worktree path — use it literally). Never rely on `cd` or an earlier
`checkout`/`branch` persisting. Recovery from a misplaced commit: `git
cherry-pick <sha>` into the correct worktree (whichever cwd holds the target
branch checked out — confirm with `pwd` + `git branch --show-current` first),
then `git -C <main-path> reset --hard <base>` to scrub the stray commit from the
wrong branch. You cannot `git branch -f` a branch that is checked out in another
worktree — cherry-pick into that worktree instead. Relates to
[[feedback-worktree-absolute-path]].
