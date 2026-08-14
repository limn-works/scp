---
name: worktree-cwd-resolution-trap
description: Bash tool cwd is unstable across worktrees — `cd <main-repo-root>` jumps OUT of the assigned worktree; use git -C <worktree-abspath> for every git op
metadata:
  type: feedback
---

When a task assigns work in a specific worktree (e.g. `.claude/worktrees/1909-p2-wasm`), the Bash tool's cwd is NOT reliably that worktree. Bare commands ran in the assigned worktree, but any command starting with `cd /Users/alec/Developer/limn/scp` (the MAIN repo root) silently jumped into the **main** worktree — which was on a DIFFERENT detached HEAD (`1620de983`, off `origin/fix/ceiling-modify-reconcile`) than the snapshot `git worktree list` showed.

**What went wrong (2026-06-28, §9.16.1 spec clarification):** Edit tool calls with the bare absolute path `/Users/alec/Developer/limn/scp/.docs/...` wrote to the MAIN worktree, and `git commit` (run under `cd <main-root>`) landed the commit on a detached HEAD off the wrong base — NOT on the assigned branch `wasm/1909-phase2-sender-layer`. The cherry-pick to recover then conflicted because the two bases had diverged. Recovery: `git reset --hard <orig-main-sha>` to restore main, then re-apply the edit at the FULL worktree path `.../.claude/worktrees/<wt>/.docs/...` and commit with `git -C <worktree-abspath>`.

**Why:** Multiple worktrees share one object DB but have independent HEADs. The harness `git status` snapshot at session start can be STALE (it showed main at the branch SHA; it was actually elsewhere).

**How to apply:**
- For a worktree task, Edit/Read the file at its FULL worktree-prefixed absolute path, never the main-repo-root path.
- Run EVERY git command with `git -C <worktree-abspath> ...` — never `cd <main-root> && git ...`.
- Before committing, assert `git -C <wt> branch --show-current` == the assigned branch and `git -C <wt> rev-parse HEAD` == the expected base SHA. A "detached HEAD" result means you're in the wrong tree.
- Commit single files with `git commit -o <path>` (not `-am`) when the worktree has unrelated dirty files (agent-memory MEMORY.md churn is common here) — keeps the commit atomic.
