---
name: worktree-grep-path-trap
description: When a change lives in a sub-worktree, grep that worktree path — not the main repo root, which is on a different branch and yields false findings
metadata:
  type: feedback
---

When interrogating a change that lives in a sub-worktree (e.g.
`/Users/alec/Developer/limn/scp/.claude/worktrees/sup-113`), run all greps/reads
against THAT worktree path, never the main repo root
(`/Users/alec/Developer/limn/scp`).

**Why:** The main worktree stays on `main` (per the repo's orchestration rules),
so it lacks the change under review. Greping it shows the PRE-change state and
manufactures false findings. In the sup-113 review I greped the main root, "found"
a surviving stale doc paragraph on `send_message` and residual commit-6/commit-11
text, and had to retract all of it after re-running against the worktree HEAD —
the deletions were actually clean and the stale paragraph was gone.

**How to apply:** Anchor every Bash `grep`/`sed` and every Read to the worktree
path given in the prompt. Cross-check `git rev-parse --short HEAD` from inside the
worktree matches the prompt's stated HEAD before trusting any grep result. The
bare bash cwd resets between calls, so pass absolute worktree paths every time
(this compounds with the existing "always absolute paths" reminder).

**RECURRED 2026-07-11 (agent-a9a59e51697d57907 worktree, TTL-close re-review).**
I fell into it AGAIN despite this memory: I ran `cd /Users/alec/Developer/limn/scp`
(MAIN root, a different branch) in every Bash call and Read'd main-root absolute
paths. Result: I "found" the snapshot still persisted relative `ttl_remaining_secs`,
`reconcile_timers` didn't exist, `on_ttl_tick` was a no-op skeleton, and declared
the ADR phantom provenance — ALL FALSE (main root was pre-fix). The fix was fully
present at the worktree HEAD. **Two hard rules that would have saved ~15 tool calls:**
(1) The single most reliable read of a commit's content is `git show <sha>:<path>`
or `git show HEAD:<path>` — the object DB is branch/worktree-independent, so it is
immune to this trap. PREFER it over Read/cd for reviewing a specific commit.
(2) `git merge-base --is-ancestor <fix-sha> HEAD` returning NO, or `git diff
<base>..HEAD` looking like a giant unrelated reorg, is the SMOKING GUN that your
`cd` target's HEAD ≠ the prompt's HEAD. Stop and re-anchor immediately.
