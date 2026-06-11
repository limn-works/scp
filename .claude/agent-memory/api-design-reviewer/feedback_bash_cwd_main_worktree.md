---
name: feedback-bash-cwd-main-worktree
description: When reviewing in a worktree, the Bash tool default cwd resolves to the MAIN worktree, not the target — pin every git command with git -C <worktree-abs-path>
metadata:
  type: feedback
---

When asked to review changes in a specific worktree (e.g. `.claude/worktrees/agent-xxxx/`), the `Bash` tool's default working directory resolves to the **MAIN** worktree (`/Users/alec/Developer/limn/scp`, branch `main`), NOT the target worktree. A bare `git show HEAD:<path>` / `git log` / `git diff` reads MAIN's HEAD and produces FALSE findings (e.g. "the enum case is missing" when it is actually present in the target worktree).

**Why:** Worktrees share the repo but have independent HEADs/branches. `cd` into the worktree is discouraged in this env (can trigger permission prompts, and shell state doesn't persist between Bash calls anyway).

**How to apply:** On every review against a worktree:
1. First run `git -C "<worktree-abs-path>" rev-parse HEAD` and `git -C "<worktree-abs-path>" branch --show-current` to confirm you are reading the intended HEAD/branch.
2. Pin ALL git commands with `git -C "<worktree-abs-path>" ...` and use absolute on-disk paths for `Read`/`sed`/`grep`.
3. If a `git show HEAD:<file>` contradicts the task's stated facts, suspect cwd-in-main before concluding the code is wrong. Re-check with `-C`.

Concretely hit on the ADR-049 §10 poison review (worktree HEAD 2490db0c5 / branch feat/actor-2b-watchdog-respawn): a bare `git show HEAD:ScpBindings.swift` returned MAIN's enum lacking the `Poisoned` case; re-pinning with `git -C` showed the case present at the correct ordinal. See [[adr049-poison-observability-review]].
