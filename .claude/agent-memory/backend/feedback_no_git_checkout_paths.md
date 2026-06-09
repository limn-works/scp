---
name: feedback-no-git-checkout-paths-on-dirty-tree
description: Never `git checkout origin/branch -- path/` on a dirty working tree — it overwrites uncommitted edits. Pair with no-stash rule.
type: feedback
---

When you want to compare the current state to the integration branch's baseline (e.g., to verify that a test failure pre-exists), do NOT do this from a dirty tree:

```bash
git stash                                        # forbidden by CLAUDE.md
git checkout origin/branch -- crates/path/       # silently overwrites uncommitted edits in `crates/path/`
```

**Why:** Both halves of that pattern destroy work. `git stash` is explicitly banned (see top-level CLAUDE.md and the agent prompt preamble). `git checkout <ref> -- <path>` overwrites the working tree without warning when the path is dirty — and `git status` after the fact shows nothing was modified, masking the loss until you re-run a failing build.

**How to apply:** When you need a baseline comparison from a dirty tree:

1. Trust the agent prompt preamble's stated baseline counts ("X pre-existing failures in package Y") — those numbers are verified by the prior agent.
2. If you must verify yourself, run the comparison from a fresh clone or a separate worktree — never reset paths in the active worktree.
3. If you've already cleared the tree by accident: `git stash pop` recovers IF you stashed; otherwise the work is gone and must be re-done from scratch.

The 12c.9g.1 hoist commit run hit this pathway: `git stash && git checkout origin/refactor/actor-per-context -- crates/scp-runtime/src/context/manager` wiped ~600 lines of edits from mod.rs / economy.rs / governance.rs. The `git stash pop` recovered them only because the stash had already captured them. Without the stash they would have been gone — and the task instructions explicitly forbid `git stash` precisely because earlier agents lost user changes that way.
