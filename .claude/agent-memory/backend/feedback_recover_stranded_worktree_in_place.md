---
name: feedback-recover-stranded-worktree-in-place
description: When recovering a stranded branch, work in the dead session's EXISTING worktree — it holds uncommitted in-flight work that a fresh worktree would silently strand again
metadata:
  type: feedback
---

Before creating a worktree for a "stranded" branch, run `git worktree list` and
check whether the dead session's worktree still exists. If it does,
`git worktree add` will fail with *"already used by worktree at ..."* — that is a
signal, not an obstacle. **Work in that existing worktree.**

**Why:** the dead session's worktree very often still holds UNCOMMITTED changes
that are part of the unfinished work. On the #2069/F2 recovery (2026-08-08) the
12 committed commits were only part of the story — the worktree also carried an
uncommitted `SCP-IDENT-1024` → new `SCP-IDENT-1029` error-code split across three
FFI bridges plus a rustdoc block. Creating a fresh worktree from the branch tip
would have left all of it behind and it would have been lost a second time.
Worse, that uncommitted work was *self-inconsistent*: a doc comment asserted a
code deletion ("It has been deleted") that had never been performed — the session
died between writing the doc and making the edit.

**How to apply:**
* `git worktree list` FIRST; reuse the existing path rather than adding one.
* `git status --porcelain` before anything else, and read the full `git diff`.
* Never `git stash` / `git checkout -- <path>` / `git reset` to "clean up" — that
  is how the work gets destroyed.
* Treat every uncommitted doc comment as a CLAIM to verify against the code, not
  as a description of it. A dying session writes the doc before the edit as often
  as after.
* Subagents dispatched to finish the work must NOT use `isolation: "worktree"` —
  that spawns a fresh checkout without the uncommitted state. Point them at the
  existing worktree path explicitly and tell them not to create one.

Related: [[feedback-worktree-absolute-path]], [[feedback-no-git-checkout-paths]].
