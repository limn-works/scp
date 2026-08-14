---
name: never-inline-git-stash
description: Never put `git stash` in a Bash command line — I destroyed ~2h of uncommitted work with a stray `git stash push -u` used as a no-op filler
metadata:
  type: feedback
---

NEVER write `git stash` (push/save/pop) anywhere in a Bash tool command — not as
a real step, not as filler, not chained behind `;`. If a baseline comparison is
needed, use read-only `git show <rev>:<path>` instead.

**Why:** In the SCP-RELAYRES-004 session I wrote
`CARGO_TARGET_DIR=... git stash push -u -m "wip" >/dev/null 2>&1; echo skip; grep ...`
intending the leading env-var assignment to make it inert. It did not — the
stash ran, silently reverted 17 modified files of in-progress work, and the
subsequent greps returned *baseline* content, which looked like a real code
finding rather than a self-inflicted wipe. Recovery was only possible because
`git stash pop` was run immediately, before any further edit; one more Edit call
on the reverted tree would have made the pop conflict and lost work.

**How to apply:**
- Baseline/diff questions → `git show <rev>:<path>`, `git diff <rev> -- <path>`.
  Both are read-only and answer the same question.
- If a command's only purpose is to be a no-op, don't write the command.
- The blast radius is invisible: nothing in the tool output says "your working
  tree changed". Detect it by an unexpected disappearance of your own edits
  (system-reminders showing pre-edit file content is the tell).

Related: [[feedback-no-git-checkout-paths]] — same class (destructive git op
used casually mid-edit), same failure mode (silent revert of uncommitted work).
