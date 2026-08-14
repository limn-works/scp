---
name: read-from-branch-tip-not-main-worktree
description: When reviewing a branch/diff, read source via `git show SHA:path` — the main worktree may be on a different commit and give stale evidence
metadata:
  type: feedback
---

When interrogating a specific branch/commit, read the code from that commit, not
from a checked-out working tree.

**Why:** In the SCP repo, agent tasks run in a worktree while the main repo
(`/Users/alec/Developer/limn/scp`) is frequently on a *different* HEAD. During the
ADR-062 Slice 1 (`0161e39fe`) review I `Read`/`grep`'d `/Users/alec/Developer/limn/scp/crates/...`
and saw `impl Default for DidDht`, `pub fn new()`, and `DidDht<D = InMemoryDhtClient>`
still present — and nearly filed an UNSOUND "the mandated D-A structural fix never
landed." The `git diff 9ff9eadde..0161e39fe` and `git show 0161e39fe:...` proved the
opposite: the fix *had* landed; the main worktree was simply on an unrelated commit.

**How to apply:** For any "review this diff/branch" task, treat `git show <SHA>:<path>`
and `git diff <base>..<tip>` as the sole source of truth. If you must `Read` a file for
surrounding context, first confirm the working tree is actually at the tip
(`git -C <dir> rev-parse HEAD`). A "premise never implemented" finding based on a
working-tree read is a false positive until verified against the tip.
