---
name: feedback-edit-worktree-path-not-main
description: When working in a worktree, Edit/Write the WORKTREE path, not the main-repo path — they are different files; cargo reads the worktree (cwd) and won't see main-repo edits
metadata:
  type: feedback
---

When the task assigns a git WORKTREE (e.g. `.claude/worktrees/<name>`), the Edit/Write/Read `file_path` MUST be the worktree path, not the main checkout path.

**Why:** I once edited `/Users/alec/Developer/limn/scp/crates/...` (MAIN repo) while the assigned worktree was `/Users/alec/Developer/limn/scp/.claude/worktrees/1909-native-aad/crates/...`. These are DIFFERENT files on disk. The Bash cwd was the worktree, so every `cargo fmt`/`clippy`/`nextest` compiled the UNMODIFIED worktree files and reported green — verifying nothing about my changes. grep against the worktree found my new tests missing while Edit reported success; that mismatch is the tell.

**How to apply:**
- At task start, note the worktree absolute path and prefix EVERY Edit/Write/Read file_path with it.
- Recovery if already done in the wrong tree: `git -C <main> diff -- <files> > /tmp/p.patch` → `git apply /tmp/p.patch` (cwd=worktree) → `git -C <main> checkout -- <files>` to restore main. Then RE-RUN all verification against the worktree (the earlier green runs are void).
- A clippy/test "pass" only counts if the on-disk files cargo compiled actually contain your edits. Confirm with `grep -c <new-symbol> <worktree-path>` before trusting green.
- Bash `grep`/`awk` on freshly-Edited files can read a stale snapshot; the Edit/Read tools are authoritative, and `cargo` (true on-disk read) is the final arbiter.
