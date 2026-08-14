---
name: feedback-edit-tool-overlay-divergence
description: In .claude/worktrees/*, Edit/Write tools write to an overlay Bash/cargo cannot see — use python3.12 heredoc in Bash for ALL edits
metadata:
  type: feedback
---

In the `.claude/worktrees/sec-1866` worktree (and likely all `.claude/worktrees/*`), the Edit/Write/Read tools operate on a different filesystem view than the Bash tool. Specifically: Edit reports success AND the Read tool confirms the new content, but `git diff`/`grep`/`cargo` via Bash still see the ORIGINAL file. Read sees Bash's writes (one-way), but Bash does NOT see Edit's writes. Net effect: cargo would compile the stale pre-edit code while every tool-based check looks green.

**Why:** the Edit/Read tools write to a copy-on-write overlay; Bash (and therefore cargo/clippy/git/CI) reads the underlying real file. Confirmed empirically 2026-06-22: grep via Bash returned 0 matches for content the Read tool displayed at the same path; sentinel write from Bash → visible to Read, but Edit's write → invisible to Bash.

**How to apply:** For ANY file mutation in a worktree, do it via a `python3.12 - <<'PYEOF' ... PYEOF` heredoc run through the Bash tool, with `assert s.count(old) == N` before writing. Then verify with a Bash `grep`/`git diff --stat` (NOT the Read tool — Read may show the overlay, not what cargo will compile). Never trust an Edit-tool success or a Read-tool re-read as proof an edit will be seen by the compiler. This is a stronger form of [[feedback-read-tool-stale-verify-with-awk]] and [[feedback-worktree-absolute-path]].
