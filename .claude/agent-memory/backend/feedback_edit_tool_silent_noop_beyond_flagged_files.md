---
name: edit-tool-silent-noop-beyond-flagged-files
description: Edit tool silently no-ops (reports success, git-diff empty) on files NOT flagged stale — verify EVERY edit landed via git diff, not the tool's success message
metadata:
  type: feedback
---

The Edit tool can report success while writing NOTHING to disk — the same silent-no-op class as [[feedback-read-tool-stale-verify-with-awk]], but it is NOT limited to files a task flags as "stale via Read/Edit."

In ticket #1901 (worktree 1901-remove-member), three files were edited with the Edit tool and ALL THREE silently failed to persist despite "updated successfully": `crates/scp-runtime/src/context/governance_helpers.rs`, `crates/scp-runtime/src/context/lifecycle_helpers.rs`, and `.docs/specs/05-contexts.md`. The task had only flagged `crates/scp-ffi/wasm/src/manager.rs` as stale. The failures were caught only because tests failed (the fix wasn't on the code path) and because I ran `git diff --stat` and noticed the spec file was absent.

**Why:** The harness's file-state tracking diverges from disk in this repo's worktrees; a "successful" Edit is not proof of a disk write.

**How to apply:** For ANY load-bearing edit in this repo (especially worktrees), prefer a `python3.12` heredoc that does `assert src.count(OLD) == 1` then `.replace()` and writes the file — it fails loudly if the anchor is gone. After editing, ALWAYS confirm with `git diff --stat` / `grep` that every expected file appears with the expected content BEFORE running tests or committing. Do not trust the Edit/Read tool's own success report. A clean fmt/clippy/test pass on a file you "edited" but that shows empty in git diff means the edit didn't land — investigate, don't assume.
