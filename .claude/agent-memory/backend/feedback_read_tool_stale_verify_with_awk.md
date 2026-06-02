---
name: read-tool-stale-verify-with-awk
description: Read tool can return stale/cached file content that disagrees with disk; verify load-bearing line content with awk/grep before editing
metadata:
  type: feedback
---

When a task's plan cites specific line numbers/behaviors and you Read the file, the Read tool may return a DIFFERENT (often newer/cached) projection than what is actually on disk. Observed in `crates/scp-ffi/src/runtime.rs` and `scp.rs`: Read showed a post-fix `with_storage_py` returning `Result`+`StorageInitError`, while the committed on-disk file (HEAD, clean working tree) still had the pre-fix `Self`-returning fallback to `Self::new_py()`.

**Why:** Editing against a stale mental model wastes effort and risks Edit failures or wrong assumptions about what work remains. Edit/Write match against the REAL on-disk file, so an Edit built from Read-hallucinated text fails; conversely a "the fix is already done" conclusion from a stale Read is wrong.

**How to apply:** For any file where the plan's described state is load-bearing (especially when the task says "the current code does X, change it to Y"), confirm the exact lines with `awk 'NR>=A && NR<=B {printf "%d: %s\n", NR, $0}' file` or `grep -n` BEFORE concluding work is done or building Edit old_strings. Cross-check `git status --short` + `git diff --stat HEAD -- file`: a clean working tree means disk == HEAD, so awk output is authoritative. Trust awk/grep over Read when they conflict. Relates to [[feedback-no-git-checkout-paths]].
