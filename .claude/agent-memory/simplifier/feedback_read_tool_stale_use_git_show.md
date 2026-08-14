---
name: read-tool-stale-use-git-show
description: When reviewing a specific committed branch HEAD, Read/Grep over the working tree can serve a STALE pre-branch file; verify against `git show <sha>:path`
metadata:
  type: feedback
---

When asked to review a specific commit/branch HEAD, do NOT trust the Read tool or `grep` over the working-tree file as authoritative for what's committed.

**Why:** On the `fix/sdk-coverage-fail-closed-and-parity` review (HEAD `614f0eb17`), the Read tool served a stale 2775-line `bindings/typescript/src/scp.ts` that PREDATED the branch work — it showed `ucanValidate`/`eventLogQuery` *without* the `mapBridgeError` try/catch and showed a still-present `@deprecated PermissionError` alias, both of which the commit had actually changed/removed. The committed file (via `git show 614f0eb17:...`) was 3700+ lines with all 203 methods uniformly wrapped and the alias gone. Line numbers in `git show <sha>` commit diffs also won't match working-tree line numbers if the branch was rebased.

**How to apply:** For "review branch/commit X" tasks, extract the authoritative file with `git show <sha>:path > /tmp/file` and Read THAT, or grep `git show <sha>:path`. Treat a mismatch between Read output and `git show` as the Read being stale, not a real revert — confirm with `git show <sha>:path | grep`. Only trust working-tree Read when the task is explicitly about uncommitted changes.
