---
name: worktree-contamination-iffalse-axis-a
description: ffi-saga-116 worktree had uncommitted `if false &&` mutation disabling axis-(a) caller-principal binding in all 3 bridges; NOT in committed HEAD
metadata:
  type: project
---

During review of branch feat/116-ffi-saga-export (HEAD 9611159f6, worktree
ffi-saga-116), the WORKING TREE carried an uncommitted mutation in all three
FFI bridges' `enforce_caller_principal_binding`:

  `if !registry_contains(caller_did)` → `if false && !registry_contains(caller_did)`

Files: crates/scp-ffi/src/tools.rs:1057, crates/scp-ffi/napi/src/tools.rs:795,
crates/scp-ffi/uniffi/src/bridge.rs:5497.

This short-circuits axis (a) (caller is hosted/channel-authenticated by this
bridge instance) to dead code, leaving ONLY axis (b) membership — a
caller-principal forgery / confused-deputy hole. It is a mutation-test probe
that proves the new `member_but_unhosted_caller` tests (this same commit) catch
axis-(a) removal.

**Why:** Verified via `git show HEAD:<file>` — committed HEAD reads the correct
`if !...` form in all 3 files; `git status` shows the 3 files M (dirty). The
contamination is purely uncommitted working-tree state, NOT part of the branch.

**How to apply:** Always diff working tree vs committed HEAD before flagging a
finding (`git diff HEAD`, `git show HEAD:<file>`). A dirty mutation probe in a
review worktree is contamination — report it as "do not commit," not as a branch
defect. The committed §6.2.4 export surface remains ZERO-FINDINGS (matches
ffi-saga-saga-116-xctx-export.md). Reaffirms the lesson:
blackhat/mutation probes left in a shared worktree contaminate file-reading
reviewers.
