---
name: shared-cargo-target-contamination
description: ~/.cargo/shared-target is shared across all worktrees; concurrent builds cause spurious compile errors — use an isolated CARGO_TARGET_DIR
metadata:
  type: feedback
---

This repo's `.cargo/config` points every crate build at a SHARED target dir
(`/Users/alec/.cargo/shared-target`). When multiple git worktrees build
concurrently (common when the orchestrator has several agents active), the
shared target gets contaminated: a build in worktree A links/reuses a crate
artifact compiled from worktree B's DIFFERENT source, producing spurious compile
errors in files you never touched.

**Signature seen (2026-08 #2196):** `cargo test/clippy` in scp-wt-2196 failed with
`crates/scp-runtime/src/context/governance_helpers.rs:XXXX: bc.rotate_all_author_keys()
takes 1 argument but 0 supplied` — yet the on-disk `fn rotate_all_author_keys`
signature (broadcast/mod.rs) was 0-arg and matched the call. A "Blocking waiting
for file lock on build directory" line confirms a concurrent build. The error was
NOT in the changed diff.

**How to confirm it's contamination, not your bug:** (1) grep the cited callee's
on-disk signature — if it matches the call, it's external; (2) `git diff --stat
HEAD -- <cited-file>` — empty means you never touched it.

**Fix — isolate the build:** `export CARGO_TARGET_DIR=<a fresh dir outside the
worktree>` for cargo commands. Builds from scratch (~2min) but is deterministic.
Put it OUTSIDE the worktree (or a gitignored path) — a bare `target-2196/` inside
the worktree is NOT gitignored and shows as untracked.

**Why:** verify your OWN change in an isolated target (authoritative), and don't
chase phantom errors in the shared target.

**How to apply:** The PRE-COMMIT HOOK also runs fmt+clippy against the shared
target and will block the commit on the same contamination. Set
`CARGO_TARGET_DIR=<isolated>` in the env for the `git commit` call too — the hook
inherits it and builds clean. This is NOT a `--no-verify` bypass; the checks
still run, just against uncontaminated artifacts. Related: [[project-adr057-3-client-wasm]].
