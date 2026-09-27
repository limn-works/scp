# The Shared Target Directory Has One Lock, and 1.4 Million Files

Every git worktree on the machine that builds this repository compiles into
`/Users/alec/.cargo/shared-target`, because `~/.cargo/config.toml` sets `build.target-dir`.
Alec ruled on 2026-08-30 that agents use that directory rather than a private one, verbatim:
**"this is the reason we have a shared build target, dummy."** Wiping the directory or
setting `CARGO_TARGET_DIR` is what that ruling forbids; `cargo clean -p <crate>` remains the
remedy for one stale artifact.

## A slow cargo command is usually queued, not compiling

- **Cargo takes one build lock on the directory.** When it prints
  `Blocking waiting for file lock on build directory`, the run is queued. Measured on
  2026-09-13: one `cargo check -p scp-protocol --all-targets` took 29 min 40 s, of which
  23 min 16 s was waiting for the lock; an immediate rerun that compiled nothing took
  28 min 27 s, all of it queued. With the lock free, `scripts/fix-round-check.sh` took
  49 seconds end to end.
- **A second cargo command does not run in parallel; it joins the queue.** Run one and let it
  finish. `scripts/fix-round-check.sh` runs exactly one, scoped to the edited crates, and
  leaves workspace clippy and nextest to CI.
- **`cargo fmt` and `cargo metadata` wait on the same queue.** `cargo metadata --no-deps
  --offline` took 68 ms alone and two and a half minutes beside another worktree's check,
  and `cargo fmt` resolves the workspace through `cargo metadata` first.
- **The lock holder is not always an agent, and not always this project.** The ruling's
  config applies to every Rust project the user builds, so Zed's `rust-analyzer` flycheck on
  another repository, on the unpinned `stable` compiler, held the same lock. One holder had
  sat 42 minutes with its `rustc` children using zero CPU; killing it drained the queue in
  four seconds.

## Why each unit compiles slowly after the wait

`debug/deps` held 1,381,573 entries (575 GB for the whole directory), and one `stat` there
cost about 2.7 ms against 2 µs in a directory of 100,000 entries, so every unit pays a fixed
filesystem charge whatever its source size: a 436-line crate took 83.6 s to check. Of those
entries, 70.8% belong to this workspace's own crates, because cargo hashes a package's
absolute path into `-C metadata`, so each worktree compiles its own copy (`scp_runtime`
compiled from at least 35 worktrees). Cargo never removes artifacts of crates the workspace
dropped.

Within one worktree the cache stays warm across branches, because a branch changes none of
the `-C metadata` inputs (package name, version, source path, features, profile, compiler);
cargo recompiles only the crates whose source the branch changed.

The macOS Gatekeeper assessment queue is a separate cost that varies from milliseconds to 31
minutes per item between days, and Apple offers no per-path exclusion for it.
