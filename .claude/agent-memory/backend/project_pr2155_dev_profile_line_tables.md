---
name: project-pr2155-dev-profile-line-tables
description: PR #2155 dev-profile line-tables-only — measured 26% target/ saving (NOT "halves"); conflict recipe vs main's ADR-057 [profile.release]; CARGO_INCREMENTAL follow-on
metadata:
  type: project
---

PR #2155 (`chore/dev-profile-line-tables`) adds `[profile.dev] debug = "line-tables-only"`
to the workspace root `Cargo.toml`. Opened 2026-07-16, went stale 24 days, went DIRTY,
rebased and re-validated 2026-08-09 onto `d1ebc5ab9` (head `8cc40c37c`).

**Why:** the shared `CARGO_TARGET_DIR` (`~/.cargo/shared-target`, set in
`~/.cargo/config.toml`) hit **287 GB** on a disk at 93% capacity. This is the direct
remedy for Alec's originating 2026-07-03 question ("the rust targets are MASSIVE / 83gb???").

**Measured numbers (macOS/aarch64, rustc 1.97.1, two clean `cargo build --workspace
--all-targets` runs with the CI feature set, isolated target dirs, identical unit graphs
of 572 rlibs / 887 fingerprints):**

| | `debug = 2` (default) | `line-tables-only` | saved |
|---|---|---|---|
| `target/` total | 25.65 GB | 18.95 GB | 6.70 GB (**26%**) |
| `debug/deps` | 16.50 GB | 11.43 GB | 31% |
| `.rlib` bytes | 3.15 GB | 1.94 GB | 38% |
| `debug/incremental` | 9.15 GB | 6.53 GB | 29% |

**The original PR body claimed "roughly halves target/". That is FALSE — it is 26%.**
Corrected in the body and the in-file comment. Reproduce the baseline with
`CARGO_PROFILE_DEV_DEBUG=2` (exactly cargo's default) — no need to check out main.

**Why:** a wrong headline number in a merged artifact becomes the thing everyone cites.
26% still earns its keep (~75 GB of 287 GB), but the claim had to match the measurement.
**How to apply:** when rescuing any stale perf/size PR, re-measure before re-pushing —
the premise may have moved, and the original number may never have been measured at all.

**Rebase conflict recipe (recurs for any root-`Cargo.toml` profile work):** main added
`[profile.release] debug-assertions = false` at EOF after this PR was opened — a
LOAD-BEARING ADR-057 §Prereq-4 block (openmls decrypt-path `debug_assert!` must stay
compiled out so a hostile relay can't abort a browser tab). Both sides appended a NEW
section at EOF, so git flags a conflict on independent additions. **Resolution: keep
both verbatim, `[profile.dev]` before `[profile.release]`.** The keys are orthogonal —
`debug` is debug-info verbosity, `debug-assertions` is codegen. Dev/test keep
`debug-assertions = true`, so the openmls assert still fires under `cargo test`.

**Backtrace trade-off (measured, not assumed — the PR was overselling it):**
`file:line:col` is preserved EXACTLY, and so is the `panicked at …` header
(`#[track_caller]`, not debuginfo). What actually degrades is the frame *name*: the
DWARF-derived crate-qualified name falls back to the linkage symbol
(`deep` vs `bt_probe[hash]::deep`). Locals become uninspectable in lldb/gdb.
Recover with `RUSTFLAGS="-C debuginfo=2"`. Zero repo code consumes backtraces
programmatically; zero `dSYM`/`lldb`/`split-debuginfo` references.

**macOS caveat:** Mach-O keeps DWARF in `.o`/rlib files, so linked test *executables*
shrink only 3-5% locally (`scp_node` 242.5→233.4 MB). On the Linux CI runners DWARF is
linked into the executable, so 26% is a floor for CI, not a ceiling.

**Follow-on lever, deliberately NOT bundled:** `debug/incremental` is 6.53 GB of the
18.95 GB post-change target dir (34%) — write-only waste for one-shot CI-mirror builds.
`.github/workflows/build-matrix.yml:28` sets `CARGO_INCREMENTAL: 0`; **`ci.yml` does
NOT** (its `env:` block has only `CARGO_TERM_COLOR` and `RUST_BACKTRACE`). Both levers
together: 25.65 GB → ~12.4 GB, which IS "roughly halves".

Related: [[feedback-check-scripts-need-cargo-target-dir]], [[feedback-worktree-absolute-path]]
