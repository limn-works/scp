---
name: pr2155-dev-profile-merge-8b7cbe7f8
description: Retro-review of unreviewed merge 8b7cbe7f8 ([profile.dev] debug=line-tables-only) — conflict resolution clean; one false cargo-inheritance claim in the comment
metadata:
  type: project
---

# 8b7cbe7f8 (PR #2155) — `[profile.dev] debug = "line-tables-only"`

Merged unreviewed 2026-08-09 onto `d1ebc5ab9` after a rebase over 61 commits of drift.
Retro-reviewed: **conflict resolution is clean**; one documentation defect.

**Verified clean (empirically, isolated `CARGO_TARGET_DIR` repros — do not re-derive):**
- Squash lost nothing: `git diff 8cc40c37c 8b7cbe7f8` is EMPTY; `git diff d1ebc5ab9 8cc40c37c` = `Cargo.toml | 39 +` only.
- ADR-057 `[profile.release] debug-assertions = false` block is **byte-identical** to the parent
  (`diff <(git show 8b7cbe7f8^:Cargo.toml) <(git show origin/main:Cargo.toml)` = pure 39-line
  addition at 121–159; release block untouched at 181–182).
- `debug-assertions = false` really IS the cargo release default: rustc flags for "no
  `[profile.release]` at all" and "`debug-assertions = false`" are **identical**
  (`-C opt-level=3 -C strip=debuginfo`, no `-C debug-assertions` emitted at all). Setting it
  `true` DOES add `-C debug-assertions=on`. So the "changes no behavior, only explicit" claim is TRUE
  and the counterfactual re-arm is detectable.
- dev + test: `-C debuginfo=line-tables-only`, no `-C opt-level`, no `-C debug-assertions`
  ⇒ rustc default ⇒ debug-assertions ON. openmls decrypt `debug_assert!` still fires under `cargo test`.
- `cargo test --release` selects the **release** profile (not `bench`); `cargo bench` selects `bench`.
- Documented escape hatch works: cargo appends RUSTFLAGS AFTER its own `-C debuginfo`, rustc last-wins.
- `scripts/check-no-panic-abort.sh` self-test passes; all 4 scanned manifests clean on `origin/main`.
- No benches exist (no `[[bench]]`, no `#[bench]`, no criterion dep) ⇒ bench profile is inert here.
- No repo claim overstates the saving; agent-memory already says 26%, not "halves".

**Cargo profile inheritance (memorize — the comment gets it wrong):**
`test` inherits `dev`. **`bench` inherits `release`, NOT `dev`.**
Proven: with `[profile.dev] debug = "line-tables-only"` present, `cargo bench --no-run` emits
`-C opt-level=3 -C strip=debuginfo` — release settings, no line-tables-only.

**Finding (LOW, doc-only):** `Cargo.toml:156` "`test` and `bench` inherit `dev`" is false for `bench`.
Same sentence is in the commit message of 8b7cbe7f8.

**Adjacent PRE-EXISTING (not from this merge):** `crates/scp-ffi/wasm` is neither in
`workspace.members` nor in an `exclude` list, so `cargo metadata --manifest-path
crates/scp-ffi/wasm/Cargo.toml` **errors** ("believes it's in a workspace when it's not") — that
crate is unbuildable as written, and its `[profile.release] opt-level = "s"` (line 94) is inert.
The new comment at `Cargo.toml:152-154` names `fuzz/` as the standalone non-member and misses this one.
