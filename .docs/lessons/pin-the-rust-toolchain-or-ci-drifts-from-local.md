# Pin the Rust Toolchain, or CI Compiles With a Different Compiler Than You Do

**Date:** 2026-08-22
**Source:** branch `fix/clippy-1-98-chunks-exact` — the `Rust / clippy` required check failed
on every branch after Rust 1.98.0 shipped, and a local run of the identical command
reported nothing.

## The Rule

A repository that runs `cargo clippy` as a required check pins its compiler in
`rust-toolchain.toml`, and every other place that selects a Rust version names the same
version. A workflow step that installs `dtolnay/rust-toolchain@stable` selects whichever
stable release exists on the morning the job runs, so a required check built that way
fails for a reason nobody changed and nobody can reproduce.

## What Happened

Rust 1.98.0 shipped on 2026-08-20. Its clippy added `chunks_exact_to_as_chunks` and
`unused_async_trait_impl`, both in the `pedantic` group, which this workspace enables at
`warn` in `[workspace.lints.clippy]` and CI escalates with `-D warnings`. Every branch in
the merge queue started failing `Rust / clippy` the next morning against code no one had
touched. Local machines were still on 1.97.1, so running the exact CI command locally
printed a clean pass, and one agent reported the failure as unreproducible.

CLAUDE.md requires running CI locally before pushing. That requirement decides nothing
while the two runs resolve to different compilers.

## The Fix

Three files select a Rust version, and all three now name `1.98.0`:

- `rust-toolchain.toml` at the repository root pins `channel`, the `clippy` and `rustfmt`
  components, and every cross-compilation target some CI job builds for. Listing the
  targets matters: the workflow steps add their targets to whatever `@stable` resolves to,
  so once stable moves past the pin, a target installed into the newer toolchain would be
  missing from the one cargo actually uses.
- `.mise.toml` names the same version, because mise exports `RUSTUP_TOOLCHAIN`, and that
  environment variable takes precedence over `rust-toolchain.toml`. Leaving it at
  `"stable"` would reintroduce the drift on every developer machine.
- `fuzz/rust-toolchain.toml` pins the nightly that `fuzz/` needs, because a root pin
  otherwise reaches that standalone crate too.

`.github/workflows/fuzz.yml` now writes `cargo +nightly-2026-05-03 fuzz run …`. Those
steps run with the repository root as the working directory, where the root pin applies,
and an explicit `+toolchain` sets `RUSTUP_TOOLCHAIN` for the command and everything it
spawns. The fuzz-crate check in `.github/workflows/ci.yml` already wrote its toolchain
that way.

## Raising the Pin

Bumping Rust is a change someone makes on purpose:

1. Raise `channel` in `rust-toolchain.toml` and `rust` in `.mise.toml` to the same version.
2. Run the CI clippy command from the "Orchestrator verification protocol" section of
   CLAUDE.md.
3. Fix everything the new release reports, in that same pull request.

A new stable release reporting new lints is then a scheduled piece of work, not an
overnight outage of the merge queue.
