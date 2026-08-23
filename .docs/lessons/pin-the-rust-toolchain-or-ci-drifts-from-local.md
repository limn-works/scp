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

Rust 1.98.0 shipped on 2026-08-20. Its clippy added two lints, and they sit in different
groups, which matters for what a reader concludes. `chunks_exact_to_as_chunks` is a `style`
lint, warn by default and a member of `clippy::all`; it fires with no group flags at all.
`unused_async_trait_impl` is allow by default and reaches this workspace through the
`pedantic` group. `[workspace.lints.clippy]` enables `all`, `pedantic`, `nursery`, and
`cargo` at `warn`, and CI escalates every one with `-D warnings`. Dropping `pedantic`
would therefore not have prevented the outage: the style lint would still have fired.
Every branch in the merge queue started failing `Rust / clippy` the next morning against
code no one had touched. Local machines were still on 1.97.1, so running the exact CI command locally
printed a clean pass, and one agent reported the failure as unreproducible.

CLAUDE.md requires running CI locally before pushing. That requirement decides nothing
while the two runs resolve to different compilers.

## The Fix

Counting the places that select a Rust version is the part a reviewer has to check, and
the first count was wrong. Four locations name the stable version and now all name
`1.98.0`:

- `rust-toolchain.toml` at the repository root pins `channel`, the `clippy` and `rustfmt`
  components, and every cross-compilation target some CI job builds for. Listing the
  targets matters, and not only for a future stable release: rustup names toolchains, and
  `stable-<host>` and `1.98.0-<host>` are already different names, so a target a workflow
  step installs into `stable` is invisible to the toolchain cargo uses.
- `.mise.toml` names the same version, because mise sets `RUSTUP_TOOLCHAIN` for the
  commands it runs and that variable overrides `rust-toolchain.toml` entirely. Verify with
  `mise x -- printenv RUSTUP_TOOLCHAIN`; plain `mise env` does not print the variable, so
  checking that command instead reports the wrong answer.
- `Dockerfile` selects a base image. `.dockerignore` does not exclude the pin, so `COPY . .`
  carries it into the build and rustup honours it over the image's own compiler.
- `.docs/standards/rust.md` states the toolchain policy, and CLAUDE.md places
  `.docs/standards/` upstream of code. A standard reading "stable (latest)" while a file
  pins a version makes the pin contradict its own governing artifact.

Two more locations name the nightly the standalone fuzz crate needs:
`fuzz/rust-toolchain.toml` and the `FUZZ_TOOLCHAIN` environment variable in
`.github/workflows/fuzz.yml`.

`scripts/check-toolchain-pin.sh` reads all six and requires exact equality. The gate is
closed by construction — a fixed list of locations, one version string extracted from
each — rather than a scan for version-shaped strings, so it admits nothing it was not told
to check. A comment asking several files to agree is not enforcement, and the repository's
own tenet is to enforce mechanically.

`.github/workflows/fuzz.yml` now names the nightly on every `cargo` command. Those steps
run with the repository root as the working directory, where the root pin applies, and an
explicit `+toolchain` sets `RUSTUP_TOOLCHAIN` for the command and everything it spawns.
The fuzz-crate check in `.github/workflows/ci.yml` already wrote its toolchain that way.

Auditing those steps turned up a second defect that had nothing to do with the pin: all
three fuzz jobs referenced the action as `dtolnay/rust-toolchain@nightly-2026-05-03`, and
that repository publishes `master`, `stable`, `beta`, `nightly`, and a branch per released
version — but no dated-nightly branch. The ref never resolved, so every scheduled Fuzz run
failed at job setup with "unable to find version"
and the fuzzer had not executed since the ref was introduced. A green pull request tells
you nothing about a workflow that runs on a schedule. Naming the date through the
`toolchain` input of `@master` — the form `ci.yml` already used — is the working shape.

## Raising the Pin

Bumping Rust is a change someone makes on purpose:

1. Raise the version in `rust-toolchain.toml`, `.mise.toml`, `Dockerfile`, and
   `.docs/standards/rust.md`.
2. Run `bash scripts/check-toolchain-pin.sh`, which fails until all four agree.
3. Run the CI clippy command from the "Orchestrator verification protocol" section of
   CLAUDE.md.
4. Fix everything the new release reports, in that same pull request.

A new stable release reporting new lints is then a scheduled piece of work, not an
overnight outage of the merge queue.
