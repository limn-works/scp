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
groups. `chunks_exact_to_as_chunks` is a `style` lint, warn by default and a member of
`clippy::all`, so it fires with no group flags at all. `unused_async_trait_impl` is allow
by default and reaches this workspace through the `pedantic` group.
`[workspace.lints.clippy]` enables `all`, `pedantic`, `nursery`, and `cargo` at `warn`,
and CI escalates every one with `-D warnings`. Dropping `pedantic` would therefore not
have prevented the outage, because the style lint would still have fired.

Every branch in the merge queue started failing `Rust / clippy` the next morning, against
code no one had touched. Local machines were still on 1.97.1, so running the exact CI
command locally printed a clean pass, and one agent reported the failure as
unreproducible.

CLAUDE.md requires running CI locally before pushing. That requirement decides nothing
while the two runs resolve to different compilers.

## The Fix

Several locations name the stable version, and all of them now name `1.98.0`. The first
draft of this fix named two, and each review round found more — which is the part worth
remembering. These four are the ones whose reasons are not obvious:

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

Three more name the nightly that the standalone fuzz crate needs:
`fuzz/rust-toolchain.toml`, and the `FUZZ_TOOLCHAIN` environment variable in
`.github/workflows/fuzz.yml` and in `.github/workflows/ci.yml`.

`scripts/check-toolchain-pin.sh` holds the authoritative list and requires exact equality.
Keep no second list: counting the locations in prose produced three artifacts that disagreed
with the gate and with each other, and one whole commit repairing them. The gate also checks
three properties that version agreement leaves open: that `rustc --version` in the repository
equals the pin, that each container build's builder stage and runtime stage name the same
Debian release, and that no file carrying a `FROM rust:` line is missing from its list — the
last one because four review rounds each found one more such file, and a list that checks
only the files it already names cannot find the next. The second one exists because the first draft of this fix broke it —
`rust:1.85-slim` is a Debian 12 image and `rust:1.98.0-slim` is a Debian 13 one, so bumping
the version alone moved the builder to glibc 2.41 while the runtime stayed on 2.36, and
glibc is backward compatible only. The gate reads a fixed list of locations and extracts one version string
from each, so it admits nothing it was not told to check; it never scans for
version-shaped strings. A comment asking several files to agree is not enforcement, and the repository's
own tenet is to enforce mechanically.

`.github/workflows/fuzz.yml` now names the nightly on every `cargo` command. Those steps
run with the repository root as the working directory, where the root pin applies, and an
explicit `+toolchain` sets `RUSTUP_TOOLCHAIN` for the command and everything it spawns.
The fuzz-crate check in `.github/workflows/ci.yml` already wrote its toolchain that way.

Auditing those steps turned up a second defect that had nothing to do with the pin: all
three fuzz jobs referenced the action as `dtolnay/rust-toolchain@nightly-2026-05-03`, and
that repository publishes `master`, `stable`, `beta`, `nightly`, and a branch per released
version — but no dated-nightly branch. The ref never resolved, so every scheduled Fuzz run
failed at job setup with "unable to find version", and the fuzzer had not executed since
the ref was introduced. No pull request runs the scheduled Fuzz workflow, so its ten
consecutive failures never appeared on one. Naming the date through the `toolchain` input
of `@master`, the form `ci.yml` already used, gives a ref that resolves.

## Raising the Pin

Bumping Rust is a change someone makes on purpose:

1. Raise the version in every location `scripts/check-toolchain-pin.sh` names.
2. Run `mise install`. mise's `RUSTUP_TOOLCHAIN` keeps selecting the previous compiler
   until it does, so the step before this one changes no build.
3. Run `bash scripts/check-toolchain-pin.sh`, which fails until every location and the
   active compiler agree.
4. Run the CI clippy command from the "Orchestrator verification protocol" section of
   CLAUDE.md.
5. Fix everything the new release reports, in that same pull request.

A new stable release then reports its lints to whoever raised the pin, on the pull request
that raised it.
