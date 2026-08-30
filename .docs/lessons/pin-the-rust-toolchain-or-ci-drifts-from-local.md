# Pin the Rust Toolchain Once, and Derive Every Other Consumer From That One File

**Problem**: a workflow step that installs `dtolnay/rust-toolchain@stable` selects whichever
stable release exists on the morning the job runs. Rust 1.98.0's clippy added
`chunks_exact_to_as_chunks`, a warn-by-default `style` lint that `clippy::all` carries, so
the `Rust / clippy` required check started failing on every branch in the merge queue
against code nobody had touched. Developers still on 1.97.1 ran the identical command,
saw a clean pass, and reported the failure as unreproducible. CLAUDE.md requires running CI
locally before pushing, and that requirement decides nothing while the local run and the CI
run resolve different compilers.

## Rules

- **Name the compiler version in exactly one file, and make every other consumer read the
  version out of that file.** A second file that names the version is the defect, and a
  gate asserting that two files agree is a workaround for that defect.
  `rust-toolchain.toml` is that file here, because `cargo` and `rustup` read it natively,
  without anything having to tell them where to look.
- **A new stable release can add a warn-by-default lint that `clippy::all` carries, so
  narrowing the enabled lint groups does not remove the exposure.** Dropping `pedantic`
  from `[workspace.lints.clippy]` would not have prevented this outage.
- **A single-source design is not finished while the commands people are told to run still
  type the version.** Moving the version out of the configuration files, and leaving it
  written into the documented `cargo` and `rustup` invocations, leaves the same defect in
  the documentation.
- **`dtolnay/rust-toolchain` reads no toolchain file.** Its `action.yml` performs no
  filesystem read of the checkout, so `@stable` installs rustup's `stable` and runs
  `rustup default stable`. rustup then applies `rust-toolchain.toml` as a directory
  override, which beats `rustup default`, so every cargo command in the job compiles on the
  pin regardless. A workflow that needs the action itself to install a specific version
  reads the channel in a prior step and passes it as the `toolchain` input to `@master`.
  That repository publishes `master`, `stable`, `beta`, `nightly`, and a branch per released
  version, and publishes no dated-nightly branch, so a ref of the form `@nightly-<date>`
  never resolves and every job referencing it dies at job setup.
- **A tool that exports one toolchain value per shell cannot serve a repository that
  resolves a different toolchain per directory.** `RUSTUP_TOOLCHAIN` overrides a toolchain
  file entirely — channel, components, and targets alike — and holds one value for the whole
  shell, while `rust-toolchain.toml` names the stable release the workspace compiles on and
  `fuzz/rust-toolchain.toml` names the nightly cargo-fuzz needs. Deriving that tool's
  exported value from the right file removes the disagreement between two files, and it
  does not give one variable two values. Take the tool out of that job instead: `.mise.toml`
  names no Rust version, and rustup reads the toolchain file of whichever directory a
  command runs in. mise exports `RUSTUP_TOOLCHAIN` only for a Rust toolchain it has
  installed, so `rust = "stable"` with `stable` installed puts every shell in the repository
  on `stable` while a version mise has not fetched exports nothing — which is why the same
  configuration can look inert on one machine and override the pin on another.
- **State what the derivation does not cover.** It removes every disagreement between two
  files in this repository. It does not remove a `RUSTUP_TOOLCHAIN` that a developer's
  environment exports from somewhere else, so each point that resolves a compiler checks
  for itself: `scripts/hooks/pre-commit` compares `rustc --version` against the workspace
  pin before it runs `cargo fmt` and `cargo clippy`, and `fuzz/build.rs` fails the fuzz
  crate's build when the compiler cargo resolved is not a nightly.
- **A container build's base tag selects a Debian release, and glibc is backward compatible
  only.** A builder stage that links against a newer release's glibc produces binaries that
  cannot exec against an older runtime stage, which dies at startup with
  ``version `GLIBC_2.xx' not found``. An unsuffixed tag hides the release: `rust:1.85-slim`
  is a bookworm image and `rust:1.98.0-slim` is a trixie one. Name the same Debian release
  in both stages, and move both stages together or neither.

## Raising the pin

1. Edit `channel` in `rust-toolchain.toml`. Nothing else names the version.
2. Run the CI clippy command from the "Orchestrator verification protocol" section of
   CLAUDE.md. rustup downloads the new toolchain, its components, and its targets on that
   first cargo invocation.
3. Fix everything the new release reports, in that same pull request. Never lower the pin
   to make a new lint disappear.

## See also

- `.docs/lessons/route-a-changed-file-to-every-lane-it-decides.md` — routing a pin change
  to every CI job that compiles on it.
- `.docs/lessons/a-gate-enumerates-its-population-and-reads-the-parse.md` — the gate that
  checks the wiring this pin cannot derive.
- `.docs/lessons/a-green-check-that-never-met-its-target-proves-nothing.md` — the container
  image and the scheduled workflow that no required check exercised.
