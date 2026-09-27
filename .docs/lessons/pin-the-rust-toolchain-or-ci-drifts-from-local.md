# Pin the Rust Toolchain Once, and Derive Every Other Consumer From That One File

**What happened**: workflow steps installed `dtolnay/rust-toolchain@stable`, which selects
whatever stable release exists that morning. Rust 1.98.0's clippy added
`chunks_exact_to_as_chunks`, a warn-by-default lint that `clippy::all` carries, and
`Rust / clippy` failed on every branch in the merge queue against untouched code, while
developers on 1.97.1 saw a clean local run. `rust-toolchain.toml` now names the version, and
every other consumer reads it from there; the Toolchain section of AGENTS.md states that
arrangement and how to raise the pin.

## Traps the arrangement had to get past

- **Narrowing the enabled lint groups does not remove the exposure.** A new stable release
  can add a warn-by-default lint to `clippy::all`; dropping `pedantic` would not have
  prevented this outage.
- **`dtolnay/rust-toolchain` reads no toolchain file.** `@stable` installs `stable` and runs
  `rustup default stable`; rustup then applies `rust-toolchain.toml` as a directory override,
  so cargo still compiles on the pin. To make the action install a specific version, read the
  channel in a prior step and pass it as the `toolchain` input to `@master`. The action
  publishes no dated-nightly branch, so a ref of the form `@nightly-<date>` never resolves and
  the job dies at setup.
- **`RUSTUP_TOOLCHAIN` holds one value per shell and overrides a toolchain file entirely**, so
  no tool that exports it can serve a repository whose `fuzz/` directory needs a nightly while
  the workspace needs stable. mise exports it only for a Rust toolchain it has installed,
  which is why the same `.mise.toml` looks inert on one machine and overrides the pin on
  another. `mise tool rust` names the file a value came from; `mise config ls` lists every file
  mise loaded, including those in ancestor directories.
- **A skip branch states a claim, and its condition must entail the claim.** The first
  `scripts/check-resolved-rustc.sh` skipped when rustup listed no pinned toolchain and
  reported "no compiler has resolved here". `rustup override set`, a Homebrew `rustc` ahead of
  `~/.cargo/bin` on `PATH`, a mise shim, and a rustup whose subcommands fail silently in an
  untrusted-mise directory (where every fresh `git worktree add` starts) each satisfy that
  condition while a non-pinned compiler answers cargo. A condition that reads a command's
  output must also read its exit status, because a failed command's empty output satisfies
  any "the list holds no entry" test.
- **Ask of every guard around a check whether it lets the check run in the state it exists
  to catch.** In the pre-commit hook the compiler comparison first sat behind "the commit
  stages a `.rs` file", which excluded commits touching only `Cargo.toml`,
  `.cargo/config.toml`, a workflow, or a gate script.
- **A container base tag selects a Debian release, and glibc is only backward compatible.**
  `rust:1.85-slim` is bookworm and `rust:1.98.0-slim` is trixie. A builder stage newer than
  the runtime stage produces binaries that die with ``version `GLIBC_2.xx' not found``, so name
  the same release in both stages.
