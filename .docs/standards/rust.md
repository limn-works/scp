# Rust Standards

Rust coding standards, safety rules, linting, formatting, testing, and CI for the SCP core crates. For workspace layout, dependency map, and error type definitions, see `.docs/scaffold/rust.md`. References `sdk-common.md` for cross-language invariants and `conventions.md` for git/branch conventions.

## Toolchain

| Tool | Version | Purpose |
|------|---------|---------|
| Rust edition | 2024 | Language edition (all crates) |
| rustc, cargo, clippy, rustfmt | the `channel` in `rust-toolchain.toml` | Compiler, build system, linter, formatter |
| cargo-deny | latest | Dependency license/advisory audit |
| cargo-nextest | latest | Test runner (parallel, better output) |

**`rust-toolchain.toml` is the one place this repository names a Rust version, and this
table names none.** A version written here would be a second declaration that could
disagree with the pin, which is the defect the single-source design removes. Every consumer
derives the version from that file:

| Consumer | How it reads the pin |
|----------|----------------------|
| `cargo`, `rustup` | natively, for any command run inside the repository; rustup installs the `channel`, `components`, and `targets` the file names on first use |
| `Dockerfile` | copies the file into the builder image before the first cargo command; the base tag names a Debian release only |
| `templates/personal-relay/README.md` | its `COPY . .` brings the file into the image, for the same reason |
| the CI workflows | their `dtolnay/rust-toolchain@stable` steps select no version — that action reads no toolchain file — so each one installs rustup's `stable` and runs `rustup default stable`, and rustup then applies `rust-toolchain.toml` as a directory override, which beats the default |

`fuzz/rust-toolchain.toml` names the nightly the standalone fuzz crate needs, because
cargo-fuzz does not run on stable. rustup applies the toolchain file of the directory a
command runs in, so every documented fuzz command runs from inside `fuzz/` and names no
channel; the fuzz check in `.github/workflows/ci.yml` does the same with
`working-directory: fuzz`. `.github/workflows/fuzz.yml` runs `cargo fuzz --fuzz-dir fuzz`
from the repository root so its corpus-cache paths and its command paths agree, so it reads
the channel out of the file in one job and passes that output to the others.

**mise names no Rust version and installs no Rust toolchain.** mise exports one
`RUSTUP_TOOLCHAIN` for every command it runs, computed from the directory the shell sat in,
and that variable overrides a toolchain file entirely — channel, components, and targets
alike. This repository resolves two compilers by directory, so one exported value cannot
serve both: a mise Rust version source puts every command in `fuzz/` on the workspace's
stable pin, where cargo-fuzz's `-Z` flags are rejected. rustup resolves both with no
variable involved, `README.md` lists rustup among the prerequisites, and
`scripts/check-toolchain-wiring.sh` fails when `.mise.toml` names a Rust version source
again. A `RUSTUP_TOOLCHAIN` exported from anywhere else still overrides both files:
`scripts/hooks/pre-commit` compares `rustc --version` against the workspace pin before it
runs cargo, and `fuzz/build.rs` fails the fuzz build when that crate resolves a compiler
`fuzz/rust-toolchain.toml` does not name.

To raise the version: edit `channel` in `rust-toolchain.toml`, run the CI clippy command,
and fix everything the new release reports in that same pull request. rustup downloads the
new toolchain the first time a cargo command runs in the repository. Never lower the pin to
make a new lint disappear.

Before the pin existed, every CI workflow installed `dtolnay/rust-toolchain@stable`, which
resolves to whichever stable release exists on the morning a job runs. Rust 1.98.0 shipped
on 2026-08-20 with two new lints — one warn-by-default `style` lint and one `pedantic` lint,
so no group setting would have avoided it — and the `Rust / clippy` required check failed on
every branch overnight while local runs on 1.97.1 reported a clean pass. See
`.docs/lessons/pin-the-rust-toolchain-or-ci-drifts-from-local.md`.

`scripts/check-toolchain-wiring.sh` checks the three properties the derivation cannot
supply.

First, that every file Docker builds from a `rust` base image carries the ASSERT-PINNED-RUSTC
block: the base tag names a Debian release and no compiler, so the copied-in file is what
selects the version, and those three lines make the build compare the compiler it resolved
against the channel that file names. A container build without them compiles on whatever
the image ships and succeeds.

The gate decides which files Docker builds by path, through two rules. A basename Docker
builds is one: `Dockerfile`, `Dockerfile.<suffix>`, `<prefix>.Dockerfile`, and the three
`Containerfile` spellings. Prose the gate's own BUILT_FROM_DOCUMENTATION list names is the
other, and `templates/personal-relay/README.md` is the entry there, because that document
tells an operator to save its container block and build it. Prose that only quotes a
container build carries no assertion; when such a document holds a `FROM` line naming a
rust image, its author lists it in the gate's QUOTES_A_CONTAINER_BUILD instead, and the gate
fails on a file neither list names. Writing a container build under a name outside the first
rule is therefore still caught, and quoting a Dockerfile in an architecture decision record
or a runbook no longer forces the author to break the quotation.

That classification search matches a whole `FROM` instruction, written to Dockerfile's
grammar for it: an optional flag, an image reference, an optional tag or digest, an
optional `AS <name>`, and then the end of the line. The end-of-line anchor keeps English
prose out. Docker permits nothing after the image reference but `AS <name>`, so a Markdown
line reading "from rust sources by uniffi." cannot be a FROM instruction, and an earlier
expression that stopped at the image reference failed the gate on exactly that sentence.

Second, that every workflow whose jobs a paths filter guards routes a change to the jobs
that build from it. Each job that compiles a crate of this workspace is guarded by
`if: needs.changes.outputs.<lane> == 'true'`, and a skipped job reports success rather than
absence: the `ci` job that aggregates every other job's result counts a skip as a pass, and
so does branch protection. An unrouted change therefore merges with every job that reads it
skipped. In `.github/workflows/ci.yml` the pin decides seven lanes, not one:

| Lane | The jobs it guards whose behaviour the pin decides |
|--------|----------------------------------------------------|
| `rust` | `rust-fmt`, `rust-clippy`, `rust-test`, `rust-test-napi-production`, `rust-build-pyo3-production`, `rust-build-uniffi-production`, `rust-doc`, `rust-deny`, and `docker-image` |
| `python` | `python-test` runs `maturin develop --release` |
| `typescript` | `typescript-check` runs `cargo build -p scp-ffi-napi --release` |
| `typescript-wasm` | `typescript-wasm-check` runs `wasm-pack build` from the repository root |
| `scaffold-typescript-web` | `scaffold-typescript-web-check` builds `bindings/typescript-wasm`, which runs that same `wasm-pack build` |
| `kotlin` | `kotlin-test` runs `cargo build -p scp-ffi-uniffi --features testing` |
| `swift` | `swift-build-test` runs `bindings/swift/build-xcframework.sh --dev`, which calls `cargo build` |

Rather than list the pin in seven filters, the `changes` job declares one `toolchain`
filter and ORs it into every lane's output, so the workflow names each file that filter
holds once. That filter holds two: `rust-toolchain.toml`, and `.cargo/**`, because cargo
reads a `.cargo/config.toml` out of every ancestor of the directory a command runs in, and
this repository's root one sets the rustflag that selects getrandom's wasm backend. The
gate reads the set of outputs out of the workflow, so a lane added later without the OR
fails it.

`.github/workflows/docs.yml` carries the same two pieces for the same reason: its
`rust-docs` job runs `cargo doc --workspace --document-private-items`, which compiles every
crate on the pinned compiler, and it is the one job in this repository that runs rustdoc
over the whole workspace while `scp-runtime` denies `rustdoc::broken_intra_doc_links`. The
gate enumerates the workflows it checks from the tree — each tracked file under
`.github/workflows/` whose extension GitHub Actions runs and that declares a
`dorny/paths-filter` step — so a paths-filtered workflow added later is covered without
anyone editing the gate. A workflow that narrows itself with `on: pull_request: paths:`
instead needs no `toolchain` filter: a required check whose workflow never starts stays
pending and blocks the merge, so that mechanism fails closed on its own.

The gate also enumerates two populations of file and requires each member to be routed by
an entry of the `rust` or `toolchain` filter, or declared in the gate's own list of files
no compile reads: every root-level file, and — derived from cargo's documented
configuration discovery — every `.cargo/config.toml` and `.cargo/config` in the tree at any
depth. Both populations share the criterion that a pull request editing one member and
nothing else is rare, so an omitted entry stays invisible. A file added to either
population fails the gate until someone classifies it. The `fuzz` lane is exempt from the
pin: `fuzz-build` runs `cargo check` with `working-directory: fuzz`, where rustup resolves
`fuzz/rust-toolchain.toml`, and the `fuzz` filter's `fuzz/**` entry covers that file.

Third, that `.mise.toml` names no Rust version source, for the reason the mise paragraph
above states. The gate parses that file with `tomllib` and asks whether the `tools` table
holds a `rust` key, rather than matching a line: TOML reaches one key many ways, and mise
2026.2.22 resolves `rust` to the same version through all eight of `rust = "…"`,
`rust = { version = "…" }`, `"rust" = "…"`, `[tools.rust]`, `[tools."rust"]`,
`tools.rust = "…"`, `rust.version = "…"`, and `rust = ["…"]`. The line matcher the check ran
before read four of the eight and reported OK for the other four.

The `Dockerfile` base tag selects a Debian release, so keep the builder stage and the
runtime stage on the same one. The builder reads `rust:slim-bookworm` and the runtime reads
`debian:bookworm-slim`, which are both Debian 12. Writing `rust:slim` instead would select
Debian 13, and because glibc is backward compatible only, a binary the builder linked
against that release's glibc 2.41 fails to exec against Debian 12's glibc 2.36.

## Safety Rules

```rust
#![forbid(unsafe_code)]
```

Every crate sets `#![forbid(unsafe_code)]` at the crate root. Unsafe code is forbidden across the entire workspace. If an FFI bridge crate requires unsafe (e.g., cbindgen C ABI), it is the sole exception and must document every `unsafe` block with a `// SAFETY:` comment explaining the invariant.

Additional enforced rules:
- No `unwrap()` or `expect()` in library code — use `?` with typed errors
- No `panic!()` in library code — return `Result` instead
- No `println!()` — use `tracing` for all output
- No `std::sync::Mutex` — use `tokio::sync::Mutex` for async contexts
- No blocking I/O in async functions — use `tokio::fs`, `tokio::net`, etc.

## Error Types

Every crate defines errors via `thiserror`, following the hierarchy in `sdk-common.md`. See `.docs/scaffold/rust.md` for the full enum definition and variant structure.

## Clippy Configuration

`.clippy.toml` at workspace root:

```toml
cognitive-complexity-threshold = 25
```

`Cargo.toml` workspace-level lint configuration:

```toml
[workspace.lints.clippy]
all = "warn"
pedantic = "warn"
nursery = "warn"
cargo = "warn"
unwrap_used = "deny"
expect_used = "deny"
panic = "deny"
todo = "deny"
unimplemented = "deny"
```

## Rustfmt Configuration

`rustfmt.toml` at workspace root:

```toml
edition = "2024"
max_width = 100
tab_spaces = 4
use_field_init_shorthand = true
use_try_shorthand = true
# imports_granularity = "Crate"      # Requires nightly rustfmt
# group_imports = "StdExternalCrate" # Requires nightly rustfmt
```

`imports_granularity` and `group_imports` are the desired import style but require nightly rustfmt. They are commented out in `rustfmt.toml` and enforced by convention and code review until stabilized. Follow the grouping order from `conventions.md` manually: std, external, local.

## Testing

### Unit tests

- Tests live in `#[cfg(test)] mod tests { }` blocks within source files
- Use `proptest` for property-based testing on all crypto operations
- Use `tokio::test` for async test functions

### Integration tests

- Live in `tests/` directory at crate root
- One file per integration scenario
- Phase integration tests (see ADR phase documents) live in `tests/integration/`

### Property-based testing (proptest)

Required for:
- All crypto operations (MLS encrypt/decrypt roundtrip, signature verify, HKDF derivation)
- Envelope serialization/deserialization roundtrip
- Event log Merkle proof verification
- UCAN attenuation chain validation
- Bucket padding roundtrip

```rust
use proptest::prelude::*;

proptest! {
    #[test]
    #[allow(clippy::unwrap_used)]  // proptest requires infallible runtime setup
    fn encrypt_decrypt_roundtrip(plaintext in any::<Vec<u8>>()) {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let group = create_test_group().await;
            let ciphertext = encrypt(&group, &plaintext).await.unwrap();
            let decrypted = decrypt(&group, &ciphertext).await.unwrap();
            prop_assert_eq!(plaintext, decrypted);
            Ok(())
        })?;
    }
}
```

### Fuzzing (cargo-fuzz)

SCP uses cargo-fuzz (libFuzzer) for parser safety and security invariant testing at trust
boundaries. The fuzz crate lives at `fuzz/` (repo root) — a **standalone crate, not a
workspace member**. All `cargo fuzz` commands require the one nightly that `fuzz/rust-toolchain.toml` pins —
nightlies after that date reject openmls 0.8.1's prelude re-export (E0365):

```sh
cd fuzz && cargo fuzz list          # list all 27 targets
cd fuzz && cargo fuzz run <target> \
  -- -dict=fuzz/dicts/<dict> -max_total_time=60    # run one target locally
cd fuzz && cargo check              # compile-check (no fuzzing)
```

**Tier strategy** (ADR-045):

| Tier | Focus | Input strategy | CI |
|------|-------|----------------|-----|
| T1 — Wire parsers | B1 relay wire, B2 post-MLS | Raw bytes + dictionary | Nightly, 15 min |
| T2 — Content trust | B2 content, B3 resolution | Raw bytes + dictionary | Nightly, 5 min |
| T3 — Invariants | Security properties, roundtrips | Raw bytes or `Arbitrary` | Local/manual |
| T4 — Deep validation | Paths requiring semantic validity | `Arbitrary` + real crypto | Local/manual |

**When to add a new fuzz target:**

1. A new type has a `from_bytes` or `from_str` entry point at a trust boundary (B1/B2/B3).
   → Add a Tier 1 or Tier 2 raw-bytes target.
2. A security invariant (I1–I10 in `fuzz/README.md`) is not yet covered by any target.
   → Add a Tier 3 or Tier 4 target.
3. A new enum variant or struct field is added to a fuzzed type.
   → Update the corresponding dictionary in `fuzz/dicts/`.

**Do NOT use `Arbitrary` for parser targets (T1/T2).** Raw bytes give libFuzzer direct
mutation-coverage feedback. `Arbitrary` wrappers cause the fuzzer to mutate the Arbitrary
encoding rather than the parser input, breaking coverage guidance. See
`.docs/lessons/fuzz-raw-bytes-over-arbitrary-wrappers.md`.

**Do NOT replicate private production functions in fuzz targets.** Replicas drift silently.
Prefer promoting the function to `#[doc(hidden)] pub` so the fuzz target calls the real
implementation. See `.docs/lessons/fuzz-replica-production-type-drift.md`.

**Size-gate before deserialization.** Any `from_bytes` function on a type with
`#[serde(flatten)]` fields MUST check `data.len() > MAX_SIZE` before calling
`rmp_serde::from_slice`. See `.docs/lessons/serde-flatten-rmpv-value-buffering.md`.

See `fuzz/README.md` for the full target inventory, crash workflow, and corpus management.
See `fuzz/.claude/CLAUDE.md` for agent-facing conventions.

### Test naming

```rust
#[test]
fn create_group_returns_group_with_one_member() { }

#[test]
fn encrypt_rejects_empty_plaintext() { }

#[test]
fn remove_member_advances_epoch() { }
```

Format: `{action}_{condition_or_expected_result}`.

## Async Patterns

- All I/O-bound operations are `async`
- Use `tokio::spawn` for concurrent tasks
- Use `tokio::select!` for racing futures
- Use `futures::StreamExt` for stream operations
- Cancellation safety: all async functions must be cancellation-safe or documented as not

## Documentation

- All public items have `///` doc comments
- Crate-level docs in `src/lib.rs` with `//!`
- Module-level docs in `mod.rs` with `//!`
- Examples in doc comments use ```` ```rust ```` blocks that compile (`cargo test --doc`)
- Cross-reference ADRs in doc comments: `/// See ADR-001 for MLS wrapper design.`

## CI Commands

```bash
# Format check
cargo fmt --all -- --check

# Lint
cargo clippy --workspace --all-targets -- -D warnings

# Build (all crates)
cargo build --workspace

# Test (all crates)
cargo nextest run --workspace

# Doc tests
cargo test --workspace --doc

# Dependency audit
cargo deny check

# Generate docs
cargo doc --workspace --no-deps
```

## Clearing a Security Advisory

When a RUSTSEC advisory names a workspace dependency, bump the dependency. Add a
`deny.toml` ignore entry only when no released version clears the advisory, or when a
dependency this workspace does not control blocks the upgrade. State that blocking
upgrade in the entry's comment, and delete the entry in the same change that takes the
fix — an ignore entry for a patched advisory is a false record.

**Choosing the version.** Take the newest release whose dependency floors this workspace
already satisfies. Reject a newer release that raises a floor on a native-code dependency
to supply a capability the workspace does not use, because recompiling a vendored C
library across every cross-compiled target adds build risk and no security. The case that
produced this rule: rustls-webpki 0.103.14 raised its `aws-lc-rs` floor from 1.14 to 1.18
to expose ML-DSA, which would have moved `aws-lc-sys` 0.39.0 to 0.44.0 and its vendored
AWS-LC 1.71.0 to 5.5.0 under twelve of the thirteen targets CI compiles for — every
one but `wasm32-unknown-unknown`: the packages CI compiles for that target
(`scp-client-wasm`, `scp-mls`, `scp-relay-client`, and their wasm-safe leaves) pull in
no `aws-lc-sys`, though a workspace-wide `cargo tree --target wasm32-unknown-unknown`
does show it, via `scp-node`, which CI never builds for wasm32 — for an algorithm this
workspace never asserts; 0.103.13 cleared the same three advisories and moved nothing.
Establish that by evidence: `diff` the candidate's `Cargo.toml` against the current one,
and read the upstream release notes for every version in between.

**Applying the bump.** Use `cargo update -p <crate> --precise <version>`. A bare
`cargo update -p <crate>` re-resolves unrelated edges, so read the whole `Cargo.lock` diff
and revert every change the advisory did not require. Prove the result resolves with
`cargo metadata --locked --all-features`.

**Verifying.** Run the cargo-deny version `EmbarkStudios/cargo-deny-action@v2` pins, not
whatever `cargo install` left on the machine. CI's verdict is the one that gates the merge,
so a local run only predicts CI when the binary matches. `.mise.toml` declares
`"cargo:cargo-deny" = "latest"`, which pins nothing and drifts, so check the installed
version rather than assuming the toolchain manifest supplied the pinned one. Two
diagnostics decide the outcome and both are version-sensitive: an `error` fails the run,
and an `advisory-not-detected` warning marks an ignore entry as unnecessary. Do not delete
an entry on an `advisory-not-detected` from an unpinned binary. Count every copy of the crate in
`Cargo.lock` before calling an advisory cleared: a bump that adds a patched version on top
of unpatched duplicates leaves the unpatched ones compiling into the shipped artifact.
Measured on 0.20.2, cargo-deny does emit one diagnostic per affected copy — both
`libcrux-sha3 0.0.6` and `0.0.7` are reported — so the count is a check on the fix, not a
compensation for the tool.

## CI Matrix

Tests are organized into three tiers. See `specs/16-test-infrastructure.md` §16.15 for the full tier definitions, §16.13 test assignments, and feature flag conventions.

### Tier 1 — PR Checks

Every push to a PR branch. Target: < 3 minutes.

| Job | Runs on | Command |
|-----|---------|---------|
| fmt | ubuntu-latest | `cargo fmt --all -- --check` |
| clippy | ubuntu-latest | `cargo clippy --workspace --all-targets -- -D warnings` |
| test | ubuntu-latest, macos-latest | `cargo nextest run --workspace` |
| build-release | ubuntu-latest, macos-latest, windows-latest | `cargo build --workspace --release` |
| doc | ubuntu-latest | `cargo test --workspace --doc && cargo doc --workspace --no-deps` |
| deny | ubuntu-latest | `cargo deny check` |

Unit tests and conformance macro suites (`transport_conformance!()`, `storage_conformance!()`, etc.) run as part of `cargo nextest run --workspace` against in-memory implementations.

### Tier 2 — Merge Gate

Merge queue entry or push to `main`. Target: < 10 minutes. Required to merge.

| Job | Runs on | Command |
|-----|---------|---------|
| All Tier 1 jobs | (same as above) | (same as above) |
| harness meta-tests | ubuntu-latest, macos-latest | `cargo nextest run --workspace --features scp-testing/ci-tier2` |
| phase integration | ubuntu-latest | `cargo nextest run --workspace --features scp-testing/ci-tier2 -E 'test(phase_integration)'` |

Harness meta-tests cover §16.13.1–10: InMemoryRelay, InMemoryTransport, SimulatedClock, NetworkTopology, ScenarioBuilder, determinism, ProtocolRepository, MlsStorageBridge, assertion library, and preset scenario validation. Phase integration runs the current phase's end-to-end test (P1 in Phase 1, P2 in Phase 2, etc.).

### Tier 3 — Nightly / Pre-Release

Scheduled (nightly) or manual trigger. Uncapped duration. Failures create issues but do not block merges.

| Job | Runs on | Command |
|-----|---------|---------|
| All Tier 2 jobs | (same as above) | (same as above) |
| proptest extended | ubuntu-latest | `cargo nextest run --workspace --features scp-testing/ci-tier3 -E 'test(proptest)'` |
| N-party simulation (multi-seed) | ubuntu-latest | `cargo nextest run --workspace --features scp-testing/ci-tier3 -E 'test(preset_.*_all_seeds)'` |
| persistent backend conformance | ubuntu-latest | `cargo nextest run --workspace --features scp-testing/ci-tier3 -E 'test(conformance.*sqlite\|conformance.*redb)'` |
| load testing | ubuntu-latest | `cargo nextest run --workspace --features scp-testing/ci-tier3 -E 'test(load_test)'` (Phase 6) |

`deny` also runs weekly on a schedule independent of all tiers.
