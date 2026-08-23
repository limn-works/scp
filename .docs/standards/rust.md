# Rust Standards

Rust coding standards, safety rules, linting, formatting, testing, and CI for the SCP core crates. For workspace layout, dependency map, and error type definitions, see `.docs/scaffold/rust.md`. References `sdk-common.md` for cross-language invariants and `conventions.md` for git/branch conventions.

## Toolchain

| Tool | Version | Purpose |
|------|---------|---------|
| Rust edition | 2024 | Language edition (all crates) |
| rustc | stable (latest) | Compiler |
| cargo | stable (latest) | Build system, package manager |
| clippy | stable (latest) | Linter |
| rustfmt | stable (latest) | Formatter |
| cargo-deny | latest | Dependency license/advisory audit |
| cargo-nextest | latest | Test runner (parallel, better output) |

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
workspace member**. All `cargo fuzz` commands require nightly:

```sh
cargo +nightly fuzz list --fuzz-dir fuzz          # list all 19 targets
cargo +nightly fuzz run <target> --fuzz-dir fuzz \
  -- -dict=fuzz/dicts/<dict> -max_total_time=60    # run one target locally
cargo +nightly check --manifest-path fuzz/Cargo.toml  # compile-check (no fuzzing)
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

## Clearing a security advisory

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
AWS-LC 1.71.0 to 5.5.0 under all thirteen targets CI builds, for an algorithm this
workspace never asserts; 0.103.13 cleared the same three advisories and moved nothing.
Establish that by evidence: `diff` the candidate's `Cargo.toml` against the current one,
and read the upstream release notes for every version in between.

**Applying the bump.** Use `cargo update -p <crate> --precise <version>`. A bare
`cargo update -p <crate>` re-resolves unrelated edges, so read the whole `Cargo.lock` diff
and revert every change the advisory did not require. Prove the result resolves with
`cargo metadata --locked --all-features`.

**Verifying.** Run the cargo-deny version `EmbarkStudios/cargo-deny-action@v2` pins, not
whatever `cargo install` left on the machine. An older cargo-deny misses whole advisory
classes — 0.19.0 reports nothing for the `unsound` class that 0.20.2 raises as an error —
so a green run from the wrong binary proves nothing, and an `advisory-not-detected`
warning from the wrong binary condemns a live entry. cargo-deny also reports an advisory
against only the highest version of a duplicated crate, so count every copy of the crate
in `Cargo.lock` before calling an advisory cleared.

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
