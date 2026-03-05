# Testing Guide

How to run tests, write tests, and debug failures across all SCP languages.

Source: `.docs/specs/21-documentation.md` section 21.7.

---

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Running Tests](#running-tests)
3. [Writing Unit Tests](#writing-unit-tests)
4. [Writing Integration Tests](#writing-integration-tests)
5. [Conformance Macros](#conformance-macros)
6. [Property-Based Tests](#property-based-tests)
7. [Debugging Failures](#debugging-failures)
8. [CI](#ci)

---

## Prerequisites

All tools are managed by [mise](https://mise.jdx.dev/). See `.mise.toml` for versions.

**Python linkage (required for Rust tests).** The `scp-ffi-uniffi` crate links against `libpython`. Every Rust test command needs the Python library directory on the dynamic linker path.

macOS:

```bash
export DYLD_LIBRARY_PATH="$(python3.12 -c 'import sysconfig; print(sysconfig.get_config_var("LIBDIR"))')"
```

Linux:

```bash
export LD_LIBRARY_PATH="$(python3.12 -c 'import sysconfig; print(sysconfig.get_config_var("LIBDIR"))')"
```

**CI feature flags.** Clippy and tests in CI enable extra features. Always use these locally to catch the same errors CI catches:

```
--features scp-ffi-uniffi/allow_in_memory_custody,scp-core/testing
```

**Kotlin.** Needs JAVA_HOME set via mise:

```bash
eval "$(mise env)"
```

---

## Running Tests

### Rust

The workspace uses `cargo nextest` (not `cargo test`) as the test runner. It provides parallel execution and better failure output.

```bash
# Run all workspace tests (unit + integration + conformance)
cargo nextest run --workspace --features scp-ffi-uniffi/allow_in_memory_custody,scp-core/testing

# Run doc tests (nextest does not run doc tests; use cargo test)
cargo test --workspace --doc --features scp-ffi-uniffi/allow_in_memory_custody,scp-core/testing

# Run tests for a single crate
cargo nextest run -p scp-core --features scp-core/testing

# Run a specific test by name
cargo nextest run -p scp-core -E 'test(encrypt_decrypt_roundtrip)'

# Format check
cargo fmt --all -- --check

# Lint (must match CI exactly)
cargo clippy --workspace --all-targets --features scp-ffi-uniffi/allow_in_memory_custody,scp-core/testing -- -D warnings

# Dependency audit
cargo deny check
```

### Python

```bash
cd bindings/python
pip install pytest pytest-asyncio ruff
ruff format --check .
ruff check .
PYTHONPATH=. pytest tests/ -v
```

### TypeScript

Never use npm or npx. Bun only.

```bash
cd bindings/typescript
bun install
bun run check    # tsc --noEmit
bun run lint     # biome lint
bun test
```

### Kotlin

```bash
cd bindings/kotlin
eval "$(mise env)"
./gradlew test
```

---

## Writing Unit Tests

### Location

Rust unit tests live inside the source file, in a `#[cfg(test)] mod tests` block at the bottom:

```rust
// src/envelope/inner.rs

// ... production code ...

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn create_and_verify_roundtrip() {
        // ...
    }
}
```

The `#[allow(...)]` attributes are required because the workspace denies `unwrap_used`, `expect_used`, and `panic` in library code. Tests are the exception.

### Naming convention

Format: `{action}_{condition_or_expected_result}`

```rust
#[test]
fn create_group_returns_group_with_one_member() { }

#[test]
fn encrypt_rejects_empty_plaintext() { }

#[test]
fn remove_member_advances_epoch() { }

#[tokio::test]
async fn verify_rejects_wrong_public_key() { }

#[tokio::test]
async fn store_and_load_context_state_roundtrip() { }

#[tokio::test]
async fn load_context_state_returns_none_for_missing() { }
```

The action comes first (`create`, `encrypt`, `verify`, `store`, `load`, `remove`, `delete`). The rest describes either the condition being tested or the expected outcome.

See `.docs/standards/rust.md` for the full testing standard.

### Template

```rust
#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    // Helper: create test fixtures shared across tests in this module.
    fn test_did() -> DID {
        DID::new("did:dht:test123")
    }

    #[tokio::test]
    async fn action_returns_expected_result() {
        // Arrange
        let store = InMemoryStorage::new();
        let did = test_did();

        // Act
        let result = some_operation(&store, &did).await.unwrap();

        // Assert
        assert_eq!(result.field, expected_value);
    }

    #[tokio::test]
    async fn action_rejects_invalid_input() {
        let store = InMemoryStorage::new();

        let result = some_operation(&store, &bad_input()).await;

        assert!(result.is_err());
    }
}
```

### Async tests

Use `#[tokio::test]` for any test that calls async functions. The workspace uses tokio as its async runtime.

---

## Writing Integration Tests

Integration tests live in `tests/` directories at the crate root. One file per scenario.

### Phase integration tests

The phase integration tests in `crates/scp-testing/tests/integration/` are the canonical templates for writing new integration tests. They exercise the full protocol stack end-to-end.

| File | What it proves |
|------|---------------|
| `phase1.rs` | All 7 Phase 1 ADRs work together: identity creation (ADR-003), MLS groups (ADR-001), sender keys (ADR-007), envelope encryption (ADR-002), relay transport (ADR-004, ADR-005), key custody (ADR-006) |
| `protocol_store.rs` | Every `ProtocolStore` domain module through the full `ProtocolStore -> Storage -> Backend` path |
| `persistence.rs` | Persistence layer roundtrips |
| `persistence_advanced.rs` | Advanced persistence scenarios |

**Use `phase1.rs` as a starting point for new integration tests.** It follows this structure:

1. File-level `#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]` -- integration tests can unwrap freely.
2. Import production types (not mocks) from the crates under test.
3. Set up real infrastructure (in-memory relay, in-memory storage, in-memory key custody).
4. Exercise the full protocol path -- identity creation through message delivery.
5. Assert on end-to-end outcomes, not intermediate state.

```rust
// crates/scp-testing/tests/integration/phase1.rs (abbreviated)
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use scp_core::crypto::mls::group::{ScpMlsGroup, create_group, generate_key_package};
use scp_identity::{DidDht, DidMethod, ScpIdentity};
use scp_platform::testing::InMemoryKeyCustody;
use scp_transport::native::server::{RelayConfig, RelayServer};
// ... full protocol stack imports ...

#[tokio::test]
async fn phase1_alice_bob_encrypted_message_exchange() {
    // 1. Create identities
    // 2. Create MLS group
    // 3. Exchange key packages
    // 4. Encrypt and send message through relay
    // 5. Receive and decrypt
    // 6. Assert content matches
}
```

See `crates/scp-testing/tests/integration/phase1.rs` for the full implementation.

---

## Conformance Macros

Conformance macros generate test suites that validate trait implementations against the protocol specification. They live in `crates/scp-testing/src/conformance/`.

### Available macros

| Macro | Tests | Validates | Spec reference |
|-------|-------|-----------|----------------|
| `storage_conformance!()` | 13 | `Storage` trait (store, retrieve, delete, list, exists) | sections 17.11, 17.13 |
| `blob_store_conformance!()` | 19 | `BlobStorage` trait (store, get, query, delete, TTL, streaming) | sections 17.11, 17.13 |
| `payment_adapter_conformance!()` | 8 | `PaymentAdapter` trait (authorize, capture, void, verify, refund) | section 19.2.6 |

`transport_conformance!()` is specified (section 16.12.1) but not yet implemented in code.

### How they work

Each macro takes a factory expression that creates a fresh instance of the implementation under test. The macro expands into a `mod` containing individual `#[tokio::test]` functions -- one per conformance requirement.

```rust
// The macro call:
storage_conformance!(InMemoryStorage::new());

// Expands to:
mod storage_conformance {
    #[tokio::test]
    async fn roundtrip() { /* ... */ }

    #[tokio::test]
    async fn missing_returns_none() { /* ... */ }

    #[tokio::test]
    async fn delete_removes_value() { /* ... */ }

    // ... 10 more tests ...
}
```

### Using conformance macros

**`storage_conformance!`** -- pass an expression that returns `impl Storage`:

```rust
use scp_testing::storage_conformance;

storage_conformance!(InMemoryStorage::new());
```

Source: `crates/scp-testing/src/conformance/storage.rs`

**`blob_store_conformance!`** -- pass an expression that returns `(impl BlobStorage, Arc<AtomicU64>)`. The `AtomicU64` is a controllable clock for deterministic TTL and purge tests:

```rust
use scp_testing::blob_store_conformance;
use std::sync::Arc;
use std::sync::atomic::AtomicU64;

fn make_store() -> (InMemoryBlobStorage, Arc<AtomicU64>) {
    let clock = Arc::new(AtomicU64::new(1_000_000));
    let clock_fn = {
        let c = clock.clone();
        Arc::new(move || c.load(std::sync::atomic::Ordering::Relaxed))
    };
    let store = InMemoryBlobStorage::with_clock(clock_fn);
    (store, clock)
}

blob_store_conformance!(make_store());
```

Source: `crates/scp-testing/src/conformance/blob_store.rs`

**`payment_adapter_conformance!`** -- pass an expression that returns `impl PaymentAdapter`:

```rust
use scp_testing::payment_adapter_conformance;

payment_adapter_conformance!(TestAdapter::new());
```

Source: `crates/scp-testing/src/conformance/payment.rs`

### Writing a new conformance suite

To write a conformance macro for a new trait:

1. Create `crates/scp-testing/src/conformance/your_trait.rs`.
2. Define a `macro_rules!` macro that takes a factory expression.
3. Use `#[macro_export]` so consumers can invoke it from their crate.
4. Generate a `mod your_trait_conformance` containing one `#[tokio::test]` per spec requirement.
5. Add the module to `crates/scp-testing/src/conformance/mod.rs`.
6. Reference the spec section the macro validates in the module doc comment.
7. Invoke the macro against your reference (in-memory) implementation in `crates/scp-testing/src/`.

Follow the existing macros as templates. See `crates/scp-testing/src/blob_store_tests.rs` for a concrete example of invoking a conformance macro against an in-memory implementation.

---

## Property-Based Tests

Property-based testing uses `proptest`. It is **required** for:

- All crypto operations (MLS encrypt/decrypt roundtrip, signature verification, HKDF derivation)
- Envelope serialization/deserialization roundtrip
- Event log Merkle proof verification
- UCAN attenuation chain validation
- Bucket padding roundtrip

### Where they live

Property tests are defined inline in `#[cfg(test)]` modules alongside the code they test. Examples:

- `crates/scp-core/src/envelope/inner.rs` -- inner envelope create/verify roundtrip
- `crates/scp-core/src/envelope/outer.rs` -- outer envelope seal/open roundtrip
- `crates/scp-core/src/envelope/padding.rs` -- bucket padding roundtrip
- `crates/scp-core/src/crypto/ucan/capability.rs` -- UCAN capability validation
- `crates/scp-core/src/crypto/sender_keys/encrypt.rs` -- sender key encrypt/decrypt roundtrip
- `crates/scp-core/src/crypto/sender_keys/broadcast.rs` -- broadcast key operations
- `crates/scp-core/src/crypto/mls/encrypt.rs` -- MLS encrypt/decrypt roundtrip

### Template

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

Key points:

- `proptest!` blocks cannot use `#[tokio::test]`. Create a `tokio::runtime::Runtime` manually inside the test body.
- `#[allow(clippy::unwrap_used)]` is needed because `proptest` requires `unwrap()` for runtime construction.
- Use `prop_assert!` and `prop_assert_eq!` instead of `assert!` and `assert_eq!` so proptest can report the shrunk counterexample.
- Return `Ok(())` from the async block (or `?` from the `prop_assert` macros) to propagate failures properly.

### Controlling iteration count

By default, proptest runs 256 cases. Nightly CI (Tier 3) runs extended proptest suites with higher iteration counts via the `scp-testing/ci-tier3` feature flag.

---

## Debugging Failures

### Common error patterns

**`DYLD_LIBRARY_PATH` / `LD_LIBRARY_PATH` not set:**

```
error while loading shared libraries: libpython3.12.so.1.0: cannot open shared object file
```

or on macOS:

```
dyld: Library not loaded: @rpath/libpython3.12.dylib
```

Fix: export the library path as shown in [Prerequisites](#prerequisites).

**Missing CI feature flags:**

```
error[E0432]: unresolved import `scp_platform::testing::InMemoryKeyCustody`
```

or clippy errors that don't reproduce locally. Fix: add `--features scp-ffi-uniffi/allow_in_memory_custody,scp-core/testing` to your command.

**`unwrap_used` / `expect_used` / `panic` in test code:**

```
error: usage of `unwrap`
  --> crates/scp-core/src/foo.rs:123:10
```

Fix: add the allow attributes to your test module:

```rust
#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests { /* ... */ }
```

For integration test files, add at the file level:

```rust
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
```

**Kotlin JAVA_HOME not set:**

```
ERROR: JAVA_HOME is not set
```

Fix: `eval "$(mise env)"` before running Gradle commands.

**TypeScript type errors:**

```
error TS2322: Type 'X' is not assignable to type 'Y'
```

Run `bun run check` locally to reproduce (`tsc --noEmit`).

### Reading nextest output

`cargo nextest` groups output by test status. Failed tests appear at the bottom with:

- The test name and crate.
- stdout/stderr captured during the test.
- The failure location (file and line number).

To re-run only failed tests:

```bash
cargo nextest run --workspace --features scp-ffi-uniffi/allow_in_memory_custody,scp-core/testing --run-ignored default --status-level fail
```

To run a single failing test with full output:

```bash
cargo nextest run -p scp-core -E 'test(the_test_name)' --no-capture
```

### Enabling backtraces

The CI environment sets `RUST_BACKTRACE=1`. To get full backtraces locally:

```bash
RUST_BACKTRACE=1 cargo nextest run --workspace --features scp-ffi-uniffi/allow_in_memory_custody,scp-core/testing
```

For more detailed backtraces:

```bash
RUST_BACKTRACE=full cargo nextest run -p scp-core -E 'test(failing_test)'
```

---

## CI

CI is defined in `.github/workflows/ci.yml`. It triggers on pushes to `main` and pull requests targeting `main`. Draft PRs are skipped.

### Path filtering

CI detects which language areas changed and only runs relevant jobs:

| Path prefix | Jobs triggered |
|-------------|---------------|
| `crates/`, `Cargo.toml`, `Cargo.lock`, `deny.toml` | Rust (fmt, clippy, test, doc, deny) |
| `bindings/python/` | Python (lint, test) |
| `bindings/typescript/` | TypeScript (check, lint, test) |
| `bindings/kotlin/` | Kotlin (test) |

### What runs on PR (Tier 1)

Every push to a non-draft PR branch. Target: under 3 minutes.

| Job | OS | Command |
|-----|----|---------|
| Rust / fmt | ubuntu | `cargo fmt --all -- --check` |
| Rust / clippy | ubuntu | `cargo clippy --workspace --all-targets --features scp-ffi-uniffi/allow_in_memory_custody,scp-core/testing -- -D warnings` |
| Rust / test | ubuntu, macos | `cargo nextest run --workspace --features scp-ffi-uniffi/allow_in_memory_custody,scp-core/testing` |
| Rust / doc | ubuntu | `cargo test --workspace --doc` + `cargo doc --workspace --no-deps` |
| Rust / deny | ubuntu | `cargo deny check` |
| Python / lint | ubuntu | `ruff format --check .` + `ruff check .` |
| Python / test | ubuntu | `PYTHONPATH=. pytest tests/ -v` |
| TypeScript / check + lint + test | ubuntu | `bun run check` + `bun run lint` + `bun test` |
| Kotlin / test | ubuntu | `./gradlew test` |

Unit tests and conformance macro suites (`storage_conformance!()`, `blob_store_conformance!()`, `payment_adapter_conformance!()`) run as part of `cargo nextest run --workspace`.

### What runs on merge (Tier 2)

Merge queue entry or push to `main`. Target: under 10 minutes. Required to merge.

All Tier 1 jobs, plus:

| Job | Command |
|-----|---------|
| Harness meta-tests | `cargo nextest run --workspace --features scp-testing/ci-tier2` |
| Phase integration | `cargo nextest run --workspace --features scp-testing/ci-tier2 -E 'test(phase_integration)'` |

### Nightly / pre-release (Tier 3)

Scheduled or manual trigger. Failures create issues but do not block merges.

All Tier 2 jobs, plus:

| Job | Command |
|-----|---------|
| Proptest extended | `cargo nextest run --workspace --features scp-testing/ci-tier3 -E 'test(proptest)'` |
| N-party simulation | `cargo nextest run --workspace --features scp-testing/ci-tier3 -E 'test(preset_.*_all_seeds)'` |
| Persistent backend conformance | `cargo nextest run --workspace --features scp-testing/ci-tier3 -E 'test(conformance.*sqlite\|conformance.*redb)'` |
| WASM conformance | `wasm-pack test --headless --chrome crates/scp-platform-web` (Phase 4+) |
| Load testing | `cargo nextest run --workspace --features scp-testing/ci-tier3 -E 'test(load_test)'` (Phase 6) |

`cargo deny check` also runs weekly on an independent schedule.

### Reproducing CI locally

Run these commands from the workspace root with the library path exported (see [Prerequisites](#prerequisites)):

```bash
# Full Tier 1 check (what runs on every PR)
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --features scp-ffi-uniffi/allow_in_memory_custody,scp-core/testing -- -D warnings
cargo nextest run --workspace --features scp-ffi-uniffi/allow_in_memory_custody,scp-core/testing
cargo test --workspace --doc --features scp-ffi-uniffi/allow_in_memory_custody,scp-core/testing
cargo deny check
```

Always run at least the clippy and test commands locally before pushing. Pushing lint or test failures wastes CI minutes.
