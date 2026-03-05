# Conformance Testing

SCP uses spec-derived conformance test suites to validate trait implementations. Every backend that implements a core SCP trait -- `Storage`, `BlobStorage`, `PaymentAdapter`, etc. -- must pass the same set of tests that the in-memory reference implementation passes. This ensures behavioral equivalence across backends without duplicating test logic.

This guide covers how conformance testing works, which suites are available, and how to use and extend them.

**Prerequisites:** Familiarity with Rust macros (`macro_rules!`), async Rust (tokio), and the SCP crate structure (`scp-core`, `scp-platform`, `scp-transport`, `scp-testing`).

**Contents:**
1. [What Conformance Means](#1-what-conformance-means)
2. [Available Suites](#2-available-suites)
3. [Using a Conformance Macro](#3-using-a-conformance-macro)
4. [Factory Expressions](#4-factory-expressions)
5. [Real-World Usage](#5-real-world-usage)
6. [Writing a New Conformance Suite](#6-writing-a-new-conformance-suite)
7. [Relationship to CI](#7-relationship-to-ci)

---

## 1. What Conformance Means

A conformance suite is a set of tests derived directly from the protocol specification (primarily sections 17.11 and 17.13) that exercise the behavioral contract of a trait. The tests are encoded as Rust macros in `crates/scp-testing/src/conformance/`. Each macro expands into a `mod` containing `#[tokio::test]` functions.

The key properties:

- **Spec-derived.** Each test maps to a requirement in the spec. The doc comments on each macro list every test case and its spec reference.
- **Backend-agnostic.** The same macro validates in-memory, SQLite, redb, filesystem, and any future backend. If it passes the conformance suite, it satisfies the trait contract.
- **Reference first.** The in-memory implementation is the reference -- it passes the suite first. Production backends are validated against the same expectations.
- **One invocation per backend.** A single macro call generates the full test module. No manual test duplication.

See spec section 16.12 ("Trait Conformance Test Generators") for the normative description.

---

## 2. Available Suites

Three conformance suites are implemented. Four more are specified but not yet implemented.

### Implemented

| Macro | Trait under test | Test count | Spec reference | Source |
|-------|-----------------|------------|----------------|--------|
| `storage_conformance!` | `Storage` (`scp-platform`) | 13 | 17.11, 17.13, ADR-006 | `crates/scp-testing/src/conformance/storage.rs` |
| `blob_store_conformance!` | `BlobStorage` (`scp-transport`) | 19 | 17.11, 17.13 | `crates/scp-testing/src/conformance/blob_store.rs` |
| `payment_adapter_conformance!` | `PaymentAdapter` (`scp-core`) | 8 | 19.2.6, ADR-033 | `crates/scp-testing/src/conformance/payment.rs` |

### Specified but not yet implemented

| Macro | Trait under test | Spec reference |
|-------|-----------------|----------------|
| `transport_conformance!` | `TransportAdapter` (`scp-transport`) | 16.12.1, ADR-005 |
| `key_custody_conformance!` | `KeyCustody` (`scp-platform`) | 16.12.3, ADR-006 |
| `attestation_conformance!` | `DeviceAttestation` (`scp-platform`) | 16.12.4, ADR-006 |
| `push_conformance!` | `Push` (`scp-platform`) | 16.12.5, ADR-006 |

### Test coverage by suite

**`storage_conformance!`** (13 tests): store/retrieve roundtrip, missing key returns `None`, delete removes value, `list_keys` sorted, `list_keys` with prefix sorted, `delete_prefix` removes matching and returns count, `delete_prefix` returns 0 for no match, `exists` true/false/after-delete, overwrite replaces value, concurrent access safety, store empty value.

**`blob_store_conformance!`** (19 tests): roundtrip, missing returns `None`, TTL expiry, query by `routing_id` ordering, query `since` filter, query limit, delete (first returns true, second returns false), store returns SHA-256 `blob_id`, concurrent store + purge safety, `purge_expired` removes only expired blobs, query for unknown `routing_id` returns empty, plus 7 streaming API tests (store streaming roundtrip, get streaming roundtrip, full streaming roundtrip, empty body, content length hint is advisory, nonexistent streaming get, expired streaming get).

**`payment_adapter_conformance!`** (8 tests): authorize/capture roundtrip, authorize/void roundtrip, double-capture rejection, insufficient balance handling, verify roundtrip, currency mismatch rejection, concurrent authorization isolation, refund against captured receipt.

---

## 3. Using a Conformance Macro

The pattern is the same for all suites:

1. Create a test file in your crate's `tests/` directory (or a `#[cfg(test)] mod` in `src/`).
2. Write a factory expression that produces a fresh instance of your implementation.
3. Invoke the macro with that expression.

### Minimal example: `storage_conformance!`

```rust
// crates/my-crate/tests/conformance_my_storage.rs

#![allow(clippy::unwrap_used, clippy::expect_used)]

use my_crate::MyStorage;

scp_testing::storage_conformance!(MyStorage::new());
```

That single line expands into a `mod storage_conformance` containing all 13 tests. Each test calls `MyStorage::new()` independently to get a fresh, isolated instance.

### Minimal example: `blob_store_conformance!`

```rust
// crates/my-crate/tests/conformance_my_blob_store.rs

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use my_crate::MyBlobStore;
use scp_transport::native::storage::ClockFn;

fn make_store() -> (MyBlobStore, Arc<AtomicU64>) {
    let clock = Arc::new(AtomicU64::new(1_000_000));
    let clock_fn: ClockFn = {
        let c = clock.clone();
        Arc::new(move || c.load(Ordering::Relaxed))
    };
    let store = MyBlobStore::with_clock(clock_fn);
    (store, clock)
}

scp_testing::blob_store_conformance!(make_store());
```

### Minimal example: `payment_adapter_conformance!`

```rust
// crates/my-crate/tests/conformance_my_payment.rs

#![allow(clippy::unwrap_used, clippy::expect_used)]

use my_crate::MyPaymentAdapter;

scp_testing::payment_adapter_conformance!(MyPaymentAdapter::new());
```

---

## 4. Factory Expressions

Each macro expects a specific shape from its factory expression.

### `storage_conformance!`

**Expects:** A single expression evaluating to `impl Storage`.

The expression is called once per test. It must return a fresh, empty storage instance with no pre-existing data.

```rust
storage_conformance!(InMemoryStorage::new());
```

If your storage needs setup (e.g., temp directories), wrap it in a function:

```rust
fn make_filesystem_storage() -> FilesystemStorage {
    let dir = tempfile::tempdir().expect("tempdir should succeed");
    let dir_path = dir.path().to_path_buf();
    let _ = Box::leak(Box::new(dir));  // Keep dir alive for the test
    FilesystemStorage::new(&dir_path).expect("should succeed")
}

storage_conformance!(make_filesystem_storage());
```

### `blob_store_conformance!`

**Expects:** A single expression evaluating to `(impl BlobStorage, Arc<AtomicU64>)`.

The first element is the storage backend. The second is a controllable clock -- an `Arc<AtomicU64>` that the macro advances directly to control time in TTL and expiry tests. Your storage implementation **must** use this clock for all timestamp operations. If it uses `SystemTime::now()` instead, TTL tests will fail nondeterministically.

The clock pattern:

```rust
fn make_store() -> (MyBlobStore, Arc<AtomicU64>) {
    let clock = Arc::new(AtomicU64::new(1_000_000));  // Start well past epoch 0
    let clock_fn: ClockFn = {
        let c = clock.clone();
        Arc::new(move || c.load(Ordering::Relaxed))
    };
    let store = MyBlobStore::with_clock(clock_fn);
    (store, clock)
}

blob_store_conformance!(make_store());
```

The starting value of `1_000_000` is the convention (see `test_helpers::DEFAULT_START_TIME` in `crates/scp-testing/src/conformance/blob_store.rs`). The macro advances the clock by writing to the `AtomicU64`:

```rust
let current = clock.load(Ordering::Relaxed);
clock.store(current + 61, Ordering::Relaxed);  // Advance 61 seconds
```

The helper function `scp_testing::conformance::blob_store::test_helpers::make_test_clock()` creates a ready-to-use `(ClockFn, Arc<AtomicU64>)` pair if you prefer not to construct it manually.

### `payment_adapter_conformance!`

**Expects:** A single expression evaluating to `impl PaymentAdapter`.

The adapter must have a clean ledger with enough balance to authorize test amounts (up to 2000 units). It must support at least one currency. The conformance helpers (`supported_currency`, `unsupported_currency`, `payer_did`, `payee_did`, `make_metadata`) are provided by `scp_testing::conformance::payment::test_helpers`.

---

## 5. Real-World Usage

Here is how every backend in the codebase invokes conformance testing.

### Storage conformance

| Backend | Crate | Test file | Factory |
|---------|-------|-----------|---------|
| `InMemoryStorage` | `scp-testing` | `crates/scp-testing/tests/conformance_storage.rs` | `InMemoryStorage::new()` |
| `FilesystemStorage` | `scp-platform` | `crates/scp-platform/tests/conformance_filesystem.rs` | Creates a leaked `tempfile::tempdir()`, passes path to `FilesystemStorage::new()` |
| `SqliteStorage` | `scp-platform` | `crates/scp-platform/tests/conformance_sqlite.rs` | Creates a leaked `tempfile::tempdir()`, passes path + 32-byte test key to `SqliteStorage::new()` |

The filesystem and SQLite tests are feature-gated (`#![cfg(feature = "filesystem")]` and `#![cfg(feature = "sqlite")]` respectively).

### Blob store conformance

| Backend | Crate | Test file | Factory |
|---------|-------|-----------|---------|
| `InMemoryBlobStorage` | `scp-testing` | `crates/scp-testing/src/blob_store_tests.rs` | Constructs clock + `InMemoryBlobStorage::with_clock()` |
| `SqliteBlobStore` | `scp-transport` | `crates/scp-transport/tests/sqlite_blob_conformance.rs` | Constructs clock + `SqliteBlobStore::in_memory_with_clock()` |
| `RedbBlobStore` | `scp-transport` | `crates/scp-transport/tests/redb_blob_conformance.rs` | Constructs clock + `RedbBlobStore::temporary_with_clock()` |

All three use the identical clock pattern described in section 4.

### Payment adapter conformance

No production backends invoke `payment_adapter_conformance!` yet. The macro is implemented and ready for use when payment adapters are built.

---

## 6. Writing a New Conformance Suite

If you add a new core trait to SCP and need a conformance suite for it, follow this template.

### Step 1: Create the macro file

Add a new file in `crates/scp-testing/src/conformance/`. Name it after the trait (e.g., `my_trait.rs`).

```rust
//! My trait conformance test macro.
//!
//! The [`my_trait_conformance`] macro generates N test cases that validate
//! any [`MyTrait`](path::to::MyTrait) implementation against the spec
//! (section X.Y):
//!
//! 1. Test description one
//! 2. Test description two
//! ...
//!
//! See spec section X.Y.

/// Generates N conformance tests for a [`MyTrait`] implementation.
///
/// # Arguments
///
/// The macro takes a single expression that evaluates to an instance
/// implementing [`MyTrait`]. Called once per test for isolation.
///
/// # Example
///
/// ```ignore
/// use scp_testing::my_trait_conformance;
///
/// my_trait_conformance!(InMemoryMyTrait::new());
/// ```
#[macro_export]
macro_rules! my_trait_conformance {
    ($factory:expr) => {
        mod my_trait_conformance {
            use super::*;

            // Import the trait so its methods are in scope.
            use path::to::MyTrait;

            #[tokio::test]
            async fn roundtrip() {
                let instance = $factory;
                // Test logic here.
            }

            #[tokio::test]
            async fn error_case() {
                let instance = $factory;
                // Test logic here.
            }

            // Additional tests...
        }
    };
}
```

### Step 2: Register the module

Add `pub mod my_trait;` to `crates/scp-testing/src/conformance/mod.rs`.

### Step 3: Validate with the in-memory reference

Create a test file that invokes the macro against the in-memory implementation:

```rust
// crates/scp-testing/tests/conformance_my_trait.rs

use scp_something::testing::InMemoryMyTrait;

scp_testing::my_trait_conformance!(InMemoryMyTrait::new());
```

Run the tests:

```sh
cargo test -p scp-testing --test conformance_my_trait
```

### Step 4: Apply to production backends

In each crate that provides a production backend, add a feature-gated test file:

```rust
// crates/scp-whatever/tests/conformance_my_trait_sqlite.rs

#![cfg(feature = "sqlite")]

use scp_whatever::SqliteMyTrait;

scp_testing::my_trait_conformance!(make_sqlite_instance());
```

### Step 5: Add helper modules if needed

If your tests need shared helpers (like the clock pattern for blob stores or the DID helpers for payment adapters), add a `pub mod test_helpers` inside your macro file. Keep helpers public so the macro-generated code can reference them via `$crate::conformance::my_trait::test_helpers::helper_fn()`.

### Step 6: Update the spec

Add a subsection under 16.12 documenting the new macro, its test cases, and the spec sections they validate.

---

## 7. Relationship to CI

Conformance tests participate in the three-tier CI model defined in spec section 16.15.

### Tier 1 -- PR Checks

**Trigger:** Every push to a PR branch.
**Command:** `cargo nextest run --workspace`

All conformance macros expand into standard `#[tokio::test]` functions inside regular `mod` blocks. They run as part of the normal workspace test suite with no feature flags required. At this tier, they exercise **in-memory implementations only** -- the tests in `scp-testing` itself. These complete in milliseconds.

The in-memory conformance tests for `Storage` and `BlobStorage` (and `PaymentAdapter` when backends exist) all run here.

### Tier 2 -- Merge Gate

**Trigger:** Merge queue entry or push to `main`.
**Command:** `cargo nextest run --workspace --features scp-testing/ci-tier2`

Tier 2 includes all Tier 1 tests plus simulation harness meta-tests and protocol integration tests. Conformance macro invocations against in-memory backends continue to run. No additional conformance-specific tests are gated behind `ci-tier2`.

### Tier 3 -- Nightly / Pre-Release

**Trigger:** Nightly schedule or manual pre-release run.
**Command:** `cargo nextest run --workspace --features scp-testing/ci-tier3`

Persistent backend conformance runs here: `storage_conformance!` and `blob_store_conformance!` against `SqliteStorage`, `SqliteBlobStore`, `RedbBlobStore`, and `FilesystemStorage`. These tests are feature-gated in their respective crates (e.g., `#![cfg(feature = "sqlite")]`) and are included when the full feature set is enabled at Tier 3.

### Summary

| Suite | Tier 1 (PR) | Tier 2 (Merge) | Tier 3 (Nightly) |
|-------|:-----------:|:--------------:|:----------------:|
| In-memory `Storage` | Yes | Yes | Yes |
| In-memory `BlobStorage` | Yes | Yes | Yes |
| In-memory `PaymentAdapter` | Yes | Yes | Yes |
| SQLite `Storage` | -- | -- | Yes |
| Filesystem `Storage` | -- | -- | Yes |
| SQLite `BlobStorage` | -- | -- | Yes |
| redb `BlobStorage` | -- | -- | Yes |

---

## Reference: Key Files

| Purpose | Path |
|---------|------|
| Conformance module root | `crates/scp-testing/src/conformance/mod.rs` |
| `storage_conformance!` macro | `crates/scp-testing/src/conformance/storage.rs` |
| `blob_store_conformance!` macro | `crates/scp-testing/src/conformance/blob_store.rs` |
| `payment_adapter_conformance!` macro | `crates/scp-testing/src/conformance/payment.rs` |
| In-memory storage conformance test | `crates/scp-testing/tests/conformance_storage.rs` |
| In-memory blob store conformance test | `crates/scp-testing/src/blob_store_tests.rs` |
| Filesystem storage conformance test | `crates/scp-platform/tests/conformance_filesystem.rs` |
| SQLite storage conformance test | `crates/scp-platform/tests/conformance_sqlite.rs` |
| SQLite blob store conformance test | `crates/scp-transport/tests/sqlite_blob_conformance.rs` |
| redb blob store conformance test | `crates/scp-transport/tests/redb_blob_conformance.rs` |
| ProtocolStore integration tests | `crates/scp-testing/tests/integration/protocol_store.rs` |
| Spec: conformance generators | `.docs/specs/16-test-infrastructure.md` section 16.12 |
| Spec: CI tiers | `.docs/specs/16-test-infrastructure.md` section 16.15 |
