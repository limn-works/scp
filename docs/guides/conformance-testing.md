# Conformance Testing

## Overview

SCP defines conformance test macros for every pluggable trait in the protocol. Each macro generates a complete test suite that validates any implementation against the protocol specification. Conformance macros are the mechanical enforcement layer -- they ensure that new backends, adapters, and platform integrations satisfy the same contract as the reference implementations.

All conformance macros live in `crates/scp-testing/src/conformance/`. They are `#[macro_export]` macros that expand into a test module with `#[tokio::test]` functions. You invoke them in your crate's test files with a factory expression that creates a fresh instance of your implementation.

**Contents:**
1. [What Conformance Means in SCP](#1-what-conformance-means-in-scp)
2. [Available Macros](#2-available-macros)
3. [Storage Conformance](#3-storage-conformance)
4. [Blob Store Conformance](#4-blob-store-conformance)
5. [Transport Conformance](#5-transport-conformance)
6. [Key Custody Conformance](#6-key-custody-conformance)
7. [Device Attestation Conformance](#7-device-attestation-conformance)
8. [Push Notification Conformance](#8-push-notification-conformance)
9. [Payment Adapter Conformance](#9-payment-adapter-conformance)
10. [Writing a New Conformance Suite](#10-writing-a-new-conformance-suite)
11. [Relationship to the Spec](#11-relationship-to-the-spec)

---

## 1. What Conformance Means in SCP

Conformance in SCP is not optional. Every pluggable trait has a defined contract, and every implementation of that trait must pass the corresponding conformance suite. This is how the protocol enforces interoperability without relying on documentation or code review alone.

The conformance macros test the behavioral contract of a trait, not its internal implementation. They verify:

- **Roundtrip correctness** -- data stored through the trait is retrievable with identical content.
- **Edge cases** -- missing keys, expired TTLs, empty values, concurrent access.
- **Ordering guarantees** -- sorted key listings, timestamp-ordered query results.
- **Error semantics** -- destroyed keys produce errors, invalid handles are rejected.
- **Concurrency safety** -- parallel operations do not corrupt state.

Conformance tests are the minimum bar. Implementations may have additional tests for backend-specific behavior (e.g., SQLite WAL mode, S3 multipart upload). But conformance tests must always pass.

---

## 2. Available Macros

| Macro | Trait | Tests | Location | Spec |
|-------|-------|-------|----------|------|
| `storage_conformance!` | `Storage` | 13 | `conformance/storage.rs` | SS17.11, SS17.13, ADR-006 |
| `blob_store_conformance!` | `BlobStorage` | 19 | `conformance/blob_store.rs` | SS17.11, SS17.13 |
| `transport_conformance!` | `TransportAdapter` | 6 | `conformance/transport.rs` | SS16.12.1, ADR-005 |
| `key_custody_conformance!` | `KeyCustody` | 4 | `conformance/key_custody.rs` | ADR-006 |
| `attestation_conformance!` | `DeviceAttestation` | 2 | `conformance/attestation.rs` | ADR-006 |
| `push_conformance!` | `Push` | 2 | `conformance/push.rs` | ADR-006 |
| `payment_adapter_conformance!` | `PaymentAdapter` | 8 | `conformance/payment.rs` | SS19.2.6, ADR-033 |

All macros are re-exported from `scp_testing`:

```rust
use scp_testing::{
    storage_conformance,
    blob_store_conformance,
    transport_conformance,
    key_custody_conformance,
    attestation_conformance,
    push_conformance,
    payment_adapter_conformance,
};
```

---

## 3. Storage Conformance

**Trait:** `Storage` (defined in `crates/scp-platform/src/traits.rs`)
**Tests:** 13
**Factory argument:** An expression that evaluates to an instance of `impl Storage`.

### Usage

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use scp_testing::storage_conformance;

    storage_conformance!(InMemoryStorage::new());
}
```

### Test cases

| # | Test | Contract verified |
|---|------|-------------------|
| 1 | `roundtrip` | `store("key1", b"value1")` then `retrieve("key1")` returns `Some(b"value1")` |
| 2 | `missing_returns_none` | `retrieve("nonexistent")` returns `None` |
| 3 | `delete_removes` | `store`, `delete`, `retrieve` returns `None` |
| 4 | `list_keys_sorted` | Keys `["c", "a", "b"]` listed as `["a", "b", "c"]` |
| 5 | `list_keys_prefix_sorted` | Prefix `"ctx/"` returns only `ctx/*` keys, sorted |
| 6 | `delete_prefix_removes` | `delete_prefix("ctx/a/")` removes 2 matching keys, preserves `ctx/b/` and `other/` |
| 7 | `delete_prefix_zero` | `delete_prefix` with no matches returns 0 |
| 8 | `exists_true` | `exists` returns true after `store` |
| 9 | `exists_false` | `exists` returns false for missing key |
| 10 | `exists_after_delete` | `exists` returns false after `delete` |
| 11 | `overwrite` | Second `store` to same key replaces value |
| 12 | `concurrent_access` | 10 concurrent store/retrieve tasks via `Arc` |
| 13 | `store_empty_value` | `store("empty", b"")` roundtrips to `Some(vec![])` |

### Where it is used

```
crates/scp-testing/tests/conformance_storage.rs      -- InMemoryStorage
crates/scp-platform/tests/conformance_sqlite.rs       -- SqliteStorage
crates/scp-platform/tests/conformance_filesystem.rs   -- FilesystemStorage
```

---

## 4. Blob Store Conformance

**Trait:** `BlobStorage` (defined in `crates/scp-transport/src/native/storage.rs`)
**Tests:** 19
**Factory argument:** An expression that evaluates to `(impl BlobStorage, Arc<AtomicU64>)`.

The second element is a controllable clock. The storage implementation must use this clock for all timestamp operations so that TTL and purge tests are deterministic.

### Usage

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use scp_testing::blob_store_conformance;
    use scp_testing::conformance::blob_store::test_helpers::make_test_clock;

    blob_store_conformance!({
        let (clock_fn, clock) = make_test_clock();
        let store = InMemoryBlobStorage::with_clock(clock_fn);
        (store, clock)
    });
}
```

### Test cases

| # | Test | Contract verified |
|---|------|-------------------|
| 1 | `roundtrip` | All `StoredBlob` fields preserved through store/get |
| 2 | `missing_returns_none` | Get for nonexistent `blob_id` returns `None` |
| 3 | `ttl_expiry` | Clock advanced past TTL: get returns `None` |
| 4 | `query_routing_order` | Query results ordered by `stored_at` ascending |
| 5 | `query_since` | Since filter excludes blobs with `stored_at <= since` |
| 6 | `query_limit` | Limit parameter caps results at N |
| 7 | `delete` | Delete removes blob; second delete returns `false` |
| 8 | `store_returns_blob_id` | Returned `blob_id` matches SHA-256 of content |
| 9 | `concurrent_store_purge` | Concurrent store + purge_expired is safe |
| 10 | `purge_expired_only` | Only expired blobs are purged |
| 11 | `query_empty_returns_empty` | Unknown `routing_id` returns empty Vec |
| 12 | `store_streaming_roundtrip` | Store via stream, verify via get |
| 13 | `get_streaming_roundtrip` | Store normally, retrieve via get_streaming |
| 14 | `store_streaming_get_streaming_roundtrip` | Full streaming roundtrip |
| 15 | `store_streaming_empty_body` | Streaming store with empty body succeeds |
| 16 | `store_streaming_content_length_hint` | Content length hint is advisory only |
| 17 | `get_streaming_nonexistent` | get_streaming for missing blob returns None |
| 18 | `store_streaming_query_interop` | Streaming-stored blob findable via query |
| 19 | `get_streaming_expired` | get_streaming returns None for expired blobs |

### Test helpers

The `scp_testing::conformance::blob_store::test_helpers` module provides:

- `make_test_clock() -> (ClockFn, Arc<AtomicU64>)` -- Creates a controllable clock starting at `1_000_000` seconds.
- `collect_body(BlobBodyStream) -> Vec<u8>` -- Collects a streaming body into bytes (panics on chunk errors).
- `DEFAULT_START_TIME: u64 = 1_000_000` -- The starting timestamp for conformance test clocks.

### Where it is used

```
crates/scp-testing/src/blob_store_tests.rs                -- InMemoryBlobStorage
crates/scp-transport/tests/sqlite_blob_conformance.rs      -- SqliteBlobStore
crates/scp-transport/tests/redb_blob_conformance.rs        -- RedbBlobStore
crates/scp-transport/tests/local_cache_conformance.rs      -- LocalBlobCache
crates/scp-transport/tests/combined_conformance.rs         -- combined storage + blob store
```

---

## 5. Transport Conformance

**Trait:** `TransportAdapter` (defined in `crates/scp-transport/src/traits.rs`)
**Tests:** 6
**Factory argument:** An expression that evaluates to an instance of `impl TransportAdapter`.

### Usage

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use scp_testing::transport_conformance;

    transport_conformance!(InMemoryTransport::new_for_test());
}
```

### Test cases

| # | Test | Contract verified |
|---|------|-------------------|
| 1 | `send_subscribe_roundtrip` | Send an envelope, subscribe to its `routing_id`, verify delivery |
| 2 | `backfill_with_since` | Subscribe with `since` parameter is accepted without error |
| 3 | `unsubscribe_stops_delivery` | Subscribe, unsubscribe, send -- no delivery to old stream |
| 4 | `query_returns_stored` | Send, query by `routing_id` -- envelope in results |
| 5 | `delete_removes_blob` | Send, delete by `blob_id` -- query returns empty |
| 6 | `deduplication_by_blob_id` | Same envelope sent twice produces same `blob_id`, appears once in query |

The tests use `create_outer_envelope()` from `scp_core::envelope::outer` to build minimal valid test envelopes. Each test creates an `OuterEnvelope` with a unique `routing_id` to prevent cross-test interference.

### Adapters with limited capabilities

Some transports cannot support all 5 `TransportAdapter` methods. For example, MQTT has no native full backfill, and BLE has no `delete`. Tier 1 adapters must pass the full suite. Tier 2 adapters should pass as many tests as the transport allows. See [Implementing a Custom TransportAdapter](transport-adapters.md) for details on handling limitations.

---

## 6. Key Custody Conformance

**Trait:** `KeyCustody` (defined in `crates/scp-platform/src/traits.rs`)
**Tests:** 4
**Factory argument:** An expression that evaluates to an instance of `impl KeyCustody`.

### Usage

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use scp_testing::key_custody_conformance;

    key_custody_conformance!(InMemoryKeyCustody::new());
}
```

### Test cases

| # | Test | Contract verified |
|---|------|-------------------|
| 1 | `generate_sign_verify_roundtrip` | Generate Ed25519 keypair, sign data, verify signature using `ed25519-dalek` |
| 2 | `destroy_prevents_sign` | Generate, destroy, sign with destroyed handle returns error |
| 3 | `distinct_handles` | Two `generate_keypair` calls produce different handles and public keys |
| 4 | `sign_with_invalid_handle_errors` | Sign with `KeyHandle::new(u64::MAX)` returns error |

### Test helpers

The `scp_testing::conformance::key_custody::test_helpers` module provides:

- `verify_ed25519_signature(public_key: &[u8], message: &[u8], signature: &[u8])` -- Verifies an Ed25519 signature using `ed25519-dalek`. Panics if the public key is not 32 bytes, the signature is not 64 bytes, or verification fails.

---

## 7. Device Attestation Conformance

**Trait:** `DeviceAttestation` (defined in `crates/scp-platform/src/traits.rs`)
**Tests:** 2
**Factory argument:** An expression that evaluates to an instance of `impl DeviceAttestation`.

### Usage

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use scp_testing::attestation_conformance;

    attestation_conformance!(InMemoryDeviceAttestation::new());
}
```

### Test cases

| # | Test | Contract verified |
|---|------|-------------------|
| 1 | `attest_verify_roundtrip` | `attest()` then `verify(token)` returns `true` |
| 2 | `invalid_token_rejected` | `verify(garbage_bytes)` returns `false` or `Err` |

The second test constructs a garbage `DeviceAttestationToken` with `[0xDE, 0xAD, 0xBE, 0xEF]`. Both `Ok(false)` and `Err(...)` are acceptable -- implementations may reject malformed tokens with either a boolean or an error.

---

## 8. Push Notification Conformance

**Trait:** `Push` (defined in `crates/scp-platform/src/traits.rs`)
**Tests:** 2
**Factory argument:** An expression that evaluates to an instance of `impl Push`.

### Usage

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use scp_testing::push_conformance;

    push_conformance!(InMemoryPush::new());
}
```

### Test cases

| # | Test | Contract verified |
|---|------|-------------------|
| 1 | `register_returns_token` | `register()` returns a non-empty `PushToken` |
| 2 | `handle_notification_produces_event` | `handle_notification(payload)` returns a non-empty `WakeSignal` |

---

## 9. Payment Adapter Conformance

**Trait:** `PaymentAdapter` (defined in `crates/scp-core/src/economy/`)
**Tests:** 8
**Factory argument:** An expression that evaluates to an instance of `impl PaymentAdapter`.

### Usage

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use scp_testing::payment_adapter_conformance;

    payment_adapter_conformance!(TestPaymentAdapter::new());
}
```

### Test cases

| # | Test | Contract verified |
|---|------|-------------------|
| 1 | `authorize_capture_roundtrip` | Authorize then capture succeeds, all fields match |
| 2 | `authorize_void_roundtrip` | Authorize, void, capture returns error |
| 3 | `double_capture_rejection` | Second capture of same authorization fails |
| 4 | `insufficient_balance_handling` | Authorization for `u64::MAX` fails |
| 5 | `verify_roundtrip` | Capture receipt then verify returns `valid: true` |
| 6 | `currency_mismatch_rejection` | Authorization with unsupported currency fails |
| 7 | `concurrent_authorization_isolation` | Two authorizations have distinct IDs, independent lifecycle |
| 8 | `refund_against_captured_receipt` | Full refund after capture succeeds |

### Test helpers

The `scp_testing::conformance::payment::test_helpers` module provides:

- `payer_did() -> DID` -- Deterministic payer DID.
- `payee_did() -> DID` -- Deterministic payee DID.
- `make_metadata() -> PaymentMetadata` -- Metadata with a unique idempotency key (counter-based).
- `supported_currency(adapter) -> CurrencyCode` -- First currency from `adapter.capabilities().supported_currencies`.
- `unsupported_currency(adapter) -> CurrencyCode` -- A synthetic currency code not in the adapter's supported list.

---

## 10. Writing a New Conformance Suite

To add a conformance suite for a new trait:

### Step 1: Create the macro file

Add a new file in `crates/scp-testing/src/conformance/`:

```rust
// crates/scp-testing/src/conformance/my_trait.rs

//! My trait conformance test macro.
//!
//! The `my_trait_conformance` macro generates N test cases that validate
//! any `MyTrait` implementation against the protocol specification.

/// Generates N conformance tests for a `MyTrait` implementation.
///
/// # Arguments
///
/// The macro takes a single expression that evaluates to an instance of a
/// type implementing `MyTrait`.
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
        #[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, unused_imports)]
        mod my_trait_conformance {
            use super::*;

            #[tokio::test]
            async fn basic_roundtrip() {
                let instance = $factory;
                // Test the contract here.
            }

            // Additional test cases...
        }
    };
}
```

### Step 2: Register in the module

Add the module to `crates/scp-testing/src/conformance/mod.rs`:

```rust
pub mod my_trait;
```

### Step 3: Add test helpers (if needed)

If your tests need shared utility functions, add a `pub mod test_helpers` inside the macro file. These must be `pub` so the macro-generated tests can reference them:

```rust
pub mod test_helpers {
    pub fn some_helper() -> SomeType {
        // ...
    }
}
```

Reference helpers from macro-generated code using the full path:

```rust
$crate::conformance::my_trait::test_helpers::some_helper()
```

### Step 4: Write a reference test

Create a test file that runs the macro against the reference implementation:

```rust
// crates/scp-testing/tests/conformance_my_trait.rs
use scp_testing::my_trait_conformance;

my_trait_conformance!(ReferenceImpl::new());
```

### Conventions

- **One factory argument.** The macro takes a single expression. If you need multiple inputs (e.g., a clock and a store), return a tuple.
- **Fresh instance per test.** The factory is called once per test, not once per suite. This ensures test isolation.
- **Allow test-only lints.** Use `#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, unused_imports)]` on the generated module. Conformance tests are the one place where `unwrap`/`expect`/`panic` are acceptable.
- **Document the test count.** The module-level doc comment must list all test cases.
- **Use `#[tokio::test]`.** All conformance tests are async.

---

## 11. Relationship to the Spec

Conformance macros are the mechanical enforcement of spec requirements. The following table maps each macro to its governing spec sections:

| Macro | Spec Sections | What the spec says |
|-------|--------------|-------------------|
| `storage_conformance!` | SS17.11, SS17.13, ADR-006 | Custom storage adapters must pass the full conformance suite. 6 methods, all async, `Send + Sync`. |
| `blob_store_conformance!` | SS17.11, SS17.13 | Custom blob store adapters must pass the full conformance suite. Controllable clock required for TTL tests. |
| `transport_conformance!` | SS16.12.1, ADR-005 | All Tier 1 transport adapters must pass the full suite. Tier 2 adapters should pass as many tests as the transport allows. |
| `key_custody_conformance!` | ADR-006 | All key custody implementations must pass. Ed25519 roundtrip is mandatory. |
| `attestation_conformance!` | ADR-006 | All attestation implementations must pass. Garbage tokens must be rejected. |
| `push_conformance!` | ADR-006 | All push implementations must pass. Tokens and wake signals must be non-empty. |
| `payment_adapter_conformance!` | SS19.2.6, ADR-033 | All payment adapters must pass. Authorize/capture/void/verify/refund lifecycle is mandatory. |

### Integration test suites

Beyond conformance macros, `scp-testing` provides full integration test suites that test cross-component behavior. These are separate from conformance tests and live in `crates/scp-testing/tests/`:

```bash
# Run all scp-testing tests (conformance + integration)
DYLD_LIBRARY_PATH=$(python3.12 -c "import sysconfig; print(sysconfig.get_config_var('LIBDIR'))") \
  cargo test -p scp-testing

# Run a specific integration suite
cargo test -p scp-testing --test identity
cargo test -p scp-testing --test governance
cargo test -p scp-testing --test attacks
```

Integration suites use the `NetworkSimulator`, `ScenarioBuilder`, and assertion primitives from `scp-testing` to test multi-party protocol flows. See the `scp-testing` crate documentation for the full simulation harness.

---

## Spec Cross-References

| Topic | Spec Section |
|-------|-------------|
| Custom storage adapter requirements | SS17.11 |
| Conformance testing extensions | SS17.13 |
| Transport adapter conformance | SS16.12.1 |
| Platform adapter design (KeyCustody, Storage, etc.) | ADR-006 |
| Transport abstraction | ADR-005 |
| Payment adapter conformance | SS19.2.6 |
| Payment adapter design | ADR-033 |
| Simulation harness (clock, relay, transport) | SS16 |
