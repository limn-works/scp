# scp-ffi-uniffi — UniFFI Bridge Layer

## Overview

This crate generates Swift and Kotlin bindings from a single Rust definition via UniFFI proc-macros (`#[uniffi::export]`). It mirrors the PyO3 bridge (`crates/scp-ffi/`) architecture but targets mobile/desktop platforms instead of Python.

## Architecture

### Runtime Registry (`runtime.rs`)

A global `OnceLock<DashMap<String, ContextRuntime>>` maps context IDs to live runtime state:
- `EventLog` — Merkle tree for event recording, querying, proofs
- `RevocationList` — UCAN token revocation tracking
- `NonceTracker<SystemClock>` — per-context UCAN nonce replay prevention (ADR-016 step 9)
- `ceiling_strings: HashSet<String>` — capability ceiling as `{resource}:{action}` strings (ADR-016 step 8)
- `creator_did` — the DID of the context creator

DashMap provides lock-free concurrent access with internal sharding. The `with_context` function takes a closure receiving `&mut ContextRuntime` and returns `Result<T, ScpError>`.

`context_create` in `bridge.rs` calls `register_context`. `context_close` calls `remove_context`. UCAN and event-log bridge functions access state via `with_context`.

### Bridge Trait Adapters (`bridge.rs`)

Four adapter structs implement scp-core's UCAN validation traits, bridging runtime registry state to the 11-step validation pipeline:

| Adapter | Implements | Purpose |
|---------|-----------|---------|
| `BridgeDidResolver` | `DidResolver` | Resolves `did:dht:z` (zbase32) and `did:key:` (hex) DIDs to Ed25519 public keys |
| `BridgeRevocationChecker` | `RevocationChecker` | Wraps `&RevocationList` for revocation lookups |
| `BridgeProofResolver` | `ProofResolver` | HashMap-backed resolver for UCAN delegation chain proofs |
| `BridgeNonceTracker` | `NonceTracker` | Adapts `nonce::NonceTracker` to `validate::NonceTracker` trait |

### Module Structure

Single-file bridge (`bridge.rs`) containing all UniFFI exports. Key function groups:

| Category | Functions |
|----------|-----------|
| Identity | `identity_create`, `identity_load`, `identity_resolve` |
| Context | `context_create`, `context_join`, `context_leave`, `context_close`, `context_send`, `context_subscribe` |
| Tools | `tool_register`, `tool_invoke`, `tool_verify` |
| UCAN | `ucan_validate`, `ucan_mint`, `ucan_delegate`, `ucan_revoke` |
| Event Log | `event_log_query`, `event_log_verify` |
| Transport | `transport_connect`, `transport_status` |

### Build

- `crate-type = ["cdylib", "staticlib"]` — cdylib for dynamic linking, staticlib for iOS
- `cargo build -p scp-ffi-uniffi` to build the native library
- `cargo test -p scp-ffi-uniffi` to run tests (no Python linkage needed, unlike scp-ffi)
- Binding generation: `cargo run -p scp-ffi-uniffi --bin uniffi-bindgen -- generate ...`

### Error Mapping

`ScpError` enum with variants mapping to Swift `throws` / Kotlin exceptions:
- `Identity`, `Context`, `Permission`, `Crypto`, `Transport`, `Tool`, `Validation`
- Each variant carries `message` (human-readable) and `code` (SCP-{CATEGORY}-{NUMBER})
- Comprehensive `From<>` impls for all scp-core error types (15+ conversions)

### Async Bridging (ADR-021)

All I/O-bound functions are `async fn`. UniFFI generates Swift `async` functions (via `CheckedContinuation`) and Kotlin `suspend` functions (via coroutines). The shared tokio runtime (`RUNTIME` in `lib.rs`) executes futures.

## Gotchas

- The tokio runtime (`RUNTIME` in `lib.rs`) must be initialized before any async bridge call. It is created as a `OnceLock<Runtime>` and exposed via `runtime()`.
- `context_create` registers runtime state; `context_close` removes it. If context creation fails partway, the registry entry must be cleaned up.
- `with_context` closures must return `Result<T, ScpError>` — use typed error variants, not raw strings.
- UCAN validation delegates to scp-core's full 11-step ADR-016 pipeline. `BridgeDidResolver` handles both `did:dht:z` (zbase32 decode) and `did:key:` (hex decode) formats. Invalid DID methods return `DidNotFound`.
- `ucan_mint` and `ucan_delegate` use the identity's retained `InMemoryKeyCustody` and `KeyHandle` from the `ContextHandle` (wired during `context_create` from the `Identity`). No ephemeral keys. See #326.
- `EventLog` is a Merkle tree storing only leaf hashes, not event payloads. `event_log_query` returns event count and Merkle root as a JSON `LogSummary`.
- `event_log_verify` supports two claim types: `"inclusion"` (prove event exists at index) and `"absence"` (prove no event at index). Both use scp-core's `prove_inclusion`/`prove_absence` + `verify_inclusion`.
- Opaque objects (`Identity`, `ContextHandle`, `UcanToken`, `TransportManager`) use `Arc<T>` wrapping and manual handle counting (`increment_handle_count`/`decrement_handle_count` in `lib.rs`). `Drop` impls decrement counts.
- `generate_nonce` produces 16 random bytes encoded as hex (32 chars). Used by `ucan_mint` for UCAN nonce field.
- `OpaqueInMemoryKeyCustody` wrapper implements `Debug` with redacted output to prevent key material in logs.
- The `scp.udl` file defines callback interfaces (which proc-macros cannot express). Both UDL and proc-macro exports are required for complete binding generation.
