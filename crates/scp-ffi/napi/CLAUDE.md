# scp-ffi-napi — napi-rs Bridge Layer

## Overview

This crate is the native addon (`.node` file) for Node.js/Bun. It exposes scp-core Rust APIs to JavaScript via `#[napi]` functions and classes. The TypeScript SDK (`@scp/sdk`) consumes this addon.

## Architecture

### Async Model

Uses a single tokio `Runtime` in a `OnceLock<Runtime>` (multi-thread). napi-rs `tokio_rt` feature handles the JS Promise ↔ Rust Future bridging. All async bridge functions are declared `async fn` with `#[napi]`.

### Runtime Registry (`runtime.rs`)

A global `OnceLock<DashMap<String, ContextRuntime>>` maps context IDs to live runtime state:
- `EventLog` — event recording, Merkle proofs
- `RevocationList` — UCAN token revocation tracking
- `NonceTracker<SystemClock>` — per-context UCAN nonce replay prevention (ADR-016 step 9)
- `ceiling_strings: HashSet<String>` — capability ceiling as strings (ADR-016 step 8)
- `creator_did` — the DID of the context creator

**Lazy registration:** Unlike the PyO3 bridge (where `py_context_create` eagerly registers), the NAPI bridge uses `ensure_registered(&NapiContextHandle)` — the first UCAN or event_log call on a context triggers registration from the handle's metadata. This avoids coupling to `context.rs`.

### Module Structure

| Module | Delegates to | Functions |
|--------|-------------|-----------|
| `identity.rs` | scp-core identity | `identity_create`, `identity_load`, `identity_resolve` |
| `context.rs` | NapiContextHandle | `context_create`, `context_join`, `context_leave`, `context_close`, `context_send`, `context_subscribe` |
| `tools.rs` | scp-core tools | `tool_register`, `tool_invoke`, `tool_verify` |
| `ucan.rs` | scp-core UCAN | `ucan_validate`, `ucan_mint`, `ucan_revoke` |
| `event_log.rs` | scp-core event_log | `event_log_query`, `event_log_verify` |
| `transport.rs` | scp-transport | `transport_connect`, `transport_disconnect`, `transport_status` |
| `runtime.rs` | DashMap registry | `ensure_registered`, `with_context`, `remove_context` |

### Build

- `crate-type = ["cdylib"]` — native addon only (no rlib)
- `#![allow(clippy::trailing_empty_array)]` required — napi-rs macros generate structs that trigger this lint
- `#![forbid(unsafe_code)]` CANNOT be used — napi-rs macros generate unsafe code
- `cargo check -p scp-ffi-napi` to verify compilation
- `cargo test -p scp-ffi-napi` to run Rust-side unit tests

### Error Mapping

`error.rs` defines `ScpNapiError` enum (7 variants) with `From<scp-core error types>` and `From<ScpNapiError> for napi::Error` (using `napi::Status::GenericFailure + error.to_string()`).

### UCAN Validation Pipeline (SCP-219)

`ucan_validate` delegates to scp-core's full 11-step ADR-016 pipeline via bridge trait adapters:
- `BridgeDidResolver` — extracts Ed25519 pubkeys from `did:dht:z{zbase32}` and `did:key:{hex}` DIDs
- `BridgeRevocationChecker` — wraps `RevocationList` from runtime registry
- `BridgeProofResolver` — in-memory `HashMap<String, UcanToken>` for delegation chains
- `BridgeNonceTracker` — adapts `nonce::NonceTracker` struct to `validate::NonceTracker` trait

`ucan_mint` **does not call `scp_core::crypto::ucan::mint::mint_ucan`** — it manually constructs `NapiUcanToken` with `encoded: String::new()`. This is a known gap (gate-audit): the token has no JWT structure and cannot be passed to `ucan_revoke` or `ucan_validate`. Fix: call `mint_ucan` with `InMemoryKeyCustody` as a placeholder (as the UniFFI bridge does) until SCP-214 wires real `KeyCustody`. See ACTION items in SCP-219 audit.

`ucan_validate` does not accept a `proof_tokens` parameter — delegated UCAN tokens (non-empty `prf` arrays) will always fail at delegation chain traversal (step 3) with "proof CID not found". The PyO3 bridge accepts `Option<Vec<String>>` proof tokens and populates `BridgeProofResolver` from them. This gap must be fixed before delegated UCANs can be validated through the NAPI bridge.

`ucan_revoke` parses the full JWT, computes CID via `compute_revocation_cid`, adds to `RevocationList`.

### Event Log (SCP-219)

`event_log_query` returns Merkle tree metadata (event count + root hash). Full event replay requires transport-layer event storage.

`event_log_verify` generates and verifies inclusion/absence Merkle proofs via `scp_core::event_log::proof`.

## Gotchas

- The `z-base-32` workspace dependency has `lib.name = "zbase32"` — use `zbase32::encode/decode` in Rust code, NOT `z_base_32::`. Do NOT add the standalone `zbase32` crate (different API: takes `&[u8]` + `u64` bits).
- `NapiContextHandle` fields are private but have `#[napi(getter)]` public methods (`context_id()`, `creator_did()`, `ceiling()`). Use these for Rust-side access.
- `napi-rs` requires `async fn` for Promise returns even when the function is sync — annotate with `#[allow(clippy::unused_async)]`.
- `napi-rs` requires owned `String`/`Vec` parameters — annotate with `#[allow(clippy::needless_pass_by_value)]`.
- Handle count: opaque types (`NapiIdentity`, `NapiContextHandle`, `NapiUcanToken`, `NapiTransportManager`) must increment `HANDLE_COUNT` on construction and decrement in `Drop`.
- Runtime registry uses lazy init pattern — `ensure_registered()` must be called before `with_context()` in every bridge function that needs runtime state.
- `event_log.rs` has no test module — `decode_hex_hash` and the inclusion/absence proof paths are untested at the unit level. Add `#[cfg(test)]` block matching the PyO3 bridge coverage before marking related stories done.
- `ensure_registered` has a TOCTOU pattern: `contains_key` check + `or_insert` are not atomic across the two calls. The current behavior is safe (DashMap `or_insert` is atomic; duplicate construction is benign), but prefer `entry().or_insert_with(|| ContextRuntime { ... })` to avoid constructing unused runtime objects on races.
