# scp-ffi-uniffi — UniFFI Bridge Layer

## Overview

This crate generates Swift and Kotlin bindings from a single Rust definition via UniFFI proc-macros (`#[uniffi::export]`). It mirrors the PyO3 bridge (`crates/scp-ffi/`) architecture but targets mobile/desktop platforms instead of Python.

## Architecture

### Shared Supervisor (`runtime.rs`) — post-ADR-049 / commit 12 (supersedes the prior `ContextManager`-keyed wiring tracked in #387)

A single `Arc<Supervisor>` (from `scp-runtime`) is held in the per-bridge `BridgeInstanceCore.supervisor` slot and shared across all bridge functions. The `Supervisor` owns all per-context state (membership, roles, governance, broadcast, TTL) and the injected providers. This replaced the previously-shared `Arc<ContextManager>` (deleted in commit 12 of the ADR-049 ladder; see `.docs/adrs/ADR-049-actor-per-context.md`).

The supervisor is built via `Supervisor::with_providers_and_journal(...)` (durable saga journal) with a real `MlsCryptoProvider::new(local_did)` bound to the caller's DID, a `NotConfiguredTransportProvider` (or `RelayTransportProvider` when `auto_wire_supervisor` succeeds), and a persistent `MerkleEventLogProvider` backed by `ProtocolRepositoryEventLogBridge` over encrypted in-memory storage (#484). The previous DID-less `FfiBridgeCrypto` / `FfiBridgeTransport` stub path was removed — first-call entry points (`context_create`, `context_join`, `context_import`, `register_local_did`, `identity_create`) now all carry the local DID. Platform-specific key custody is injected via the `KeyCustodyProvider` callback.

Bridge functions access the supervisor via `crate::runtime::supervisor()`.

### Broadcast subscribe routes through the supervisor shim

`broadcast_subscribe` routes through `Supervisor::dispatch_broadcast_command` with a `BroadcastCommand::SubscribeBroadcast` payload (since ADR-049 commit 11). The legacy generic typed path on the deleted `ContextManager` plus its no-op UCAN-validation trait stubs (`NoOpDidResolver` / `NoOpNonceTracker` / `NoOpRevocationChecker` / `NoOpProofResolver`) were removed once the typed callsite went away.

### Module Structure

Single-file bridge (`bridge.rs`) containing all UniFFI exports. Key function groups:

| Category | Functions |
|----------|-----------|
| Identity | `identity_create`, `identity_load`, `identity_resolve` |
| Context lifecycle | `context_create`, `context_join`, `context_leave`, `context_close`, `context_send`, `context_subscribe` |
| Membership queries | `context_member_count`, `context_is_member`, `context_member_dids`, `context_member_role` |
| Events | `context_drain_events` |
| Governance | `governance_execute` |
| Broadcast | `broadcast_subscribe`, `broadcast_unsubscribe`, `broadcast_publish`, `broadcast_block_subscriber`, `broadcast_handle_key_request`, `broadcast_subscriber_count`, `broadcast_is_subscriber`, `broadcast_admission` |
| TTL | `context_handle_ttl_expiry`, `context_propose_ttl_extension`, `context_reset_ttl_timer` |
| Local DID | `register_local_did`, `is_local_did` |
| Outlets | `outlet_register`, `outlet_invoke`, `outlet_verify` |
| UCAN | `ucan_validate`, `ucan_mint`, `ucan_revoke` |
| Event Log | `event_log_query`, `event_log_verify` |
| Transport | `transport_connect`, `transport_disconnect`, `transport_status` |

### Build

- `crate-type = ["cdylib", "staticlib"]` — cdylib for dynamic linking, staticlib for iOS
- `cargo build -p scp-ffi-uniffi` to build the native library
- `cargo test -p scp-ffi-uniffi` to run tests (no Python linkage needed, unlike scp-ffi)
- Binding generation: `cargo run -p scp-ffi-uniffi --bin uniffi-bindgen -- generate ...`

### Error Mapping

`ScpError` enum with variants mapping to Swift `throws` / Kotlin exceptions:
- `Identity`, `Context`, `Permission`, `Crypto`, `Transport`, `Outlet`, `Validation`
- Each variant carries `message` (human-readable) and `code` (SCP-{CATEGORY}-{NUMBER})
- Comprehensive `From<>` impls for all scp-core error types (15+ conversions)

### Async Bridging (ADR-021)

All I/O-bound functions are `async fn`. UniFFI generates Swift `async` functions (via `CheckedContinuation`) and Kotlin `suspend` functions (via coroutines). The shared tokio runtime (`RUNTIME` in `lib.rs`) executes futures.

## Gotchas

- The tokio runtime (`RUNTIME` in `lib.rs`) must be initialized before any async bridge call. It is created as a `OnceLock<Runtime>` and exposed via `runtime()`.
- **Shared Supervisor (post-ADR-049 / commit 12):** All context lifecycle/membership/governance/broadcast/TTL operations delegate to `crate::runtime::supervisor()`. The old `ContextRuntime` struct and `DashMap` registry are deleted. Context state lives in the `Supervisor`, not in the bridge.
- Bridge functions create ephemeral `scp_runtime::context::ContextHandle` instances to pass `context_id` to the supervisor. The FFI `ContextHandle` (in `bridge.rs`) remains a separate opaque object with its own state lock for handle counting and state queries.
- **Close authorization**: `context_close` does NOT perform bridge-layer authorization. It delegates to `Supervisor::close_context` (the hoisted `lifecycle_helpers::close_context` body) which checks the `ContextClose` capability via `ttl::close_context`. The Supervisor is the authoritative auth layer.
- **register_local_did**: `context_create` calls `supervisor.register_local_did(identity.did)` after creating the context, matching NAPI's behavior for defense-in-depth.
- `ucan_mint` uses `InMemoryKeyCustody` for signing (feature-gated). Real `KeyCustody` wiring deferred to platform integration.
- Opaque objects (`Identity`, `ContextHandle`, `UcanToken`, `TransportManager`) use `Arc<T>` wrapping and manual handle counting (`increment_handle_count`/`decrement_handle_count` in `lib.rs`). `Drop` impls decrement counts.
- `OpaqueInMemoryKeyCustody` wrapper implements `Debug` with redacted output to prevent key material in logs.
- The `scp.udl` file is minimal (namespace anchor only). All types and functions are defined via proc-macros.
