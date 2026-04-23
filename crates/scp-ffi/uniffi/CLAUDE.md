# scp-ffi-uniffi — UniFFI Bridge Layer

## Overview

This crate generates Swift and Kotlin bindings from a single Rust definition via UniFFI proc-macros (`#[uniffi::export]`). It mirrors the PyO3 bridge (`crates/scp-ffi/`) architecture but targets mobile/desktop platforms instead of Python.

## Architecture

### Shared ContextManager (`runtime.rs`) — issue #387

A single `Arc<ContextManager>` (from `scp-core`) is created once via `OnceLock` and shared across all bridge functions. The `ContextManager` owns all per-context state (membership, roles, governance, broadcast, TTL) and the injected providers. This replaced the old `DashMap<String, ContextRuntime>` global registry.

The manager is initialized via `init_context_manager_with_did(local_did)` with a real `MlsCryptoProvider::new(local_did)` bound to the caller's DID, a `NotConfiguredTransportProvider` (or `RelayTransportProvider` when `auto_wire_context_manager` succeeds), and a persistent `MerkleEventLogProvider` backed by `ProtocolRepositoryEventLogBridge` over encrypted in-memory storage (#484). The previous DID-less `FfiBridgeCrypto` / `FfiBridgeTransport` stub path was removed — first-call entry points (`context_create`, `context_join`, `context_import`, `register_local_did`, `identity_create`) now all carry the local DID. Platform-specific key custody is injected via the `KeyCustodyProvider` callback.

Bridge functions access the manager via `crate::runtime::context_manager()`.

### Broadcast subscribe routes through the supervisor shim

`broadcast_subscribe` no longer invokes the generic
`ContextManager::subscribe_broadcast::<DidResolver, NonceTracker, RevocationChecker, ProofResolver>`
typed path. After the ADR-049 commit-11 shim landed, the bridge routes
through `Supervisor::dispatch_broadcast_command` with a
`BroadcastCommand::SubscribeBroadcast` payload — the no-op
UCAN-validation trait stubs (`NoOpDidResolver` / `NoOpNonceTracker` /
`NoOpRevocationChecker` / `NoOpProofResolver`) were deleted once the
typed callsite went away.

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
| Tools | `tool_register`, `tool_invoke`, `tool_verify` |
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
- `Identity`, `Context`, `Permission`, `Crypto`, `Transport`, `Tool`, `Validation`
- Each variant carries `message` (human-readable) and `code` (SCP-{CATEGORY}-{NUMBER})
- Comprehensive `From<>` impls for all scp-core error types (15+ conversions)

### Async Bridging (ADR-021)

All I/O-bound functions are `async fn`. UniFFI generates Swift `async` functions (via `CheckedContinuation`) and Kotlin `suspend` functions (via coroutines). The shared tokio runtime (`RUNTIME` in `lib.rs`) executes futures.

## Gotchas

- The tokio runtime (`RUNTIME` in `lib.rs`) must be initialized before any async bridge call. It is created as a `OnceLock<Runtime>` and exposed via `runtime()`.
- **Shared ContextManager (post-#387):** All context lifecycle/membership/governance/broadcast/TTL operations delegate to `crate::runtime::context_manager()`. The old `ContextRuntime` struct and `DashMap` registry are deleted. Context state lives in the `ContextManager`, not in the bridge.
- Bridge functions create ephemeral `scp_core::context::ContextHandle` instances to pass `context_id` to the manager. The FFI `ContextHandle` (in `bridge.rs`) remains a separate opaque object with its own state lock for handle counting and state queries.
- **Close authorization**: `context_close` does NOT perform bridge-layer authorization. It delegates to `ContextManager::close_context`, which checks the `ContextClose` capability via `ttl::close_context`. The ContextManager is the authoritative auth layer.
- **register_local_did**: `context_create` calls `manager.register_local_did(identity.did)` after creating the context, matching NAPI's behavior for defense-in-depth.
- `ucan_mint` uses `InMemoryKeyCustody` for signing (feature-gated). Real `KeyCustody` wiring deferred to platform integration.
- Opaque objects (`Identity`, `ContextHandle`, `UcanToken`, `TransportManager`) use `Arc<T>` wrapping and manual handle counting (`increment_handle_count`/`decrement_handle_count` in `lib.rs`). `Drop` impls decrement counts.
- `OpaqueInMemoryKeyCustody` wrapper implements `Debug` with redacted output to prevent key material in logs.
- The `scp.udl` file is minimal (namespace anchor only). All types and functions are defined via proc-macros.
