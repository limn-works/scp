# scp-ffi-uniffi — UniFFI Bridge Layer

## Overview

This crate generates Swift and Kotlin bindings from a single Rust definition via UniFFI proc-macros (`#[uniffi::export]`). It mirrors the PyO3 bridge (`crates/scp-ffi/`) architecture but targets mobile/desktop platforms instead of Python.

## Architecture

### Shared Supervisor (`runtime.rs`) — post-ADR-049 / commit 12 (supersedes the prior `ContextManager`-keyed wiring tracked in #387)

A single `Arc<Supervisor>` (from `scp-runtime`) is held in the per-bridge `BridgeInstanceCore.supervisor` slot and shared across all bridge functions. The `Supervisor` owns all per-context state (membership, roles, governance, broadcast, TTL) and the injected providers. This replaced the previously-shared `Arc<ContextManager>` (deleted in commit 12 of the ADR-049 ladder; see `.docs/adrs/ADR-049-actor-per-context.md`).

The supervisor is built via `Supervisor::with_providers_and_journal(...)` (durable saga journal) with a real `NodeMlsFactory::new(local_did)` bound to the caller's DID, a `NotConfiguredTransportProvider` (or `RelayTransportProvider` when `auto_wire_supervisor` succeeds), and a persistent `MerkleEventLogProvider` backed by `ProtocolRepositoryEventLogBridge` over encrypted in-memory storage (#484). The previous DID-less `FfiBridgeCrypto` / `FfiBridgeTransport` stub path was removed — first-call entry points (`context_create`, `context_join`, `context_import`, `register_local_did`, `identity_create`) now all carry the local DID. Platform-specific key custody is injected via the `KeyCustodyProvider` callback.

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
- **Close authorization**: `context_close` does NOT perform bridge-layer authorization. It delegates to `Supervisor::close_context` (the hoisted `lifecycle_helpers::close_context` body) which checks the `ContextClose` capability via `ttl::close_context`. The Supervisor is the authoritative auth layer. Its gate reads `UniffiBridgeInstance::read_live_context_state`, the `Option` form of the live read: an absent actor (a completed TTL expiry) and a `Closing`/`Closed`/`Expired`/`Tombstoned` supervisor state skip the dispatch and still release the per-context UCAN state, because that release has no other path after creation; only a live non-active state (`Creating`, `MigratingOut`, `Poisoned`) refuses the close.
- **A lifecycle gate reads the supervisor actor, never the cached handle state**: `context_join`, `context_leave`, `context_send`, `context_subscribe`, and the nine outlet entry points that decide an authorization question — `outlet_register`, `outlet_invoke`, `outlet_verify`, `outlet_invoke_cross_context` (both axes), `outlet_invoke_cross_context_saga` (both axes), `outlet_session_create`, `outlet_session_invoke`, `outlet_interface_expose`, and `outlet_interface_accept` — call `UniffiBridgeInstance::require_active_context(context_id, verb, mk_err)`, which reads the per-context supervisor actor and refuses unless it reports `Active`. Two outlet entry points carry no gate, and each one's doc comment says why: `outlet_session_close` releases one session entry the handle owns, and `outlet_interface_revoke` reads no context state and only builds an `InterfaceRevoked` event for the caller to distribute. The NAPI bridge draws the same line at the same two operations. `outlet_invoke_cross_context` gates both axes through it (`SCP-OUTLET-6010` for the source, `SCP-OUTLET-6011` for the target) where it had compared each handle's cached state, and `outlet_invoke_cross_context_saga` gates both axes through it where it had carried no lifecycle gate at all. `mk_err` keeps each operation's own `ScpError` variant and error code. It fails closed when no actor answers. `ContextHandle::state` stays a cached snapshot that records only the transitions THIS bridge observed, so a TTL expiry the supervisor applied on its own timer, a close another member initiated, a migration, and an actor poison all leave it reading `Active`. The `PyO3` and NAPI bridges gate on the same live read.
- **Authorization reads the supervisor actor, never a bridge copy**: `ucan_validate`, `ucan_evaluate`, `ucan_mint`, `ucan_delegate`, `ucan_revoke`, `outlet_register`, `outlet_interface_expose`, `outlet_interface_accept`, `validate_outlet_ucan_uniffi`, and the MCP `validate_capability` provider all read the capability ceiling and the context creator through `UniffiBridgeInstance::live_role_state`, which queries the per-context supervisor actor and fails closed when that actor holds no role state. `ContextHandle::ceiling_strings` and `ContextHandle::creator_did` record what THIS bridge saw at registration, so a `ModifyCeiling` governance action or an `AdminTransferred` action leaves them granting what the supervisor already withdrew, and no authorization site reads either one. `UcanContextState` carried the same two facts and is now three fields — the bridge-owned revocation list, nonce tracker, and event log — so `ensure_ucan_registered(context_id)` and `register_ucan_occupied(context_id)` take the id alone and no call site can hand an authorization decision a bridge-local rival to the actor. `ucan_mint` also resolves the signing custody and the Active Signing Key from this instance's identity registry under the live creator DID, because signing with the handle's key while issuing as the live creator would mint a token whose `iss` names one principal and whose signature belongs to another; `resolve_context_custody`, which read that key off the handle, is deleted. The three outlet entry points went further than a stale copy: each built a `ContextRoleState` on the spot from the handle's creator DID, `default_ceiling()`, and an empty member list, so `register_outlet` / `expose_outlet` / `accept_outlet_interface` graded every caller against a record this bridge invented, and a `ModifyCeiling` governance action changed nothing about what they admitted. The `PyO3` and NAPI bridges read the actor at the same decisions, so the three bridges answer one authorization question one way.
- **No role-state re-sync after governance**: the five governance entry points called `sync_role_state_from_manager`, which read the supervisor's role state and discarded it. Every UniFFI authorization site reads the actor at the moment it decides, so the call synced nothing and it is deleted.
- **register_local_did**: `context_create` calls `supervisor.register_local_did(identity.did)` after creating the context, matching NAPI's behavior for defense-in-depth.
- `ucan_mint` uses `InMemoryKeyCustody` for signing (feature-gated). Real `KeyCustody` wiring deferred to platform integration.
- Opaque objects (`Identity`, `ContextHandle`, `UcanToken`, `TransportManager`) use `Arc<T>` wrapping and manual handle counting (`increment_handle_count`/`decrement_handle_count` in `lib.rs`). `Drop` impls decrement counts.
- `OpaqueInMemoryKeyCustody` wrapper implements `Debug` with redacted output to prevent key material in logs.
- The `scp.udl` file is minimal (namespace anchor only). All types and functions are defined via proc-macros.
