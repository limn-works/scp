# scp-ffi-uniffi -- UniFFI Bridge

Generates Swift and Kotlin bindings from a single Rust definition via UniFFI
proc-macros (`#[uniffi::export]`). Consumed by the Swift SDK
(`bindings/swift/`) and Kotlin SDK (`bindings/kotlin/`).

## Architecture

**`Scp` object + shared Supervisor**: Same per-instance pattern as PyO3 and
NAPI. The `#[derive(uniffi::Object)] Scp` (in `scp.rs`) is the caller-owned
handle exposed to Swift/Kotlin; its sole `#[uniffi::constructor] with_storage`
takes a typed `StorageConfig` and is fail-closed (spec §17.6) -- there is no
zero-argument constructor. `Scp` wraps a `UniffiBridgeInstance` that holds a
shared `Arc<Supervisor>` in its `BridgeInstanceCore.supervisor` slot; the
Supervisor owns all context lifecycle, membership, governance, broadcast, and
TTL state. It is built by `build_supervisor` in `runtime.rs` via
`Supervisor::with_providers_and_journal(...)` (durable saga journal) and reached
through `self.core.try_supervisor()` / `has_supervisor()`. This replaced the
previously-shared `Arc<ContextManager>`, now deleted (see
[ADR-049](../../../.docs/adrs/ADR-049-actor-per-context.md)); there is no
`context_manager()` accessor. See
[construction.md](../../../.docs/standards/construction.md) (ADR-052) for the
mandatory-config API rule.

**Single bridge module**: All `#[uniffi::export]` free functions live in
`bridge.rs` -- function groups for identity, context lifecycle, membership
queries, governance, broadcast, TTL, tools, UCAN, event log, transport,
discovery, provenance, trust, and sync.

**Callback interfaces**: Platform-specific operations are injected from
Swift/Kotlin via `#[uniffi::export(callback_interface)]` traits:
- `MessageListener` -- incoming message streams
- `KeyCustodyProvider` -- Ed25519 signing, DH, pseudonym derivation
- `StorageProvider` -- persistent key-value storage
- `PushProvider` -- APNs / FCM push notifications
- `DeviceAttestationProvider` -- App Attest / Play Integrity

**Async bridging**: All I/O-bound functions are `async fn`. UniFFI generates
Swift `async` functions (via `CheckedContinuation`) and Kotlin `suspend`
functions (via coroutines). A shared tokio multi-thread runtime executes
futures.

**Handle counting**: Opaque objects (`Identity`, `ContextHandle`, `UcanToken`,
`TransportManager`) use `Arc<T>` wrapping with a global `AtomicUsize` reference
counter. `scp_shutdown(timeout_secs)` blocks until all handles are released.

**Error mapping**: `ScpError` enum with variants (`Identity`, `Context`,
`Permission`, `Crypto`, `Transport`, `Tool`, `Validation`), each carrying a
`message` and structured `code` (`SCP-{CATEGORY}-{NUMBER}`).

## Modules

| File | Contents |
|------|----------|
| `scp.rs` | The `Scp` UniFFI object -- caller-owned handle; sole fail-closed `with_storage(StorageConfig)` constructor |
| `bridge.rs` | All `#[uniffi::export]` free functions and types |
| `runtime.rs` | `UniffiBridgeInstance`: supervisor slot + `build_supervisor`, storage selection, UCAN state |
| `server.rs` | Relay / application-node server startup (wraps `scp-ffi-common::server`) |
| `lib.rs` | Tokio runtime, handle counting, callback interface traits, UDL scaffolding |

## Build

```sh
# Build native library
cargo build -p scp-ffi-uniffi

# Run Rust tests
cargo test -p scp-ffi-uniffi

# Generate Swift bindings
cargo run -p scp-ffi-uniffi --bin uniffi-bindgen -- generate \
  --library target/debug/libscp_ffi_uniffi.dylib --language swift --out-dir out/

# Generate Kotlin bindings
cargo run -p scp-ffi-uniffi --bin uniffi-bindgen -- generate \
  --library target/debug/libscp_ffi_uniffi.dylib --language kotlin --out-dir out/
```

## Crate type

`cdylib` (dynamic linking) + `staticlib` (iOS) + `lib` (test linkage). The UDL
file (`scp.udl`) is minimal -- only the namespace anchor. All types and
functions are defined via proc-macros.

## Feature flags

`allow_in_memory_custody` -- gates the `"in_memory"` path in `identity_create`.
Stores keys in unprotected heap memory. Suitable for testing and desktop; must
NOT be enabled in production mobile builds.
