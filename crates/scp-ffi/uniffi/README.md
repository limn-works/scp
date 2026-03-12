# scp-ffi-uniffi -- UniFFI Bridge

Generates Swift and Kotlin bindings from a single Rust definition via UniFFI
proc-macros (`#[uniffi::export]`). Consumed by the Swift SDK
(`bindings/swift/`) and Kotlin SDK (`bindings/kotlin/`).

## Architecture

**Shared ContextManager**: Same pattern as PyO3 and NAPI -- a single
`Arc<ContextManager>` in `OnceLock` owns all context lifecycle, membership,
governance, broadcast, and TTL state. Bridge functions access it via
`crate::runtime::context_manager()`.

**Single bridge module**: All exports live in `bridge.rs` -- function groups
for identity, context lifecycle, membership queries, governance, broadcast,
TTL, tools, UCAN, event log, transport, discovery, provenance, trust, and sync.

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
| `bridge.rs` | All `#[uniffi::export]` functions and types |
| `runtime.rs` | ContextManager initialization, UCAN state |
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
