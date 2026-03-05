# scp-ffi-napi

NAPI-RS native addon exposing `scp-core` to Node.js and Bun. Compiled to a `.node` cdylib consumed by the `@scp/sdk` TypeScript package in `bindings/typescript/`.

## Architecture

### Type mapping

Rust types are exposed to JS via napi-rs `#[napi]` annotations:

- **Opaque classes** (`#[napi] pub struct`) -- JS objects with getters/methods. Private key material never crosses the FFI boundary. Four opaque types: `NapiIdentity`, `NapiContextHandle`, `NapiUcanToken`, `NapiTransportManager`.
- **Object literals** (`#[napi(object)]`) -- plain JS objects with public fields, used for data records returned across the boundary (`NapiDIDDocument`, `NapiMessage`, `NapiToolDefinition`, `NapiEvent`, `NapiProof`, `NapiTransportStatus`, `NapiUcanTokenData`, `NapiToolVerificationResult`).
- **Bridge functions** (`#[napi] pub async fn`) -- top-level JS functions that return `Promise<T>`. napi-rs runs the Rust `Future` on the tokio runtime and resolves the Promise on the JS event loop.

### Module structure

| Module | Domain | Key functions |
|--------|--------|---------------|
| `identity.rs` | DID lifecycle | `identity_create`, `identity_create_with_agent_key`, `identity_load`, `identity_resolve` |
| `context.rs` | Context lifecycle | `context_create`, `context_join`, `context_leave`, `context_close`, `context_send`, `context_subscribe` |
| `ucan.rs` | UCAN tokens | `ucan_validate`, `ucan_mint`, `ucan_revoke` |
| `tools.rs` | Tool registry | `tool_register`, `tool_invoke`, `tool_verify` |
| `event_log.rs` | Merkle event log | `event_log_query`, `event_log_verify` |
| `transport.rs` | Relay connections | `transport_connect`, `transport_status`, `transport_disconnect` |
| `runtime.rs` | Per-context state | `ensure_registered`, `with_context`, `remove_context` |
| `error.rs` | Error hierarchy | `ScpNapiError` with `[SCP-{CAT}-{NUM}]` codes |

### Relationship to `scp-ffi-common`

`scp-ffi-common` (`crates/scp-ffi/common/`) contains bridge adapter types shared across all FFI bridges (PyO3, napi-rs, UniFFI). Specifically: `BridgeDidResolver`, `BridgeRevocationChecker`, `BridgeProofResolver`, `BridgeNonceTracker`. These adapt `scp-core`'s validation traits to the runtime state held by each bridge. The NAPI bridge imports and uses them in `ucan.rs`.

### Async model

A single tokio multi-thread `Runtime` is created at module load (`OnceLock<Runtime>` in `lib.rs`). All `#[napi] pub async fn` functions run on this runtime. napi-rs handles the Rust-to-JS async bridging: the Rust future executes on tokio worker threads, and the resulting `Promise` resolves on the Node.js event loop.

### State model

Unlike the PyO3 bridge (which uses a global `DashMap<String, ContextRuntime>` for all state), the NAPI bridge stores most state directly on opaque handle structs. `NapiContextHandle` carries context metadata, key custody, and signing key references. `NapiIdentity` retains `ScpIdentity`, `InMemoryKeyCustody`, and `DidDocument`.

A supplementary global `ContextRuntime` registry in `runtime.rs` holds per-context objects needed by UCAN and event log operations (event logs, revocation lists, nonce trackers). This registry uses lazy initialization: the first UCAN or event log call on a context triggers registration from the `NapiContextHandle` metadata.

### Shutdown ordering

A global `HANDLE_COUNT` (`AtomicUsize`) tracks live opaque FFI handles. Each opaque type increments on construction and decrements in `Drop`. `scp_shutdown(timeout_secs)` polls this counter at 10ms intervals and blocks until it reaches zero or the timeout elapses. Callers should invoke this from a `process.on('exit')` handler.

### Error model

`ScpNapiError` is a `thiserror` enum with variants for each error category (Identity, Context, Permission, Crypto, Transport, Tool, Validation). Each variant carries a stable error code (`SCP-{CAT}-{NUM}`) and a human-readable message. The `Into<napi::Error>` impl formats the JS `Error.message` as `[{code}] {category} error: {message}`. The TypeScript SDK parses the bracketed code to select the appropriate `ScpError` subclass. `From` impls map all `scp-core` error types to the correct variant.

## Build

### Prerequisites

- Rust toolchain (via mise)
- napi-rs CLI: `cargo install napi-cli` (or use `@napi-rs/cli` via bun)

### Compile

```sh
# Type-check only (no cdylib linking)
cargo check -p scp-ffi-napi

# Full build (produces .node artifact)
napi build --platform --release crates/scp-ffi/napi
```

The `build.rs` script calls `napi_build::setup()` to configure the napi-rs code generator. The crate type is `cdylib` only.

### Artifacts

The build produces a platform-specific `.node` file (e.g., `scp-ffi-napi.darwin-arm64.node`). This file is loaded by the TypeScript SDK at runtime via `@scp/sdk-napi`.

## Testing

```sh
# Rust unit tests (no Node.js or Python linkage required)
cargo test -p scp-ffi-napi
```

Tests are standard `#[cfg(test)]` modules within each source file. The `runtime.rs` module provides `register_test_context()` for unit tests that need runtime state without constructing a full `NapiContextHandle`. No special environment variables are needed (unlike `scp-ffi`, which requires `DYLD_LIBRARY_PATH` for Python linkage).

Integration testing of the full JS-to-Rust path runs through the TypeScript SDK tests in `bindings/typescript/` (`bun test`), which load the compiled `.node` addon.

## Adding new bindings

To expose a new Rust type or function to JS:

### 1. Choose the right annotation

- **Opaque handle** (has methods, private state, custom `Drop`): use `#[napi] pub struct`. Add `increment_handle_count()` in the constructor and `decrement_handle_count()` in the `Drop` impl.
- **Plain data record** (all fields public, no methods): use `#[napi(object)] pub struct`.
- **Async function** returning a `Promise`: use `#[napi] pub async fn ... -> napi::Result<T>`.
- **Sync function**: use `#[napi] pub fn ... -> napi::Result<T>` (or just `-> T` for infallible).

### 2. Add the module

Create `src/{domain}.rs` with the bridge types and functions. Add `pub mod {domain};` to `lib.rs`.

### 3. Map errors

Add a `From<YourCoreError> for ScpNapiError` impl in `error.rs`. Pick the appropriate variant and assign a stable error code from the ranges defined in `sdk-common.md`.

### 4. Wire to scp-core

Call `scp-core` APIs directly. The tokio runtime is available for all async operations. For operations that need per-context state (event log, revocation, nonce tracking), use `runtime::ensure_registered(handle)` and `runtime::with_context(context_id, |rt| { ... })`.

### 5. Use scp-ffi-common for shared logic

If your bridge logic (trait adapter, resolver, checker) is also needed by the PyO3 or UniFFI bridges, put it in `crates/scp-ffi/common/` and import from `scp_ffi_common`.

### 6. Add to TypeScript SDK

The TypeScript wrapper in `bindings/typescript/src/internal/native.ts` imports from the `.node` addon. Add your new function to the native bridge interface, then expose it through the SDK's public API.

### Checklist

- [ ] Opaque handles increment/decrement `HANDLE_COUNT`
- [ ] All errors use `ScpNapiError` with stable codes (not raw strings)
- [ ] Private key material never appears in error messages, logs, or return values
- [ ] `#[napi(object)]` structs have only public fields of napi-compatible types
- [ ] Async functions that are not actually async are annotated `#[allow(clippy::unused_async)]` with a comment explaining napi-rs requires it for Promise return
- [ ] New dependencies added to `Cargo.toml` use `workspace = true` where available
- [ ] `cargo test -p scp-ffi-napi` passes
- [ ] `cargo clippy -p scp-ffi-napi` passes
