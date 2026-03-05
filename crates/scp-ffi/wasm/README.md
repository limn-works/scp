# scp-ffi-wasm

`wasm-bindgen` FFI bridge that compiles SCP protocol operations to WebAssembly for browser targets. Consumed by the `@scp/sdk` TypeScript package.

## Architecture

### No scp-core dependency (ADR-034)

`scp-core` depends on `tokio = { features = ["full"] }`, which requires a multi-thread runtime. The `wasm32-unknown-unknown` target cannot compile this. Therefore, **this crate does not depend on scp-core**. Protocol logic (tool registry, Merkle tree, schema validation, UCAN revocation) is re-implemented locally in `src/runtime.rs` using WASM-compatible crates only.

All re-implementations must be algorithm-identical to scp-core. When scp-core changes an algorithm, `runtime.rs` must be updated in lockstep. See `.docs/lessons/wasm-cid-consistency.md`.

### Relationship to scp-ffi-common

`scp-ffi-common` (`crates/scp-ffi/common/`) provides shared bridge adapter types (DID resolver, UCAN revocation checker, proof resolver, nonce tracker) used by the PyO3, napi-rs, and UniFFI bridges. **This crate does not use scp-ffi-common** because scp-ffi-common depends on scp-core, which cannot compile to WASM. The WASM bridge re-implements equivalent logic locally.

The napi-rs bridge (`crates/scp-ffi/napi/`) serves Node.js/Bun and does depend on scp-core directly.

### JS mapping

Types are exposed as opaque `#[wasm_bindgen]` structs with getter properties. Async bridge functions use `wasm_bindgen_futures::future_to_promise` to return `Promise<T>` to JavaScript. WASM is single-threaded -- the browser event loop drives all async execution (no Tokio runtime).

Browser-native APIs (WebCrypto, OPFS, IndexedDB) are injected from the TypeScript wrapper via extern types (`JsKeyCustody`, `JsStorage`, `JsMessageCallback`). See ADR-022.

### Module structure

| Module | Responsibility |
|--------|---------------|
| `lib.rs` | Entry point (`scp_init`, `scp_version`), module declarations |
| `runtime.rs` | WASM-local runtime registry: `WasmContextRuntime`, `ToolRegistry`, `WasmEventLog`, Merkle proofs, schema validation, `with_context` |
| `identity.rs` | `WasmIdentity`, `WasmDIDDocument`, identity lifecycle (create, load, resolve) |
| `context.rs` | `WasmContextHandle`, `WasmMessage`, context lifecycle (create, join, leave, close, send, subscribe) |
| `tools.rs` | Tool registration, invocation, verification |
| `ucan.rs` | UCAN token management (validate, mint, revoke) |
| `event_log.rs` | Event log query, Merkle inclusion/absence proofs |
| `transport.rs` | Transport connect/disconnect/status |
| `custody.rs` | `JsKeyCustody` extern type -- WebCrypto injection point |
| `storage.rs` | `JsStorage` extern type -- OPFS/IndexedDB injection point |
| `error.rs` | `ScpWasmError` enum with stable error codes (`[SCP-IDENT-1000]` through `[SCP-VALID-7000]`) |

### Runtime registry

WASM is single-threaded, so the context registry uses `thread_local! { RefCell<HashMap<...>> }` instead of the `DashMap` used by the PyO3 bridge. Access pattern: `with_context(context_id, |rt| { ... })`.

## Build

```sh
wasm-pack build crates/scp-ffi/wasm --target bundler
```

Produces `pkg/scp_ffi_wasm.js` + `pkg/scp_ffi_wasm_bg.wasm` for the TypeScript wrapper.

For type-checking without a full wasm-pack build:

```sh
cargo check --target wasm32-unknown-unknown -p scp-ffi-wasm
```

CI lint:

```sh
cargo clippy -p scp-ffi-wasm --target wasm32-unknown-unknown
```

## Testing

This crate has no standalone unit test suite. Algorithm correctness is verified via conformance tests that run both the scp-core and WASM implementations and compare outputs:

```sh
cargo test -p scp-core --test wasm_conformance
```

## Adding new bindings

To expose a new type or function to JavaScript:

1. **Add a module** (or extend an existing one) under `src/`. Follow the pattern in `identity.rs` or `tools.rs`.

2. **Define the Rust type** as a `#[wasm_bindgen]` struct. Expose fields via `#[wasm_bindgen(getter)]` methods. Use `js_name = "camelCase"` for JS naming conventions.

3. **Write bridge functions** as `#[wasm_bindgen]` free functions. Async functions return `Promise` via `future_to_promise`. Accept owned `String` parameters (not `&str` -- wasm-bindgen requirement).

4. **Re-implement any scp-core logic** in `runtime.rs` if the function requires protocol algorithms. The WASM bridge cannot call scp-core. Algorithms must be identical -- add a case to the `wasm_conformance` test to prove equivalence.

5. **Map errors** using `ScpWasmError` variants from `error.rs`. Every error must carry a stable `SCP-{CATEGORY}-{NUMBER}` code.

6. **Declare the module** in `lib.rs` (`pub mod your_module;`).

7. **For browser-native APIs** (crypto, storage, networking), define an `extern "C"` type with `#[wasm_bindgen]` method signatures. The TypeScript wrapper injects the implementation. See `custody.rs` and `storage.rs` for the pattern.
