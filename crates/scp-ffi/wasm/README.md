# scp-ffi-wasm -- wasm-bindgen Bridge

The browser-target Rust half of `@limn-works/scp-ts`. Compiled to WebAssembly
via `wasm-pack` and consumed by the TypeScript SDK in `bindings/typescript/`.

## Critical constraint: no scp-core dependency

`scp-core` depends on `tokio = { features = ["full"] }`, which requires a
multi-thread runtime that cannot compile to `wasm32-unknown-unknown`. This crate
**does not depend on scp-core**. Protocol algorithms (tool registry, Merkle
tree, schema validation, UCAN validation, Ed25519 signing) are re-implemented
locally in `runtime.rs` using WASM-compatible crates only.

All re-implementations must be algorithm-identical to scp-core. When scp-core
changes an algorithm, this crate must be updated in lockstep. See ADR-034.

## Architecture

**Single-threaded runtime**: WASM runs on one thread. The context registry uses
`thread_local! { RefCell<HashMap<String, WasmContextRuntime>> }` -- no mutex or
DashMap needed. Access follows the same `with_context(id, closure)` pattern as
the other bridges.

**Dual storage for events**: The event log uses two layers:
1. `WasmEventLog` in `runtime.rs` -- Merkle tree of leaf hashes for
   cryptographic proofs (inclusion/absence).
2. `EVENT_METADATA` in `event_log.rs` -- full event metadata (type, actor,
   timestamp, payload) for filtered queries.

Both are keyed by context ID and written atomically by `append_event()`.

**JS callback injection**: Browser-native APIs (WebCrypto, OPFS, IndexedDB) are
not available as Rust crates. `JsKeyCustody` and `JsStorage` are extern types
that the TypeScript wrapper injects. This is the permanent WASM architecture per
ADR-022.

**UCAN validation**: Full 11-step ADR-016 pipeline including Ed25519 signature
verification, delegation chain traversal, nonce replay detection, and revocation
checking. `ucan_mint` generates real Ed25519 keypairs via `rand_core::OsRng`.

## Modules

| Module | Domain |
|--------|--------|
| `runtime.rs` | WASM-local registry, `ToolRegistry`, `WasmEventLog`, Merkle proofs, schema validation |
| `identity.rs` | Ed25519 key generation, `did:dht:z{zbase32}` derivation |
| `context.rs` | Context lifecycle (create, join, leave, close, send, subscribe, export, import) |
| `tools.rs` | Tool register (deterministic IDs), invoke (echo mode), verify |
| `ucan.rs` | Full UCAN validate, mint, revoke |
| `event_log.rs` | Event metadata storage, query with filtering, Merkle proofs |
| `custody.rs` | `JsKeyCustody` extern type (WebCrypto injection) |
| `storage.rs` | `JsStorage` extern type (OPFS/IndexedDB injection) |
| `transport.rs` | Transport connect, disconnect, status |
| `discovery.rs` | Context discovery |
| `error.rs` | `ScpWasmError` with stable error codes (`SCP-*-NNNN`) |

## Build

```sh
# Full WASM build (produces pkg/ with JS + .wasm)
wasm-pack build crates/scp-ffi/wasm --target bundler

# Type-check without full build
cargo check --target wasm32-unknown-unknown -p scp-ffi-wasm

# Lint
cargo clippy -p scp-ffi-wasm --target wasm32-unknown-unknown

# Conformance tests (runs against scp-core to verify algorithm parity)
cargo test -p scp-core --test wasm_conformance
```

## Crate type

`cdylib` only (WASM module).
