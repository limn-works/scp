# scp-ffi-wasm -- wasm-bindgen Bridge

The browser-target Rust half of `@limn-works/scp-ts`. Compiled to WebAssembly
via `wasm-pack` and consumed by the TypeScript SDK in `bindings/typescript/`.

## Architecture constraint: no scp-runtime dependency

`scp-runtime` depends on `tokio = { features = ["full"] }`, which requires a
multi-thread runtime that cannot compile to `wasm32-unknown-unknown`. This crate
imports pure sync types from `scp-protocol` and event log types from
`scp-event-log`. Only WASM-specific orchestration and JS bridge logic remains
local. See ADR-034.

## Architecture

**Single-threaded runtime**: WASM runs on one thread. The context registry uses
`thread_local! { RefCell<HashMap<String, WasmContextRuntime>> }` -- no mutex or
DashMap needed. Access follows the same `with_context(id, closure)` pattern as
the other bridges.

**Shared imports from scp-protocol**: Sender keys, UCAN validation, tool types,
governance types, context events, broadcast context, discovery types, sync
policy, economy formula, SCPID types, and more are imported from `scp-protocol`
and `scp-event-log` -- not reimplemented locally.

**Event log**: Each context owns an `scp_event_log::EventLog` instance (shared
implementation). Events are appended via `append_unsigned_event` and proofs
generated via `prove_inclusion`/`prove_absence`.

**JS callback injection**: Browser-native APIs (WebCrypto, OPFS, IndexedDB) are
not available as Rust crates. `JsKeyCustody` and `JsStorage` are extern types
that the TypeScript wrapper injects (ADR-022).

**JS-idiomatic serialization**: Enum types (GovernanceAction, ContextEvent) are
converted between serde's externally-tagged PascalCase and JS-idiomatic
internally-tagged camelCase at the FFI boundary. ContextParams fields use
camelCase (maxChainDepth, maxNestingDepth, sessionCap).

## Modules

| Module | Domain |
|--------|--------|
| `bridge.rs` | Bridge connector operations (register, trust evaluation, shadow identities) |
| `context.rs` | Context lifecycle (create, join, leave, close, send, subscribe, export, import) |
| `custody.rs` | `JsKeyCustody` extern type (WebCrypto injection) |
| `discovery.rs` | Context discovery, petnames, handle registry |
| `error.rs` | `ScpWasmError` with stable error codes (`SCP-*-NNNN`) |
| `event_log.rs` | Event log query, Merkle proofs |
| `identity.rs` | Ed25519 key generation, `did:dht:z{zbase32}` derivation |
| `manager.rs` | `WasmContextManager` -- context state, governance, broadcast |
| `provenance.rs` | Provenance chain depth, quality evaluation, metadata attachment |
| `runtime.rs` | WASM-local registry, `ToolRegistry`, schema validation |
| `scpid.rs` | SCPID stateless DID auth (types from `scp-protocol`) |
| `storage.rs` | `JsStorage` extern type (OPFS/IndexedDB injection) |
| `sync.rs` | Offline classification and sync policy |
| `time.rs` | Hardened time source (captured `Date.now` reference), `WasmClock` |
| `tools.rs` | Tool register (deterministic IDs), invoke, verify |
| `transport.rs` | Transport connect, disconnect, status |
| `trust.rs` | Trust engine (attestation, challenge, participation verification) |
| `ucan.rs` | UCAN validate (delegates to scp-protocol), mint, revoke |

## Build

```sh
# Full WASM build (produces pkg/ with JS + .wasm)
wasm-pack build crates/scp-ffi/wasm --target bundler

# Type-check without full build
cargo check --target wasm32-unknown-unknown -p scp-ffi-wasm

# Lint
cargo clippy -p scp-ffi-wasm --target wasm32-unknown-unknown

# Conformance tests
cargo test -p scp-runtime --test wasm_conformance --features scp-runtime/testing
```

## Crate type

`cdylib` only (WASM module).
