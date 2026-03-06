# scp-ffi-wasm — wasm-bindgen Bridge Layer

## Overview

This crate is the browser-target Rust half of the `@scp/sdk` TypeScript package. It exposes SCP protocol operations to JavaScript via `wasm-bindgen`, compiled to WebAssembly with `wasm-pack`. See ADR-022 in `.docs/adrs/phase-4.md`.

## Architecture Constraint: No scp-core Dependency

`scp-core` depends on `tokio = { features = ["full"] }` which requires a multi-thread runtime. The `wasm32-unknown-unknown` target cannot compile this. Therefore, **this crate does NOT depend on scp-core**. Protocol logic (tool registry, Merkle tree, schema validation, UCAN revocation) is re-implemented locally in `src/runtime.rs` using WASM-compatible crates only.

All re-implementations must be algorithm-identical to scp-core. When scp-core changes an algorithm, `runtime.rs` must be updated in lockstep. See `.docs/lessons/wasm-cid-consistency.md`.

## Module Structure

| Module | Responsibility |
|--------|---------------|
| `manager.rs` | `WasmContextManager` — central coordinator for all context state. Mirrors `scp_core::context::manager::ContextManager` API surface. All bridge functions delegate here. |
| `runtime.rs` | Pure algorithm implementations: `ToolRegistry`, `WasmEventLog`, Merkle proof functions, schema validation. No state management. |
| `context.rs` | Context lifecycle bridge: create, join, leave, close, send, subscribe, membership queries, governance, broadcast, TTL, drain_events. All delegate to `manager.rs`. |
| `tools.rs` | Tool registration, invocation, verification. Delegates to `manager.rs`. |
| `ucan.rs` | UCAN token management: validate (full 11-step pipeline), mint, revoke. Validation algorithm is local; state ops (nonces, revocations) delegate to `manager.rs`. |
| `event_log.rs` | Event log query, Merkle inclusion/absence proofs. Delegates to `manager.rs`. |
| `identity.rs` | Identity create, load, resolve |
| `transport.rs` | Transport connect/disconnect/status |
| `custody.rs` | `JsKeyCustody` extern type (WebCrypto injection point) |
| `storage.rs` | `JsStorage` extern type (OPFS/IndexedDB injection point) |
| `error.rs` | `ScpWasmError` → `JsError` mapping with stable error codes |

## WasmContextManager (manager.rs)

Central coordinator for all context state. Mirrors `ContextManager` from scp-core. Uses `thread_local! { RefCell<WasmContextManager> }` for the singleton (WASM is single-threaded). Access via `with_manager(|mgr| { ... })`.

The manager owns all per-context state (`PerContextState`): lifecycle state, members, roles, tool registry, event log (Merkle tree), UCAN nonce/revocation tracking, event buffer, broadcast state, governance replay protection, write-revoked members, and TTL.

All 24 `GovernanceAction` variants are dispatchable through `execute_governance_action`. Broadcast operations (subscribe, publish, unsubscribe, block) are direct methods. Membership queries (member_count, is_member, member_dids, member_role) mirror `ContextManager` exactly.

## UCAN Validation — Full 11-Step Pipeline

`ucan_validate` performs the full 11-step UCAN validation pipeline from ADR-016:
1. Parse JWT format (3 base64url segments)
2. Ed25519 signature verification via `ed25519-dalek`
3. Delegation chain verification (aud/iss linkage, recursive)
4. Root issuer must be context creator
5. Audience DID validation (with RED-105 trailing-slash protection)
6. Capability match (fail-closed on unparseable URIs)
7. Attenuation enforcement (child capabilities ⊆ parent)
8. Capability ceiling check
9. Nonce replay detection (delegated to `WasmContextManager`)
10. Revocation check (delegated to `WasmContextManager`)
11. Time bounds (exp, nbf, 24h max lifetime)

## UCAN Revocation — CID Consistency

`ucan_revoke` and `ucan_validate` MUST hash the same input to compute the revocation CID. **Both must call `compute_token_cid` on the full JWT string** — not a nonce-derived ID, not the payload struct. Any deviation silently breaks revocation. See `.docs/lessons/wasm-cid-consistency.md`.

`ucan_revoke` parameter: full encoded JWT string (same as PyO3 `py_ucan_revoke`).
`ucan_validate` revocation check: `compute_token_cid(&token)` where `token` is the full JWT parameter.

## Capability Wildcard Matching

When checking `can_str == "*"`, the wildcard only applies within the correct resource scope. Always check the `with` field first:

```rust
let resource_matches = with_str == required_resource || with_str.starts_with(&format!("{required_resource}/"));
let can_matches = can_str == required_action || can_str == "*";
has_capability = resource_matches && can_matches;
```

A token granting `scp:ctx:A/*` must NOT pass validation for `scp:ctx:B/messages:write`.

## Tool Invocation — Capability Check

`tool_invoke` currently ignores the `identity_did` parameter (`let _ = &identity_did`). No role-state capability check is performed because `WasmContextRuntime` has no `RoleState` field. When `RoleState` is wired, add `has_tool_invoke_capability` check matching the PyO3 bridge. See `.docs/lessons/enforcement-wiring-gap.md`.

## Build

```sh
wasm-pack build crates/scp-ffi/wasm --target bundler
```

Produces `pkg/scp_ffi_wasm.js` + `pkg/scp_ffi_wasm_bg.wasm` consumed by the TypeScript wrapper.

For type-checking without a full wasm-pack build:
```sh
cargo check --target wasm32-unknown-unknown -p scp-ffi-wasm
```

## Gotchas

- `wasm-bindgen` requires owned `String` parameters (not `&str`) for `#[wasm_bindgen]` functions — `clippy::needless_pass_by_value` is suppressed crate-wide.
- `wasm-bindgen` does not support `const fn` on exported methods — `clippy::missing_const_for_fn` is suppressed crate-wide.
- All async bridge functions use `wasm_bindgen_futures::future_to_promise` — futures must be non-blocking (no blocking I/O inside futures).
- `uuid::Uuid::new_v4()` requires the `getrandom/js` feature to use `crypto.getRandomValues` in the browser. Verify this is present in `Cargo.toml` when adding UUID usage.
- `js_sys::Date::now()` returns milliseconds since epoch as `f64` — divide by 1000.0 for seconds. Do not use `std::time::SystemTime` (not available on wasm32).
