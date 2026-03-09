# scp-ffi-wasm — wasm-bindgen Bridge Layer

## Overview

This crate is the browser-target Rust half of the `@scp/sdk` TypeScript package. It exposes SCP protocol operations to JavaScript via `wasm-bindgen`, compiled to WebAssembly with `wasm-pack`. See ADR-022 in `.docs/adrs/phase-4.md`.

## Architecture Constraint: No scp-core Dependency

`scp-core` depends on `tokio = { features = ["full"] }` which requires a multi-thread runtime. The `wasm32-unknown-unknown` target cannot compile this. Therefore, **this crate does NOT depend on scp-core**. Protocol logic (tool registry, Merkle tree, schema validation, UCAN revocation) is re-implemented locally in `src/runtime.rs` using WASM-compatible crates only.

All re-implementations must be algorithm-identical to scp-core. When scp-core changes an algorithm, `runtime.rs` must be updated in lockstep. See `.docs/lessons/wasm-cid-consistency.md`.

## Module Structure

| Module | Responsibility |
|--------|---------------|
| `runtime.rs` | WASM-local runtime registry: `WasmContextRuntime`, `ToolRegistry`, `WasmEventLog`, Merkle proof functions, schema validation, `with_context` |
| `context.rs` | Context lifecycle: create, join, leave, close, send, subscribe, export, import |
| `tools.rs` | Tool registration, invocation, verification |
| `ucan.rs` | UCAN token management: validate, mint, revoke |
| `event_log.rs` | Event log query, Merkle inclusion/absence proofs |
| `identity.rs` | Identity create, load, resolve |
| `transport.rs` | Transport connect/disconnect/status |
| `custody.rs` | `JsKeyCustody` extern type (WebCrypto injection point) |
| `storage.rs` | `JsStorage` extern type (OPFS/IndexedDB injection point) |
| `error.rs` | `ScpWasmError` → `JsError` mapping with stable error codes |

## Runtime Registry

WASM is single-threaded. The context registry uses `thread_local! { static CONTEXT_REGISTRY: RefCell<HashMap<String, WasmContextRuntime>> }` — no `Mutex` or `DashMap` needed. `with_context(id, closure)` is the access pattern, mirroring the PyO3 bridge's pattern.

`WasmContextRuntime` fields:
- `tool_registry: ToolRegistry` — tool registration/invocation
- `event_log: WasmEventLog` — Merkle tree (append-only, RFC 6962)
- `revoked_tokens: HashSet<String>` — UCAN revocation set (CIDs)
- `ceiling_strings: HashSet<String>` — capability ceiling for UCAN validation
- `creator_did: String` — DID of the context creator

## UCAN — Full Implementation (SCP-218)

`ucan_validate` performs the full 11-step ADR-016 validation pipeline:
1. Parse (JWT 3-segment decode)
2. Ed25519 signature verification via `ed25519-dalek`
3. Delegation chain traversal with aud/iss linkage
4. Root issuer verification (must be context creator)
5. Audience DID validation
6. Capability match with trailing-slash prefix-collision protection (RED-105)
7. Attenuation enforcement (child <= parent)
8. Capability ceiling check
9. Nonce replay detection (per-context `HashSet<String>`)
10. Revocation check (CID in revocation set)
11. Time bounds (exp, nbf, 24h max lifetime)

`ucan_mint` generates Ed25519 keypair via `rand_core::OsRng`, builds and signs JWT, returns `WasmUcanToken` with `encoded` field. Uses `build_ucan_token` helper.

`ucan_revoke` computes token CID (`SHA-256` of full JWT string) and adds to both per-context UCAN state (`WasmUcanContextState.revoked_cids`) and runtime revocation set (`WasmContextRuntime.revoked_tokens`).

Per-context UCAN state lives in `static UCAN_STATE: Mutex<Option<HashMap<...>>>` (separate from the `thread_local` context registry) because it needs `Mutex` for `sync_context_state` cross-thread safety.

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

## Event Log — Dual Storage Pattern

The event log uses two storage layers:
1. **`WasmEventLog` in `runtime.rs`** — Merkle tree storing only leaf hashes (`[u8; 32]`). Used for cryptographic proofs (inclusion/absence).
2. **`EVENT_METADATA` in `event_log.rs`** — `thread_local! { RefCell<HashMap<String, Vec<EventMetadata>>> }` storing full event metadata (type, actor, timestamp, payload, sequence). Used for queries with filtering.

Both are keyed by context ID. `append_event()` writes to both atomically. `remove_event_metadata()` should be called on context close.

The Merkle tree leaf hash is `SHA-256(0x00 || event_type || actor_did || payload_json)` with RFC 6962 domain separation.

## Identity — WASM-Local Registry

`identity_create` generates Ed25519 keypair via `rand_core::OsRng` (backed by `getrandom/js` → `crypto.getRandomValues`), derives `did:dht:z{zbase32(pubkey)}`, and stores in `thread_local! IDENTITY_REGISTRY`. `identity_resolve` returns a DID document with the Ed25519 verification method for locally-created identities, or a minimal document for unknown DIDs.

The `zbase32_encode` function exists in both `identity.rs` and `ucan.rs` (duplicated to avoid coupling). If a third module needs it, extract to a shared `encoding.rs` module.

## Tool Registration — Deterministic IDs

`tool_register` generates tool IDs as `tool-{SHA-256(context_id:name)[..16]}`. This is deterministic — the same tool name in the same context always produces the same ID. Input/output schemas are validated via the `jsonschema` crate. Test vectors are optional.

`tool_invoke` operates in echo mode (no external handler dispatch). Returns `{"status": "validated", "tool_id": ..., "input": ...}`. When JS-injected handlers are added, dispatch logic goes here.

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
- `rand_core = { version = "0.6", features = ["getrandom"] }` provides `OsRng` for Ed25519 key generation. Works via `getrandom` 0.2 with `js` feature → `crypto.getRandomValues`. Must match `ed25519-dalek`'s `rand_core` 0.6 version.
- `zbase32_encode` is duplicated in `identity.rs` and `ucan.rs`. Extract to shared module if a third consumer appears.
- `event_log.rs` `EVENT_METADATA` is separate from `runtime.rs` `CONTEXT_REGISTRY` — both must be cleaned up on context close. Call `remove_event_metadata(context_id)` alongside `remove_context(context_id)`.
