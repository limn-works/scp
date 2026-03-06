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
| `context.rs` | Context lifecycle: create, join, leave, close, send, subscribe |
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
- `ceiling_strings: HashSet<String>` — capability ceiling for UCAN validation
- `creator_did: String` — DID of the context creator

Note: UCAN revocation state lives in `WasmUcanState` (in `ucan.rs`), not on `WasmContextRuntime`. The `is_token_revoked` helper queries the per-context revocation set via `with_ucan_state`.

## UCAN Validation — Known Gaps (SCP-218)

`validate_tool_ucan_wasm` (in `runtime.rs`) performs 7-step validation:
1. JWT format check (3-part dot-split)
2. Base64 decode + JSON parse of payload
3. Expiry check (`exp` required field)
4. Revocation check via `WasmUcanState.revoked_cids` using `compute_revocation_cid` (JSON payload hash)
5. Audience DID validation (`aud` required field)
6. Capability string match against `att` array (`tool_invoke:{name}` or wildcard)
7. Capability ceiling compliance

The function is decomposed into 6 focused helpers (`parse_and_decode_ucan_payload`, `check_ucan_expiry`, `check_ucan_revocation`, `check_ucan_audience`, `check_ucan_tool_capability`, `check_ucan_ceiling`) to stay under clippy's 100-line limit.

**Not yet implemented** (deferred to key custody wiring):
- Ed25519 signature verification — requires `JsKeyCustody` (WebCrypto) injection
- Delegation chain traversal — requires proof token resolution
- Root issuer verification
- Attenuation enforcement
- Nonce replay detection (infrastructure exists: add `nonce_tracker: HashSet<String>` to `WasmContextRuntime`)

Do NOT claim "full validation" in docstrings until all steps are implemented. See `.docs/lessons/wasm-partial-ucan-validation.md`.

## UCAN Revocation — CID Consistency

`ucan_revoke` and `validate_tool_ucan_wasm` MUST hash the same input to compute the revocation CID. **Both use `compute_revocation_cid` which hashes the JSON-serialized `UcanPayload` struct** (matching scp-core's `compute_revocation_cid` in `revoke.rs`). This means the CID is derived from the payload content, NOT from the full JWT string. Any deviation silently breaks revocation. See `.docs/lessons/wasm-cid-consistency.md`.

`ucan_revoke` parameter: full encoded JWT string — decoded to payload, then `compute_revocation_cid`.
`validate_tool_ucan_wasm` revocation check: decodes payload bytes to `UcanPayloadForRevocation`, calls `compute_revocation_cid_from_payload`, checks against `WasmUcanState.revoked_cids`.

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
