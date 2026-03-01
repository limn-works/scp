# scp-ffi-napi — napi-rs Bridge Layer

## Overview

This crate is the `@scp/sdk-napi` native addon (`.node` file). It exposes scp-core APIs to
Node.js/Bun via napi-rs `#[napi]` types and functions. Unlike the PyO3 bridge (`crates/scp-ffi`),
this bridge has no global runtime registry — all context state lives in the `NapiContextHandle`
struct itself.

## Architecture

### No Runtime Registry

The PyO3 bridge uses a global `DashMap<String, ContextRuntime>` keyed by context ID. The NAPI
bridge does NOT have an equivalent. All state needed by bridge functions is stored directly on
the opaque handle structs:

- `NapiContextHandle` — carries `context_id`, `creator_did`, `mode`, `ceiling`, etc.
- `NapiUcanToken` — carries `data: NapiUcanTokenData` and `encoded: String`
- `NapiIdentity` — carries `did`, `custody_type`
- `NapiTransportManager` — carries transport state

Functions that need context data receive the handle as `&NapiContextHandle` and read from it
directly. There is no `with_context` lookup by ID.

### Module Structure

| Module | Functions |
|--------|-----------|
| `identity.rs` | `identity_create`, `identity_load`, `identity_resolve` |
| `context.rs` | `context_create`, `context_join`, `context_leave`, `context_close`, `context_send`, `context_subscribe` |
| `tools.rs` | `tool_register`, `tool_invoke`, `tool_verify` |
| `ucan.rs` | `ucan_validate`, `ucan_mint`, `ucan_revoke` |
| `event_log.rs` | `event_log_query`, `event_log_verify` |
| `transport.rs` | `transport_connect`, `transport_disconnect`, `transport_status` |

### Build

- `crate-type = ["cdylib"]` only (unlike PyO3 which has rlib for test linkage)
- Tests run via `cargo test -p scp-ffi-napi` (no Python linkage required, unlike scp-ffi)
- `cargo check -p scp-ffi-napi` validates without building the full cdylib

## Key Differences From the PyO3 Bridge

### NapiUcanToken Has `encoded` Field; PyUcanToken Does Not

`NapiUcanToken` carries a `pub(crate) encoded: String` field for future revocation/validation
wiring. `PyUcanToken` in the PyO3 bridge has no such field — it only exposes metadata.

When implementing `ucan_mint`, the `encoded` field MUST be set to a valid JWT-format string:
`base64url(header_json).base64url(payload_json).base64url(sig_bytes)`. A placeholder 64-byte
zero signature is acceptable until real Ed25519 signing is wired (SCP-214).

An empty `encoded` field means:
- `ucan_revoke` cannot compute the revocation CID (it needs to call `parse_ucan`)
- `ucan_validate` cannot verify the token
- The token is structurally non-round-trippable

### JWT Construction Pattern (NAPI)

```rust
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use scp_core::crypto::ucan::{Attenuation, UcanHeader, UcanPayload};

let header = UcanHeader::new();
let payload = UcanPayload { iss, aud, exp, nbf: None, nnc, att, prf: vec![], fct: None };

let header_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header)?);
let payload_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&payload)?);
let sig_b64 = URL_SAFE_NO_PAD.encode([0u8; 64]);

let encoded = format!("{header_b64}.{payload_b64}.{sig_b64}");
```

This produces a string parseable by `scp_core::crypto::ucan::validate::parse_ucan`.

### Capability URI Scoping

Capabilities passed as `"messages:write"` are scoped to `"scp:ctx:{context_id}/messages:write"`.
Capabilities already starting with `"scp:ctx:"` are passed through unchanged. The `can` field
of each `Attenuation` is derived from `rsplit_once(':')` on the scoped URI.

### Nonce Generation

The NAPI bridge uses `rand::rngs::OsRng.fill_bytes` directly (no wrapper). Format:
`{unix_millis_timestamp}-{16_random_bytes_hex}` matching ADR-016 §7.2.

## Gotchas

- `NapiUcanToken.encoded` is `#[allow(dead_code)]` because `ucan_revoke` takes `token_id: String`
  (not the full token). When revocation is wired to the runtime, the NAPI bridge will need a way
  to look up the encoded token by ID (e.g., a handle registry or passing the full token to revoke).

- Bridge functions returning `Err(...)` immediately without constructing the output type leave
  `encoded` / other fields unset. Always construct the output struct before the feature is
  "working" in any sense — stubs that silently produce empty fields are worse than stubs that
  return errors, because they look like they work.

- The `ucan_validate` and `ucan_revoke` functions still return errors — they require a live
  runtime registry (not yet present in the NAPI bridge). These are SCP-219 scope work items.

- Dependencies: add `base64 = { workspace = true }` and `rand = { workspace = true }` to
  `Cargo.toml` when building JWT-format tokens. Both are workspace deps.

## SCP-219 Status

As of 2026-03-01:
- `ucan_mint`: FIXED — constructs proper JWT-format `encoded` string with placeholder signature
- `ucan_validate`: stub — returns `SCP-PRM-4002` error
- `ucan_revoke`: stub — returns `SCP-PRM-4006` error

Real signing and runtime wiring are SCP-214 scope.
