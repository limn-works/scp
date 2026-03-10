# scp-ffi-napi — napi-rs Bridge Layer

## Overview

This crate is the `@scp/sdk-napi` native addon (`.node` file). It exposes scp-core APIs to
Node.js/Bun via napi-rs `#[napi]` types and functions.

## Architecture

### Shared ContextManager (issue #388)

All context lifecycle, messaging, governance, broadcast, membership, and TTL operations
delegate to a shared `Arc<ContextManager>` initialized once via `OnceLock` in `runtime.rs`.

The `ContextManager` is constructed with bridge-local provider implementations:
- `NapiBridgeCryptoProvider` — no-op MLS/sender-key operations
- `NapiBridgeTransportProvider` — reports connected, no-op send
- `NapiBridgeEventLogProvider` — no-op event log
- `NapiBridgePersistence` — in-memory `DashMap`-backed persistence

### UCAN State Registry

A separate `DashMap<String, UcanContextState>` in `runtime.rs` stores per-context UCAN
validation state (revocation lists, nonce trackers, capability ceilings, event logs for
Merkle proofs). This is NOT a duplicate of `ContextManager` state — the manager does not
track UCAN revocation or nonces.

Functions: `ensure_registered`, `with_context`, `remove_context`.

### Module Structure

| Module | Functions |
|--------|-----------|
| `identity.rs` | `identity_create`, `identity_create_with_agent_key`, `identity_load`, `identity_resolve` |
| `context.rs` | `context_create`, `context_join`, `context_leave`, `context_close`, `context_send`, `context_subscribe`, `context_member_count`, `context_is_member`, `context_member_dids`, `context_member_role`, `context_drain_events`, `context_broadcast_subscriber_count`, `context_is_broadcast_subscriber`, `context_broadcast_admission`, `broadcast_subscribe`, `broadcast_unsubscribe`, `broadcast_publish`, `broadcast_block_subscriber`, `broadcast_handle_key_request`, `context_execute_governance_action`, `context_handle_ttl_expiry`, `context_propose_ttl_extension`, `context_reset_ttl_timer`, `context_export`, `context_import` |
| `tools.rs` | `tool_register`, `tool_invoke`, `tool_verify` |
| `ucan.rs` | `ucan_validate`, `ucan_mint`, `ucan_revoke` |
| `event_log.rs` | `event_log_query`, `event_log_verify` |
| `transport.rs` | `transport_connect`, `transport_disconnect`, `transport_status` |
| `runtime.rs` | `context_manager()`, `ensure_registered`, `with_context`, `remove_context` |

### Build

- `crate-type = ["cdylib"]` only
- Tests run via `cargo test -p scp-ffi-napi` (no Python linkage required)
- `cargo check -p scp-ffi-napi` validates without building the full cdylib

## Key Differences From the PyO3 Bridge

### NapiUcanToken Has `encoded` Field; PyUcanToken Does Not

`NapiUcanToken` carries a `pub(crate) encoded: String` field for revocation/validation.
`PyUcanToken` in the PyO3 bridge has no such field.

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

### Capability URI Scoping

Capabilities passed as `"messages:write"` are scoped to `"scp:ctx:{context_id}/messages:write"`.
Capabilities already starting with `"scp:ctx:"` are passed through unchanged.

### Nonce Generation

The NAPI bridge uses `rand::rngs::OsRng.fill_bytes` directly. Format:
`{unix_millis_timestamp}-{16_random_bytes_hex}` matching ADR-016 §7.2.

## Gotchas

- Bridge functions in `context.rs` delegate to the shared `ContextManager` via
  `crate::runtime::context_manager()`. The `NapiContextHandle` stores a `core_handle: Option<ContextHandle>`
  for manager operations.
- UCAN validation state (revocation lists, nonce trackers) lives in a separate `DashMap` registry,
  NOT in the `ContextManager`. The `ensure_registered` / `with_context` pattern accesses this state.
- `context_close` does NOT perform bridge-layer authorization — it delegates to `ContextManager::close_context` which checks the `ContextClose` capability. Removes UCAN state via `remove_context` after closing.
- `context_create` maps all user-specified fields from params JSON to `ContextParams` (mode, ceiling, ceiling_policy, promotion_policy, memory_scope, governance, ttl). Previously only mode and ttl were passed.
- The bridge event log provider is no-op. Real Merkle proofs use the UCAN registry's `EventLog`.
- `NapiUcanToken.encoded` is `#[allow(dead_code)]` because `ucan_revoke` currently returns a stub
  error. When revocation is wired to the runtime, the bridge will parse the full JWT `token`
  parameter to compute the revocation CID.
- Dependencies: `base64`, `rand`, `dashmap` in `Cargo.toml`.
