# scp-ffi-napi — napi-rs Bridge Layer

## Overview

This crate is the `@limn-works/scp-ts-napi` native addon (`.node` file). It exposes scp-core APIs to
Node.js/Bun via napi-rs `#[napi]` types and functions.

## Architecture

### Shared Supervisor (post-ADR-049 / commit 12; supersedes the prior `ContextManager`-keyed wiring tracked in #388)

All context lifecycle, messaging, governance, broadcast, membership, and TTL operations
delegate to a shared `Arc<Supervisor>` held in the per-bridge `BridgeInstanceCore.supervisor` slot. The previously-shared `Arc<ContextManager>` is gone — see `.docs/adrs/ADR-049-actor-per-context.md` for the rationale.

The `Supervisor` is constructed via `Supervisor::with_providers_and_journal(...)` (durable saga journal) with production provider implementations:
- `NodeMlsFactory` — real OpenMLS-backed encryption, sender keys, and group management (#1294)
- `NotConfiguredTransportProvider` (from `scp-core`) — returns descriptive errors until relay configured (#501)
- `MerkleEventLogProvider` — persistent Merkle-chained event log backed by
  `ProtocolRepositoryEventLogBridge` over encrypted in-memory storage (#484)
- `NapiBridgePersistence` — in-memory `DashMap`-backed persistence

### UCAN State Registry

A separate `DashMap<String, UcanContextState>` in `runtime.rs` stores per-context UCAN
validation state (revocation lists, nonce trackers, capability ceilings, event logs for
Merkle proofs). This is NOT a duplicate of `Supervisor` state — the supervisor does not
track UCAN revocation or nonces.

Functions: `ensure_registered`, `with_context`, `remove_context`.

### Module Structure

| Module | Functions |
|--------|-----------|
| `identity.rs` | `identity_create`, `identity_create_with_agent_key`, `identity_load`, `identity_resolve`, `NapiIdentity::migrate` |
| `context.rs` | `context_create`, `context_join`, `context_leave`, `context_close`, `context_send`, `context_subscribe`, `context_member_count`, `context_is_member`, `context_member_dids`, `context_member_role`, `context_drain_events`, `context_broadcast_subscriber_count`, `context_is_broadcast_subscriber`, `context_broadcast_admission`, `broadcast_subscribe`, `broadcast_unsubscribe`, `broadcast_publish`, `broadcast_block_subscriber`, `broadcast_handle_key_request`, `context_execute_governance_action`, `context_handle_ttl_expiry`, `context_propose_ttl_extension`, `context_reset_ttl_timer`, `context_export`, `context_import` |
| `outlets.rs` | `outlet_register`, `outlet_invoke`, `outlet_verify` |
| `ucan.rs` | `ucan_validate`, `ucan_mint`, `ucan_revoke` |
| `event_log.rs` | `event_log_query`, `event_log_verify` |
| `transport.rs` | `transport_connect`, `transport_disconnect`, `transport_status` |
| `runtime.rs` | `supervisor()` (formerly `context_manager()`), `ensure_registered`, `with_context`, `remove_context` |

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

- Bridge functions in `context.rs` delegate to the shared `Supervisor` (formerly the now-deleted `ContextManager`) via the per-bridge supervisor accessor. The `NapiContextHandle` stores a `core_handle: Option<ContextHandle>` for supervisor operations.
- **Recovery / custody-migration ownership + concurrency invariants (ADR-048 §7, round-2/3).**
  `Scp::identity_execute_recovery` and `Scp::identity_execute_custody_migration` enforce three mechanical
  gates before the orchestrator runs, in order:
  1. **DID ownership** — the DID must be present in this instance's identity registry
     (`crate::runtime::identity_registry(&self.inner).contains_key(&did)`). Missing DIDs
     return `SCP-IDENT-1020` (recovery) / `SCP-IDENT-1024` (migration). Closes the
     realm-local amplifier where any caller could drive unmetered orchestrator work
     on `crate::runtime()` against arbitrary DIDs.
  2. **Length cap** — `context_ids.len() <= MAX_CONTEXT_IDS_PER_{RECOVERY,MIGRATION} = 1024`;
     over-cap returns `SCP-VALID-7120`.
  3. **Concurrency semaphore** — `NapiBridgeInstance::recovery_semaphore`
     (`RECOVERY_CONCURRENCY_CAP` permits, `try_acquire_owned`). Exhausted permits
     return `SCP-VALID-7140` non-blockingly. Queueing would itself pin a libuv
     worker on the wait, so the bridge prefers immediate-busy over queued.
  These methods are **sync** napi entry points — the async orchestrator is driven by
  `crate::runtime().block_on(...)`. Do not change them back to `async fn`; the
  napi-rs worker thread has no tokio context (see `3de6cbe30` / `78102c871` history).
- UCAN validation state (revocation lists, nonce trackers) lives in a separate `DashMap` registry,
  NOT in the `Supervisor`. The `ensure_registered` / `with_context` pattern accesses this state.
- `context_close` does NOT perform bridge-layer authorization — it delegates to `Supervisor::close_context` (the hoisted `lifecycle_helpers::close_context` body) which checks the `ContextClose` capability. Removes UCAN state via `remove_context` after closing.
- `context_create` maps all user-specified fields from params JSON to `ContextParams` (mode, ceiling, ceiling_policy, promotion_policy, memory_scope, governance, ttl).
- The bridge event log provider uses `MerkleEventLogProvider::with_persistence` backed by
  `ProtocolRepositoryEventLogBridge` over encrypted in-memory storage (#484). The UCAN
  registry's `EventLog` is used separately for per-context Merkle proofs.
- `NapiUcanToken.encoded` carries the full JWT so `ucan_revoke` can compute the revocation CID.
- **`ucan_revoke` fails closed (no revocation broadcast)**: `scp_ffi_common::UnavailableRevocationDistributor`
  reports step 3 of the ADR-016 revocation flow as failed, because no type in this workspace
  broadcasts a revocation as an MLS application message. `revoke_ucan` then rolls the
  `RevocationPending` entry back and `ucan_revoke_on` rejects. The resolved "UCAN revocation
  mechanism" entry in `.docs/specs/00-open-questions.md` requires that rollback so the revoker and
  the other members do not disagree about the token.
- **The only DID resolver is `IdentityBackedDidResolver`**: `crate::runtime::init_did_resolver`,
  called from `identity_create`, installs it. `ucan_validate_on`, `ucan_evaluate_on`, and
  `validate_ucan_for_outlet` read it through `scp_ffi_common::require_did_resolver` and reject with
  `SCP-PERM-3031` when a caller reaches validation before creating an identity on that instance.
  There is no substitute resolver.
- **Storage provider (spec §17.6)**: storage selection is per-instance via the `SCP.withStorage(configJson)` factory (`scp.rs`) → `NapiBridgeInstance::with_storage_napi(StorageConfig)`. `{"type":"in_memory"}` → encrypted in-memory; `{"type":"sqlite","path":...,"key":"<hex>"|[..]}` → raw-key `SqliteKeyMaterial::Raw`; `{"type":"sqlite","path":...,"passphrase":"..."}` → Argon2id `SqliteKeyMaterial::Passphrase`. For `sqlite`, **exactly one** of `key`/`passphrase` is required — both/neither is `SCP-VALID-7005`.
  - **FAIL CLOSED (spec §17.6).** `with_storage_napi` returns `Result<Self, StorageInitError>`. A failed SQLCipher open (bad key/passphrase, permission denied, corrupt file, salt-sidecar fail-closed) returns `StorageInitError::SqliteOpen`; the factory surfaces it as a JS-thrown `ValidationError`. There is **no** silent degrade to in-memory; in-memory is reachable only via the explicit `{"type":"in_memory"}` selection.
  - **`mls_storage` consumer (supervisor).** `build_supervisor_arc` takes a required `durable: DurableProviders` arg, sourced from `bi.durable_providers_ref()`. `durable_providers_from_handle` calls `DurableProviders::from_handle(handle)`, deriving BOTH the durable `ProtocolRepositorySagaJournal` and the `mls_storage` view from one `Arc<S>` — so they share one backend by construction (type-enforced, not by convention). That single chosen `Storage`: the Sqlite path retains the same `Arc<SqliteStorage>` that backs persistence + event log; the in-memory path uses the un-swallowed `EventLogInMemoryStorageHandle` (3rd element of `build_event_log_provider`, an `Arc<EncryptingAdapter<scp_platform::in_memory::InMemoryStorage>>`) — NOT `NapiBridgePersistence` (a `DashMap`, not a `Storage`). All `init_supervisor*` paths read `durable_providers_ref()` and fail closed (no supervisor attached) if unset.
- Dependencies: `base64`, `rand`, `dashmap` in `Cargo.toml`.
