# scp-ffi-napi -- napi-rs Bridge

Native addon (`.node` file) for Node.js and Bun. Exposes `scp-core` APIs via
napi-rs `#[napi]` functions and types. Consumed by the `@limn-works/scp-ts`
TypeScript package as its native backend.

## Architecture

**`SCP` class + shared Supervisor**: The `#[napi(js_name = "SCP")] Scp` class
(in `scp.rs`) is the caller-owned handle exposed to TypeScript; its
`SCP.withStorage(configJson)` factory is fail-closed (spec §17.6) -- there is no
zero-argument constructor. It owns a `NapiBridgeInstance` that holds a shared
`Arc<Supervisor>` in its `BridgeInstanceCore.supervisor` slot; the Supervisor
owns all context lifecycle state -- membership, roles, governance, broadcast,
TTL. It is built by `build_supervisor_arc` in `runtime.rs` via
`Supervisor::with_providers_and_journal(...)` (durable saga journal) and reached
through `runtime::supervisor()`. This replaced the previously-shared
`Arc<ContextManager>`, now deleted (see
[ADR-049](../../../.docs/adrs/ADR-049-actor-per-context.md)). See
[construction.md](../../../.docs/standards/construction.md) (ADR-052) for the
mandatory-config API rule.

**UCAN state registry**: A separate `DashMap<String, UcanContextState>` stores
per-context UCAN validation state (revocation lists, nonce trackers, capability
ceilings, event logs). This is not duplicated from the Supervisor -- the
Supervisor does not track UCAN revocation or nonces.

**Tokio runtime**: Multi-threaded, created lazily via `OnceLock::get_or_init`.
napi-rs `#[napi]` async functions run on this runtime and resolve JS Promises
on the Node.js event loop automatically.

**Handle counting**: Opaque handles (`NapiIdentity`, `NapiContextHandle`,
`NapiUcanToken`, `NapiTransportManager`) track lifetime via a global
`AtomicUsize`. `scp_shutdown(timeout_secs)` blocks until all handles are
released or the deadline elapses.

## Modules

| Module | Domain |
|--------|--------|
| `scp.rs` | The `SCP` `#[napi]` class -- caller-owned handle; `SCP.withStorage(config)` factory |
| `bridge_connector.rs` | Bridge connector operations (register, trust evaluation, shadow identities) |
| `context.rs` | Context lifecycle, membership, governance, broadcast, TTL, export/import |
| `custody.rs` | `KeyCustody` enum dispatch for the napi bridge |
| `discovery.rs` | Context discovery |
| `economy.rs` | Economic governance operations |
| `error.rs` | `ScpNapiError` to napi Error mapping |
| `event_log.rs` | Merkle event log query and verify |
| `identity.rs` | DID create (with optional agent key), load, resolve, migrate |
| `mcp.rs` | MCP server/client bridge |
| `media.rs` | Media session lifecycle and signaling |
| `provenance.rs` | Provenance operations |
| `runtime.rs` | Per-instance `NapiBridgeInstance` state: supervisor slot + `build_supervisor_arc`, UCAN state registry |
| `scpid.rs` | SCPID stateless DID authentication (§3.11) |
| `server.rs` | Relay / application-node server startup (wraps `scp-ffi-common::server`) |
| `sync.rs` | Offline sync classification |
| `tools.rs` | Tool register, invoke, verify |
| `transport.rs` | Relay connect, disconnect, status |
| `trust.rs` | Trust evaluation |
| `ucan.rs` | UCAN validate, mint, revoke |

## Key differences from PyO3

- `NapiUcanToken` carries an `encoded` field for revocation/validation.
- Capability URIs are auto-scoped to `scp:ctx:{context_id}/` when not prefixed.
- Nonce format: `{unix_millis}-{16_random_bytes_hex}` (ADR-016 section 7.2).
- Sync functions run on libuv worker threads -- use `crate::runtime().block_on()`,
  not `Handle::current()` (which panics without a tokio context).

## Build and test

```sh
# Build native addon
cargo build -p scp-ffi-napi

# Type-check only
cargo check -p scp-ffi-napi

# Run Rust unit tests (no Python linkage needed)
cargo test -p scp-ffi-napi

# TypeScript integration tests (from bindings/typescript/)
bun test
```

## Crate type

`cdylib` only. Produces a `.node` native addon via napi-rs.
