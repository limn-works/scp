# scp-ffi -- PyO3 Bridge

The `_scp_core` Python extension module. Exposes `scp-core` Rust APIs to Python
via PyO3 `#[pyfunction]` and `#[pyclass]` definitions. The Pythonic wrapper
layer (`scp_sdk`) in `bindings/python/` imports this as `scp_sdk._scp_core`.

This is the **reference bridge** -- all other FFI bridges target API parity
with this one.

## Architecture

**`SCP` class** (`scp.rs`): the Python SDK's sole user-facing entry point -- a
`#[pyclass(name = "SCP", frozen)]` wrapper over a caller-owned
`PyBridgeInstance`. Storage selection is **mandatory and fail-closed** (spec
§17.6): the constructor requires a storage-config dict (`SCP({...})`, also
spelled `SCP.with_storage({...})`) -- there is no zero-argument constructor and
no default backend. Each call mints a fresh instance whose handles are
affinity-stamped; there is no process-global bridge (the
`DEFAULT_BRIDGE_INSTANCE` static was deleted in ADR-048 Phase D). See
[ADR-049](../../.docs/adrs/ADR-049-actor-per-context.md) for the per-instance
actor model and [construction.md](../../.docs/standards/construction.md)
(ADR-052) for the mandatory-config API rule.

**Supervisor** (shared `Arc<Supervisor>` on the per-bridge instance): owns
context lifecycle -- membership, roles, governance, broadcast, TTL. It lives in
the `CoreFields.supervisor` slot of `PyBridgeInstance` (not a process-global
`OnceLock`), is built by `build_supervisor` in `runtime.rs` via
`Supervisor::with_providers_and_journal(...)` (durable saga journal plus
production MLS / transport / event-log providers), and is reached through
`runtime::supervisor()`. All `py_context_*` functions delegate here. This
replaced the previously-shared `Arc<ContextManager>`, now deleted (ADR-049
actor-per-context).

**FfiBridgeState** (per-context, `OnceLock<DashMap<String, _>>`): FFI-only state
that does not duplicate Supervisor state -- tool registry, event log, UCAN
revocation list, nonce tracker, capability ceiling, tool handlers, message
channels.

**Identity registry** (per-instance `Arc<DashMap<..>>` on `PyBridgeInstance`,
**not** a process global): maps DID strings to `ScpIdentity` +
`InMemoryKeyCustody` + `DidDocument`, reached via
`runtime::identity_registry(bi)`. Private keys never cross FFI (ADR-006).

A single multi-threaded tokio runtime (`RUNTIME`, an `OnceLock<Runtime>` in
`lib.rs`) is created at module import. Sync bridge functions release the GIL via
`py.allow_threads(|| rt.block_on(...))`.

## Modules

| Module | Domain |
|--------|--------|
| `scp.rs` | The `SCP` `#[pyclass]` -- sole SDK entry point; mandatory storage-config constructor |
| `bridge_adapters.rs` | Shared bridge adapter types for the UCAN validation pipeline |
| `bridge_connector.rs` | Bridge connector operations (register, trust evaluation, shadow identities) |
| `context.rs` | Context create, join, leave, close, send, receive |
| `custody.rs` | `FfiKeyCustody` enum dispatch for `KeyCustody` trait (in-memory + file) |
| `discovery.rs` | Context discovery (local + relay probe) |
| `economy.rs` | Economic governance operations (exposed as `SCP` methods) |
| `error.rs` | `ScpPyError` to Python exception mapping |
| `event_log.rs` | Merkle event log query and verify |
| `identity.rs` | DID create, load, resolve, rotate, migrate |
| `mcp.rs` | MCP server/client (stdio + SSE), tool handlers |
| `media.rs` | Media session lifecycle and signaling |
| `provenance.rs` | Provenance attach and chain verification |
| `runtime.rs` | Per-instance state on `PyBridgeInstance` (supervisor slot, FFI bridge state, identity registry, transport, storage) |
| `scpid.rs` | SCPID stateless DID authentication -- challenge, sign, verify (§3.11) |
| `server.rs` | Relay / application-node server startup (wraps `scp-ffi-common::server`) |
| `sync.rs` | Offline sync classification |
| `tools.rs` | Tool register, invoke, verify |
| `transport.rs` | Relay connect, disconnect, status |
| `trust.rs` | Trust evaluation |
| `types.rs` | JSON <-> Python dict conversion |
| `ucan.rs` | UCAN validate (11-step ADR-016), mint, delegate, revoke |
| `validate.rs` | Input validation at FFI boundary |

## Build

```sh
# Full build (produces Python extension module)
maturin develop --release

# Type-check only (no Python linkage)
cargo check -p scp-ffi

# Rust unit tests (requires Python lib on dyld path)
DYLD_LIBRARY_PATH=$(python3.12 -c "import sysconfig; print(sysconfig.get_config_var('LIBDIR'))") \
  cargo test -p scp-ffi

# Python integration tests
maturin develop --release && python3.12 -m pytest bindings/python/tests/ -v
```

## Crate type

`cdylib` (Python extension) + `rlib` (test binary linkage). The
`extension-module` feature is passed by maturin via `pyproject.toml`.
