# scp-ffi -- PyO3 Bridge

The `_scp_core` Python extension module. Exposes `scp-core` Rust APIs to Python
via PyO3 `#[pyfunction]` and `#[pyclass]` definitions. The Pythonic wrapper
layer (`scp_sdk`) in `bindings/python/` imports this as `scp_sdk._scp_core`.

This is the **reference bridge** -- all other FFI bridges target API parity
with this one.

## Architecture

**ContextManager** (shared `Arc<ContextManager>` in `OnceLock`): Owns context
lifecycle -- membership, roles, governance, broadcast, TTL. All `py_context_*`
functions delegate here.

**FfiBridgeState** (per-context, `DashMap`): FFI-only state that does not
duplicate the ContextManager -- tool registry, event log, UCAN revocation list,
nonce tracker, capability ceiling, tool handlers, message channels.

**Identity registry** (global `DashMap`): Maps DID strings to `ScpIdentity` +
`InMemoryKeyCustody` + `DidDocument`. Private keys never cross FFI.

A single multi-threaded tokio runtime (`OnceLock<Runtime>`) is created at
module import. Sync bridge functions release the GIL via
`py.allow_threads(|| rt.block_on(...))`.

## Modules

| Module | Domain |
|--------|--------|
| `bridge_adapters.rs` | Shared bridge adapter types for the UCAN validation pipeline |
| `bridge_connector.rs` | Bridge connector operations (register, trust evaluation, shadow identities) |
| `context.rs` | Context create, join, leave, close, send, receive |
| `custody.rs` | `FfiKeyCustody` enum dispatch for `KeyCustody` trait (in-memory + file) |
| `discovery.rs` | Context discovery (local + relay probe) |
| `error.rs` | `ScpPyError` to Python exception mapping |
| `event_log.rs` | Merkle event log query and verify |
| `identity.rs` | DID create, load, resolve, rotate, migrate |
| `mcp.rs` | MCP server/client (stdio + SSE), tool handlers |
| `provenance.rs` | Provenance attach and chain verification |
| `runtime.rs` | Global registries (context, identity, relay, storage) |
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
