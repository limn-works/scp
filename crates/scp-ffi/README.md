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
| `identity.rs` | DID create, load, resolve, rotate, migrate |
| `context.rs` | Context create, join, leave, close, send, receive |
| `tools.rs` | Tool register, invoke, verify |
| `ucan.rs` | UCAN validate (11-step ADR-016), mint, delegate, revoke |
| `event_log.rs` | Merkle event log query and verify |
| `mcp.rs` | MCP server/client (stdio + SSE), tool handlers |
| `transport.rs` | Relay connect, disconnect, status |
| `discovery.rs` | Context discovery (local + relay probe) |
| `provenance.rs` | Provenance attach and chain verification |
| `trust.rs` | Trust evaluation |
| `sync.rs` | Offline sync classification |
| `validate.rs` | Input validation at FFI boundary |
| `runtime.rs` | Global registries (context, identity, relay, storage) |
| `error.rs` | `ScpPyError` to Python exception mapping |
| `types.rs` | JSON <-> Python dict conversion |

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
