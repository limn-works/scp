# scp-ffi — PyO3 Bridge Layer

## Overview

This crate is the `_scp_core` Python extension module. It exposes scp-core/scp-mcp/scp-transport Rust APIs to Python via PyO3 `#[pyfunction]` and `#[pyclass]` definitions. The Pythonic wrapper layer (`scp_sdk`) in `bindings/python/` imports this module.

## Architecture

### Runtime Registry (`runtime.rs`)

A global `OnceLock<Mutex<HashMap<String, ContextRuntime>>>` maps context IDs to live runtime state:
- `ToolRegistry` — tool registration/invocation
- `EventLog` — event recording, querying, Merkle proofs
- `RevocationList` — UCAN token revocation tracking

`py_context_create` in `context.rs` registers runtime state. Other modules (`tools.rs`, `ucan.rs`, `event_log.rs`) look up state by context ID.

### Module Structure

| Module | Delegates to | Functions |
|--------|-------------|-----------|
| `identity.rs` | scp-core identity | `py_identity_create`, `py_identity_load` |
| `context.rs` | runtime registry | `py_context_create`, `py_context_join`, `py_context_leave`, `py_context_close`, `py_context_send`, `py_context_receive` |
| `tools.rs` | scp-core tools | `py_tool_register`, `py_tool_invoke`, `py_tool_verify` |
| `ucan.rs` | scp-core UCAN | `py_ucan_validate`, `py_ucan_mint`, `py_ucan_revoke` |
| `event_log.rs` | scp-core event_log | `py_event_log_query`, `py_event_log_verify` |
| `mcp.rs` | scp-mcp | `py_mcp_serve`, `py_mcp_client_connect_stdio/sse`, `py_mcp_client_disconnect`, `py_mcp_client_list_tools`, `py_mcp_client_invoke`, `py_mcp_server_stop/wait`, `py_mcp_server_register/deregister_tool`, `py_mcp_server_list_contexts` |
| `transport.rs` | scp-transport | `py_transport_connect`, `py_transport_disconnect` |

### Build

- `crate-type = ["cdylib"]` — builds as Python extension module
- `test = false` — cannot link test binary without Python dev headers; tests run via `maturin develop` + `pytest`
- Use `cargo check -p scp-ffi` to verify compilation without Python linkage
- Full build via `maturin build` or `maturin develop`

### Error Mapping

`error.rs` defines `ScpPyError` enum with variants mapping to Python exception classes:
- `IdentityError` → `ScpIdentityError`
- `ContextError` → `ScpContextError`
- `UcanError` → `ScpUcanError`
- `TransportError` → `ScpTransportError`
- `ToolError` → `ScpToolError`

### JSON Conversion

`types.rs` provides `json_to_py_dict` and `py_dict_to_json` for serde_json::Value ↔ Python dict conversions.

## Gotchas

- The tokio runtime (`RUNTIME` in `lib.rs`) must be initialized before any async bridge call. It's auto-initialized at module import.
- `py_context_create` creates real `ToolRegistry` and `EventLog` objects in the runtime registry. If context creation fails partway, the registry entry must be cleaned up.
- MCP bridge functions use opaque handles (u64 IDs) for server/client instances. Handles are managed by a separate registry in `mcp.rs`.
