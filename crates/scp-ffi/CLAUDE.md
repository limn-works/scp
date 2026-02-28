# scp-ffi — PyO3 Bridge Layer

## Overview

This crate is the `_scp_core` Python extension module. It exposes scp-core/scp-mcp/scp-transport Rust APIs to Python via PyO3 `#[pyfunction]` and `#[pyclass]` definitions. The Pythonic wrapper layer (`scp_sdk`) in `bindings/python/` imports this module.

## Architecture

### Runtime Registry (`runtime.rs`)

A global `OnceLock<DashMap<String, ContextRuntime>>` maps context IDs to live runtime state:
- `ToolRegistry` — tool registration/invocation
- `EventLog` — event recording, querying, Merkle proofs
- `RevocationList` — UCAN token revocation tracking
- `RoleState` — role assignments for capability checking
- `NonceTracker<SystemClock>` — per-context UCAN nonce replay prevention (ADR-016 step 9)
- `ceiling_strings: HashSet<String>` — capability ceiling as `{resource}:{action}` strings (ADR-016 step 8)
- `creator_did` — the DID of the context creator

DashMap provides lock-free concurrent access with internal sharding — no global mutex contention under concurrent Python calls (important for PEP 703 free-threaded Python). The `with_context` function takes a closure receiving `&mut ContextRuntime` and returns `Result<T, ScpPyError>` with typed errors.

`py_context_create` in `context.rs` registers runtime state. Other modules (`tools.rs`, `ucan.rs`, `event_log.rs`) look up state by context ID via `with_context`.

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

### MCP Bridge (`mcp.rs`)

The MCP bridge delegates to real `scp-mcp` server/client implementations via two DashMap registries (one for servers, one for clients), keyed by opaque cryptographically random hex handles.

**Server side:**
- `FfiBridgeProvider` implements `scp_mcp::server::ContextProvider` by reading tool registrations, role state, and event log data from the runtime registry via `with_context()`.
- Servers run on the shared tokio runtime. Shutdown is coordinated via `tokio::sync::oneshot` channel. `py_mcp_server_wait` blocks until the task completes.
- Supports both `stdio` and `sse` transport modes.

**Client side:**
- `StdioClientTransport` spawns a subprocess, communicates via line-delimited JSON-RPC over piped stdin/stdout using `BufReader`/`BufWriter`.
- `SseClientTransport` connects via raw `TcpStream` with HTTP/1.1, parsing SSE event streams.
- `ClientTransport` enum dispatches between Stdio and Sse variants (avoids orphan rule — cannot implement foreign `McpTransport` trait for `Box<dyn McpTransport>`).
- Connection functions run the MCP `initialize` handshake and store real `McpClient` instances in the registry.

## Gotchas

- The tokio runtime (`RUNTIME` in `lib.rs`) must be initialized before any async bridge call. It's auto-initialized at module import.
- `py_context_create` creates real `ToolRegistry` and `EventLog` objects in the runtime registry. If context creation fails partway, the registry entry must be cleaned up.
- MCP bridge functions use opaque string handles (cryptographically random hex IDs) for server/client instances. Server and client state tracked in separate `DashMap` registries in `mcp.rs`.
- `with_context` closures must return `Result<T, ScpPyError>` — use typed error variants (`ScpPyError::ContextError`, `ScpPyError::UcanError`, etc.) not raw strings.
- UCAN validation (SCP-164) now delegates to scp-core's full 11-step ADR-016 pipeline including Ed25519 signature verification. Bridge trait implementations (`BridgeDidResolver`, `BridgeRevocationChecker`, `BridgeProofResolver`, `BridgeNonceTracker`) in `ucan.rs` adapt runtime state to scp-core's validation traits. The `py_ucan_validate` function accepts optional `presenting_agent_did` and `proof_tokens` parameters for delegation chain verification.
- MCP server async tasks hold `Arc<Mutex<McpServer>>` — when extracting data from the mutex guard for use in async code (e.g. SSE transport), scope the lock to avoid holding `MutexGuard` across `.await` points (the guard is not `Send`).
- `EventLog` is a Merkle tree storing only leaf hashes, not event payloads. The `context_events` provider method returns event count and Merkle root, not raw events.
- `ToolRegistry::registrations()` returns an iterator, not a Vec. There is no `invoke()` method — tool invocation checks tool existence and returns a JSON status response.
- `SseClientTransport` uses raw `TcpStream` — `https://` URLs are explicitly rejected (no TLS). Only `http://` is supported; add `rustls` dependency for HTTPS.
- `FfiBridgeProvider::validate_capability` always returns `Ok(())` (TODO #106) — authorization depends on UCAN layer. `invoke_tool` returns stub JSON (TODO #106), not real tool execution.
- `parse_http_url` rejects control characters (CRLF injection defense). SSE `post_path` from server is also validated.
- SSE response event loop is bounded to 1000 events. If the server streams non-matching events beyond this, the request fails.
- **Stdio allowlist**: `StdioClientTransport::spawn` validates the command against a configurable allowlist before calling `Command::new`. Default allows: `uvx`, `npx`, `bunx`, `pipx`, `python`, `python3`, `node`, `bun`, `deno`, `docker`, `podman`, `scp-mcp`. Basename is extracted (neutralizes path traversal). Extend via `py_mcp_configure_stdio_allowlist()` or set `unrestricted=True` to bypass. Per MCP Security Best Practices.
- `py_mcp_load_contexts` always returns an empty list — requires relay transport layer (scp-transport) not yet wired.
