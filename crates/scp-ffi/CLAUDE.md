# scp-ffi — PyO3 Bridge Layer

## Overview

This crate is the `_scp_core` Python extension module. It exposes scp-core/scp-mcp/scp-transport Rust APIs to Python via PyO3 `#[pyfunction]` and `#[pyclass]` definitions. The Pythonic wrapper layer (`scp_sdk`) in `bindings/python/` imports this module.

## Architecture

### Runtime Registry (`runtime.rs`)

**Context registry:** A global `OnceLock<DashMap<String, ContextRuntime>>` maps context IDs to live runtime state:
- `ToolRegistry` — tool registration/invocation
- `EventLog` — event recording, querying, Merkle proofs
- `RevocationList` — UCAN token revocation tracking
- `RoleState` — role assignments for capability checking
- `NonceTracker<SystemClock>` — per-context UCAN nonce replay prevention (ADR-016 step 9)
- `ceiling_strings: HashSet<String>` — capability ceiling as `{resource}:{action}` strings (ADR-016 step 8)
- `creator_did` — the DID of the context creator
- `tool_handlers: HashMap<String, ToolHandler>` — registered tool handler closures keyed by tool ID (SCP-212)
- `message_tx: Option<mpsc::Sender<PyMessage>>` — sender half of the receive channel (SCP-216). Stored so transport can feed messages. Dropping closes the channel.
- `message_rx: Option<Arc<tokio::sync::Mutex<mpsc::Receiver<PyMessage>>>>` — shared receiver for oldest-drop overflow (SCP-216). Shared with `PyMessageReceiver`.

**Identity registry (SCP-214):** A global `OnceLock<DashMap<String, IdentityEntry>>` maps DID strings to retained identity state:
- `ScpIdentity` — opaque key handles (`identity_key`, `active_signing_key`), pre-rotation commitment, DID string
- `Arc<InMemoryKeyCustody>` — the custody provider holding actual key material. Private keys never cross FFI (ADR-006).
- `DidDocument` — the identity's DID document

`py_identity_create` registers identity state. Bridge functions (`context.rs`, `ucan.rs`, `identity.rs`) look up state by DID via `with_identity` / `with_identity_mut`. `remove_identity` is called during DID migration.

DashMap provides lock-free concurrent access with internal sharding — no global mutex contention under concurrent Python calls (important for PEP 703 free-threaded Python). The `with_context` function takes a closure receiving `&mut ContextRuntime` and returns `Result<T, ScpPyError>` with typed errors. The `with_identity` / `with_identity_mut` functions follow the same pattern for identity state.

`py_context_create` in `context.rs` registers runtime state. Other modules (`tools.rs`, `ucan.rs`, `event_log.rs`) look up state by context ID via `with_context`.

Additional global registries in `runtime.rs`:
- `KNOWN_CONTEXTS: OnceLock<DashMap<String, KnownContext>>` — context-to-relay mappings for discovery (SCP-213)
- `RELAY_CONNECTION: OnceLock<RwLock<Option<Arc<NativeRelayAdapter>>>>` — active relay connection
- `STORAGE_PROVIDER: OnceLock<Arc<InMemoryStorage>>` — storage backend for identity persistence (SCP-217)

### Module Structure

| Module | Delegates to | Functions |
|--------|-------------|-----------|
| `identity.rs` | scp-core identity | `py_init_storage`, `py_identity_create`, `py_identity_load`, `py_identity_resolve`, `py_identity_rotate_key`, `py_identity_migrate` |
| `context.rs` | runtime registry | `py_context_create`, `py_context_join`, `py_context_leave`, `py_context_close`, `py_context_send`, `py_context_receive` |
| `tools.rs` | scp-core tools | `py_tool_register`, `py_tool_invoke`, `py_tool_verify` |
| `ucan.rs` | scp-core UCAN | `py_ucan_validate`, `py_ucan_mint`, `py_ucan_delegate`, `py_ucan_revoke` |
| `event_log.rs` | scp-core event_log | `py_event_log_query`, `py_event_log_verify` |
| `mcp.rs` | scp-mcp | `py_mcp_serve`, `py_mcp_client_connect_stdio/sse`, `py_mcp_client_disconnect`, `py_mcp_client_list_tools`, `py_mcp_client_invoke`, `py_mcp_server_stop/wait`, `py_mcp_server_register/deregister_tool`, `py_mcp_server_list_contexts`, `py_register_tool_handler` |
| `transport.rs` | scp-transport | `py_transport_connect`, `py_transport_disconnect`, `py_transport_status` |
| `validate.rs` | (internal) | Input validation for all bridge functions |

### Input Validation (`validate.rs`)

All public `#[pyfunction]` bridge functions validate string inputs at the FFI boundary before passing them to scp-core. Validation is defense-in-depth: it catches malformed input early with clear `ValidationError` messages. All validators are O(n) string scans with no allocations on the happy path.

| Input type | Validator | Checks | Max length |
|-----------|-----------|--------|------------|
| Context ID | `validate_context_id` | Non-empty, alphanumeric/hyphens/underscores, no control chars | 256 |
| DID string | `validate_did` | Non-empty, `did:{method}:{id}` format, lowercase method, no control chars | 512 |
| Tool name | `validate_tool_name` | Non-empty, no `{`/`}` (format string safety), no control chars | 256 |
| Tool ID | `validate_tool_id` | Non-empty, no control chars | 512 |
| Capability URI | `validate_capability_uri` | Non-empty, no control chars | 1024 |
| UCAN token | `validate_ucan_token` | Non-empty, no control chars | 65536 |
| MCP handle | `validate_mcp_handle` | Non-empty, no control chars | 256 |
| Relay URL | `validate_relay_url` | Non-empty, valid scheme (ws/wss/http/https), no control chars (CRLF defense) | 2048 |
| Transport mode | `validate_transport_mode` | Must be "stdio" or "sse" | 64 |

Invalid inputs raise `ValidationError` (subclass of `ScpError`) with descriptive messages including the invalid value and what was expected. See GitHub issue #104.

### Build

- `crate-type = ["cdylib", "rlib"]` — cdylib for Python extension module, rlib for test binary linkage
- `extension-module` is a crate feature (not default) — maturin passes it explicitly via pyproject.toml
- Rust tests: `DYLD_LIBRARY_PATH=$(python3.12 -c "import sysconfig; print(sysconfig.get_config_var('LIBDIR'))") cargo test -p scp-ffi` (Python 3.12 available via mise — do NOT skip these tests)
- Python integration tests: `maturin develop --release` + `pytest bindings/python/tests/`
- Use `cargo check -p scp-ffi` to verify compilation without Python linkage
- Full build via `maturin build --features extension-module` or `maturin develop`

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
- **Identity registry (SCP-214)**: `py_identity_create` registers identity state in the global identity registry (`runtime::IDENTITY_REGISTRY`). All crypto bridge functions (`py_ucan_mint`, `py_ucan_delegate`, `py_context_send`, `py_identity_rotate_key`, `py_identity_migrate`) look up the retained `InMemoryKeyCustody` and `KeyHandle`s via `with_identity()`. The `KeyCustody` trait uses RPITIT (return-position impl Trait in trait), making it NOT object-safe — must use concrete `InMemoryKeyCustody` type directly. `parse_custody("platform")` returns an error (criterion 11) to prevent silent fallback.
- **Nested block_on prevention**: `with_identity` / `with_identity_mut` are sync closures wrapping DashMap access. If a crypto operation inside the closure is async (e.g., `derive_pseudonym`, `create_inner_envelope`), call `rt.block_on()` inside the closure — never nest `block_on` calls or tokio will deadlock. Pattern: `with_identity(did, |entry| { rt.block_on(async { ... }) })`.
- UCAN validation (SCP-164) now delegates to scp-core's full 11-step ADR-016 pipeline including Ed25519 signature verification. Bridge trait implementations (`BridgeDidResolver`, `BridgeRevocationChecker`, `BridgeProofResolver`, `BridgeNonceTracker`) in `ucan.rs` adapt runtime state to scp-core's validation traits. The `py_ucan_validate` function accepts optional `presenting_agent_did` and `proof_tokens` parameters for delegation chain verification.
- MCP server async tasks hold `Arc<Mutex<McpServer>>` — when extracting data from the mutex guard for use in async code (e.g. SSE transport), scope the lock to avoid holding `MutexGuard` across `.await` points (the guard is not `Send`).
- `EventLog` is a Merkle tree storing only leaf hashes, not event payloads. The `context_events` provider method returns event count and Merkle root, not raw events.
- `ToolRegistry::registrations()` returns an iterator, not a Vec. There is no `invoke()` method — tool invocation checks tool existence and returns a JSON status response.
- `SseClientTransport` uses raw `TcpStream` — `https://` URLs are explicitly rejected (no TLS). Only `http://` is supported; add `rustls` dependency for HTTPS.
- `FfiBridgeProvider::validate_capability` performs real capability checking via `has_tool_invoke_capability` against the context's role state (SCP-210). Defense-in-depth alongside the UCAN layer. `invoke_tool` validates input against the tool's JSON schema and dispatches to a registered handler if one exists (SCP-212). If no handler is registered, falls back to echo mode with `"status": "validated"`. Handler output is also validated against the tool's output schema (defense-in-depth).
- **Tool handler registration (SCP-212)**: `py_register_tool_handler(context_id, tool_name, handler)` wraps a Python callable in a Rust closure and stores it in `ContextRuntime::tool_handlers`. The handler is called by `FfiBridgeProvider::invoke_tool` when the tool is invoked via MCP. The tool must be registered in the `ToolRegistry` first. `ContextProvider::invoke_tool` is sync, and Python handlers are GIL-bound (inherently sync), so no async boundary crossing is needed at the FFI layer. Python SDK wrapper: `scp_sdk.mcp.register_tool_handler(context, tool_name, handler)`.
- **Receive channel lifecycle (SCP-216)**: `py_context_receive` creates a bounded channel (capacity 1000, `RECEIVE_BUFFER_CAPACITY`), stores the sender in `ContextRuntime::message_tx` and a shared receiver `Arc` in both `ContextRuntime::message_rx` and `PyMessageReceiver`. `__anext__` returns an `asyncio.Future` — it spawns the `recv()` on the tokio runtime and resolves the future via `call_soon_threadsafe` when a message arrives, so the asyncio event loop is never blocked (#138). Channel closes on `py_context_leave` (via `close_receive_channel`) or `py_context_close` (via `remove_context` dropping the runtime). `deliver_message` in `runtime.rs` feeds messages and handles oldest-drop overflow: on full buffer, acquires `try_lock` on the shared receiver (never `blocking_lock` which would panic inside tokio), pops exactly 1 oldest item, sends the new message, then best-effort sends a `BufferOverflow` warning. If `try_lock` fails (consumer holds the mutex), returns `Err` instead of silently dropping the message.
- **Thread leak on tool handler timeout**: When `FfiBridgeProvider::invoke_tool` times out (via `recv_timeout`), the spawned `std::thread` continues running in the background until the handler returns naturally. Rust has no mechanism to forcibly cancel a thread. The leaked thread holds an `Arc<dyn Fn>` (handler closure) and the Python GIL (for Python handlers). No DashMap locks are held (two-phase design from #122). Cooperative cancellation was rejected as unreasonable API burden for handler authors. Mitigation path if needed: process-level isolation, not in-process cancellation. See PR #170 review discussion and the doc comment in `invoke_tool` in `mcp.rs`.
- `parse_http_url` rejects control characters (CRLF injection defense). SSE `post_path` from server is also validated.
- SSE response event loop is bounded to 1000 events. If the server streams non-matching events beyond this, the request fails.
- **Stdio allowlist**: `StdioClientTransport::spawn` validates the command against a configurable allowlist before calling `Command::new`. Default allows: `uvx`, `npx`, `bunx`, `pipx`, `python`, `python3`, `node`, `bun`, `deno`, `docker`, `podman`, `scp-mcp`. Only bare binary names are accepted — paths (absolute or relative) are rejected to prevent basename-spoofing bypasses. The OS resolves the binary via `PATH`. Per MCP Security Best Practices.
  - `py_mcp_configure_stdio_allowlist(additional_binaries)` — add entries (validated: no paths, no NUL, no empty).
  - `py_mcp_disable_stdio_allowlist()` — enter unrestricted mode (separate function for ceremony).
  - `py_mcp_reset_stdio_allowlist()` — restore defaults and re-enable enforcement.
  - `py_mcp_get_stdio_allowlist()` — introspect current state (`{"allowed": [...], "unrestricted": bool}`).
  - Python SDK exposes these as module-level functions: `configure_stdio_allowlist()`, `disable_stdio_allowlist(i_trust_all_commands=True)`, `reset_stdio_allowlist()`, `get_stdio_allowlist()`. Pre-validation in `McpClient.connect()` catches path and allowlist issues before crossing FFI, raising `ValidationError` with actionable messages.
- **Context discovery (SCP-213)**: `py_mcp_load_contexts` performs client-side context discovery combining three sources:
  1. **Local runtime registry** (`runtime::context_ids_for_member()`) — always available
  2. **Known-contexts registry** (`runtime::known_contexts_for_member()`) — tracks context-to-routing-id-to-relay mappings
  3. **Relay probe** — if a relay connection is active (via `py_transport_connect`), probes known routing IDs via QUERY to detect active contexts
  - Falls back gracefully to local-only when relay is unreachable. Results are deduplicated by context ID.
  - The relay is a dumb blob store with no identity-to-context mapping; discovery is purely client-side.
  - `py_transport_connect(relay_url)` creates a `NativeRelayAdapter` and stores it in `runtime::RELAY_CONNECTION`. `py_transport_disconnect()` clears it.
  - `runtime::KnownContext` stores `routing_id`, `relay_url`, `member_did`, `last_seen` for each tracked context.
  - Each result dict contains: `context_id`, `source` ("local"/"relay"/"local+relay"), `relay_active` (bool), plus optional `creator_did`/`member_count`/`tool_count`.
  - Result dicts from bridge functions must be consumed with `h["key"]` syntax in Python — NOT `h.key`. Prefer returning a `#[pyclass]` struct for new structured return types.
- **Storage provider (SCP-217)**: `py_init_storage("in_memory")` injects a global `InMemoryStorage` via `OnceLock<Arc<InMemoryStorage>>` in `runtime.rs`. `py_identity_create` persists identity state under `identity/{did}/state` after creation. `py_identity_load` retrieves from storage and raises `IdentityError` if the DID is not found (no silent fallback). The `Storage` trait uses RPITIT and is **not dyn-compatible** — the global must use a concrete type (`InMemoryStorage`), not `Arc<dyn Storage>`. When `SqliteStorage` lands, this will need an enum dispatch or generic parameter.
