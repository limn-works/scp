# scp-ffi — PyO3 Bridge Layer

## Overview

This crate is the `_scp_core` Python extension module. It exposes scp-core/scp-mcp/scp-transport Rust APIs to Python via PyO3 `#[pyfunction]` and `#[pyclass]` definitions. The Pythonic wrapper layer (`scp_sdk`) in `bindings/python/` imports this module.

## Architecture

### Runtime Registry (`runtime.rs`)

**Architecture (post-ADR-049 / commit 12):** Context lifecycle is delegated to a shared `Arc<Supervisor>` held in the per-bridge `BridgeInstanceCore.supervisor` slot. Per-context FFI-specific state lives in `FfiBridgeState` in a `OnceLock<DashMap<String, FfiBridgeState>>`. The previously-shared `Arc<ContextManager>` is gone (see `.docs/adrs/ADR-049-actor-per-context.md` for the rationale and migration path).

**Supervisor (shared):** Owns context lifecycle state — membership, roles, governance, broadcast, TTL. All `py_context_*` functions delegate to `Supervisor::create_context`, `join_context`, `leave_context`, `close_context`, `send_message`. Built via `Supervisor::with_providers_and_journal(...)` (durable saga journal) with production providers: `NodeMlsFactory` (real OpenMLS-backed encryption, sender keys, and group management — #1324, matching NAPI bridge #1305), `NotConfiguredTransportProvider` (returns descriptive errors until relay is configured via `transport_connect`), the persistent `MerkleEventLogProvider` from `build_event_log_provider` (sharing the bridge instance's single storage backend, so the supervisor's own convergent event log is readable by `Supervisor::participation_record` (§7.3.2) and other supervisor log queries — every `init_context_manager*` path, including the relay/local-transport paths, wires this; the former `NoOpEventLogProvider` was removed because a no-op silently dropped governance/role/membership leaves the supervisor must read), and a `not_configured_key_resolver` that logs errors on every lookup rather than silently skipping verification (#501). The `local_did` is passed to `NodeMlsFactory::new` as the MLS credential identity.

**FfiBridgeState (per-context, FFI-only):** Does NOT duplicate Supervisor state:
- `OutletRegistry` — outlet registration/invocation
- `EventLog` — event recording, querying, Merkle proofs
- `RevocationList` — UCAN token revocation tracking
- `NonceTracker<SystemClock>` — per-context UCAN nonce replay prevention (ADR-016 step 9)
- `creator_did` — the DID of the context creator
- `outlet_handlers: HashMap<String, OutletHandler>` — registered outlet handler closures keyed by outlet ID (SCP-212)
- `message_tx: Option<mpsc::Sender<PyMessage>>` — sender half of the receive channel (SCP-216). Stored so transport can feed messages. Dropping closes the channel.
- `message_rx: Option<Arc<tokio::sync::Mutex<mpsc::Receiver<PyMessage>>>>` — shared receiver for oldest-drop overflow (SCP-216). Shared with `PyMessageReceiver`.

**Backward-compatibility aliases:** `with_context` → `with_ffi_state`, `register_context` → `register_ffi_state` + Supervisor wiring (formerly `init_context_manager`), `remove_context` → `remove_ffi_state`. Existing modules (`outlets.rs`, `ucan.rs`, `event_log.rs`, `mcp.rs`) use these aliases without modification.

**Identity registry (SCP-214):** A global `OnceLock<DashMap<String, IdentityEntry>>` maps DID strings to retained identity state:
- `ScpIdentity` — opaque key handles (`identity_key`, `active_signing_key`), pre-rotation commitment, DID string
- `Arc<InMemoryKeyCustody>` — the custody provider holding actual key material. Private keys never cross FFI (ADR-006).
- `DidDocument` — the identity's DID document

`py_identity_create` registers identity state. Bridge functions (`context.rs`, `ucan.rs`, `identity.rs`) look up state by DID via `with_identity` / `with_identity_mut`. `remove_identity` is called during DID migration.

DashMap provides lock-free concurrent access with internal sharding — no global mutex contention under concurrent Python calls (important for PEP 703 free-threaded Python). The `with_context` function (alias for `with_ffi_state`) takes a closure receiving `&mut FfiBridgeState` and returns `Result<T, ScpPyError>` with typed errors. The `with_identity` / `with_identity_mut` functions follow the same pattern for identity state.

`py_context_create` in `context.rs` registers FFI bridge state and delegates lifecycle to `Supervisor`. Other modules (`outlets.rs`, `ucan.rs`, `event_log.rs`) look up FFI state by context ID via `with_context` (alias for `with_ffi_state`).

Known contexts (SCP-213), transport, storage provider, identity registry, UCAN registry,
economy trackers, and bridge connector state are now owned by `BridgeInstance` and
accessed via `crate::runtime::bridge_instance()`. The old per-bridge `OnceLock` globals
(`KNOWN_CONTEXTS`, `RELAY_CONNECTION`, `STORAGE_PROVIDER`, `IDENTITY_REGISTRY`, etc.)
have been consolidated into `BridgeInstance` (see `scp-ffi-common/src/bridge_instance.rs`).

### Module Structure

| Module | Delegates to | Functions |
|--------|-------------|-----------|
| `identity.rs` | scp-core identity | `py_identity_create`, `py_identity_load`, `py_identity_resolve`, `py_identity_rotate_key`, `py_identity_migrate` (storage attached at construction via `PyScp::with_storage`) |
| `context.rs` | runtime registry | `py_context_create`, `py_context_join`, `py_context_leave`, `py_context_close`, `py_context_send`, `py_context_receive` |
| `outlets.rs` | scp-core outlets | `py_outlet_register`, `py_outlet_invoke`, `py_outlet_verify` |
| `ucan.rs` | scp-core UCAN | `py_ucan_validate`, `py_ucan_mint`, `py_ucan_delegate`, `py_ucan_revoke` |
| `event_log.rs` | scp-core event_log | `py_event_log_query`, `py_event_log_verify` |
| `mcp.rs` | scp-mcp | `py_mcp_serve`, `py_mcp_client_connect_stdio/sse`, `py_mcp_client_disconnect`, `py_mcp_client_list_tools`, `py_mcp_client_invoke`, `py_mcp_server_stop/wait`, `py_mcp_server_register/deregister_outlet`, `py_mcp_server_list_contexts`, `py_register_outlet_handler` |
| `transport.rs` | scp-transport | `py_transport_connect`, `py_transport_disconnect`, `py_transport_status` |
| `validate.rs` | (internal) | Input validation for all bridge functions |

### Input Validation (`validate.rs`)

All public `#[pyfunction]` bridge functions validate string inputs at the FFI boundary before passing them to scp-core. Validation is defense-in-depth: it catches malformed input early with clear `ValidationError` messages. All validators are O(n) string scans with no allocations on the happy path.

| Input type | Validator | Checks | Max length |
|-----------|-----------|--------|------------|
| Context ID | `validate_context_id` | Non-empty, alphanumeric/hyphens/underscores, no control chars | 256 |
| DID string | `validate_did` | Non-empty, `did:{method}:{id}` format, lowercase method, no control chars | 512 |
| Outlet name | `validate_outlet_name` | Non-empty, no `{`/`}` (format string safety), no control chars | 256 |
| Outlet ID | `validate_outlet_id` | Non-empty, no control chars | 512 |
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
- `OutletError` → `ScpOutletError`

### JSON Conversion

`types.rs` provides `json_to_py_dict` and `py_dict_to_json` for serde_json::Value ↔ Python dict conversions.

### MCP Bridge (`mcp.rs`)

The MCP bridge delegates to real `scp-mcp` server/client implementations via two DashMap registries (one for servers, one for clients), keyed by opaque cryptographically random hex handles.

**Server side:**
- `FfiBridgeProvider` implements `scp_mcp::server::ContextProvider` by reading outlet registrations and event log data from the runtime registry via `with_context()`, and membership, role assignments, and the ceiling from the per-context supervisor actor via `runtime::live_role_state()`.
- Servers run on the shared tokio runtime. Shutdown is coordinated via `tokio::sync::oneshot` channel. `py_mcp_server_wait` blocks until the task completes.
- Supports both `stdio` and `sse` transport modes.

**Client side:**
- `StdioClientTransport` spawns a subprocess, communicates via line-delimited JSON-RPC over piped stdin/stdout using `BufReader`/`BufWriter`.
- `SseClientTransport` connects via raw `TcpStream` with HTTP/1.1, parsing SSE event streams.
- `ClientTransport` enum dispatches between Stdio and Sse variants (avoids orphan rule — cannot implement foreign `McpTransport` trait for `Box<dyn McpTransport>`).
- Connection functions run the MCP `initialize` handshake and store real `McpClient` instances in the registry.

## Gotchas

- The tokio runtime (`RUNTIME` in `lib.rs`) must be initialized before any async bridge call. It's auto-initialized at module import.
- `py_context_create` creates real `OutletRegistry` and `EventLog` objects in the runtime registry. If context creation fails partway, the registry entry must be cleaned up. It also calls `Supervisor::register_local_did` to register the creator's DID for defense-in-depth (matching NAPI behavior).
- **Close authorization**: `py_context_close` does NOT perform bridge-layer authorization. It delegates to `Supervisor::close_context` (the hoisted helper in `lifecycle_helpers`), which checks the `ContextClose` capability via `ttl::close_context`. The Supervisor is the authoritative auth layer. Errors from the Supervisor are propagated (except "not registered"/"context not found" which are idempotent).
- **Authorization reads live supervisor state**: every gate that decides whether an operation is permitted reads membership, role assignment, per-member capability, suspension, or the capability ceiling through `runtime::live_role_state(bi, context_id)` or `runtime::live_ceiling_strings(bi, context_id)`, and every gate that refuses a non-active context reads `runtime::live_context_state_str(bi, context_id)`. Each helper routes through the per-context supervisor actor's mailbox, and each fails closed with `SCP-CTX-2023` when the supervisor holds no actor for the context.
  - `FfiBridgeState` holds no role state and no ceiling, and no `sync_*` helper exists. The bridge cached a `ContextRoleState` clone plus a ceiling string set until a remote governance action proved the copies could not be kept current: six LOCAL governance call sites re-synced the clone, and no remote path invalidated it, so a `RemoveMember` another participant committed left every bridge gate authorizing the removed member. Do NOT reintroduce a field, a helper, or a refresh call site — a seventh refresh site would close no window.
  - `runtime::block_on_supervisor_query` drives each live read from the sync `PyO3` surface. It handles the three tokio regimes the bridge runs under: no ambient runtime (a Python call under the GIL), an ambient multi-thread runtime (the SSE MCP handler), and an ambient current-thread runtime (the stdio MCP loop). Call a live read OUTSIDE `with_identity`, whose closure already drives async work through `rt.block_on`, so the two do not stack.
  - A context the supervisor created with an EMPTY ceiling authorizes its creator for nothing. The bridge substitutes no `default_ceiling()` on the caller's behalf, so a test that needs an authorized creator passes the capabilities it needs in `ContextParams.ceiling` at creation.
- MCP bridge functions use opaque string handles (cryptographically random hex IDs) for server/client instances. Server and client state tracked in separate `DashMap` registries in `mcp.rs`.
- `with_context` closures must return `Result<T, ScpPyError>` — use typed error variants (`ScpPyError::ContextError`, `ScpPyError::UcanError`, etc.) not raw strings.
- **Identity registry (SCP-214)**: `py_identity_create` registers identity state in the `BridgeInstance` identity registry (type-erased, set via `set_identity_registry`). All crypto bridge functions (`py_ucan_mint`, `py_ucan_delegate`, `py_context_send`, `py_identity_rotate_key`, `py_identity_migrate`) look up the retained `InMemoryKeyCustody` and `KeyHandle`s via `with_identity()`. The `KeyCustody` trait uses RPITIT (return-position impl Trait in trait), making it NOT object-safe — must use concrete `InMemoryKeyCustody` type directly. `parse_custody("platform")` returns an error (criterion 11) to prevent silent fallback.
- **Nested block_on prevention**: `with_identity` / `with_identity_mut` are sync closures wrapping DashMap access. If a crypto operation inside the closure is async (e.g., `derive_pseudonym`, `create_inner_envelope`), call `rt.block_on()` inside the closure — never nest `block_on` calls or tokio will deadlock. Pattern: `with_identity(did, |entry| { rt.block_on(async { ... }) })`.
- UCAN validation (SCP-164) now delegates to scp-core's full 11-step ADR-016 pipeline including Ed25519 signature verification. Bridge trait implementations (`DispatchDidResolver`, `BridgeRevocationChecker`, `BridgeProofResolver`, `BridgeNonceTracker`) in `ucan.rs` adapt runtime state to scp-core's validation traits. The `py_ucan_validate` function accepts optional `presenting_agent_did` and `proof_tokens` parameters for delegation chain verification.
- **Unified DID resolver (#311)**: `DispatchDidResolver` replaces `BridgeDidResolver` in production code paths. When the global `DID_RESOLVER` is initialized (via `runtime::init_did_resolver`, called from `py_identity_create`), it delegates to `IdentityBackedDidResolver` which performs full DID document validation (BEP44 sig, self-certification, sequence tracking). Falls back to `BridgeDidResolver` (string-only) when uninitialized. The resolver is in `scp-ffi-common` — shared across all FFI bridges.
- MCP server async tasks hold `Arc<Mutex<McpServer>>` — when extracting data from the mutex guard for use in async code (e.g. SSE transport), scope the lock to avoid holding `MutexGuard` across `.await` points (the guard is not `Send`).
- `EventLog` is a Merkle tree storing only leaf hashes, not event payloads. The `context_events` provider method returns event count and Merkle root, not raw events.
- `OutletRegistry::registrations()` returns an iterator, not a Vec. There is no `invoke()` method — outlet invocation checks outlet existence and returns a JSON status response.
- `SseClientTransport` uses raw `TcpStream` — `https://` URLs are explicitly rejected (no TLS). Only `http://` is supported; add `rustls` dependency for HTTPS.
- `FfiBridgeProvider::validate_capability` performs real capability checking via `has_outlet_invocation_capability` against the role state the per-context supervisor actor answers with (SCP-210). Defense-in-depth alongside the UCAN layer. `invoke_outlet` validates input against the outlet's JSON schema and dispatches to a registered handler if one exists (SCP-212). If no handler is registered, falls back to echo mode with `"status": "validated"`. Handler output is also validated against the outlet's output schema (defense-in-depth).
- **Outlet handler registration (SCP-212)**: `py_register_outlet_handler(context_id, outlet_name, handler)` wraps a Python callable in a Rust closure and stores it in `FfiBridgeState::outlet_handlers`. The handler is called by `FfiBridgeProvider::invoke_outlet` when the outlet is invoked via MCP. The outlet must be registered in the `OutletRegistry` first. `ContextProvider::invoke_outlet` is sync, and Python handlers are GIL-bound (inherently sync), so no async boundary crossing is needed at the FFI layer. Python SDK wrapper: `scp_sdk.mcp.register_outlet_handler(context, outlet_name, handler)`.
- **Receive channel lifecycle (SCP-216, #332)**: `py_context_receive` creates a bounded channel (capacity 1000, `RECEIVE_BUFFER_CAPACITY`), stores the sender in `FfiBridgeState::message_tx` and a shared receiver `Arc` in both `FfiBridgeState::message_rx` and `PyMessageReceiver`. `__anext__` returns an `asyncio.Future` — it spawns the `recv()` on the tokio runtime and resolves the future via `call_soon_threadsafe` when a message arrives, so the asyncio event loop is never blocked (#138). Channel closes on `py_context_leave` (via `close_receive_channel`) or `py_context_close` (via `remove_context` dropping the runtime). **Producer wiring (#332):** `drain_and_deliver()` in `context.rs` bridges `Supervisor::drain_events()` to `runtime::deliver_message()`. Called after `py_context_send` (MessageSent), `py_context_join` (MemberJoined), `py_context_leave` (MemberLeft, before channel close), and `py_context_close` (SystemClose, before remove). Events are converted from `ContextEvent` to `PyMessage`: MessageSent carries the original payload; system events (MemberJoined/Left/SystemClose) use `scp:system` sender with structured payload strings; other variants use Debug format. `deliver_message` in `runtime.rs` handles oldest-drop overflow: on full buffer, acquires `blocking_lock` on the shared receiver, pops exactly 1 oldest item, sends the new message, then best-effort sends a `BufferOverflow` warning.
- **Thread leak on outlet handler timeout**: When `FfiBridgeProvider::invoke_outlet` times out (via `recv_timeout`), the spawned `std::thread` continues running in the background until the handler returns naturally. Rust has no mechanism to forcibly cancel a thread. The leaked thread holds an `Arc<dyn Fn>` (handler closure) and the Python GIL (for Python handlers). No DashMap locks are held (two-phase design from #122). Cooperative cancellation was rejected as unreasonable API burden for handler authors. Mitigation path if needed: process-level isolation, not in-process cancellation. See PR #170 review discussion and the doc comment in `invoke_outlet` in `mcp.rs`.
- `parse_http_url` rejects control characters (CRLF injection defense). SSE `post_path` from server is also validated.
- SSE response event loop is bounded to 1000 events. If the server streams non-matching events beyond this, the request fails.
- **Stdio allowlist (per-instance)**: `StdioClientTransport::spawn` validates the command against a per-`PyBridgeInstance` allowlist (`bi.core.mcp_allowlist()`, an owned `Mutex<scp_mcp::allowlist::StdioAllowlist>`) before calling `Command::new`. Default allows: `uvx`, `npx`, `bunx`, `pipx`, `python`, `python3`, `node`, `bun`, `deno`, `docker`, `podman`, `scp-mcp`. Only bare binary names are accepted — paths (absolute or relative) are rejected to prevent basename-spoofing bypasses, even when the allowlist is in unrestricted mode. The OS resolves the binary via `PATH`. Per MCP Security Best Practices and ADR-048 §1 multi-instance neutrality.
  - `PyScp::mcp_configure_stdio_allowlist(additional_binaries)` — add entries to THIS instance's allowlist (validated: no paths, no NUL, no empty).
  - `PyScp::mcp_disable_stdio_allowlist()` — enter unrestricted mode for THIS instance only. `scp_mcp::allowlist::StdioAllowlist::disable_enforcement` emits `tracing::warn!` for operator audit.
  - `PyScp::mcp_reset_stdio_allowlist()` — restore defaults and re-enable enforcement on THIS instance.
  - `PyScp::mcp_get_stdio_allowlist()` — introspect current state (`{"allowed": [...], "unrestricted": bool}`).
  - Python SDK exposes these as methods on `scp_sdk.SCP`: `scp.mcp_configure_stdio_allowlist(...)`, `scp.mcp_disable_stdio_allowlist(i_trust_all_commands=True)` (keyword-only ceremony + warning log), `scp.mcp_reset_stdio_allowlist()`, `scp.mcp_get_stdio_allowlist()`. Pre-validation in `validate_client_connect()` catches path / unlisted-binary issues before crossing FFI when an allowlist snapshot is supplied.
  - The legacy process-global `OnceLock<Mutex<StdioAllowlist>>` and the four top-level `py_mcp_*_stdio_allowlist` `#[pyfunction]`s were deleted; one bridge instance disabling enforcement no longer affects another in the same process.
- **Context discovery (SCP-213)**: `py_mcp_load_contexts` performs client-side context discovery combining three sources:
  1. **Local runtime registry** (`runtime::context_ids_for_member()`) — always available
  2. **Known-contexts registry** (`runtime::known_contexts_for_member()`) — tracks context-to-routing-id-to-relay mappings
  3. **Relay probe** — if a relay connection is active (via `py_transport_connect`), probes known routing IDs via QUERY to detect active contexts
  - Falls back gracefully to local-only when relay is unreachable. Results are deduplicated by context ID.
  - The relay is a dumb blob store with no identity-to-context mapping; discovery is purely client-side.
  - `py_transport_connect(relay_url)` creates a `NativeRelayAdapter` and stores the `TransportManager` in `BridgeInstance`. `py_transport_disconnect()` clears it.
  - `runtime::KnownContext` stores `routing_id`, `relay_url`, `member_did`, `last_seen` for each tracked context.
  - Each result dict contains: `context_id`, `source` ("local"/"relay"/"local+relay"), `relay_active` (bool), plus optional `creator_did`/`member_count`/`outlet_count`.
  - Result dicts from bridge functions must be consumed with `h["key"]` syntax in Python — NOT `h.key`. Prefer returning a `#[pyclass]` struct for new structured return types.
- **Storage provider (SCP-217 / spec §17.6)**: storage is a **per-instance** `storage_provider: OnceLock<StorageProvider>` field on `PyBridgeInstance` (NOT a process-global `OnceLock`). `StorageProvider` is an enum dispatching between `EncryptingAdapter<InMemoryStorage>` (encrypted in-memory; random AES-256-GCM key via `OsRng`) and `Arc<SqliteStorage>` (SQLCipher on disk). It implements `Storage` (enum dispatch) and `Clone`. The `Storage` trait uses RPITIT and is **not dyn-compatible**, so the slot holds the typed enum, not `Arc<dyn Storage>`.
  - **Selection.** The per-instance `SCP.with_storage({...})` factory drives `PyBridgeInstance::with_storage_py(StorageConfig)`: `{"type":"in_memory"}` → `StorageConfig::InMemory`; `{"type":"sqlite","path":...,"key":b"..."}` → raw-key `SqliteKeyMaterial::Raw`; `{"type":"sqlite","path":...,"passphrase":"..."}` → Argon2id `SqliteKeyMaterial::Passphrase`. For `sqlite`, **exactly one** of `key`/`passphrase` is required — both/neither is a `ValidationError`. Passphrase is moved into `Zeroizing<String>` at the dict boundary. The legacy default-instance free-function path (`py_init_storage("in_memory")` → `runtime::init_storage`) still exists for `py_identity_create`/`py_context_create` flows; `init_supervisor*` calls `ensure_default_instance_storage` to make the explicit in-memory dev-affordance selection on the default instance when none was set (the runtime core never defaults storage).
  - **FAIL CLOSED (spec §17.6).** `with_storage_py` returns `Result<Self, StorageInitError>`. A failed SQLCipher open (bad key/passphrase, permission denied, corrupt file, salt-sidecar fail-closed) returns `StorageInitError::SqliteOpen`; `SCP.with_storage` surfaces it as a Python `ValidationError`. There is **no** silent degrade to in-memory or no-storage. In-memory is reachable only via the explicit `{"type":"in_memory"}` selection.
  - **`mls_storage` consumer (supervisor).** `build_supervisor` derives the supervisor's `DurableProviders` from the bridge instance's single chosen `StorageProvider`: `durable_providers_from_bi(bi)` calls `DurableProviders::from_handle(Arc::new(storage_provider().clone()))`, which derives BOTH the durable `ProtocolRepositorySagaJournal` and the `mls_storage` (`Arc<dyn OpenMlsStorageAdapter>`) from that ONE handle — so the saga journal, `mls_storage`, persistence, and the event log share one backend BY CONSTRUCTION (the same-backend invariant is type-enforced, not by convention; spec §17.6 / §17.16). **Storage-before-supervisor precondition:** if `storage_provider` is unset when `build_supervisor` runs, it returns an error (no fabrication, no default).
  - `py_identity_create` persists identity state under `identity/{did}/state` after creation. `py_identity_load` retrieves from storage and raises `IdentityError` if the DID is not found (no silent fallback).
