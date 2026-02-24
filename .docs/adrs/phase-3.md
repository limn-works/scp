# Phase 3 Architecture Decision Records — Python SDK

**Date:** February 22, 2026
**Phase goal:** `pip install scp-sdk` works. Python agents use SCP. MCP bridge connects any MCP-compatible model to SCP contexts.
**Deliverable:** Python SDK on PyPI, MCP adapter, UCAN validation in SDK. Two Python agents on different machines exchange encrypted messages, invoke tools, and expose SCP contexts as MCP tools.
**Timeline:** Weeks 9-12
**Dependencies between ADRs:**

```
ADR-001..012 (Phase 1 + Phase 2)
         |
    +----+----------+
    |                |
    v                v
ADR-013 (PyO3    ADR-033 (Economic
  Bridge)          Governance)
  /        \         |
 v          v        | depends on ADR-002,005,008,009,011
ADR-014    ADR-016
(Python    (UCAN
  SDK)    Validation)
  |
  v
ADR-015
(MCP Adapter)
```

Build order: ADR-013 (depends on all Phase 1 + Phase 2 Rust crates) --> ADR-014 + ADR-016 (parallel, both depend on ADR-013) --> ADR-015 (depends on ADR-013 + ADR-014). ADR-033 depends on Phase 1 + Phase 2 ADRs (002, 005, 008, 009, 011) and can be built in parallel with ADR-013.

---

## ADR-013: PyO3 Bridge Layer

**Status:** Decided

### Context

The Python SDK is the most critical language binding for SCP. The agent ecosystem — LangChain, CrewAI, AutoGen, custom agents — is overwhelmingly Python (architecture.md section 3.1). If agents cannot `import scp`, the protocol does not exist to them. The bridge layer is the boundary between the Rust protocol engine (scp-core, scp-transport, scp-platform) and the Python world. It must expose core SCP types and operations to Python without leaking Rust concepts, while bridging async runtimes (tokio on the Rust side, asyncio on the Python side).

PyO3 is the established Rust-Python FFI framework, and maturin is the standard build tool for PyO3 projects. Together they produce Python wheels with the compiled Rust binary embedded — users run `pip install scp-sdk` and get a working binary extension with zero Rust toolchain requirement (architecture.md section 3.1).

### Decision

Implement the FFI bridge as the `scp-ffi/pyo3/` crate using PyO3 and maturin. The bridge exposes a flat set of `#[pyfunction]` and `#[pyclass]` definitions that map directly to scp-core's public API. Async functions use PyO3's native async support (`#[pyfunction] async fn`) to bridge Rust futures (tokio) to Python coroutines (asyncio). Rust `Result<T, E>` types are mapped to Python exceptions via a unified error hierarchy. All SCP domain types (Identity, ContextHandle, OuterEnvelope, UcanToken, etc.) are exposed as opaque Python objects with attribute access — no raw structs, no Rust generics, no lifetime markers visible to Python.

### Rationale

- **PyO3 over cffi/ctypes:** PyO3 generates native Python extension modules with automatic type conversion, exception mapping, and GIL management. cffi/ctypes require manual C ABI definitions and offer no async bridging. PyO3 is the Rust-Python standard with mature tooling.
- **maturin over setuptools-rust:** maturin is purpose-built for PyO3/Rust-Python projects. It handles cross-compilation, wheel building for multiple platforms (manylinux, macOS universal2, Windows), and integrates with PyPI publishing. setuptools-rust requires more configuration and has fewer CI/CD integrations.
- **Native async bridging (PyO3 0.22+):** PyO3 natively supports `async fn` in `#[pyfunction]` and `#[pymethods]`, converting Rust `Future`s into Python coroutines directly. The tokio runtime runs in a background thread pool; async functions declared with `async fn` automatically bridge between the two event loops. The deprecated `pyo3-asyncio` crate is no longer needed.
- **Flat function surface:** The bridge layer is deliberately flat (no deep class hierarchies). Each Python-visible function maps to one Rust function. The Pythonic API (context managers, method chaining, iterators) is built in the pure Python wrapper layer (ADR-014), not in the FFI bridge. This keeps the bridge thin and testable.
- **Opaque types over data transfer:** SCP types like `Identity`, `ContextHandle`, and `MlsGroup` contain crypto state that must not be serialized to Python objects. They are exposed as opaque PyO3 classes with getter methods for safe fields (DID string, context ID, state) and no access to internal key material.

### Implementation

- **Language:** Rust (PyO3 macros) + Python (type stubs)
- **Libraries:** `pyo3` (0.22+), `maturin` (build tool)
- **Crate:** `scp-ffi` (workspace member)
- **Module:** `scp-ffi/pyo3/`
- **Build output:** Python extension module `_scp_core` (imported by the `scp_sdk` Python package)
- **Async runtime:** A single tokio `Runtime` is created at module import time and shared across all async calls. The runtime runs in a background thread pool managed by PyO3's native async machinery.
- **Platform wheels:** maturin builds wheels for manylinux (x86_64, aarch64), macOS (x86_64, arm64 universal2), and Windows (x86_64). CI/CD via GitHub Actions with maturin's `maturin-action`.

### Dependencies

- **All Phase 1 ADRs (ADR-001 through ADR-007):** The bridge exposes MLS operations, envelope creation, DID identity, transport, sender keys, and platform adapters to Python.
- **All Phase 2 ADRs (ADR-008 through ADR-012):** The bridge exposes context lifecycle, role/UCAN enforcement, tool registration/invocation, event log queries, and multi-transport routing to Python.

### Acceptance Criteria

1. **Tokio runtime initialization:**
   - A tokio `Runtime` is created once at Python module import (`_scp_core.__init__`).
   - The runtime is multi-threaded (default thread count) and stored in a `OnceCell<Runtime>`.
   - All async bridge functions declared with `async fn` use PyO3's native async support, which automatically bridges between the tokio runtime and Python's asyncio event loop.
   - **Runtime isolation:** The tokio runtime is NEVER accessed via `block_on` from within an async context. All sync->async bridging happens in the Python layer (via `run_coroutine_threadsafe` to a dedicated asyncio loop), which then calls the async bridge functions normally. The Rust side only ever sees async function calls driven by PyO3's native async machinery.
   - Runtime shutdown is handled on module finalization (Python interpreter exit). The `Runtime` is dropped, which waits for in-flight tasks to complete (with a 5-second timeout).

2. **Identity bridge functions:**

   ```rust
   #[pyfunction]
   async fn py_identity_create(custody: &str) -> PyResult<PyIdentity> {
       let identity = Identity::create(parse_custody(custody)?).await?;
       Ok(PyIdentity::from(identity))
   }

   #[pyfunction]
   fn py_identity_resolve<'py>(py: Python<'py>, did: &str) -> PyResult<Bound<'py, PyAny>> { ... }
   ```

   - `py_identity_create(custody) -> PyIdentity` — creates a new DID identity. `custody` is a string: `"platform"`, `"in_memory"`.
   - `py_identity_load(did) -> PyIdentity` — loads an existing identity from storage.
   - `py_identity_resolve(did) -> PyDIDDocument` — resolves a DID to its document.
   - `py_identity_rotate_key(identity) -> PyIdentity` — rotates the identity's key.

3. **Context bridge functions:**
   - `py_context_create(identity, params) -> PyContextHandle` — creates a context. `params` is a Python dict converted to `ContextParams`.
   - `py_context_join(handle, identity) -> None` — joins a context.
   - `py_context_leave(handle, identity) -> None` — leaves a context.
   - `py_context_close(handle, identity) -> None` — closes a context.
   - `py_context_send(handle, identity, payload) -> None` — sends a message.
   - `py_context_receive(handle) -> PyAsyncIterator` — returns an async iterator of incoming messages.

4. **Tool bridge functions:**
   - `py_tool_register(handle, registration) -> str` — registers a tool (returns tool ID).
   - `py_tool_invoke(handle, tool_id, input, identity) -> PyObject` — invokes a tool (returns JSON-compatible output).
   - `py_tool_verify(handle, tool_id) -> PyToolVerificationResult` — verifies a tool against test vectors.

5. **Transport bridge functions:**
   - `py_transport_connect(relay_url) -> None` — connects to an SCP relay.
   - `py_transport_status() -> PyTransportStatus` — returns transport connection status.

6. **UCAN bridge functions:**
   - `py_ucan_validate(handle, token, capability) -> None` — validates a UCAN token (raises exception on failure).
   - `py_ucan_mint(handle, member_did, capabilities) -> PyUcanToken` — mints UCAN tokens.
   - `py_ucan_revoke(handle, token_id) -> None` — revokes a UCAN token.

7. **Event log bridge functions:**
   - `py_event_log_query(handle, filter) -> list[PyEvent]` — queries the context event log.
   - `py_event_log_verify(handle, claim) -> PyProof` — verifies a claim against the event log.

8. **Error mapping:**

   ```rust
   #[derive(Debug)]
   pub enum ScpPyError {
       IdentityError(String),
       ContextError(String),
       CryptoError(String),
       TransportError(String),
       UcanError(String),
       ValidationError(String),
   }

   impl From<ScpPyError> for PyErr {
       fn from(e: ScpPyError) -> PyErr {
           match e {
               ScpPyError::IdentityError(msg) => PyIdentityError::new_err(msg),
               ScpPyError::ContextError(msg) => PyContextError::new_err(msg),
               // ...
           }
       }
   }
   ```

   - Every Rust error type from scp-core maps to a specific Python exception class.
   - Exception classes form a hierarchy rooted at `scp_sdk.ScpError`.
   - Error messages include actionable detail (what failed, why, what to do).

9. **Type stubs (.pyi files):**
   - Generate Python type stub files for the `_scp_core` module.
   - All bridge functions have complete type annotations.
   - Stubs enable IDE autocompletion and mypy/pyright static analysis.

10. **Build and distribution:**
    - `maturin develop` builds the extension in-place for development.
    - `maturin build --release` produces optimized wheels.
    - `maturin publish` uploads to PyPI.
    - CI builds wheels for Linux (manylinux2014 x86_64 + aarch64), macOS (universal2), Windows (x86_64).
    - Users install with `pip install scp-sdk` — no Rust toolchain required.

### Scope

**Files (~6-8):**

| File | Purpose |
|------|---------|
| `scp-ffi/pyo3/lib.rs` | PyO3 module definition, `#[pymodule]` entry point, tokio runtime initialization |
| `scp-ffi/pyo3/identity.rs` | `PyIdentity`, `PyDIDDocument` classes, identity bridge functions |
| `scp-ffi/pyo3/context.rs` | `PyContextHandle`, `PyContextParams` classes, context bridge functions |
| `scp-ffi/pyo3/tools.rs` | Tool bridge functions, `PyToolRegistration`, `PyToolVerificationResult` |
| `scp-ffi/pyo3/transport.rs` | Transport bridge functions, `PyTransportStatus` |
| `scp-ffi/pyo3/ucan.rs` | UCAN bridge functions, `PyUcanToken` |
| `scp-ffi/pyo3/event_log.rs` | Event log bridge functions, `PyEvent`, `PyProof` |
| `scp-ffi/pyo3/error.rs` | `ScpPyError` enum, Python exception class hierarchy, `From` conversions |
| `scp-ffi/pyo3/types.rs` | Shared type conversions: Python dict <-> Rust struct, JSON <-> serde_json |

**Estimated functions:** ~25-30 bridge functions, ~15-20 type classes, ~10-15 conversion helpers.

---

## ADR-014: Python SDK Wrappers

**Status:** Decided

### Context

The PyO3 bridge (ADR-013) exposes raw Rust operations to Python as flat functions and opaque types. While functional, this surface is not Pythonic — it lacks context managers, method chaining, async iterators, and the ergonomic patterns Python developers expect. The Python SDK wrapper layer transforms the bridge into a natural Python API that feels like it was designed in Python from the start, matching the "20-line agent" target from architecture.md section 3.1.

The wrapper layer is pure Python. It imports `_scp_core` (the PyO3 extension module) and builds high-level classes on top. This separation means Pythonic ergonomics can be iterated rapidly without rebuilding Rust, and the wrapper can add Python-ecosystem integrations (logging, context managers, dataclasses) that have no Rust equivalent.

### Decision

Implement the Python SDK as the `scp_sdk` package in `bindings/python/scp_sdk/`. The package is async-first — all network operations are `async def` methods using asyncio. Synchronous convenience wrappers are provided for simple scripts and REPL usage. Full PEP 484 type hints throughout. Resource lifecycle managed via async context managers (`async with`). Error handling uses a Pythonic exception hierarchy that wraps the bridge-level exceptions with additional context.

### Rationale

- **Async-first with sync convenience:** The agent ecosystem (LangChain, CrewAI) is increasingly async-first. SCP operations are inherently async (network I/O, crypto operations). Making async the default and sync the convenience wrapper (not the other way around) means the SDK works naturally in async agent frameworks. Sync wrappers use `asyncio.run()` internally — they exist for scripts, notebooks, and simple use cases.
- **Pure Python wrappers, not logic reimplementation:** The wrapper layer contains zero protocol logic. It delegates everything to `_scp_core`. This means there is one implementation of every operation (Rust), wrapped in Pythonic ergonomics (Python). No divergence, no duplication, no consistency bugs between languages.
- **Context managers for resource lifecycle:** SCP contexts, identities, and transport connections hold resources (MLS group state, WebSocket connections, key material). Python's `async with` pattern ensures cleanup on scope exit, even on exceptions. This prevents resource leaks in long-running agent processes.
- **Type hints for the agent ecosystem:** Agent frameworks (LangChain, CrewAI) and modern Python tooling (mypy, pyright, VS Code) rely on type hints for autocompletion, documentation, and static analysis. Full PEP 484 annotations make the SDK immediately accessible to these tools and workflows.
- **Dataclass-based configuration:** Python dataclasses provide clean, typed configuration objects (ContextParams, ToolDefinition, etc.) with defaults, validation, and serialization. They are more Pythonic than raw dicts and more lightweight than Pydantic for this use case.

### Implementation

- **Language:** Python 3.10+ (for `match` statements, `ParamSpec`, union type syntax)
- **Package:** `scp_sdk` (published to PyPI as `scp-sdk`)
- **Dependencies:** `_scp_core` (PyO3 extension, bundled in the wheel), no external runtime dependencies beyond asyncio (stdlib)
- **Optional dependencies:** `scp-sdk[langchain]` for LangChain integration, `scp-sdk[mcp]` for MCP server (ADR-015)
- **Module structure:** `bindings/python/scp_sdk/`
- **Build:** maturin builds the `_scp_core` extension into the `scp_sdk` package directory. `pyproject.toml` declares the package metadata, version, Python version constraints, and optional dependencies.

### Dependencies

- **ADR-013 (PyO3 Bridge):** Every SDK wrapper method delegates to a bridge function. The `_scp_core` module is the sole runtime dependency.

### Acceptance Criteria

1. **`Identity` class:**

   ```python
   class Identity:
       did: str
       custody_type: str

       @classmethod
       async def create(cls, custody: str = "platform") -> "Identity":
           """Create a new SCP identity with the specified key custody method."""
           ...

       @classmethod
       async def load(cls, did: str) -> "Identity":
           """Load an existing identity from storage."""
           ...

       @classmethod
       def create_sync(cls, custody: str = "platform") -> "Identity":
           """Synchronous convenience wrapper for create()."""
           return asyncio.run(cls.create(custody))

       async def rotate_key(self) -> "Identity":
           """Rotate this identity's key. Returns updated Identity."""
           ...

       async def resolve(self, did: str) -> "DIDDocument":
           """Resolve another identity's DID document."""
           ...
   ```

   - `Identity.create()` is the entry point. Custody parameter defaults to `"platform"`.
   - All `Identity` instances expose `.did` (string), `.custody_type` (string).
   - Sync wrappers (`create_sync`, `load_sync`) use `asyncio.run()`.

2. **`Context` class with async context manager:**

   ```python
   class Context:
       context_id: str
       state: str  # "creating", "active", "closing", "closed", "expired"

       @classmethod
       async def create(
           cls,
           creator: Identity,
           ceiling: list[str],
           tools: list[ToolDefinition] | None = None,
           roles: dict[str, list[str]] | None = None,
           ttl: float | None = None,
           memory_scope: str = "full",
           governance: str = "single_admin",
       ) -> "Context":
           """Create a new SCP context."""
           ...

       async def join(self, identity: Identity) -> "Membership":
           """Join this context."""
           ...

       async def leave(self, identity: Identity) -> None:
           """Leave this context."""
           ...

       async def close(self, identity: Identity) -> None:
           """Close this context (requires admin role)."""
           ...

       async def send(self, message: str | bytes, identity: Identity | None = None) -> None:
           """Send a message to this context."""
           ...

       async def receive(self) -> AsyncIterator[Message]:
           """Async iterator of incoming messages."""
           ...

       async def invoke(self, tool: str, input: dict, identity: Identity | None = None) -> dict:
           """Invoke a tool in this context."""
           ...

       async def __aenter__(self) -> "Context":
           return self

       async def __aexit__(self, *exc) -> None:
           # Cleanup: leave context if still active
           ...
   ```

   - `Context.create()` accepts Pythonic parameters — lists of strings for ceiling, dicts for roles.
   - Async context manager ensures cleanup.
   - `send()` and `invoke()` optionally accept an identity parameter (defaults to the creator if a single identity is active).
   - `receive()` returns an `AsyncIterator[Message]` for streaming incoming messages.

3. **`ToolDefinition` dataclass:**

   ```python
   @dataclass
   class ToolDefinition:
       name: str
       description: str
       input_schema: dict       # JSON Schema
       output_schema: dict      # JSON Schema
       operator: Identity | str # DID string or Identity object
       test_vectors: list[TestVector] | None = None
       implementation_hash: bytes | None = None
   ```

4. **`Message` dataclass:**

   ```python
   @dataclass
   class Message:
       sender_did: str
       content: str | bytes
       timestamp: float
       sequence: int
       context_id: str
       provenance: Provenance | None = None
   ```

5. **Exception hierarchy:**

   ```python
   class ScpError(Exception):
       """Base exception for all SCP errors."""

   class IdentityError(ScpError):
       """Identity creation, resolution, or key management failure."""

   class ContextError(ScpError):
       """Context lifecycle errors (create, join, leave, close)."""

   class PermissionError(ScpError):
       """UCAN capability validation failure."""

   class CryptoError(ScpError):
       """Encryption, decryption, or signature failure."""

   class TransportError(ScpError):
       """Network or relay communication failure."""

   class ToolError(ScpError):
       """Tool registration, invocation, or verification failure."""

   class ValidationError(ScpError):
       """Input validation failure (schema, parameters)."""
   ```

   - Every exception includes a human-readable message and machine-readable error code.
   - Exceptions wrap the corresponding bridge-level `ScpPyError` variants.

6. **Sync convenience API:**

   ```python
   import asyncio
   import threading

   # Dedicated background event loop for sync wrappers.
   # Created lazily on first sync call. Runs in a daemon thread.
   _sync_loop: asyncio.AbstractEventLoop | None = None
   _sync_loop_lock = threading.Lock()

   def _get_sync_loop() -> asyncio.AbstractEventLoop:
       global _sync_loop
       if _sync_loop is None or _sync_loop.is_closed():
           with _sync_loop_lock:
               if _sync_loop is None or _sync_loop.is_closed():
                   _sync_loop = asyncio.new_event_loop()
                   t = threading.Thread(target=_sync_loop.run_forever, daemon=True)
                   t.start()
       return _sync_loop

   def run_sync(coro):
       """Run an async coroutine synchronously.

       Safe to call from any context:
       - From a non-async context: uses a dedicated background event loop.
       - From an async context (Jupyter, nested): uses the background loop
         via run_coroutine_threadsafe, avoiding deadlock.
       """
       loop = _get_sync_loop()
       future = asyncio.run_coroutine_threadsafe(coro, loop)
       return future.result()  # Blocks the calling thread until complete
   ```

   - Sync methods are named `*_sync` (e.g., `Identity.create_sync()`).
   - `run_sync` is safe in ALL contexts: plain scripts, Jupyter notebooks, inside async functions, inside other frameworks' event loops. It never calls `asyncio.run()` (which fails inside running loops) and never calls `block_on` (which panics inside tokio).
   - The background event loop is a daemon thread that dies with the process.
   - Thread safety: `run_coroutine_threadsafe` is the asyncio-blessed mechanism for cross-thread coroutine submission.

7. **Module-level convenience functions:**

   ```python
   # scp_sdk/__init__.py
   from scp_sdk.identity import Identity
   from scp_sdk.context import Context
   from scp_sdk.tools import ToolDefinition, TestVector
   from scp_sdk.trust import evaluate_trust
   from scp_sdk.errors import ScpError, IdentityError, ContextError, ...

   __version__ = "0.1.0"
   ```

   - Top-level imports: `import scp_sdk` or `from scp_sdk import Identity, Context`.
   - The `scp` namespace alias: `import scp_sdk as scp` enables the 20-line agent from architecture.md section 3.1.

8. **Event log query API:**

   ```python
   class EventLog:
       async def query(
           self,
           filter: str | None = None,
           since: float | None = None,
           actor: str | None = None,
           event_type: str | None = None,
       ) -> list[Event]:
           ...

       async def verify(self, claim: dict) -> Proof:
           ...

       async def checkpoint(self) -> Checkpoint:
           ...
   ```

9. **Logging integration:**
   - SDK uses Python's `logging` module with the logger name `scp_sdk`.
   - Users configure logging level via standard `logging.getLogger("scp_sdk").setLevel(...)`.
   - Bridge-level debug output (Rust `tracing`) is forwarded to Python logging via a pyo3 log bridge.

### Scope

**Files (~8-10):**

| File | Purpose |
|------|---------|
| `scp_sdk/__init__.py` | Package root, re-exports, version, top-level convenience |
| `scp_sdk/identity.py` | `Identity` class, `DIDDocument`, identity operations |
| `scp_sdk/context.py` | `Context` class, `Membership`, async context manager, message streaming |
| `scp_sdk/tools.py` | `ToolDefinition`, `TestVector`, `ToolVerification` dataclasses |
| `scp_sdk/trust.py` | `evaluate_trust()`, `TrustEvaluation` dataclass |
| `scp_sdk/event_log.py` | `EventLog` class, `Event`, `Proof`, `Checkpoint` dataclasses |
| `scp_sdk/errors.py` | Exception hierarchy, error code constants |
| `scp_sdk/transport.py` | `TransportConfig`, relay connection helpers |
| `scp_sdk/types.py` | Shared types: `Message`, `Provenance`, `Capability`, enums |
| `scp_sdk/sync.py` | Sync wrapper utilities, `run_sync()` helper |
| `scp_sdk/py.typed` | PEP 561 marker file for type checking |
| `pyproject.toml` | Package metadata, build config, dependencies, optional extras |

**Estimated functions:** ~40-50 public methods, ~15-20 dataclasses/types, ~10 internal helpers.

---

## ADR-015: MCP Adapter

**Status:** Decided

### Context

MCP (Model Context Protocol) defines how AI models connect to tools and data sources locally via JSON-RPC (spec section 8.5). The SCP agent acts as an MCP server from the model's perspective and an SCP protocol participant from the network's perspective. Any MCP-compatible model (Claude, GPT, Gemini, open-source models) can participate in SCP contexts without knowing SCP exists — it sees MCP tools namespaced by context, calls them, and gets results. The MCP adapter is the translation layer that makes this work (architecture.md section 1.3).

The adapter must map SCP tool interfaces to MCP tool definitions, filter tools by the agent's role and UCAN capabilities (so models never see tools they cannot access), handle MCP protocol mechanics (JSON-RPC over stdio or SSE), and route tool invocations through the SCP protocol engine with full authentication, encryption, and provenance.

### Decision

Implement the MCP adapter as the `scp-mcp` crate (Rust) with a Python interface via the PyO3 bridge (ADR-013) and Python wrappers (ADR-014). The adapter implements both MCP server mode (SCP agent exposes tools to a local model) and MCP client mode (SCP agent consumes external MCP tools and wraps them with SCP provenance). The primary interface for Python users is `scp_sdk.mcp.serve_mcp()`, which starts an MCP server that dynamically exposes tools from the agent's active SCP contexts.

### Rationale

- **MCP server as the model-facing surface:** The model calls MCP tools. The adapter translates each tool call into an SCP context operation (message send, tool invocation, event log query). The model never handles DIDs, UCANs, encryption, or transport. This separation is critical — it means every existing MCP-compatible model works with SCP with zero integration effort (spec section 8.5).
- **Capability filtering at the adapter:** MCP has no access control concept — all configured tools are available. SCP tools are capability-gated by role. The adapter resolves this by querying the agent's UCAN capabilities and exposing only permitted tools to the model. Tools the agent lacks capability for are invisible to the model (spec section 8.5, "capability filtering happens at the agent").
- **Context-namespaced tools:** Tools are namespaced by context: `context_a/send_message`, `context_a/guide_assistant`, `context_b/schedule_meeting`. This gives the model a flat tool surface that implicitly encodes context scoping. The adapter parses the namespace prefix, routes to the correct context, and handles the SCP protocol mechanics.
- **Dual transport: stdio and SSE:** MCP supports two transport modes. stdio (standard input/output) is the default for local integrations (Claude Code, Cursor). SSE (Server-Sent Events over HTTP) supports remote and web-based integrations. The adapter supports both.
- **MCP client mode:** An SCP agent can also consume tools from external MCP servers (non-SCP tools). When it does, the adapter wraps the tool call with SCP provenance metadata: "this result came from external MCP tool X, invoked by agent Y in context Z." This maintains SCP's provenance-everywhere principle (spec section 1, principle 3) even for external tool calls.

### Implementation

- **Language:** Rust (`scp-mcp` crate) + Python (`scp_sdk/mcp.py` wrapper)
- **MCP protocol:** JSON-RPC 2.0 over stdio (stdin/stdout line-delimited JSON) and SSE (HTTP with Server-Sent Events for server-to-client, POST for client-to-server)
- **Libraries:** `serde_json` for JSON-RPC serialization, `tokio` for async I/O, `axum` for HTTP/SSE transport, `hyper` for HTTP client (MCP client mode)
- **Crate:** `scp-mcp`
- **Modules:** `scp-mcp/server.rs` (MCP server), `scp-mcp/client.rs` (MCP client), `scp-mcp/protocol.rs` (JSON-RPC types)
- **Python:** `scp_sdk/mcp.py` wraps the Rust MCP server/client via the PyO3 bridge

### Dependencies

- **ADR-013 (PyO3 Bridge):** The MCP adapter is exposed to Python through the bridge layer.
- **ADR-014 (Python SDK Wrappers):** The `scp_sdk.mcp` module uses SDK wrapper types (Identity, Context, ToolDefinition).
- **ADR-010 (Tools):** Tool registration and invocation flow through the context tool registry.
- **ADR-009 (Roles/UCAN):** Capability filtering requires UCAN validation to determine which tools the agent can access.

### Acceptance Criteria

1. **MCP server — tool listing:**

   ```python
   # Python usage
   from scp_sdk.mcp import serve_mcp

   server = await serve_mcp(
       identity=my_identity,
       contexts=[context_a, context_b],
       transport="stdio",  # or "sse"
   )
   ```

   - `tools/list` JSON-RPC method returns all tools the agent can access across all active contexts.
   - Tools are namespaced: `{ "name": "context_a/guide_assistant", "inputSchema": {...} }`.
   - Built-in tools per context: `{context}/send_message`, `{context}/read_messages`, `{context}/list_members`.
   - Context-registered tools: `{context}/{tool_name}` for each tool in the context's tool registry.
   - Capability filtering: only tools the agent's role permits are listed. An agent with `member` role does not see admin-only tools.

2. **MCP server — tool invocation:**

   ```json
   // MCP request from model
   {
       "jsonrpc": "2.0",
       "method": "tools/call",
       "params": {
           "name": "context_a/guide_assistant",
           "arguments": { "query": "butter substitute" }
       },
       "id": 1
   }
   ```

   - The adapter parses the context namespace prefix.
   - Validates the agent's UCAN capability for the target tool in the target context.
   - Routes the invocation through the SCP context's tool invocation path (ADR-010).
   - Input is validated against the tool's input schema.
   - Output is validated against the tool's output schema.
   - Provenance is attached to the result.
   - The JSON-RPC response contains the tool output as content.
   - Errors are returned as JSON-RPC error responses with descriptive messages.

3. **MCP server — resource listing (context events):**
   - `resources/list` returns SCP context event streams as MCP resources.
   - Resources: `scp://context_a/events`, `scp://context_a/members`, `scp://context_a/tools`.
   - `resources/read` returns the current state of a resource (e.g., member list, recent events).
   - Resource subscriptions (`resources/subscribe`) map to SCP context event streams.

4. **MCP server — stdio transport:**
   - Reads JSON-RPC requests from stdin (line-delimited JSON).
   - Writes JSON-RPC responses to stdout.
   - Handles MCP lifecycle: `initialize`, `initialized`, `ping`.
   - Runs as a long-lived process (suitable for Claude Code, Cursor, and other MCP hosts).

5. **MCP server — SSE transport:**
   - HTTP server (configurable host:port) serves SSE endpoint for server-to-client messages.
   - POST endpoint accepts client-to-server JSON-RPC requests.
   - Handles connection lifecycle, reconnection, keep-alive.
   - Suitable for web-based MCP clients and remote integrations.

6. **MCP client — consuming external tools:**

   ```python
   from scp_sdk.mcp import McpClient

   # Connect to an external MCP server
   client = await McpClient.connect("stdio", command=["uvx", "some-mcp-server"])

   # List available tools
   tools = await client.list_tools()

   # Invoke a tool with SCP provenance wrapping
   result = await client.invoke(
       tool="external_tool",
       input={"key": "value"},
       context=my_context,      # SCP context for provenance
       identity=my_identity,    # SCP identity for signing
   )
   # result.provenance = { source: "mcp:external_tool", invoked_by: my_did, context: ctx_id }
   ```

   - Connects to external MCP servers via stdio or SSE.
   - Lists and invokes external tools.
   - Wraps results with SCP provenance metadata (source tool, invoking agent, context, timestamp).
   - Provenance-wrapped results can be sent into SCP contexts as tool outputs with traceable origin.

7. **Dynamic context updates:**
   - When the agent joins or leaves a context, the MCP server's tool list updates dynamically.
   - `notifications/tools/list_changed` is sent to MCP clients to trigger re-listing.
   - When a tool is registered, updated, or removed in a context, the MCP tool list reflects the change.

8. **CLI entry point:**

   ```bash
   # Start SCP as an MCP server from the command line
   scp-mcp serve --identity <did> --relay <relay_url> --transport stdio
   ```

   - The `scp-mcp` CLI binary starts an MCP server for a given SCP identity.
   - Connects to specified relays, loads active contexts, and serves tools.
   - Suitable for integration with MCP hosts that launch servers as subprocesses.

### Scope

**Files (~6-8):**

| File | Purpose |
|------|---------|
| `scp-mcp/server.rs` | MCP server: tool listing (with capability filtering), tool invocation routing, resource listing, lifecycle handling |
| `scp-mcp/client.rs` | MCP client: connect to external MCP servers, invoke tools, wrap results with SCP provenance |
| `scp-mcp/protocol.rs` | JSON-RPC 2.0 types: Request, Response, Error, Notification. MCP-specific message types: Initialize, ToolsList, ToolsCall, ResourcesList |
| `scp-mcp/stdio.rs` | stdio transport: line-delimited JSON over stdin/stdout |
| `scp-mcp/sse.rs` | SSE transport: HTTP server with SSE for server-to-client, POST for client-to-server |
| `scp-mcp/namespace.rs` | Context namespace parsing: `context_id/tool_name` splitting, built-in tool definitions (send_message, read_messages, list_members) |
| `scp_sdk/mcp.py` | Python wrapper: `serve_mcp()`, `McpClient`, configuration, convenience functions |

**Estimated functions:** ~20-25 public functions (server), ~10-15 public functions (client), ~10 protocol types, ~5-8 Python wrapper methods.

---

## ADR-016: UCAN Validation

**Status:** Decided

### Context

UCAN (User Controlled Authorization Networks) tokens are the capability enforcement mechanism for SCP (spec section 7.2). Every protocol action — message send, tool invocation, member management, role change — requires a valid UCAN token. Tokens are bearer tokens with cryptographic delegation chains, mandatory nonces for replay prevention (spec section 9.5), and independent revocability. The UCAN validation module in the SDK is the enforcement point: it verifies signature chains, capability scoping, nonce uniqueness, revocation status, expiry, and ceiling compliance on every action.

Phase 2 (ADR-009) defined the role assignment and capability ceiling enforcement architecture. This ADR specifies the SDK-level UCAN validation implementation that Python (and other language) SDK users interact with — the validation logic exposed through the PyO3 bridge and used by the MCP adapter for capability filtering.

### Decision

Implement comprehensive UCAN validation in `scp-core/crypto/ucan/` (Rust, building on the ADR-009 foundation) with full exposure through the PyO3 bridge (ADR-013) to Python. The validation module handles: UCAN token parsing, Ed25519 signature chain verification, capability matching against context ceilings, nonce uniqueness enforcement, revocation checking, expiry verification, and attenuation chain verification. The Python SDK exposes validation as both an explicit API (`scp_sdk.ucan.validate()`) and an implicit enforcement layer (every `Context.send()`, `Context.invoke()`, etc. validates capabilities internally).

### Rationale

- **Per-action validation is non-negotiable:** The spec mandates UCAN validation on every action (spec section 7.2). A token revoked mid-session takes effect immediately — the next action fails. This is not an optimization target; it is a security invariant. Validation is in the hot path for every SCP operation.
- **Attenuation chain verification:** UCAN tokens support delegation — Alice delegates to Bob, who delegates to Carol. Each delegation can attenuate (narrow) capabilities. The validation module must verify the complete chain: every signature valid, every delegation narrower than or equal to its parent, root issuer is the context creator. Attenuation violations (a delegatee claiming broader capabilities than delegated) must be rejected.
- **Nonce uniqueness for replay prevention (spec section 9.5):** Every UCAN token includes a mandatory `nnc` (nonce) field. The SDK tracks seen nonces per context and rejects duplicates. Without nonce tracking, a captured UCAN could be replayed to authorize actions the human never intended. Nonces are pruned after 24 hours to bound storage.
- **Ceiling integration:** UCAN capabilities are bounded by the context's immutable capability ceiling (spec section 5.3). A valid UCAN chain that grants a capability outside the ceiling is rejected. Ceiling checking is a constant-time set membership test, performed as part of every validation.
- **Rust implementation, Python exposure:** Validation logic is implemented in Rust for performance (hot path) and correctness (crypto operations). Python sees a clean API surface via the bridge. Validation failures surface as `scp_sdk.PermissionError` with descriptive messages.

### Implementation

- **Language:** Rust
- **Library:** `rs-ucan` crate (or `ucan` crate — must support UCAN 0.10+ with mandatory nonce field). If no crate supports mandatory nonces, implement UCAN parsing and validation directly using `serde_json`, `ed25519-dalek`, and `base64`.
- **Crate:** `scp-core`
- **Module:** `scp-core/crypto/ucan/` (extends the ADR-009 structure)
- **Nonce storage:** In-memory `HashSet<String>` per context with 24-hour pruning, backed by `scp-platform` Storage trait for persistence across restarts.
- **Revocation storage:** Per-context revocation list (set of revoked token CIDs), distributed via MLS application messages, persisted to storage.

### Dependencies

- **ADR-013 (PyO3 Bridge):** UCAN validation is exposed to Python via bridge functions (`py_ucan_validate`, `py_ucan_mint`, `py_ucan_revoke`).
- **ADR-009 (Roles/UCAN):** ADR-009 defined the role assignment and ceiling enforcement architecture. ADR-016 implements the complete validation pipeline that ADR-009 calls into.
- **ADR-003 (DID):** UCAN token signatures are verified against DID public keys. Delegation chains reference DIDs. Validation requires DID resolution for public key lookup.
- **ADR-008 (Context):** UCAN validation is context-scoped. The capability ceiling, nonce tracker, and revocation list are per-context state.

### Acceptance Criteria

1. **UCAN token structure:**

   ```rust
   pub struct UcanToken {
       pub header: UcanHeader,
       pub payload: UcanPayload,
       pub signature: Ed25519Signature,
       pub encoded: String,            // Original encoded token (for signature verification)
   }

   pub struct UcanHeader {
       pub alg: String,                // "EdDSA"
       pub typ: String,                // "JWT" (UCAN is JWT-based)
       pub ucv: String,                // UCAN version, "0.10.0"
   }

   pub struct UcanPayload {
       pub iss: String,                // Issuer DID
       pub aud: String,                // Audience DID
       pub exp: u64,                   // Expiration (Unix timestamp)
       pub nbf: Option<u64>,           // Not-before (Unix timestamp)
       pub nnc: String,                // Nonce (mandatory, spec §9.5)
       pub att: Vec<Attenuation>,      // Capabilities granted
       pub prf: Vec<String>,           // Proof chain (CIDs of parent UCANs)
       pub fct: Option<serde_json::Value>, // Optional facts
   }

   pub struct Attenuation {
       pub with: String,               // Resource URI: "scp:ctx:{context_id}/{capability}"
       pub can: String,                // Action: "invoke", "read", "write"
   }
   ```

2. **`validate_ucan(context, token, required_capability) -> Result<(), UcanError>`:**
   - **Step 1 — Parse:** Decode the JWT-format UCAN token. Reject malformed tokens.
   - **Step 2 — Signature verification:** Verify the Ed25519 signature on the token. The signature covers `base64url(header).base64url(payload)`.
   - **Step 3 — Chain verification:** For each proof CID in `prf`, resolve the parent UCAN, verify its signature, and verify the parent's `aud` matches this token's `iss` (delegation chain integrity). Recurse until reaching a root token (empty `prf`).
   - **Step 4 — Root issuer:** Verify the root token's `iss` is the context creator's DID.
   - **Step 5 — Audience:** Verify the token's `aud` matches the presenting agent's DID.
   - **Step 6 — Capability match:** Verify the token's `att` includes the `required_capability`. Capability matching supports wildcards (`scp:ctx:*/messages:write` matches any context).
   - **Step 7 — Attenuation:** Verify each delegation in the chain narrows or preserves capabilities (never widens). A child token cannot grant capabilities its parent does not have.
   - **Step 8 — Ceiling:** Verify the `required_capability` is within the context's immutable capability ceiling.
   - **Step 9 — Nonce:** Validate nonce format (`{unix_millis}-{hex16}`). Validate nonce freshness (timestamp within ± 5 minutes of now). Verify `nnc` has not been seen before in this context. Record the nonce with the token's `exp` in the context's nonce tracker.
   - **Step 10 — Revocation:** Verify the token's CID is not in the context's revocation list.
   - **Step 11 — Expiry:** Verify `exp > now` and `nbf <= now` (if present).
   - Returns `Ok(())` if all 11 checks pass. Returns a specific `UcanError` variant indicating which check failed.

3. **`mint_ucan(issuer, audience, capabilities, context_id, expiry) -> UcanToken`:**
   - Creates a new UCAN token.
   - Generates a unique nonce (UUID v4 or 32 random bytes, hex-encoded).
   - Constructs the `att` array from the `capabilities` list, scoped to the context: `"scp:ctx:{context_id}/{capability}"`.
   - Signs with the issuer's Ed25519 key.
   - Returns the signed token.

4. **`delegate_ucan(parent_token, delegator, delegatee, attenuated_capabilities) -> UcanToken`:**
   - Creates a delegated UCAN.
   - Verifies `delegator` DID matches `parent_token.aud`.
   - Verifies `attenuated_capabilities` is a subset of `parent_token.att` (attenuation, never widening).
   - Sets `prf` to include the parent token's CID.
   - Signs with the delegator's key.
   - Returns the delegated token.

5. **`revoke_ucan(context, token_cid, revoker) -> Result<(), UcanError>`:**
   - Verifies the revoker is the token's issuer or the context creator.
   - Adds the token CID to the context's revocation list.
   - Distributes the revocation as an MLS application message to all context members.
   - Appends `TokenRevoked` event to the context's event log.

6. **`NonceTracker` (per-context):**

   ```rust
   pub struct NonceTracker {
       /// Map of nonce -> (first_seen_timestamp, token_expiry_timestamp).
       seen: HashMap<String, (u64, u64)>,
       context_id: ContextId,
   }

   impl NonceTracker {
       pub fn check_and_record(&mut self, nonce: &str, token_expiry: u64) -> Result<(), UcanError> { ... }
       pub fn prune(&mut self) { ... }
   }
   ```

   **Nonce format:** `{unix_millis_timestamp}-{16_random_bytes_hex}`. The timestamp prefix enables efficient pruning; the random suffix ensures uniqueness.

   **Nonce freshness check:** The timestamp prefix MUST be within `now ± 5 minutes` (matching clock skew tolerance from §9.14). Nonces outside this window are rejected as `UcanError::NonceTooOld` or `UcanError::NonceFuture`.

   **Replay window:** A nonce is retained until `max(token_expiry + 5 minutes, first_seen + 24 hours)`.

   - `check_and_record(nonce, token_expiry)` validates format, validates freshness, returns `UcanError::NonceReused` if seen before, records `(now, token_expiry)` if new.
   - `prune()` removes entries where `now > max(token_expiry + 300, first_seen + 86400)`. Runs every 1000 checks or 10 minutes.
   - State is persisted to `scp-platform` Storage for crash recovery.

7. **`RevocationList` (per-context):**

   ```rust
   pub struct RevocationList {
       revoked: HashSet<String>,       // Set of revoked token CIDs
       context_id: ContextId,
   }

   impl RevocationList {
       pub fn is_revoked(&self, token_cid: &str) -> bool { ... }
       pub fn revoke(&mut self, token_cid: String) { ... }
       pub fn merge(&mut self, remote: &RevocationList) { ... }  // Merge from MLS message
   }
   ```

   - Revocations are distributed as MLS application messages, so all members maintain consistent revocation lists.
   - `merge()` is union-only (revocations are append-only — a token cannot be un-revoked).

8. **Python SDK exposure:**

   ```python
   # Explicit validation (for advanced use)
   from scp_sdk.ucan import validate, mint, revoke

   token = await mint(
       issuer=my_identity,
       audience=agent_did,
       capabilities=["messages:write", "tool_invoke:assistant"],
       context=my_context,
       expiry=3600,  # seconds from now
   )

   await validate(
       context=my_context,
       token=token,
       capability="messages:write",
   )

   await revoke(context=my_context, token=token)

   # Implicit validation (built into every SDK operation)
   await context.send("hello")  # Internally calls validate() before sending
   ```

9. **Capability URI format:**
   - Resource URI: `scp:ctx:{context_id}/{capability}`
   - Examples:
     - `scp:ctx:abc123/messages:write`
     - `scp:ctx:abc123/tool_invoke:assistant`
     - `scp:ctx:abc123/member:invite`
     - `scp:ctx:abc123/role:assign`
     - `scp:ctx:abc123/context:close`
   - Wildcard: `scp:ctx:*/messages:write` (all contexts — used for root authority tokens).

### Scope

**Files (~4-6):**

| File | Purpose |
|------|---------|
| `scp-core/crypto/ucan/mod.rs` | Module root, `UcanToken` struct, `UcanHeader`, `UcanPayload`, `Attenuation`, re-exports |
| `scp-core/crypto/ucan/validate.rs` | `validate_ucan()` — the 11-step validation pipeline, capability matching, attenuation verification |
| `scp-core/crypto/ucan/mint.rs` | `mint_ucan()`, `delegate_ucan()` — token creation with nonce generation, signing, delegation chain construction |
| `scp-core/crypto/ucan/revoke.rs` | `revoke_ucan()`, `RevocationList` struct — revocation management and MLS distribution |
| `scp-core/crypto/ucan/nonce.rs` | `NonceTracker` struct — nonce uniqueness enforcement, pruning, storage persistence |
| `scp-core/crypto/ucan/capability.rs` | Capability URI parsing, matching, wildcard support, ceiling intersection |
| `scp_sdk/ucan.py` | Python wrapper: `validate()`, `mint()`, `revoke()`, `delegate()` |

**Estimated functions:** ~15-18 public functions, ~10-12 internal helpers, ~8-10 type definitions.

---

## Phase 3 Dependency Graph

```
Phase 1 (ADR-001..007)    Phase 2 (ADR-008..012)
         \                      /          \
          \                    /            \
           v                  v              v
    ADR-013 (PyO3 Bridge Layer)    ADR-033 (Economic Governance)
      /        \
     v          v
ADR-014       ADR-016
(Python SDK)  (UCAN Validation)
     |
     v
ADR-015
(MCP Adapter)
```

Build order:
1. ADR-013 + ADR-033 — PyO3 bridge and economic governance (parallel, both depend on Phase 1 + Phase 2)
2. ADR-014 + ADR-016 — Python SDK wrappers and UCAN validation (parallel, both depend on ADR-013)
3. ADR-015 — MCP adapter (depends on ADR-013 + ADR-014)

---

## Phase 3 Integration Test

The ultimate acceptance criterion for Phase 3 exercises all 4 ADRs together with the Phase 1 and Phase 2 Rust stacks:

```
1. Install the SDK: `pip install scp-sdk` in a clean Python venv. No Rust toolchain.
   Zero compilation. Binary wheel installs in seconds.

2. Alice creates an identity in Python:
   alice = await scp.Identity.create(custody="in_memory")
   Calls through: Python wrapper (ADR-014) → PyO3 bridge (ADR-013) → scp-core Identity::create

3. Alice creates a context with tools:
   ctx = await scp.Context.create(
       creator=alice,
       ceiling=["messaging", "tool_invoke"],
       tools=[scp.ToolDefinition(name="calculator", ...)],
   )
   Context creation mints admin UCAN tokens for Alice (ADR-016).
   UCAN nonce is generated and tracked. Capability ceiling is set and immutable.

4. Bob creates an identity and joins the context:
   bob = await scp.Identity.create(custody="in_memory")
   membership = await ctx.join(bob)
   Bob receives member-role UCAN tokens (ADR-016). Tokens are scoped to
   messages:read, messages:write, tool_invoke_all. UCAN signature chain
   traces to Alice (context creator) as root authority.

5. Alice sends a message — UCAN validated:
   await ctx.send("Hello from Python", identity=alice)
   Internally: validate_ucan(ctx, alice_token, "messages:write") passes (ADR-016).
   Message flows through scp-core: sender key encrypt → MLS encrypt → envelope →
   multi-relay publish. All via PyO3 bridge (ADR-013).

6. Bob receives the message via async iterator:
   async for msg in ctx.receive():
       print(msg.content)  # "Hello from Python"
   Async iterator bridges tokio stream → Python asyncio via PyO3 native async (ADR-013).

7. Bob invokes the calculator tool:
   result = await ctx.invoke("calculator", {"operation": "add", "a": 1, "b": 2})
   assert result == {"result": 3}
   UCAN validates Bob has tool_invoke capability (ADR-016).
   Tool invocation is logged in the Merkle event log.

8. Bob attempts an admin action — UCAN rejects:
   try:
       await ctx.close(identity=bob)
   except scp.PermissionError:
       pass  # Bob lacks context:close capability. UCAN validation failed (ADR-016).

9. Start an MCP server exposing Alice's SCP contexts (ADR-015):
   server = await scp.mcp.serve_mcp(identity=alice, contexts=[ctx], transport="stdio")
   An MCP client (Claude, GPT) connects and sees:
     tools/list → [
       {"name": "ctx_123/send_message", ...},
       {"name": "ctx_123/calculator", ...},
       {"name": "ctx_123/read_messages", ...},
       {"name": "ctx_123/list_members", ...},
     ]
   Admin tools (close_context, invite_member) are visible because Alice is admin.
   Member tools only would be visible for a member-role agent.

10. MCP client invokes a tool:
    tools/call("ctx_123/calculator", {"operation": "multiply", "a": 3, "b": 7})
    → {"result": 21}
    The MCP adapter (ADR-015) parses the context namespace, validates UCAN,
    routes through scp-core tool invocation, returns the result via JSON-RPC.
    The model never saw a DID, UCAN token, MLS group, or relay.

11. Verify event log from Python:
    events = await ctx.event_log.query(event_type="tool_invoked")
    proof = await ctx.event_log.verify({"event_exists": events[0].id})
    assert proof.valid
    Merkle proof verification runs in Rust, result returned to Python (ADR-013).

12. Alice revokes Bob's tool invocation capability:
    await scp.ucan.revoke(context=ctx, token=membership.tokens["tool_invoke_all"])
    Revocation distributed via MLS to all members (ADR-016).
    Bob's next tool invocation attempt fails with PermissionError.

13. Throughout: Every Python async call crosses the PyO3 bridge (ADR-013),
    runs on the shared tokio runtime, and returns results as native Python
    objects. No Rust concepts leak. Errors are Python exceptions. Types have
    full PEP 484 hints. IDE autocompletion works.
```

This test proves: pip install works without Rust, the 20-line agent works, async Python wraps Rust correctly, UCAN enforces on every action, MCP exposes SCP tools to any model, the event log is queryable from Python, and the full Phase 1 + Phase 2 Rust stack is accessible through a Pythonic API.

---

## ADR-033: Economic Governance

**Status:** Decided

### Context

The agent economy needs protocol-level economic infrastructure. SaaS companies are seeing 50k+ agent requests/hour from OpenClaw-style agents. Machine payments are a rate limit that generates money — the modern realization of Dwork & Naor (1992), fixing Hashcash's botnet asymmetry problem ($0.001 costs $0.001 regardless of attacker resources).

Prior art: Dwork & Naor (1992) computational spam prevention, Hashcash (1997) proof-of-work for email, x402 (2025) machine-to-machine payments on Base/Solana, L402 Lightning + Macaroons for API access, Stripe machine payments (2025), EIP-1559 algorithmic dynamic pricing.

No existing standard combines UCAN delegation chains with payment semantics. L402/Macaroons have spending caveats but not DID-based delegation. ILP/GNAP has payment authorization but not capability-chain attenuation. SCP is the first to define spending-scoped UCAN capabilities.

### Decision

1. **Payment adapter trait** following the transport adapter pattern (ADR-005): `PaymentAdapter` with `authorize`, `capture`, `void`, `verify`, `refund` methods. `AdapterCapabilities` struct declares supported features. `payment_adapter_conformance!()` macro validates implementations. `TestAdapter` in-memory reference ships with SDK.

2. **Spending UCAN** as new capability type: `SpendingCapability` with `max_per_action`, `max_total`, `currency`, `time_window`, `allowed_adapters`. AND-composed with action UCANs — both required for paid actions. Standard UCAN attenuation and revocation rules apply.

3. **Formula-based dynamic pricing** (EIP-1559-inspired): `PricingFormula` with `base_cost`, `variables` (linear/step), `cap`, `floor`. Observable metrics: `ContextMessageRate`, `MemberCount`, `RelayQueueDepth`, `TimeOfDay`, `SenderVelocity`, `StorageUsage`. Both sides evaluate independently — deterministic, no oracle.

4. **Mutable economic policy with optional lock**: `EconomicPolicy` governed by default (pricing changes are normal business), with optional immutability lock at creation. Lock is itself immutable.

5. **Authorize-then-capture and invoice-then-preimage** as canonical flow patterns: two models that cover x402/Stripe (auth-capture) and Lightning/L402 (invoice-preimage). Both map onto the `PaymentAdapter` trait.

6. **Three independent economic levels**: relay (transport), context (participation), tool (per-invocation). Each with its own payee, pricing, and adapter configuration. Free is default at all levels.

7. **Phase 3 delivery**: All protocol components (trait, policy, UCAN type, receipts, formulas) compose Phase 1 + Phase 2 primitives. No new crypto. Community adapters (x402, Lightning, SPL, Stripe) are Phase 4+.

8. **Integer-only arithmetic** for cross-party determinism: `Amount(u64)` in smallest currency unit (cents, satoshis), `Coefficient(i64)` as fixed-point with 6 decimal places. No IEEE 754 floats in economic calculations — both sides evaluate pricing formulas identically.

### Rationale

- **Adapter trait pattern (ADR-005 mirror):** The transport adapter pattern proved successful — thin async trait, conformance macro, reference implementation, community adapters. Economic governance mirrors this exactly. Adapter authors implement 5 methods; the protocol handles all integration logic. Trait evolution never touches adapter implementations.
- **Spending UCAN over bespoke authorization:** UCANs already provide delegation, attenuation, and revocation (ADR-009, §7.2). Adding a new capability type (`SpendingCapability`) extends the existing system rather than creating a parallel one. AND-composition with action UCANs means spending authorization composes with every other capability type without special-casing.
- **Formula-based over oracle-based pricing:** The protocol-requires-no-operator principle (§1) forbids external dependencies for core protocol operations. Formula-based pricing is deterministic, evaluable by both parties independently, and requires no external service. EIP-1559 proved this model at massive scale (Ethereum processes ~1M transactions/day with algorithmic pricing).
- **Mutable economic policy vs. immutable ceiling:** Capability ceilings are security boundaries — changing what CAN happen has security implications. Economic policy governs what things COST — price changes are normal business operations. Different mutability defaults reflect this distinction. Optional immutability lock provides voluntary commitment for trust-sensitive contexts (public goods, permanent free tiers).
- **Integer arithmetic over floating-point:** IEEE 754 is non-associative: `(a + b) + c != a + (b + c)` in general. When payer and receiver independently evaluate a pricing formula, f64 coefficients can produce different results. Integer arithmetic (Amount in smallest unit, Coefficient as fixed-point) is deterministic across all platforms, compilers, and optimization levels. Follows Stripe/Bitcoin/Solana conventions.

### Implementation

- **Language:** Rust
- **Crates affected:**
  - `scp-core/src/economy/` — new module: `PaymentAdapter` trait, `EconomicPolicy`, `CostSchedule`, `PricingFormula`, `SpendingCapability`, `PaymentReceipt`, `Amount`, `Coefficient`, `CurrencyCode`
  - `scp-core/src/ucan/` — add `SpendingCapability` variant to capability types, AND-composition logic
  - `scp-core/src/context/` — add `economic_policy: Option<EconomicPolicy>` to `ContextParams`, auto-accept guard for paid contexts
  - `scp-core/src/event/` — add `PaymentReceived`, `EconomicPolicyChanged`, `SpendingUcanGranted`, `SpendingUcanRevoked` event types
  - `scp-core/src/store/` — add `ProtocolStore` methods for economic data (economic_policy, payment_receipt, spending_ucan storage keys per §17.3)
  - `scp-testing/src/conformance/payment.rs` — `payment_adapter_conformance!()` macro (§16.12.7)
  - `scp-testing/src/` — `TestAdapter` in-memory reference payment adapter
  - `scp-transport/native/` — extend `.well-known/scp` relay config parsing with economic fields

- **Key types:**

```rust
// --- Core economic types (§19.1.1) ---

pub struct Amount(pub u64);                     // smallest currency unit (cents, satoshis)
pub struct CurrencyCode(pub [u8; 4]);           // ISO 4217 or protocol-defined
pub struct Coefficient(pub i64);                // fixed-point: value = raw / 1_000_000
pub type PaymentAdapterRef = String;            // adapter_id string

pub enum PaidActionType {
    MessageSend, ToolInvoke, ContextJoin, SubscriptionPeriod, ByteStored,
}

// --- Payment adapter (§19.2.1) ---

#[async_trait]
pub trait PaymentAdapter: Send + Sync {
    fn adapter_id(&self) -> &str;
    fn capabilities(&self) -> AdapterCapabilities;
    async fn authorize(&self, payer: &DID, payee: &DID, amount: Amount,
        currency: CurrencyCode, metadata: PaymentMetadata,
    ) -> Result<PaymentAuthorization, PaymentError>;
    async fn capture(&self, auth: &PaymentAuthorization) -> Result<PaymentReceipt, PaymentError>;
    async fn void(&self, auth: &PaymentAuthorization) -> Result<(), PaymentError>;
    async fn verify(&self, receipt: &PaymentReceipt) -> Result<VerificationResult, PaymentError>;
    async fn refund(&self, receipt: &PaymentReceipt, amount: Option<Amount>,
    ) -> Result<RefundConfirmation, PaymentError>;
}

pub struct AdapterCapabilities {
    pub supported_currencies: Vec<CurrencyCode>,
    pub supports_streaming: bool,
    pub supports_batch_auth: bool,
    pub supports_single_step: bool,
    pub min_amount: Option<Amount>,
    pub max_amount: Option<Amount>,
    pub typical_settlement_ms: u64,
    pub requires_facilitator: bool,
}

pub struct PaymentMetadata {
    pub action_type: PaidActionType,
    pub context_id: Option<ContextId>,
    pub idempotency_key: [u8; 16],
}

pub struct PaymentAuthorization {
    pub auth_id: [u8; 32],
    pub payer: DID, pub payee: DID,
    pub amount: Amount, pub currency: CurrencyCode,
    pub adapter_id: String,
    pub created_at: u64, pub expires_at: u64,
    pub adapter_state: Vec<u8>,
}

pub enum PaymentError {
    InsufficientBalance { available: Amount, requested: Amount },
    UnsupportedCurrency(CurrencyCode),
    AuthorizationExpired { auth_id: [u8; 32] },
    AlreadyCaptured { auth_id: [u8; 32] },
    AlreadyVoided { auth_id: [u8; 32] },
    InvalidReceipt(String),
    AdapterError(String),
    NoCompatiblePaymentAdapter,
}

// --- Economic policy (§19.3) ---

pub struct EconomicPolicy {
    pub locked: bool,
    pub cost_schedule: CostSchedule,
    pub payment_adapters: Vec<PaymentAdapterRef>,
    pub pricing_formula: Option<PricingFormula>,
    pub payee: DID,
}

pub struct CostSchedule {
    pub currency: CurrencyCode,
    pub per_message: Option<Amount>,
    pub per_tool_invoke: Option<Amount>,
    pub per_join: Option<Amount>,
    pub per_period: Option<SubscriptionCost>,
    pub per_byte_stored: Option<Amount>,
}

pub struct SubscriptionCost {
    pub amount: Amount, pub period: SubscriptionPeriod, pub currency: CurrencyCode,
}
pub enum SubscriptionPeriod { Daily, Weekly, Monthly, Custom { seconds: u64 } }

// --- Dynamic pricing (§19.4) ---

pub struct PricingFormula {
    pub base_cost: Amount,
    pub variables: Vec<PricingVariable>,
    pub cap: Option<Amount>,
    pub floor: Option<Amount>,
}

pub enum PricingVariable {
    Linear { metric: PricingMetric, coefficient: Coefficient },
    Step { metric: PricingMetric, thresholds: Vec<(u64, Amount)> },
}

pub enum PricingMetric {
    ContextMessageRate, MemberCount, RelayQueueDepth,
    TimeOfDay, SenderVelocity, StorageUsage,
}

pub struct CostInsufficient {
    pub expected: Amount, pub provided: Amount,
    pub currency: CurrencyCode,
    pub metric_snapshot: Vec<(PricingMetric, u64)>,
}

// --- Spending UCAN (§19.5) ---

pub struct SpendingCapability {
    pub max_per_action: Amount,
    pub max_total: Amount,
    pub currency: CurrencyCode,
    pub time_window: Duration,
    pub allowed_adapters: Vec<String>,
}

// --- Payment receipt (§19.6) ---

pub struct PaymentReceipt {
    pub receipt_id: [u8; 32],
    pub payer: DID, pub payee: DID,
    pub amount: Amount, pub currency: CurrencyCode,
    pub action_type: PaidActionType,
    pub context_id: Option<ContextId>,
    pub adapter_id: String,
    pub adapter_proof: Vec<u8>,
    pub timestamp: u64,
    pub signature: Ed25519Signature,
}

pub struct VerificationResult {
    pub valid: bool, pub adapter_id: String,
    pub verified_amount: Amount, pub verified_currency: CurrencyCode,
    pub verification_timestamp: u64,
}

pub struct RefundConfirmation {
    pub refund_id: [u8; 32], pub original_receipt_id: [u8; 32],
    pub refunded_amount: Amount, pub currency: CurrencyCode,
    pub adapter_proof: Vec<u8>,
}
```

### Scope

**In scope (Phase 3):**
- `PaymentAdapter` trait and `AdapterCapabilities`
- `payment_adapter_conformance!()` macro
- `TestAdapter` in-memory reference implementation
- `SpendingCapability` UCAN type with AND-composition and attenuation
- `EconomicPolicy`, `CostSchedule`, `PricingFormula` structures
- `PaymentReceipt` as event log provenance record
- Dynamic pricing formula evaluation with `Amount`/`Coefficient` integer arithmetic
- Anti-spam cost escalation via `SenderVelocity`
- Relay economic config extension to `.well-known/scp`
- `paid-service` and `paid-broadcast` context templates
- Auto-accept guard for paid contexts
- Storage keys for economic data (§17.3)
- Economic event types: `PaymentReceived`, `EconomicPolicyChanged`, `SpendingUcanGranted`, `SpendingUcanRevoked`

**Out of scope (Phase 4+):**
- Production payment adapter implementations (x402, Lightning, SPL, Stripe) — community/vendor maintained
- Subscription lifecycle management (billing cycles, grace periods, dunning)
- Cross-adapter settlement or reconciliation
- Payment dispute resolution
- Tax/compliance integration
- Payment UI components

### Consequences

**Positive:**
- Every paid action generates a `PaymentReceipt` in the context event log — full economic provenance.
- Anti-spam becomes economic: `SenderVelocity` metric with step pricing makes bulk spam a P&L decision.
- Relay operators can monetize transport without accessing content (dumb pipe model preserved).
- UCAN spending delegation is a novel contribution — first standard to combine DID-based delegation chains with payment semantics.
- Agents never silently incur costs — auto-accept never applies to paid contexts.

**Negative (acknowledged trade-offs):**
- Payment adapter adds a new trait surface for SDK implementers to understand, increasing onboarding complexity.
- Integer-only arithmetic limits coefficient precision to 6 decimal places — sufficient for pricing but not for all financial calculations.
- No protocol-level subscription lifecycle — subscription billing must be implemented by contexts/tools, potentially leading to inconsistent experiences.
- `TestAdapter` is in-memory only — developers must find/implement production adapters separately (by design, but adds friction).
- Pricing formula divergence between payer and receiver (due to metric observation timing) creates retry overhead, even with the `CostInsufficient` metric snapshot mechanism.

**Protocol invariants established:**
- Free relays MUST always exist in the bootstrap list — economic gatekeeping is a protocol violation.
- Auto-accept never applies to paid contexts — agents never silently incur costs.
- Free operation is default — no economic policy = free.
- Payment data inside encrypted envelope — relays never see context-level payment metadata.

### Alternatives Rejected

- **Oracle-based pricing:** External dependency, new trust surface. Contradicts protocol-requires-no-operator principle.
- **Protocol-native token:** Regulatory complexity, violates simplicity principle. Payment rails already exist.
- **No economic layer:** Leaves spam unsolved, relay monetization ad-hoc, no standard for agent-to-service payments.
- **Per-action HTTP round-trip for payment (x402 pure):** Too tightly coupled to HTTP transport. SCP is transport-independent, so the payment adapter abstracts over the rail.
- **Prepaid balance as protocol concept:** Adapter concern (some adapters batch naturally), not protocol's business. Would add state management complexity for minimal benefit.
- **f64 coefficients in pricing formulas:** IEEE 754 non-associativity means payer and receiver can compute different prices from the same formula. Integer arithmetic (Coefficient as fixed-point) eliminates this class of bug entirely.

### Dependencies

- ADR-002 (DID identity) — DIDs as payer/payee identifiers in all payment operations
- ADR-005 (transport trait) — pattern for adapter trait design; relay economic config extends transport layer
- ADR-008 (context lifecycle) — economic policy is a context setting governed through context governance
- ADR-009 (roles/capabilities) — spending capability as new UCAN type, AND-composed with action UCANs
- ADR-011 (event log) — payment receipts recorded as event log entries with Merkle inclusion proofs

### Acceptance Criteria

1. `PaymentAdapter` trait compiles with 5 async methods: `authorize`, `capture`, `void`, `verify`, `refund`.
2. `AdapterCapabilities` struct includes all fields from §19.2.1: `supported_currencies`, `supports_streaming`, `supports_batch_auth`, `supports_single_step`, `min_amount`, `max_amount`, `typical_settlement_ms`, `requires_facilitator`.
3. `payment_adapter_conformance!()` macro generates 8 test cases matching §19.2.6: authorize/capture roundtrip, authorize/void roundtrip, double-capture rejection, insufficient balance, verify roundtrip, currency mismatch, concurrent isolation, refund.
4. `TestAdapter` passes `payment_adapter_conformance!()`.
5. `SpendingCapability` is a valid UCAN capability type. AND-composition enforced: action requiring both `messagesWrite` and `SpendingCapability` fails if either is missing.
6. UCAN attenuation: sub-delegated `SpendingCapability` must narrow (lower `max_per_action`, `max_total`) — widening is rejected.
7. `EconomicPolicy` stored in `ContextParams`. Contexts without `EconomicPolicy` are free (no payment required for any action).
8. `PricingFormula` evaluation uses `Amount(u64)` and `Coefficient(i64)` exclusively — no `f64` in any economic calculation path.
9. `CostInsufficient` error includes receiver's `metric_snapshot` so payer can see why costs diverged.
10. Auto-accept guard: `ContextInvitation` with `EconomicPolicy` requiring payment is never auto-accepted regardless of auto-accept policy configuration.
11. `PaymentReceipt` events recorded in context event log with Merkle inclusion proofs.
12. `.well-known/scp` relay config parsing accepts optional `economic` object with `per_publish`, `per_byte_stored`, `payment_adapters`, `payee` fields.
13. `paid-service` and `paid-broadcast` context templates defined with required economic policy fields.
14. Free relays exist in the default bootstrap relay list — at least one relay in the SDK's fallback list has no `economic` config.
