# Python SDK Scaffold

> Source of truth: .docs/specs/, .docs/sketch.md, .docs/adrs/. This file is downstream of those documents.

Build blueprint for the SCP Python SDK: package structure, build configuration, PyO3 bridge patterns, and type definitions. See `.docs/standards/python.md` for coding standards (style rules, linting, testing, CI).

## Package Layout

```
bindings/python/
  pyproject.toml                # Build config, metadata, dependencies
  scp_sdk/
    __init__.py                 # Re-exports: Identity, Context, ToolDefinition, ScpError, __version__
    py.typed                    # PEP 561 marker for type checkers
    identity.py                 # Identity class
    context.py                  # Context class, Membership, async context manager
    tools.py                    # ToolDefinition, TestVector dataclasses
    trust.py                    # evaluate_trust(), TrustEvaluation
    event_log.py                # EventLog class, Event, Proof, Checkpoint
    errors.py                   # Exception hierarchy (ScpError -> subtypes)
    transport.py                # TransportConfig, relay connection helpers
    types.py                    # Shared types: Message, Provenance, Capability enums
    sync.py                     # Sync wrapper utilities, run_sync() helper
    ucan.py                     # UCAN validate(), mint(), revoke(), delegate()
    mcp.py                      # serve_mcp(), McpClient
    _scp_core.pyi               # Type stubs for the PyO3 extension module
  tests/
    conftest.py                 # Shared fixtures (in-memory identity, test context)
    test_identity.py
    test_context.py
    test_tools.py
    test_ucan.py
    test_transport.py
    test_event_log.py
    test_mcp.py
    test_sync.py
    conformance/                # Cross-language conformance test runner
      test_conformance.py
```

## pyproject.toml

```toml
[build-system]
requires = ["maturin>=1.0"]
build-backend = "maturin"

[project]
name = "scp-python"
description = "Shared Context Protocol SDK — identity, encryption, contexts, tools for AI agents"
requires-python = ">=3.10"
# license = TBD
classifiers = [
    "Development Status :: 3 - Alpha",
    "Intended Audience :: Developers",
    "Programming Language :: Python :: 3",
    "Programming Language :: Rust",
    "Topic :: Security :: Cryptography",
]
dynamic = ["version"]

[project.optional-dependencies]
dev = ["pytest", "pytest-asyncio", "mypy", "ruff"]
mcp = []  # MCP server dependencies (if any beyond stdlib)

[tool.maturin]
python-source = "."
module-name = "scp_sdk._scp_core"
# Features of `scp-ffi`, the package `manifest-path` names. `extension-module`
# forwards `pyo3/extension-module`; `vendored-openssl` compiles OpenSSL into the
# Linux and Windows wheels' SQLCipher (the comment on this table in
# `bindings/python/pyproject.toml` says why and what a macOS build uses).
features = ["extension-module", "vendored-openssl"]
manifest-path = "../../crates/scp-ffi/Cargo.toml"

[tool.ruff]
target-version = "py310"
line-length = 100

[tool.ruff.lint]
select = [
    "E",    # pycodestyle errors
    "W",    # pycodestyle warnings
    "F",    # pyflakes
    "I",    # isort
    "N",    # pep8-naming
    "UP",   # pyupgrade
    "B",    # flake8-bugbear
    "A",    # flake8-builtins
    "SIM",  # flake8-simplicity
    "TCH",  # flake8-type-checking
    "RUF",  # ruff-specific rules
    "ASYNC",# flake8-async
]

[tool.ruff.lint.isort]
known-first-party = ["scp_sdk"]

[tool.mypy]
strict = true
python_version = "3.10"
warn_return_any = true
warn_unused_configs = true
disallow_untyped_defs = true
disallow_incomplete_defs = true

[tool.pytest.ini_options]
asyncio_mode = "auto"
testpaths = ["tests"]
```

## PyO3 Bridge Conventions

### Bridge function naming

Free bridge functions in Rust use the `py_` prefix. An operation that touches instance state is a method on the `SCP` pyclass instead (ADR-048, SCP as a first-class multi-instance SDK object, §1), and every identity operation is one, because the instance's Supervisor owns the identity store and the node network (`03-identity.md` §3.10.10):

```rust
#[pymethods]
impl PyScp {
    // check_ready, then Supervisor::dispatch_identity_create
    fn identity_create<'py>(&self, py: Python<'py>, config: IdentityConfig, signers: SignerPlan) -> PyResult<Bound<'py, PyAny>> { ... }
}
```

**`scp.identity_create` takes the config object `.docs/standards/construction.md` states, and `custody` carries the bridge's `KeyCustodyConfig` and carries no default**, because that slot decides where an identity's private key lives. No free `Identity.create` exists:

```python
class SCP:
    async def identity_create(self, config: IdentityConfig, signers: SignerPlan) -> Created:
        raw = await self._core.identity_create(config, signers)
        return Created._from_raw(raw)  # Created.identity is an Identity wrapping the bridge's handle id

# IdentityConfig(custody=KeyCustodyConfig.ENCRYPTED_FILE,       # required; no default (03-identity.md §3.2.2)
#                next_set_custody=...,                      # required; the bridge's NextSetCustodyConfig
#                profile=...,                               # required; the CustodyProfile
#                witnesses=WitnessChoice.CommunityDefault)  # required; no default; no store field, no ephemeral identity
```

### Node and identity types

| Concept | Python |
|---------|--------|
| Canonical node URL, validated at construction | `NodeUrl` |
| A context's node address, read-only: `url` and optional `bridge` | `NodeAddress` |
| The accepted node list, read-only: `entries` and `node_list_sequence` | `AcceptedNodeList` |
| Read the accepted node list, `None` where the instance holds none | `scp.identity_node_list()` |
| Witness choice, name-bound | `WitnessChoice.CommunityDefault`, `WitnessChoice.Designated(witnesses=[...])`, `WitnessChoice.NoWitness` |
| One identity's handle, returned by `scp.identity_create` (as `Created.identity`) and `scp.identity_load` | `Identity` |

### Opaque types

PyO3 classes are opaque — no raw struct access from Python. Public fields are exposed via getter properties.

```rust
#[pyclass]
pub struct PyIdentity {
    inner: Identity,  // Rust type, not directly accessible from Python
}

#[pymethods]
impl PyIdentity {
    #[getter]
    fn identifier(&self) -> &[u8] { &self.inner.identifier }

    /// `CustodyType` is name-bound, so the getter returns the enumeration and
    /// never a bare string (`09-security-model.md` §9.7.4.2 definitions).
    #[getter]
    fn custody_type(&self) -> CustodyType { self.inner.custody_type }
}
```

### Async bridging

Use synchronous `#[pyfunction]` with `py.allow_threads(|| rt.block_on(...))` to run tokio futures while releasing the Python GIL. PyO3's experimental native async (`#[pyfunction] async fn`) was evaluated but rejected: it holds the GIL during `Future::poll` and does not integrate with the tokio runtime. The deprecated `pyo3_asyncio` crate is not needed.

## Exception Hierarchy

```python
class ScpError(Exception):
    """Base exception for all SCP errors."""
    code: str  # Machine-readable error code (e.g., "SCP-CTX-2001")

class IdentityError(ScpError): ...
class ContextError(ScpError): ...
class UcanPermissionError(ScpError): ...  # UCAN validation failures (named to avoid shadowing builtins.PermissionError)
class CryptoError(ScpError): ...
class TransportError(ScpError): ...
class ToolError(ScpError): ...
class ValidationError(ScpError): ...
```
