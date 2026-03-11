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
    identity.py                 # Identity class, DIDDocument
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
requires-python = ">=3.12"
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
features = ["pyo3/extension-module"]

[tool.ruff]
target-version = "py312"
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
python_version = "3.12"
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

Bridge functions in Rust use `py_` prefix:

```rust
#[pyfunction]
fn py_identity_create<'py>(py: Python<'py>, custody: &str) -> PyResult<Bound<'py, PyAny>> { ... }
```

Python wrappers call these without the prefix:

```python
from scp_sdk._scp_core import py_identity_create

class Identity:
    @classmethod
    async def create(cls, custody: str = "platform") -> Identity:
        raw = await py_identity_create(custody)
        return cls(raw)
```

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
    fn did(&self) -> &str { &self.inner.did }

    #[getter]
    fn custody_type(&self) -> &str { self.inner.custody_type.as_str() }
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
