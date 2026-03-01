# Python Standards

Python conventions, toolchain, and CI for the SCP Python SDK. References `sdk-common.md` for cross-language invariants and `conventions.md` for git/branch conventions. See `.docs/scaffold/python.md` for package layout, build configuration, PyO3 bridge patterns, and type definitions.

## Toolchain

| Tool | Version | Purpose |
|------|---------|---------|
| Python | 3.12+ | Minimum supported version (for PEP 695 type parameter syntax, `type X` statements, `ParamSpec`). `match` (3.10), `X \| Y` union syntax (3.10) are available but 3.12 is the floor for type parameter syntax. |
| maturin | latest | Build tool for PyO3 Rust extension |
| ruff | latest | Linter + formatter (replaces flake8, isort, black) |
| mypy | latest | Static type checker (`--strict` mode) |
| pytest | latest | Test framework |
| pytest-asyncio | latest | Async test support |

## Code Style

### Async-first

All SDK methods that perform I/O are `async def`. Sync convenience wrappers are separate.

```python
class Context:
    async def send(self, message: str | bytes, identity: Identity | None = None) -> None:
        """Send a message to this context."""
        ...

    def send_sync(self, message: str | bytes, identity: Identity | None = None) -> None:
        """Synchronous convenience wrapper for send()."""
        return run_sync(self.send(message, identity))
```

### Sync wrapper pattern

Uses a dedicated background event loop running in a daemon thread. This is safe to call from any context — plain scripts, Jupyter notebooks, inside async functions, and inside other frameworks' event loops. See ADR-014 acceptance criterion 6.

```python
# scp_sdk/sync.py
import asyncio
import threading
from typing import TypeVar

_T = TypeVar("_T")

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

def run_sync(coro: Coroutine[Any, Any, _T]) -> _T:
    """Run an async coroutine synchronously from any context."""
    loop = _get_sync_loop()
    future = asyncio.run_coroutine_threadsafe(coro, loop)
    return future.result()
```

### Type hints

Full PEP 484 type annotations on every public function, method, and class attribute. Use `from __future__ import annotations` for forward references.

```python
from __future__ import annotations
from dataclasses import dataclass

@dataclass
class Config:
    relay_url: str
    timeout: float = 30.0
    max_retries: int = 3
```

### Dataclasses for configuration

Use `@dataclass` for all value types (messages, tool definitions, events). Not Pydantic — keep dependencies minimal. See `.docs/scaffold/python.md` for canonical dataclass definitions (Message, ToolDefinition, etc.).

### Context managers for resource lifecycle

```python
class Context:
    async def __aenter__(self) -> Context:
        return self

    async def __aexit__(self, *exc: Any) -> None:
        if self.state == "active":
            await self.leave(self._default_identity)
```

### Logging

Use Python `logging` module. Logger name: `scp_sdk`.

```python
import logging

logger = logging.getLogger("scp_sdk")
```

Rust `tracing` output forwards to Python logging via pyo3 log bridge.

### Import order

1. `__future__` imports
2. Standard library
3. Third-party packages
4. Local (`scp_sdk`) modules

Enforced by `ruff` isort rules.

## Testing

### Test framework

pytest with pytest-asyncio. All test files in `tests/`.

Configure pytest-asyncio in `pyproject.toml`:

```toml
[tool.pytest.ini_options]
asyncio_mode = "auto"
```

This avoids needing `@pytest.mark.asyncio` on every async test.

### Fixtures

```python
# tests/conftest.py
import pytest
from scp_sdk import Identity, Context

@pytest.fixture
async def alice():
    return await Identity.create(custody="in_memory")

@pytest.fixture
async def context(alice):
    async with await Context.create(
        creator=alice,
        ceiling=["messaging", "tool_invoke"],
    ) as ctx:
        yield ctx
```

### Test naming

```python
async def test_identity_create_returns_valid_did():
    identity = await Identity.create(custody="in_memory")
    assert identity.did.startswith("did:dht:")

async def test_context_send_requires_active_state():
    ...

async def test_ucan_rejects_replayed_nonce():
    ...
```

Format: `test_{action}_{condition_or_expected_result}`.

### Conformance tests

```python
# tests/conformance/test_conformance.py
import json
from pathlib import Path

FIXTURES = Path(__file__).parent.parent.parent.parent / "tests" / "conformance"

@pytest.mark.parametrize("fixture", load_fixtures(FIXTURES / "identity.json"))
async def test_conformance(fixture):
    result = await run_operation(fixture["operation"], fixture["input"])
    assert_matches(result, fixture["expected"])
```

## CI Commands

```bash
# Format check
ruff format --check bindings/python/

# Lint
ruff check bindings/python/

# Type check
mypy bindings/python/scp_sdk/ --strict

# Build extension (dev mode)
maturin develop --release

# Run tests
pytest bindings/python/tests/ -v

# Run async tests
pytest bindings/python/tests/ -v --asyncio-mode=auto

# Build wheel
maturin build --release

# Build wheels for all platforms (CI)
maturin build --release --target x86_64-unknown-linux-gnu
maturin build --release --target aarch64-unknown-linux-gnu
maturin build --release --target x86_64-apple-darwin
maturin build --release --target aarch64-apple-darwin
maturin build --release --target x86_64-pc-windows-msvc
```

## CI Matrix

| Job | Runs on | Python versions | Trigger |
|-----|---------|-----------------|---------|
| ruff (lint+format) | ubuntu-latest | 3.12 | Every PR |
| mypy | ubuntu-latest | 3.12 | Every PR |
| pip-audit | ubuntu-latest | 3.12 | Every PR |
| test | ubuntu-latest, macos-latest | 3.12, 3.13 | Every PR |
| build-wheel | ubuntu-latest, macos-latest, windows-latest | 3.12+ | Every PR |
| conformance | ubuntu-latest | 3.12 | Every PR |
| publish (PyPI) | ubuntu-latest | 3.12 | Tagged release |

## Platform Wheels

maturin builds binary wheels with the Rust extension embedded. Users install with `pip install scp-sdk` — no Rust toolchain required.

| Platform | Architecture | Wheel tag |
|----------|-------------|-----------|
| Linux | x86_64 | manylinux2014_x86_64 |
| Linux | aarch64 | manylinux2014_aarch64 |
| macOS | universal2 | macosx_11_0_universal2 |
| Windows | x86_64 | win_amd64 |
