# Python Standards

Python conventions, toolchain, and CI for the SCP Python SDK. References `sdk-common.md` for cross-language invariants and `conventions.md` for git/branch conventions. See `.docs/scaffold/python.md` for package layout, build configuration, PyO3 bridge patterns, and type definitions.

## Toolchain

| Tool | Version | Purpose |
|------|---------|---------|
| Python | 3.10-3.13 | Supported range, as ADR phase-3 and `requires-python = ">=3.10,<3.14"` in `bindings/python/pyproject.toml` set it; wheels ship for CPython 3.10-3.13, and §Platform Wheels says why 3.14 cannot install. `match`, `X \| Y` union syntax and `ParamSpec` (3.10) are available. PEP 695 type parameter syntax and `type X` statements (3.12) are not: write a type alias as `X: TypeAlias = ...`. Ruff's `target-version = "py310"` rejects the newer syntax, and CI job `python-wheel-build` imports every `scp_sdk` module under CPython 3.10, which rejects such syntax in any module. |
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

### Generated PyO3 type stub (`_scp_core.pyi`)

The extension-module stub `bindings/python/scp_sdk/_scp_core.pyi` is the type-checker's and IDE's view of the `_scp_core` PyO3 bridge. Its function/method **parameter lists are generated**, not hand-maintained: PyO3 binds positional parameters by declaration order (absent an explicit `#[pyo3(signature = ...)]`), so the Rust `#[pyfunction]` / `#[pymethods]` signatures are the single source of truth for the Python-visible keyword surface. A hand-edited stub drifts silently — mypy/pyright trust the stub itself, so a transposed or missing parameter is invisible.

`scripts/generate-pyi.py` reads the authoritative Rust signatures (via tree-sitter) and rewrites each stub signature's positional parameter **names, order, and arity** to match, carrying each parameter's hand-authored annotation and default by name (a transposition auto-heals; a pure rename keeps its type via positional fallback). Prose — docstrings, section comments, value classes, property blocks — is preserved verbatim. It also asserts **set parity**: every export has a stub and every stubbed symbol is a real export.

**Mechanism preventing drift:** `scripts/check-pyi-generated.sh` runs the generator in `--check` mode in CI (job `pyi-generated`) and fails on any name / order / arity mismatch or missing/extra symbol. Its `--self-test` mode plants a deliberately-transposed parameter and proves the gate rejects it. Both the committed stub and the regenerated candidate pass through the same `ruff format`, so the comparison is formatting-stable — only a genuine signature difference produces a diff. To change a signature: edit the Rust export, run `python3.12 scripts/generate-pyi.py`, and commit the regenerated stub. Never hand-edit the parameter lists.

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
        ceiling=["messaging", "outlet_call"],
    ) as ctx:
        yield ctx
```

### Test naming

```python
async def test_identity_create_returns_a_32_byte_identifier(alice):
    assert len(alice.identifier) == 32  # 09-security-model.md §9.7.4.2 R13

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

# Build extension (dev mode), from the directory whose pyproject.toml holds [tool.maturin]
(cd bindings/python && maturin develop --release)

# Run tests
pytest bindings/python/tests/ -v

# Run async tests
pytest bindings/python/tests/ -v --asyncio-mode=auto

# Build wheel, from the same directory
(cd bindings/python && maturin build --release)

# Build wheels for all platforms (CI: job python-wheels in .github/workflows/build-matrix.yml,
# from bindings/python; Linux legs run in the manylinux_2_28 container)
(cd bindings/python && maturin build --release --target x86_64-unknown-linux-gnu -i python3.10 python3.11 python3.12 python3.13)
(cd bindings/python && maturin build --release --target aarch64-unknown-linux-gnu -i python3.10 python3.11 python3.12 python3.13)
(cd bindings/python && maturin build --release --target universal2-apple-darwin -i python3.10 python3.11 python3.12 python3.13)
(cd bindings/python && maturin build --release --target x86_64-pc-windows-msvc -i python3.10 python3.11 python3.12 python3.13)
```

## CI Matrix

| Job | Runs on | Python versions | Trigger |
|-----|---------|-----------------|---------|
| ruff (lint+format) | ubuntu-latest | 3.12 | Every PR |
| mypy | ubuntu-latest | 3.12 | Every PR |
| pyi-generated (`.pyi` ↔ PyO3 signature parity) | ubuntu-latest | 3.12 | Every PR |
| pip-audit | ubuntu-latest | 3.12 | Every PR |
| test | ubuntu-latest, macos-latest | 3.12, 3.13 | Every PR |
| python-wheel-build (debug wheel, installed and imported) | ubuntu-latest | 3.10, 3.12 | Every PR |
| python-wheels (release wheels) | ubuntu-latest, macos-latest, windows-latest | 3.10, 3.11, 3.12, 3.13 | Tagged release |
| conformance | ubuntu-latest | 3.12 | Every PR |
| publish (PyPI) | ubuntu-latest | 3.12 | Tagged release |

## Platform Wheels

maturin builds binary wheels with the Rust extension embedded. Users on a platform and CPython minor a wheel covers (CPython 3.10-3.13 on Linux x86_64 and aarch64 with glibc 2.28 or newer, macOS 11 or newer, and Windows x86_64) install with `pip install scp-python` — no Rust toolchain required. On any other platform with CPython 3.10-3.13, pip builds the sdist, which compiles OpenSSL and needs a Rust toolchain and a full perl, plus make on Linux and macOS. CPython 3.14 and newer cannot install: the locked PyO3 0.24 builds for CPython 3.13 at most. `requires-python = ">=3.10,<3.14"` makes pip on 3.14 skip every release built from this pyproject. scp-python 0.1.0b2 and 0.1.0b3, which PyPI already serves, declare `>=3.10` with no ceiling, so while neither is yanked pip on 3.14 falls back to the 0.1.0b3 sdist, and that build fails in PyO3 0.24.

| Platform | Architecture | Wheel tag |
|----------|-------------|-----------|
| Linux | x86_64 | manylinux_2_28_x86_64 |
| Linux | aarch64 | manylinux_2_28_aarch64 |
| macOS | universal2 | macosx_11_0_universal2 |
| Windows | x86_64 | win_amd64 |
