"""Root conftest for SCP Python SDK tests.

Provides the ``scp`` fixture: a fresh :class:`scp_sdk.SCP` wrapper per
test, each owning an independent native bridge instance. This replaces
the per-test reliance on the process-wide ``_scp_core.SCP.default_instance()``
that was removed in Phase 4 PR 4 (#1549, ADR-048) — every test now
threads an explicit instance through the SDK surface.

Tests that exercise raw bridge methods access ``scp._native`` (the
``_scp_core.SCP`` handle) directly.
"""

from __future__ import annotations

from collections.abc import Iterator

import pytest


def extension_is_absent(exc: BaseException) -> bool:
    """Report whether one exception means the native extension is not installed.

    CRITERION: the exception is the :class:`scp_sdk.errors.ScpError` carrying
    ``SCP-UNKNOWN-0001``. :func:`scp_sdk._extension.native_module` raises that
    code for exactly one cause — no compiled extension file is present, which
    :func:`scp_sdk._extension.extension_is_installed` decides by looking for
    the file without executing it, on the import path and in the ``scp_sdk``
    package directory alike. The second look is what sees a module another
    interpreter built, whose filename carries that interpreter's tag and so
    matches none of this one's ``importlib.machinery.EXTENSION_SUFFIXES``.

    A *present* extension that fails to load raises ``SCP-UNKNOWN-0002``
    instead, and so does an extension that loads without exporting the ``SCP``
    class (``scp_sdk.scp._native_cls``). The exception type cannot make that
    separation, because Python raises ``ImportError`` for an absent module and
    for a ``dlopen`` failure alike — an undefined symbol, a libpython the
    module was not built against, a missing transitive shared library. The
    code carries it.

    Every other construction failure — a panic in bridge initialisation, a
    storage backend that refuses to open — raises a different type or carries a
    different code, and the fixture below re-raises it. Skipping on any of
    those would let a CI job that downloaded a broken extension exit 0 over
    zero executed assertions.
    """
    from scp_sdk.errors import ScpError

    return isinstance(exc, ScpError) and exc.code == "SCP-UNKNOWN-0001"


@pytest.fixture
def scp() -> Iterator:
    """Fresh ``scp_sdk.SCP`` wrapper per test.

    Yields an SDK-level :class:`scp_sdk.SCP` instance. Each test receives
    its own bridge instance, fully isolated from every other test's state
    (no shared context manager, transport, or registry). The underlying
    :class:`_scp_core.SCP` handle is reachable via ``scp._native`` for
    tests that poke directly at the raw bridge API.

    The fixture is function-scoped so no state leaks across tests. The
    native instance is shut down on teardown with a 5-second deadline —
    matching :meth:`scp_sdk.SCP.__exit__` — so tokio-side resources are
    released deterministically.
    """
    # Skip entire fixture if native extension is unavailable. Tests that
    # use only pure-Python paths (e.g. test_types.py) don't depend on the
    # fixture and remain unaffected.
    #
    # Only an ``ImportError`` skips here. ``scp_sdk/__init__.py`` raises
    # ``SCP-UNKNOWN-0002`` — an ``ScpError``, not an ``ImportError`` — when the
    # extension file is present and fails to load, so that cause propagates out
    # of this fixture and fails the test instead of skipping it.
    try:
        from scp_sdk import SCP
    except ImportError:
        pytest.skip("scp_sdk not importable — run maturin develop first")

    try:
        instance = SCP(storage={"type": "in_memory"})
    except Exception as exc:
        if not extension_is_absent(exc):
            raise
        pytest.skip(f"native _scp_core extension not installed: {exc}")

    try:
        yield instance
    finally:
        # `SCP.__exit__` is the shutdown path a synchronous caller uses, and this
        # teardown is synchronous, so it calls `__exit__`. `SCP.shutdown` is a
        # coroutine function: calling it here would build a coroutine that nothing
        # runs, the native instance would stay alive for the rest of the pytest
        # process, and CPython would print `RuntimeWarning: coroutine
        # 'SCP.shutdown' was never awaited` when it collected that coroutine.
        # `__exit__` passes the same 5-second deadline to `_native.shutdown`, and a
        # second native shutdown is a documented no-op that
        # `tests/test_scp_class.py::test_shutdown_is_idempotent` asserts, so a test
        # that shut its own instance down does not fail here. An error this call
        # raises fails the test rather than being swallowed: a shutdown that cannot
        # complete is a defect this suite exists to surface.
        instance.__exit__(None, None, None)
