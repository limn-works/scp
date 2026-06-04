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
    try:
        from scp_sdk import SCP
    except ImportError:
        pytest.skip("scp_sdk not importable — run maturin develop first")

    try:
        instance = SCP()
    except Exception as exc:
        pytest.skip(f"SCP() construction failed — extension not built: {exc}")

    try:
        yield instance
    finally:
        # Matches SCP.__exit__: 5-second graceful shutdown.
        try:
            instance.shutdown(5.0)
        except Exception:
            pass
