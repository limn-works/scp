"""Tests for the bridge lifecycle controls (SCP.suspend / SCP.resume).

Exercises :meth:`scp_sdk.SCP.suspend` and :meth:`scp_sdk.SCP.resume`
against the PyO3 FFI layer.  Each test verifies:

1. suspend before any context work is a no-op (fresh instance).
2. resume before any context work is a no-op (fresh instance).
3. suspend after Identity.create() (which exercises bridge state) succeeds.
4. resume after suspend succeeds.

Phase 4 PR 4 (#1549) deleted the free-function ``suspend(scp)`` /
``resume(scp)`` delegates; the class methods are now the only entry
point (one happy path — CLAUDE.md architecture tenet).

Requires the native _scp_core extension built via maturin.
"""

from __future__ import annotations

import pytest

try:
    from scp_sdk import _scp_core  # noqa: F401 — confirms native module is available
except (ImportError, AttributeError):
    pytest.skip(
        "Native _scp_core extension not available — run maturin develop first",
        allow_module_level=True,
    )

from scp_sdk import SCP

from .harness_custody import create_in_memory_identity


def test_suspend_before_init_is_noop(scp: SCP) -> None:
    """suspend() on a fresh instance must succeed (no context state)."""
    scp.suspend()


@pytest.mark.asyncio
async def test_resume_before_init_is_noop(scp: SCP) -> None:
    """resume() on a fresh (not-suspended) instance must succeed."""
    await scp.resume()


@pytest.mark.asyncio
async def test_suspend_and_resume_roundtrip_after_init(scp: SCP) -> None:
    """suspend / resume after an Identity.create succeed roundtrip.

    Identity.create exercises the bridge's ContextManager, so this
    triggers the "real BridgeInstance" code path rather than an
    entirely-inert instance.
    """

    _identity = await create_in_memory_identity(scp)
    scp.suspend()
    await scp.resume()


@pytest.mark.asyncio
async def test_multiple_suspend_resume_cycles_are_idempotent(scp: SCP) -> None:
    """Multiple suspend/resume cycles are safe; neither raises."""

    _identity = await create_in_memory_identity(scp)
    scp.suspend()
    scp.suspend()
    await scp.resume()
    await scp.resume()
