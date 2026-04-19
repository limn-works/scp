"""Tests for the bridge lifecycle controls (suspend / resume).

Exercises scp_sdk.suspend() and scp_sdk.resume() against the PyO3 FFI
layer.  Each test verifies:

1. suspend before any context work is a no-op (fresh instance).
2. resume before any context work is a no-op (fresh instance).
3. suspend after Identity.create() (which exercises bridge state) succeeds.
4. resume after suspend succeeds.

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

from scp_sdk import SCP, resume, suspend


def test_suspend_before_init_is_noop(scp: SCP) -> None:
    """suspend() on a fresh instance must succeed (no context state)."""
    suspend(scp)


@pytest.mark.asyncio
async def test_resume_before_init_is_noop(scp: SCP) -> None:
    """resume() on a fresh (not-suspended) instance must succeed."""
    await resume(scp)


@pytest.mark.asyncio
async def test_suspend_and_resume_roundtrip_after_init(scp: SCP) -> None:
    """suspend / resume after an Identity.create succeed roundtrip.

    Identity.create exercises the bridge's ContextManager, so this
    triggers the "real BridgeInstance" code path rather than an
    entirely-inert instance.
    """
    from scp_sdk.identity import Identity
    from scp_sdk.types import CustodyType

    _identity = await Identity.create(scp, custody=CustodyType.IN_MEMORY)
    suspend(scp)
    await resume(scp)


@pytest.mark.asyncio
async def test_multiple_suspend_resume_cycles_are_idempotent(scp: SCP) -> None:
    """Multiple suspend/resume cycles are safe; neither raises."""
    from scp_sdk.identity import Identity
    from scp_sdk.types import CustodyType

    _identity = await Identity.create(scp, custody=CustodyType.IN_MEMORY)
    suspend(scp)
    suspend(scp)
    await resume(scp)
    await resume(scp)
