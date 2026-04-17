"""Tests for the bridge lifecycle controls (suspend / resume).

Exercises scp_sdk.suspend() and scp_sdk.resume() against the PyO3 FFI
layer.  Each test verifies:

1. suspend before any bridge init is a no-op.
2. resume before any bridge init is a no-op.
3. suspend after Identity.create() (which initializes the bridge) succeeds.
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

from scp_sdk import resume, suspend


def test_suspend_before_init_is_noop() -> None:
    """suspend() with no prior bridge init must succeed (no-op branch).

    BRIDGE_INSTANCE is a process-wide OnceLock — another test in the
    same session may have already initialized the bridge — but suspend
    must succeed in both states.
    """
    suspend()


def test_resume_before_init_is_noop() -> None:
    """resume() with no prior bridge init must succeed (no-op branch)."""
    resume()


def test_suspend_and_resume_roundtrip_after_init() -> None:
    """suspend / resume after an Identity.create succeed roundtrip.

    Identity.create triggers ensure_bridge_instance inside the PyO3
    bridge, so this exercises the "real BridgeInstance" code path
    rather than the None-fallback.
    """
    from scp_sdk.identity import Identity
    from scp_sdk.types import CustodyType

    _identity = Identity.create(custody=CustodyType.IN_MEMORY)
    suspend()
    resume()


def test_multiple_suspend_resume_cycles_are_idempotent() -> None:
    """Multiple suspend/resume cycles are safe; neither raises."""
    from scp_sdk.identity import Identity
    from scp_sdk.types import CustodyType

    _identity = Identity.create(custody=CustodyType.IN_MEMORY)
    suspend()
    suspend()
    resume()
    resume()
