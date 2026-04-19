"""Bridge lifecycle controls for the SCP Python SDK.

Exposes :func:`suspend` and :func:`resume` which disconnect the bridge
from its relay (preserving context state) and clear the suspended flag,
respectively.  Use when backgrounding a mobile/desktop app, then call
:func:`resume` plus :func:`scp_sdk.connect_relay` to rejoin.

Both functions delegate to methods on an explicit :class:`scp_sdk.SCP`
instance (``suspend`` / ``resume``). After #1549 Phase 4 PR 4 the
default-instance façade is gone — callers thread an explicit
:class:`scp_sdk.SCP` through every operation.
"""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING

from scp_sdk.errors import ContextError, TransportError

if TYPE_CHECKING:
    from scp_sdk.scp import SCP


def suspend(scp: SCP) -> None:
    """Suspend the given bridge instance for backgrounding.

    Disconnects the transport (clearing the relay connection) and marks
    the instance as suspended.  Context state is preserved — the
    instance remains alive but inactive.  Transport-dependent operations
    will fail until :func:`resume` is called.

    After suspension, callers should call :func:`resume` to re-activate
    and then re-establish the relay connection via
    :func:`scp_sdk.connect_relay`.

    Args:
        scp: The :class:`scp_sdk.SCP` instance to suspend.

    Raises:
        TransportError: If transport cleanup fails.
    """
    try:
        scp._native.suspend()
    except Exception as exc:  # PyO3 raises ScpTransportError
        raise TransportError(
            f"suspend failed: {exc}",
            code="SCP-TRANS-5001",
        ) from exc


async def resume(scp: SCP) -> None:
    """Resume a suspended bridge instance.

    Clears the suspended flag so bridge operations can proceed.  As of
    Phase 4 PR 3 (#1678) the bridge also reconnects the transport to
    every relay URL the instance was subscribed to at suspend time —
    callers no longer need to re-invoke :func:`scp_sdk.connect_relay`
    manually.

    Delegates to the SDK wrapper's :meth:`SCP.resume` which already runs
    the blocking FFI call in :func:`asyncio.to_thread`.

    Args:
        scp: The :class:`scp_sdk.SCP` instance to resume.

    Raises:
        ContextError: If the bridge has been permanently shut down
            (``shutdown_runtime`` was already called).
    """
    try:
        await asyncio.to_thread(scp._native.resume)
    except Exception as exc:  # PyO3 raises ScpContextError
        # The PyO3 bridge emits SCP-CTX-2000 for resume failures (matching
        # the NAPI and UniFFI bridges — see `scp-ffi/src/lib.rs::scp_resume`).
        # Keeping the code hardcoded here makes the SDK contract explicit
        # even when running against an older bridge where the PyO3
        # constructor used the CTX_2001 default.
        raise ContextError(
            f"resume failed: {exc}",
            code="SCP-CTX-2000",
        ) from exc
