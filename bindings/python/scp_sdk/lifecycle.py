"""Bridge lifecycle controls for the SCP Python SDK.

Exposes :func:`suspend` and :func:`resume` which disconnect the bridge
from its relay (preserving context state) and clear the suspended flag,
respectively.  Use when backgrounding a mobile/desktop app, then call
:func:`resume` plus :func:`scp_sdk.connect_relay` to rejoin.

Both functions delegate to the ``_scp_core`` PyO3 bridge layer
(`scp_suspend`, `scp_resume`).  They are no-ops when the bridge has
not been initialized.
"""

from __future__ import annotations

from typing import Any

from scp_sdk._deprecation import deprecated_default_instance
from scp_sdk.errors import ContextError, ScpError, TransportError


def _bridge() -> Any:
    """Return the ``_scp_core`` extension module, imported lazily."""
    try:
        import _scp_core  # type: ignore[import-not-found]

        return _scp_core
    except ImportError as exc:
        raise ScpError(
            "The _scp_core extension module is not installed. "
            "Install scp-python with: pip install scp-python",
            code="SCP-UNKNOWN-0001",
        ) from exc


@deprecated_default_instance
def suspend() -> None:
    """Suspend the bridge instance for backgrounding.

    Disconnects the transport (clearing the relay connection) and marks
    the instance as suspended.  Context state is preserved — the
    instance remains alive but inactive.  Transport-dependent operations
    will fail until :func:`resume` is called.

    After suspension, callers should call :func:`resume` to re-activate
    and then re-establish the relay connection via
    :func:`scp_sdk.connect_relay`.

    No-op if the bridge is already shut down or has not been
    initialized.

    Raises:
        TransportError: If transport cleanup fails.
    """
    bridge = _bridge()
    try:
        bridge.scp_suspend()
    except Exception as exc:  # PyO3 raises ScpTransportError
        raise TransportError(
            f"suspend failed: {exc}",
            code="SCP-TRANS-5001",
        ) from exc


@deprecated_default_instance
def resume() -> None:
    """Resume a suspended bridge instance.

    Clears the suspended flag so bridge operations can proceed.  The
    caller must re-establish the relay connection via
    :func:`scp_sdk.connect_relay` — resume does not reconnect
    automatically.

    No-op if the bridge is not initialized.

    Raises:
        ContextError: If the bridge has been permanently shut down
            (``shutdown_runtime`` was already called).
    """
    bridge = _bridge()
    try:
        bridge.scp_resume()
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
