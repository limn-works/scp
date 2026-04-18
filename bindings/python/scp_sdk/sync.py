"""Synchronous helper for running async coroutines from any context.

Provides :func:`run_sync`, which submits a coroutine to a dedicated
background event loop running in a daemon thread.  This is safe to call
from plain scripts, Jupyter notebooks, inside async functions, and inside
other frameworks' event loops -- it never calls :func:`asyncio.run`
(which fails inside running loops) and never calls ``block_on`` (which
panics inside tokio).

The background loop is created lazily on first call and runs in a daemon
thread that dies with the process.  Thread safety is ensured via
:func:`asyncio.run_coroutine_threadsafe`, the asyncio-blessed mechanism
for cross-thread coroutine submission.

See ``.docs/adrs/phase-3.md`` ADR-014 acceptance criterion 6 for the
canonical design.
"""

from __future__ import annotations

import asyncio
import threading
from collections.abc import Coroutine
from typing import Any, TypeVar

from scp_sdk._deprecation import deprecated_default_instance

_T = TypeVar("_T")

_sync_loop: asyncio.AbstractEventLoop | None = None
_sync_loop_lock = threading.Lock()


def _get_sync_loop() -> asyncio.AbstractEventLoop:
    """Return the shared background event loop, creating it if necessary.

    Uses double-checked locking to avoid creating multiple loops under
    contention while keeping the fast path lock-free.
    """
    global _sync_loop
    if _sync_loop is None or _sync_loop.is_closed():
        with _sync_loop_lock:
            if _sync_loop is None or _sync_loop.is_closed():
                _sync_loop = asyncio.new_event_loop()
                t = threading.Thread(target=_sync_loop.run_forever, daemon=True)
                t.start()
    return _sync_loop


def run_sync(coro: Coroutine[Any, Any, _T]) -> _T:
    """Run an async coroutine synchronously.

    Submits *coro* to a dedicated background event loop and blocks the
    calling thread until the result is available.

    Safe to call from any context:

    - From a non-async context (scripts, REPL): works normally.
    - From an async context (Jupyter, nested frameworks): uses the
      background loop via :func:`asyncio.run_coroutine_threadsafe`,
      avoiding deadlock.

    Args:
        coro: An awaitable coroutine to execute.

    Returns:
        The coroutine's return value.

    Raises:
        Exception: Any exception raised by the coroutine is re-raised
            in the calling thread.
    """
    loop = _get_sync_loop()
    future = asyncio.run_coroutine_threadsafe(coro, loop)
    return future.result()


# ---------------------------------------------------------------------------
# Sync/offline operations (ADR-029)
# ---------------------------------------------------------------------------


def _bridge() -> Any:
    """Return the ``_scp_core`` extension module, imported lazily."""
    try:
        import _scp_core  # type: ignore[import-not-found]

        return _scp_core
    except ImportError as exc:
        from scp_sdk.errors import ScpError

        raise ScpError(
            "The _scp_core extension module is not installed. "
            "Install scp-python with: pip install scp-python",
            code="SCP-UNKNOWN-0001",
        ) from exc


@deprecated_default_instance
def classify_offline(last_relay_contact: int, now: int) -> str:
    """Classify an offline duration into the appropriate recovery tier.

    Uses the default sync policy thresholds:

    - Tier 1 (Short): < 4 hours.
    - Tier 2 (Extended): 4 hours to 7 days.
    - Tier 3 (Long): > 7 days.

    Args:
        last_relay_contact: Unix timestamp (seconds) of last relay contact.
        now: Current Unix timestamp (seconds).

    Returns:
        ``"short"``, ``"extended"``, or ``"long"``.
    """
    bridge = _bridge()
    return bridge.sync_classify_offline(last_relay_contact, now)


@deprecated_default_instance
def get_policy() -> dict[str, Any]:
    """Return the default sync policy parameters.

    Returns:
        A dict with ``tier_1_threshold_secs``, ``tier_2_threshold_secs``,
        ``gap_timeout_secs``, ``reorder_buffer_capacity``,
        ``max_sequential_commits``, ``commit_process_timeout_secs``,
        ``sender_key_timeout_secs``, ``reconnection_dedup_window_secs``.
    """
    bridge = _bridge()
    return dict(bridge.sync_get_policy())


__all__ = [
    "classify_offline",
    "get_policy",
    "run_sync",
]
