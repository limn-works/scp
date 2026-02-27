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
from typing import Any, Coroutine, TypeVar

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


__all__ = [
    "run_sync",
]
