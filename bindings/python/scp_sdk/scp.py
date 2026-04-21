"""SDK-level :class:`SCP` entry point for the Python SDK.

See ADR-048 ("SCP multi-instance bridge + check-handle-affinity gate")
for the design rationale. The :class:`SCP` class is the only public way
to build against the SCP protocol from Python — each :class:`SCP`
instance owns an independent ``BridgeInstance`` (registries, transport,
context manager), so tests, multi-identity apps, and per-tenant services
can hold distinct instances without sharing state.

The free-function façade that used to delegate to a process-global
default instance was removed in Phase 4 PR 4 (#1549). Every SDK
function now requires an explicit :class:`SCP` argument.

Example usage::

    from scp_sdk import SCP

    # Construct a fresh instance with in-memory state.
    with SCP() as scp:
        # scp.instance_id is a monotonic u64 unique per process.
        ...

    # Explicit in-memory storage config.
    scp = SCP(storage={"type": "in_memory"})
    scp.shutdown(timeout=5.0)

    # SQLCipher-encrypted on-disk storage (Phase 4 PR 3, #1549).
    scp = SCP(storage={
        "type": "sqlite",
        "path": "/var/lib/my-app",
        "key": b"\\x00" * 32,
    })

    # `resume` is async — it awaits transport reconnect (#1678).
    scp.suspend()
    await scp.resume()
"""

from __future__ import annotations

import asyncio
import math
from types import TracebackType
from typing import Any

from scp_sdk.errors import ScpError

__all__ = ["SCP"]


def _native_cls() -> Any:
    """Return the PyO3-native ``SCP`` class from the ``_scp_core`` extension.

    Raised at call time (not import time) so that pure-Python environments
    — where the native extension isn't available — can still ``import
    scp_sdk`` without an ImportError. The caller sees a meaningful
    :class:`ScpError` the first time they actually construct an instance.
    """
    try:
        import _scp_core  # type: ignore[import-not-found]
    except ImportError as exc:
        raise ScpError(
            "The _scp_core extension module is not installed. "
            "Install scp-python with: pip install scp-python",
            code="SCP-UNKNOWN-0001",
        ) from exc
    cls = getattr(_scp_core, "SCP", None)
    if cls is None:
        raise ScpError(
            "_scp_core does not export the SCP class — rebuild the native "
            "extension with `maturin develop --release` from the Phase 4 "
            "PR 1 codebase.",
            code="SCP-UNKNOWN-0001",
        )
    return cls


class SCP:
    """Caller-owned SCP instance — the sole public SDK entry point.

    Each :class:`SCP` wraps an independent native ``BridgeInstance`` (with
    its own registries, transport state, and context manager). The wrapper
    exposes lifecycle controls (:meth:`suspend`, :meth:`resume`,
    :meth:`shutdown`) plus the monotonic :attr:`instance_id` used by the
    FFI handle-affinity check.

    Phase 4 PR 4 (#1549, ADR-048) removed the process-global default
    instance and the free-function façade that delegated to it. Every
    caller now owns an explicit :class:`SCP` — pass it positionally to
    :meth:`Identity.create`, :meth:`Context.create`, and every other
    SDK entry point.

    :class:`SCP` is a context manager: ``with SCP() as scp: ...`` calls
    :meth:`shutdown` with a 5-second timeout on exit.
    """

    # The native PyO3 SCP handle. `frozen=True` on the Rust side guarantees
    # we never mutate it from Python; all state mutation is through the
    # interior atomics/mutexes on `PyBridgeInstance`.
    _native: Any

    def __init__(
        self,
        *,
        storage: dict[str, Any] | None = None,
    ) -> None:
        """Construct a fresh :class:`SCP` instance.

        :param storage: Optional storage configuration dict. Accepted shapes:

            * ``{"type": "in_memory"}`` — ephemeral encrypted in-memory
              storage (the default when ``storage`` is ``None``).
            * ``{"type": "sqlite", "path": str, "key": bytes}`` —
              SQLCipher-encrypted on-disk storage at ``{path}/scp.db``.
              ``key`` is the raw encryption key material (32 bytes
              recommended) and is zeroized on the Rust side once the
              database is opened. Landed in Phase 4 PR 3 (#1549).

            When ``None``, defaults to in-memory storage.
        :raises ValidationError: If ``storage`` contains an unknown
            ``type`` or is missing required fields for the selected
            variant.

        .. note::

           A standalone ``persistence`` parameter (injecting a custom
           :class:`ContextPersistence` impl across the FFI boundary)
           remains unexposed at the SDK surface. The SQLite storage
           variant above automatically constructs a real
           :class:`ContextPersistence` internally — opt in via the
           ``storage`` dict. A Python-accessible custom persistence
           trait is deferred; no tracking issue is open because SQLite
           covers the documented use cases.
        """
        cls = _native_cls()
        if storage is not None:
            self._native = cls.with_storage(storage)
        else:
            self._native = cls()

    @property
    def instance_id(self) -> int:
        """Monotonic u64 identifier for this bridge instance.

        Unique per process. Used by the FFI handle-affinity check — every
        handle minted by this instance stores this id, and FFI entry
        points reject handles whose id does not match the receiving
        instance's id.
        """
        return int(self._native.instance_id)

    def suspend(self) -> None:
        """Suspend the bridge for mobile/desktop backgrounding.

        Disconnects the transport (clears the relay connection) and marks
        the instance as suspended. Context state is preserved;
        transport-dependent operations will fail until :meth:`resume` is
        called.

        :raises TransportError: If transport cleanup fails
            (code ``SCP-TRANS-5001``).
        """
        # Lazy import avoids circular dep (errors -> scp -> errors).
        from scp_sdk.errors import TransportError

        try:
            self._native.suspend()
        except Exception as exc:  # PyO3 raises ScpTransportError
            raise TransportError(
                f"suspend failed: {exc}",
                code="SCP-TRANS-5001",
            ) from exc

    async def resume(self) -> None:
        """Resume a suspended bridge instance.

        Clears the suspended flag and — as of Phase 4 PR 3 (#1678) —
        automatically reconnects the transport to every relay URL the
        instance was subscribed to at suspend time. Callers no longer
        need to re-invoke :func:`scp_sdk.connect_relay` manually; the
        FFI layer replays the pending-URL list internally.

        This is an ``async`` coroutine because the underlying PyO3
        ``resume`` performs async work (transport reconnect, persisted
        context restoration) behind a blocking ``block_on`` at the FFI
        boundary. We wrap the blocking call in :func:`asyncio.to_thread`
        so the Python event loop remains responsive while the reconnect
        round-trips complete. Matches the async ``resume`` surface on
        the NAPI and UniFFI bridges (see #1549 PR 3 — commit
        ``refactor(ffi): make resume() async across bridge core + scp
        handles``).

        :raises ContextError: If the instance has been permanently shut
            down (code ``SCP-CTX-2000``).
        """
        # Lazy import avoids circular dep (errors -> scp -> errors).
        from scp_sdk.errors import ContextError

        try:
            await asyncio.to_thread(self._native.resume)
        except Exception as exc:  # PyO3 raises ScpContextError
            raise ContextError(
                f"resume failed: {exc}",
                code="SCP-CTX-2000",
            ) from exc

    def shutdown(self, timeout: float = 5.0) -> None:
        """Shut down this instance with a graceful deadline.

        Drains in-flight tasks within ``timeout`` seconds, aborts any
        stragglers, then runs typed-field cleanup. A second call is a
        no-op (the underlying :class:`ShutdownError::AlreadyShutDown` is
        swallowed at the SDK surface).

        ``timeout`` is clamped defensively: ``NaN`` and negative values
        map to ``0`` (abort immediately); ``math.inf`` or values that
        would overflow ``u64`` milliseconds map to ``0xFFFFFFFF_FFFFFFFF``
        (effectively unbounded). Finite in-range values are rounded to
        the nearest millisecond (``round()`` rather than ``int()``
        truncation — we were dropping up to 0.999 ms of caller budget
        per call before the round 2 review).

        :param timeout: Maximum seconds to wait for in-flight tasks
            (float — fractional seconds are preserved to millisecond
            resolution before crossing the FFI boundary).
        :raises ContextError: If the tokio runtime is unavailable.
        """
        # u64::MAX milliseconds — matches the Rust-side PyO3 bridge type.
        u64_max = 0xFFFFFFFF_FFFFFFFF
        # Order matters: isinf(+) must be caught BEFORE !isfinite, otherwise
        # math.inf collapses to the NaN/negative abort branch. NaN is not
        # orderable, so explicitly testing isfinite()==False is the only
        # reliable way to trap it.
        if math.isinf(timeout) and timeout > 0:
            millis = u64_max
        elif not math.isfinite(timeout) or timeout <= 0:
            # NaN, negative, negative-infinity, or zero → immediate abort.
            millis = 0
        elif timeout * 1000 > u64_max:
            millis = u64_max
        else:
            millis = round(timeout * 1000)
        self._native.shutdown(millis)

    def __enter__(self) -> SCP:
        """Enter the context-manager scope — returns ``self``."""
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        """Shut down on scope exit using the default 5-second timeout."""
        self.shutdown()

    def __repr__(self) -> str:
        """Developer-facing repr including the native ``instance_id``."""
        return f"SCP(instance_id={self.instance_id})"
