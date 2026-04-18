"""SDK-level :class:`SCP` entry point for the Python SDK.

See ADR-048 ("SCP multi-instance bridge + check-handle-affinity gate")
for the design rationale. The :class:`SCP` class is the preferred way to
build against the SCP protocol from Python — each :class:`SCP` instance
owns an independent ``BridgeInstance`` (registries, transport, context
manager), so tests, multi-identity apps, and per-tenant services can hold
distinct instances without sharing state.

The free-function façade (``scp_sdk.identity_create(...)``,
``scp_sdk.context_create(...)``, etc.) is deprecated and delegates to a
shared process-global default instance. See :mod:`scp_sdk._deprecation`.

Example usage::

    from scp_sdk import SCP

    # Construct a fresh instance with in-memory state.
    with SCP() as scp:
        # scp.instance_id is a monotonic u64 unique per process.
        ...

    # Explicit storage config.
    scp = SCP(storage={"type": "in_memory"})
    scp.shutdown(timeout=5.0)

    # Shared process-wide default (deprecated — prefer explicit construction).
    default = SCP.default()
"""

from __future__ import annotations

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
    """Caller-owned SCP instance — the preferred SDK entry point.

    Each :class:`SCP` wraps an independent native ``BridgeInstance`` (with
    its own registries, transport state, and context manager). The wrapper
    exposes lifecycle controls (:meth:`suspend`, :meth:`resume`,
    :meth:`shutdown`) plus the monotonic :attr:`instance_id` used by the
    FFI handle-affinity check.

    For single-tenant processes that just need "the" bridge, use
    :meth:`default` — but note that this is a process-wide shared instance
    that the deprecated free-function façade also uses. New code should
    construct explicit :class:`SCP` instances.

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
        persistence: object | None = None,
    ) -> None:
        """Construct a fresh :class:`SCP` instance.

        :param storage: Optional storage configuration dict. In Phase 4 PR 1
            only ``{"type": "in_memory"}`` is supported; PR 3 adds
            ``{"type": "sqlite", "path": "..."}``. When ``None``, defaults
            to in-memory storage.
        :param persistence: Optional persistence provider. In PR 1 this
            parameter is accepted for API forward-compatibility but has no
            effect — PR 3 wires the real :class:`ContextPersistence`
            plumbing through the FFI boundary. Passing a non-``None`` value
            currently constructs an in-memory instance and does not raise.
        :raises ValidationError: If ``storage`` contains an unknown
            ``type``.
        """
        cls = _native_cls()
        if persistence is not None:
            # PR 1: persistence provider accepted for API shape only.
            # Delegates to the native `with_persistence` factory which
            # currently behaves identically to `new()`. PR 3 wires the
            # real ContextPersistence trait through.
            self._native = cls.with_persistence()
        elif storage is not None:
            self._native = cls.with_storage(storage)
        else:
            self._native = cls()

    @classmethod
    def default(cls) -> SCP:
        """Return an :class:`SCP` wrapping the process-wide default instance.

        Repeated calls yield distinct Python objects sharing the same
        underlying native handle — :attr:`instance_id` is stable across
        calls. This is what the deprecated free-function façade
        (``scp_sdk.identity_create``, etc.) uses under the hood.

        Prefer constructing :class:`SCP` explicitly in new code. The
        default-instance path is scheduled for removal two release cycles
        after Phase 4 merge (ADR-048).

        :returns: An :class:`SCP` handle on the shared default instance.
        :raises ContextError: If the default instance is currently
            suspended.
        """
        native_cls = _native_cls()
        instance = cls.__new__(cls)
        instance._native = native_cls.default_instance()
        return instance

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

        :raises TransportError: If the transport lock is poisoned.
        """
        self._native.suspend()

    def resume(self) -> None:
        """Resume a suspended bridge instance.

        Clears the suspended flag. The caller must re-establish the relay
        connection explicitly — :meth:`resume` does not reconnect
        automatically.

        :raises ContextError: If the instance has been permanently shut
            down.
        """
        self._native.resume()

    def shutdown(self, timeout: float = 5.0) -> None:
        """Shut down this instance with a graceful deadline.

        Drains in-flight tasks within ``timeout`` seconds, aborts any
        stragglers, then runs typed-field cleanup. A second call is a
        no-op (the underlying :class:`ShutdownError::AlreadyShutDown` is
        swallowed at the SDK surface).

        :param timeout: Maximum seconds to wait for in-flight tasks.
            Clamped to ``max(0.0, timeout)`` on the native side.
        :raises ContextError: If the tokio runtime is unavailable.
        """
        self._native.shutdown(float(timeout))

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
