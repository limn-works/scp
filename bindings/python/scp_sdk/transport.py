"""Transport configuration and relay connection helpers for the SCP Python SDK.

Provides :class:`TransportConfig` for configuring relay connections and
helper functions for connecting to and querying SCP relays.  Wraps the
``_scp_core`` bridge functions ``transport_connect`` and
``transport_status`` (see ADR-013 S5).

See ``.docs/adrs/phase-3.md`` ADR-014 and ``.docs/standards/python.md``
for conventions.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from scp_sdk._deprecation import deprecated_default_instance, resolve_scp
from scp_sdk.errors import TransportError

if TYPE_CHECKING:
    import _scp_core

logger = logging.getLogger("scp_sdk")

# ---------------------------------------------------------------------------
# Lazy bridge import helper
# ---------------------------------------------------------------------------


def _bridge() -> Any:
    """Return the ``_scp_core`` extension module, imported lazily."""
    try:
        import _scp_core  # type: ignore[import-not-found]

        return _scp_core
    except ImportError as exc:
        raise TransportError(
            "The _scp_core extension module is not installed. "
            "Install scp-python with: pip install scp-python",
            code="SCP-TRANS-5001",
        ) from exc


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------


@dataclass
class TransportStatus:
    """Current transport connection status.

    Mirrors ``PyTransportStatus`` from ``_scp_core``.
    """

    #: ``True`` if the transport is currently connected to a relay.
    connected: bool

    #: The relay URL, if connected.  ``None`` if disconnected.
    relay_url: str | None = None

    #: Round-trip latency to the relay in milliseconds.  ``None`` if not
    #: measured or disconnected.
    latency_ms: float | None = None


@dataclass
class TransportConfig:
    """Configuration for an SCP transport relay connection.

    Provides typed configuration and convenience methods for connecting
    to an SCP relay.

    Example::

        config = TransportConfig(relay_url="wss://relay.example.com")
        await config.connect()
        status = await config.status()
        print(status.connected)  # True
    """

    #: The URL of the SCP relay to connect to.
    relay_url: str

    #: Connection timeout in seconds.
    timeout: float = 30.0

    #: Maximum number of reconnection attempts on failure.
    max_retries: int = 3

    async def connect(self, scp: _scp_core.SCP | None = None) -> None:
        """Connect to the configured relay.

        Establishes a transport connection to :attr:`relay_url`.

        Args:
            scp: Optional explicit :class:`_scp_core.SCP` instance. When
                ``None`` the process-wide default instance is used for
                back-compat (ADR-048).

        Raises:
            TransportError: If the connection fails.
        """
        logger.debug("Connecting to relay %s", self.relay_url)
        instance = resolve_scp(scp)
        await asyncio.to_thread(instance.transport_connect, self.relay_url)
        logger.info("Connected to relay %s", self.relay_url)

    async def status(self, scp: _scp_core.SCP | None = None) -> TransportStatus:
        """Query the current transport connection status.

        Args:
            scp: Optional explicit :class:`_scp_core.SCP` instance. When
                ``None`` the process-wide default instance is used for
                back-compat (ADR-048).

        Returns:
            A :class:`TransportStatus` with connection state, relay URL,
            and latency.

        Raises:
            TransportError: If querying transport status fails.
        """
        instance = resolve_scp(scp)
        raw = await asyncio.to_thread(instance.transport_status)
        return TransportStatus(
            connected=raw.connected,
            relay_url=raw.relay_url,
            latency_ms=raw.latency_ms,
        )


# ---------------------------------------------------------------------------
# Module-level convenience functions
# ---------------------------------------------------------------------------


@deprecated_default_instance
async def connect_relay(relay_url: str, scp: _scp_core.SCP | None = None) -> TransportConfig:
    """Connect to an SCP relay and return the transport configuration.

    Convenience function that creates a :class:`TransportConfig` and
    calls :meth:`~TransportConfig.connect` in one step.

    Args:
        relay_url: The URL of the SCP relay (e.g., ``"wss://relay.example.com"``).
        scp: Optional explicit :class:`_scp_core.SCP` instance. When
            ``None`` the process-wide default instance is used for
            back-compat (ADR-048).

    Returns:
        A connected :class:`TransportConfig` instance.

    Raises:
        TransportError: If the connection fails.
    """
    config = TransportConfig(relay_url=relay_url)
    await config.connect(scp=scp)
    return config


@deprecated_default_instance
async def relay_status(scp: _scp_core.SCP | None = None) -> TransportStatus:
    """Query the current transport connection status.

    Module-level convenience that wraps the :class:`_scp_core.SCP`
    ``transport_status`` method.

    Args:
        scp: Optional explicit :class:`_scp_core.SCP` instance. When
            ``None`` the process-wide default instance is used for
            back-compat (ADR-048).

    Returns:
        A :class:`TransportStatus` with connection state.

    Raises:
        TransportError: If querying transport status fails.
    """
    instance = resolve_scp(scp)
    raw = await asyncio.to_thread(instance.transport_status)
    return TransportStatus(
        connected=raw.connected,
        relay_url=raw.relay_url,
        latency_ms=raw.latency_ms,
    )


__all__ = [
    "TransportConfig",
    "TransportStatus",
    "connect_relay",
    "relay_status",
]
