"""Transport configuration and relay connection helpers for the SCP Python SDK.

Provides :class:`TransportConfig` for configuring relay connections and
helper functions for connecting to and querying SCP relays.  Wraps the
``_scp_core`` bridge functions ``transport_connect`` and
``transport_status`` (see ADR-013 S5).

See ``.docs/adrs/phase-3.md`` ADR-014 and ``.docs/standards/python.md``
for conventions.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

from scp_sdk.errors import TransportError

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

    async def connect(self) -> None:
        """Connect to the configured relay.

        Establishes a transport connection to :attr:`relay_url`.

        Raises:
            TransportError: If the connection fails.
        """
        logger.debug("Connecting to relay %s", self.relay_url)
        bridge = _bridge()
        bridge.transport_connect(self.relay_url)
        logger.info("Connected to relay %s", self.relay_url)

    async def status(self) -> TransportStatus:
        """Query the current transport connection status.

        Returns:
            A :class:`TransportStatus` with connection state, relay URL,
            and latency.

        Raises:
            TransportError: If querying transport status fails.
        """
        bridge = _bridge()
        raw = bridge.transport_status()
        return TransportStatus(
            connected=raw.connected,
            relay_url=raw.relay_url,
            latency_ms=raw.latency_ms,
        )


# ---------------------------------------------------------------------------
# Module-level convenience functions
# ---------------------------------------------------------------------------


async def connect_relay(relay_url: str) -> TransportConfig:
    """Connect to an SCP relay and return the transport configuration.

    Convenience function that creates a :class:`TransportConfig` and
    calls :meth:`~TransportConfig.connect` in one step.

    Args:
        relay_url: The URL of the SCP relay (e.g., ``"wss://relay.example.com"``).

    Returns:
        A connected :class:`TransportConfig` instance.

    Raises:
        TransportError: If the connection fails.
    """
    config = TransportConfig(relay_url=relay_url)
    await config.connect()
    return config


async def relay_status() -> TransportStatus:
    """Query the current transport connection status.

    Module-level convenience that wraps ``_scp_core.transport_status()``.

    Returns:
        A :class:`TransportStatus` with connection state.

    Raises:
        TransportError: If querying transport status fails.
    """
    bridge = _bridge()
    raw = bridge.transport_status()
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
