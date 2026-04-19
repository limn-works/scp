"""Transport configuration and relay connection helpers for the SCP Python SDK.

Provides :class:`TransportConfig` for configuring relay connections and
helper functions for connecting to and querying SCP relays.  Wraps the
:class:`scp_sdk.SCP` methods ``transport_connect`` and ``transport_status``
(see ADR-013 S5).

See ``.docs/adrs/phase-3.md`` ADR-014 and ``.docs/standards/python.md``
for conventions.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from typing import TYPE_CHECKING

from scp_sdk.errors import TransportError

if TYPE_CHECKING:
    from scp_sdk.scp import SCP

logger = logging.getLogger("scp_sdk")


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

        scp = SCP()
        config = TransportConfig(relay_url="wss://relay.example.com")
        await config.connect(scp)
        status = await config.status(scp)
        print(status.connected)  # True
    """

    #: The URL of the SCP relay to connect to.
    relay_url: str

    #: Connection timeout in seconds.
    timeout: float = 30.0

    #: Maximum number of reconnection attempts on failure.
    max_retries: int = 3

    async def connect(self, scp: SCP) -> None:
        """Connect to the configured relay.

        Establishes a transport connection to :attr:`relay_url`.

        Args:
            scp: The :class:`scp_sdk.SCP` instance whose transport is
                being configured.

        Raises:
            TransportError: If the connection fails.
        """
        logger.debug("Connecting to relay %s", self.relay_url)
        try:
            await asyncio.to_thread(scp._native.transport_connect, self.relay_url)
        except Exception as exc:  # propagate PyO3 transport errors
            raise TransportError(
                f"transport_connect({self.relay_url}) failed: {exc}",
                code="SCP-TRANS-5001",
            ) from exc
        logger.info("Connected to relay %s", self.relay_url)

    async def status(self, scp: SCP) -> TransportStatus:
        """Query the current transport connection status.

        Args:
            scp: The :class:`scp_sdk.SCP` instance whose transport is
                being queried.

        Returns:
            A :class:`TransportStatus` with connection state, relay URL,
            and latency.

        Raises:
            TransportError: If querying transport status fails.
        """
        raw = await asyncio.to_thread(scp._native.transport_status)
        return TransportStatus(
            connected=raw.connected,
            relay_url=raw.relay_url,
            latency_ms=raw.latency_ms,
        )


# ---------------------------------------------------------------------------
# Module-level convenience functions
# ---------------------------------------------------------------------------


async def connect_relay(scp: SCP, relay_url: str) -> TransportConfig:
    """Connect to an SCP relay and return the transport configuration.

    Convenience function that creates a :class:`TransportConfig` and
    calls :meth:`~TransportConfig.connect` in one step.

    Args:
        scp: The :class:`scp_sdk.SCP` instance whose transport is
            being configured.
        relay_url: The URL of the SCP relay (e.g., ``"wss://relay.example.com"``).

    Returns:
        A connected :class:`TransportConfig` instance.

    Raises:
        TransportError: If the connection fails.
    """
    config = TransportConfig(relay_url=relay_url)
    await config.connect(scp)
    return config


async def relay_status(scp: SCP) -> TransportStatus:
    """Query the current transport connection status.

    Module-level convenience that wraps the :class:`_scp_core.SCP`
    ``transport_status`` method.

    Args:
        scp: The :class:`scp_sdk.SCP` instance whose transport is
            being queried.

    Returns:
        A :class:`TransportStatus` with connection state.

    Raises:
        TransportError: If querying transport status fails.
    """
    raw = await asyncio.to_thread(scp._native.transport_status)
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
