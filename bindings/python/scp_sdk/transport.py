"""Transport configuration data types for the SCP Python SDK.

Phase 4 PR 5 Agent B+C (#1549) collapsed the transport helpers into
methods on :class:`scp_sdk.SCP`. :func:`connect_relay` is replaced by
:meth:`scp_sdk.SCP.transport_connect`;
:func:`transport_status` is replaced by
:meth:`scp_sdk.SCP.transport_status`.

The two remaining exports are pure data classes.

See ``.docs/adrs/phase-3.md`` ADR-014 and ADR-048 (the SCP multi-instance
façade consolidation).
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

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

    Example::

        scp = SCP()
        config = TransportConfig(relay_url="wss://relay.example.com")
        await scp.transport_connect(config.relay_url)
        status = await scp.transport_status()
        print(status.connected)  # True
    """

    #: The URL of the SCP relay to connect to.
    relay_url: str

    #: Connection timeout in seconds.
    timeout: float = 30.0

    #: Maximum number of reconnection attempts on failure.
    max_retries: int = 3


__all__ = [
    "TransportConfig",
    "TransportStatus",
]
