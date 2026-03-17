"""Server-side SDK wrappers for relay and application node lifecycle.

Provides :class:`Relay` and :class:`Node` classes that wrap the PyO3 bridge
functions ``py_relay_start_in_memory`` / ``py_relay_start_local`` and
``py_node_start_in_memory`` / ``py_node_start_local``.

Both classes support ``async with`` context-manager usage for automatic
shutdown:

.. code-block:: python

    async with await Relay.start_in_memory() as relay:
        print(relay.relay_url)

    async with await Node.start_in_memory() as node:
        print(node.relay_url, node.did)

Gated behind the ``server`` feature in ``scp-ffi-common``. Not available
for WASM (ADR-034).
"""

from __future__ import annotations

import asyncio
from types import TracebackType

import _scp_core


class Relay:
    """Opaque handle to a running SCP relay server.

    Use the static factory methods :meth:`start_in_memory` or
    :meth:`start_local` to create an instance. Call :meth:`shutdown` to
    stop the relay, or use ``async with`` for automatic cleanup.
    """

    __slots__ = ("_handle",)

    def __init__(self, handle: _scp_core.RelayHandle) -> None:
        self._handle = handle

    @property
    def relay_url(self) -> str:
        """The WebSocket URL clients should connect to (e.g. ``ws://127.0.0.1:PORT/scp/v1``)."""
        return self._handle.relay_url  # type: ignore[no-any-return]

    @property
    def relay_port(self) -> int:
        """The port the relay is listening on."""
        return self._handle.relay_port  # type: ignore[no-any-return]

    @property
    def is_shutdown(self) -> bool:
        """``True`` if :meth:`shutdown` has already been called."""
        return self._handle.is_shutdown  # type: ignore[no-any-return]

    @staticmethod
    async def start_in_memory() -> Relay:
        """Start a relay with in-memory blob storage on an OS-assigned port.

        Returns a :class:`Relay` whose :attr:`relay_url` property contains
        the WebSocket URL for clients.
        """
        handle = await asyncio.to_thread(_scp_core.py_relay_start_in_memory)
        return Relay(handle)

    @staticmethod
    async def start_local(data_dir: str) -> Relay:
        """Start a relay with redb-backed blob storage on an OS-assigned port.

        Opens (or creates) a redb database at ``<data_dir>/blobs.redb``.

        Args:
            data_dir: Directory for persistent blob storage.
        """
        handle = await asyncio.to_thread(_scp_core.py_relay_start_local, data_dir)
        return Relay(handle)

    async def shutdown(self) -> None:
        """Signal the relay to stop accepting new connections.

        In-flight connection handlers drain naturally. Idempotent.
        """
        await asyncio.to_thread(self._handle.shutdown)

    async def __aenter__(self) -> Relay:
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        await self.shutdown()

    def __repr__(self) -> str:
        return f"Relay(url={self.relay_url})"


class Node:
    """Opaque handle to a running SCP application node.

    An application node includes a running relay server, a generated DID
    identity, and (optionally) persistent storage. Use the static factory
    methods :meth:`start_in_memory` or :meth:`start_local` to create an
    instance.
    """

    __slots__ = ("_handle",)

    def __init__(self, handle: _scp_core.NodeHandle) -> None:
        self._handle = handle

    @property
    def relay_url(self) -> str:
        """The WebSocket URL for this node's relay (e.g. ``ws://127.0.0.1:PORT/scp/v1``)."""
        return self._handle.relay_url  # type: ignore[no-any-return]

    @property
    def relay_port(self) -> int:
        """The port the node's relay is listening on."""
        return self._handle.relay_port  # type: ignore[no-any-return]

    @property
    def did(self) -> str:
        """The node's DID string (e.g. ``did:dht:z6Mk...``)."""
        return self._handle.did  # type: ignore[no-any-return]

    @property
    def is_shutdown(self) -> bool:
        """``True`` if :meth:`shutdown` has already been called."""
        return self._handle.is_shutdown  # type: ignore[no-any-return]

    @staticmethod
    async def start_in_memory() -> Node:
        """Start a full application node with in-memory storage.

        Auto-wires in-memory key custody, in-memory storage, in-memory DHT
        client, self-signed TLS, and a relay on an OS-assigned port.
        """
        handle = await asyncio.to_thread(_scp_core.py_node_start_in_memory)
        return Node(handle)

    @staticmethod
    async def start_local(data_dir: str) -> Node:
        """Start a full application node with file-backed storage.

        Opens (or creates) persistent storage at ``<data_dir>/storage/``
        and a redb blob database at ``<data_dir>/blobs.redb``.

        Args:
            data_dir: Directory for persistent storage.
        """
        handle = await asyncio.to_thread(_scp_core.py_node_start_local, data_dir)
        return Node(handle)

    async def shutdown(self) -> None:
        """Signal the node to stop (relay + background tasks).

        In-flight connection handlers drain naturally. Idempotent.
        """
        await asyncio.to_thread(self._handle.shutdown)

    async def __aenter__(self) -> Node:
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        await self.shutdown()

    def __repr__(self) -> str:
        return f"Node(relay_url={self.relay_url}, did={self.did})"
