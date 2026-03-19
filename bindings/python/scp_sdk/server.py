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

:class:`Node` also exposes broadcast deployment lifecycle methods
(SCP-296, spec §18.11.8):

.. code-block:: python

    async with await Node.start_in_memory() as node:
        await node.enable_site_projection(context_id, broadcast_key_hex,
                                          author_did, "open", config)
        count = await node.commit_deploy(context_id, deploy_id)
        await node.rollback_deploy(context_id, deploy_id)
        await node.disable_site_projection(context_id)

Gated behind the ``server`` feature in ``scp-ffi-common``. Not available
for WASM (ADR-034).
"""

from __future__ import annotations

import asyncio
from types import TracebackType
from typing import TYPE_CHECKING

import _scp_core

from scp_sdk.context import validate_admission, validate_broadcast_key_hex

if TYPE_CHECKING:
    from scp_sdk.context import SiteConfig
    from scp_sdk.identity import Identity


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

    async def http_url(self) -> str | None:
        """Return the HTTP URL of the background server, or ``None`` if not serving.

        Returns the literal bind address, which may contain ``0.0.0.0`` if the
        server was bound to the unspecified address.
        """
        return await asyncio.to_thread(self._handle.http_url)  # type: ignore[no-any-return]

    @property
    def is_shutdown(self) -> bool:
        """``True`` if :meth:`shutdown` has already been called."""
        return self._handle.is_shutdown  # type: ignore[no-any-return]

    @staticmethod
    async def start_in_memory(identity: Identity | None = None) -> Node:
        """Start a full application node with in-memory storage.

        Auto-wires in-memory key custody, in-memory storage, in-memory DHT
        client, self-signed TLS, and a relay on an OS-assigned port.

        Args:
            identity: Optional pre-existing :class:`~scp_sdk.identity.Identity`
                to use.  If provided, the node uses this identity instead of
                generating a fresh DID.  The identity must have been created
                via :meth:`~scp_sdk.identity.Identity.create` in the same
                process (it must exist in the bridge identity registry).
        """
        did = identity.did if identity is not None else None
        handle = await asyncio.to_thread(_scp_core.py_node_start_in_memory, did)
        return Node(handle)

    @staticmethod
    async def start_local(data_dir: str, identity: Identity | None = None) -> Node:
        """Start a full application node with file-backed storage.

        Opens (or creates) persistent storage at ``<data_dir>/storage/``
        and a redb blob database at ``<data_dir>/blobs.redb``.

        Args:
            data_dir: Directory for persistent storage.
            identity: Optional pre-existing :class:`~scp_sdk.identity.Identity`
                to use.  If provided, the node uses this identity instead of
                generating one from ``SCP_KEY_PASSPHRASE``.
        """
        did = identity.did if identity is not None else None
        handle = await asyncio.to_thread(_scp_core.py_node_start_local, data_dir, did)
        return Node(handle)

    async def serve(self, bind_addr: str | None = None) -> str:
        """Start the HTTP server in the background.

        If ``bind_addr`` is ``None``, defaults to ``127.0.0.1:8443``
        (loopback only). Pass ``"0.0.0.0:PORT"`` for network access.

        Returns the actual bound address as a raw string (e.g.
        ``"127.0.0.1:8080"``). Use :meth:`http_url` for the full URL
        form (``"http://127.0.0.1:8080"``).

        Note: The background server does not support TLS. For production
        deployments requiring encryption, use the node binary's
        ``serve()`` with TLS configuration.

        Args:
            bind_addr: Socket address to bind (e.g. ``"127.0.0.1:8080"``).

        Returns:
            The actual bound address as a string (e.g. ``"127.0.0.1:8080"``).

        Raises:
            RuntimeError: If the server is already running or binding fails.
            ValueError: If ``bind_addr`` is not a valid socket address.
        """
        return await asyncio.to_thread(self._handle.serve, bind_addr)  # type: ignore[no-any-return]

    async def shutdown(self) -> None:
        """Signal the node to stop (relay + background tasks).

        In-flight connection handlers drain naturally. Idempotent.
        """
        await asyncio.to_thread(self._handle.shutdown)

    async def __aenter__(self) -> Node:
        return self

    # ------------------------------------------------------------------
    # Broadcast deployment lifecycle (SCP-296, spec §18.11.8)
    # ------------------------------------------------------------------

    async def enable_site_projection(
        self,
        context_id: str,
        admission: str,
        config: SiteConfig,
        broadcast_key_hex: str | None = None,
        author_did: str | None = None,
    ) -> None:
        """Activate HTTP broadcast projection for a context.

        When both ``broadcast_key_hex`` and ``author_did`` are ``None``, the
        key is auto-resolved using the node's identity DID. When only
        ``author_did`` is provided, auto-resolves using that DID (useful
        when the author identity differs from the node identity).
        Providing ``broadcast_key_hex`` requires ``author_did``.

        Args:
            context_id: The context ID to project.
            admission: ``"open"`` or ``"gated"``.
            config: :class:`~scp_sdk.context.SiteConfig` with hostname,
                index path, and deploy limits.
            broadcast_key_hex: 32-byte AES-256 broadcast key as a
                64-character hex string, or ``None`` for auto-lookup.
            author_did: DID of the broadcast key owner, or ``None``
                for auto-lookup using the node's DID.

        Raises:
            ValueError: If parameters are invalid or ``broadcast_key_hex``
                is provided without ``author_did``.
            RuntimeError: If the underlying node operation fails or
                auto-lookup cannot find the key.
        """
        validate_admission(admission)
        if broadcast_key_hex is not None and author_did is None:
            raise ValueError(
                "broadcast_key_hex requires author_did — provide the DID of the "
                "broadcast key owner, or omit both for auto-resolve"
            )
        if broadcast_key_hex is not None:
            validate_broadcast_key_hex(broadcast_key_hex)
        await asyncio.to_thread(
            self._handle.enable_site_projection,
            context_id,
            admission,
            config.hostname,
            broadcast_key_hex,
            author_did,
            config.index_path if config.index_path != "/index.html" else None,
            config.max_assets_per_deploy if config.max_assets_per_deploy != 10_000 else None,
            config.max_deploy_size_bytes if config.max_deploy_size_bytes != 536_870_912 else None,
            config.deploy_retention_count if config.deploy_retention_count != 2 else None,
            config.csp_override,
        )

    async def commit_deploy(self, context_id: str, deploy_id: str) -> int:
        """Commit a deploy for a projected context (§18.11.11).

        Scans blobs matching the ``deploy_id``, decrypts each to extract
        metadata, builds an immutable path index, and atomically swaps the
        serving pointer.

        Args:
            context_id: The projected context ID.
            deploy_id: The deploy identifier (hex, from publish).

        Returns:
            The number of assets in the committed deploy.

        Raises:
            RuntimeError: If the context is not projected or commit fails.
        """
        return await asyncio.to_thread(  # type: ignore[no-any-return]
            self._handle.commit_deploy, context_id, deploy_id
        )

    async def rollback_deploy(self, context_id: str, deploy_id: str) -> None:
        """Roll back to a previous deploy for a projected context (§18.11.11).

        Sets the path index pointer to a previous deploy within the
        retention window.

        Args:
            context_id: The projected context ID.
            deploy_id: The deploy identifier to roll back to.

        Raises:
            RuntimeError: If the context is not projected or deploy not found.
        """
        await asyncio.to_thread(self._handle.rollback_deploy, context_id, deploy_id)

    async def disable_site_projection(self, context_id: str) -> None:
        """Deactivate HTTP broadcast projection for a context.

        Removes the projected context from the registry and drops all
        retained epoch keys. Idempotent — calling on a non-projected
        context is a no-op.

        Args:
            context_id: The context ID to stop projecting.
        """
        await asyncio.to_thread(self._handle.disable_site_projection, context_id)

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        await self.shutdown()

    def __repr__(self) -> str:
        return f"Node(relay_url={self.relay_url}, did={self.did})"
