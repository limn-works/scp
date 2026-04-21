"""Server-side SDK handle wrappers for relay and application node lifecycle.

Phase 4 PR 5 Agent B+C (#1549) collapsed :class:`Relay` and :class:`Node`
into pure handle wrappers. Use :meth:`scp_sdk.SCP.relay_start_in_memory`,
:meth:`scp_sdk.SCP.relay_start_local`,
:meth:`scp_sdk.SCP.node_start_in_memory`, and
:meth:`scp_sdk.SCP.node_start_local` to construct them.

Handle-level methods on the PyO3 objects — ``shutdown``, ``serve``,
``http_url``, the broadcast deployment lifecycle on Node
(``enable_site_projection``, ``commit_deploy``, ``rollback_deploy``,
``disable_site_projection``) — remain available because the PyO3 bridge
exposes them directly on the handle type. No :class:`SCP` dispatch is
needed for those calls.

Gated behind the ``server`` feature in ``scp-ffi-common``. Not available
for WASM (ADR-034).
"""

from __future__ import annotations

import asyncio
from types import TracebackType
from typing import TYPE_CHECKING, Any

from scp_sdk.context import validate_admission, validate_broadcast_key_hex

if TYPE_CHECKING:
    from scp_sdk.context import SiteConfig
    from scp_sdk.scp import SCP


class Relay:
    """Opaque handle to a running SCP relay server.

    Construct via :meth:`scp_sdk.SCP.relay_start_in_memory` or
    :meth:`scp_sdk.SCP.relay_start_local`. Call :meth:`shutdown` to stop
    the relay, or use ``async with`` for automatic cleanup.
    """

    __slots__ = ("_raw_handle",)

    def __init__(self, handle: Any) -> None:
        self._raw_handle = handle

    @classmethod
    def _from_handle(cls, _scp: SCP | None, raw: Any) -> Relay:
        """Internal constructor used by :class:`scp_sdk.SCP`."""
        return cls(raw)

    @property
    def relay_url(self) -> str:
        """The WebSocket URL clients should connect to (e.g. ``ws://127.0.0.1:PORT/scp/v1``)."""
        return self._raw_handle.relay_url  # type: ignore[no-any-return]

    @property
    def relay_port(self) -> int:
        """The port the relay is listening on."""
        return self._raw_handle.relay_port  # type: ignore[no-any-return]

    @property
    def is_shutdown(self) -> bool:
        """``True`` if :meth:`shutdown` has already been called."""
        return self._raw_handle.is_shutdown  # type: ignore[no-any-return]

    async def shutdown(self) -> None:
        """Signal the relay to stop accepting new connections.

        In-flight connection handlers drain naturally. Idempotent.
        """
        await asyncio.to_thread(self._raw_handle.shutdown)

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
    identity, and (optionally) persistent storage. Construct via
    :meth:`scp_sdk.SCP.node_start_in_memory` or
    :meth:`scp_sdk.SCP.node_start_local`.
    """

    __slots__ = ("_raw_handle",)

    def __init__(self, handle: Any) -> None:
        self._raw_handle = handle

    @classmethod
    def _from_handle(cls, _scp: SCP | None, raw: Any) -> Node:
        """Internal constructor used by :class:`scp_sdk.SCP`."""
        return cls(raw)

    @property
    def relay_url(self) -> str:
        """The WebSocket URL for this node's relay (e.g. ``ws://127.0.0.1:PORT/scp/v1``)."""
        return self._raw_handle.relay_url  # type: ignore[no-any-return]

    @property
    def relay_port(self) -> int:
        """The port the node's relay is listening on."""
        return self._raw_handle.relay_port  # type: ignore[no-any-return]

    @property
    def did(self) -> str:
        """The node's DID string (e.g. ``did:dht:z6Mk...``)."""
        return self._raw_handle.did  # type: ignore[no-any-return]

    @property
    def is_shutdown(self) -> bool:
        """``True`` if :meth:`shutdown` has already been called."""
        return self._raw_handle.is_shutdown  # type: ignore[no-any-return]

    async def http_url(self) -> str | None:
        """Return the HTTP URL of the background server, or ``None`` if not serving.

        Returns the literal bind address, which may contain ``0.0.0.0`` if the
        server was bound to the unspecified address.
        """
        return await asyncio.to_thread(self._raw_handle.http_url)  # type: ignore[no-any-return]

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
        return await asyncio.to_thread(self._raw_handle.serve, bind_addr)  # type: ignore[no-any-return]

    async def shutdown(self) -> None:
        """Signal the node to stop (relay + background tasks).

        In-flight connection handlers drain naturally. Idempotent.
        """
        await asyncio.to_thread(self._raw_handle.shutdown)

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

        Three resolution modes:

        1. Both ``broadcast_key_hex`` **and** ``author_did`` provided — uses
           the explicit key with epoch 0.
        2. Only ``author_did`` provided — auto-resolves the broadcast key
           using that DID (useful when the author identity differs from
           the node identity).
        3. Neither provided — auto-resolves using the node's identity DID.

        Providing ``broadcast_key_hex`` without ``author_did`` is an error.
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
            self._raw_handle.enable_site_projection,
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
        """Commit a deploy for a projected context (§18.11.11)."""
        return await asyncio.to_thread(  # type: ignore[no-any-return]
            self._raw_handle.commit_deploy, context_id, deploy_id
        )

    async def rollback_deploy(self, context_id: str, deploy_id: str) -> None:
        """Roll back to a previous deploy for a projected context (§18.11.11)."""
        await asyncio.to_thread(self._raw_handle.rollback_deploy, context_id, deploy_id)

    async def disable_site_projection(self, context_id: str) -> None:
        """Deactivate HTTP broadcast projection for a context."""
        await asyncio.to_thread(self._raw_handle.disable_site_projection, context_id)

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        await self.shutdown()

    def __repr__(self) -> str:
        return f"Node(relay_url={self.relay_url}, did={self.did})"
