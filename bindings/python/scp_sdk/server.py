"""Server-side SDK handle wrappers for relay and application node lifecycle.

Phase 4 PR 5 Agent B+C (#1549) collapsed :class:`Relay` and :class:`Node`
into pure handle wrappers. Use :meth:`scp_sdk.SCP.relay_start_in_memory`,
:meth:`scp_sdk.SCP.relay_start_local`, :meth:`scp_sdk.SCP.node_start`,
:meth:`scp_sdk.SCP.node_start_in_memory`, and
:meth:`scp_sdk.SCP.node_start_local` to construct them. The last two are the
development pair: a shipped extension refuses both with ``SCP-TRANS-5055``.

Handle-level methods on the PyO3 objects — ``shutdown``, ``serve``,
``http_url``, the broadcast deployment lifecycle on Node
(``enable_site_projection``, ``commit_deploy``, ``rollback_deploy``,
``disable_site_projection``) — remain available because the PyO3 bridge
exposes them directly on the handle type. No :class:`SCP` dispatch is
needed for those calls.

:class:`NodeStartConfig` and its sum types mirror the bridge's
``NodeStartConfig`` (``.docs/standards/construction.md`` §"Node start —
``NodeStartConfig``"), which :meth:`scp_sdk.SCP.node_start` sends to the
PyO3 ``node_start`` export.

Gated behind the ``server`` feature in ``scp-ffi-common``.
"""

from __future__ import annotations

import asyncio
import dataclasses
import json
import os
from dataclasses import dataclass
from types import NoneType, TracebackType
from typing import TYPE_CHECKING, Any, ClassVar, TypeAlias, get_args, get_type_hints

from scp_sdk.context import validate_admission, validate_broadcast_key_hex
from scp_sdk.errors import StorageError, _require_type
from scp_sdk.identity import Identity

if TYPE_CHECKING:
    from scp_sdk.context import SiteConfig
    from scp_sdk.scp import SCP


# ---------------------------------------------------------------------------
# NodeStartConfig (construction.md §"Node start — NodeStartConfig", ADR-052)
# ---------------------------------------------------------------------------

#: The code ``node_start`` returns for an invalid configuration
#: (sdk-common.md §"Node start error codes"). The SDK raises it for a config
#: it cannot encode, as the bridge does for a config it cannot read.
NODE_START_INVALID_CONFIG_CODE = "SCP-STORAGE-8007"


class _Arm:
    """One arm of a ``kind``-tagged sum type of the bridge config.

    ``_KIND`` is the arm's ``snake_case`` name, the ``kind`` value the bridge's
    serde reads; the arm's dataclass fields follow it on the wire.
    """

    _KIND: ClassVar[str]

    def _wire(self) -> dict[str, Any]:
        """Return ``{"kind": _KIND, **fields}``, each path lowered to its string
        with :func:`os.fspath`."""
        wire: dict[str, Any] = {"kind": self._KIND}
        for f in dataclasses.fields(self):  # type: ignore[arg-type]
            value = getattr(self, f.name)
            wire[f.name] = os.fspath(value) if isinstance(value, os.PathLike) else value
        return wire


@dataclass(frozen=True, kw_only=True)
class ReachDomain(_Arm):
    """The node serves ``domain``, a DNS name the operator controls, without a
    scheme, port or path."""

    _KIND: ClassVar[str] = "domain"
    domain: str


@dataclass(frozen=True, kw_only=True)
class ReachNatTraversal(_Arm):
    """The node sits behind NAT and uses the NAT traversal tiers."""

    _KIND: ClassVar[str] = "nat_traversal"


@dataclass(frozen=True, kw_only=True)
class ReachLocal(_Arm):
    """The node serves the local machine only."""

    _KIND: ClassVar[str] = "local"


#: How the node is reached. The bridge omits the core's ``Tunnel`` arm, because
#: the core does not thread its ``public_url`` into the published relay URL.
Reach: TypeAlias = ReachDomain | ReachNatTraversal | ReachLocal


@dataclass(frozen=True, kw_only=True)
class BlobInMemory(_Arm):
    """Durability-only in-memory blob storage: the node's blobs die with it
    (spec §17.17)."""

    _KIND: ClassVar[str] = "in_memory"


@dataclass(frozen=True, kw_only=True)
class BlobRedb(_Arm):
    """A redb blob database file at ``path``, a ``str`` or path-like object;
    ``node_start`` creates its parent directory."""

    _KIND: ClassVar[str] = "redb"
    path: str | os.PathLike[str]


@dataclass(frozen=True, kw_only=True)
class BlobSqlite(_Arm):
    """A SQLite blob database file at ``path``, a ``str`` or path-like object;
    ``node_start`` creates its parent directory."""

    _KIND: ClassVar[str] = "sqlite"
    path: str | os.PathLike[str]


#: The relay's blob storage backend. S3 and Postgres are not exposed.
BlobBackend: TypeAlias = BlobInMemory | BlobRedb | BlobSqlite


@dataclass(frozen=True, kw_only=True)
class TlsSelfSigned(_Arm):
    """Serve a self-signed certificate for the reach's domain."""

    _KIND: ClassVar[str] = "self_signed"


@dataclass(frozen=True, kw_only=True)
class TlsAcme(_Arm):
    """Provision a certificate through ACME for the reach's domain. ``email``
    is the ACME account contact; ``None`` selects headless ACME."""

    _KIND: ClassVar[str] = "acme"
    email: str | None = None


@dataclass(frozen=True, kw_only=True)
class TlsPlaintext(_Arm):
    """Serve plaintext. The bridge rejects it with :class:`ReachDomain`."""

    _KIND: ClassVar[str] = "plaintext"


@dataclass(frozen=True, kw_only=True)
class TlsTerminated(_Arm):
    """TLS terminates upstream, at a tunnel or reverse proxy."""

    _KIND: ClassVar[str] = "terminated"


#: TLS selection. The core's ``Custom`` arm carries a trait object and is not
#: exposed.
TlsMode: TypeAlias = TlsSelfSigned | TlsAcme | TlsPlaintext | TlsTerminated


@dataclass(frozen=True, kw_only=True)
class DhtDisabled(_Arm):
    """Publish nothing: the node runs its relay and publishes no DID document
    (keri's scope ruling of 2026-10-13)."""

    _KIND: ClassVar[str] = "disabled"


#: DID-document publication. ``Disabled`` is the only arm.
DhtMode: TypeAlias = DhtDisabled


@dataclass(frozen=True, kw_only=True)
class CorsAnyOrigin(_Arm):
    """Allow every origin (``*``), selected only because the caller names it."""

    _KIND: ClassVar[str] = "any_origin"


@dataclass(frozen=True, kw_only=True)
class CorsAllowlist(_Arm):
    """Allow exactly ``origins``, such as ``["https://app.example.org"]``."""

    _KIND: ClassVar[str] = "allowlist"
    origins: list[str]


#: CORS origins for the node's public endpoints.
CorsOrigins: TypeAlias = CorsAnyOrigin | CorsAllowlist


@dataclass(frozen=True, kw_only=True)
class NatAuto(_Arm):
    """The default NAT strategy."""

    _KIND: ClassVar[str] = "auto"


#: NAT strategy. The core's ``Custom`` and ``Tuned`` arms carry trait objects
#: and are not exposed.
Nat: TypeAlias = NatAuto


@dataclass(frozen=True, kw_only=True)
class NodeStartConfig:
    """The flat config :meth:`scp_sdk.SCP.node_start` starts a production node
    from (construction.md §"Node start — ``NodeStartConfig``", ADR-052).

    Every field the bridge requires is required here. The config has no storage
    field: the node runs on the ``SCP`` instance's own storage (spec §17.6), and
    an in-memory instance store loses all node state when the node drops.

    Two error rules apply before the bridge runs. An ``identity`` that is not an
    :class:`~scp_sdk.Identity`, or a value passed to
    :meth:`scp_sdk.SCP.node_start` that is not a ``NodeStartConfig``, raises
    :class:`~scp_sdk.errors.ValidationError` ``SCP-VALID-7005``. A sum-typed
    field holding a value outside its arms raises
    :class:`~scp_sdk.errors.StorageError` ``SCP-STORAGE-8007``, the code the
    bridge returns for a malformed config.

    Attributes:
        reach: How the node is reached.
        identity: The operator :class:`~scp_sdk.Identity`, already created on
            the same ``SCP`` instance; the bridge receives its DID. Nodes have
            no identity of their own.
        blob_storage: The relay's blob storage backend.
        tls: TLS selection.
        dht: DID-document publication; :class:`DhtDisabled` is the only arm.
        cors_origins: CORS origins for the public endpoints. Required, because
            an absent list would mean the permissive ``*`` origin.
        bind_addr: Relay bind address such as ``"127.0.0.1:0"``; ``None``
            binds ``127.0.0.1:0``.
        http_bind_addr: Public HTTP bind address; ``None`` selects the core
            default.
        nat: NAT strategy; ``None`` selects :class:`NatAuto`.
        projection_rate_limit: Per-IP rate limit for broadcast projection
            endpoints, greater than 0; ``None`` selects the core default.
    """

    reach: Reach
    identity: Identity
    blob_storage: BlobBackend
    tls: TlsMode
    dht: DhtMode
    cors_origins: CorsOrigins
    bind_addr: str | None = None
    http_bind_addr: str | None = None
    nat: Nat | None = None
    projection_rate_limit: int | None = None

    def _to_wire(self) -> dict[str, Any]:
        """Return the dict the bridge's ``NodeStartConfig::from_json`` reads.

        Every field appears under its own name and in declaration order;
        ``identity`` is lowered to its DID, and an absent optional is ``null``,
        which the bridge reads as absent.

        Raises:
            ValidationError: ``SCP-VALID-7005`` when ``identity`` is not an
                :class:`~scp_sdk.Identity`.
            StorageError: ``SCP-STORAGE-8007`` when a sum-typed field holds a
                value that is not one of its arms.
        """
        wire: dict[str, Any] = {}
        for field in dataclasses.fields(self):
            value = getattr(self, field.name)
            if field.name == "identity":
                wire[field.name] = _require_type(value, Identity, "NodeStartConfig.identity").did
                continue
            arms = _ARMS.get(field.name)
            if arms is None:
                wire[field.name] = value
            elif value is None and field.name in _OPTIONAL_SUM_FIELDS:
                wire[field.name] = None
            elif isinstance(value, arms):
                wire[field.name] = value._wire()
            else:
                names = ", ".join(a.__name__ for a in arms)
                raise StorageError(
                    f"NodeStartConfig.{field.name} must be one of {names}, "
                    f"not {type(value).__name__}",
                    code=NODE_START_INVALID_CONFIG_CODE,
                )
        return wire

    def _to_json(self) -> str:
        """Return :meth:`_to_wire` as the JSON string the bridge's ``node_start``
        takes.

        Raises:
            ValidationError: ``SCP-VALID-7005`` when ``identity`` is not an
                :class:`~scp_sdk.Identity`.
            StorageError: ``SCP-STORAGE-8007`` when the config holds a value
                that is not one of its arms or that JSON cannot encode, such as
                ``bytes`` or a non-finite float.
        """
        wire = self._to_wire()
        try:
            return json.dumps(wire, allow_nan=False)
        except (TypeError, ValueError) as exc:
            raise StorageError(
                f"NodeStartConfig cannot be encoded: {exc}",
                code=NODE_START_INVALID_CONFIG_CODE,
            ) from exc


def _arms_of(hint: Any) -> tuple[type[_Arm], ...]:
    """The :class:`_Arm` classes a field's type hint admits: every member of a
    union, or the hint itself when it is one arm."""
    members = get_args(hint) or (hint,)
    return tuple(m for m in members if isinstance(m, type) and issubclass(m, _Arm))


_HINTS = get_type_hints(NodeStartConfig)

#: The arms each sum-typed field accepts, keyed by field name, derived from the
#: field's type alias so a new arm in an alias needs no second list.
_ARMS: dict[str, tuple[type[_Arm], ...]] = {
    name: arms for name, hint in _HINTS.items() if (arms := _arms_of(hint))
}

#: The sum-typed fields whose hint admits ``None``.
_OPTIONAL_SUM_FIELDS: frozenset[str] = frozenset(
    name for name in _ARMS if NoneType in get_args(_HINTS[name])
)


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

    An application node includes a running relay server and runs under a DID.
    Construct a production node via :meth:`scp_sdk.SCP.node_start`, which runs
    it on the ``SCP`` instance's storage under an operator identity, or a
    development node via :meth:`scp_sdk.SCP.node_start_in_memory` or
    :meth:`scp_sdk.SCP.node_start_local`, which a shipped extension refuses
    with ``SCP-TRANS-5055``.
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
        """The DID the node runs under (e.g. ``did:dht:z6Mk...``); for
        :meth:`scp_sdk.SCP.node_start`, the operator DID."""
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
            TransportError: If the server is already running or binding fails
                (``SCP-TRANS-5054``).
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
