"""Unit tests for Node broadcast deployment lifecycle (SCP-296) and for
``SCP.node_start`` and its ``NodeStartConfig`` (SCP-323).

Most tests mock the ``_scp_core`` bridge layer. The ``node_start`` tests that
take the ``scp`` fixture run against the built extension
(``maturin develop --features testing``) and skip only when no extension is
installed.

See spec section 18.11.8 and ``.docs/prds/http-features.json`` SCP-296.
"""

from __future__ import annotations

import dataclasses
import json
import re
import socket
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest

from scp_sdk.context import SiteConfig
from scp_sdk.errors import (
    ContextError,
    IdentityError,
    ScpError,
    StorageError,
    TransportError,
    ValidationError,
)
from scp_sdk.server import (
    BlobInMemory,
    BlobRedb,
    BlobSqlite,
    CorsAllowlist,
    CorsAnyOrigin,
    DhtDisabled,
    NatAuto,
    Node,
    NodeStartConfig,
    ReachDomain,
    ReachLocal,
    ReachNatTraversal,
    TlsAcme,
    TlsPlaintext,
    TlsSelfSigned,
    TlsTerminated,
)

# ---------------------------------------------------------------------------
# Helpers -- mock bridge objects
# ---------------------------------------------------------------------------


@dataclass
class _MockNodeHandle:
    """Mock for the opaque PyNodeHandle from _scp_core."""

    relay_url: str = "ws://127.0.0.1:9876/scp/v1"
    relay_port: int = 9876
    did: str = "did:dht:z6MkTestNode"
    is_shutdown: bool = False

    def shutdown(self) -> None:
        self.is_shutdown = True

    def enable_site_projection(
        self,
        context_id: str,
        admission: str,
        hostname: str,
        broadcast_key_hex: str | None = None,
        author_did: str | None = None,
        index_path: str | None = None,
        max_assets_per_deploy: int | None = None,
        max_deploy_size_bytes: int | None = None,
        deploy_retention_count: int | None = None,
        csp_override: str | None = None,
    ) -> None:
        """Mock: records call args for assertion."""
        self._last_enable_args = {
            "context_id": context_id,
            "broadcast_key_hex": broadcast_key_hex,
            "author_did": author_did,
            "admission": admission,
            "hostname": hostname,
            "index_path": index_path,
            "max_assets_per_deploy": max_assets_per_deploy,
            "max_deploy_size_bytes": max_deploy_size_bytes,
            "deploy_retention_count": deploy_retention_count,
            "csp_override": csp_override,
        }

    def commit_deploy(self, context_id: str, deploy_id: str) -> int:
        return 42

    def rollback_deploy(self, context_id: str, deploy_id: str) -> None:
        pass

    def disable_site_projection(self, context_id: str) -> None:
        pass


def _make_node(handle: _MockNodeHandle | None = None) -> Node:
    return Node(handle or _MockNodeHandle())


# ---------------------------------------------------------------------------
# enable_site_projection
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_enable_site_projection_delegates_to_handle() -> None:
    """enable_site_projection passes SiteConfig fields to the bridge handle."""
    handle = _MockNodeHandle()
    node = _make_node(handle)
    config = SiteConfig(
        hostname="mysite.example.com",
        index_path="/app.html",
        max_assets_per_deploy=5000,
        max_deploy_size_bytes=100_000_000,
        deploy_retention_count=4,
        csp_override="default-src 'self'",
    )

    await node.enable_site_projection(
        context_id="ctx-123",
        admission="open",
        config=config,
        broadcast_key_hex="ab" * 32,
        author_did="did:dht:z6MkAuthor",
    )

    assert handle._last_enable_args["context_id"] == "ctx-123"
    assert handle._last_enable_args["broadcast_key_hex"] == "ab" * 32
    assert handle._last_enable_args["author_did"] == "did:dht:z6MkAuthor"
    assert handle._last_enable_args["admission"] == "open"
    assert handle._last_enable_args["hostname"] == "mysite.example.com"
    assert handle._last_enable_args["index_path"] == "/app.html"
    assert handle._last_enable_args["max_assets_per_deploy"] == 5000
    assert handle._last_enable_args["max_deploy_size_bytes"] == 100_000_000
    assert handle._last_enable_args["deploy_retention_count"] == 4
    assert handle._last_enable_args["csp_override"] == "default-src 'self'"


@pytest.mark.asyncio
async def test_enable_site_projection_defaults_pass_none() -> None:
    """Default SiteConfig values result in None being passed to the bridge."""
    handle = _MockNodeHandle()
    node = _make_node(handle)
    config = SiteConfig(hostname="example.com")

    await node.enable_site_projection(
        context_id="ctx-456",
        admission="gated",
        config=config,
        broadcast_key_hex="cd" * 32,
        author_did="did:dht:z6MkAuthor2",
    )

    assert handle._last_enable_args["index_path"] is None
    assert handle._last_enable_args["max_assets_per_deploy"] is None
    assert handle._last_enable_args["max_deploy_size_bytes"] is None
    assert handle._last_enable_args["deploy_retention_count"] is None
    assert handle._last_enable_args["csp_override"] is None


@pytest.mark.asyncio
async def test_enable_site_projection_requires_config() -> None:
    """enable_site_projection raises TypeError when config is omitted."""
    node = _make_node()

    with pytest.raises(TypeError):
        await node.enable_site_projection(  # type: ignore[call-arg]
            context_id="ctx-789",
            admission="open",
        )


# ---------------------------------------------------------------------------
# commit_deploy
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_commit_deploy_returns_asset_count() -> None:
    """commit_deploy delegates to handle and returns the asset count."""
    node = _make_node()
    count = await node.commit_deploy("ctx-123", "deploy-abc")
    assert count == 42


@pytest.mark.asyncio
async def test_commit_deploy_propagates_errors() -> None:
    """commit_deploy propagates RuntimeError from the bridge."""
    handle = _MockNodeHandle()
    handle.commit_deploy = MagicMock(side_effect=RuntimeError("not projected"))
    node = _make_node(handle)

    with pytest.raises(RuntimeError, match="not projected"):
        await node.commit_deploy("ctx-bad", "deploy-xyz")


# ---------------------------------------------------------------------------
# rollback_deploy
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_rollback_deploy_delegates_to_handle() -> None:
    """rollback_deploy calls through to the bridge handle."""
    handle = _MockNodeHandle()
    handle.rollback_deploy = MagicMock()
    node = _make_node(handle)

    await node.rollback_deploy("ctx-123", "deploy-old")

    handle.rollback_deploy.assert_called_once_with("ctx-123", "deploy-old")


@pytest.mark.asyncio
async def test_rollback_deploy_propagates_errors() -> None:
    """rollback_deploy propagates RuntimeError from the bridge."""
    handle = _MockNodeHandle()
    handle.rollback_deploy = MagicMock(side_effect=RuntimeError("deploy not found"))
    node = _make_node(handle)

    with pytest.raises(RuntimeError, match="deploy not found"):
        await node.rollback_deploy("ctx-bad", "deploy-nope")


# ---------------------------------------------------------------------------
# disable_site_projection
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_disable_site_projection_delegates_to_handle() -> None:
    """disable_site_projection calls through to the bridge handle."""
    handle = _MockNodeHandle()
    handle.disable_site_projection = MagicMock()
    node = _make_node(handle)

    await node.disable_site_projection("ctx-123")

    handle.disable_site_projection.assert_called_once_with("ctx-123")


@pytest.mark.asyncio
async def test_disable_site_projection_is_noop_on_unprojected() -> None:
    """disable_site_projection does not raise on non-projected context."""
    node = _make_node()
    # Should not raise -- the mock simply returns None.
    await node.disable_site_projection("ctx-nonexistent")


# ---------------------------------------------------------------------------
# Node properties still work
# ---------------------------------------------------------------------------


def test_node_properties() -> None:
    """Node exposes relay_url, relay_port, did, is_shutdown from the handle."""
    node = _make_node()
    assert node.relay_url == "ws://127.0.0.1:9876/scp/v1"
    assert node.relay_port == 9876
    assert node.did == "did:dht:z6MkTestNode"
    assert node.is_shutdown is False


@pytest.mark.asyncio
async def test_node_context_manager_shutdown() -> None:
    """Node async context manager calls shutdown on exit."""
    handle = _MockNodeHandle()
    node = _make_node(handle)

    async with node:
        assert handle.is_shutdown is False

    assert handle.is_shutdown is True


# ---------------------------------------------------------------------------
# Identity portability — Node.start_in_memory / start_local
# ---------------------------------------------------------------------------


class _MockIdentity:
    """Minimal mock for scp_sdk.identity.Identity."""

    def __init__(self, did: str = "did:dht:z6MkTestIdentity") -> None:
        self.did = did


class _MockNative:
    """Test double for the raw bridge (exposed as ``SCP._native``).

    Lets us observe calls to ``node_start_in_memory`` / ``node_start_local``
    without monkey-patching the real (frozen) PyScp class.
    """

    def __init__(self) -> None:
        self.in_memory_calls: list[tuple[str | None]] = []
        self.local_calls: list[tuple[str, str | None, str | None]] = []

    def node_start_in_memory(self, identity_did: str | None = None) -> _MockNodeHandle:
        self.in_memory_calls.append((identity_did,))
        return _MockNodeHandle()

    def node_start_local(
        self,
        data_dir: str,
        identity_did: str | None = None,
        passphrase: str | None = None,
    ) -> _MockNodeHandle:
        self.local_calls.append((data_dir, identity_did, passphrase))
        return _MockNodeHandle()


class _MockSCP:
    """SDK-wrapper-shaped stand-in: exposes ``_native`` with the mock bridge.

    After #1549 Phase 4 PR 4, every SDK function dispatches on ``scp._native``,
    so tests pass a stand-in with the attribute wired to a _MockNative.
    """

    def __init__(self) -> None:
        self._native = _MockNative()


@pytest.mark.asyncio
async def test_start_in_memory_without_identity() -> None:
    """SCP.node_start_in_memory() without identity calls bridge with None."""
    from scp_sdk.scp import SCP

    scp = _MockSCP()
    node = await SCP.node_start_in_memory(scp)  # type: ignore[arg-type]
    assert isinstance(node, Node)
    assert scp._native.in_memory_calls == [(None,)]


@pytest.mark.asyncio
async def test_start_in_memory_with_identity() -> None:
    """SCP.node_start_in_memory(identity_did) passes the DID to the bridge."""
    from scp_sdk.scp import SCP

    scp = _MockSCP()
    identity = _MockIdentity("did:dht:z6MkPortable")
    node = await SCP.node_start_in_memory(scp, identity.did)  # type: ignore[arg-type]
    assert isinstance(node, Node)
    assert scp._native.in_memory_calls == [("did:dht:z6MkPortable",)]


@pytest.mark.asyncio
async def test_start_local_without_identity() -> None:
    """SCP.node_start_local(dir) without identity calls the bridge with None."""
    from scp_sdk.scp import SCP

    scp = _MockSCP()
    node = await SCP.node_start_local(scp, "/tmp/test-dir")  # type: ignore[arg-type]
    assert isinstance(node, Node)
    assert scp._native.local_calls == [("/tmp/test-dir", None, None)]


@pytest.mark.asyncio
async def test_start_local_with_identity() -> None:
    """SCP.node_start_local(dir, identity_did) passes the DID to the bridge."""
    from scp_sdk.scp import SCP

    scp = _MockSCP()
    identity = _MockIdentity("did:dht:z6MkPersist")
    node = await SCP.node_start_local(scp, "/tmp/test-dir", identity.did)  # type: ignore[arg-type]
    assert isinstance(node, Node)
    assert scp._native.local_calls == [("/tmp/test-dir", "did:dht:z6MkPersist", None)]


@pytest.mark.asyncio
async def test_start_local_with_passphrase() -> None:
    """SCP.node_start_local(dir, passphrase=...) passes passphrase to the bridge."""
    from scp_sdk.scp import SCP

    scp = _MockSCP()
    node = await SCP.node_start_local(scp, "/tmp/test-dir", None, "my-secret")  # type: ignore[arg-type]
    assert isinstance(node, Node)
    assert scp._native.local_calls == [("/tmp/test-dir", None, "my-secret")]


# ---------------------------------------------------------------------------
# enable_site_projection validation (#1405)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_enable_site_projection_broadcast_key_without_author_did_raises() -> None:
    """broadcast_key_hex without author_did raises ValueError."""
    node = _make_node()
    config = SiteConfig(hostname="example.com")

    with pytest.raises(ValueError, match="broadcast_key_hex requires author_did"):
        await node.enable_site_projection(
            context_id="ctx-123",
            admission="open",
            config=config,
            broadcast_key_hex="ab" * 32,
            author_did=None,
        )


@pytest.mark.asyncio
async def test_enable_site_projection_author_did_without_key_passes_through() -> None:
    """author_did without broadcast_key_hex is allowed (auto-resolve with author_did)."""
    handle = _MockNodeHandle()
    node = _make_node(handle)
    config = SiteConfig(hostname="example.com")

    # This should pass SDK validation and reach the bridge handle.
    await node.enable_site_projection(
        context_id="ctx-123",
        admission="open",
        config=config,
        broadcast_key_hex=None,
        author_did="did:dht:z6MkAuthor",
    )

    assert handle._last_enable_args["broadcast_key_hex"] is None
    assert handle._last_enable_args["author_did"] == "did:dht:z6MkAuthor"


@pytest.mark.asyncio
async def test_enable_site_projection_both_none_passes_through() -> None:
    """Both None is allowed (auto-resolve with node DID)."""
    handle = _MockNodeHandle()
    node = _make_node(handle)
    config = SiteConfig(hostname="example.com")

    await node.enable_site_projection(
        context_id="ctx-123",
        admission="open",
        config=config,
    )

    assert handle._last_enable_args["broadcast_key_hex"] is None
    assert handle._last_enable_args["author_did"] is None


# ---------------------------------------------------------------------------
# node_start (SCP-323): NodeStartConfig wire shape, delegation, error mapping
# ---------------------------------------------------------------------------

_REPO = Path(__file__).resolve().parents[3]

#: The bridge's ``NodeStartConfig`` source, which the wire-shape checks parse so
#: a field or arm added, renamed or removed on either side fails here.
_RUST_CONFIG = _REPO / "crates/scp-ffi/common/src/node_start_config.rs"

#: Each sum-typed field, the Rust enum that types it, and the Python arms.
_SUM_FIELDS: dict[str, tuple[str, tuple[type, ...]]] = {
    "reach": ("FfiReach", (ReachDomain, ReachNatTraversal, ReachLocal)),
    "blob_storage": ("FfiBlobBackend", (BlobInMemory, BlobRedb, BlobSqlite)),
    "tls": ("FfiTlsMode", (TlsSelfSigned, TlsAcme, TlsPlaintext, TlsTerminated)),
    "dht": ("FfiDhtMode", (DhtDisabled,)),
    "cors_origins": ("FfiCorsOrigins", (CorsAnyOrigin, CorsAllowlist)),
    "nat": ("FfiNat", (NatAuto,)),
}

_OPERATOR = "did:dht:z6MkNodeStartOperatorProbe"


def _rust_block(header: str) -> str:
    """Return the body of the Rust item in ``_RUST_CONFIG`` that ``header``
    opens."""
    source = _RUST_CONFIG.read_text()
    start = source.index(header) + len(header)
    return source[start : source.index("\n}\n", start)]


def _rust_struct_fields() -> list[tuple[str, bool]]:
    """``NodeStartConfig``'s fields in order, each with whether it is required
    (not an ``Option``)."""
    body = _rust_block("pub struct NodeStartConfig {")
    return [
        (name, not ty.startswith("Option<"))
        for name, ty in re.findall(r"^    pub (\w+): ([^\n]+),$", body, re.MULTILINE)
    ]


def _rust_enum_arms(enum: str) -> dict[str, list[str]]:
    """``enum``'s arms as wire ``kind`` values, each with its field names."""
    body = _rust_block(f"pub enum {enum} {{")
    arms: dict[str, list[str]] = {}
    for arm, fields in re.findall(r"^    (\w+) \{(.*?)\},$", body, re.MULTILINE | re.DOTALL):
        kind = re.sub(r"(?<!^)(?=[A-Z])", "_", arm).lower()
        arms[kind] = re.findall(r"^        (\w+): ", fields, re.MULTILINE)
    return arms


def _sample_arm(cls: type) -> Any:
    """An instance of arm ``cls`` with every field set."""
    values: dict[str, Any] = {
        "domain": "node.example.org",
        "path": "/var/lib/scp/blobs.db",
        "email": "ops@example.org",
        "origins": ["https://app.example.org"],
    }
    return cls(**{f.name: values[f.name] for f in dataclasses.fields(cls)})


def _config(**overrides: Any) -> NodeStartConfig:
    fields: dict[str, Any] = {
        "reach": ReachLocal(),
        "identity": _OPERATOR,
        "blob_storage": BlobInMemory(),
        "tls": TlsPlaintext(),
        "dht": DhtDisabled(),
        "cors_origins": CorsAnyOrigin(),
        "bind_addr": "127.0.0.1:0",
    }
    fields.update(overrides)
    return NodeStartConfig(**fields)


def test_node_start_config_fields_match_the_bridge_struct() -> None:
    """NodeStartConfig carries the bridge struct's fields, in order, with the
    same required and optional split."""
    rust = _rust_struct_fields()
    assert len(rust) == 10, rust
    python = [
        (f.name, f.default is dataclasses.MISSING) for f in dataclasses.fields(NodeStartConfig)
    ]
    assert python == rust


@pytest.mark.parametrize("field", list(_SUM_FIELDS))
def test_node_start_config_arms_match_the_bridge_enum(field: str) -> None:
    """Each sum type has exactly the bridge enum's arms, each with the same
    ``kind`` and the same fields."""
    enum, arms = _SUM_FIELDS[field]
    rust = _rust_enum_arms(enum)
    assert rust, f"no arms parsed from {enum}"
    python = {cls._KIND: [f.name for f in dataclasses.fields(cls)] for cls in arms}  # type: ignore[attr-defined]
    assert python == rust


def test_node_start_config_requires_every_bridge_required_field() -> None:
    """Omitting a required field raises TypeError, and an omitted optional field
    is None, which the bridge reads as absent."""
    full = {f.name: getattr(_config(), f.name) for f in dataclasses.fields(NodeStartConfig)}
    for name, required in _rust_struct_fields():
        partial = {k: v for k, v in full.items() if k != name}
        if required:
            with pytest.raises(TypeError, match=name):
                NodeStartConfig(**partial)
        else:
            assert getattr(NodeStartConfig(**partial), name) is None


def test_node_start_config_takes_named_fields_only() -> None:
    with pytest.raises(TypeError):
        NodeStartConfig(ReachLocal(), _OPERATOR)  # type: ignore[misc]


def test_node_start_config_wire_is_the_bridge_shape_field_for_field() -> None:
    """to_wire emits every bridge field under its own name and in the bridge's
    order, each arm tagged ``kind``, and an absent optional as null."""
    full = _config(
        reach=ReachDomain(domain="node.example.org"),
        blob_storage=BlobRedb(path="/var/lib/scp/blobs.redb"),
        tls=TlsAcme(email="ops@example.org"),
        cors_origins=CorsAllowlist(origins=["https://app.example.org"]),
        http_bind_addr="0.0.0.0:8443",
        nat=NatAuto(),
        projection_rate_limit=30,
    )
    assert full.to_wire() == {
        "reach": {"kind": "domain", "domain": "node.example.org"},
        "identity": _OPERATOR,
        "blob_storage": {"kind": "redb", "path": "/var/lib/scp/blobs.redb"},
        "tls": {"kind": "acme", "email": "ops@example.org"},
        "dht": {"kind": "disabled"},
        "cors_origins": {"kind": "allowlist", "origins": ["https://app.example.org"]},
        "bind_addr": "127.0.0.1:0",
        "http_bind_addr": "0.0.0.0:8443",
        "nat": {"kind": "auto"},
        "projection_rate_limit": 30,
    }
    minimal = _config(bind_addr=None)
    assert json.loads(minimal.to_json()) == {
        "reach": {"kind": "local"},
        "identity": _OPERATOR,
        "blob_storage": {"kind": "in_memory"},
        "tls": {"kind": "plaintext"},
        "dht": {"kind": "disabled"},
        "cors_origins": {"kind": "any_origin"},
        "bind_addr": None,
        "http_bind_addr": None,
        "nat": None,
        "projection_rate_limit": None,
    }
    assert list(minimal.to_wire()) == [name for name, _ in _rust_struct_fields()]


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("tls", ReachLocal()),
        ("reach", "local"),
        ("cors_origins", None),
        ("dht", {"kind": "disabled"}),
        ("nat", TlsPlaintext()),
    ],
)
def test_node_start_config_rejects_a_value_outside_its_arms(field: str, value: Any) -> None:
    """A sum-typed field holding anything but one of its arms raises
    StorageError SCP-STORAGE-8007."""
    with pytest.raises(StorageError) as raised:
        _config(**{field: value}).to_json()
    assert raised.value.code == "SCP-STORAGE-8007"
    assert field in raised.value.message


def test_node_start_config_rejects_a_value_json_cannot_encode() -> None:
    with pytest.raises(StorageError) as raised:
        _config(blob_storage=BlobRedb(path=Path("/tmp/blobs.redb"))).to_json()  # type: ignore[arg-type]
    assert raised.value.code == "SCP-STORAGE-8007"


class _NodeStartNative:
    """Raw-bridge double for ``SCP.node_start``: records each config string,
    then returns a handle or raises ``error``."""

    def __init__(self, error: Exception | None = None) -> None:
        self.calls: list[str] = []
        self.error = error

    def node_start(self, config_json: str) -> _MockNodeHandle:
        self.calls.append(config_json)
        if self.error is not None:
            raise self.error
        return _MockNodeHandle(did=_OPERATOR)


class _NodeStartSCP:
    def __init__(self, native: _NodeStartNative) -> None:
        self._native = native


@pytest.mark.asyncio
async def test_node_start_sends_the_encoded_config_and_returns_a_node() -> None:
    """SCP.node_start calls the bridge's node_start once with the config's JSON
    and wraps the handle in a Node."""
    from scp_sdk.scp import SCP

    native = _NodeStartNative()
    config = _config(tls=TlsAcme(), projection_rate_limit=5)
    node = await SCP.node_start(_NodeStartSCP(native), config)  # type: ignore[arg-type]
    assert isinstance(node, Node)
    assert node.did == _OPERATOR
    assert len(native.calls) == 1
    assert json.loads(native.calls[0]) == config.to_wire()


@pytest.mark.asyncio
async def test_node_start_rejects_an_unencodable_config_before_the_bridge() -> None:
    from scp_sdk.scp import SCP

    native = _NodeStartNative()
    with pytest.raises(StorageError):
        await SCP.node_start(_NodeStartSCP(native), _config(tls="plaintext"))  # type: ignore[arg-type]
    assert native.calls == []


def _bridge_class(name: str) -> type[Exception]:
    """A stand-in for the PyO3 bridge's native exception class ``name``
    (``crates/scp-ffi/src/error.rs``), unrelated to the SDK's classes."""
    return type(name, (Exception,), {})


#: Every row of sdk-common.md §"Node start error codes": the code, the native
#: class `server_error_class` gives it on the PyO3 bridge, and the SDK class of
#: the code's category.
_NODE_START_CODES: list[tuple[str, str, type[ScpError]]] = [
    ("SCP-STORAGE-8007", "ValidationError", StorageError),
    ("SCP-STORAGE-8008", "ValidationError", StorageError),
    ("SCP-STORAGE-8009", "ValidationError", StorageError),
    ("SCP-IDENT-1063", "IdentityError", IdentityError),
    ("SCP-TRANS-5051", "TransportError", TransportError),
    ("SCP-TRANS-5052", "TransportError", TransportError),
    ("SCP-TRANS-5054", "TransportError", TransportError),
    ("SCP-TRANS-5050", "TransportError", TransportError),
    ("SCP-IDENT-1001", "IdentityError", IdentityError),
    ("SCP-VALID-7004", "ValidationError", ValidationError),
    ("SCP-CTX-2053", "ContextError", ContextError),
    ("SCP-TRANS-5055", "TransportError", TransportError),
    ("SCP-TRANS-5056", "TransportError", TransportError),
]


def test_node_start_code_table_covers_every_sdk_common_row() -> None:
    """The table above names exactly the codes of sdk-common.md §"Node start
    error codes"."""
    doc = (_REPO / ".docs/standards/sdk-common.md").read_text()
    section = doc[doc.index("### Node start error codes") :]
    section = section[: section.index("\n### ")]
    rows = re.findall(r"^\| [^|]+ \| `(SCP-[A-Z]+-\d+)` \|", section, re.MULTILINE)
    assert len(rows) == len(set(rows))
    assert sorted(rows) == sorted(code for code, _, _ in _NODE_START_CODES)


@pytest.mark.asyncio
@pytest.mark.parametrize(("code", "bridge_class", "sdk_class"), _NODE_START_CODES)
async def test_node_start_raises_the_typed_error_of_each_code(
    code: str, bridge_class: str, sdk_class: type[ScpError]
) -> None:
    """A bridge failure with a node start code raises the SDK error of the code's
    category, with the code preserved and the bridge error as its cause."""
    from scp_sdk.scp import SCP

    bridge_error = _bridge_class(bridge_class)(f"[{code}] node start failed")
    native = _NodeStartNative(bridge_error)
    with pytest.raises(ScpError) as raised:
        await SCP.node_start(_NodeStartSCP(native), _config())  # type: ignore[arg-type]
    assert type(raised.value) is sdk_class
    assert raised.value.code == code
    assert raised.value.__cause__ is bridge_error


# ---------------------------------------------------------------------------
# node_start against the built extension (the `scp` fixture)
# ---------------------------------------------------------------------------


async def _start_error(scp: Any, config: NodeStartConfig) -> ScpError:
    try:
        node = await scp.node_start(config)
    except ScpError as exc:
        return exc
    await node.shutdown()
    pytest.fail(f"node_start must fail for {config}")


@pytest.mark.asyncio
async def test_node_start_starts_and_stops_a_node_on_the_extension(scp: Any) -> None:
    """A valid config starts a node under the operator identity, and shutdown
    stops it."""
    from tests.harness_custody import create_in_memory_identity

    operator = await create_in_memory_identity(scp)
    node = await scp.node_start(_config(identity=operator.did))
    try:
        assert isinstance(node, Node)
        assert node.did == operator.did
        assert node.relay_port > 0
        assert node.relay_url.startswith("ws://127.0.0.1:")
        assert node.is_shutdown is False
    finally:
        await node.shutdown()
    assert node.is_shutdown is True


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "arm",
    [cls for _, arms in _SUM_FIELDS.values() for cls in arms],
    ids=lambda cls: cls.__name__,
)
async def test_node_start_extension_reads_every_arm(scp: Any, arm: type) -> None:
    """The extension parses a config carrying each arm and every optional field:
    an unregistered operator fails at identity resolution (SCP-IDENT-1063),
    which runs only after the parse that rejects an unknown key or ``kind``
    with SCP-STORAGE-8007."""
    field = next(f for f, (_, arms) in _SUM_FIELDS.items() if arm in arms)
    overrides: dict[str, Any] = {
        "http_bind_addr": "127.0.0.1:0",
        "nat": NatAuto(),
        "projection_rate_limit": 5,
    }
    overrides[field] = _sample_arm(arm)
    err = await _start_error(scp, _config(**overrides))
    assert (type(err), err.code) == (IdentityError, "SCP-IDENT-1063"), err


def test_node_start_extension_rejects_a_key_outside_the_bridge_shape(scp: Any) -> None:
    """Control for the parse check above: the extension refuses a config with a
    key the bridge struct lacks, so a misnamed wire key could not pass it."""
    wire = _config().to_wire()
    wire["bind_address"] = wire.pop("bind_addr")
    with pytest.raises(Exception, match=r"^\[SCP-STORAGE-8007\]"):
        scp._native.node_start(json.dumps(wire))


@pytest.mark.asyncio
async def test_node_start_extension_raises_each_reachable_code(scp: Any, tmp_path: Path) -> None:
    """Each node start code a caller can reach through the extension raises the
    typed SDK error carrying that code."""
    from tests.harness_custody import create_in_memory_identity

    operator = (await create_in_memory_identity(scp)).did
    regular_file = tmp_path / "regular-file"
    regular_file.write_bytes(b"x")
    under_file = str(regular_file / "sub" / "blobs.redb")
    taken = socket.socket()
    taken.bind(("127.0.0.1", 0))
    taken.listen()
    taken_addr = f"127.0.0.1:{taken.getsockname()[1]}"
    cases: list[tuple[str, NodeStartConfig, type[ScpError], str]] = [
        ("malformed DID", _config(identity="not-a-did"), StorageError, "SCP-STORAGE-8007"),
        (
            "domain with plaintext",
            _config(identity=operator, reach=ReachDomain(domain="node.example.org")),
            StorageError,
            "SCP-STORAGE-8007",
        ),
        (
            "zero projection rate limit",
            _config(identity=operator, projection_rate_limit=0),
            StorageError,
            "SCP-STORAGE-8007",
        ),
        (
            "blob parent under a regular file",
            _config(identity=operator, blob_storage=BlobRedb(path=under_file)),
            StorageError,
            "SCP-STORAGE-8008",
        ),
        ("unregistered operator", _config(), IdentityError, "SCP-IDENT-1063"),
        (
            "relay bind on a taken port",
            _config(identity=operator, bind_addr=taken_addr),
            TransportError,
            "SCP-TRANS-5051",
        ),
    ]
    try:
        for label, config, sdk_class, code in cases:
            err = await _start_error(scp, config)
            assert (type(err), err.code) == (sdk_class, code), (label, err)
    finally:
        taken.close()

    first = await scp.node_start(_config(identity=operator))
    try:
        err = await _start_error(scp, _config(identity=operator))
        assert (type(err), err.code) == (TransportError, "SCP-TRANS-5056"), err
    finally:
        await first.shutdown()
