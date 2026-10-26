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
from collections.abc import Iterator
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
    UcanPermissionError,
    ValidationError,
)
from scp_sdk.identity import Identity
from scp_sdk.server import (
    _ARMS,
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
    TlsAcme,
    TlsPlaintext,
)
from tests.harness_custody import create_in_memory_native_identity

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


#: The error a shipped extension's dev pair raises (SCP-327), in the form the
#: PyO3 bridge renders it.
_DEV_START_UNAVAILABLE = (
    "[SCP-TRANS-5055] transport error: "
    "development node start is unavailable in this build; use node_start"
)


class _ShippedDevPairNative:
    """The dev pair of a shipped extension: both calls raise SCP-TRANS-5055."""

    def __init__(self) -> None:
        self.error = Exception(_DEV_START_UNAVAILABLE)

    def node_start_in_memory(self, identity_did: str | None = None) -> _MockNodeHandle:
        raise self.error

    def node_start_local(
        self,
        data_dir: str,
        identity_did: str | None = None,
        passphrase: str | None = None,
    ) -> _MockNodeHandle:
        raise self.error


@pytest.mark.asyncio
async def test_dev_pair_on_a_shipped_extension_raises_transport_error_5055() -> None:
    """A shipped extension refuses the dev pair with SCP-TRANS-5055, and the SDK
    raises it as ``TransportError`` with the code preserved and the bridge
    error as its cause."""
    from scp_sdk.scp import SCP

    scp = _MockSCP()
    native = _ShippedDevPairNative()
    scp._native = native  # type: ignore[assignment]
    calls = [
        SCP.node_start_in_memory(scp),  # type: ignore[arg-type]
        SCP.node_start_local(scp, "/tmp/test-dir", None, "my-secret"),  # type: ignore[arg-type]
    ]
    for call in calls:
        with pytest.raises(ScpError) as raised:
            await call
        assert type(raised.value) is TransportError
        assert raised.value.code == "SCP-TRANS-5055"
        assert raised.value.__cause__ is native.error


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

#: The bridge's wire-shape fixture: every arm of every sum type, a full config,
#: and the optional fields. The ``node_start_config.rs`` unit tests check it
#: against the Rust types, so a field or arm added, renamed or made optional in
#: Rust fails there until the fixture follows, and fails here until the Python
#: types follow.
_WIRE = json.loads(
    (_REPO / "crates/scp-ffi/common/tests/fixtures/node_start_config.json").read_text()
)


@pytest.fixture
def operator(scp: Any) -> Identity:
    """An identity registered on the ``scp`` instance."""
    return Identity(create_in_memory_native_identity(scp._native))


@pytest.fixture
def stranger(scp: Any) -> Iterator[Identity]:
    """An identity registered on another instance, not on ``scp``."""
    from scp_sdk import SCP

    other = SCP(storage={"type": "in_memory"})
    try:
        yield Identity(create_in_memory_native_identity(other._native))
    finally:
        other.__exit__(None, None, None)


def _arm_class(field: str, kind: str) -> type:
    """The Python arm of sum-typed ``field`` whose ``kind`` is ``kind``."""
    matches = [cls for cls in _ARMS[field] if cls._KIND == kind]
    assert len(matches) == 1, (field, kind, _ARMS[field])
    return matches[0]


def _arm_from_wire(field: str, wire: dict[str, Any]) -> Any:
    """The Python arm a fixture entry describes, built from its fields."""
    return _arm_class(field, wire["kind"])(**{k: v for k, v in wire.items() if k != "kind"})


def _fixture_config(identity: Identity) -> NodeStartConfig:
    """The fixture's full config, as a Python config under ``identity``."""
    values = {
        name: (_arm_from_wire(name, value) if name in _ARMS else value)
        for name, value in _WIRE["config"].items()
    }
    values["identity"] = identity
    return NodeStartConfig(**values)


def _config(identity: Identity, **overrides: Any) -> NodeStartConfig:
    fields: dict[str, Any] = {
        "reach": ReachLocal(),
        "identity": identity,
        "blob_storage": BlobInMemory(),
        "tls": TlsPlaintext(),
        "dht": DhtDisabled(),
        "cors_origins": CorsAnyOrigin(),
        "bind_addr": "127.0.0.1:0",
    }
    fields.update(overrides)
    return NodeStartConfig(**fields)


def _defaults_to_none(field: dataclasses.Field[Any]) -> bool:
    return field.default is None and field.default_factory is dataclasses.MISSING


def test_node_start_config_fields_match_the_bridge_struct() -> None:
    """NodeStartConfig carries the bridge struct's fields, in order, and a field
    is optional (defaults to None) exactly when the bridge's is."""
    fields = dataclasses.fields(NodeStartConfig)
    assert [f.name for f in fields] == _WIRE["fields"]
    optional = [f.name for f in fields if _defaults_to_none(f)]
    assert optional == _WIRE["optional_fields"]
    required = [f.name for f in fields if f.default is dataclasses.MISSING]
    assert required == [n for n in _WIRE["fields"] if n not in _WIRE["optional_fields"]]


def test_node_start_config_sum_fields_match_the_bridge() -> None:
    """The fields typed by an arm alias are exactly the bridge's enum-typed
    fields."""
    assert sorted(_ARMS) == sorted(_WIRE["arms"])


@pytest.mark.parametrize("field", sorted(_WIRE["arms"]))
def test_node_start_config_arms_match_the_bridge_enum(field: str) -> None:
    """Each sum type has exactly the bridge enum's arms; each arm built from the
    fixture entry emits that entry, and an arm field is optional exactly when
    the bridge's is."""
    entries = _WIRE["arms"][field]
    assert sorted(cls._KIND for cls in _ARMS[field]) == sorted(e["kind"] for e in entries)
    for entry in entries:
        arm = _arm_from_wire(field, entry)
        assert arm._wire() == entry
        optional = _WIRE["optional_arm_fields"].get(field, {}).get(entry["kind"], [])
        fields = dataclasses.fields(type(arm))
        assert [f.name for f in fields if _defaults_to_none(f)] == optional, entry
        assert all(f.default is dataclasses.MISSING for f in fields if f.name not in optional), (
            entry
        )


def test_node_start_config_requires_every_bridge_required_field(operator: Identity) -> None:
    """Omitting a required field raises TypeError, and an omitted optional field
    is None, which the bridge reads as absent."""
    full = _fixture_config(operator)
    values = {f.name: getattr(full, f.name) for f in dataclasses.fields(NodeStartConfig)}
    for name in _WIRE["fields"]:
        partial = {k: v for k, v in values.items() if k != name}
        if name in _WIRE["optional_fields"]:
            assert getattr(NodeStartConfig(**partial), name) is None
        else:
            with pytest.raises(TypeError, match=name):
                NodeStartConfig(**partial)


def test_node_start_config_takes_named_fields_only(operator: Identity) -> None:
    with pytest.raises(TypeError):
        NodeStartConfig(ReachLocal(), operator)  # type: ignore[misc]


def test_node_start_config_wire_is_the_bridge_shape_field_for_field(operator: Identity) -> None:
    """_to_wire emits the fixture's full config field for field and in the
    bridge's order, with the identity lowered to its DID; an absent optional is
    null."""
    expected = {**_WIRE["config"], "identity": operator.did}
    wire = _fixture_config(operator)._to_wire()
    assert wire == expected
    assert list(wire) == _WIRE["fields"]
    minimal = NodeStartConfig(
        **{
            name: value
            for name, value in vars(_fixture_config(operator)).items()
            if name not in _WIRE["optional_fields"]
        }
    )
    assert json.loads(minimal._to_json()) == {
        **{k: v for k, v in expected.items() if k not in _WIRE["optional_fields"]},
        **dict.fromkeys(_WIRE["optional_fields"]),
    }


def test_node_start_config_lowers_a_path_like_blob_path(operator: Identity) -> None:
    """A pathlib.Path blob path is accepted and sent as its string."""
    for arm in (BlobRedb, BlobSqlite):
        config = _config(operator, blob_storage=arm(path=Path("/var/lib/scp/blobs.db")))
        wire = json.loads(config._to_json())["blob_storage"]
        assert wire == {"kind": arm._KIND, "path": "/var/lib/scp/blobs.db"}


@pytest.mark.parametrize(
    "identity",
    ["did:dht:z6MkNodeStartOperatorProbe", None, object()],
    ids=["did-string", "none", "object"],
)
def test_node_start_config_rejects_an_identity_that_is_not_an_identity(identity: Any) -> None:
    """An identity that is not an scp_sdk.Identity raises ValidationError
    SCP-VALID-7005 naming the expected type."""
    with pytest.raises(ValidationError) as raised:
        _config(identity)._to_json()
    assert raised.value.code == "SCP-VALID-7005"
    assert "scp_sdk.Identity" in raised.value.message


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
def test_node_start_config_rejects_a_value_outside_its_arms(
    operator: Identity, field: str, value: Any
) -> None:
    """A sum-typed field holding anything but one of its arms raises
    StorageError SCP-STORAGE-8007."""
    with pytest.raises(StorageError) as raised:
        _config(operator, **{field: value})._to_json()
    assert raised.value.code == "SCP-STORAGE-8007"
    assert field in raised.value.message


@pytest.mark.parametrize(
    "overrides",
    [
        {"cors_origins": CorsAllowlist(origins=[b"https://app.example.org"])},  # type: ignore[list-item]
        {"projection_rate_limit": float("nan")},
    ],
    ids=["bytes", "nan"],
)
def test_node_start_config_rejects_a_value_json_cannot_encode(
    operator: Identity, overrides: dict[str, Any]
) -> None:
    with pytest.raises(StorageError) as raised:
        _config(operator, **overrides)._to_json()
    assert raised.value.code == "SCP-STORAGE-8007"


class _NodeStartNative:
    """Raw-bridge double for ``SCP.node_start``: records each config string,
    then returns a handle or raises ``error``."""

    def __init__(self, did: str, error: Exception | None = None) -> None:
        self.calls: list[str] = []
        self.handles: list[Any] = []
        self.did = did
        self.error = error

    def node_start(self, config_json: str, identity: Any) -> _MockNodeHandle:
        self.calls.append(config_json)
        self.handles.append(identity)
        if self.error is not None:
            raise self.error
        return _MockNodeHandle(did=self.did)


class _NodeStartSCP:
    def __init__(self, native: _NodeStartNative) -> None:
        self._native = native


@pytest.mark.asyncio
async def test_node_start_sends_the_encoded_config_and_returns_a_node(operator: Identity) -> None:
    """SCP.node_start calls the bridge's node_start once with the config's JSON
    and wraps the handle in a Node."""
    from scp_sdk.scp import SCP

    native = _NodeStartNative(operator.did)
    config = _config(operator, tls=TlsAcme(), projection_rate_limit=5)
    node = await SCP.node_start(_NodeStartSCP(native), config)  # type: ignore[arg-type]
    assert isinstance(node, Node)
    assert node.did == operator.did
    assert len(native.calls) == 1
    assert json.loads(native.calls[0]) == config._to_wire()
    assert native.handles == [operator._raw_handle]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("config", "error", "code"),
    [
        ("not-a-config", ValidationError, "SCP-VALID-7005"),
        ("bad-identity", ValidationError, "SCP-VALID-7005"),
        ("bad-arm", StorageError, "SCP-STORAGE-8007"),
    ],
)
async def test_node_start_rejects_a_bad_config_before_the_bridge(
    operator: Identity, config: str, error: type[ScpError], code: str
) -> None:
    """A value that is not a config, an identity that is not an Identity, and
    an arm outside its type each raise their typed error, and the bridge is
    never called."""
    from scp_sdk.scp import SCP

    value: Any = {
        "not-a-config": _WIRE["config"],
        "bad-identity": _config(operator.did),  # type: ignore[arg-type]
        "bad-arm": _config(operator, tls="plaintext"),
    }[config]
    native = _NodeStartNative(operator.did)
    with pytest.raises(error) as raised:
        await SCP.node_start(_NodeStartSCP(native), value)  # type: ignore[arg-type]
    assert raised.value.code == code
    assert native.calls == []


#: Every row of sdk-common.md §"Node start error codes": the code and the SDK
#: class of its category.
_NODE_START_CODES: list[tuple[str, type[ScpError]]] = [
    ("SCP-STORAGE-8007", StorageError),
    ("SCP-STORAGE-8008", StorageError),
    ("SCP-STORAGE-8009", StorageError),
    ("SCP-IDENT-1063", IdentityError),
    ("SCP-IDENT-1100", IdentityError),
    ("SCP-TRANS-5051", TransportError),
    ("SCP-TRANS-5052", TransportError),
    ("SCP-TRANS-5054", TransportError),
    ("SCP-TRANS-5050", TransportError),
    ("SCP-IDENT-1001", IdentityError),
    ("SCP-VALID-7004", ValidationError),
    ("SCP-CTX-2053", ContextError),
    ("SCP-TRANS-5055", TransportError),
    ("SCP-TRANS-5056", TransportError),
    ("SCP-PERM-3030", UcanPermissionError),
]


def test_node_start_code_table_covers_every_sdk_common_row() -> None:
    """The table above names exactly the codes of sdk-common.md §"Node start
    error codes"."""
    doc = (_REPO / ".docs/standards/sdk-common.md").read_text()
    section = doc[doc.index("### Node start error codes") :]
    section = section[: section.index("\n### ")]
    rows = re.findall(r"^\| [^|]+ \| `(SCP-[A-Z]+-\d+)` \|", section, re.MULTILINE)
    assert len(rows) == len(set(rows))
    assert sorted(rows) == sorted(code for code, _ in _NODE_START_CODES)


@pytest.mark.asyncio
@pytest.mark.parametrize(("code", "sdk_class"), _NODE_START_CODES)
async def test_node_start_raises_the_typed_error_of_each_code(
    operator: Identity, code: str, sdk_class: type[ScpError]
) -> None:
    """A bridge failure with a node start code raises the SDK error of the code's
    category, with the code preserved and the bridge error as its cause. The
    SDK classifies by the code alone, so the bridge exception's own class does
    not enter into it."""
    from scp_sdk.scp import SCP

    bridge_error = Exception(f"[{code}] node start failed")
    native = _NodeStartNative(operator.did, bridge_error)
    with pytest.raises(ScpError) as raised:
        await SCP.node_start(_NodeStartSCP(native), _config(operator))  # type: ignore[arg-type]
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
async def test_node_start_starts_and_stops_a_node_on_the_extension(
    scp: Any, operator: Identity
) -> None:
    """A valid config starts a node under the operator identity, and shutdown
    stops it."""
    node = await scp.node_start(_config(operator))
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
async def test_dev_pair_starts_a_node_on_the_testing_extension(
    scp: Any, operator: Identity, tmp_path: Path
) -> None:
    """The SDK suite runs against an extension built with ``testing``, where the
    dev pair still starts a node (SCP-327 cuts it only from shipped builds)."""
    node = await scp.node_start_in_memory()
    try:
        assert node.did.startswith("did:")
        assert node.relay_port > 0
    finally:
        await node.shutdown()
    assert node.is_shutdown is True

    node = await scp.node_start_local(str(tmp_path / "node"), operator.did)
    try:
        assert node.did == operator.did
        assert node.relay_port > 0
    finally:
        await node.shutdown()
    assert node.is_shutdown is True


@pytest.mark.parametrize(
    ("field", "entry"),
    [(field, entry) for field, entries in _WIRE["arms"].items() for entry in entries],
    ids=lambda v: v if isinstance(v, str) else v["kind"],
)
def test_node_start_extension_reads_every_arm(
    scp: Any, operator: Identity, stranger: Identity, field: str, entry: dict[str, Any]
) -> None:
    """The extension parses a config carrying each arm and every optional field:
    a config naming an operator not registered on the instance fails at
    identity resolution (SCP-IDENT-1063), which runs only after the parse that
    rejects an unknown key or ``kind`` with SCP-STORAGE-8007. The handle passed
    is the instance's own, so the ADR-048 check before the parse passes."""
    overrides: dict[str, Any] = {
        "http_bind_addr": "127.0.0.1:0",
        "nat": NatAuto(),
        "projection_rate_limit": 5,
        field: _arm_from_wire(field, entry),
    }
    wire = _config(stranger, **overrides)._to_wire()
    with pytest.raises(Exception, match=r"^\[SCP-IDENT-1063\]"):
        scp._native.node_start(json.dumps(wire), operator._raw_handle)


def test_node_start_extension_rejects_a_key_outside_the_bridge_shape(
    scp: Any, operator: Identity
) -> None:
    """Control for the parse check above: the extension refuses a config with a
    key the bridge struct lacks, so a misnamed wire key could not pass it."""
    wire = _config(operator)._to_wire()
    wire["bind_address"] = wire.pop("bind_addr")
    with pytest.raises(Exception, match=r"^\[SCP-STORAGE-8007\]"):
        scp._native.node_start(json.dumps(wire), operator._raw_handle)


@pytest.mark.asyncio
async def test_node_start_extension_raises_8007_8008_3030_5051_and_5056(
    scp: Any, operator: Identity, stranger: Identity, tmp_path: Path
) -> None:
    """The extension raises SCP-STORAGE-8007, SCP-STORAGE-8008, SCP-PERM-3030,
    SCP-TRANS-5051 and SCP-TRANS-5056 as the typed SDK error carrying each code.
    An operator identity another ``SCP`` instance minted is SCP-PERM-3030
    (ADR-048), as on every bridge.

    No config makes the extension raise the other node start codes from a test:

    - ``SCP-STORAGE-8009`` is a core node storage error. The node writes to the
      ``SCP`` instance's own storage, which the config does not name, and the
      in-memory instance store a test builds does not fail.
    - ``SCP-TRANS-5052`` is a TLS provisioning failure. A self-signed
      certificate is generated for any domain, and ACME needs port 80 and a
      reachable certificate authority, so its outcome depends on the network.
    - ``SCP-TRANS-5054`` is a serve or NAT traversal failure. ``node_start``
      does not bind the HTTP server (a taken ``http_bind_addr`` starts), and
      NAT traversal fails only when its STUN exchange over the network does.

    The table test above shows each of these codes raises its typed error.
    """
    regular_file = tmp_path / "regular-file"
    regular_file.write_bytes(b"x")
    taken = socket.socket()
    taken.bind(("127.0.0.1", 0))
    taken.listen()
    taken_addr = f"127.0.0.1:{taken.getsockname()[1]}"
    cases: list[tuple[str, NodeStartConfig, type[ScpError], str]] = [
        (
            "domain with plaintext",
            _config(operator, reach=ReachDomain(domain="node.example.org")),
            StorageError,
            "SCP-STORAGE-8007",
        ),
        (
            "zero projection rate limit",
            _config(operator, projection_rate_limit=0),
            StorageError,
            "SCP-STORAGE-8007",
        ),
        (
            "malformed bind address",
            _config(operator, bind_addr="not-an-address"),
            StorageError,
            "SCP-STORAGE-8007",
        ),
        (
            "blob parent under a regular file",
            _config(operator, blob_storage=BlobRedb(path=regular_file / "sub" / "blobs.redb")),
            StorageError,
            "SCP-STORAGE-8008",
        ),
        (
            "operator from another SCP instance",
            _config(stranger),
            UcanPermissionError,
            "SCP-PERM-3030",
        ),
        (
            "relay bind on a taken port",
            _config(operator, bind_addr=taken_addr),
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

    first = await scp.node_start(_config(operator))
    try:
        err = await _start_error(scp, _config(operator))
        assert (type(err), err.code) == (TransportError, "SCP-TRANS-5056"), err
    finally:
        await first.shutdown()
