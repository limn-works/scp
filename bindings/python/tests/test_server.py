"""Unit tests for Node broadcast deployment lifecycle (SCP-296).

Tests mock the ``_scp_core`` bridge layer; no Rust extension required.

See spec section 18.11.8 and ``.docs/prds/http-features.json`` SCP-296.
"""

from __future__ import annotations

from dataclasses import dataclass
from unittest.mock import MagicMock

import pytest

from scp_sdk.context import SiteConfig
from scp_sdk.server import Node

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


@pytest.mark.asyncio
async def test_start_in_memory_without_identity() -> None:
    """start_in_memory() without identity calls bridge with None."""
    import _scp_core

    original = _scp_core.py_node_start_in_memory
    calls: list[tuple[str | None]] = []

    def mock_start(identity_did: str | None = None) -> _MockNodeHandle:
        calls.append((identity_did,))
        return _MockNodeHandle()

    _scp_core.py_node_start_in_memory = mock_start
    try:
        node = await Node.start_in_memory()
        assert isinstance(node, Node)
        assert len(calls) == 1
        assert calls[0] == (None,)
    finally:
        _scp_core.py_node_start_in_memory = original


@pytest.mark.asyncio
async def test_start_in_memory_with_identity() -> None:
    """start_in_memory(identity) passes identity.did to bridge."""
    import _scp_core

    original = _scp_core.py_node_start_in_memory
    calls: list[tuple[str | None]] = []

    def mock_start(identity_did: str | None = None) -> _MockNodeHandle:
        calls.append((identity_did,))
        return _MockNodeHandle()

    _scp_core.py_node_start_in_memory = mock_start
    try:
        identity = _MockIdentity("did:dht:z6MkPortable")
        node = await Node.start_in_memory(identity=identity)
        assert isinstance(node, Node)
        assert len(calls) == 1
        assert calls[0] == ("did:dht:z6MkPortable",)
    finally:
        _scp_core.py_node_start_in_memory = original


@pytest.mark.asyncio
async def test_start_local_without_identity() -> None:
    """start_local(dir) without identity calls bridge with None."""
    import _scp_core

    original = _scp_core.py_node_start_local
    calls: list[tuple[str, str | None]] = []

    def mock_start(data_dir: str, identity_did: str | None = None) -> _MockNodeHandle:
        calls.append((data_dir, identity_did))
        return _MockNodeHandle()

    _scp_core.py_node_start_local = mock_start
    try:
        node = await Node.start_local("/tmp/test-dir")
        assert isinstance(node, Node)
        assert len(calls) == 1
        assert calls[0] == ("/tmp/test-dir", None)
    finally:
        _scp_core.py_node_start_local = original


@pytest.mark.asyncio
async def test_start_local_with_identity() -> None:
    """start_local(dir, identity) passes identity.did to bridge."""
    import _scp_core

    original = _scp_core.py_node_start_local
    calls: list[tuple[str, str | None]] = []

    def mock_start(data_dir: str, identity_did: str | None = None) -> _MockNodeHandle:
        calls.append((data_dir, identity_did))
        return _MockNodeHandle()

    _scp_core.py_node_start_local = mock_start
    try:
        identity = _MockIdentity("did:dht:z6MkPersist")
        node = await Node.start_local("/tmp/test-dir", identity=identity)
        assert isinstance(node, Node)
        assert len(calls) == 1
        assert calls[0] == ("/tmp/test-dir", "did:dht:z6MkPersist")
    finally:
        _scp_core.py_node_start_local = original


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
