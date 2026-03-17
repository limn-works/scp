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
        broadcast_key_hex: str,
        author_did: str,
        admission: str,
        hostname: str,
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
        broadcast_key_hex="ab" * 32,
        author_did="did:dht:z6MkAuthor",
        admission="open",
        config=config,
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
        broadcast_key_hex="cd" * 32,
        author_did="did:dht:z6MkAuthor2",
        admission="gated",
        config=config,
    )

    assert handle._last_enable_args["index_path"] is None
    assert handle._last_enable_args["max_assets_per_deploy"] is None
    assert handle._last_enable_args["max_deploy_size_bytes"] is None
    assert handle._last_enable_args["deploy_retention_count"] is None
    assert handle._last_enable_args["csp_override"] is None


@pytest.mark.asyncio
async def test_enable_site_projection_requires_config() -> None:
    """enable_site_projection raises ValueError when config is None."""
    node = _make_node()

    with pytest.raises(ValueError, match="config is required"):
        await node.enable_site_projection(
            context_id="ctx-789",
            broadcast_key_hex="ef" * 32,
            author_did="did:dht:z6MkAuthor3",
            admission="open",
            config=None,
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
