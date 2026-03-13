"""Integration tests for SCP Python SDK Context class (SCP-043).

Covers all acceptance criteria from SCP-043:
- Context.create() accepts Pythonic parameters (lists for ceiling, dicts for roles)
- Async context manager ensures cleanup (leave if active on __aexit__)
- send() and invoke() accept optional identity parameter (defaults to creator)
- receive() returns AsyncIterator[Message] with buffer semantics
- context_id and state properties
- Context.create signature matches spec
- join(), leave(), close(), send(), receive(), invoke() methods
- __aenter__/__aexit__ implemented
- Receive buffer: 1,000-event default, configurable buffer_size (100--10,000)
- __anext__ returns awaitables that do not block the asyncio event loop (#138)

Receive stream buffer test IDs from .docs/standards/sdk-common.md:
- receive-buffer-capacity-001
- receive-buffer-configurable-004

Tests mock the ``_scp_core`` bridge layer; no Rust extension required.

See ``.docs/adrs/phase-3.md`` ADR-014 and ``.docs/standards/sdk-common.md``
section "Receive stream buffer tests" for the canonical design.
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from dataclasses import dataclass
from unittest.mock import MagicMock, patch

import pytest

from scp_sdk.context import (
    _DEFAULT_BUFFER_SIZE,
    _MAX_BUFFER_SIZE,
    _MIN_BUFFER_SIZE,
    Context,
    Membership,
    _ReceiveIterator,
    _validate_buffer_size,
)
from scp_sdk.errors import ContextError
from scp_sdk.types import Message

# ---------------------------------------------------------------------------
# Helpers -- mock bridge objects
# ---------------------------------------------------------------------------


@dataclass
class _MockHandle:
    """Mock for the opaque bridge context handle."""

    context_id: str = "ctx-test-abc123"
    state: str = "active"


@dataclass
class _MockIdentity:
    """Mock for the Identity class (only .did is needed)."""

    did: str = "did:dht:z6MkAlice"


@dataclass
class _MockBridgeMessage:
    """Mock for a raw bridge message returned by py_context_receive."""

    sender_did: str = "did:dht:z6MkBob"
    payload: str = "hello"
    timestamp: float = 1_700_000_000.0
    context_id: str = "ctx-test-abc123"


def _make_context(
    handle: _MockHandle | None = None,
    creator_did: str = "did:dht:z6MkAlice",
    buffer_size: int = _DEFAULT_BUFFER_SIZE,
) -> Context:
    """Construct a Context with a mock handle for testing."""
    return Context(
        handle=handle or _MockHandle(),
        creator_did=creator_did,
        buffer_size=buffer_size,
    )


# ---------------------------------------------------------------------------
# Membership dataclass tests
# ---------------------------------------------------------------------------


class TestMembership:
    """Tests for the Membership dataclass."""

    def test_construction(self) -> None:
        m = Membership(did="did:dht:z6MkBob", role="member", context_id="ctx-1")
        assert m.did == "did:dht:z6MkBob"
        assert m.role == "member"
        assert m.context_id == "ctx-1"

    def test_equality(self) -> None:
        kwargs: dict[str, str] = {"did": "did:dht:z6MkBob", "role": "admin", "context_id": "ctx-1"}
        assert Membership(**kwargs) == Membership(**kwargs)


# ---------------------------------------------------------------------------
# Context properties tests
# ---------------------------------------------------------------------------


class TestContextProperties:
    """Tests for context_id and state properties (AC 5)."""

    def test_context_id_returns_string(self) -> None:
        ctx = _make_context()
        assert ctx.context_id == "ctx-test-abc123"
        assert isinstance(ctx.context_id, str)

    def test_state_returns_string(self) -> None:
        ctx = _make_context()
        assert ctx.state == "active"
        assert isinstance(ctx.state, str)

    def test_state_reflects_handle_changes(self) -> None:
        handle = _MockHandle(state="creating")
        ctx = _make_context(handle=handle)
        assert ctx.state == "creating"
        handle.state = "active"
        assert ctx.state == "active"
        handle.state = "closed"
        assert ctx.state == "closed"

    def test_all_lifecycle_states(self) -> None:
        for state in ("creating", "active", "closing", "closed", "expired"):
            handle = _MockHandle(state=state)
            ctx = _make_context(handle=handle)
            assert ctx.state == state


# ---------------------------------------------------------------------------
# Context.create tests
# ---------------------------------------------------------------------------


class TestContextCreate:
    """Tests for Context.create() factory (AC 1, 6)."""

    async def test_create_accepts_pythonic_parameters(self) -> None:
        mock_bridge = MagicMock()
        mock_bridge.py_context_create.return_value = _MockHandle()

        with patch.dict("sys.modules", {"_scp_core": mock_bridge}):
            creator = _MockIdentity()
            ctx = await Context.create(
                creator=creator,
                ceiling=["messages:read", "messages:write"],
                tools=None,
                roles={"admin": ["context:close"], "member": ["messages:read"]},
                ttl=300.0,
                memory_scope="full",
                governance="single_admin",
            )

        assert isinstance(ctx, Context)
        assert ctx.context_id == "ctx-test-abc123"
        mock_bridge.py_context_create.assert_called_once()
        call_args = mock_bridge.py_context_create.call_args
        assert call_args[0][0] == "did:dht:z6MkAlice"
        params = call_args[0][1]
        assert params["ceiling"] == ["messages:read", "messages:write"]
        assert params["roles"] == {"admin": ["context:close"], "member": ["messages:read"]}
        assert params["ttl"] == 300.0

    async def test_create_uses_defaults(self) -> None:
        mock_bridge = MagicMock()
        mock_bridge.py_context_create.return_value = _MockHandle()

        with patch.dict("sys.modules", {"_scp_core": mock_bridge}):
            ctx = await Context.create(
                creator=_MockIdentity(),
                ceiling=["messages:read"],
            )

        params = mock_bridge.py_context_create.call_args[0][1]
        assert params["roles"] == {}
        assert params["tools"] == []
        assert params["ttl"] is None
        assert params["memory_scope"] == "full"
        assert params["governance"] == "single_admin"
        assert isinstance(ctx, Context)

    async def test_create_passes_tool_names(self) -> None:
        mock_bridge = MagicMock()
        mock_bridge.py_context_create.return_value = _MockHandle()
        tool = MagicMock()
        tool.name = "recipe_search"

        with patch.dict("sys.modules", {"_scp_core": mock_bridge}):
            await Context.create(
                creator=_MockIdentity(),
                ceiling=["tool:invoke:*"],
                tools=[tool],
            )

        params = mock_bridge.py_context_create.call_args[0][1]
        assert params["tools"] == ["recipe_search"]

    async def test_create_with_custom_buffer_size(self) -> None:
        mock_bridge = MagicMock()
        mock_bridge.py_context_create.return_value = _MockHandle()

        with patch.dict("sys.modules", {"_scp_core": mock_bridge}):
            ctx = await Context.create(
                creator=_MockIdentity(),
                ceiling=["messages:read"],
                buffer_size=500,
            )

        assert ctx._buffer_size == 500

    async def test_create_raises_on_missing_bridge(self) -> None:
        with patch.dict("sys.modules", {"_scp_core": None}):
            with pytest.raises(ContextError, match="_scp_core"):
                await Context.create(
                    creator=_MockIdentity(),
                    ceiling=["messages:read"],
                )

    async def test_create_rejects_invalid_buffer_size(self) -> None:
        with pytest.raises(ValueError, match="buffer_size"):
            await Context.create(
                creator=_MockIdentity(),
                ceiling=["messages:read"],
                buffer_size=50,
            )

    async def test_create_passes_mode(self) -> None:
        mock_bridge = MagicMock()
        mock_bridge.py_context_create.return_value = _MockHandle()

        with patch.dict("sys.modules", {"_scp_core": mock_bridge}):
            await Context.create(
                creator=_MockIdentity(),
                ceiling=["messages:read"],
                mode="broadcast",
            )

        params = mock_bridge.py_context_create.call_args[0][1]
        assert params["mode"] == "broadcast"

    async def test_create_passes_ceiling_policy(self) -> None:
        mock_bridge = MagicMock()
        mock_bridge.py_context_create.return_value = _MockHandle()

        with patch.dict("sys.modules", {"_scp_core": mock_bridge}):
            await Context.create(
                creator=_MockIdentity(),
                ceiling=["messages:read"],
                ceiling_policy="governed",
            )

        params = mock_bridge.py_context_create.call_args[0][1]
        assert params["ceiling_policy"] == "governed"

    async def test_create_passes_promotion_policy(self) -> None:
        mock_bridge = MagicMock()
        mock_bridge.py_context_create.return_value = _MockHandle()

        with patch.dict("sys.modules", {"_scp_core": mock_bridge}):
            await Context.create(
                creator=_MockIdentity(),
                ceiling=["messages:read"],
                promotion_policy="promotable",
            )

        params = mock_bridge.py_context_create.call_args[0][1]
        assert params["promotion_policy"] == "promotable"

    async def test_create_passes_template_id(self) -> None:
        mock_bridge = MagicMock()
        mock_bridge.py_context_create.return_value = _MockHandle()

        with patch.dict("sys.modules", {"_scp_core": mock_bridge}):
            await Context.create(
                creator=_MockIdentity(),
                ceiling=["messages:read"],
                template_id="PublicBroadcast",
            )

        params = mock_bridge.py_context_create.call_args[0][1]
        assert params["template_id"] == "PublicBroadcast"

    async def test_create_passes_economic_policy(self) -> None:
        mock_bridge = MagicMock()
        mock_bridge.py_context_create.return_value = _MockHandle()

        ep_json = '{"locked": false, "cost_schedule": {}}'
        with patch.dict("sys.modules", {"_scp_core": mock_bridge}):
            await Context.create(
                creator=_MockIdentity(),
                ceiling=["messages:read"],
                economic_policy=ep_json,
            )

        params = mock_bridge.py_context_create.call_args[0][1]
        assert params["economic_policy"] == ep_json

    async def test_create_default_new_fields(self) -> None:
        mock_bridge = MagicMock()
        mock_bridge.py_context_create.return_value = _MockHandle()

        with patch.dict("sys.modules", {"_scp_core": mock_bridge}):
            await Context.create(
                creator=_MockIdentity(),
                ceiling=["messages:read"],
            )

        params = mock_bridge.py_context_create.call_args[0][1]
        assert params["mode"] == "encrypted"
        assert params["ceiling_policy"] == "immutable"
        assert params["promotion_policy"] == "no_promotion"
        assert params["template_id"] is None
        assert params["economic_policy"] is None

    async def test_create_accepts_enum_mode(self) -> None:
        from scp_sdk.types import ContextMode

        mock_bridge = MagicMock()
        mock_bridge.py_context_create.return_value = _MockHandle()

        with patch.dict("sys.modules", {"_scp_core": mock_bridge}):
            await Context.create(
                creator=_MockIdentity(),
                ceiling=["messages:read"],
                mode=ContextMode.BROADCAST,
            )

        params = mock_bridge.py_context_create.call_args[0][1]
        assert params["mode"] == "broadcast"

    async def test_create_accepts_enum_ceiling_policy(self) -> None:
        from scp_sdk.types import CeilingPolicy

        mock_bridge = MagicMock()
        mock_bridge.py_context_create.return_value = _MockHandle()

        with patch.dict("sys.modules", {"_scp_core": mock_bridge}):
            await Context.create(
                creator=_MockIdentity(),
                ceiling=["messages:read"],
                ceiling_policy=CeilingPolicy.GOVERNED,
            )

        params = mock_bridge.py_context_create.call_args[0][1]
        assert params["ceiling_policy"] == "governed"

    async def test_create_accepts_enum_promotion_policy(self) -> None:
        from scp_sdk.types import PromotionPolicy

        mock_bridge = MagicMock()
        mock_bridge.py_context_create.return_value = _MockHandle()

        with patch.dict("sys.modules", {"_scp_core": mock_bridge}):
            await Context.create(
                creator=_MockIdentity(),
                ceiling=["messages:read"],
                promotion_policy=PromotionPolicy.PROMOTABLE,
            )

        params = mock_bridge.py_context_create.call_args[0][1]
        assert params["promotion_policy"] == "promotable"


# ---------------------------------------------------------------------------
# Lifecycle method tests (join, leave, close)
# ---------------------------------------------------------------------------


class TestContextJoin:
    """Tests for Context.join() (AC 7)."""

    async def test_join_returns_membership(self) -> None:
        mock_bridge = MagicMock()

        with patch.dict("sys.modules", {"_scp_core": mock_bridge}):
            ctx = _make_context()
            identity = _MockIdentity(did="did:dht:z6MkBob")
            membership = await ctx.join(identity)

        assert isinstance(membership, Membership)
        assert membership.did == "did:dht:z6MkBob"
        assert membership.role == "member"
        assert membership.context_id == "ctx-test-abc123"
        mock_bridge.py_context_join.assert_called_once()

    async def test_join_raises_on_missing_bridge(self) -> None:
        with patch.dict("sys.modules", {"_scp_core": None}):
            ctx = _make_context()
            with pytest.raises(ContextError, match="_scp_core"):
                await ctx.join(_MockIdentity())


class TestContextLeave:
    """Tests for Context.leave() (AC 8)."""

    async def test_leave_delegates_to_bridge(self) -> None:
        mock_bridge = MagicMock()

        with patch.dict("sys.modules", {"_scp_core": mock_bridge}):
            ctx = _make_context()
            identity = _MockIdentity(did="did:dht:z6MkBob")
            await ctx.leave(identity)

        mock_bridge.py_context_leave.assert_called_once()
        call_args = mock_bridge.py_context_leave.call_args[0]
        assert call_args[1] == "did:dht:z6MkBob"

    async def test_leave_raises_on_missing_bridge(self) -> None:
        with patch.dict("sys.modules", {"_scp_core": None}):
            ctx = _make_context()
            with pytest.raises(ContextError, match="_scp_core"):
                await ctx.leave(_MockIdentity())


class TestContextClose:
    """Tests for Context.close() (AC 9)."""

    async def test_close_delegates_to_bridge(self) -> None:
        mock_bridge = MagicMock()

        with patch.dict("sys.modules", {"_scp_core": mock_bridge}):
            ctx = _make_context()
            identity = _MockIdentity(did="did:dht:z6MkAlice")
            await ctx.close(identity)

        mock_bridge.py_context_close.assert_called_once()
        call_args = mock_bridge.py_context_close.call_args[0]
        assert call_args[1] == "did:dht:z6MkAlice"

    async def test_close_raises_on_missing_bridge(self) -> None:
        with patch.dict("sys.modules", {"_scp_core": None}):
            ctx = _make_context()
            with pytest.raises(ContextError, match="_scp_core"):
                await ctx.close(_MockIdentity())


# ---------------------------------------------------------------------------
# Messaging tests (send, receive, invoke)
# ---------------------------------------------------------------------------


class TestContextSend:
    """Tests for Context.send() (AC 3, 10)."""

    async def test_send_with_explicit_identity(self) -> None:
        mock_bridge = MagicMock()

        with patch.dict("sys.modules", {"_scp_core": mock_bridge}):
            ctx = _make_context(creator_did="did:dht:z6MkAlice")
            identity = _MockIdentity(did="did:dht:z6MkBob")
            await ctx.send("hello world", identity=identity)

        call_args = mock_bridge.py_context_send.call_args[0]
        assert call_args[1] == "did:dht:z6MkBob"
        assert call_args[2] == "hello world"

    async def test_send_defaults_to_creator(self) -> None:
        mock_bridge = MagicMock()

        with patch.dict("sys.modules", {"_scp_core": mock_bridge}):
            ctx = _make_context(creator_did="did:dht:z6MkAlice")
            await ctx.send("message without identity")

        call_args = mock_bridge.py_context_send.call_args[0]
        assert call_args[1] == "did:dht:z6MkAlice"

    async def test_send_bytes_content(self) -> None:
        mock_bridge = MagicMock()

        with patch.dict("sys.modules", {"_scp_core": mock_bridge}):
            ctx = _make_context()
            await ctx.send(b"\x00\x01\x02")

        call_args = mock_bridge.py_context_send.call_args[0]
        assert call_args[2] == b"\x00\x01\x02"

    async def test_send_raises_on_missing_bridge(self) -> None:
        with patch.dict("sys.modules", {"_scp_core": None}):
            ctx = _make_context()
            with pytest.raises(ContextError, match="_scp_core"):
                await ctx.send("test")


class TestContextInvoke:
    """Tests for Context.invoke() (AC 3, 12).

    The PyO3 bridge ``tool_invoke`` requires a mandatory ``ucan_token``
    parameter (5th positional) and an optional ``proof_tokens`` (6th).
    See spec section 6.2, section 8, ADR-016, and issue #517.
    """

    async def test_invoke_with_explicit_identity(self) -> None:
        mock_bridge = MagicMock()
        mock_bridge.tool_invoke.return_value = {"result": "42"}

        with patch.dict("sys.modules", {"_scp_core": mock_bridge}):
            ctx = _make_context(creator_did="did:dht:z6MkAlice")
            identity = _MockIdentity(did="did:dht:z6MkBob")
            result = await ctx.invoke(
                "calculator",
                {"op": "add"},
                ucan_token="eyJ0eXAiOiJKV1QiLCJhbGciOiJFZERTQSJ9.test",
                identity=identity,
            )

        assert result == {"result": "42"}
        call_args = mock_bridge.tool_invoke.call_args[0]
        assert call_args[0] == "ctx-test-abc123"
        assert call_args[1] == "calculator"
        assert call_args[2] == {"op": "add"}
        assert call_args[3] == "did:dht:z6MkBob"
        assert call_args[4] == "eyJ0eXAiOiJKV1QiLCJhbGciOiJFZERTQSJ9.test"
        assert call_args[5] is None

    async def test_invoke_defaults_to_creator(self) -> None:
        mock_bridge = MagicMock()
        mock_bridge.tool_invoke.return_value = {}

        with patch.dict("sys.modules", {"_scp_core": mock_bridge}):
            ctx = _make_context(creator_did="did:dht:z6MkAlice")
            await ctx.invoke("tool_name", {}, ucan_token="tok")

        call_args = mock_bridge.tool_invoke.call_args[0]
        assert call_args[3] == "did:dht:z6MkAlice"
        assert call_args[4] == "tok"

    async def test_invoke_passes_ucan_token(self) -> None:
        """ucan_token is forwarded as the 5th positional arg (#517)."""
        mock_bridge = MagicMock()
        mock_bridge.tool_invoke.return_value = {}

        ucan = "eyJ0eXAiOiJKV1QiLCJhbGciOiJFZERTQSJ9.payload.signature"
        with patch.dict("sys.modules", {"_scp_core": mock_bridge}):
            ctx = _make_context()
            await ctx.invoke("tool", {"key": "val"}, ucan_token=ucan)

        call_args = mock_bridge.tool_invoke.call_args[0]
        assert call_args[4] == ucan

    async def test_invoke_passes_proof_tokens(self) -> None:
        """proof_tokens is forwarded as the 6th positional arg (#517)."""
        mock_bridge = MagicMock()
        mock_bridge.tool_invoke.return_value = {}

        proofs = ["proof-a", "proof-b"]
        with patch.dict("sys.modules", {"_scp_core": mock_bridge}):
            ctx = _make_context()
            await ctx.invoke(
                "tool",
                {},
                ucan_token="tok",
                proof_tokens=proofs,
            )

        call_args = mock_bridge.tool_invoke.call_args[0]
        assert call_args[5] == ["proof-a", "proof-b"]

    async def test_invoke_proof_tokens_defaults_to_none(self) -> None:
        """proof_tokens defaults to None when not provided."""
        mock_bridge = MagicMock()
        mock_bridge.tool_invoke.return_value = {}

        with patch.dict("sys.modules", {"_scp_core": mock_bridge}):
            ctx = _make_context()
            await ctx.invoke("tool", {}, ucan_token="tok")

        call_args = mock_bridge.tool_invoke.call_args[0]
        assert call_args[5] is None

    async def test_invoke_returns_dict(self) -> None:
        mock_bridge = MagicMock()
        expected = {"recipes": ["cake", "pie"], "count": 2}
        mock_bridge.tool_invoke.return_value = expected

        with patch.dict("sys.modules", {"_scp_core": mock_bridge}):
            ctx = _make_context()
            result = await ctx.invoke(
                "recipe_search",
                {"query": "dessert"},
                ucan_token="tok",
            )

        assert result == expected
        assert isinstance(result, dict)

    async def test_invoke_raises_on_missing_bridge(self) -> None:
        with patch.dict("sys.modules", {"_scp_core": None}):
            ctx = _make_context()
            with pytest.raises(ContextError, match="_scp_core"):
                await ctx.invoke("tool", {}, ucan_token="tok")


class TestContextReceive:
    """Tests for Context.receive() (AC 4, 11)."""

    async def test_receive_returns_async_iterator(self) -> None:
        mock_bridge = MagicMock()
        mock_receiver = _FakeReceiver([])
        mock_bridge.py_context_receive.return_value = mock_receiver

        with patch.dict("sys.modules", {"_scp_core": mock_bridge}):
            ctx = _make_context()
            iterator = await ctx.receive()

        assert isinstance(iterator, AsyncIterator)

    async def test_receive_yields_message_objects(self) -> None:
        raw_msg = _MockBridgeMessage(
            sender_did="did:dht:z6MkBob",
            payload="hello from Bob",
            timestamp=1_700_000_001.0,
            context_id="ctx-test-abc123",
        )
        mock_bridge = MagicMock()
        mock_receiver = _FakeReceiver([raw_msg])
        mock_bridge.py_context_receive.return_value = mock_receiver

        with patch.dict("sys.modules", {"_scp_core": mock_bridge}):
            ctx = _make_context()
            iterator = await ctx.receive()
            msg = await iterator.__anext__()

        assert isinstance(msg, Message)
        assert msg.sender_did == "did:dht:z6MkBob"
        assert msg.content == "hello from Bob"
        assert msg.timestamp == 1_700_000_001.0
        assert msg.context_id == "ctx-test-abc123"

    async def test_receive_raises_on_missing_bridge(self) -> None:
        with patch.dict("sys.modules", {"_scp_core": None}):
            ctx = _make_context()
            with pytest.raises(ContextError, match="_scp_core"):
                await ctx.receive()


# ---------------------------------------------------------------------------
# Async context manager tests
# ---------------------------------------------------------------------------


class TestAsyncContextManager:
    """Tests for __aenter__/__aexit__ (AC 2, 13)."""

    async def test_aenter_returns_self(self) -> None:
        ctx = _make_context()
        result = await ctx.__aenter__()
        assert result is ctx

    async def test_aexit_leaves_active_context(self) -> None:
        mock_bridge = MagicMock()
        handle = _MockHandle(state="active")

        with patch.dict("sys.modules", {"_scp_core": mock_bridge}):
            ctx = _make_context(handle=handle, creator_did="did:dht:z6MkAlice")
            await ctx.__aexit__(None, None, None)

        mock_bridge.py_context_leave.assert_called_once()
        call_args = mock_bridge.py_context_leave.call_args[0]
        assert call_args[1] == "did:dht:z6MkAlice"

    async def test_aexit_skips_leave_for_closed_context(self) -> None:
        mock_bridge = MagicMock()
        handle = _MockHandle(state="closed")

        with patch.dict("sys.modules", {"_scp_core": mock_bridge}):
            ctx = _make_context(handle=handle)
            await ctx.__aexit__(None, None, None)

        mock_bridge.py_context_leave.assert_not_called()

    async def test_aexit_does_not_raise_on_cleanup_failure(self) -> None:
        mock_bridge = MagicMock()
        mock_bridge.py_context_leave.side_effect = RuntimeError("bridge error")
        handle = _MockHandle(state="active")

        with patch.dict("sys.modules", {"_scp_core": mock_bridge}):
            ctx = _make_context(handle=handle)
            await ctx.__aexit__(None, None, None)

    async def test_async_with_syntax(self) -> None:
        mock_bridge = MagicMock()
        handle = _MockHandle(state="active")

        with patch.dict("sys.modules", {"_scp_core": mock_bridge}):
            ctx = _make_context(handle=handle, creator_did="did:dht:z6MkAlice")
            async with ctx as c:
                assert c is ctx
                assert c.state == "active"

        mock_bridge.py_context_leave.assert_called_once()

    async def test_async_with_exception_still_cleans_up(self) -> None:
        mock_bridge = MagicMock()
        handle = _MockHandle(state="active")

        with patch.dict("sys.modules", {"_scp_core": mock_bridge}):
            ctx = _make_context(handle=handle)
            with pytest.raises(ValueError, match="test error"):
                async with ctx:
                    raise ValueError("test error")

        mock_bridge.py_context_leave.assert_called_once()


# ---------------------------------------------------------------------------
# Context.configure tests
# ---------------------------------------------------------------------------


class TestContextConfigure:
    """Tests for Context.configure() runtime configuration."""

    def test_configure_updates_buffer_size(self) -> None:
        ctx = _make_context(buffer_size=1000)
        ctx.configure(buffer_size=500)
        assert ctx._buffer_size == 500

    def test_configure_rejects_below_min(self) -> None:
        ctx = _make_context()
        with pytest.raises(ValueError, match="buffer_size"):
            ctx.configure(buffer_size=50)

    def test_configure_rejects_above_max(self) -> None:
        ctx = _make_context()
        with pytest.raises(ValueError, match="buffer_size"):
            ctx.configure(buffer_size=20_000)

    def test_configure_no_args_is_noop(self) -> None:
        ctx = _make_context(buffer_size=1000)
        ctx.configure()
        assert ctx._buffer_size == 1000


# ---------------------------------------------------------------------------
# Buffer size validation tests
# ---------------------------------------------------------------------------


class TestBufferSizeValidation:
    """Tests for _validate_buffer_size helper."""

    def test_accepts_minimum(self) -> None:
        _validate_buffer_size(_MIN_BUFFER_SIZE)

    def test_accepts_maximum(self) -> None:
        _validate_buffer_size(_MAX_BUFFER_SIZE)

    def test_accepts_default(self) -> None:
        _validate_buffer_size(_DEFAULT_BUFFER_SIZE)

    def test_rejects_below_minimum(self) -> None:
        with pytest.raises(ValueError, match="buffer_size"):
            _validate_buffer_size(_MIN_BUFFER_SIZE - 1)

    def test_rejects_above_maximum(self) -> None:
        with pytest.raises(ValueError, match="buffer_size"):
            _validate_buffer_size(_MAX_BUFFER_SIZE + 1)

    def test_rejects_zero(self) -> None:
        with pytest.raises(ValueError):
            _validate_buffer_size(0)

    def test_rejects_negative(self) -> None:
        with pytest.raises(ValueError):
            _validate_buffer_size(-1)


# ---------------------------------------------------------------------------
# _ReceiveIterator tests
# ---------------------------------------------------------------------------


class _FakeReceiver:
    """An async-compatible fake that simulates the bridge receiver.

    ``__anext__`` returns a resolved ``asyncio.Future`` (or ``None``
    when exhausted), matching the new non-blocking bridge behaviour
    introduced by #138.
    """

    def __init__(self, messages: list[_MockBridgeMessage]) -> None:
        self._messages = list(messages)
        self._index = 0

    def __anext__(self) -> asyncio.Future[_MockBridgeMessage | None]:
        loop = asyncio.get_running_loop()
        future: asyncio.Future[_MockBridgeMessage | None] = loop.create_future()
        if self._index >= len(self._messages):
            future.set_result(None)
        else:
            msg = self._messages[self._index]
            self._index += 1
            future.set_result(msg)
        return future


class TestReceiveIterator:
    """Tests for the _ReceiveIterator async iterator."""

    async def test_iterates_messages_in_order(self) -> None:
        messages = [
            _MockBridgeMessage(payload="msg-1", timestamp=1.0),
            _MockBridgeMessage(payload="msg-2", timestamp=2.0),
            _MockBridgeMessage(payload="msg-3", timestamp=3.0),
        ]
        receiver = _FakeReceiver(messages)
        iterator = _ReceiveIterator(receiver, buffer_size=_DEFAULT_BUFFER_SIZE)

        collected = []
        async for msg in iterator:
            collected.append(msg)

        assert len(collected) == 3
        assert collected[0].content == "msg-1"
        assert collected[1].content == "msg-2"
        assert collected[2].content == "msg-3"

    async def test_empty_receiver_stops_iteration(self) -> None:
        receiver = _FakeReceiver([])
        iterator = _ReceiveIterator(receiver, buffer_size=_DEFAULT_BUFFER_SIZE)

        collected = []
        async for msg in iterator:
            collected.append(msg)

        assert collected == []

    async def test_closed_iterator_raises_stop_async_iteration(self) -> None:
        receiver = _FakeReceiver([_MockBridgeMessage()])
        iterator = _ReceiveIterator(receiver, buffer_size=_DEFAULT_BUFFER_SIZE)
        iterator.close()

        with pytest.raises(StopAsyncIteration):
            await iterator.__anext__()

    async def test_yields_message_type(self) -> None:
        receiver = _FakeReceiver([_MockBridgeMessage()])
        iterator = _ReceiveIterator(receiver, buffer_size=_DEFAULT_BUFFER_SIZE)

        msg = await iterator.__anext__()
        assert isinstance(msg, Message)


# ---------------------------------------------------------------------------
# Receive buffer conformance tests (sdk-common.md)
# ---------------------------------------------------------------------------


class TestReceiveBufferCapacity001:
    """receive-buffer-capacity-001: buffer holds up to default 1,000 events."""

    async def test_default_buffer_capacity(self) -> None:
        assert _DEFAULT_BUFFER_SIZE == 1000

    async def test_buffer_holds_default_capacity(self) -> None:
        messages = [
            _MockBridgeMessage(payload=f"msg-{i}", timestamp=float(i))
            for i in range(_DEFAULT_BUFFER_SIZE)
        ]
        receiver = _FakeReceiver(messages)
        iterator = _ReceiveIterator(receiver, buffer_size=_DEFAULT_BUFFER_SIZE)

        collected = []
        async for msg in iterator:
            collected.append(msg)

        assert len(collected) == _DEFAULT_BUFFER_SIZE
        assert collected[0].content == "msg-0"
        assert collected[-1].content == f"msg-{_DEFAULT_BUFFER_SIZE - 1}"


class TestNonBlockingAnext:
    """Tests that __anext__ does not block the asyncio event loop (#138).

    Verifies acceptance criterion: concurrent asyncio tasks make progress
    while waiting for messages.
    """

    async def test_concurrent_asyncio_tasks_progress_while_waiting(self) -> None:
        """Start async-for on a receiver, run a timer task concurrently.

        The timer task must complete on schedule (not blocked), confirming
        that __anext__ yields control to the event loop.
        """

        class _DelayedReceiver:
            """Returns a message after a delay, simulating async bridge."""

            def __init__(self) -> None:
                self._delivered = False

            def __anext__(self) -> asyncio.Future[_MockBridgeMessage | None]:
                loop = asyncio.get_running_loop()
                future: asyncio.Future[_MockBridgeMessage | None] = loop.create_future()
                if self._delivered:
                    future.set_result(None)
                else:
                    self._delivered = True
                    # Schedule resolution after 50ms to simulate async recv.
                    loop.call_later(
                        0.05,
                        future.set_result,
                        _MockBridgeMessage(payload="delayed"),
                    )
                return future

        receiver = _DelayedReceiver()
        iterator = _ReceiveIterator(receiver, buffer_size=_DEFAULT_BUFFER_SIZE)

        timer_completed = False

        async def timer_task() -> None:
            nonlocal timer_completed
            await asyncio.sleep(0.01)
            timer_completed = True

        # Run both tasks concurrently. If __anext__ blocked the event
        # loop, the timer_task would never complete.
        async def receive_task() -> list[Message]:
            collected = []
            async for msg in iterator:
                collected.append(msg)
            return collected

        results = await asyncio.gather(
            receive_task(),
            timer_task(),
        )

        assert timer_completed, "timer task should complete while receiver awaits"
        messages = results[0]
        assert len(messages) == 1
        assert messages[0].content == "delayed"

    async def test_multiple_receivers_concurrent_progress(self) -> None:
        """Multiple receivers in concurrent asyncio tasks all make progress."""
        messages_a = [_MockBridgeMessage(payload="a-1"), _MockBridgeMessage(payload="a-2")]
        messages_b = [_MockBridgeMessage(payload="b-1"), _MockBridgeMessage(payload="b-2")]

        iter_a = _ReceiveIterator(_FakeReceiver(messages_a), buffer_size=_DEFAULT_BUFFER_SIZE)
        iter_b = _ReceiveIterator(_FakeReceiver(messages_b), buffer_size=_DEFAULT_BUFFER_SIZE)

        async def collect(it: _ReceiveIterator) -> list[str]:
            out: list[str] = []
            async for msg in it:
                out.append(msg.content)
            return out

        result_a, result_b = await asyncio.gather(collect(iter_a), collect(iter_b))

        assert result_a == ["a-1", "a-2"]
        assert result_b == ["b-1", "b-2"]


class TestReceiveBufferConfigurable004:
    """receive-buffer-configurable-004: buffer size configurable 100--10,000."""

    def test_default_buffer_size_constant(self) -> None:
        assert _DEFAULT_BUFFER_SIZE == 1000

    def test_min_buffer_size_constant(self) -> None:
        assert _MIN_BUFFER_SIZE == 100

    def test_max_buffer_size_constant(self) -> None:
        assert _MAX_BUFFER_SIZE == 10_000

    async def test_create_with_custom_buffer_size(self) -> None:
        mock_bridge = MagicMock()
        mock_bridge.py_context_create.return_value = _MockHandle()

        with patch.dict("sys.modules", {"_scp_core": mock_bridge}):
            ctx = await Context.create(
                creator=_MockIdentity(),
                ceiling=["messages:read"],
                buffer_size=200,
            )

        assert ctx._buffer_size == 200

    async def test_create_with_minimum_buffer_size(self) -> None:
        mock_bridge = MagicMock()
        mock_bridge.py_context_create.return_value = _MockHandle()

        with patch.dict("sys.modules", {"_scp_core": mock_bridge}):
            ctx = await Context.create(
                creator=_MockIdentity(),
                ceiling=["messages:read"],
                buffer_size=_MIN_BUFFER_SIZE,
            )

        assert ctx._buffer_size == _MIN_BUFFER_SIZE

    async def test_create_with_maximum_buffer_size(self) -> None:
        mock_bridge = MagicMock()
        mock_bridge.py_context_create.return_value = _MockHandle()

        with patch.dict("sys.modules", {"_scp_core": mock_bridge}):
            ctx = await Context.create(
                creator=_MockIdentity(),
                ceiling=["messages:read"],
                buffer_size=_MAX_BUFFER_SIZE,
            )

        assert ctx._buffer_size == _MAX_BUFFER_SIZE

    async def test_configure_changes_buffer_size(self) -> None:
        ctx = _make_context(buffer_size=1000)
        ctx.configure(buffer_size=500)
        assert ctx._buffer_size == 500

    async def test_configured_buffer_size_affects_new_iterators(self) -> None:
        mock_bridge = MagicMock()
        mock_receiver = _FakeReceiver([])
        mock_bridge.py_context_receive.return_value = mock_receiver

        ctx = _make_context(buffer_size=200)

        with patch.dict("sys.modules", {"_scp_core": mock_bridge}):
            iterator = await ctx.receive()

        assert iterator._buffer_size == 200


# ---------------------------------------------------------------------------
# Context repr test
# ---------------------------------------------------------------------------


class TestContextRepr:
    """Tests for Context.__repr__."""

    def test_repr_includes_context_id_and_state(self) -> None:
        ctx = _make_context()
        r = repr(ctx)
        assert "Context" in r
        assert "ctx-test-abc123" in r
        assert "active" in r


# ---------------------------------------------------------------------------
# Economic policy roundtrip tests (#592)
# ---------------------------------------------------------------------------


class TestEconomicPolicyRoundtrip:
    """Roundtrip tests for set/get economic policy via mock bridge."""

    @pytest.mark.asyncio
    async def test_set_then_get_roundtrip(self) -> None:
        """Set a policy, get it back, verify equality."""
        mock_bridge = MagicMock()
        # py_set_economic_policy stores the JSON on the handle;
        # py_get_economic_policy reads it back. We simulate this
        # by having the mock mutate a shared dict.
        stored: dict[str, str | None] = {"policy": None}

        def fake_set(handle: object, policy_json: str) -> None:
            stored["policy"] = policy_json

        def fake_get(handle: object) -> str | None:
            return stored["policy"]

        mock_bridge.py_set_economic_policy.side_effect = fake_set
        mock_bridge.py_get_economic_policy.side_effect = fake_get

        ctx = _make_context()
        ep_json = (
            '{"locked":false,"cost_schedule":{"currency":[85,83,68,0]},'
            '"payment_adapters":[],"pricing_formula":null,'
            '"payee":"did:dht:z6MkPayee"}'
        )

        with patch.dict("sys.modules", {"_scp_core": mock_bridge}):
            await ctx.set_economic_policy(ep_json)
            result = await ctx.get_economic_policy()

        assert result == ep_json

    @pytest.mark.asyncio
    async def test_get_returns_none_when_unset(self) -> None:
        """get_economic_policy returns None before any set."""
        mock_bridge = MagicMock()
        mock_bridge.py_get_economic_policy.return_value = None

        ctx = _make_context()
        with patch.dict("sys.modules", {"_scp_core": mock_bridge}):
            result = await ctx.get_economic_policy()

        assert result is None


# ---------------------------------------------------------------------------
# Package re-export tests
# ---------------------------------------------------------------------------


class TestContextPackageReExports:
    """Tests that Context and Membership are re-exported from top-level."""

    def test_context_accessible_from_top_level(self) -> None:
        import scp_sdk

        assert scp_sdk.Context is Context

    def test_membership_accessible_from_top_level(self) -> None:
        import scp_sdk

        assert scp_sdk.Membership is Membership
