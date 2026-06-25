"""Integration tests for SCP Python SDK Context-layer APIs (SCP-043).

Phase 4 PR 5 Agent B+C (#1549) collapsed :class:`Context` into a pure
handle wrapper and moved every lifecycle/messaging/governance operation
onto :class:`scp_sdk.SCP` methods. These tests verify the new SCP-based
surface with mocked ``_native`` objects:

- :class:`Context` / :class:`Membership` data-class shape
- :meth:`SCP.context_create` forwards Pythonic parameters correctly
- :meth:`SCP.context_join` / ``context_leave`` / ``context_close`` /
  ``context_send`` / ``context_receive`` / ``tool_invoke`` dispatch
- :meth:`SCP.evaluate_invitation` with ``spending_json``
- Consequence event message types

Tests mock the PyO3 ``_native`` bridge; no Rust extension required.

See ``.docs/adrs/phase-3.md`` ADR-014, ADR-048, and
``.docs/standards/sdk-common.md``.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from unittest.mock import AsyncMock, MagicMock

import pytest

from scp_sdk.context import Context, Membership
from scp_sdk.types import Message

# ---------------------------------------------------------------------------
# Helpers — minimal bridge mocks
# ---------------------------------------------------------------------------


@dataclass
class _MockHandle:
    """Mock for the opaque bridge context handle."""

    context_id: str = "ctx-test-abc123"
    state: str = "active"


@dataclass
class _MockIdentity:
    """Mock for the Identity wrapper (only .did / ._raw_handle are needed)."""

    did: str = "did:dht:z6MkAlice"

    @property
    def _raw_handle(self) -> object:
        return MagicMock(did=self.did)


def _make_scp(native_mock: MagicMock | None = None) -> MagicMock:
    """Return a mock ``SCP`` wrapper with a ``_native`` attached.

    Tests call into the real :meth:`SCP.context_*` methods by passing
    ``SCP.method(scp_mock, ...)`` so the bound wrapper delegates to the
    mocked ``_native``.
    """
    scp = MagicMock()
    scp._native = native_mock if native_mock is not None else MagicMock()
    return scp


def _make_context(
    handle: _MockHandle | None = None,
    identity_did: str = "did:dht:z6MkAlice",
) -> Context:
    """Construct a Context wrapper with a mock handle for testing."""
    return Context(
        handle=handle or _MockHandle(),
        identity_did=identity_did,
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
        kwargs: dict[str, str] = {
            "did": "did:dht:z6MkBob",
            "role": "admin",
            "context_id": "ctx-1",
        }
        assert Membership(**kwargs) == Membership(**kwargs)


# ---------------------------------------------------------------------------
# Context handle wrapper tests
# ---------------------------------------------------------------------------


class TestContextHandleProperties:
    """Tests for the Context wrapper's property forwarding."""

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

    def test_repr_includes_context_id_and_state(self) -> None:
        ctx = _make_context()
        r = repr(ctx)
        assert "Context" in r
        assert "ctx-test-abc123" in r
        assert "active" in r

    def test_raw_handle_exposed(self) -> None:
        """Context wrapper exposes the opaque handle under ``_raw_handle``."""
        handle = _MockHandle()
        ctx = _make_context(handle=handle)
        assert ctx._raw_handle is handle

    def test_identity_did_stored(self) -> None:
        ctx = _make_context(identity_did="did:dht:z6MkSomeone")
        assert ctx.identity_did == "did:dht:z6MkSomeone"


# ---------------------------------------------------------------------------
# SCP.context_create tests — via mocked _native
# ---------------------------------------------------------------------------


class TestScpContextCreate:
    """Verify :meth:`SCP.context_create` parameter forwarding (AC 1, 6)."""

    async def test_returns_context_wrapper(self) -> None:
        from scp_sdk.scp import SCP

        native = MagicMock()
        native.context_create.return_value = _MockHandle()
        scp = _make_scp(native)

        ctx = await SCP.context_create(scp, "did:dht:z6MkAlice", {"ceiling": ["messages:read"]})

        assert isinstance(ctx, Context)
        assert ctx.context_id == "ctx-test-abc123"
        assert ctx.identity_did == "did:dht:z6MkAlice"

    async def test_forwards_params_dict_to_bridge(self) -> None:
        from scp_sdk.scp import SCP

        native = MagicMock()
        native.context_create.return_value = _MockHandle()
        scp = _make_scp(native)

        params = {
            "ceiling": ["messages:read", "messages:write"],
            "roles": {"admin": ["context:close"]},
            "tools": [],
            "ttl": 300.0,
            "memory_scope": "full",
            "governance": "single_admin",
            "mode": "encrypted",
            "ceiling_policy": "immutable",
            "promotion_policy": "no_promotion",
            "template_id": None,
            "economic_policy": None,
            "consequence_rules": None,
            "consequence_config": None,
        }
        await SCP.context_create(scp, "did:dht:z6MkAlice", params)

        call = native.context_create.call_args
        assert call[0][0] == "did:dht:z6MkAlice"
        assert call[0][1] == params

    async def test_passes_template_id(self) -> None:
        from scp_sdk.scp import SCP

        native = MagicMock()
        native.context_create.return_value = _MockHandle()
        scp = _make_scp(native)

        await SCP.context_create(
            scp,
            "did:dht:z6MkAlice",
            {"ceiling": [], "template_id": "PublicBroadcast"},
        )

        params = native.context_create.call_args[0][1]
        assert params["template_id"] == "PublicBroadcast"

    async def test_passes_mode(self) -> None:
        from scp_sdk.scp import SCP

        native = MagicMock()
        native.context_create.return_value = _MockHandle()
        scp = _make_scp(native)

        await SCP.context_create(scp, "did:dht:z6MkAlice", {"ceiling": [], "mode": "broadcast"})
        assert native.context_create.call_args[0][1]["mode"] == "broadcast"

    async def test_passes_ceiling_policy(self) -> None:
        from scp_sdk.scp import SCP

        native = MagicMock()
        native.context_create.return_value = _MockHandle()
        scp = _make_scp(native)

        await SCP.context_create(
            scp, "did:dht:z6MkAlice", {"ceiling": [], "ceiling_policy": "governed"}
        )
        assert native.context_create.call_args[0][1]["ceiling_policy"] == "governed"

    async def test_passes_promotion_policy(self) -> None:
        from scp_sdk.scp import SCP

        native = MagicMock()
        native.context_create.return_value = _MockHandle()
        scp = _make_scp(native)

        await SCP.context_create(
            scp, "did:dht:z6MkAlice", {"ceiling": [], "promotion_policy": "promotable"}
        )
        assert native.context_create.call_args[0][1]["promotion_policy"] == "promotable"

    async def test_passes_economic_policy(self) -> None:
        from scp_sdk.scp import SCP

        native = MagicMock()
        native.context_create.return_value = _MockHandle()
        scp = _make_scp(native)

        ep_json = '{"locked": false, "cost_schedule": {}}'
        await SCP.context_create(
            scp, "did:dht:z6MkAlice", {"ceiling": [], "economic_policy": ep_json}
        )
        assert native.context_create.call_args[0][1]["economic_policy"] == ep_json

    async def test_passes_consequence_config(self) -> None:
        """C5: consequence_config must be JSON-serialized and forwarded (ADR-017, #1531).

        In the collapsed surface, the caller is responsible for the JSON
        serialization — the bridge method forwards the dict verbatim.
        """
        from scp_sdk.scp import SCP

        native = MagicMock()
        native.context_create.return_value = _MockHandle()
        scp = _make_scp(native)

        config = {"allow_automatic_access_revocation": True}
        await SCP.context_create(
            scp,
            "did:dht:z6MkAlice",
            {
                "ceiling": [],
                "consequence_config": json.dumps(config),
            },
        )
        params = native.context_create.call_args[0][1]
        assert params["consequence_config"] == json.dumps(config)

    async def test_consequence_config_none_default(self) -> None:
        from scp_sdk.scp import SCP

        native = MagicMock()
        native.context_create.return_value = _MockHandle()
        scp = _make_scp(native)

        await SCP.context_create(
            scp,
            "did:dht:z6MkAlice",
            {"ceiling": [], "consequence_config": None},
        )
        assert native.context_create.call_args[0][1]["consequence_config"] is None

    async def test_accepts_empty_consequence_rules(self) -> None:
        """H14 / M16: an explicit empty consequence_rules list must round-trip as `[]`."""
        from scp_sdk.scp import SCP

        native = MagicMock()
        native.context_create.return_value = _MockHandle()
        scp = _make_scp(native)

        await SCP.context_create(
            scp,
            "did:dht:z6MkAlice",
            {"ceiling": [], "consequence_rules": json.dumps([])},
        )
        params = native.context_create.call_args[0][1]
        assert params["consequence_rules"] == json.dumps([])

    async def test_consequence_rules_none_default(self) -> None:
        from scp_sdk.scp import SCP

        native = MagicMock()
        native.context_create.return_value = _MockHandle()
        scp = _make_scp(native)

        await SCP.context_create(
            scp, "did:dht:z6MkAlice", {"ceiling": [], "consequence_rules": None}
        )
        assert native.context_create.call_args[0][1]["consequence_rules"] is None

    async def test_accepts_empty_roles(self) -> None:
        """H14: an explicit empty roles dict must round-trip as an empty dict."""
        from scp_sdk.scp import SCP

        native = MagicMock()
        native.context_create.return_value = _MockHandle()
        scp = _make_scp(native)

        await SCP.context_create(scp, "did:dht:z6MkAlice", {"ceiling": [], "roles": {}})
        assert native.context_create.call_args[0][1]["roles"] == {}

    async def test_accepts_empty_tools(self) -> None:
        """H14: an explicit empty tools list must round-trip as an empty list."""
        from scp_sdk.scp import SCP

        native = MagicMock()
        native.context_create.return_value = _MockHandle()
        scp = _make_scp(native)

        await SCP.context_create(scp, "did:dht:z6MkAlice", {"ceiling": [], "tools": []})
        assert native.context_create.call_args[0][1]["tools"] == []


# ---------------------------------------------------------------------------
# SCP.context_join / leave / close — dispatch tests
# ---------------------------------------------------------------------------


class TestScpContextJoinLeaveClose:
    """Verify :meth:`SCP.context_join` / ``context_leave`` / ``context_close``."""

    async def test_join_forwards_handle_did_and_spending(self) -> None:
        from scp_sdk.scp import SCP

        native = MagicMock()
        scp = _make_scp(native)
        ctx = _make_context()

        await SCP.context_join(scp, ctx._raw_handle, "did:dht:z6MkBob", "spending-jwt")

        native.context_join.assert_called_once_with(
            ctx._raw_handle, "did:dht:z6MkBob", "spending-jwt"
        )

    async def test_join_default_spending_is_none(self) -> None:
        from scp_sdk.scp import SCP

        native = MagicMock()
        scp = _make_scp(native)
        ctx = _make_context()

        await SCP.context_join(scp, ctx._raw_handle, "did:dht:z6MkBob")

        native.context_join.assert_called_once_with(ctx._raw_handle, "did:dht:z6MkBob", None)

    async def test_leave_dispatch(self) -> None:
        from scp_sdk.scp import SCP

        native = MagicMock()
        scp = _make_scp(native)
        ctx = _make_context()

        await SCP.context_leave(scp, ctx._raw_handle, "did:dht:z6MkBob")

        native.context_leave.assert_called_once_with(ctx._raw_handle, "did:dht:z6MkBob")

    async def test_close_dispatch(self) -> None:
        from scp_sdk.scp import SCP

        native = MagicMock()
        scp = _make_scp(native)
        ctx = _make_context()

        await SCP.context_close(scp, ctx._raw_handle, "did:dht:z6MkAlice")

        native.context_close.assert_called_once_with(ctx._raw_handle, "did:dht:z6MkAlice")


# ---------------------------------------------------------------------------
# SCP.context_send — dispatch tests
# ---------------------------------------------------------------------------


class TestScpContextSend:
    """Verify :meth:`SCP.context_send` parameter forwarding (AC 3, 10)."""

    async def test_send_string_payload(self) -> None:
        from scp_sdk.scp import SCP

        native = MagicMock()
        scp = _make_scp(native)
        ctx = _make_context()

        await SCP.context_send(scp, ctx._raw_handle, "did:dht:z6MkBob", "hello world")

        native.context_send.assert_called_once_with(
            ctx._raw_handle, "did:dht:z6MkBob", "hello world", None
        )

    async def test_send_bytes_payload(self) -> None:
        from scp_sdk.scp import SCP

        native = MagicMock()
        scp = _make_scp(native)
        ctx = _make_context()

        await SCP.context_send(scp, ctx._raw_handle, "did:dht:z6MkAlice", b"\x00\x01\x02")

        native.context_send.assert_called_once_with(
            ctx._raw_handle, "did:dht:z6MkAlice", b"\x00\x01\x02", None
        )

    async def test_send_with_spending_ucan(self) -> None:
        from scp_sdk.scp import SCP

        native = MagicMock()
        scp = _make_scp(native)
        ctx = _make_context()

        await SCP.context_send(scp, ctx._raw_handle, "did:dht:z6MkAlice", "msg", "spending.jwt")

        native.context_send.assert_called_once_with(
            ctx._raw_handle, "did:dht:z6MkAlice", "msg", "spending.jwt"
        )


# ---------------------------------------------------------------------------
# SCP.tool_invoke — dispatch tests
# ---------------------------------------------------------------------------


class TestScpToolInvoke:
    """Verify :meth:`SCP.tool_invoke` (AC 3, 12).

    The PyO3 bridge requires ``ucan_token`` (5th positional), an optional
    ``proof_tokens`` (6th), and an optional ``spending_ucan`` (7th).
    See spec §6.2, §8, ADR-016, and issue #517.
    """

    async def test_invoke_returns_dict(self) -> None:
        from scp_sdk.scp import SCP

        native = MagicMock()
        expected = {"recipes": ["cake", "pie"], "count": 2}
        native.tool_invoke.return_value = expected
        scp = _make_scp(native)

        result = await SCP.tool_invoke(
            scp,
            "ctx-test-abc123",
            "recipe_search",
            {"query": "dessert"},
            "did:dht:z6MkAlice",
            "ucan.jwt",
        )

        assert result == expected
        assert isinstance(result, dict)

    async def test_invoke_passes_ucan_token(self) -> None:
        """ucan_token is forwarded as the 5th positional arg (#517)."""
        from scp_sdk.scp import SCP

        native = MagicMock()
        native.tool_invoke.return_value = {}
        scp = _make_scp(native)

        ucan = "eyJ0eXAiOiJKV1QiLCJhbGciOiJFZERTQSJ9.payload.signature"
        await SCP.tool_invoke(
            scp,
            "ctx-test-abc123",
            "tool",
            {"key": "val"},
            "did:dht:z6MkAlice",
            ucan,
        )

        call_args = native.tool_invoke.call_args[0]
        assert call_args[4] == ucan

    async def test_invoke_passes_proof_tokens(self) -> None:
        """proof_tokens is forwarded as the 6th positional arg (#517)."""
        from scp_sdk.scp import SCP

        native = MagicMock()
        native.tool_invoke.return_value = {}
        scp = _make_scp(native)

        proofs = ["proof-a", "proof-b"]
        await SCP.tool_invoke(
            scp,
            "ctx-test-abc123",
            "tool",
            {},
            "did:dht:z6MkAlice",
            "tok",
            proofs,
        )

        call_args = native.tool_invoke.call_args[0]
        assert call_args[5] == ["proof-a", "proof-b"]

    async def test_invoke_spending_ucan_default_none(self) -> None:
        """spending_ucan defaults to None when not provided."""
        from scp_sdk.scp import SCP

        native = MagicMock()
        native.tool_invoke.return_value = {}
        scp = _make_scp(native)

        await SCP.tool_invoke(
            scp,
            "ctx-test-abc123",
            "tool",
            {},
            "did:dht:z6MkAlice",
            "tok",
        )

        call_args = native.tool_invoke.call_args[0]
        assert call_args[6] is None

    async def test_invoke_passes_spending_ucan(self) -> None:
        """spending_ucan is forwarded as the 7th positional arg (#1606 C4)."""
        from scp_sdk.scp import SCP

        native = MagicMock()
        native.tool_invoke.return_value = {}
        scp = _make_scp(native)

        spending = "eyJ0eXAiOiJKV1QiLCJhbGciOiJFZERTQSJ9.spending.sig"
        await SCP.tool_invoke(
            scp,
            "ctx-test-abc123",
            "paid_tool",
            {"amount": 100},
            "did:dht:z6MkAlice",
            "tok",
            None,
            spending,
        )

        call_args = native.tool_invoke.call_args[0]
        assert call_args[6] == spending


# ---------------------------------------------------------------------------
# SCP.context_receive — wrapper returns the raw receiver object
# ---------------------------------------------------------------------------


class TestScpContextReceive:
    """Verify :meth:`SCP.context_receive` dispatch (AC 4, 11)."""

    async def test_receive_returns_bridge_receiver(self) -> None:
        """The SCP wrapper returns whatever ``_native.context_receive`` returns.

        Callers iterate the PyO3 ``PyMessageReceiver`` directly — the
        receiver produces raw ``PyMessage`` events, which callers convert
        to :class:`scp_sdk.types.Message` themselves.
        """
        from scp_sdk.scp import SCP

        fake_receiver = MagicMock()
        native = MagicMock()
        native.context_receive.return_value = fake_receiver
        scp = _make_scp(native)
        ctx = _make_context()

        receiver = await SCP.context_receive(scp, ctx._raw_handle)
        assert receiver is fake_receiver


# ---------------------------------------------------------------------------
# SCP.set_economic_policy / get_economic_policy roundtrip (#592)
# ---------------------------------------------------------------------------


class TestEconomicPolicyRoundtrip:
    """Roundtrip tests for set/get economic policy via mocked native."""

    @pytest.mark.asyncio
    async def test_set_then_get_roundtrip(self) -> None:
        from scp_sdk.scp import SCP

        stored: dict[str, str | None] = {"policy": None}

        def fake_set(handle: object, policy_json: str) -> None:
            stored["policy"] = policy_json

        def fake_get(handle: object) -> str | None:
            return stored["policy"]

        native = MagicMock()
        native.set_economic_policy.side_effect = fake_set
        native.get_economic_policy.side_effect = fake_get
        scp = _make_scp(native)
        ctx = _make_context()

        ep_json = (
            '{"locked":false,"cost_schedule":{"currency":[85,83,68,0]},'
            '"payment_adapters":[],"pricing_formula":null,'
            '"payee":"did:dht:z6MkPayee"}'
        )
        await SCP.set_economic_policy(scp, ctx._raw_handle, ep_json)
        result = await SCP.get_economic_policy(scp, ctx._raw_handle)

        assert result == ep_json

    @pytest.mark.asyncio
    async def test_get_returns_none_when_unset(self) -> None:
        from scp_sdk.scp import SCP

        native = MagicMock()
        native.get_economic_policy.return_value = None
        scp = _make_scp(native)
        ctx = _make_context()

        result = await SCP.get_economic_policy(scp, ctx._raw_handle)
        assert result is None


# ---------------------------------------------------------------------------
# SCP.evaluate_invitation with spending forwarding
# ---------------------------------------------------------------------------


class TestEvaluateInvitationSpending:
    """Tests for :meth:`SCP.evaluate_invitation` spending forwarding.

    Trust is allowlist-only (§5.12.2): the ``known_did`` allowlist travels
    inside ``policy_json`` (the policy's ``TrustRequirement::KnownDid``
    variant), so there is no separate trusted-DID parameter to forward.
    """

    @pytest.mark.asyncio
    async def test_accepts_spending_json(self) -> None:
        from scp_sdk.scp import SCP

        native = MagicMock()
        native.evaluate_invitation.return_value = "prompt_agent"
        scp = _make_scp(native)

        result = await SCP.evaluate_invitation(
            scp,
            '{"ceiling":[]}',
            "did:dht:z6MkBob",
            "did:dht:z6MkLocal",
            None,
            '{"has_spending_ucan":true,"configured_adapters":["x402"],"available_balance":10000}',
        )

        assert result == "prompt_agent"
        call = native.evaluate_invitation.call_args[0]
        # spending_json is the 5th positional (index 4).
        assert call[4] is not None
        assert "has_spending_ucan" in call[4]

    @pytest.mark.asyncio
    async def test_none_spending_passes_none(self) -> None:
        from scp_sdk.scp import SCP

        native = MagicMock()
        native.evaluate_invitation.return_value = "prompt_agent"
        scp = _make_scp(native)

        await SCP.evaluate_invitation(scp, '{"ceiling":[]}', "did:dht:z6MkBob", "did:dht:z6MkLocal")

        assert native.evaluate_invitation.call_args[0][4] is None

    @pytest.mark.asyncio
    async def test_known_did_allowlist_travels_in_policy(self) -> None:
        """The ``known_did`` allowlist is carried inside ``policy_json``; the
        wrapper forwards the policy verbatim and adds no separate trusted-DID
        argument (only five positionals reach the native bridge).
        """
        from scp_sdk.scp import SCP

        native = MagicMock()
        native.evaluate_invitation.return_value = "auto_accept"
        scp = _make_scp(native)

        policy_json = json.dumps(
            {
                "template": "bilateral-ephemeral",
                "from": {"KnownDid": ["did:dht:z6MkBob", "did:dht:z6MkCarol"]},
                "max_ttl": None,
                "rate_limit": None,
            }
        )

        await SCP.evaluate_invitation(
            scp,
            '{"ceiling":[]}',
            "did:dht:z6MkBob",
            "did:dht:z6MkLocal",
            policy_json,
        )

        call = native.evaluate_invitation.call_args[0]
        # No trusted-DID positional exists: exactly five args are forwarded.
        assert len(call) == 5
        # The allowlist rides inside policy_json (the 4th positional, index 3).
        assert json.loads(call[3])["from"]["KnownDid"] == [
            "did:dht:z6MkBob",
            "did:dht:z6MkCarol",
        ]


# ---------------------------------------------------------------------------
# Consequence event message type tests (#1531, #1594)
# ---------------------------------------------------------------------------


class TestConsequenceEventConversion:
    """Tests for consequence event types at the SDK level (#1531, #1594)."""

    def test_consequence_triggered_message_type(self) -> None:
        payload = (
            "consequence_triggered: member=did:dht:z6MkBob"
            " rule=2 trigger=velocity action=mute"
            " context=ctx-123"
        )
        msg = Message(
            sender_did="scp:system",
            content=payload,
            timestamp=1700000000.0,
            sequence=0,
            context_id="ctx-123",
        )
        assert msg.sender_did == "scp:system"
        assert "consequence_triggered" in msg.content

    def test_consequence_enforced_message_type(self) -> None:
        payload = (
            "consequence_enforced:"
            " member=did:dht:z6MkAlice"
            " action=restrict_write success=true"
            " context=ctx-456"
        )
        msg = Message(
            sender_did="scp:system",
            content=payload,
            timestamp=1700000000.0,
            sequence=0,
            context_id="ctx-456",
        )
        assert msg.sender_did == "scp:system"
        assert "consequence_enforced" in msg.content
        assert "success=true" in msg.content


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


# Silence unused-name warning when the helpers above are re-imported by
# other test modules.
_ = AsyncMock
_ = _MockIdentity
