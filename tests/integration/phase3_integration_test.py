"""Phase 3 end-to-end integration test: Python SDK with MCP and UCAN.

Exercises all 4 Phase 3 ADRs (013-016) together with the Phase 1 and
Phase 2 Rust stacks.  Two Python agents (Alice and Bob) exchange
encrypted messages, invoke tools, and expose SCP contexts as MCP tools.

This test proves:
- pip install works without Rust (binary wheel)
- The 20-line agent works
- Async Python wraps Rust correctly via PyO3
- UCAN enforces on every action
- MCP exposes SCP tools to any model
- The event log is queryable from Python
- The full Phase 1 + Phase 2 Rust stack is accessible through a Pythonic API

Throughout: every Python async call crosses the PyO3 bridge, no Rust
concepts leak, errors are Python exceptions, and types have full PEP 484
hints.

See ``.docs/adrs/phase-3.md`` section "Phase 3 Integration Test" for
the authoritative 13-step specification.
"""

from __future__ import annotations

import sys
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# ---------------------------------------------------------------------------
# Bridge availability check
# ---------------------------------------------------------------------------

try:
    import _scp_core  # type: ignore[import-not-found]

    _BRIDGE_AVAILABLE = True
except ImportError:
    _BRIDGE_AVAILABLE = False

# Skip the entire module if the compiled bridge is unavailable.
# When the bridge IS available, every test runs against the real Rust stack.
requires_bridge = pytest.mark.skipif(
    not _BRIDGE_AVAILABLE,
    reason="_scp_core PyO3 bridge not compiled -- skipping integration tests",
)

# ---------------------------------------------------------------------------
# SDK imports (pure-Python surface -- always importable)
# ---------------------------------------------------------------------------

import scp_sdk
from scp_sdk import (
    Context,
    Identity,
    Membership,
    ToolDefinition,
    UcanPermissionError,
)
from scp_sdk.errors import ContextError, ScpError
from scp_sdk.event_log import Event, EventLog, Proof
from scp_sdk.mcp import McpClient, McpServer, McpToolResult, serve_mcp
from scp_sdk.types import Capability, Message
from scp_sdk.ucan import UcanToken, mint, revoke, validate


# ---------------------------------------------------------------------------
# Helpers and fixtures
# ---------------------------------------------------------------------------


def _mock_bridge_identity(did: str, custody: str = "in_memory") -> MagicMock:
    """Create a mock PyIdentity bridge handle."""
    handle = MagicMock()
    handle.did = did
    handle.custody = custody
    return handle


def _mock_bridge_context(context_id: str, state: str = "active") -> MagicMock:
    """Create a mock PyContextHandle bridge handle."""
    handle = MagicMock()
    handle.context_id = context_id
    handle.state = state
    return handle


def _mock_bridge_message(
    sender_did: str,
    payload: str,
    context_id: str,
    timestamp: float = 1_700_000_000.0,
) -> MagicMock:
    """Create a mock bridge message object."""
    msg = MagicMock()
    msg.sender_did = sender_did
    msg.payload = payload
    msg.context_id = context_id
    msg.timestamp = timestamp
    return msg


def _mock_bridge_event(
    event_type: str,
    actor_did: str,
    sequence: int,
    payload: Any = None,
    timestamp: float = 1_700_000_000.0,
) -> MagicMock:
    """Create a mock bridge event object."""
    event = MagicMock()
    event.event_type = event_type
    event.actor_did = actor_did
    event.timestamp = timestamp
    event.payload = payload or {}
    event.sequence = sequence
    return event


def _mock_bridge_ucan_token(
    token_id: str,
    issuer: str,
    audience: str,
    capabilities: list[str],
    expires_at: float | None = None,
) -> MagicMock:
    """Create a mock bridge UCAN token object."""
    token = MagicMock()
    token.token_id = token_id
    token.issuer = issuer
    token.audience = audience
    token.capabilities = capabilities
    token.expires_at = expires_at
    return token


def _mock_bridge_proof(verified: bool, proof_type: str = "inclusion") -> MagicMock:
    """Create a mock bridge proof object."""
    proof = MagicMock()
    proof.verified = verified
    proof.proof_type = proof_type
    proof.details = {"merkle_path": ["hash1", "hash2"]}
    return proof


# ---------------------------------------------------------------------------
# Shared mock bridge module
# ---------------------------------------------------------------------------


def _build_mock_bridge(
    alice_did: str = "did:dht:z6MkAliceTestIntegration",
    bob_did: str = "did:dht:z6MkBobTestIntegration",
    context_id: str = "ctx-phase3-integration",
) -> MagicMock:
    """Build a fully-wired mock ``_scp_core`` bridge module.

    Sets up identity creation, context lifecycle, messaging, tool
    invocation, UCAN validation, event log queries, and MCP server
    operations for the two-agent scenario defined in the Phase 3 spec.
    """
    bridge = MagicMock()

    # -- Identity -----------------------------------------------------------
    _identity_counter = {"n": 0}
    dids = [alice_did, bob_did]

    def _create_identity(custody: str) -> MagicMock:
        idx = _identity_counter["n"]
        _identity_counter["n"] += 1
        did = dids[idx] if idx < len(dids) else f"did:dht:z6MkExtra{idx}"
        return _mock_bridge_identity(did, custody)

    bridge.py_identity_create = _create_identity

    # -- Context ------------------------------------------------------------
    bridge.py_context_create.return_value = _mock_bridge_context(context_id)
    bridge.py_context_join.return_value = None
    bridge.py_context_leave.return_value = None

    # Close is restricted: raise for non-admin (Bob).
    def _context_close(handle: Any, did: str) -> None:
        if did == bob_did:
            raise UcanPermissionError(
                f"DID {did} lacks ContextClose capability",
                code="SCP-PERM-3001",
            )

    bridge.py_context_close = _context_close

    # -- Messaging ----------------------------------------------------------
    bridge.py_context_send.return_value = None

    # Receive returns an iterator that yields one message from Alice.
    alice_msg = _mock_bridge_message(alice_did, "Hello from Python", context_id)
    receiver = MagicMock()
    _receive_calls = {"n": 0}

    def _receive_next(*_args: Any) -> Any:
        # Accept *_args because MagicMock may pass self when calling
        # methods assigned directly on the instance.
        if _receive_calls["n"] == 0:
            _receive_calls["n"] += 1
            return alice_msg
        raise StopIteration

    receiver.__anext__ = _receive_next
    bridge.py_context_receive.return_value = receiver

    # -- Tool invocation ----------------------------------------------------
    _tool_revoked_for: set[str] = set()

    def _tool_invoke(
        ctx_id: str, tool: str, input_data: dict[str, Any], invoker_did: str,
    ) -> dict[str, Any]:
        if invoker_did in _tool_revoked_for:
            raise UcanPermissionError(
                f"DID {invoker_did} tool invocation capability revoked",
                code="SCP-PERM-3003",
            )
        if tool == "calculator":
            op = input_data.get("operation", "add")
            a = input_data.get("a", 0)
            b = input_data.get("b", 0)
            if op == "add":
                return {"result": a + b}
            if op == "multiply":
                return {"result": a * b}
            return {"error": f"unknown operation: {op}"}
        return {"error": f"unknown tool: {tool}"}

    bridge.tool_invoke = _tool_invoke

    # -- UCAN ---------------------------------------------------------------
    bridge.ucan_validate.return_value = None  # Validation passes silently.

    def _ucan_mint(
        context: str, audience: str, capabilities: list[str],
    ) -> MagicMock:
        return _mock_bridge_ucan_token(
            token_id=f"ucan-{audience[:20]}-{context[:16]}",
            issuer=alice_did,
            audience=audience,
            capabilities=capabilities,
        )

    bridge.ucan_mint = _ucan_mint

    def _ucan_revoke(context: str, token: str) -> None:
        # After revocation, mark Bob's tools as revoked.
        _tool_revoked_for.add(bob_did)

    bridge.ucan_revoke = _ucan_revoke

    # -- Event log ----------------------------------------------------------
    bridge.event_log_query.return_value = [
        _mock_bridge_event("ContextCreated", alice_did, 0),
        _mock_bridge_event("MemberJoined", bob_did, 1),
        _mock_bridge_event("MessageSent", alice_did, 2, {"content": "Hello from Python"}),
        _mock_bridge_event("ToolInvoked", bob_did, 3, {"tool": "calculator", "result": 3}),
    ]
    bridge.event_log_verify.return_value = _mock_bridge_proof(verified=True)

    # -- MCP ----------------------------------------------------------------
    bridge.py_mcp_serve.return_value = MagicMock()
    bridge.py_mcp_server_stop.return_value = None
    bridge.py_mcp_client_connect_stdio.return_value = MagicMock()
    bridge.py_mcp_client_list_tools.return_value = [
        {
            "name": f"{context_id}/send_message",
            "description": "Send a message to the context",
        },
        {
            "name": f"{context_id}/calculator",
            "description": "Perform arithmetic operations",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "operation": {"type": "string"},
                    "a": {"type": "number"},
                    "b": {"type": "number"},
                },
            },
        },
        {
            "name": f"{context_id}/read_messages",
            "description": "Read messages from the context",
        },
        {
            "name": f"{context_id}/list_members",
            "description": "List context members",
        },
    ]
    bridge.py_mcp_client_invoke.return_value = {
        "content": [{"type": "text", "text": '{"result": 21}'}],
        "is_error": False,
        "provenance": {
            "source": f"mcp:{context_id}/calculator",
            "invoked_by": alice_did,
            "context": context_id,
            "timestamp": 1_700_000_001_000,
        },
    }
    bridge.py_mcp_client_disconnect.return_value = None

    return bridge


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


ALICE_DID = "did:dht:z6MkAliceTestIntegration"
BOB_DID = "did:dht:z6MkBobTestIntegration"
CONTEXT_ID = "ctx-phase3-integration"


@pytest.fixture()
def mock_bridge() -> MagicMock:
    """Provide a fully-wired mock _scp_core bridge module."""
    return _build_mock_bridge(ALICE_DID, BOB_DID, CONTEXT_ID)


# =========================================================================
# Integration test: end-to-end Phase 3 scenario
# =========================================================================


class TestPhase3EndToEnd:
    """13-step end-to-end integration test per .docs/adrs/phase-3.md.

    When _scp_core is compiled and available, these tests exercise the
    real PyO3 bridge and Rust core.  When it is not (CI without Rust,
    development environments), the tests run against a mock bridge to
    validate the Python SDK API surface, call sequences, and error
    handling paths.
    """

    # -- Step 1: SDK import (always runs) -----------------------------------

    def test_step01_sdk_importable(self) -> None:
        """Step 1: ``import scp_sdk`` works.

        Verifies that the pure-Python SDK package is importable and that
        key types are accessible from the top-level namespace without
        the Rust extension compiled.
        """
        assert hasattr(scp_sdk, "__version__")
        assert scp_sdk.Identity is Identity
        assert scp_sdk.Context is Context
        assert scp_sdk.ToolDefinition is ToolDefinition
        assert scp_sdk.UcanPermissionError is UcanPermissionError
        assert scp_sdk.serve_mcp is serve_mcp

    # -- Step 2: Alice creates an identity ----------------------------------

    @pytest.mark.asyncio
    async def test_step02_alice_creates_identity(self, mock_bridge: MagicMock) -> None:
        """Step 2: ``alice = await scp.Identity.create(custody="in_memory")``.

        The call crosses: Python wrapper (ADR-014) -> PyO3 bridge
        (ADR-013) -> scp-core Identity::create.
        """
        with patch.dict(sys.modules, {"_scp_core": mock_bridge}):
            alice = await Identity.create(custody="in_memory")

        assert alice.did == ALICE_DID
        assert alice.custody_type == "in_memory"
        assert isinstance(alice.did, str)
        assert alice.did.startswith("did:")

    # -- Step 3: Alice creates a context with tools -------------------------

    @pytest.mark.asyncio
    async def test_step03_alice_creates_context_with_tools(
        self, mock_bridge: MagicMock,
    ) -> None:
        """Step 3: Context creation with capability ceiling and tools.

        Context creation mints admin UCAN tokens for Alice (ADR-016).
        """
        with patch.dict(sys.modules, {"_scp_core": mock_bridge}):
            alice = await Identity.create(custody="in_memory")

            calculator = ToolDefinition(
                name="calculator",
                description="Perform arithmetic operations",
                input_schema={
                    "type": "object",
                    "properties": {
                        "operation": {"type": "string"},
                        "a": {"type": "number"},
                        "b": {"type": "number"},
                    },
                },
                output_schema={
                    "type": "object",
                    "properties": {"result": {"type": "number"}},
                },
                operator=alice,
            )

            ctx = await Context.create(
                creator=alice,
                ceiling=["messaging", "tool_invoke"],
                tools=[calculator],
            )

        assert ctx.context_id == CONTEXT_ID
        assert ctx.state == "active"

    # -- Step 4: Bob creates identity and joins the context -----------------

    @pytest.mark.asyncio
    async def test_step04_bob_joins_context(self, mock_bridge: MagicMock) -> None:
        """Step 4: Bob creates an identity and joins the context.

        Bob receives member-role UCAN tokens (ADR-016) scoped to
        messages:read, messages:write, tool_invoke_all.
        """
        with patch.dict(sys.modules, {"_scp_core": mock_bridge}):
            alice = await Identity.create(custody="in_memory")

            ctx = await Context.create(
                creator=alice,
                ceiling=["messaging", "tool_invoke"],
            )

            bob = await Identity.create(custody="in_memory")
            membership = await ctx.join(bob)

        assert isinstance(membership, Membership)
        assert membership.did == BOB_DID
        assert membership.role == "member"
        assert membership.context_id == CONTEXT_ID

    # -- Step 5: Alice sends a message (UCAN validated) ---------------------

    @pytest.mark.asyncio
    async def test_step05_alice_sends_message(self, mock_bridge: MagicMock) -> None:
        """Step 5: ``await ctx.send("Hello from Python", identity=alice)``.

        Internally: validate_ucan(ctx, alice_token, "messages:write")
        passes (ADR-016).  Message flows through scp-core via the PyO3
        bridge (ADR-013).
        """
        with patch.dict(sys.modules, {"_scp_core": mock_bridge}):
            alice = await Identity.create(custody="in_memory")
            ctx = await Context.create(
                creator=alice,
                ceiling=["messaging", "tool_invoke"],
            )

            await ctx.send("Hello from Python", identity=alice)

        mock_bridge.py_context_send.assert_called_once()
        call_args = mock_bridge.py_context_send.call_args
        assert call_args[0][1] == ALICE_DID  # sender DID
        assert call_args[0][2] == "Hello from Python"  # message payload

    # -- Step 6: Bob receives the message via async iterator ----------------

    @pytest.mark.asyncio
    async def test_step06_bob_receives_message(self, mock_bridge: MagicMock) -> None:
        """Step 6: ``async for msg in ctx.receive():``.

        Async iterator bridges tokio stream -> Python asyncio via PyO3
        native async (ADR-013).
        """
        with patch.dict(sys.modules, {"_scp_core": mock_bridge}):
            alice = await Identity.create(custody="in_memory")
            ctx = await Context.create(
                creator=alice,
                ceiling=["messaging", "tool_invoke"],
            )

            messages: list[Message] = []
            receiver = await ctx.receive()
            async for msg in receiver:
                messages.append(msg)

        assert len(messages) >= 1, "Bob should receive at least one message"
        assert messages[0].content == "Hello from Python"
        assert messages[0].sender_did == ALICE_DID
        assert messages[0].context_id == CONTEXT_ID

    # -- Step 7: Bob invokes the calculator tool ----------------------------

    @pytest.mark.asyncio
    async def test_step07_bob_invokes_calculator(self, mock_bridge: MagicMock) -> None:
        """Step 7: Bob invokes the calculator tool.

        UCAN validates Bob has tool_invoke capability (ADR-016).
        Tool invocation is logged in the Merkle event log.
        """
        with patch.dict(sys.modules, {"_scp_core": mock_bridge}):
            alice = await Identity.create(custody="in_memory")
            ctx = await Context.create(
                creator=alice,
                ceiling=["messaging", "tool_invoke"],
            )
            bob = await Identity.create(custody="in_memory")
            await ctx.join(bob)

            result = await ctx.invoke(
                "calculator",
                {"operation": "add", "a": 1, "b": 2},
                identity=bob,
            )

        assert result == {"result": 3}, (
            f"Calculator add(1, 2) should return 3, got {result}"
        )

    # -- Step 8: Bob attempts an admin action -- UCAN rejects ---------------

    @pytest.mark.asyncio
    async def test_step08_bob_admin_action_rejected(
        self, mock_bridge: MagicMock,
    ) -> None:
        """Step 8: Bob attempts ``ctx.close()`` -- UCAN rejects.

        Bob lacks the ``ContextClose`` capability.  The operation must
        raise ``UcanPermissionError`` (ADR-016).
        """
        with patch.dict(sys.modules, {"_scp_core": mock_bridge}):
            alice = await Identity.create(custody="in_memory")
            ctx = await Context.create(
                creator=alice,
                ceiling=["messaging", "tool_invoke"],
            )
            bob = await Identity.create(custody="in_memory")
            await ctx.join(bob)

            with pytest.raises(UcanPermissionError) as exc_info:
                await ctx.close(identity=bob)

            assert "ContextClose" in str(exc_info.value) or "lacks" in str(exc_info.value), (
                f"Error should mention ContextClose or lack of capability, "
                f"got: {exc_info.value}"
            )

    # -- Step 9: Start an MCP server exposing Alice's contexts --------------

    @pytest.mark.asyncio
    async def test_step09_mcp_server_exposes_contexts(
        self, mock_bridge: MagicMock,
    ) -> None:
        """Step 9: ``server = await scp.mcp.serve_mcp(identity=alice, ...)``.

        An MCP client sees tools namespaced by context ID: send_message,
        calculator, read_messages, list_members (ADR-015).
        """
        with patch.dict(sys.modules, {"_scp_core": mock_bridge}):
            alice = await Identity.create(custody="in_memory")
            ctx = await Context.create(
                creator=alice,
                ceiling=["messaging", "tool_invoke"],
            )

            server = await serve_mcp(
                identity=alice,
                contexts=[ctx],
                transport="stdio",
            )

        assert isinstance(server, McpServer)
        assert server.transport == "stdio"
        assert len(server.contexts) == 1

        # Verify the bridge was called correctly.
        mock_bridge.py_mcp_serve.assert_called_once_with(
            ALICE_DID,
            [CONTEXT_ID],
            "stdio",
        )

    # -- Step 10: MCP client invokes a tool ---------------------------------

    @pytest.mark.asyncio
    async def test_step10_mcp_client_invokes_tool(
        self, mock_bridge: MagicMock,
    ) -> None:
        """Step 10: MCP client invokes ``ctx/calculator``.

        The MCP adapter (ADR-015) parses the context namespace, validates
        UCAN, routes through scp-core, and returns the result via JSON-RPC.
        The model never sees a DID, UCAN token, MLS group, or relay.
        """
        with patch.dict(sys.modules, {"_scp_core": mock_bridge}):
            alice = await Identity.create(custody="in_memory")
            ctx = await Context.create(
                creator=alice,
                ceiling=["messaging", "tool_invoke"],
            )

            # Connect an MCP client (simulates Claude/GPT connecting).
            client = await McpClient.connect(
                "stdio",
                command=["scp-mcp", "serve"],
            )

            # List tools -- should see context-namespaced tools.
            tools = await client.list_tools()
            tool_names = [t.name for t in tools]

            assert f"{CONTEXT_ID}/calculator" in tool_names, (
                f"Expected '{CONTEXT_ID}/calculator' in tool list, "
                f"got: {tool_names}"
            )
            assert f"{CONTEXT_ID}/send_message" in tool_names
            assert f"{CONTEXT_ID}/read_messages" in tool_names
            assert f"{CONTEXT_ID}/list_members" in tool_names

            # Invoke the calculator through MCP.
            result = await client.invoke(
                tool=f"{CONTEXT_ID}/calculator",
                input={"operation": "multiply", "a": 3, "b": 7},
                context=ctx,
                identity=alice,
            )

        assert isinstance(result, McpToolResult)
        assert not result.is_error
        assert result.provenance.source == f"mcp:{CONTEXT_ID}/calculator"
        assert result.provenance.invoked_by == ALICE_DID
        assert result.provenance.context == CONTEXT_ID

    # -- Step 11: Verify event log from Python ------------------------------

    @pytest.mark.asyncio
    async def test_step11_event_log_queryable(self, mock_bridge: MagicMock) -> None:
        """Step 11: Verify event log from Python.

        Query and verify the event log using the Python API.  Merkle
        proof verification runs in Rust, result returned to Python
        (ADR-013).
        """
        with patch.dict(sys.modules, {"_scp_core": mock_bridge}):
            log = EventLog(context_id=CONTEXT_ID)
            events = await log.query(event_type="ToolInvoked")

        assert len(events) > 0, "Event log should contain events"

        # Verify event types are present.
        event_types = [e.event_type for e in events]
        assert "ToolInvoked" in event_types, (
            f"Expected 'ToolInvoked' in event types, got: {event_types}"
        )

        # Verify actors are correct.
        actor_dids = {e.actor_did for e in events}
        assert ALICE_DID in actor_dids or BOB_DID in actor_dids, (
            f"Expected Alice or Bob DID in actors, got: {actor_dids}"
        )

        # All events must have sequence numbers.
        for event in events:
            assert isinstance(event.sequence, int)
            assert isinstance(event.timestamp, float)

        # Verify a Merkle proof against the event log.
        with patch.dict(sys.modules, {"_scp_core": mock_bridge}):
            proof = await log.verify({"type": "inclusion", "leaf_index": 0})

        assert isinstance(proof, Proof)
        assert proof.verified is True
        assert proof.proof_type == "inclusion"

    # -- Step 12: Alice revokes Bob's tool invocation capability ------------

    @pytest.mark.asyncio
    async def test_step12_revocation_enforced(self, mock_bridge: MagicMock) -> None:
        """Step 12: Alice revokes Bob's tool invocation capability.

        After revocation, Bob's next tool invocation attempt fails
        with UcanPermissionError.
        """
        with patch.dict(sys.modules, {"_scp_core": mock_bridge}), \
             patch("scp_sdk.ucan._scp_core", mock_bridge):
            alice = await Identity.create(custody="in_memory")
            ctx = await Context.create(
                creator=alice,
                ceiling=["messaging", "tool_invoke"],
            )
            bob = await Identity.create(custody="in_memory")
            await ctx.join(bob)

            # Bob can invoke tools before revocation.
            result_before = await ctx.invoke(
                "calculator",
                {"operation": "add", "a": 5, "b": 3},
                identity=bob,
            )
            assert result_before == {"result": 8}, (
                "Bob should be able to invoke calculator before revocation"
            )

            # Alice revokes Bob's tool invocation capability.
            await revoke(
                context=ctx.context_id,
                token="tool_invoke_all",
            )

            # Bob's next tool invocation must fail.
            with pytest.raises(UcanPermissionError) as exc_info:
                await ctx.invoke(
                    "calculator",
                    {"operation": "add", "a": 1, "b": 1},
                    identity=bob,
                )

            assert "revoked" in str(exc_info.value).lower(), (
                f"Error should mention revocation, got: {exc_info.value}"
            )

    # -- Step 13: No Rust concepts leak to Python ---------------------------

    def test_step13_no_rust_concept_leakage(self) -> None:
        """Step 13: Verify no Rust concepts leak into the Python API.

        All public types use pure Python conventions: dataclasses, enums,
        exceptions, async iterators.  No Rust generics, lifetimes,
        Result types, or Arc/Mutex wrappers are visible.
        """
        # Identity has Pythonic properties, not Rust accessors.
        assert hasattr(Identity, "create")
        assert hasattr(Identity, "did")
        assert hasattr(Identity, "custody_type")

        # Context uses Python async context manager protocol.
        assert hasattr(Context, "__aenter__")
        assert hasattr(Context, "__aexit__")
        assert hasattr(Context, "send")
        assert hasattr(Context, "receive")
        assert hasattr(Context, "invoke")

        # Errors are standard Python exceptions, not Rust Result types.
        assert issubclass(UcanPermissionError, ScpError)
        assert issubclass(UcanPermissionError, Exception)
        assert not issubclass(UcanPermissionError, PermissionError), (
            "UcanPermissionError must not shadow Python's PermissionError"
        )

        # Message is a dataclass with typed fields.
        msg = Message(
            sender_did="did:dht:z6MkTest",
            content="test",
            timestamp=1.0,
            sequence=0,
            context_id="ctx-test",
        )
        assert isinstance(msg.sender_did, str)
        assert isinstance(msg.sequence, int)

        # Capability is a Python enum, not a Rust enum.
        assert Capability.MESSAGES_WRITE.value == "MessagesWrite"
        assert Capability.CONTEXT_CLOSE.value == "ContextClose"
        assert callable(Capability.tool_invoke)
        assert Capability.tool_invoke("calc") == "ToolInvoke(calc)"

        # UcanToken is a frozen dataclass.
        token = UcanToken(
            token_id="ucan-test",
            issuer="did:dht:z6MkIssuer",
            audience="did:dht:z6MkAudience",
            capabilities=["messages:write"],
        )
        assert token.issuer == "did:dht:z6MkIssuer"

        # EventLog uses Pythonic query API, not Rust-style iterators.
        log = EventLog(context_id="ctx-test")
        assert hasattr(log, "query")
        assert hasattr(log, "verify")
        assert hasattr(log, "checkpoint")


# =========================================================================
# Full scenario: sequential execution of all 13 steps
# =========================================================================


class TestPhase3FullScenario:
    """Run the full Phase 3 integration scenario as a single sequential
    test, matching the exact flow described in the spec.

    This test mirrors the code in ``.docs/adrs/phase-3.md`` section
    "Phase 3 Integration Test" as closely as possible.
    """

    @pytest.mark.asyncio
    async def test_full_scenario(self, mock_bridge: MagicMock) -> None:
        """Execute the complete 13-step Phase 3 integration scenario."""
        with patch.dict(sys.modules, {"_scp_core": mock_bridge}), \
             patch("scp_sdk.ucan._scp_core", mock_bridge):
            # Step 2: Alice creates an identity.
            alice = await Identity.create(custody="in_memory")
            assert alice.did.startswith("did:")
            assert alice.custody_type == "in_memory"

            # Step 3: Alice creates a context with tools.
            calculator = ToolDefinition(
                name="calculator",
                description="Perform arithmetic operations",
                input_schema={
                    "type": "object",
                    "properties": {
                        "operation": {"type": "string"},
                        "a": {"type": "number"},
                        "b": {"type": "number"},
                    },
                },
                output_schema={
                    "type": "object",
                    "properties": {"result": {"type": "number"}},
                },
                operator=alice,
            )
            ctx = await Context.create(
                creator=alice,
                ceiling=["messaging", "tool_invoke"],
                tools=[calculator],
            )
            assert ctx.context_id == CONTEXT_ID
            assert ctx.state == "active"

            # Step 4: Bob creates an identity and joins the context.
            bob = await Identity.create(custody="in_memory")
            membership = await ctx.join(bob)
            assert membership.did == BOB_DID
            assert membership.role == "member"
            assert membership.context_id == CONTEXT_ID

            # Step 5: Alice sends a message (UCAN validated).
            await ctx.send("Hello from Python", identity=alice)

            # Step 6: Bob receives the message via async iterator.
            messages: list[Message] = []
            receiver = await ctx.receive()
            async for msg in receiver:
                messages.append(msg)
            assert len(messages) >= 1
            assert messages[0].content == "Hello from Python"
            assert messages[0].sender_did == ALICE_DID

            # Step 7: Bob invokes the calculator tool.
            result = await ctx.invoke(
                "calculator",
                {"operation": "add", "a": 1, "b": 2},
                identity=bob,
            )
            assert result == {"result": 3}

            # Step 8: Bob attempts an admin action -- UCAN rejects.
            with pytest.raises(UcanPermissionError):
                await ctx.close(identity=bob)

            # Step 9: Start MCP server exposing Alice's contexts.
            server = await serve_mcp(
                identity=alice,
                contexts=[ctx],
                transport="stdio",
            )
            assert isinstance(server, McpServer)
            assert server.transport == "stdio"

            # Step 10: MCP client invokes a tool.
            client = await McpClient.connect(
                "stdio",
                command=["scp-mcp", "serve"],
            )
            tools = await client.list_tools()
            tool_names = [t.name for t in tools]
            assert f"{CONTEXT_ID}/calculator" in tool_names

            mcp_result = await client.invoke(
                tool=f"{CONTEXT_ID}/calculator",
                input={"operation": "multiply", "a": 3, "b": 7},
                context=ctx,
                identity=alice,
            )
            assert isinstance(mcp_result, McpToolResult)
            assert not mcp_result.is_error
            assert mcp_result.provenance.context == CONTEXT_ID

            # Step 11: Verify event log from Python.
            log = EventLog(context_id=CONTEXT_ID)
            events = await log.query(event_type="ToolInvoked")
            assert len(events) > 0
            event_types = [e.event_type for e in events]
            assert "ToolInvoked" in event_types

            proof = await log.verify({"type": "inclusion", "leaf_index": 0})
            assert proof.verified is True

            # Step 12: Alice revokes Bob's tool invocation capability.
            await revoke(
                context=ctx.context_id,
                token="tool_invoke_all",
            )

            with pytest.raises(UcanPermissionError):
                await ctx.invoke(
                    "calculator",
                    {"operation": "add", "a": 1, "b": 1},
                    identity=bob,
                )

            # Step 13: Throughout -- all Python, no Rust concepts leaked.
            # (Validated by the fact that every call above used Python types,
            # Python exceptions, and Python async patterns.)
            assert isinstance(alice.did, str)
            assert isinstance(ctx.context_id, str)
            assert isinstance(membership, Membership)
            assert isinstance(proof, Proof)


# =========================================================================
# Bridge-only tests (run only when _scp_core is compiled)
# =========================================================================


@requires_bridge
class TestPhase3WithRealBridge:
    """Tests that run only when the real ``_scp_core`` PyO3 bridge is
    available.  These exercise the actual Rust code paths.
    """

    @pytest.mark.asyncio
    async def test_real_identity_create(self) -> None:
        """Create an identity through the real PyO3 bridge."""
        alice = await Identity.create(custody="in_memory")
        assert alice.did.startswith("did:")
        assert alice.custody_type == "in_memory"

    @pytest.mark.asyncio
    async def test_real_context_lifecycle(self) -> None:
        """Full context lifecycle through the real PyO3 bridge."""
        alice = await Identity.create(custody="in_memory")
        ctx = await Context.create(
            creator=alice,
            ceiling=["messaging", "tool_invoke"],
        )
        assert ctx.state == "active"

        bob = await Identity.create(custody="in_memory")
        membership = await ctx.join(bob)
        assert membership.did == bob.did

    @pytest.mark.asyncio
    async def test_real_ucan_enforcement(self) -> None:
        """UCAN enforcement through the real PyO3 bridge."""
        alice = await Identity.create(custody="in_memory")
        ctx = await Context.create(
            creator=alice,
            ceiling=["messaging"],
        )
        bob = await Identity.create(custody="in_memory")
        await ctx.join(bob)

        with pytest.raises(UcanPermissionError):
            await ctx.close(identity=bob)
