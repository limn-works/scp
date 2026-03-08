"""Tests for the SCP reference agent MCP translation layer.

Verifies:
1. MCP tool definitions are valid JSON Schema.
2. End-to-end flow (create identity, create context, send, receive).
3. Capability filtering based on agent role.
4. Error handling for invalid requests.
5. JSON-RPC 2.0 protocol compliance.

Run with::

    python3 -m pytest test_agent.py -v
"""

from __future__ import annotations

import json

import pytest

from agent import (
    INVALID_PARAMS,
    INVALID_REQUEST,
    METHOD_NOT_FOUND,
    AgentState,
    McpAgent,
    TOOL_SCHEMAS,
    agent_has_capability,
    filtered_tools,
)


# ---------------------------------------------------------------------------
# JSON Schema validation tests
# ---------------------------------------------------------------------------


class TestToolSchemas:
    """Verify MCP tool definitions are valid JSON Schema."""

    def test_all_tools_have_name(self) -> None:
        """Every tool definition must have a 'name' field."""
        for tool_name, schema in TOOL_SCHEMAS.items():
            assert "name" in schema, f"Tool {tool_name} missing 'name'"
            assert schema["name"] == tool_name

    def test_all_tools_have_description(self) -> None:
        """Every tool definition must have a 'description' field."""
        for tool_name, schema in TOOL_SCHEMAS.items():
            assert "description" in schema, f"Tool {tool_name} missing 'description'"
            assert isinstance(schema["description"], str)
            assert len(schema["description"]) > 0

    def test_all_tools_have_input_schema(self) -> None:
        """Every tool definition must have an 'inputSchema' field."""
        for tool_name, schema in TOOL_SCHEMAS.items():
            assert "inputSchema" in schema, f"Tool {tool_name} missing 'inputSchema'"
            input_schema = schema["inputSchema"]
            assert input_schema.get("type") == "object", (
                f"Tool {tool_name} inputSchema must be type 'object'"
            )

    def test_input_schemas_have_properties(self) -> None:
        """Every inputSchema must have a 'properties' field."""
        for tool_name, schema in TOOL_SCHEMAS.items():
            input_schema = schema["inputSchema"]
            assert "properties" in input_schema, (
                f"Tool {tool_name} inputSchema missing 'properties'"
            )

    def test_required_fields_are_in_properties(self) -> None:
        """All 'required' fields must exist in 'properties'."""
        for tool_name, schema in TOOL_SCHEMAS.items():
            input_schema = schema["inputSchema"]
            required = input_schema.get("required", [])
            properties = input_schema.get("properties", {})
            for field_name in required:
                assert field_name in properties, (
                    f"Tool {tool_name}: required field '{field_name}' not in properties"
                )

    def test_schema_json_serializable(self) -> None:
        """All tool schemas must be JSON-serializable."""
        for tool_name, schema in TOOL_SCHEMAS.items():
            try:
                json.dumps(schema)
            except (TypeError, ValueError) as exc:
                pytest.fail(f"Tool {tool_name} schema not JSON-serializable: {exc}")

    def test_expected_tools_present(self) -> None:
        """All six required tools must be defined."""
        expected = {
            "identity_create",
            "context_create",
            "context_join",
            "context_send",
            "context_receive",
            "context_leave",
        }
        assert set(TOOL_SCHEMAS.keys()) == expected

    def test_context_send_requires_context_id_and_content(self) -> None:
        """context_send must require both context_id and content."""
        schema = TOOL_SCHEMAS["context_send"]["inputSchema"]
        required = schema.get("required", [])
        assert "context_id" in required
        assert "content" in required

    def test_context_join_requires_context_id(self) -> None:
        """context_join must require context_id."""
        schema = TOOL_SCHEMAS["context_join"]["inputSchema"]
        required = schema.get("required", [])
        assert "context_id" in required

    def test_context_receive_requires_context_id(self) -> None:
        """context_receive must require context_id."""
        schema = TOOL_SCHEMAS["context_receive"]["inputSchema"]
        required = schema.get("required", [])
        assert "context_id" in required

    def test_context_leave_requires_context_id(self) -> None:
        """context_leave must require context_id."""
        schema = TOOL_SCHEMAS["context_leave"]["inputSchema"]
        required = schema.get("required", [])
        assert "context_id" in required

    def test_all_schemas_disable_additional_properties(self) -> None:
        """All schemas should set additionalProperties to False."""
        for tool_name, schema in TOOL_SCHEMAS.items():
            input_schema = schema["inputSchema"]
            assert input_schema.get("additionalProperties") is False, (
                f"Tool {tool_name} should disable additionalProperties"
            )


# ---------------------------------------------------------------------------
# Capability filtering tests
# ---------------------------------------------------------------------------


class TestCapabilityFiltering:
    """Verify capability-based tool filtering."""

    def test_admin_has_all_capabilities(self) -> None:
        state = AgentState(
            identity_did="did:key:test", context_roles={"ctx-1": "admin"}
        )
        assert agent_has_capability(state, "ctx-1", "MessagesRead")
        assert agent_has_capability(state, "ctx-1", "MessagesWrite")

    def test_member_has_read_and_write(self) -> None:
        state = AgentState(
            identity_did="did:key:test", context_roles={"ctx-1": "member"}
        )
        assert agent_has_capability(state, "ctx-1", "MessagesRead")
        assert agent_has_capability(state, "ctx-1", "MessagesWrite")

    def test_observer_has_read_only(self) -> None:
        state = AgentState(
            identity_did="did:key:test", context_roles={"ctx-1": "observer"}
        )
        assert agent_has_capability(state, "ctx-1", "MessagesRead")
        assert not agent_has_capability(state, "ctx-1", "MessagesWrite")

    def test_none_capability_always_passes(self) -> None:
        state = AgentState()
        assert agent_has_capability(state, "any-ctx", None)

    def test_unknown_role_has_no_capabilities(self) -> None:
        state = AgentState(
            identity_did="did:key:test", context_roles={"ctx-1": "unknown-role"}
        )
        assert not agent_has_capability(state, "ctx-1", "MessagesRead")
        assert not agent_has_capability(state, "ctx-1", "MessagesWrite")

    def test_filtered_tools_includes_all_for_admin(self) -> None:
        state = AgentState(
            identity_did="did:key:test", context_roles={"ctx-1": "admin"}
        )
        tools = filtered_tools(state, "ctx-1")
        tool_names = {t["name"] for t in tools}
        assert "context_send" in tool_names
        assert "context_receive" in tool_names
        assert "identity_create" in tool_names
        assert "context_create" in tool_names
        assert "context_join" in tool_names
        assert "context_leave" in tool_names

    def test_filtered_tools_excludes_write_for_observer(self) -> None:
        state = AgentState(
            identity_did="did:key:test", context_roles={"ctx-1": "observer"}
        )
        tools = filtered_tools(state, "ctx-1")
        tool_names = {t["name"] for t in tools}
        assert "context_receive" in tool_names
        assert "context_send" not in tool_names

    def test_filtered_tools_without_context_includes_all(self) -> None:
        """Without a context_id, all tools are included (no capability check)."""
        state = AgentState()
        tools = filtered_tools(state, None)
        assert len(tools) == 6

    def test_observer_send_rejected_at_handler(self) -> None:
        """An observer attempting context_send gets a capability error."""
        agent = McpAgent()
        agent.initialized = True
        agent.state.identity_did = "did:key:test"
        agent.state.context_roles["ctx-1"] = "observer"
        agent.state.message_buffers["ctx-1"] = []

        response = agent.handle_request(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {
                    "name": "context_send",
                    "arguments": {"context_id": "ctx-1", "content": "hello"},
                },
            }
        )
        assert response is not None
        result = response["result"]
        assert result["isError"] is True
        tool_result = json.loads(result["content"][0]["text"])
        assert "MessagesWrite" in tool_result["error"]


# ---------------------------------------------------------------------------
# End-to-end flow tests
# ---------------------------------------------------------------------------


class TestEndToEnd:
    """Verify the full agent lifecycle."""

    @staticmethod
    def _init_agent() -> McpAgent:
        """Create and initialize an McpAgent."""
        agent = McpAgent()
        agent.handle_request(
            {
                "jsonrpc": "2.0",
                "id": 0,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {},
                    "clientInfo": {"name": "test", "version": "1.0.0"},
                },
            }
        )
        agent.handle_request(
            {
                "jsonrpc": "2.0",
                "method": "notifications/initialized",
            }
        )
        return agent

    @staticmethod
    def _call_tool(agent: McpAgent, name: str, arguments: dict | None = None) -> dict:
        """Helper to call a tool and return the parsed result."""
        response = agent.handle_request(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": name, "arguments": arguments or {}},
            }
        )
        assert response is not None
        assert "result" in response, f"Expected result, got: {response}"
        content = response["result"].get("content", [])
        assert len(content) > 0
        return json.loads(content[0]["text"])

    def test_full_lifecycle(self) -> None:
        """Create identity -> create context -> send -> receive -> leave."""
        agent = self._init_agent()

        # Step 1: Create identity.
        result = self._call_tool(agent, "identity_create")
        assert "did" in result
        did = result["did"]

        # Step 2: Create context.
        result = self._call_tool(agent, "context_create", {"template": "default"})
        assert "context_id" in result
        context_id = result["context_id"]

        # Step 3: Send message.
        result = self._call_tool(
            agent,
            "context_send",
            {
                "context_id": context_id,
                "content": "test message",
            },
        )
        assert result["content"] == "test message"
        assert result["sender_did"] == did

        # Step 4: Receive messages.
        result = self._call_tool(
            agent,
            "context_receive",
            {
                "context_id": context_id,
            },
        )
        assert len(result["messages"]) >= 1
        assert result["messages"][-1]["content"] == "test message"

        # Step 5: Leave context.
        result = self._call_tool(
            agent,
            "context_leave",
            {
                "context_id": context_id,
            },
        )
        assert result["context_id"] == context_id

    def test_send_without_identity_returns_error(self) -> None:
        """Sending without an identity should return an error."""
        agent = self._init_agent()
        result = self._call_tool(
            agent,
            "context_send",
            {
                "context_id": "ctx-1",
                "content": "hello",
            },
        )
        assert "error" in result

    def test_send_without_join_returns_error(self) -> None:
        """Sending to an unjoined context should return an error."""
        agent = self._init_agent()
        self._call_tool(agent, "identity_create")
        result = self._call_tool(
            agent,
            "context_send",
            {
                "context_id": "nonexistent-ctx",
                "content": "hello",
            },
        )
        assert "error" in result

    def test_receive_without_join_returns_error(self) -> None:
        """Receiving from an unjoined context should return an error."""
        agent = self._init_agent()
        self._call_tool(agent, "identity_create")
        result = self._call_tool(
            agent,
            "context_receive",
            {"context_id": "nonexistent-ctx"},
        )
        assert "error" in result

    def test_leave_unjoined_context_returns_error(self) -> None:
        """Leaving a context not joined should return an error."""
        agent = self._init_agent()
        self._call_tool(agent, "identity_create")
        result = self._call_tool(
            agent,
            "context_leave",
            {
                "context_id": "nonexistent-ctx",
            },
        )
        assert "error" in result

    def test_context_join_without_identity_returns_error(self) -> None:
        """Joining a context without an identity returns an error."""
        agent = self._init_agent()
        result = self._call_tool(
            agent,
            "context_join",
            {"context_id": "some-ctx"},
        )
        assert "error" in result

    def test_context_join_empty_id_returns_error(self) -> None:
        """Joining with an empty context_id returns an error."""
        agent = self._init_agent()
        self._call_tool(agent, "identity_create")
        result = self._call_tool(
            agent,
            "context_join",
            {"context_id": ""},
        )
        assert "error" in result

    def test_send_empty_content_returns_error(self) -> None:
        """Sending an empty message returns an error."""
        agent = self._init_agent()
        self._call_tool(agent, "identity_create")
        ctx = self._call_tool(agent, "context_create")
        result = self._call_tool(
            agent,
            "context_send",
            {"context_id": ctx["context_id"], "content": ""},
        )
        assert "error" in result

    def test_multiple_messages_accumulate(self) -> None:
        """Multiple sends accumulate in the message buffer."""
        agent = self._init_agent()
        self._call_tool(agent, "identity_create")
        ctx = self._call_tool(agent, "context_create")
        ctx_id = ctx["context_id"]

        self._call_tool(
            agent, "context_send", {"context_id": ctx_id, "content": "msg1"}
        )
        self._call_tool(
            agent, "context_send", {"context_id": ctx_id, "content": "msg2"}
        )
        self._call_tool(
            agent, "context_send", {"context_id": ctx_id, "content": "msg3"}
        )

        result = self._call_tool(agent, "context_receive", {"context_id": ctx_id})
        assert len(result["messages"]) == 3
        assert result["messages"][0]["content"] == "msg1"
        assert result["messages"][2]["content"] == "msg3"

    def test_leave_clears_state(self) -> None:
        """Leaving a context clears both roles and message buffers."""
        agent = self._init_agent()
        self._call_tool(agent, "identity_create")
        ctx = self._call_tool(agent, "context_create")
        ctx_id = ctx["context_id"]

        self._call_tool(agent, "context_send", {"context_id": ctx_id, "content": "msg"})
        self._call_tool(agent, "context_leave", {"context_id": ctx_id})

        # Verify state is cleared.
        assert ctx_id not in agent.state.context_roles
        assert ctx_id not in agent.state.message_buffers


# ---------------------------------------------------------------------------
# JSON-RPC 2.0 protocol compliance tests
# ---------------------------------------------------------------------------


class TestJsonRpcCompliance:
    """Verify JSON-RPC 2.0 protocol compliance."""

    def test_unknown_method_returns_method_not_found(self) -> None:
        agent = McpAgent()
        agent.initialized = True
        response = agent.handle_request(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "nonexistent/method",
            }
        )
        assert response is not None
        assert "error" in response
        assert response["error"]["code"] == METHOD_NOT_FOUND

    def test_notification_returns_none(self) -> None:
        agent = McpAgent()
        response = agent.handle_request(
            {
                "jsonrpc": "2.0",
                "method": "notifications/initialized",
            }
        )
        assert response is None

    def test_ping_returns_empty_result(self) -> None:
        agent = McpAgent()
        response = agent.handle_request(
            {
                "jsonrpc": "2.0",
                "id": 42,
                "method": "ping",
            }
        )
        assert response is not None
        assert response["id"] == 42
        assert response["result"] == {}

    def test_initialize_returns_server_info(self) -> None:
        agent = McpAgent()
        response = agent.handle_request(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {},
                    "clientInfo": {"name": "test", "version": "1.0.0"},
                },
            }
        )
        assert response is not None
        result = response["result"]
        assert result["protocolVersion"] == "2024-11-05"
        assert result["serverInfo"]["name"] == "scp-reference-agent"
        assert result["serverInfo"]["version"] == "0.1.0"
        assert result["capabilities"]["tools"]["listChanged"] is True

    def test_tools_list_returns_tools_array(self) -> None:
        agent = McpAgent()
        agent.initialized = True
        response = agent.handle_request(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/list",
            }
        )
        assert response is not None
        tools = response["result"]["tools"]
        assert isinstance(tools, list)
        assert len(tools) == 6

    def test_unknown_tool_returns_error(self) -> None:
        agent = McpAgent()
        agent.initialized = True
        response = agent.handle_request(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": "nonexistent_tool", "arguments": {}},
            }
        )
        assert response is not None
        assert "error" in response
        assert response["error"]["code"] == INVALID_PARAMS

    def test_pre_init_guard_rejects_tools_list(self) -> None:
        """tools/list before initialize should be rejected."""
        agent = McpAgent()
        response = agent.handle_request(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/list",
            }
        )
        assert response is not None
        assert "error" in response
        assert response["error"]["code"] == INVALID_REQUEST

    def test_pre_init_guard_rejects_tools_call(self) -> None:
        """tools/call before initialize should be rejected."""
        agent = McpAgent()
        response = agent.handle_request(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": "identity_create", "arguments": {}},
            }
        )
        assert response is not None
        assert "error" in response
        assert response["error"]["code"] == INVALID_REQUEST

    def test_pre_init_guard_allows_ping(self) -> None:
        """ping should work before initialize."""
        agent = McpAgent()
        response = agent.handle_request(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "ping",
            }
        )
        assert response is not None
        assert "result" in response
        assert response["result"] == {}

    def test_response_has_jsonrpc_field(self) -> None:
        """Every response must have jsonrpc: '2.0'."""
        agent = McpAgent()
        response = agent.handle_request(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "ping",
            }
        )
        assert response is not None
        assert response["jsonrpc"] == "2.0"

    def test_response_id_matches_request(self) -> None:
        """Response ID must match the request ID."""
        agent = McpAgent()
        for req_id in [1, 42, "abc-123"]:
            response = agent.handle_request(
                {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "method": "ping",
                }
            )
            assert response is not None
            assert response["id"] == req_id


# ---------------------------------------------------------------------------
# Demo script test
# ---------------------------------------------------------------------------


class TestDemoScript:
    """Verify the demo script runs successfully."""

    def test_demo_exits_zero(self) -> None:
        """The demo script must exit 0 on success."""
        from demo import main

        exit_code = main()
        assert exit_code == 0, f"Demo exited with code {exit_code}"
