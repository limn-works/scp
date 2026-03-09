"""SCP Reference Agent -- MCP Translation Layer.

Implements a reference agent that translates between SCP tool calls and
MCP (Model Context Protocol). The agent is an MCP server from the model's
perspective, exposing SCP context operations as MCP tools with JSON Schema
definitions.

This bridges SCP's tool system with MCP's tool discovery and invocation,
demonstrating the minimum viable SCP agent pattern:

- MCP server exposing SCP context operations as tools
- Capability filtering based on the agent's role in each context
- Human input forwarded as SCP messages
- SCP messages presented to the model

Architecture:
    Model <-> MCP (JSON-RPC 2.0) <-> Reference Agent <-> SCP SDK

See:
    - Spec section 4.5 (agent role definition)
    - Spec section 8.5 (MCP compatibility)
    - ADR-015 (MCP adapter)
"""

from __future__ import annotations

import json
import logging
import sys
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger("scp_reference_agent")

# ---------------------------------------------------------------------------
# JSON Schema definitions for MCP tools (spec section 8.5)
# ---------------------------------------------------------------------------

#: Schema definitions for all SCP MCP tools. SCP tool definitions are a
#: superset of MCP tool definitions (spec section 8.5).
TOOL_SCHEMAS: dict[str, dict[str, Any]] = {
    "identity_create": {
        "name": "identity_create",
        "description": "Create a new SCP identity (DID). Returns the DID string.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "custody_type": {
                    "type": "string",
                    "description": "Key custody type: 'in_memory' for testing.",
                    "default": "in_memory",
                    "enum": ["in_memory"],
                },
            },
            "additionalProperties": False,
        },
    },
    "context_create": {
        "name": "context_create",
        "description": (
            "Create a new SCP context with the specified template. "
            "Returns the context ID."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "template": {
                    "type": "string",
                    "description": "Context template ID (e.g. 'default', 'ephemeral').",
                    "default": "default",
                },
            },
            "additionalProperties": False,
        },
    },
    "context_join": {
        "name": "context_join",
        "description": "Join an existing SCP context by context ID.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "context_id": {
                    "type": "string",
                    "description": "The ID of the context to join.",
                },
            },
            "required": ["context_id"],
            "additionalProperties": False,
        },
    },
    "context_send": {
        "name": "context_send",
        "description": "Send a message to an SCP context.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "context_id": {
                    "type": "string",
                    "description": "The context to send the message to.",
                },
                "content": {
                    "type": "string",
                    "description": "The message content to send.",
                },
            },
            "required": ["context_id", "content"],
            "additionalProperties": False,
        },
    },
    "context_receive": {
        "name": "context_receive",
        "description": (
            "Retrieve messages from an SCP context. Returns a list of "
            "messages with sender DID and content."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "context_id": {
                    "type": "string",
                    "description": "The context to retrieve messages from.",
                },
            },
            "required": ["context_id"],
            "additionalProperties": False,
        },
    },
    "context_leave": {
        "name": "context_leave",
        "description": "Leave an SCP context by context ID.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "context_id": {
                    "type": "string",
                    "description": "The context to leave.",
                },
            },
            "required": ["context_id"],
            "additionalProperties": False,
        },
    },
}

# ---------------------------------------------------------------------------
# Capability requirements per tool (spec section 8.5 capability filtering)
# ---------------------------------------------------------------------------

#: Maps tool names to the capability required to invoke them.
#: Tools requiring capabilities the agent lacks are filtered out of the
#: tool listing (spec section 8.5).
TOOL_CAPABILITIES: dict[str, str | None] = {
    "identity_create": None,  # No context capability needed.
    "context_create": None,  # Creating contexts is always allowed.
    "context_join": None,  # Joining is subject to context policy, not local filtering.
    "context_send": "MessagesWrite",
    "context_receive": "MessagesRead",
    "context_leave": None,  # Leaving is always allowed for members.
}


# ---------------------------------------------------------------------------
# Agent state
# ---------------------------------------------------------------------------


@dataclass
class AgentState:
    """Mutable state for the reference agent.

    Tracks the agent's identity and the contexts it has joined, along
    with the agent's role in each context for capability filtering.
    """

    #: The agent's DID string, or None if not yet created.
    identity_did: str | None = None

    #: Mapping of context_id -> role for joined contexts.
    #: Role determines which tools are available (capability filtering).
    context_roles: dict[str, str] = field(default_factory=dict)

    #: Mapping of context_id -> list of received messages.
    #: Messages are stored as dicts with 'sender_did' and 'content'.
    message_buffers: dict[str, list[dict[str, str]]] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Capability filtering
# ---------------------------------------------------------------------------

#: Capabilities available per role (simplified mapping for the reference agent).
#: A full implementation uses the UCAN capability chain from the SDK.
ROLE_CAPABILITIES: dict[str, frozenset[str]] = {
    "admin": frozenset(
        {"MessagesRead", "MessagesWrite", "ContextClose", "GovernancePropose"}
    ),
    "member": frozenset({"MessagesRead", "MessagesWrite"}),
    "observer": frozenset({"MessagesRead"}),
}


def agent_has_capability(
    state: AgentState, context_id: str, capability: str | None
) -> bool:
    """Check if the agent has a capability in a context.

    Args:
        state: Current agent state.
        context_id: The context to check.
        capability: The required capability, or None if no capability check needed.

    Returns:
        True if the agent has the capability (or no capability is required).
    """
    if capability is None:
        return True
    role = state.context_roles.get(context_id, "member")
    role_caps = ROLE_CAPABILITIES.get(role, frozenset())
    return capability in role_caps


def filtered_tools(
    state: AgentState, context_id: str | None = None
) -> list[dict[str, Any]]:
    """Return MCP tool definitions filtered by the agent's capabilities.

    Tools requiring capabilities the agent lacks in the given context are
    excluded from the listing (spec section 8.5).

    Args:
        state: Current agent state.
        context_id: If provided, filter context-specific tools by the agent's
            role in this context. If None, include all non-context-specific tools.

    Returns:
        List of MCP-compatible tool definition dicts.
    """
    tools = []
    for tool_name, schema in TOOL_SCHEMAS.items():
        required_cap = TOOL_CAPABILITIES.get(tool_name)
        # For tools that need a context, check capability if context_id is provided.
        if required_cap is not None and context_id is not None:
            if not agent_has_capability(state, context_id, required_cap):
                continue
        tools.append(schema)
    return tools


# ---------------------------------------------------------------------------
# Tool handlers
# ---------------------------------------------------------------------------


def handle_identity_create(
    state: AgentState,
    _arguments: dict[str, Any],
) -> dict[str, Any]:
    """Handle identity_create tool invocation.

    Creates a new SCP identity using the SDK's in-memory key custody
    (suitable for testing and demos).

    Args:
        state: Mutable agent state (updated with the new DID).
        _arguments: Tool arguments (unused for identity creation).

    Returns:
        Dict with 'did' key containing the new DID string.
    """
    try:
        from scp_sdk.identity import Identity

        identity = Identity.create_sync(custody_type="in_memory")
        state.identity_did = identity.did
        logger.info("Created identity: %s", identity.did)
        return {"did": identity.did}
    except ImportError:
        # Fallback for environments without the SDK installed.
        import uuid

        did = f"did:key:z6Mk{uuid.uuid4().hex[:32]}"
        state.identity_did = did
        logger.info("Created mock identity: %s", did)
        return {"did": did}


def handle_context_create(
    state: AgentState,
    arguments: dict[str, Any],
) -> dict[str, Any]:
    """Handle context_create tool invocation.

    Creates a new SCP context. The agent automatically joins as admin.

    Args:
        state: Mutable agent state (updated with the new context).
        arguments: Tool arguments with optional 'template' key.

    Returns:
        Dict with 'context_id' key.
    """
    if state.identity_did is None:
        return {"error": "No identity created. Call identity_create first."}

    template = arguments.get("template", "default")

    try:
        from scp_sdk.context import Context
        from scp_sdk.identity import Identity

        identity = Identity.load_sync(state.identity_did)
        context = Context.create_sync(identity=identity, template=template)
        context_id = context.context_id
    except ImportError:
        import uuid

        context_id = f"ctx-{uuid.uuid4().hex[:16]}"

    state.context_roles[context_id] = "admin"
    state.message_buffers[context_id] = []
    logger.info("Created context: %s (template=%s)", context_id, template)
    return {"context_id": context_id}


def handle_context_join(
    state: AgentState,
    arguments: dict[str, Any],
) -> dict[str, Any]:
    """Handle context_join tool invocation.

    Joins an existing SCP context by ID.

    Args:
        state: Mutable agent state (updated with the joined context).
        arguments: Tool arguments with 'context_id' key.

    Returns:
        Dict with 'context_id' and 'role' keys.
    """
    if state.identity_did is None:
        return {"error": "No identity created. Call identity_create first."}

    context_id = arguments.get("context_id", "")
    if not context_id:
        return {"error": "context_id is required."}

    try:
        from scp_sdk.context import Context
        from scp_sdk.identity import Identity

        identity = Identity.load_sync(state.identity_did)
        context = Context.join_sync(identity=identity, context_id=context_id)
        role = "member"  # Default role on join.
        _ = context
    except ImportError:
        role = "member"

    state.context_roles[context_id] = role
    state.message_buffers.setdefault(context_id, [])
    logger.info("Joined context: %s (role=%s)", context_id, role)
    return {"context_id": context_id, "role": role}


def handle_context_send(
    state: AgentState,
    arguments: dict[str, Any],
) -> dict[str, Any]:
    """Handle context_send tool invocation.

    Sends a message to an SCP context.

    Args:
        state: Mutable agent state.
        arguments: Tool arguments with 'context_id' and 'content' keys.

    Returns:
        Dict confirming the send with 'context_id', 'content', and 'sender_did'.
    """
    if state.identity_did is None:
        return {"error": "No identity created. Call identity_create first."}

    context_id = arguments.get("context_id", "")
    content = arguments.get("content", "")

    if not context_id:
        return {"error": "context_id is required."}
    if not content:
        return {"error": "content is required."}
    if context_id not in state.context_roles:
        return {"error": f"Not a member of context {context_id}. Join first."}

    if not agent_has_capability(state, context_id, "MessagesWrite"):
        return {"error": "Insufficient capability: MessagesWrite required."}

    try:
        from scp_sdk.context import Context
        from scp_sdk.identity import Identity

        identity = Identity.load_sync(state.identity_did)
        context = Context(context_id=context_id, identity=identity)
        context.send_sync(content=content)
    except ImportError:
        pass

    # Store the sent message locally for the demo.
    msg = {"sender_did": state.identity_did, "content": content}
    state.message_buffers.setdefault(context_id, []).append(msg)
    logger.info("Sent message to %s: %s", context_id, content[:50])
    return {
        "context_id": context_id,
        "content": content,
        "sender_did": state.identity_did,
    }


def handle_context_receive(
    state: AgentState,
    arguments: dict[str, Any],
) -> dict[str, Any]:
    """Handle context_receive tool invocation.

    Retrieves messages from an SCP context.

    Args:
        state: Current agent state.
        arguments: Tool arguments with 'context_id' key.

    Returns:
        Dict with 'context_id' and 'messages' (list of message dicts).
    """
    if state.identity_did is None:
        return {"error": "No identity created. Call identity_create first."}

    context_id = arguments.get("context_id", "")
    if not context_id:
        return {"error": "context_id is required."}
    if context_id not in state.context_roles:
        return {"error": f"Not a member of context {context_id}. Join first."}

    if not agent_has_capability(state, context_id, "MessagesRead"):
        return {"error": "Insufficient capability: MessagesRead required."}

    messages = state.message_buffers.get(context_id, [])
    logger.info("Retrieved %d messages from %s", len(messages), context_id)
    return {"context_id": context_id, "messages": messages}


def handle_context_leave(
    state: AgentState,
    arguments: dict[str, Any],
) -> dict[str, Any]:
    """Handle context_leave tool invocation.

    Leaves an SCP context.

    Args:
        state: Mutable agent state (context removed).
        arguments: Tool arguments with 'context_id' key.

    Returns:
        Dict confirming the leave with 'context_id'.
    """
    if state.identity_did is None:
        return {"error": "No identity created. Call identity_create first."}

    context_id = arguments.get("context_id", "")
    if not context_id:
        return {"error": "context_id is required."}
    if context_id not in state.context_roles:
        return {"error": f"Not a member of context {context_id}."}

    try:
        from scp_sdk.context import Context
        from scp_sdk.identity import Identity

        identity = Identity.load_sync(state.identity_did)
        context = Context(context_id=context_id, identity=identity)
        context.leave_sync()
    except ImportError:
        pass

    del state.context_roles[context_id]
    state.message_buffers.pop(context_id, None)
    logger.info("Left context: %s", context_id)
    return {"context_id": context_id}


#: Registry of tool handlers.
TOOL_HANDLERS: dict[str, Any] = {
    "identity_create": handle_identity_create,
    "context_create": handle_context_create,
    "context_join": handle_context_join,
    "context_send": handle_context_send,
    "context_receive": handle_context_receive,
    "context_leave": handle_context_leave,
}


# ---------------------------------------------------------------------------
# MCP JSON-RPC 2.0 server
# ---------------------------------------------------------------------------

#: MCP protocol version supported by this agent.
MCP_PROTOCOL_VERSION = "2024-11-05"


def make_response(request_id: Any, result: Any) -> dict[str, Any]:
    """Build a JSON-RPC 2.0 success response."""
    return {"jsonrpc": "2.0", "id": request_id, "result": result}


def make_error(request_id: Any, code: int, message: str) -> dict[str, Any]:
    """Build a JSON-RPC 2.0 error response."""
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "error": {"code": code, "message": message},
    }


class McpAgent:
    """MCP server implementing the SCP reference agent pattern.

    Handles JSON-RPC 2.0 requests from an MCP-compatible model, translating
    them into SCP SDK operations. The agent exposes SCP context operations
    as MCP tools with JSON Schema definitions.

    This is a stateful server: it tracks the agent's identity and context
    memberships across requests.

    Architecture:
        Model sends JSON-RPC -> McpAgent routes to tool handler -> SCP SDK

    Usage::

        agent = McpAgent()
        # Process requests from stdin (stdio transport)
        agent.run_stdio()
    """

    def __init__(self) -> None:
        self.state = AgentState()
        self.initialized = False

    def handle_request(self, request: dict[str, Any]) -> dict[str, Any] | None:
        """Route a JSON-RPC 2.0 request to the appropriate handler.

        Args:
            request: Parsed JSON-RPC 2.0 request dict.

        Returns:
            JSON-RPC 2.0 response dict, or None for notifications.
        """
        method = request.get("method", "")
        request_id = request.get("id")
        params = request.get("params", {})

        if method == "initialize":
            return self._handle_initialize(request_id, params)
        if method == "notifications/initialized":
            return None  # Notification, no response.
        if method == "ping":
            return make_response(request_id, {})
        if method == "tools/list":
            return self._handle_tools_list(request_id)
        if method == "tools/call":
            return self._handle_tools_call(request_id, params)

        return make_error(request_id, -32601, f"Method not found: {method}")

    def _handle_initialize(
        self,
        request_id: Any,
        params: dict[str, Any],
    ) -> dict[str, Any]:
        """Handle MCP initialize request."""
        _ = params  # Client capabilities stored if needed.
        self.initialized = True
        return make_response(
            request_id,
            {
                "protocolVersion": MCP_PROTOCOL_VERSION,
                "capabilities": {
                    "tools": {"listChanged": True},
                },
                "serverInfo": {
                    "name": "scp-reference-agent",
                    "version": "0.1.0",
                },
            },
        )

    def _handle_tools_list(self, request_id: Any) -> dict[str, Any]:
        """Handle MCP tools/list request with capability filtering.

        Returns only tools the agent's current role permits in each context.
        """
        # Get the first context for capability filtering, or None.
        context_id = next(iter(self.state.context_roles), None)
        tools = filtered_tools(self.state, context_id)
        return make_response(request_id, {"tools": tools})

    def _handle_tools_call(
        self,
        request_id: Any,
        params: dict[str, Any],
    ) -> dict[str, Any]:
        """Handle MCP tools/call request.

        Routes the tool invocation to the appropriate handler and returns
        the result as MCP content items.
        """
        tool_name = params.get("name", "")
        arguments = params.get("arguments", {})

        handler = TOOL_HANDLERS.get(tool_name)
        if handler is None:
            return make_error(request_id, -32602, f"Unknown tool: {tool_name}")

        try:
            result = handler(self.state, arguments)
            return make_response(
                request_id,
                {
                    "content": [{"type": "text", "text": json.dumps(result)}],
                    "isError": "error" in result,
                },
            )
        except Exception as exc:
            logger.exception("Tool %s failed", tool_name)
            return make_response(
                request_id,
                {
                    "content": [
                        {"type": "text", "text": json.dumps({"error": str(exc)})}
                    ],
                    "isError": True,
                },
            )

    def run_stdio(self) -> None:
        """Run the agent using stdio transport (line-delimited JSON).

        Reads JSON-RPC requests from stdin, processes them, and writes
        responses to stdout. Runs until stdin is closed (EOF).
        """
        logger.info("SCP Reference Agent starting (stdio transport)")
        for line in sys.stdin:
            line = line.strip()
            if not line:
                continue
            try:
                request = json.loads(line)
            except json.JSONDecodeError as exc:
                response = make_error(None, -32700, f"Parse error: {exc}")
                sys.stdout.write(json.dumps(response) + "\n")
                sys.stdout.flush()
                continue

            response = self.handle_request(request)
            if response is not None:
                sys.stdout.write(json.dumps(response) + "\n")
                sys.stdout.flush()
        logger.info("SCP Reference Agent stopped (stdin closed)")


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------


def main() -> None:
    """CLI entry point for the SCP reference agent."""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
        stream=sys.stderr,  # Logs to stderr, JSON-RPC on stdout.
    )
    agent = McpAgent()
    agent.run_stdio()


if __name__ == "__main__":
    main()
