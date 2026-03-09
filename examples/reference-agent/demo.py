"""Self-contained demo of the SCP reference agent.

Demonstrates the end-to-end flow:
1. Creates an identity
2. Creates a context
3. Sends a message
4. Receives the message

Runs the agent in-process (no external infrastructure required beyond
the agent itself). Exits 0 on success, non-zero on failure.

Usage::

    python3 demo.py
"""

from __future__ import annotations

import json
import sys

from agent import McpAgent


def send_request(agent: McpAgent, method: str, params: dict | None = None) -> dict:
    """Send a JSON-RPC request to the agent and return the result.

    Args:
        agent: The MCP agent instance.
        method: The JSON-RPC method name.
        params: Optional method parameters.

    Returns:
        The 'result' field from the JSON-RPC response.

    Raises:
        RuntimeError: If the response contains an error.
    """
    request = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": method,
    }
    if params is not None:
        request["params"] = params

    response = agent.handle_request(request)
    if response is None:
        return {}

    if "error" in response:
        raise RuntimeError(
            f"JSON-RPC error: {response['error']['message']} "
            f"(code {response['error']['code']})"
        )

    return response.get("result", {})


def extract_tool_result(result: dict) -> dict:
    """Extract the tool result from MCP content items.

    Args:
        result: The tools/call response result.

    Returns:
        Parsed JSON from the first text content item.
    """
    content = result.get("content", [])
    if not content:
        return {}
    text = content[0].get("text", "{}")
    return json.loads(text)


def main() -> int:
    """Run the end-to-end demo.

    Returns:
        0 on success, 1 on failure.
    """
    agent = McpAgent()

    # Step 0: Initialize the MCP connection.
    print("Step 0: Initializing MCP connection...")
    init_result = send_request(
        agent,
        "initialize",
        {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {"name": "demo", "version": "1.0.0"},
        },
    )
    print(
        f"  Server: {init_result['serverInfo']['name']} "
        f"v{init_result['serverInfo']['version']}"
    )

    # Send the initialized notification.
    agent.handle_request(
        {
            "jsonrpc": "2.0",
            "method": "notifications/initialized",
        }
    )

    # Step 1: Create an identity.
    print("\nStep 1: Creating identity...")
    result = send_request(
        agent,
        "tools/call",
        {
            "name": "identity_create",
            "arguments": {"custody_type": "in_memory"},
        },
    )
    identity_data = extract_tool_result(result)
    did = identity_data["did"]
    print(f"  DID: {did}")
    assert did.startswith("did:"), f"Expected DID, got: {did}"

    # Step 2: Create a context.
    print("\nStep 2: Creating context...")
    result = send_request(
        agent,
        "tools/call",
        {
            "name": "context_create",
            "arguments": {"template": "default"},
        },
    )
    context_data = extract_tool_result(result)
    context_id = context_data["context_id"]
    print(f"  Context ID: {context_id}")
    assert context_id, "Expected non-empty context_id"

    # Step 3: Send a message.
    print("\nStep 3: Sending message...")
    message_content = "Hello from the SCP reference agent!"
    result = send_request(
        agent,
        "tools/call",
        {
            "name": "context_send",
            "arguments": {
                "context_id": context_id,
                "content": message_content,
            },
        },
    )
    send_data = extract_tool_result(result)
    print(f"  Sent: {send_data['content']}")
    assert send_data["content"] == message_content
    assert send_data["sender_did"] == did

    # Step 4: Receive messages.
    print("\nStep 4: Receiving messages...")
    result = send_request(
        agent,
        "tools/call",
        {
            "name": "context_receive",
            "arguments": {"context_id": context_id},
        },
    )
    receive_data = extract_tool_result(result)
    messages = receive_data["messages"]
    print(f"  Received {len(messages)} message(s)")
    assert len(messages) >= 1, f"Expected at least 1 message, got {len(messages)}"
    assert messages[-1]["content"] == message_content
    assert messages[-1]["sender_did"] == did
    print(f"  Last message: [{messages[-1]['sender_did']}] {messages[-1]['content']}")

    # Step 5: Verify tools/list with capability filtering.
    print("\nStep 5: Verifying tool listing...")
    list_result = send_request(agent, "tools/list")
    tools = list_result.get("tools", [])
    tool_names = [t["name"] for t in tools]
    print(f"  Available tools: {tool_names}")
    assert "identity_create" in tool_names
    assert "context_create" in tool_names
    assert "context_send" in tool_names
    assert "context_receive" in tool_names

    print("\n" + "=" * 60)
    print("Demo completed successfully!")
    print("=" * 60)
    return 0


if __name__ == "__main__":
    sys.exit(main())
