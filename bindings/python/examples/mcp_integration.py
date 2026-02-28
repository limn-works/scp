"""MCP integration: expose SCP tools via MCP JSON-RPC server."""

import asyncio

from scp_sdk import Context, Identity
from scp_sdk.mcp import McpClient, serve_mcp


async def main() -> None:
    identity = await Identity.create(custody="platform")

    # Create a context with tools
    ctx = await Context.create(
        identity=identity,
        params={
            "ceiling": ["msg:send", "msg:receive", "tool:invoke", "mcp:serve"],
            "tools": [
                {
                    "name": "summarize",
                    "description": "Summarize text content",
                    "input_schema": {
                        "type": "object",
                        "properties": {"text": {"type": "string"}},
                        "required": ["text"],
                    },
                    "output_schema": {
                        "type": "object",
                        "properties": {"summary": {"type": "string"}},
                    },
                    "operator": identity.did,
                }
            ],
        },
    )

    # Start an MCP server exposing context tools on stdio
    server = await serve_mcp(ctx, transport="stdio")
    print(f"MCP server running, exposing {len(ctx.tools)} tool(s)")

    # Or connect as an MCP client to a remote server
    client = await McpClient.connect("ws://localhost:8080/mcp")
    tools = await client.list_tools()
    print(f"Remote server offers {len(tools)} tool(s)")

    result = await client.call_tool("summarize", {"text": "SCP is a protocol for..."})
    print(f"Result: {result}")

    await client.close()
    await server.stop()
    await ctx.close()


if __name__ == "__main__":
    asyncio.run(main())
