"""MCP integration: expose SCP context tools via MCP server, connect as client."""

import asyncio

from scp_sdk import Context, Identity
from scp_sdk.mcp import McpClient, serve_mcp
from scp_sdk.types import Capability, CustodyType, MemoryScope


async def main() -> None:
    identity = await Identity.create(custody=CustodyType.IN_MEMORY)

    # Create a context with tool capabilities
    ctx = await Context.create(
        creator=identity,
        ceiling=[
            Capability.MESSAGES_READ,
            Capability.MESSAGES_WRITE,
            Capability.TOOL_INVOKE_ALL,
            Capability.TOOL_REGISTER,
        ],
        memory_scope=MemoryScope.EPHEMERAL,
        governance="single_admin",
    )

    # Start an MCP server exposing context tools on stdio
    server = await serve_mcp(identity=identity, contexts=[ctx], transport="stdio")
    print("MCP server running")

    # Or connect as an MCP client to an external server via SSE
    client = await McpClient.connect("sse", url="http://localhost:8080/mcp")
    tools = await client.list_tools()
    print(f"Remote server offers {len(tools)} tool(s)")

    result = await client.invoke(
        tool="summarize",
        input={"text": "SCP is a protocol for..."},
        context=ctx,
        identity=identity,
    )
    print(f"Result: {result}")

    await client.disconnect()
    await server.stop()
    await ctx.close(identity)


if __name__ == "__main__":
    asyncio.run(main())
