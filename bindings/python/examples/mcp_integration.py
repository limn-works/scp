"""MCP integration: expose SCP context outlets via MCP server, connect as client.

Phase 4 PR 5 (#1549) moved MCP operations onto :class:`scp_sdk.SCP`.
Use :meth:`SCP.mcp_serve`, :meth:`SCP.mcp_client_connect_sse`,
:meth:`SCP.mcp_client_list_tools`, :meth:`SCP.mcp_client_invoke`,
:meth:`SCP.mcp_client_disconnect`, and :meth:`SCP.mcp_server_stop`.
"""

import asyncio
import os

from scp_sdk import SCP
from scp_sdk.types import Capability, CustodyType, MemoryScope


async def main() -> None:
    with SCP(storage={"type": "in_memory"}) as scp:
        identity = await scp.identity_create(CustodyType.IN_MEMORY)

        # Create a context with outlet capabilities.
        ctx = await scp.context_create(
            identity.did,
            {
                "ceiling": [
                    Capability.MESSAGES_READ.value,
                    Capability.MESSAGES_WRITE.value,
                    Capability.OUTLET_CALL_ALL.value,
                    Capability.OUTLET_REGISTER.value,
                ],
                "memory_scope": MemoryScope.EPHEMERAL.value,
                "governance": "single_admin",
            },
        )

        # Start an MCP server exposing context outlets on stdio.
        server = await scp.mcp_serve(identity.did, [ctx.context_id], "stdio")
        print("MCP server running")

        # Or connect as an MCP client to an SCP SSE server on this machine that
        # exposes this context. An SCP SSE server always runs a bearer check
        # (ADR-015), so pass the token that server's operator gives you; this
        # example reads it from SCP_MCP_SSE_TOKEN. The transport has no TLS, so
        # a token is sent only to a loopback host.
        sse_token = os.environ.get("SCP_MCP_SSE_TOKEN")
        if not sse_token:
            raise RuntimeError("set SCP_MCP_SSE_TOKEN to the bearer token of the SCP SSE server")
        client = await scp.mcp_client_connect_sse("http://localhost:8080/mcp", sse_token)
        outlets = await scp.mcp_client_list_tools(client)
        print(f"The SSE server offers {len(outlets)} outlet(s)")

        result = await scp.mcp_client_invoke(
            client,
            "summarize",
            {"text": "SCP is a protocol for..."},
            ctx.context_id,
            identity.did,
        )
        print(f"Result: {result}")

        await scp.mcp_client_disconnect(client)
        await scp.mcp_server_stop(server)
        await scp.context_close(ctx._raw_handle, identity.did)


if __name__ == "__main__":
    asyncio.run(main())
