"""MCP integration: expose SCP context outlets via MCP server, connect as client.

Phase 4 PR 5 (#1549) moved MCP operations onto :class:`scp_sdk.SCP`.
Use :meth:`SCP.mcp_serve`, :meth:`SCP.mcp_client_connect_sse`,
:meth:`SCP.mcp_client_list_tools`, :meth:`SCP.mcp_client_invoke`,
:meth:`SCP.mcp_client_disconnect`, and :meth:`SCP.mcp_server_stop`.

Run: python3.12 examples/mcp_integration.py, with a separate SCP SSE server
listening on 127.0.0.1:8080 and SCP_MCP_SSE_TOKEN and SCP_MCP_SSE_CONTEXT_ID
set as the client section below describes.
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

        # Or connect as an MCP client to an SCP SSE server started separately on
        # this machine at 127.0.0.1:8080. The server streams events at ``/sse``
        # and takes requests at the ``/message`` path it names in its first
        # event, so the client dials ``/sse``. The context created above lives
        # only in this process's in-memory store, so that server cannot expose
        # it: the example invokes a context the server exposes, read from
        # SCP_MCP_SSE_CONTEXT_ID, and that context must offer an outlet named
        # ``summarize``. An SCP SSE server always runs a bearer check (ADR-015),
        # so pass the token that server's operator gives you, read here from
        # SCP_MCP_SSE_TOKEN. The transport has no TLS, so a token is sent only
        # to a loopback host.
        sse_token = os.environ.get("SCP_MCP_SSE_TOKEN")
        sse_context_id = os.environ.get("SCP_MCP_SSE_CONTEXT_ID")
        if not sse_token or not sse_context_id:
            raise RuntimeError(
                "set SCP_MCP_SSE_TOKEN to the bearer token of the SCP SSE server on "
                "127.0.0.1:8080 and SCP_MCP_SSE_CONTEXT_ID to a context it exposes"
            )
        client = await scp.mcp_client_connect_sse("http://127.0.0.1:8080/sse", sse_token)
        outlets = await scp.mcp_client_list_tools(client)
        print(f"The SSE server offers {len(outlets)} outlet(s)")

        result = await scp.mcp_client_invoke(
            client,
            "summarize",
            {"text": "SCP is a protocol for..."},
            sse_context_id,
            identity.did,
        )
        print(f"Result: {result}")

        await scp.mcp_client_disconnect(client)
        await scp.mcp_server_stop(server)
        await scp.context_close(ctx._raw_handle, identity.did)


if __name__ == "__main__":
    asyncio.run(main())
