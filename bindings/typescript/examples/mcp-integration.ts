/**
 * MCP integration: expose SCP outlets via an MCP JSON-RPC server, then
 * connect as an MCP client to an MCP server on this machine.
 *
 * Post-Phase-4 (ADR-048): all bridge operations route through an
 * explicit `SCP` instance. The free-function shims (`serveMcp`,
 * `connectMcp`, `connectMcpStdio`) were removed — use
 * `scp.mcpServerCreate`, `scp.mcpClientConnectSse`, and the other
 * `scp.mcp*` methods directly.
 *
 * Run: bun run examples/mcp-integration.ts
 */

import { SCP, defineOutletDefinition } from "../src/index";

async function main(): Promise<void> {
  const scp = new SCP({ storage: { type: "in_memory" } });
  try {
    const identity = await scp.identityCreate("in_memory");

    // Create a context with outlet capabilities.
    const ctx = await scp.contextCreate(
      identity,
      JSON.stringify({
        ceiling: ["messages:read", "messages:write", "outlet:call:*", "outlet:register"],
        memoryScope: "ephemeral",
        governance: "single_admin",
      }),
    );

    // Register an outlet in the context.
    const outlet = defineOutletDefinition({
      name: "summarize",
      description: "Summarize text content",
      kind: "action",
      inputSchema: {
        type: "object",
        properties: { text: { type: "string" } },
        required: ["text"],
      },
      outputSchema: {
        type: "object",
        properties: { summary: { type: "string" } },
      },
      operator: identity.did,
    });
    await scp.outletRegister(ctx._rawHandle, outlet);

    // Start an MCP server exposing context outlets on stdio.
    const server = await scp.mcpServerCreate({
      identityDid: identity.did,
      contextIds: [ctx.contextId],
      transport: "stdio",
    });
    console.log("MCP server running, exposing outlets");

    try {
      // Or connect as an MCP client to an SCP SSE server on this machine that
      // exposes this context. An SCP SSE server always runs a bearer check
      // (ADR-015), so pass the token that server's operator gives you; this
      // example reads it from SCP_MCP_SSE_TOKEN. The transport has no TLS, so
      // a token is sent only to a loopback host.
      const sseToken = process.env.SCP_MCP_SSE_TOKEN;
      if (sseToken === undefined || sseToken === "") {
        throw new Error("set SCP_MCP_SSE_TOKEN to the bearer token of the SCP SSE server");
      }
      const client = await scp.mcpClientConnectSse("http://localhost:8080/mcp", sseToken);
      try {
        const outlets = await scp.mcpClientListTools(client);
        console.log(`The server offers ${outlets.length} outlet(s)`);

        const result = await scp.mcpClientInvoke(
          client,
          "summarize",
          JSON.stringify({ text: "SCP is a protocol for..." }),
          ctx.contextId,
          identity.did,
        );
        console.log("Result:", result);
      } finally {
        await scp.mcpClientDisconnect(client);
      }
    } finally {
      await scp.mcpServerStop(server);
    }

    await scp.contextClose(ctx._rawHandle, identity.did);
  } finally {
    await scp.shutdown(5);
  }
}

main().catch((error: unknown) => {
  console.error("Demo failed:", error);
  process.exit(1);
});
