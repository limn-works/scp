/**
 * MCP integration: expose SCP tools via an MCP JSON-RPC server, then
 * connect as an MCP client to a remote server.
 *
 * Post-Phase-4 (ADR-048): all bridge operations route through an
 * explicit `SCP` instance. The free-function shims (`serveMcp`,
 * `connectMcp`, `connectMcpStdio`) were removed — use
 * `scp.mcpServerCreate`, `scp.mcpClientConnectSse`, and the other
 * `scp.mcp*` methods directly.
 *
 * Run: bun run examples/mcp-integration.ts
 */

import { SCP, defineToolDefinition } from "../src/index";

async function main(): Promise<void> {
  const scp = new SCP();
  try {
    const identity = await scp.identityCreate("in_memory");

    // Create a context with tool capabilities.
    const ctx = await scp.contextCreate(
      identity,
      JSON.stringify({
        ceiling: ["messages:read", "messages:write", "tool:invoke:*", "tool:register"],
        memoryScope: "ephemeral",
        governance: "single_admin",
      }),
    );

    // Register a tool in the context.
    const tool = defineToolDefinition({
      name: "summarize",
      description: "Summarize text content",
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
    await scp.toolRegister(ctx._rawHandle, tool);

    // Start an MCP server exposing context tools on stdio.
    const server = await scp.mcpServerCreate({
      identityDid: identity.did,
      contextIds: [ctx.contextId],
      transport: "stdio",
    });
    console.log("MCP server running, exposing tools");

    try {
      // Or connect as an MCP client to a remote server.
      const client = await scp.mcpClientConnectSse("http://localhost:8080/mcp");
      try {
        const tools = await scp.mcpClientListTools(client);
        console.log(`Remote server offers ${tools.length} tool(s)`);

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
