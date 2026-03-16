/**
 * MCP integration: expose SCP tools via MCP JSON-RPC server.
 */

import { Context, Identity } from "@limn-works/scp-ts";
import { connectMcp, serveMcp } from "@limn-works/scp-ts/mcp";

async function main(): Promise<void> {
  const identity = await Identity.create({ custody: "in_memory" });

  // Create a context with tool capabilities
  const ctx = await Context.create(identity, {
    ceiling: [
      "messages:read",
      "messages:write",
      "tool:invoke:*",
      "tool:register",
    ],
    memoryScope: "ephemeral",
    governance: "single_admin",
  });

  // Register a tool in the context
  await ctx.registerTool({
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

  // Start an MCP server exposing context tools on stdio
  const server = await serveMcp(ctx, {
    tools: [
      {
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
      },
    ],
  });
  console.log("MCP server running, exposing tools");

  // Or connect as an MCP client to a remote server
  const client = await connectMcp({ serverUrl: "http://localhost:8080/mcp" });
  const tools = await client.listTools();
  console.log(`Remote server offers ${tools.length} tool(s)`);

  const result = await client.invokeTool("summarize", {
    text: "SCP is a protocol for...",
  });
  console.log("Result:", result);

  await client.disconnect();
  await server.stop();
  await ctx.close();
}

main().catch(console.error);
