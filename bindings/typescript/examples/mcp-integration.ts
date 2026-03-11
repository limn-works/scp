/**
 * MCP integration: expose SCP tools via MCP JSON-RPC server.
 */

import { Context, Identity } from "@limn-works/scp-ts";
import { McpClient, serveMcp } from "@limn-works/scp-ts/mcp";

async function main(): Promise<void> {
  const identity = await Identity.create({ custody: "platform" });

  // Create a context with tools
  const ctx = await Context.create(identity, {
    ceiling: ["msg:send", "msg:receive", "tool:invoke", "mcp:serve"],
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

  // Start an MCP server exposing context tools on stdio
  const server = await serveMcp(ctx, { transport: "stdio" });
  console.log(`MCP server running, exposing tools`);

  // Or connect as an MCP client to a remote server
  const client = await McpClient.connect("ws://localhost:8080/mcp");
  const tools = await client.listTools();
  console.log(`Remote server offers ${tools.length} tool(s)`);

  const result = await client.callTool("summarize", {
    text: "SCP is a protocol for...",
  });
  console.log("Result:", result);

  await client.close();
  await server.stop();
  await ctx.close();
}

main().catch(console.error);
