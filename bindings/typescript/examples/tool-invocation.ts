/**
 * Tool invocation: register a tool with test vectors and invoke it.
 */

import { Context, Identity, mintUcan } from "@limn-works/scp-ts";
import type { ToolDefinition } from "@limn-works/scp-ts";

async function main(): Promise<void> {
  const identity = await Identity.create({ custody: "in_memory" });

  const weatherTool: ToolDefinition = {
    name: "weather",
    description: "Get current weather for a city",
    inputSchema: {
      type: "object",
      properties: { city: { type: "string" } },
      required: ["city"],
    },
    outputSchema: {
      type: "object",
      properties: {
        tempC: { type: "number" },
        condition: { type: "string" },
      },
    },
    operator: identity.did,
    testVectors: [
      {
        input: { city: "Berlin" },
        expectedOutput: { tempC: 18, condition: "cloudy" },
        description: "Berlin weather lookup",
      },
    ],
  };

  const ctx = await Context.create(identity, {
    ceiling: ["messages:read", "messages:write", "tool:invoke:*", "tool:register"],
    memoryScope: "ephemeral",
    governance: "single_admin",
  });

  // Register the tool
  const toolId = await ctx.registerTool(weatherTool);
  console.log(`Registered tool: ${toolId}`);

  // Mint a UCAN token for tool invocation (§7.2 — required for all actions)
  const ucan = await mintUcan(ctx, identity.did, ["tool_invoke:*"]);

  // Invoke the tool with the UCAN token
  const result = await ctx.invokeTool("weather", { city: "Berlin" }, identity, ucan.id);
  console.log("Weather result:", result);

  await ctx.close();
}

main().catch(console.error);
