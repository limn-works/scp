/**
 * Tool invocation: register a tool with test vectors and invoke it.
 */

import { Context, Identity } from "@limn-works/scp-ts";
import type { ToolDefinition } from "@limn-works/scp-ts";

async function main(): Promise<void> {
  const identity = await Identity.create({ custody: "platform" });

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
    ceiling: ["msg:send", "msg:receive", "tool:invoke"],
    tools: [weatherTool],
  });

  // Invoke the tool
  const result = await ctx.invokeTool("weather", { city: "Berlin" });
  console.log("Weather result:", result);

  await ctx.close();
}

main().catch(console.error);
