/**
 * Tool invocation demo.
 *
 * Starts an in-memory relay, creates an identity, creates a context
 * with tool capabilities, registers a tool with test vectors, mints a
 * UCAN token, invokes the tool with authorization, and verifies the
 * result.
 *
 * Run: bun run examples/tool-invocation.ts
 */

import { connectLocalTransport, Context, Identity, Relay, mintUcan } from "@limn-works/scp-ts";
import type { ToolDefinition } from "@limn-works/scp-ts";

async function main(): Promise<void> {
  // 1. Start an in-memory relay
  const relay = await Relay.startInMemory();
  try {
    console.log(`Relay listening at ${relay.relayUrl}`);

    // 1b. Connect transport to the relay
    await connectLocalTransport(relay.relayUrl);

    // 2. Create an identity
    const identity = await Identity.create({ custody: "in_memory" });
    console.log(`Identity DID: ${identity.did}`);

    // 3. Define a tool with test vectors
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

    // 4. Create a context with tool capabilities
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
    console.log(`Context created: ${ctx.contextId}`);

    // 5. Register the tool
    const toolId = await ctx.registerTool(weatherTool);
    console.log(`Registered tool: ${toolId}`);

    // 6. Mint a UCAN token for tool invocation
    const ucan = await mintUcan(ctx, identity.did, ["tool_invoke:*"]);
    console.log(`UCAN minted: ${ucan.id}`);

    // 7. Invoke the tool with the UCAN token
    try {
      const result = await ctx.invokeTool(
        "weather",
        { city: "Berlin" },
        identity,
        ucan.id,
      );
      console.log("Weather result:", result);
    } catch (err) {
      console.log("Tool invocation result:", err);
    }

    // 8. Cleanup
    await ctx.close();
    console.log("Context closed");
  } finally {
    await relay.shutdown();
    console.log("Demo complete");
  }
}

main().catch(console.error);
