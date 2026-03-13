/**
 * Tool registration and invocation within a context.
 *
 * Demonstrates defining a tool with a JSON schema, registering it
 * in a context, and invoking it with UCAN authorization.
 *
 * Prerequisites:
 *   bun add @limn-works/scp-ts
 *
 * Usage:
 *   bun run tools.ts
 */

import {
  Context,
  Identity,
  defineToolDefinition,
  mintUcan,
} from "@limn-works/scp-ts";
import type { ContextParams, ToolDefinition } from "@limn-works/scp-ts";

async function main(): Promise<void> {
  // 1. Create an identity for the tool operator.
  const operator = await Identity.create({ custody: "in_memory" });
  console.log(`Operator DID: ${operator.did}`);

  // 2. Create a context with tool capabilities.
  const params: ContextParams = {
    ceiling: [
      "messages:read",
      "messages:write",
      "tool:register",
      "tool:invoke_all",
    ],
  };

  const ctx = await Context.create(operator, params);
  console.log(`Context: ${ctx.contextId}`);

  // 3. Define a calculator tool using the defineToolDefinition helper.
  //    This validates required fields and returns an immutable definition.
  const calculator: ToolDefinition = defineToolDefinition({
    name: "calculator",
    description: "A simple arithmetic calculator",
    inputSchema: {
      type: "object",
      properties: {
        a: { type: "number" },
        b: { type: "number" },
        op: { type: "string", enum: ["add", "sub", "mul"] },
      },
      required: ["a", "b", "op"],
    },
    outputSchema: {
      type: "object",
      properties: {
        result: { type: "number" },
      },
      required: ["result"],
    },
    operator: operator.did,
    testVectors: [
      {
        input: { a: 2, b: 3, op: "add" },
        expectedOutput: { result: 5 },
        description: "2 + 3 = 5",
      },
      {
        input: { a: 7, b: 3, op: "mul" },
        expectedOutput: { result: 21 },
        description: "7 * 3 = 21",
      },
    ],
  });

  console.log(`\nTool defined: ${calculator.name}`);
  console.log(`  Description: ${calculator.description}`);

  // 4. Register the tool in the context.
  const toolId = await ctx.registerTool(calculator);
  console.log(`  Registered with ID: ${toolId}`);

  // 5. Verify the tool against its test vectors.
  const verification = await ctx.verifyTool(toolId);
  console.log(`  Verification passed: ${verification.passed}`);

  // 6. Mint a UCAN token authorizing tool invocation.
  //    The token grants tool_invoke:* capability for this context.
  const ucanToken = await mintUcan(
    operator._handle,
    operator.did,
    JSON.stringify(["tool_invoke:*"]),
  );
  console.log(`\nUCAN minted (length: ${ucanToken.length})`);

  // 7. Invoke the tool with UCAN authorization.
  const result = await ctx.invokeTool(
    toolId,
    { a: 7, b: 3, op: "mul" },
    operator,
    ucanToken,
  );
  console.log(`\nInvoked calculator: 7 * 3`);
  console.log(`  Result: ${JSON.stringify(result)}`);

  // 8. Clean up.
  await ctx.leave();
  console.log("\nTool operations complete.");
}

main().catch(console.error);
