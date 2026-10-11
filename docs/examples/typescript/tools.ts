/**
 * Outlet registration and invocation within a context.
 *
 * Demonstrates defining a query outlet with JSON schemas and test vectors,
 * registering it in a context, verifying it against its vectors, and
 * invoking it under a UCAN that grants the call.
 *
 * The TypeScript SDK ships no production key store, so the caller passes a
 * `KeyCustodyProvider`; its one `CustodyType`, `"in_memory"`, works only
 * with an addon built with the `testing` feature.
 *
 * Prerequisites:
 *   bun add @limn-works/scp-ts
 *
 * Usage:
 *   import { toolsExample } from "./tools";
 *   await toolsExample(operatorProvider, process.env.SCP_STORAGE_PASSPHRASE);
 */

import {
  Capabilities,
  type ContextParams,
  defineOutletDefinition,
  type KeyCustodyProvider,
  type OutletDefinition,
  outletQuery,
  SCP,
} from "@limn-works/scp-ts";

/**
 * Read a field the native result object exposes, rejecting any other shape.
 * `ucanMint` and `outletVerify` type their results as `unknown`.
 */
function field(value: unknown, name: string): unknown {
  if (typeof value !== "object" || value === null || !(name in value)) {
    throw new TypeError(`result has no ${name} field`);
  }
  return (value as Record<string, unknown>)[name];
}

function stringField(value: unknown, name: string): string {
  const v = field(value, name);
  if (typeof v !== "string") throw new TypeError(`${name} is not a string`);
  return v;
}

function booleanField(value: unknown, name: string): boolean {
  const v = field(value, name);
  if (typeof v !== "boolean") throw new TypeError(`${name} is not a boolean`);
  return v;
}

export async function toolsExample(
  operatorProvider: KeyCustodyProvider,
  storagePassphrase: string,
): Promise<void> {
  const scp = new SCP({
    storage: { type: "sqlite", path: "./scp-tools", passphrase: storagePassphrase },
  });
  try {
    // 1. Create an identity for the outlet operator.
    const operator = await scp.identityCreateWithCustody(operatorProvider);
    console.log(`Operator DID: ${operator.did}`);

    // 2. Create a context whose ceiling allows registering outlets and
    //    calling query outlets.
    const params: ContextParams = {
      ceiling: [
        Capabilities.MESSAGES_READ,
        Capabilities.MESSAGES_WRITE,
        Capabilities.OUTLET_REGISTER,
        Capabilities.OUTLET_QUERY_ALL,
      ],
      memoryScope: "ephemeral",
      mode: "Encrypted",
      governance: "single_admin",
    };
    const ctx = await scp.contextCreate(operator, JSON.stringify(params));
    console.log(`Context: ${ctx.contextId}`);

    // 3. Define a calculator. defineOutletDefinition validates the required
    //    fields; a query outlet is read-only and never billed.
    const calculator: OutletDefinition = defineOutletDefinition({
      name: "calculator",
      description: "A simple arithmetic calculator",
      kind: "query",
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
    console.log(`\nOutlet defined: ${calculator.name}`);
    console.log(`  Description: ${calculator.description}`);

    // 4. Register the outlet in the context.
    const outletId = await scp.outletRegister(ctx, calculator);
    console.log(`  Registered with ID: ${outletId}`);

    // 5. Verify the outlet against its test vectors.
    const verification = await scp.outletVerify(ctx, outletId);
    console.log(`  Verification passed: ${booleanField(verification, "passed")}`);

    // 6. Mint a UCAN that grants calling this one query outlet.
    const ucan = await scp.ucanMint(ctx, operator.did, [outletQuery(outletId)]);
    const ucanToken = stringField(ucan, "encoded");
    console.log("\nUCAN minted.");

    // 7. Invoke the outlet. Awaiting the handle drains the stream to its
    //    aggregated result.
    const result = await ctx.outlets.invoke(outletId, { a: 7, b: 3, op: "mul" }, { ucanToken });
    console.log("\nInvoked calculator: 7 * 3");
    console.log(`  Result: ${JSON.stringify(result.value)}`);

    // 8. Close the context.
    await scp.contextClose(ctx, operator.did);
    console.log("\nOutlet operations complete.");
  } finally {
    await scp.shutdown();
  }
}
