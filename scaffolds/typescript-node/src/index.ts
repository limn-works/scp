/**
 * Minimal SCP agent in Node.js/Bun.
 *
 * Creates a DID identity, opens an encrypted context, and sends a message.
 * Uses the NAPI native addon for full performance.
 *
 * Usage:
 *   bun run src/index.ts
 */

import { Context, Identity } from "@limn-works/scp-ts";

async function main(): Promise<void> {
  // 1. Create a DID identity with in-memory key custody.
  const identity = await Identity.create({ custody: "in_memory" });
  console.log(`Created identity: ${identity.did}`);

  // 2. Create an encrypted context with messaging capabilities.
  const ctx = await Context.create(identity, {
    ceiling: ["messages:read", "messages:write", "role:assign", "member:invite"],
    memoryScope: "ephemeral",
  });
  console.log(`Created context: ${ctx.contextId}`);

  // 3. Send a message.
  await ctx.send("Hello, SCP!");
  console.log("  Message sent.");

  // 4. Clean up.
  await ctx.leave();
  console.log("\nAgent complete.");
}

main().catch(console.error);
