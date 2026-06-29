/**
 * Minimal SCP browser app (remote thin client).
 *
 * Creates a DID identity, opens an encrypted context, and sends a message.
 * In the browser the SDK is a remote thin client: it drives a server-side
 * scp-node that runs the protocol engine.
 *
 * Usage:
 *   bun install && bun run build
 *   Open index.html in a browser
 */

import { Context, Identity } from "@limn-works/scp-ts";

async function main(): Promise<void> {
  const output = document.getElementById("output");
  const log = (msg: string) => {
    if (output) output.textContent += msg + "\n";
    console.log(msg);
  };

  // 1. Create a DID identity with in-memory key custody.
  const identity = await Identity.create({ custody: "in_memory" });
  log(`Created identity: ${identity.did}`);

  // 2. Create an encrypted context with messaging capabilities.
  const ctx = await Context.create(identity, {
    ceiling: ["messages:read", "messages:write"],
    memoryScope: "ephemeral",
  });
  log(`Created context: ${ctx.contextId}`);

  // 3. Send a message.
  await ctx.send("Hello from the browser!");
  log("Message sent.");

  // 4. Clean up.
  await ctx.leave();
  log("\nBrowser app complete.");
}

main().catch(console.error);
