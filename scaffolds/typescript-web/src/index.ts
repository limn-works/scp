/**
 * Minimal SCP example (in-process via the NAPI native addon).
 *
 * Creates a DID identity, opens an encrypted context, and sends a message.
 *
 * This runs the protocol engine in-process through `@limn-works/scp-ts`, whose
 * NAPI native addon loads only under Node.js / Bun — NOT in a browser. So this
 * is a server-side (Node/Bun) example, even though the DOM code below previews a
 * future browser UI.
 *
 * Browser support is forthcoming and not what this does today: per ADR-055 the
 * browser model is a remote thin client to a server-side scp-node over
 * RPC/WebSocket (no in-browser protocol execution). That transport does not
 * exist yet — until it lands, run this under Bun/Node, not in a browser.
 *
 * Usage:
 *   bun install && bun run start   # builds and runs under Bun
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
