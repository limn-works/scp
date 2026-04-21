/**
 * Basic messaging: create identity, create context, send and receive messages.
 *
 * Post-Phase-4 (ADR-048): every SDK call routes through an explicit `SCP`
 * instance. Construct one at process start, pass it to `Identity.create`,
 * and call `scp.shutdown(...)` to drain in-flight work on exit.
 */

import { Context, Identity, SCP } from "@limn-works/scp-ts";

async function main(): Promise<void> {
  const scp = new SCP();
  try {
    // Create two identities (in_memory custody for examples)
    const alice = await Identity.create(scp, { custody: "in_memory" });
    const bob = await Identity.create(scp, { custody: "in_memory" });
    console.log(`Alice DID: ${alice.did}`);
    console.log(`Bob DID: ${bob.did}`);

    // Alice creates a context
    const ctx = await Context.create(alice, {
      ceiling: ["messages:read", "messages:write"],
      memoryScope: "ephemeral",
      governance: "single_admin",
      ttl: 3600,
    });
    console.log(`Context ID: ${ctx.contextId}`);

    // Bob joins the context (admin adds bob via the context instance)
    await ctx.join(bob);

    // Alice sends a message
    await ctx.send(new TextEncoder().encode("Hello Bob, this is Alice"));

    // Bob receives it
    for await (const msg of ctx.receive()) {
      const text = new TextDecoder().decode(msg.content as Uint8Array);
      console.log(`Bob received from ${msg.senderDid}: ${text}`);
      break;
    }

    // Cleanup
    await ctx.leave();
    await ctx.close();
  } finally {
    // Graceful bridge shutdown — drains in-flight tasks within 5 seconds.
    await scp.shutdown(5);
  }
}

main().catch(console.error);
