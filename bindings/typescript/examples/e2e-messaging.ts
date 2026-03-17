/**
 * E2E encrypted messaging demo.
 *
 * Starts an in-memory relay, creates two identities, creates an encrypted
 * context, joins both participants, sends a message from Alice, receives
 * it as Bob, and shuts everything down cleanly.
 *
 * Run: bun run examples/e2e-messaging.ts
 */

import { connectLocalTransport, Context, Identity, Relay } from "@limn-works/scp-ts";

async function main(): Promise<void> {
  // 1. Start an in-memory relay (zero external dependencies)
  const relay = await Relay.startInMemory();
  try {
    console.log(`Relay listening at ${relay.relayUrl}`);

    // 1b. Connect transport to the relay
    await connectLocalTransport(relay.relayUrl);

    // 2. Create two identities
    const alice = await Identity.create({ custody: "in_memory" });
    const bob = await Identity.create({ custody: "in_memory" });
    console.log(`Alice DID: ${alice.did}`);
    console.log(`Bob DID:   ${bob.did}`);

    // 3. Alice creates an encrypted context on this relay
    const ctx = await Context.create(alice, {
      ceiling: ["messages:read", "messages:write", "member:invite"],
      memoryScope: "ephemeral",
      governance: "single_admin",
      ttl: 300,
    });
    console.log(`Context created: ${ctx.contextId}`);

    // 4. Bob joins the context
    await ctx.join(bob);
    console.log("Bob joined the context");

    // 5. Alice sends a message
    const plaintext = new TextEncoder().encode(
      "Hello Bob, this message is E2E encrypted via MLS",
    );
    await ctx.send(plaintext);
    console.log("Alice sent message");

    // 6. Bob receives the message
    for await (const msg of ctx.receive()) {
      const text = new TextDecoder().decode(msg.content as Uint8Array);
      console.log(`Bob received from ${msg.senderDid}: ${text}`);
      break;
    }

    // 7. Cleanup
    await ctx.leave();
    console.log("Bob left the context");

    await ctx.close();
    console.log("Context closed");
  } finally {
    await relay.shutdown();
    console.log("Relay shut down -- demo complete");
  }
}

main().catch(console.error);
