/**
 * Broadcast demo.
 *
 * Starts an in-memory relay, creates a broadcast context, subscribes a
 * listener, publishes a message, and verifies receipt.
 *
 * Run: bun run examples/broadcast.ts
 */

import { connectLocalTransport, Context, Identity, Relay } from "@limn-works/scp-ts";

async function main(): Promise<void> {
  // 1. Start an in-memory relay
  const relay = await Relay.startInMemory();
  try {
    console.log(`Relay listening at ${relay.relayUrl}`);

    // 1b. Connect transport to the relay
    await connectLocalTransport(relay.relayUrl);

    // 2. Create publisher and subscriber identities
    const publisher = await Identity.create({ custody: "in_memory" });
    const subscriber = await Identity.create({ custody: "in_memory" });
    console.log(`Publisher DID:  ${publisher.did}`);
    console.log(`Subscriber DID: ${subscriber.did}`);

    // 3. Create a broadcast context
    const ctx = await Context.create(publisher, {
      ceiling: ["messages:read", "messages:write", "member:invite"],
      memoryScope: "ephemeral",
      governance: "single_admin",
      mode: "broadcast",
      ttl: 300,
    });
    console.log(`Broadcast context created: ${ctx.contextId}`);

    // 4. Subscriber joins
    await ctx.join(subscriber);
    console.log("Subscriber joined");

    // 5. Publisher sends a broadcast message
    const payload = new TextEncoder().encode(
      "Breaking news: SCP protocol is live!",
    );
    await ctx.send(payload);
    console.log("Publisher sent broadcast");

    // 6. Subscriber receives the broadcast
    for await (const msg of ctx.receive()) {
      const text = new TextDecoder().decode(msg.content as Uint8Array);
      console.log(`Subscriber received: ${text}`);
      break;
    }

    // 7. Cleanup
    await ctx.close();
    console.log("Context closed");
  } finally {
    await relay.shutdown();
    console.log("Demo complete");
  }
}

main().catch(console.error);
