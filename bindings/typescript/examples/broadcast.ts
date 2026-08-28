/**
 * Broadcast demo.
 *
 * Starts an in-memory relay via the caller-owned `SCP`, creates a
 * broadcast context, subscribes a listener, publishes a message, and
 * verifies receipt.
 *
 * Post-Phase-4 (ADR-048): all bridge operations route through an
 * explicit `SCP` instance. `Relay.startInMemory()` / `startLocal()`
 * static factories were removed — construct a relay via
 * `scp.relayStartInMemory()`.
 *
 * Run: bun run examples/broadcast.ts
 */

import { SCP } from "../src/index";

async function main(): Promise<void> {
  const scp = new SCP({ storage: { type: "in_memory" } });
  let relay: Awaited<ReturnType<SCP["relayStartInMemory"]>> | null = null;
  try {
    // 1. Start an in-memory relay.
    relay = await scp.relayStartInMemory();
    console.log(`Relay listening at ${relay.relayUrl}`);

    // 2. Create publisher and subscriber identities.
    const publisher = await scp.identityCreate("encrypted_file");
    const subscriber = await scp.identityCreate("encrypted_file");
    console.log(`Publisher DID:  ${publisher.did}`);
    console.log(`Subscriber DID: ${subscriber.did}`);

    // 3. Wire the bridge's transport to the relay.
    await scp.configureRelayTransport(relay.relayUrl, publisher.did);

    // 4. Create a broadcast context.
    const ctx = await scp.contextCreate(
      publisher,
      JSON.stringify({
        ceiling: ["messages:read", "messages:write", "member:invite"],
        memoryScope: "ephemeral",
        governance: "single_admin",
        mode: "broadcast",
        ttl: 300,
      }),
    );
    console.log(`Broadcast context created: ${ctx.contextId}`);

    // 5. Subscriber joins.
    await scp.contextJoin(ctx._rawHandle, subscriber.did, null);
    console.log("Subscriber joined");

    // 6. Subscribe on the relay before publishing.
    let received: Uint8Array | null = null;
    await scp.contextSubscribe(ctx._rawHandle, subscriber.did, (raw) => {
      const msg = raw as { payload?: number[] | Uint8Array };
      if (msg?.payload !== undefined) {
        received = msg.payload instanceof Uint8Array ? msg.payload : new Uint8Array(msg.payload);
      }
    });

    // 7. Publisher sends a broadcast message.
    const payload = new TextEncoder().encode("Breaking news: SCP protocol is live!");
    await scp.contextSend(ctx._rawHandle, publisher.did, payload, null);
    console.log("Publisher sent broadcast");

    // 8. Give the subscription a chance to flush, then report.
    await new Promise((resolve) => setTimeout(resolve, 100));
    if (received !== null) {
      console.log(`Subscriber received: ${new TextDecoder().decode(received)}`);
    }

    // 9. Cleanup.
    await scp.contextClose(ctx._rawHandle, publisher.did);
    console.log("Context closed");
  } finally {
    if (relay !== null) {
      await relay.shutdown();
    }
    await scp.shutdown(5);
    console.log("Demo complete");
  }
}

main().catch((error: unknown) => {
  console.error("Demo failed:", error);
  process.exit(1);
});
