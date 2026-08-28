/**
 * E2E encrypted messaging demo.
 *
 * Starts an in-memory relay via the caller-owned `SCP`, creates two
 * identities, creates an encrypted context, joins both participants,
 * sends a message from Alice, receives it as Bob, and shuts everything
 * down cleanly.
 *
 * Post-Phase-4 (ADR-048): every SDK call routes through an explicit
 * `SCP` instance. The static `Relay.startInMemory()` factory was
 * removed — construct via `scp.relayStartInMemory()`.
 *
 * Run: bun run examples/e2e-messaging.ts
 */

import { SCP } from "../src/index";

async function main(): Promise<void> {
  const scp = new SCP({ storage: { type: "in_memory" } });
  let relay: Awaited<ReturnType<SCP["relayStartInMemory"]>> | null = null;
  try {
    // 1. Start an in-memory relay (zero external dependencies).
    relay = await scp.relayStartInMemory();
    console.log(`Relay listening at ${relay.relayUrl}`);

    // 2. Create two identities.
    const alice = await scp.identityCreate("encrypted_file");
    const bob = await scp.identityCreate("encrypted_file");
    console.log(`Alice DID: ${alice.did}`);
    console.log(`Bob DID:   ${bob.did}`);

    // 3. Wire the bridge's transport to the relay.
    await scp.configureRelayTransport(relay.relayUrl, alice.did);

    // 4. Alice creates an encrypted context on this relay.
    const ctx = await scp.contextCreate(
      alice,
      JSON.stringify({
        ceiling: ["messages:read", "messages:write", "member:invite"],
        memoryScope: "ephemeral",
        governance: "single_admin",
        ttl: 300,
      }),
    );
    console.log(`Context created: ${ctx.contextId}`);

    // 5. Bob joins the context.
    await scp.contextJoin(ctx._rawHandle, bob.did, null);
    console.log("Bob joined the context");

    // 6. Subscribe Bob before Alice sends.
    let received: { senderDid: string; payload: Uint8Array } | null = null;
    await scp.contextSubscribe(ctx._rawHandle, bob.did, (raw) => {
      const msg = raw as { senderDid?: string; payload?: number[] | Uint8Array };
      if (msg?.senderDid !== undefined && msg.payload !== undefined) {
        const bytes = msg.payload instanceof Uint8Array ? msg.payload : new Uint8Array(msg.payload);
        received = { senderDid: msg.senderDid, payload: bytes };
      }
    });

    // 7. Alice sends a message.
    const plaintext = new TextEncoder().encode(
      "Hello Bob, this message is E2E encrypted via MLS",
    );
    await scp.contextSend(ctx._rawHandle, alice.did, plaintext, null);
    console.log("Alice sent message");

    // 8. Give the subscription a chance to flush, then report.
    await new Promise((resolve) => setTimeout(resolve, 100));
    if (received !== null) {
      const { senderDid, payload } = received as { senderDid: string; payload: Uint8Array };
      console.log(`Bob received from ${senderDid}: ${new TextDecoder().decode(payload)}`);
    }

    // 9. Cleanup.
    await scp.contextLeave(ctx._rawHandle, bob.did);
    console.log("Bob left the context");

    await scp.contextClose(ctx._rawHandle, alice.did);
    console.log("Context closed");
  } finally {
    if (relay !== null) {
      await relay.shutdown();
    }
    await scp.shutdown(5);
    console.log("Relay shut down -- demo complete");
  }
}

main().catch((error: unknown) => {
  console.error("Demo failed:", error);
  process.exit(1);
});
