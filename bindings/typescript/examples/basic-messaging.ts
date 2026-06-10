/**
 * Basic messaging: create identities, create a context, send a message, and
 * receive it on a subscriber callback.
 *
 * Post-Phase-4 (ADR-048): every SDK call routes through an explicit `SCP`
 * instance. Construct one at process start, invoke bridge operations as
 * `scp.<method>(...)`, and call `scp.shutdown(...)` to drain in-flight
 * work on exit.
 */

import { SCP } from "../src/index";

async function main(): Promise<void> {
  const scp = new SCP({ storage: { type: "in_memory" } });
  try {
    // Create two identities (in_memory custody for examples).
    const alice = await scp.identityCreate("in_memory");
    const bob = await scp.identityCreate("in_memory");
    console.log(`Alice DID: ${alice.did}`);
    console.log(`Bob DID: ${bob.did}`);

    // Alice creates a context and Bob joins it.
    const ctx = await scp.contextCreate(
      alice,
      JSON.stringify({
        ceiling: ["messages:read", "messages:write", "member:invite"],
        memoryScope: "ephemeral",
        governance: "single_admin",
        ttl: 3600,
      }),
    );
    console.log(`Context ID: ${ctx.contextId}`);

    await scp.contextJoin(ctx._rawHandle, bob.did, null);

    // Subscribe Bob to incoming messages BEFORE Alice sends so we don't
    // race the first payload.
    let received: { senderDid: string; payload: Uint8Array } | null = null;
    await scp.contextSubscribe(ctx._rawHandle, bob.did, (raw) => {
      const msg = raw as { senderDid?: string; payload?: number[] | Uint8Array };
      if (msg?.senderDid !== undefined && msg.payload !== undefined) {
        const bytes = msg.payload instanceof Uint8Array ? msg.payload : new Uint8Array(msg.payload);
        received = { senderDid: msg.senderDid, payload: bytes };
      }
    });

    // Alice sends a message.
    await scp.contextSend(
      ctx._rawHandle,
      alice.did,
      new TextEncoder().encode("Hello Bob, this is Alice"),
      null,
    );

    // Give the subscription a chance to flush.
    await new Promise((resolve) => setTimeout(resolve, 50));
    if (received !== null) {
      const { senderDid, payload } = received as { senderDid: string; payload: Uint8Array };
      console.log(`Bob received from ${senderDid}: ${new TextDecoder().decode(payload)}`);
    }

    // Leave and close.
    await scp.contextLeave(ctx._rawHandle, bob.did);
    await scp.contextClose(ctx._rawHandle, alice.did);
  } finally {
    // Graceful bridge shutdown — drains in-flight tasks within 5 seconds.
    await scp.shutdown(5);
  }
}

main().catch((error: unknown) => {
  console.error("Demo failed:", error);
  process.exit(1);
});
