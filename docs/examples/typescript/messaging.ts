/**
 * Two-participant message exchange over a relay.
 *
 * Demonstrates two nodes that each attach a relay transport, a context that
 * Alice creates and Bob joins, a subscription on Bob's side, and a message
 * that Alice sends to it.
 *
 * The creator and the joiner each run their own `SCP` instance with its own
 * database, as two devices would. Each passes its own `KeyCustodyProvider`,
 * which is how the `"os_keystore"` custody request of spec `03-identity.md`
 * §3.2.2 reaches a host key store.
 *
 * Prerequisites:
 *   bun add @limn-works/scp-ts
 *
 * Usage:
 *   import { messagingExample } from "./messaging";
 *   await messagingExample(aliceProvider, bobProvider, relayUrl, storagePassphrase);
 */

import {
  type Context,
  ContextError,
  type ContextParams,
  type KeyCustodyProvider,
  SCP,
} from "@limn-works/scp-ts";

/**
 * A send fails with this code until a peer's routing announcement has arrived
 * over the relay (spec §9.10.4). The send is rolled back, so a retry is safe.
 */
const NO_PEER_ROUTE = "SCP-CTX-2095";
const SEND_ATTEMPTS = 10;
const RETRY_DELAY_MS = 500;
const RECEIVE_TIMEOUT_MS = 10_000;

/** The fields this example reads from a delivered message. */
interface ReceivedMessage {
  readonly senderDid: string;
  readonly payload: Uint8Array;
}

/** Narrow the subscription callback's value, rejecting any other shape. */
function readMessage(value: unknown): ReceivedMessage {
  if (typeof value !== "object" || value === null) {
    throw new TypeError("subscription delivered a non-object message");
  }
  const { senderDid, payload } = value as { senderDid?: unknown; payload?: unknown };
  if (typeof senderDid !== "string") {
    throw new TypeError("message has no senderDid string");
  }
  if (payload instanceof Uint8Array) {
    return { senderDid, payload };
  }
  if (Array.isArray(payload) && payload.every((b) => typeof b === "number")) {
    return { senderDid, payload: Uint8Array.from(payload as number[]) };
  }
  throw new TypeError("message has no byte payload");
}

async function sendWhenRoutable(
  node: SCP,
  ctx: Context,
  senderDid: string,
  payload: Uint8Array,
): Promise<void> {
  for (let attempt = 1; ; attempt += 1) {
    try {
      await node.contextSend(ctx, senderDid, payload);
      return;
    } catch (err) {
      const retryable = err instanceof ContextError && err.code === NO_PEER_ROUTE;
      if (!retryable || attempt === SEND_ATTEMPTS) throw err;
      await new Promise((resolve) => setTimeout(resolve, RETRY_DELAY_MS));
    }
  }
}

export async function messagingExample(
  aliceProvider: KeyCustodyProvider,
  bobProvider: KeyCustodyProvider,
  relayUrl: string,
  storagePassphrase: string,
): Promise<void> {
  const aliceNode = new SCP({
    storage: { type: "sqlite", path: "./scp-messaging-alice", passphrase: storagePassphrase },
  });
  const bobNode = new SCP({
    storage: { type: "sqlite", path: "./scp-messaging-bob", passphrase: storagePassphrase },
  });
  try {
    // 1. Each side creates its identity in its own node.
    const alice = await aliceNode.identityCreateWithCustody(aliceProvider);
    const bob = await bobNode.identityCreateWithCustody(bobProvider);
    console.log(`Alice: ${alice.did}`);
    console.log(`Bob:   ${bob.did}`);

    // 2. Each node attaches its relay transport before it creates or joins a
    //    context: the context supervisor starts on the first context and
    //    binds the transport it finds then. transportConnect opens the
    //    connection that contextSubscribe reads from.
    for (const [node, did] of [
      [aliceNode, alice.did],
      [bobNode, bob.did],
    ] as const) {
      await node.configureRelayTransport(relayUrl, did);
      await node.transportConnect(relayUrl);
    }

    // 3. Alice creates a single-admin context. Inviting runs through the
    //    governance gate, so the ceiling carries governance:propose.
    const params: ContextParams = {
      ceiling: [
        "messages:read",
        "messages:write",
        "member:invite",
        "member:remove",
        "governance:propose",
      ],
      memoryScope: "ephemeral",
      mode: "Encrypted",
      governance: "single_admin",
    };
    const ctx = await aliceNode.contextCreate(alice, JSON.stringify(params));
    console.log(`\nContext: ${ctx.contextId}`);

    // 4. Bob reserves a KeyPackage, Alice seals an invitation to it, and Bob
    //    joins from the sealed bundle.
    const reservation = await bobNode.reserveKeyPackage(bob.did);
    const outcome = await aliceNode.inviteMember(
      ctx.contextId,
      alice.did,
      bob.did,
      reservation.keyPackagePublic,
      [relayUrl],
    );
    const bobCtx = await bobNode.contextJoinFromWelcome(
      bob.did,
      outcome.bundle,
      reservation.reservationId,
    );
    console.log("Bob joined the context.");

    // 5. Bob subscribes before Alice sends. The first message settles the
    //    promise; a timer bounds the wait.
    let timer: ReturnType<typeof setTimeout> | undefined;
    const firstMessage = new Promise<ReceivedMessage>((resolve, reject) => {
      timer = setTimeout(
        () => reject(new Error(`no message within ${RECEIVE_TIMEOUT_MS} ms`)),
        RECEIVE_TIMEOUT_MS,
      );
      bobNode
        .contextSubscribe(bobCtx, bob.did, (message) => {
          try {
            resolve(readMessage(message));
          } catch (err) {
            reject(err);
          }
        })
        .catch(reject);
    });

    try {
      // 6. Alice sends once Bob's routing announcement has reached her.
      await sendWhenRoutable(aliceNode, ctx, alice.did, new TextEncoder().encode("Hello Bob!"));
      console.log("\nAlice: Hello Bob!");

      // 7. Bob reads the message.
      const received = await firstMessage;
      console.log(
        `Bob received from ${received.senderDid}: ${new TextDecoder().decode(received.payload)}`,
      );
    } finally {
      clearTimeout(timer);
      bobNode.contextCancelSubscription(bobCtx);
    }

    // 8. Bob leaves the context.
    await bobNode.contextLeave(bobCtx, bob.did);
    console.log("\nBob left the context.");
  } finally {
    await bobNode.shutdown();
    await aliceNode.shutdown();
  }
}
