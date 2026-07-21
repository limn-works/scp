/**
 * ONE functional wiring example for `@limn-works/scp-ts-wasm` (ADR-057 Slice 3).
 *
 * Shows the batteries-included browser path end to end: WebCrypto custody +
 * IndexedDB storage + the managed WebSocket relay transport, then the participant
 * message flow (create → add → join → send → receive). The polished demo pair is
 * Slice-4 / #1951; this is the minimal, correct wiring the SDK's happy path
 * produces.
 *
 * Run in a browser (or any host with WebCrypto + IndexedDB + WebSocket). The
 * `did` values come from your identity flow; the relay URL is your SCP relay.
 */

import {
  type AddMemberOutput,
  IndexedDbStorage,
  ScpBrowserClient,
  type ScpBrowserClient as ScpBrowserClientType,
  type SenderKeyDistribution,
  WebCryptoCustody,
} from "@limn-works/scp-ts-wasm";

/** Connects a fully-wired in-browser client for `did` over `relayUrl`. */
async function connect(did: string, relayUrl: string): Promise<ScpBrowserClientType> {
  // On-device key custody (WebCrypto) + durable storage (IndexedDB). Both are
  // explicit, injected ports — the SDK never reaches for a hidden default.
  const custody = await WebCryptoCustody.create({ did });
  const storage = await IndexedDbStorage.open();

  // The managed transport wires the inbound pump + reconnect for you: on every
  // (re)open it re-drives SUBSCRIBEs (resubscribeAll); on every relay frame it
  // feeds handleRelayFrame; on drop it reconnects with backoff.
  return ScpBrowserClient.connect({
    custody,
    storage,
    url: relayUrl,
    onError: (err) => console.error(`[scp] relay pump error ${err.code}:`, err.message),
  });
}

/** Routes each §9.16 sender-key distribution to its target participant. */
function deliverSenderKeys(
  distributions: SenderKeyDistribution[],
  route: (targetDid: string, ciphertext: Uint8Array) => void,
): void {
  for (const dist of distributions) {
    // Deliver `dist.ciphertext` to `dist.targetDid`'s receiveMessage — over your
    // own out-of-band channel or a directed relay publish.
    route(dist.targetDid, dist.ciphertext);
  }
}

export async function main(): Promise<void> {
  const relayUrl = "wss://relay.example";
  const aliceDid = "did:dht:z6MkAlice…";
  const bobDid = "did:dht:z6MkBob…";

  const alice = await connect(aliceDid, relayUrl);
  const bob = await connect(bobDid, relayUrl);

  // Alice creates a context; Bob generates a join key package.
  const contextId = "demo-context";
  alice.createContext(contextId);
  const bobKeyPackage = bob.generateKeyPackageForJoin(contextId);

  // Alice adds Bob and shares the join replay material + sender keys.
  const add: AddMemberOutput = alice.addMember(contextId, bobKeyPackage);
  const bobDistributions = bob.joinContextEncrypted(
    contextId,
    add.welcome,
    add.eventLog,
    add.wrappingKeys,
  );

  // Exchange §9.16 sender keys (both directions) so app-data can decrypt.
  const route = (targetDid: string, ciphertext: Uint8Array): void => {
    const target = targetDid === aliceDid ? alice : bob;
    target.receiveMessage(contextId, ciphertext);
  };
  deliverSenderKeys(add.senderKeyDistributions, route);
  deliverSenderKeys(bobDistributions, route);

  // Alice sends; the ciphertext fans out over the relay. Bob receives it through
  // the managed pump and drains it.
  alice.sendMessage(contextId, new TextEncoder().encode("hello, Bob"));
  for (const event of bob.drainEvents(contextId)) {
    if (event.kind === "MessageReceived") {
      console.log(`from ${event.senderDid}:`, new TextDecoder().decode(event.payload));
    }
  }

  alice.disconnect();
  bob.disconnect();
}
