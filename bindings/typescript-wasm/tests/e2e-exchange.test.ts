/**
 * Two-party end-to-end exchange driven through `ScpBrowserClient` against the
 * REAL built wasm and the REAL relay wire protocol (ADR-057 Slice 3).
 *
 * Mirrors the shape of the Rust surface proof
 * (`crates/scp-client-wasm/tests/wasm_surface_exchange.rs`): Alice (creator) and
 * Bob (joiner) go through create / generate-key-package / add-member / join /
 * §9.16 sender-key exchange / §9.10.4 pseudonym announce / send / relay-route /
 * receive / drain / convergence / close — touching ONLY the public
 * `ScpBrowserClient` surface + the production adapters, over the managed
 * WebSocketRelaySocket transport and the faithful in-test relay.
 *
 * There is NO mock of `WasmScpClient` — the client is the actual compiled wasm.
 * The only test double is the external relay (a dumb pipe) and the DID-only
 * custody stub, exactly what a real embedder supplies today.
 */

import { beforeAll, expect, test } from "bun:test";
import {
  ContextError,
  InMemoryStorage,
  type ReceivedEvent,
  ScpBrowserClient,
  type SenderKeyDistribution,
} from "../src/index";
import { loadRealWasm } from "./support/load-wasm";
import { stubCustody } from "./support/stubs";
import { MockWebSocket, TestRelay } from "./support/test-relay";

const CTX = "ctx-adr057-slice3-ts-e2e";
const ALICE = "did:key:z6MkAlice3SurfaceExchangeFixtureKeyAAAAAAA";
const BOB = "did:key:z6MkBob3SurfaceExchangeFixtureKeyBBBBBBBBBB";

beforeAll(async () => {
  await loadRealWasm();
}, 120_000);

/** Connects a client over a fresh MockWebSocket on the shared relay, then opens it. */
async function connectClient(
  relay: TestRelay,
  did: string,
): Promise<{ client: ScpBrowserClient; ws: MockWebSocket }> {
  let ws: MockWebSocket | undefined;
  const client = await ScpBrowserClient.connect({
    custody: stubCustody(did),
    storage: new InMemoryStorage(),
    url: "ws://relay.test",
    createWebSocket: () => {
      const created = new MockWebSocket(relay);
      ws = created;
      return created;
    },
    reconnect: { enabled: false },
  });
  if (!ws) {
    throw new Error("createWebSocket factory was not invoked by connect()");
  }
  ws.open();
  return { client, ws };
}

/** Routes each §9.16 sender-key distribution to its target via receiveMessage (out-of-band). */
function deliverDistributions(
  distributions: SenderKeyDistribution[],
  alice: ScpBrowserClient,
  bob: ScpBrowserClient,
): void {
  for (const d of distributions) {
    const target = d.targetDid === ALICE ? alice : bob;
    if (d.targetDid !== ALICE && d.targetDid !== BOB) {
      throw new Error(`unexpected distribution target ${d.targetDid}`);
    }
    const out = target.receiveMessage(CTX, d.ciphertext);
    expect(out.application).toBe(false);
    expect(out.senderKeyDistributions).toHaveLength(0);
  }
}

/** Wires Alice+Bob into a fully-connected pair (MLS, sender keys, pseudonym mesh). */
function connectPair(relay: TestRelay, alice: ScpBrowserClient, bob: ScpBrowserClient): void {
  alice.createContext(CTX);
  const bobKp = bob.generateKeyPackageForJoin(CTX);
  const add = alice.addMember(CTX, bobKp);
  const bobDists = bob.joinContextEncrypted(CTX, add.welcome, add.eventLog, add.wrappingKeys);

  deliverDistributions(add.senderKeyDistributions, alice, bob);
  deliverDistributions(bobDists, alice, bob);
  relay.pump(); // run the §9.10.4 reciprocal-announce cascade to quiescence

  alice.drainEvents(CTX);
  bob.drainEvents(CTX);
}

function received(events: ReceivedEvent[]): ReceivedEvent[] {
  return events.filter((e) => e.kind === "MessageReceived");
}

test("two-party create/add/join/send/receive/converge through the real wasm + relay", async () => {
  const relay = new TestRelay();
  const { client: alice } = await connectClient(relay, ALICE);
  const { client: bob } = await connectClient(relay, BOB);

  expect(alice.did).toBe(ALICE);

  connectPair(relay, alice, bob);

  const members = alice.memberDids(CTX)?.slice().sort();
  expect(members).toEqual([ALICE, BOB].sort());
  expect(alice.eventLogLeafCount(CTX)).toBe(2n);
  expect(bob.eventLogRoot(CTX)).toEqual(alice.eventLogRoot(CTX));

  // Alice → Bob: fans out over the relay (no return value), pumped into Bob.
  const plaintext = new TextEncoder().encode("hello from Alice through the browser SDK");
  alice.sendMessage(CTX, plaintext);
  expect(alice.eventLogLeafCount(CTX)).toBe(2n); // a send stamps no convergent leaf (ADR-011)
  relay.pump();

  const bobEvents = received(bob.drainEvents(CTX));
  expect(bobEvents).toHaveLength(1);
  expect(bobEvents[0]?.senderDid).toBe(ALICE);
  expect(bobEvents[0]?.payload).toEqual(plaintext);
  expect(received(bob.drainEvents(CTX))).toHaveLength(0); // drained

  // Bob → Alice.
  const reply = new TextEncoder().encode("hi Alice");
  bob.sendMessage(CTX, reply);
  relay.pump();
  const aliceEvents = received(alice.drainEvents(CTX));
  expect(aliceEvents).toHaveLength(1);
  expect(aliceEvents[0]?.payload).toEqual(reply);

  // §9.9.3 convergence: every leaf hash is byte-identical across both members.
  const aliceLeaves = alice.eventLogLeafHashes(CTX);
  expect(aliceLeaves).toEqual(bob.eventLogLeafHashes(CTX));
  expect(aliceLeaves).toBeDefined();
  expect(aliceLeaves?.length).toBe(2 * 32);
  expect(alice.eventLogRoot(CTX)).toEqual(bob.eventLogRoot(CTX));

  // The add Commit advanced the MLS epoch (a live context returns a bigint).
  const epoch = alice.mlsEpoch(CTX);
  expect(epoch).toBeDefined();
  expect((epoch ?? 0n) >= 1n).toBe(true);
  // Symmetric with the sibling observers: an absent context is undefined, not a throw.
  expect(alice.mlsEpoch("no-such-ctx")).toBeUndefined();

  alice.closeContext(CTX);
  bob.closeContext(CTX);
  expect(alice.memberDids(CTX)).toBeUndefined();
  expect(alice.contextStatus(CTX)).toBe("absent");
});

test("an op on an unknown context throws a typed ContextError (SCP-CTX-2001) through the real wasm", async () => {
  const relay = new TestRelay();
  const { client: alice } = await connectClient(relay, ALICE);
  // The real wasm throws "[SCP-CTX-2001] …"; the wrapper's prefix dispatch maps
  // it to the typed ContextError with a stable .code — the error-path contract.
  let caught: unknown;
  try {
    alice.sendMessage("no-such-ctx", new TextEncoder().encode("x"));
  } catch (e) {
    caught = e;
  }
  expect(caught).toBeInstanceOf(ContextError);
  expect((caught as ContextError).code).toBe("SCP-CTX-2001");
});
