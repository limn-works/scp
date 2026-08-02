/**
 * Browser-invoker cross-context streaming-saga session (SCP-OUT-048), driven
 * against the REAL built wasm and the REAL relay wire, within the ADR-057 scope
 * fence: the browser SIGNS its own open/credit/cancel in-tab and DECRYPTS +
 * VERIFIES each re-encrypted chunk on-device, while a MOCKED node coordinator
 * plays the node's 047 saga (coordination is node-delegated).
 *
 * The chunk data plane is a §25.2 reference-key KAT: the operator-signed chunks
 * are produced in Rust under the RFC 8032 §7.1 Test-Vector-1 operator key and
 * committed as a fixture (`fixtures/outlet-stream-invoker-kat.json`, pinned by
 * `crates/scp-client-wasm/tests/out048_ts_invoker_fixture_kat.rs`). The test
 * transports those exact bytes through a real MLS group (operator client →
 * relay → invoker client) and the browser verifies each on-device — so both the
 * chunk wire and the caveats-binding are cross-target KATs, not re-derived in TS.
 *
 * The "node coordinator" is a legitimate EXTERNAL test double (it stands in for
 * the always-on node saga), never a mock of the client under test. The invoker
 * runs the actual compiled `scp-client-wasm`.
 */

import { beforeAll, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import {
  BrowserInvokerStreamSession,
  InMemoryStorage,
  type JsSocket,
  type NodeStreamCoordinator,
  OutletError,
  outletStreamComputeCancelPreimage,
  outletStreamComputeCaveatsBinding,
  outletStreamComputeCreditPreimage,
  outletStreamVerifyChunkSignature,
  ScpBrowserClient,
  type SenderKeyDistribution,
} from "../src/index";
import { loadRealWasm } from "./support/load-wasm";
import { stubCustody } from "./support/stubs";
import { TestRelay } from "./support/test-relay";

const here = dirname(fileURLToPath(import.meta.url));

interface Fixture {
  contextId: string;
  outletId: string;
  requestIdHex: string;
  ucanCid: string;
  invokerDid: string;
  estimatedChunkCount: number;
  streamEpoch: number;
  caveatsJcsHex: string;
  caveatsBindingHex: string;
  operatorPkHex: string;
  wrongOperatorPkHex: string;
  invokerSeedHex: string;
  invokerPkHex: string;
  chunks: Array<{ sequence: number; wireHex: string }>;
  wrongKeyChunkWireHex: string;
}

const FIX: Fixture = JSON.parse(
  readFileSync(join(here, "fixtures", "outlet-stream-invoker-kat.json"), "utf8"),
);

const OPERATOR_DID = "did:key:z6MkOperatorOUT048NodeFixtureKeyBBBBBBBBBB";
const UCAN_TOKEN = "eyJhbGciOiJFZERTQSJ9.fixture-invoker-ucan.sig";

function hexToBytes(h: string): Uint8Array {
  const out = new Uint8Array(h.length / 2);
  for (let i = 0; i < out.length; i += 1) {
    out[i] = Number.parseInt(h.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

/** A fresh `ArrayBuffer` copy — satisfies WebCrypto's `BufferSource` typing. */
function bufOf(b: Uint8Array): ArrayBuffer {
  const copy = new Uint8Array(b.length);
  copy.set(b);
  return copy.buffer;
}

/** WebCrypto Ed25519 verify — the node/operator's role, exercised in-test. */
async function ed25519Verify(pk: Uint8Array, sig: Uint8Array, msg: Uint8Array): Promise<boolean> {
  const key = await crypto.subtle.importKey("raw", bufOf(pk), { name: "Ed25519" }, false, [
    "verify",
  ]);
  return crypto.subtle.verify("Ed25519", key, bufOf(sig), bufOf(msg));
}

function sigOf(signedWire: Uint8Array): Uint8Array {
  const obj = JSON.parse(new TextDecoder().decode(signedWire)) as { sig: number[] };
  return Uint8Array.from(obj.sig);
}

beforeAll(async () => {
  await loadRealWasm();
}, 120_000);

/**
 * Builds a fully-connected operator↔invoker MLS pair over one relay. The
 * operator (a second `ScpBrowserClient`, the node/executor MLS peer) uses the
 * managed auto-decrypt socket; the INVOKER uses an injected `JsSocket` whose
 * inbound frames are CAPTURED (not auto-decrypted) so the session drives decrypt
 * itself via the node coordinator + `handleRelayFrame`.
 */
async function buildPair(): Promise<{
  invoker: ScpBrowserClient;
  operator: ScpBrowserClient;
  relay: TestRelay;
  invokerInbound: Uint8Array[];
  settle: () => void;
}> {
  const relay = new TestRelay();
  const CTX = FIX.contextId;

  // Operator: managed auto-decrypt socket (a plain relay peer).
  const { MockWebSocket } = await import("./support/test-relay");
  let operatorWs: InstanceType<typeof MockWebSocket> | undefined;
  const operator = await ScpBrowserClient.connect({
    custody: stubCustody(OPERATOR_DID),
    storage: new InMemoryStorage(),
    url: "ws://relay.test",
    createWebSocket: () => {
      const ws = new MockWebSocket(relay);
      operatorWs = ws;
      return ws;
    },
    reconnect: { enabled: false },
  });
  operatorWs?.open();

  // Invoker: injected capturing socket. Inbound frames queue in `invokerInbound`.
  const invokerInbound: Uint8Array[] = [];
  const invokerConn = relay.connect((frame) => invokerInbound.push(frame));
  const invokerSocket: JsSocket = {
    send: (frame) => relay.handleClientFrame(invokerConn, frame),
  };
  const invoker = ScpBrowserClient.create({
    custody: stubCustody(FIX.invokerDid),
    storage: new InMemoryStorage(),
    socket: invokerSocket,
  });

  // Drive the setup mesh: pump the relay, then feed captured frames into the
  // invoker's receive path until quiescent (the §9.10.4 reciprocal-announce
  // cascade). Used ONLY for setup — during chunk transport the SESSION drives it.
  const settle = (): void => {
    for (let i = 0; i < 100; i += 1) {
      relay.pump();
      if (invokerInbound.length === 0) {
        return;
      }
      for (const frame of invokerInbound.splice(0)) {
        invoker.handleRelayFrame(frame);
      }
    }
    throw new Error("operator↔invoker mesh did not settle");
  };

  const deliver = (dists: SenderKeyDistribution[]): void => {
    for (const d of dists) {
      if (d.targetDid === FIX.invokerDid) {
        invoker.receiveMessage(CTX, d.ciphertext);
      } else if (d.targetDid === OPERATOR_DID) {
        operator.receiveMessage(CTX, d.ciphertext);
      } else {
        throw new Error(`unexpected distribution target ${d.targetDid}`);
      }
    }
  };

  // MLS handshake: operator hosts the context, invoker joins.
  operator.createContext(CTX);
  const kp = invoker.generateKeyPackageForJoin(CTX);
  const add = operator.addMember(CTX, kp);
  const invokerDists = invoker.joinContextEncrypted(
    CTX,
    add.welcome,
    add.eventLog,
    add.wrappingKeys,
  );
  deliver(add.senderKeyDistributions);
  deliver(invokerDists);
  invoker.resubscribeAll();
  settle();
  // Clear any buffered setup events (pseudonym announcements) so the session's
  // drain sees only chunk messages.
  invoker.drainEvents(CTX);
  operator.drainEvents(CTX);

  return { invoker, operator, relay, invokerInbound, settle };
}

test("browser-invoker streaming round-trip: signs open + credit in-tab, decrypts + verifies 10 Data and terminal End on-device", async () => {
  const { invoker, operator, relay, invokerInbound } = await buildPair();
  const CTX = FIX.contextId;

  // The browser computes the §5.4.5 caveats_binding in-tab — a cross-target KAT
  // against the Rust-pinned fixture value (same inputs → same 32 bytes).
  const caveatsBinding = outletStreamComputeCaveatsBinding(
    new TextEncoder().encode(FIX.ucanCid),
    hexToBytes(FIX.requestIdHex),
    FIX.invokerDid,
    FIX.estimatedChunkCount,
    hexToBytes(FIX.caveatsJcsHex),
  );
  expect(Buffer.from(caveatsBinding).toString("hex")).toBe(FIX.caveatsBindingHex);

  // The node forwards the re-encrypted chunk frames (captured off the relay).
  const chunkFrames: Uint8Array[] = [];
  const routedCredits: Uint8Array[] = [];
  let opened = false;
  const coordinator: NodeStreamCoordinator = {
    open: async () => {
      opened = true;
    },
    grantCredit: async (signed) => {
      routedCredits.push(signed);
    },
    cancel: async () => {},
    pollNext: async () => chunkFrames.shift() ?? null,
  };

  // Operator (node/executor) re-encrypts + forwards every KAT chunk over MLS.
  for (const c of FIX.chunks) {
    operator.sendMessage(CTX, hexToBytes(c.wireHex));
  }
  relay.pump();
  chunkFrames.push(...invokerInbound.splice(0));
  expect(chunkFrames).toHaveLength(11);

  const session = new BrowserInvokerStreamSession({
    client: invoker,
    coordinator,
    contextId: CTX,
    outletId: FIX.outletId,
    requestId: hexToBytes(FIX.requestIdHex),
    invokerDid: FIX.invokerDid,
    invokerSigningSeed: hexToBytes(FIX.invokerSeedHex),
    operatorPk: hexToBytes(FIX.operatorPkHex),
    ucanToken: UCAN_TOKEN,
    caveatsBinding,
    streamEpoch: BigInt(FIX.streamEpoch),
    estimatedChunkCount: FIX.estimatedChunkCount,
  });

  await session.open();
  expect(opened).toBe(true);

  // Grant credit — SIGNED IN-TAB, routed to the node. The produced signature
  // verifies under the invoker's public key over the §5.4.5 credit preimage.
  const signedCredit = await session.grantCredit(4);
  expect(routedCredits).toHaveLength(1);
  const creditPreimage = outletStreamComputeCreditPreimage(
    CTX,
    FIX.outletId,
    hexToBytes(FIX.requestIdHex),
    4,
    0n, // first grant's monotonic_seq
    BigInt(FIX.streamEpoch),
    caveatsBinding,
  );
  expect(
    await ed25519Verify(hexToBytes(FIX.invokerPkHex), sigOf(signedCredit), creditPreimage),
  ).toBe(true);

  // Consume: the browser MLS-decrypts each frame on-device and verifies the
  // operator signature before yielding. All 10 Data + the terminal End.
  const seen: number[] = [];
  let terminal = 0;
  for await (const chunk of session) {
    seen.push(chunk.sequence);
    if (chunk.isTerminal) {
      terminal += 1;
      expect(chunk.kind).toBe("end");
    }
  }
  expect(seen).toEqual([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
  expect(terminal).toBe(1);

  // The aggregate is the End chunk's aggregate value (cached; no re-drain).
  const agg = await session.aggregate();
  expect(agg.value).toBe(9);
  expect(agg.executionTimeMs).toBe(100);

  invoker.closeContext(CTX);
  operator.closeContext(CTX);
});

test("a signed OutletStreamCancel verifies under the invoker public key (in-tab signing)", async () => {
  await loadRealWasm();
  const caveatsBinding = hexToBytes(FIX.caveatsBindingHex);
  const routedCancels: Uint8Array[] = [];
  const coordinator: NodeStreamCoordinator = {
    open: async () => {},
    grantCredit: async () => {},
    cancel: async (signed) => {
      routedCancels.push(signed);
    },
    pollNext: async () => null,
  };
  // Cancel is pure in-tab signing + routing — no MLS context needed. A minimal
  // client with a no-op socket satisfies the session constructor.
  const client = ScpBrowserClient.create({
    custody: stubCustody(FIX.invokerDid),
    storage: new InMemoryStorage(),
    socket: { send: () => {} },
  });
  const session = new BrowserInvokerStreamSession({
    client,
    coordinator,
    contextId: FIX.contextId,
    outletId: FIX.outletId,
    requestId: hexToBytes(FIX.requestIdHex),
    invokerDid: FIX.invokerDid,
    invokerSigningSeed: hexToBytes(FIX.invokerSeedHex),
    operatorPk: hexToBytes(FIX.operatorPkHex),
    ucanToken: UCAN_TOKEN,
    caveatsBinding,
    streamEpoch: BigInt(FIX.streamEpoch),
    estimatedChunkCount: FIX.estimatedChunkCount,
  });

  const signedCancel = await session.cancel();
  expect(routedCancels).toHaveLength(1);
  const cancelPreimage = outletStreamComputeCancelPreimage(
    FIX.contextId,
    FIX.outletId,
    hexToBytes(FIX.requestIdHex),
    0n, // no chunks consumed → next_seq cursor is 0
    caveatsBinding,
  );
  expect(
    await ed25519Verify(hexToBytes(FIX.invokerPkHex), sigOf(signedCancel), cancelPreimage),
  ).toBe(true);

  // A closed session refuses a second control-plane call.
  await expect(session.cancel()).rejects.toBeInstanceOf(OutletError);
});

test("a chunk signed by a non-operator key is rejected on-device", async () => {
  await loadRealWasm();
  const caveatsBinding = hexToBytes(FIX.caveatsBindingHex);

  // (a) a chunk signed by the WRONG key, verified under the correct operator PK.
  const wrongKeyChunk = hexToBytes(FIX.wrongKeyChunkWireHex);
  expect(
    outletStreamVerifyChunkSignature(
      wrongKeyChunk,
      hexToBytes(FIX.operatorPkHex),
      FIX.contextId,
      FIX.outletId,
      caveatsBinding,
    ),
  ).toBe(false);

  // (b) a correctly-signed chunk, verified under a WRONG operator PK.
  const goodChunk = hexToBytes(FIX.chunks[0]?.wireHex ?? "");
  expect(
    outletStreamVerifyChunkSignature(
      goodChunk,
      hexToBytes(FIX.wrongOperatorPkHex),
      FIX.contextId,
      FIX.outletId,
      caveatsBinding,
    ),
  ).toBe(false);

  // (c) the same good chunk verifies TRUE under the correct operator PK (control).
  expect(
    outletStreamVerifyChunkSignature(
      goodChunk,
      hexToBytes(FIX.operatorPkHex),
      FIX.contextId,
      FIX.outletId,
      caveatsBinding,
    ),
  ).toBe(true);
});
