/**
 * Browser-invoker cross-context streaming-saga session (SCP-OUT-048), driven
 * against the REAL built wasm and the REAL relay wire, within the ADR-057 scope
 * fence: the browser SIGNS its own open/credit in-tab and DECRYPTS + VERIFIES
 * each re-encrypted chunk on-device, while a MOCKED node coordinator plays the
 * node's 047 saga (coordination is node-delegated). Browser-initiated cancel is
 * out of scope this slice (§5.4.5 runtime-derived next_seq; node-delegated per
 * ADR-057) — a detected sequence gap surfaces StreamGap instead.
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
  Credit,
  InMemoryStorage,
  InvalidGrant,
  type JsSocket,
  type NodeStreamCoordinator,
  OutletError,
  outletStreamComputeCaveatsBinding,
  outletStreamComputeCreditPreimage,
  outletStreamVerifyChunkSignature,
  ScpBrowserClient,
  type SenderKeyDistribution,
  ValidationError,
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
  /** §5.4.5 credit-grant preimage golden for (grant=4, monotonic_seq=0, stream_epoch). */
  creditGrant: number;
  creditMonotonicSeq: number;
  creditPreimageHex: string;
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

  // Grant credit — SIGNED IN-TAB, routed to the node. `grant` is a validated
  // branded Credit (a raw number is a tsc error). The produced signature
  // verifies under the invoker's public key over the §5.4.5 credit preimage.
  const signedCredit = await session.grantCredit(new Credit(FIX.creditGrant));
  expect(routedCredits).toHaveLength(1);
  const creditPreimage = outletStreamComputeCreditPreimage({
    contextId: CTX,
    outletId: FIX.outletId,
    requestId: hexToBytes(FIX.requestIdHex),
    grant: FIX.creditGrant,
    monotonicSeq: BigInt(FIX.creditMonotonicSeq), // first grant's monotonic_seq
    streamEpoch: BigInt(FIX.streamEpoch),
    caveatsBinding,
  });
  // Cross-target golden: the credit preimage matches the Rust-pinned fixture
  // byte-for-byte (closes the "sign & compute share one builder so both drift
  // together" blind spot — the Rust KAT re-derives this same value).
  expect(Buffer.from(creditPreimage).toString("hex")).toBe(FIX.creditPreimageHex);
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

test("grantCredit requires a validated Credit — a bad grant throws InvalidGrant at construction", () => {
  // Browser-initiated cancel is out of scope this slice (§5.4.5 runtime-derived
  // next_seq; node-delegated per ADR-057) — there is no session.cancel(). Credit
  // is the one invoker-authored control-plane step, and it is a branded,
  // validating newtype: a raw / out-of-range grant never reaches signing.
  expect(() => new Credit(0)).toThrow(InvalidGrant);
  expect(() => new Credit(-1)).toThrow(InvalidGrant);
  expect(() => new Credit(3.5)).toThrow(InvalidGrant);
  expect(() => new Credit(2 ** 32)).toThrow(InvalidGrant);
  expect(new Credit(4).value).toBe(4);
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

/** Session options bound to a built invoker/coordinator (shared across the drain tests). */
function sessionOpts(
  invoker: ScpBrowserClient,
  coordinator: NodeStreamCoordinator,
  caveatsBinding: Uint8Array,
): ConstructorParameters<typeof BrowserInvokerStreamSession>[0] {
  return {
    client: invoker,
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
  };
}

test("a §5.4.5 sequence gap rejects with SCP-OUTLET-6131 without yielding the offending chunk (no cancel routed)", async () => {
  const { invoker, operator, relay, invokerInbound } = await buildPair();
  const CTX = FIX.contextId;
  const caveatsBinding = hexToBytes(FIX.caveatsBindingHex);

  const chunkFrames: Uint8Array[] = [];
  // NodeStreamCoordinator has NO cancel port this slice (cancel is node-delegated
  // per ADR-057 / §5.4.5 runtime-derived next_seq), so there is nothing to route
  // on a gap — the drain surfaces StreamGap and node-side reclamation cleans up.
  const coordinator: NodeStreamCoordinator = {
    open: async () => {},
    grantCredit: async () => {},
    pollNext: async () => chunkFrames.shift() ?? null,
  };

  // Operator forwards chunks 0, 1, then 3 — sequence 2 is MISSING (a gap).
  for (const seq of [0, 1, 3]) {
    operator.sendMessage(CTX, hexToBytes(FIX.chunks[seq]?.wireHex ?? ""));
  }
  relay.pump();
  chunkFrames.push(...invokerInbound.splice(0));
  expect(chunkFrames).toHaveLength(3);

  const session = new BrowserInvokerStreamSession(
    sessionOpts(invoker, coordinator, caveatsBinding),
  );

  const seen: number[] = [];
  let thrown: unknown;
  try {
    for await (const chunk of session) {
      seen.push(chunk.sequence);
    }
  } catch (error) {
    thrown = error;
  }
  expect(thrown).toBeInstanceOf(OutletError);
  expect((thrown as OutletError).code).toBe("SCP-OUTLET-6131");
  // 0 and 1 were yielded; the non-contiguous chunk (seq 3) was NOT.
  expect(seen).toEqual([0, 1]);
  // The session is closed and #pending was cleared: a further pull returns done,
  // never the buffered offending chunk.
  expect(await session.next()).toEqual({ done: true, value: undefined });

  invoker.closeContext(CTX);
  operator.closeContext(CTX);
});

test("a wrong-key chunk driven THROUGH the session rejects with SCP-OUTLET-6110 and clears #pending", async () => {
  const { invoker, operator, relay, invokerInbound } = await buildPair();
  const CTX = FIX.contextId;
  const caveatsBinding = hexToBytes(FIX.caveatsBindingHex);

  const chunkFrames: Uint8Array[] = [];
  const coordinator: NodeStreamCoordinator = {
    open: async () => {},
    grantCredit: async () => {},
    pollNext: async () => chunkFrames.shift() ?? null,
  };

  // Operator forwards a chunk whose operator signature is INVALID (wrong key).
  operator.sendMessage(CTX, hexToBytes(FIX.wrongKeyChunkWireHex));
  relay.pump();
  chunkFrames.push(...invokerInbound.splice(0));
  expect(chunkFrames).toHaveLength(1);

  const session = new BrowserInvokerStreamSession(
    sessionOpts(invoker, coordinator, caveatsBinding),
  );

  await expect(session.next()).rejects.toMatchObject({ code: "SCP-OUTLET-6110" });
  // #pending was cleared and the session closed: a subsequent pull returns done,
  // never a residual chunk buffered before the verify failure.
  expect(await session.next()).toEqual({ done: true, value: undefined });

  invoker.closeContext(CTX);
  operator.closeContext(CTX);
});

test("a second live session on the same (client, context) is refused (SCP-VALID-7028)", async () => {
  const { invoker, operator } = await buildPair();
  const caveatsBinding = hexToBytes(FIX.caveatsBindingHex);
  const coordinator: NodeStreamCoordinator = {
    open: async () => {},
    grantCredit: async () => {},
    pollNext: async () => null,
  };
  const first = new BrowserInvokerStreamSession(sessionOpts(invoker, coordinator, caveatsBinding));
  expect(
    () => new BrowserInvokerStreamSession(sessionOpts(invoker, coordinator, caveatsBinding)),
  ).toThrow(ValidationError);
  // Draining the first to its terminal releases the claim, so a fresh session
  // on the same (client, context) then constructs cleanly.
  await first.aggregate().catch(() => {});
  const second = new BrowserInvokerStreamSession(sessionOpts(invoker, coordinator, caveatsBinding));
  expect(second.requestId).toBeInstanceOf(Uint8Array);

  invoker.closeContext(FIX.contextId);
  operator.closeContext(FIX.contextId);
});
