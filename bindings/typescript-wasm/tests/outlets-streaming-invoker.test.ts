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
  outletStreamSignCredit,
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
  operatorSeedHex: string;
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

/** PKCS#8 DER prefix for a 32-byte Ed25519 seed (RFC 8410 OneAsymmetricKey). */
const PKCS8_ED25519_PREFIX = hexToBytes("302e020100300506032b657004220420");

/** WebCrypto Ed25519 sign from a raw 32-byte seed — the operator's role in-test. */
async function ed25519Sign(seed: Uint8Array, msg: Uint8Array): Promise<Uint8Array> {
  const pkcs8 = new Uint8Array(PKCS8_ED25519_PREFIX.length + seed.length);
  pkcs8.set(PKCS8_ED25519_PREFIX);
  pkcs8.set(seed, PKCS8_ED25519_PREFIX.length);
  const key = await crypto.subtle.importKey("pkcs8", bufOf(pkcs8), { name: "Ed25519" }, false, [
    "sign",
  ]);
  return new Uint8Array(await crypto.subtle.sign("Ed25519", key, bufOf(msg)));
}

async function sha256(bytes: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", bufOf(bytes)));
}

function concatBytes(...parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }
  return out;
}

function u32be(n: number): Uint8Array {
  const b = new Uint8Array(4);
  new DataView(b.buffer).setUint32(0, n, false);
  return b;
}

function u64be(n: bigint): Uint8Array {
  const b = new Uint8Array(8);
  new DataView(b.buffer).setBigUint64(0, n, false);
  return b;
}

/** `len_be32(bytes) || bytes` — the §9.5.1 uniform variable-length field rule. */
function lenPrefixed(bytes: Uint8Array): Uint8Array {
  return concatBytes(u32be(bytes.length), bytes);
}

/**
 * Signs an operator chunk in-tab and returns its JSON wire bytes, mirroring the
 * Rust `sign_chunk` (stream.rs) over the §5.4.5 `SCP-OUTLET-CHUNK-SIG-V1`
 * preimage:
 *
 *   SHA-256("SCP-OUTLET-CHUNK-SIG-V1:" || len_be32(ctx)||ctx || len_be32(outlet)
 *     ||outlet || request_id(16) || sequence_be(8) || caveats_binding(32)
 *     || SHA-256(jcs(payload))(32))
 *
 * `payload` MUST already be in RFC-8785 JCS key order (for these ASCII-only
 * payloads `JSON.stringify` of a sorted-key object IS the JCS). This is
 * SELF-VALIDATING: the on-device verify only accepts the chunk if this preimage
 * matches the Rust one byte-for-byte — otherwise `#ingestFrame` throws 6110
 * instead of reaching the terminal path. A cross-target KAT on the chunk wire.
 */
async function signOperatorChunkWire(
  seed: Uint8Array,
  contextId: string,
  outletId: string,
  requestId: Uint8Array,
  sequence: bigint,
  caveatsBinding: Uint8Array,
  payload: Record<string, unknown>,
): Promise<Uint8Array> {
  const enc = new TextEncoder();
  const payloadHash = await sha256(enc.encode(JSON.stringify(payload)));
  const preimage = await sha256(
    concatBytes(
      enc.encode("SCP-OUTLET-CHUNK-SIG-V1:"),
      lenPrefixed(enc.encode(contextId)),
      lenPrefixed(enc.encode(outletId)),
      requestId,
      u64be(sequence),
      caveatsBinding,
      payloadHash,
    ),
  );
  const sig = await ed25519Sign(seed, preimage);
  const wire = {
    request_id: Array.from(requestId),
    sequence: Number(sequence),
    payload,
    sig: Array.from(sig),
  };
  return enc.encode(JSON.stringify(wire));
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

test("the raw credit predicates reject an out-of-range grant (InvalidGrant) before touching wasm", () => {
  const requestId = hexToBytes(FIX.requestIdHex);
  const caveatsBinding = hexToBytes(FIX.caveatsBindingHex);
  const seed = hexToBytes(FIX.invokerSeedHex);
  const epoch = BigInt(FIX.streamEpoch);

  // wasm-bindgen would silently coerce these into a `u32`; the wrapper guard
  // rejects them up front with the uniform InvalidGrant, matching the branded
  // `Credit` bound the session's grantCredit enforces.
  for (const bad of [0, -1, 3.5, 2 ** 32]) {
    expect(() =>
      outletStreamSignCredit({
        signingKeySeed: seed,
        contextId: FIX.contextId,
        outletId: FIX.outletId,
        requestId,
        grant: bad,
        monotonicSeq: 0n,
        streamEpoch: epoch,
        caveatsBinding,
      }),
    ).toThrow(InvalidGrant);
    expect(() =>
      outletStreamComputeCreditPreimage({
        contextId: FIX.contextId,
        outletId: FIX.outletId,
        requestId,
        grant: bad,
        monotonicSeq: 0n,
        streamEpoch: epoch,
        caveatsBinding,
      }),
    ).toThrow(InvalidGrant);
  }
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

test("a wrong-key chunk sharing ONE #ingestFrame with a prior VALID chunk clears #pending (SCP-OUTLET-6110, never yields the buffered chunk)", async () => {
  const { invoker, operator, relay, invokerInbound } = await buildPair();
  const CTX = FIX.contextId;
  const caveatsBinding = hexToBytes(FIX.caveatsBindingHex);

  // The discriminating multi-chunk-single-frame case the single-chunk-per-frame
  // 6110 test above CANNOT exercise: there #pending is already empty at the
  // throw, so the `#pending.length = 0` clear is a no-op. Here a VALID chunk
  // (seq 0) is buffered in #pending FIRST, then a wrong-key chunk fails verify
  // in the SAME #ingestFrame drain — so the clear is load-bearing.
  //
  // A single #ingestFrame processes every event `drainEvents` returns. To batch
  // two chunks into ONE ingest we pre-decrypt the VALID frame into the client's
  // per-context buffer, then let the session's own ingest decrypt the wrong-key
  // frame: that ingest's single `drainEvents()` then yields BOTH the pre-buffered
  // valid chunk and the freshly-decrypted wrong-key chunk, in FIFO order.
  operator.sendMessage(CTX, hexToBytes(FIX.chunks[0]?.wireHex ?? ""));
  operator.sendMessage(CTX, hexToBytes(FIX.wrongKeyChunkWireHex));
  relay.pump();
  const frames = invokerInbound.splice(0);
  expect(frames).toHaveLength(2);
  const [validFrame, wrongKeyFrame] = frames as [Uint8Array, Uint8Array];

  // Pre-decrypt the VALID frame so its MessageReceived event is buffered FIRST
  // (FIFO). The session's ingest of the wrong-key frame then drains BOTH in one
  // batch — the valid chunk is pushed to #pending, then the wrong-key chunk
  // fails verify in the same loop.
  invoker.handleRelayFrame(validFrame);

  const chunkFrames: Uint8Array[] = [wrongKeyFrame];
  const coordinator: NodeStreamCoordinator = {
    open: async () => {},
    grantCredit: async () => {},
    pollNext: async () => chunkFrames.shift() ?? null,
  };
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
  expect((thrown as OutletError).code).toBe("SCP-OUTLET-6110");
  // The valid seq-0 chunk was in #pending when the wrong-key chunk in the SAME
  // ingest failed verify: it was NEVER yielded (seen stays empty), and the
  // #pending clear means a subsequent pull returns done, not the buffered chunk.
  expect(seen).toEqual([]);
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
  // Pin the specific code (not just the ValidationError class): the second-live-
  // session refusal is SCP-VALID-7028 exactly, distinct from the SCP-VALID-7029
  // re-entrant-drain guard below.
  let secondErr: unknown;
  try {
    new BrowserInvokerStreamSession(sessionOpts(invoker, coordinator, caveatsBinding));
  } catch (error) {
    secondErr = error;
  }
  expect(secondErr).toBeInstanceOf(ValidationError);
  expect((secondErr as ValidationError).code).toBe("SCP-VALID-7028");
  // Draining the first to its terminal releases the claim, so a fresh session
  // on the same (client, context) then constructs cleanly.
  await first.aggregate().catch(() => {});
  const second = new BrowserInvokerStreamSession(sessionOpts(invoker, coordinator, caveatsBinding));
  expect(second.requestId).toBeInstanceOf(Uint8Array);

  invoker.closeContext(FIX.contextId);
  operator.closeContext(FIX.contextId);
});

test("a re-entrant concurrent drain on one session is refused (SCP-VALID-7029)", async () => {
  const { invoker, operator } = await buildPair();
  const caveatsBinding = hexToBytes(FIX.caveatsBindingHex);
  const coordinator: NodeStreamCoordinator = {
    open: async () => {},
    grantCredit: async () => {},
    pollNext: async () => null,
  };
  const session = new BrowserInvokerStreamSession(
    sessionOpts(invoker, coordinator, caveatsBinding),
  );

  // Enter the single shared drain, then RE-ENTER it before the first pull
  // settles. next() sets #draining synchronously (before its first await), so a
  // second concurrent next() sees the guard and rejects with SCP-VALID-7029
  // (caller misuse) — a code distinct from the SCP-OUTLET-6100 lifecycle-closed
  // cases, so an operator can filter misuse apart from protocol/lifecycle.
  const first = session.next();
  const reentrant = session.next();
  await expect(reentrant).rejects.toBeInstanceOf(ValidationError);
  await expect(reentrant).rejects.toMatchObject({ code: "SCP-VALID-7029" });
  // The first drain settles cleanly (pollNext → null → done): no leak, and the
  // guard did not corrupt the single drain's own lifecycle.
  expect(await first).toEqual({ done: true, value: undefined });

  invoker.closeContext(FIX.contextId);
  operator.closeContext(FIX.contextId);
});

test("a terminal Error chunk drives aggregate() to re-throw it as an OutletError", async () => {
  const { invoker, operator, relay, invokerInbound } = await buildPair();
  const CTX = FIX.contextId;
  const caveatsBinding = hexToBytes(FIX.caveatsBindingHex);

  // Construct a terminal Error chunk (seq 0) signed in-tab under the REAL
  // operator seed (RFC 8032 §7.1 test vector 1 — the fixture operator key). The
  // on-device verify accepts it only if the TS chunk-sig preimage matches Rust
  // byte-for-byte, so this doubles as a cross-target KAT on the Error variant.
  const errorPayload = {
    "@type": "error",
    code: "SCP-OUTLET-6130",
    message: "executor aborted the stream",
    terminal: true,
  };
  const errorWire = await signOperatorChunkWire(
    hexToBytes(FIX.operatorSeedHex),
    CTX,
    FIX.outletId,
    hexToBytes(FIX.requestIdHex),
    0n,
    caveatsBinding,
    errorPayload,
  );

  operator.sendMessage(CTX, errorWire);
  relay.pump();
  const chunkFrames = invokerInbound.splice(0);
  expect(chunkFrames).toHaveLength(1);

  const coordinator: NodeStreamCoordinator = {
    open: async () => {},
    grantCredit: async () => {},
    pollNext: async () => chunkFrames.shift() ?? null,
  };
  const session = new BrowserInvokerStreamSession(
    sessionOpts(invoker, coordinator, caveatsBinding),
  );

  // aggregate() drains to the terminal Error and re-throws the typed OutletError
  // carrying the chunk's own code + message (not the End aggregate). Idempotent:
  // a second call re-throws the same cached error.
  await expect(session.aggregate()).rejects.toBeInstanceOf(OutletError);
  await expect(session.aggregate()).rejects.toMatchObject({
    code: "SCP-OUTLET-6130",
    message: "executor aborted the stream",
  });

  invoker.closeContext(CTX);
  operator.closeContext(CTX);
});

test("a stream that closes without an End chunk makes aggregate() throw SCP-OUTLET-6100", async () => {
  const { invoker, operator } = await buildPair();
  const caveatsBinding = hexToBytes(FIX.caveatsBindingHex);

  // The node signals no more frames (pollNext → null) before any terminal chunk
  // arrives — an abnormal close. aggregate() must surface SCP-OUTLET-6100
  // (asserted directly, not .catch-swallowed as the 7028 claim-release does).
  const coordinator: NodeStreamCoordinator = {
    open: async () => {},
    grantCredit: async () => {},
    pollNext: async () => null,
  };
  const session = new BrowserInvokerStreamSession(
    sessionOpts(invoker, coordinator, caveatsBinding),
  );

  await expect(session.aggregate()).rejects.toBeInstanceOf(OutletError);
  await expect(session.aggregate()).rejects.toMatchObject({ code: "SCP-OUTLET-6100" });

  invoker.closeContext(FIX.contextId);
  operator.closeContext(FIX.contextId);
});

test("breaking out of a drain releases the (client, context) claim (return() hook)", async () => {
  const { invoker, operator, relay, invokerInbound } = await buildPair();
  const CTX = FIX.contextId;
  const caveatsBinding = hexToBytes(FIX.caveatsBindingHex);

  const chunkFrames: Uint8Array[] = [];
  const coordinator: NodeStreamCoordinator = {
    open: async () => {},
    grantCredit: async () => {},
    pollNext: async () => chunkFrames.shift() ?? null,
  };

  // Forward two chunks so the drain yields at least one before the `break`.
  for (const seq of [0, 1]) {
    operator.sendMessage(CTX, hexToBytes(FIX.chunks[seq]?.wireHex ?? ""));
  }
  relay.pump();
  chunkFrames.push(...invokerInbound.splice(0));

  const first = new BrowserInvokerStreamSession(sessionOpts(invoker, coordinator, caveatsBinding));
  for await (const chunk of first) {
    expect(chunk.sequence).toBe(0);
    // `break` mid-drain: the `for await … of` protocol invokes the iterator's
    // return() hook, which must release the live-consumer claim (not leak it).
    break;
  }

  // Proof the claim was released: a fresh session on the SAME (client, context)
  // constructs without SCP-VALID-7028.
  const second = new BrowserInvokerStreamSession(sessionOpts(invoker, coordinator, caveatsBinding));
  expect(second.requestId).toBeInstanceOf(Uint8Array);

  invoker.closeContext(CTX);
  operator.closeContext(CTX);
});

test("close() releases the (client, context) claim", async () => {
  const { invoker, operator } = await buildPair();
  const caveatsBinding = hexToBytes(FIX.caveatsBindingHex);
  const coordinator: NodeStreamCoordinator = {
    open: async () => {},
    grantCredit: async () => {},
    pollNext: async () => null,
  };

  const first = new BrowserInvokerStreamSession(sessionOpts(invoker, coordinator, caveatsBinding));
  first.close();
  // The claim released by close() lets a fresh session construct on the same pair.
  const second = new BrowserInvokerStreamSession(sessionOpts(invoker, coordinator, caveatsBinding));
  expect(second.requestId).toBeInstanceOf(Uint8Array);

  invoker.closeContext(FIX.contextId);
  operator.closeContext(FIX.contextId);
});

test("`await using` releases the (client, context) claim on block exit (asyncDispose)", async () => {
  const { invoker, operator } = await buildPair();
  const caveatsBinding = hexToBytes(FIX.caveatsBindingHex);
  const coordinator: NodeStreamCoordinator = {
    open: async () => {},
    grantCredit: async () => {},
    pollNext: async () => null,
  };

  {
    // `await using` only type-checks if [Symbol.asyncDispose] returns a
    // PromiseLike (the R4-1 fix); this block also exercises it at runtime.
    await using session = new BrowserInvokerStreamSession(
      sessionOpts(invoker, coordinator, caveatsBinding),
    );
    expect(session.requestId).toBeInstanceOf(Uint8Array);
  }

  // Block exit ran [Symbol.asyncDispose] → #markClosed → claim released: a fresh
  // session on the same pair constructs without SCP-VALID-7028.
  const next = new BrowserInvokerStreamSession(sessionOpts(invoker, coordinator, caveatsBinding));
  expect(next.requestId).toBeInstanceOf(Uint8Array);

  invoker.closeContext(FIX.contextId);
  operator.closeContext(FIX.contextId);
});

test("grantCredit rejects a non-Credit at runtime (InvalidGrant) even when tsc is bypassed", async () => {
  const { invoker, operator } = await buildPair();
  const caveatsBinding = hexToBytes(FIX.caveatsBindingHex);
  let openCalls = 0;
  const coordinator: NodeStreamCoordinator = {
    open: async () => {
      openCalls += 1;
    },
    grantCredit: async () => {},
    pollNext: async () => null,
  };
  const session = new BrowserInvokerStreamSession(
    sessionOpts(invoker, coordinator, caveatsBinding),
  );

  // A bare `{ value }` object satisfies tsc via the cast but is NOT a branded
  // Credit instance — the runtime guard must reject it (InvalidGrant) BEFORE it
  // reaches signing with an unvalidated `.value`, mirroring the native surface.
  await expect(session.grantCredit({ value: 3.5 } as unknown as Credit)).rejects.toBeInstanceOf(
    InvalidGrant,
  );
  await expect(session.grantCredit({ value: 0 } as unknown as Credit)).rejects.toBeInstanceOf(
    InvalidGrant,
  );
  // The guard runs before the lazy open, so no grant ever opened the stream.
  expect(openCalls).toBe(0);

  session.close();
  invoker.closeContext(FIX.contextId);
  operator.closeContext(FIX.contextId);
});
