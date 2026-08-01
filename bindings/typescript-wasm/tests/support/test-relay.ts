/**
 * A faithful in-test relay + mock WebSocket — the "dumb pipe" a real relay is.
 *
 * This is a legitimately EXTERNAL component (the relay is a separate untrusted
 * pipe in the real system), NOT a mock of the client under test. The Rust
 * `scp-relay-mock` (`crates/scp-relay-mock/src/lib.rs`) is the SEMANTIC AUTHORITY
 * for the shipped relay's client-facing behavior; this JS relay MIRRORS it (kept
 * in sync by hand — if the two diverge, the Rust mock is correct), so
 * `ScpBrowserClient` drives the REAL wasm over the REAL relay wire protocol:
 *
 *   - a subscription table `routing_id → subscribers`, populated by `SUBSCRIBE`
 *     frames, so a `PUBLISH` reaches only those subscribed at publish time;
 *   - delivery of a `PUBLISH` to ALL current subscribers of its routing id
 *     INCLUDING the publisher (no publisher exclusion — the self-echo the driver
 *     must drop benignly);
 *   - no `since:None` backfill (the client never uses it).
 *
 * Frames are the MessagePack `ClientMessage` / `RelayMessage` wire format
 * (`crates/scp-relay-client/src/protocol.rs`, internally `op`-tagged named maps).
 * `pump()` drains queued `BLOB`s into each subscriber iteratively until quiescent,
 * so the §9.10.4 reciprocal-announce cascade runs to completion exactly as over a
 * live relay.
 */

import { decode, encode } from "@msgpack/msgpack";
import type { WebSocketLike } from "../../src/index";

const WS_CONNECTING = 0;
const WS_OPEN = 1;
const WS_CLOSED = 3;

type ConnId = number;
type DeliverFn = (frame: Uint8Array) => void;

function toHex(bytes: Uint8Array): string {
  let s = "";
  for (const b of bytes) {
    s += b.toString(16).padStart(2, "0");
  }
  return s;
}

function asBytes(data: ArrayBufferView | ArrayBufferLike): Uint8Array {
  if (data instanceof Uint8Array) {
    return data;
  }
  if (ArrayBuffer.isView(data)) {
    return new Uint8Array(data.buffer, data.byteOffset, data.byteLength);
  }
  return new Uint8Array(data as ArrayBufferLike);
}

interface DecodedClientMessage {
  op?: string;
  routing_id?: Uint8Array;
  recipient_hint?: Uint8Array;
  blob_ttl?: number;
  blob?: Uint8Array;
}

/** The shared relay. Route `SUBSCRIBE`/`PUBLISH`, deliver `BLOB`s on {@link pump}. */
export class TestRelay {
  readonly #subscriptions = new Map<string, Set<ConnId>>();
  readonly #deliver = new Map<ConnId, DeliverFn>();
  #queue: Array<{ conn: ConnId; frame: Uint8Array }> = [];
  #nextConn = 0;
  #clock = 0;

  /** Registers a connection with its inbound delivery callback. */
  connect(deliver: DeliverFn): ConnId {
    const conn = this.#nextConn++;
    this.#deliver.set(conn, deliver);
    return conn;
  }

  /** Handles one outbound client frame (a mock WebSocket's `send`). */
  handleClientFrame(conn: ConnId, frame: Uint8Array): void {
    const msg = decode(frame) as DecodedClientMessage;
    if (msg.op === "SUBSCRIBE" && msg.routing_id) {
      this.#subscribe(conn, msg.routing_id);
    } else if (msg.op === "PUBLISH" && msg.routing_id && msg.blob) {
      this.#publish(msg.routing_id, msg.blob, msg.blob_ttl ?? 0, msg.recipient_hint);
    }
    // Every other op (PING/UNSUBSCRIBE/…) is ignored, exactly like scp-relay-mock.
  }

  #subscribe(conn: ConnId, routingId: Uint8Array): void {
    const key = toHex(routingId);
    let subs = this.#subscriptions.get(key);
    if (!subs) {
      subs = new Set();
      this.#subscriptions.set(key, subs);
    }
    subs.add(conn);
  }

  #publish(
    routingId: Uint8Array,
    blob: Uint8Array,
    blobTtl: number,
    recipientHint: Uint8Array | undefined,
  ): void {
    this.#clock += 1;
    // A monotonic, non-verified blob_id (8 BE bytes of the clock + zeros) —
    // faithful to scp-relay-mock; the driver does not verify blob_id == sha256.
    const blobId = new Uint8Array(32);
    new DataView(blobId.buffer).setBigUint64(0, BigInt(this.#clock), false);

    const relayBlob: Record<string, unknown> = {
      op: "BLOB",
      routing_id: routingId,
      blob_id: blobId,
      blob_ttl: blobTtl,
      stored_at: this.#clock,
      blob,
    };
    if (recipientHint) {
      relayBlob.recipient_hint = recipientHint;
    }
    const frame = encode(relayBlob);

    const subs = this.#subscriptions.get(toHex(routingId));
    if (!subs) {
      return;
    }
    for (const sub of subs) {
      // Deliver to ALL subscribers INCLUDING the publisher (self-echo).
      this.#queue.push({ conn: sub, frame });
    }
  }

  /** Drains queued `BLOB`s into subscribers, iteratively until quiescent. */
  pump(): void {
    // A converged mesh quiesces in O(members) rounds; bound generously so a real
    // non-convergence fails loudly instead of hanging.
    const maxRounds = 512;
    for (let round = 0; round < maxRounds; round += 1) {
      if (this.#queue.length === 0) {
        return;
      }
      const batch = this.#queue;
      this.#queue = [];
      for (const { conn, frame } of batch) {
        // Deliver a fresh copy so a handler retaining the buffer cannot alias the
        // next frame.
        this.#deliver.get(conn)?.(frame.slice());
      }
    }
    throw new Error("test relay did not converge within the round bound (reciprocal cascade bug?)");
  }
}

/**
 * A mock {@link WebSocketLike} bound to a {@link TestRelay} connection. Opening
 * is manual ({@link MockWebSocket.open}) so the test controls when `onopen`
 * (→ resubscribeAll) fires relative to the two-phase attach.
 */
export class MockWebSocket implements WebSocketLike {
  readyState = WS_CONNECTING;
  binaryType = "blob";
  onopen: (() => void) | null = null;
  onmessage: ((event: { data: unknown }) => void) | null = null;
  onclose: (() => void) | null = null;
  onerror: (() => void) | null = null;

  readonly #relay: TestRelay;
  readonly #conn: ConnId;

  constructor(relay: TestRelay) {
    this.#relay = relay;
    this.#conn = relay.connect((frame) => {
      // Deliver as an ArrayBuffer, exactly as a real socket with
      // binaryType="arraybuffer" would.
      const copy = frame.slice();
      this.onmessage?.({ data: copy.buffer });
    });
  }

  /** Transitions to OPEN and fires `onopen` (the test drives this). */
  open(): void {
    this.readyState = WS_OPEN;
    this.onopen?.();
  }

  send(data: ArrayBufferView | ArrayBufferLike): void {
    if (this.readyState !== WS_OPEN) {
      throw new Error("mock WebSocket is not open");
    }
    this.#relay.handleClientFrame(this.#conn, asBytes(data));
  }

  close(): void {
    this.readyState = WS_CLOSED;
    this.onclose?.();
  }
}
