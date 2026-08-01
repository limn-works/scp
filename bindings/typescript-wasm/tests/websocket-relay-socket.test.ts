/**
 * Unit tests for {@link WebSocketRelaySocket} against a controllable mock
 * WebSocket — the transport-wiring contract (ADR-057 T-3), with no wasm.
 */

import { expect, test } from "bun:test";
import { type RelayPumpHandlers, type WebSocketLike, WebSocketRelaySocket } from "../src/index";

const WS_CONNECTING = 0;
const WS_OPEN = 1;
const WS_CLOSED = 3;

/** A controllable WebSocket double recording sends and exposing open/deliver/close. */
class StubWebSocket implements WebSocketLike {
  readyState = WS_CONNECTING;
  binaryType = "blob";
  onopen: (() => void) | null = null;
  onmessage: ((event: { data: unknown }) => void) | null = null;
  onclose: (() => void) | null = null;
  onerror: (() => void) | null = null;
  readonly sent: Uint8Array[] = [];

  open(): void {
    this.readyState = WS_OPEN;
    this.onopen?.();
  }

  deliver(bytes: Uint8Array): void {
    this.onmessage?.({
      data: bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength),
    });
  }

  send(data: ArrayBufferView): void {
    this.sent.push(new Uint8Array(data.buffer, data.byteOffset, data.byteLength));
  }

  close(): void {
    this.readyState = WS_CLOSED;
    this.onclose?.();
  }
}

const sleep = (ms: number): Promise<void> => new Promise((r) => setTimeout(r, ms));

function collectHandlers(): {
  handlers: RelayPumpHandlers;
  opens: number;
  frames: Uint8Array[];
} {
  const state = { opens: 0, frames: [] as Uint8Array[] };
  const handlers: RelayPumpHandlers = {
    onOpen: () => {
      state.opens += 1;
    },
    onFrame: (frame) => {
      state.frames.push(frame);
    },
  };
  return {
    handlers,
    get opens() {
      return state.opens;
    },
    frames: state.frames,
  };
}

test("send throws before the socket is OPEN, then succeeds once open", () => {
  let ws: StubWebSocket | undefined;
  const socket = new WebSocketRelaySocket({
    url: "ws://test",
    createWebSocket: () => {
      ws = new StubWebSocket();
      return ws;
    },
    reconnect: { enabled: false },
  });
  const h = collectHandlers();
  socket.attach(h.handlers);
  if (!ws) {
    throw new Error("factory not invoked");
  }

  // CONNECTING → send rejects (surfaced as SCP-TRANS-5010 at the client boundary).
  expect(() => socket.send(new Uint8Array([1]))).toThrow();

  ws.open();
  expect(h.opens).toBe(1); // onopen → resubscribeAll
  socket.send(new Uint8Array([1, 2, 3]));
  expect(ws.sent).toEqual([new Uint8Array([1, 2, 3])]);
});

test("inbound onmessage routes bytes to onFrame (handleRelayFrame)", () => {
  let ws: StubWebSocket | undefined;
  const socket = new WebSocketRelaySocket({
    url: "ws://test",
    createWebSocket: () => {
      ws = new StubWebSocket();
      return ws;
    },
    reconnect: { enabled: false },
  });
  const h = collectHandlers();
  socket.attach(h.handlers);
  if (!ws) {
    throw new Error("factory not invoked");
  }
  ws.open();

  ws.deliver(new Uint8Array([9, 8, 7]));
  expect(h.frames).toEqual([new Uint8Array([9, 8, 7])]);
});

test("a throwing onFrame routes to onError and does not kill the pump", () => {
  let ws: StubWebSocket | undefined;
  const errors: string[] = [];
  const socket = new WebSocketRelaySocket({
    url: "ws://test",
    createWebSocket: () => {
      ws = new StubWebSocket();
      return ws;
    },
    reconnect: { enabled: false },
    onError: (e) => errors.push(e.code),
  });
  let calls = 0;
  socket.attach({
    onOpen: () => {},
    onFrame: () => {
      calls += 1;
      if (calls === 1) {
        throw new Error("[SCP-CRYPTO-4010] boom");
      }
    },
  });
  if (!ws) {
    throw new Error("factory not invoked");
  }
  ws.open();

  ws.deliver(new Uint8Array([1])); // throws → routed to onError
  ws.deliver(new Uint8Array([2])); // pump survived → delivered
  expect(calls).toBe(2);
  expect(errors).toEqual(["SCP-CRYPTO-4010"]);
});

test("reconnect after close re-opens and re-fires onOpen (resubscribe)", async () => {
  const created: StubWebSocket[] = [];
  const socket = new WebSocketRelaySocket({
    url: "ws://test",
    createWebSocket: () => {
      const ws = new StubWebSocket();
      created.push(ws);
      return ws;
    },
    reconnect: { enabled: true, initialDelayMs: 5, maxDelayMs: 20, factor: 2 },
  });
  const h = collectHandlers();
  socket.attach(h.handlers);
  created[0]?.open();
  expect(h.opens).toBe(1);
  expect(created).toHaveLength(1);

  // The socket drops: onclose → schedule reconnect → a NEW ws is created.
  created[0]?.close();
  await sleep(30);
  expect(created.length).toBeGreaterThanOrEqual(2);

  // Opening the reconnected socket re-fires onOpen (the resubscribe trigger).
  created[1]?.open();
  expect(h.opens).toBe(2);

  socket.close();
});

test("onopen re-sends the tracked subscriptions on the reconnected socket", async () => {
  // Focused unit coverage for drop → reopen → resubscribe: the pump's onOpen is
  // `client.resubscribeAll`, which re-drives the tracked SUBSCRIBE frames on the
  // CURRENT socket every (re)open. Here onOpen stands in for that by re-sending a
  // fixed SUBSCRIBE frame, and we assert it lands on the NEW socket after a
  // reconnect — proving subscriptions resume on the reconnected transport.
  // (The full client-driven reconnect over the faithful relay mock is an e2e gap,
  // deliberately not exercised here to avoid ballooning that mock.)
  const created: StubWebSocket[] = [];
  const subscribe = new Uint8Array([0x5, 0x5, 0x5]); // a stand-in tracked SUBSCRIBE frame
  const socket = new WebSocketRelaySocket({
    url: "ws://test",
    createWebSocket: () => {
      const ws = new StubWebSocket();
      created.push(ws);
      return ws;
    },
    reconnect: { enabled: true, initialDelayMs: 5, maxDelayMs: 20, factor: 2 },
  });
  socket.attach({ onOpen: () => socket.send(subscribe), onFrame: () => {} });

  created[0]?.open();
  expect(created[0]?.sent).toEqual([subscribe]); // subscribed on the initial open

  created[0]?.close();
  await sleep(30);
  expect(created.length).toBeGreaterThanOrEqual(2);

  created[1]?.open();
  expect(created[1]?.sent).toEqual([subscribe]); // RE-subscribed on the reconnected socket

  socket.close();
});

test("close() disables reconnect", async () => {
  const created: StubWebSocket[] = [];
  const socket = new WebSocketRelaySocket({
    url: "ws://test",
    createWebSocket: () => {
      const ws = new StubWebSocket();
      created.push(ws);
      return ws;
    },
    reconnect: { enabled: true, initialDelayMs: 5 },
  });
  socket.attach({ onOpen: () => {}, onFrame: () => {} });
  created[0]?.open();
  socket.close(); // user close → no reconnect
  await sleep(20);
  expect(created).toHaveLength(1);
});
