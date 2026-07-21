/**
 * {@link WebSocketRelaySocket} — the browser-default {@link JsSocket}: an
 * outbound relay sink over a WebSocket that also owns the inbound pump and
 * reconnect wiring (ADR-057 T-3, D4).
 *
 * The wasm driver calls `send` outbound; inbound relay frames are JS-pumped back
 * into the client via the two-phase attach {@link ScpBrowserClient.connect}
 * performs. No loopback/in-memory socket ships here — that is `#[cfg(test)]`-only
 * in the Rust crate (the no-dev/test-stand-in-in-production tenet).
 */

import { mapWasmError, type ScpError } from "../errors";
import type { JsSocket } from "./types";

/** WebSocket `readyState` for an OPEN connection (per the WHATWG WebSocket standard). */
const WS_OPEN = 1;

/**
 * The minimal WebSocket surface this adapter drives. The global browser
 * `WebSocket`, a Deno socket, a Cloudflare `WebSocketPair` half, and the Node
 * `ws` client all satisfy it — so an embedder can supply any of them via
 * {@link WebSocketRelaySocketOptions.createWebSocket}.
 */
export interface WebSocketLike {
  /** `0` CONNECTING, `1` OPEN, `2` CLOSING, `3` CLOSED. */
  readonly readyState: number;
  /** Set to `"arraybuffer"` so inbound binary frames arrive as `ArrayBuffer`. */
  binaryType: string;
  /** Sends one binary frame. */
  send(data: ArrayBufferView): void;
  /** Closes the connection. */
  close(): void;
  onopen: (() => void) | null;
  onmessage: ((event: { data: unknown }) => void) | null;
  onclose: (() => void) | null;
  onerror: (() => void) | null;
}

/** Reconnect-with-backoff tuning. Reconnect is enabled by default. */
export interface WebSocketRelayReconnectOptions {
  /** Whether to reconnect after an unexpected close. Default `true`. */
  readonly enabled?: boolean;
  /** First backoff delay in ms. Default `500`. */
  readonly initialDelayMs?: number;
  /** Maximum backoff delay in ms. Default `30000`. */
  readonly maxDelayMs?: number;
  /** Backoff multiplier per attempt. Default `2`. */
  readonly factor?: number;
}

/** Options for {@link WebSocketRelaySocket}. */
export interface WebSocketRelaySocketOptions {
  /** The relay WebSocket URL (e.g. `wss://relay.example/…`). */
  readonly url: string;
  /**
   * Factory that creates a {@link WebSocketLike} for `url`. Defaults to the
   * global `WebSocket`. Supply your own for Deno / Workers / `ws` / tests.
   */
  readonly createWebSocket?: (url: string) => WebSocketLike;
  /** Reconnect-with-backoff options. */
  readonly reconnect?: WebSocketRelayReconnectOptions;
  /** Called with a typed error when the inbound pump surfaces one. */
  readonly onError?: (error: ScpError) => void;
}

/** Handlers the client wires into the pump via {@link WebSocketRelaySocket.attach}. */
export interface RelayPumpHandlers {
  /** Re-drive subscriptions — fired on the initial open AND every reconnect. */
  readonly onOpen: () => void;
  /** Deliver one inbound relay frame into the driver. May throw (routed to `onError`). */
  readonly onFrame: (frame: Uint8Array) => void;
  /** Route a pump error without killing the pump. */
  readonly onError?: (error: ScpError) => void;
}

/** Extracts the binary payload of an inbound WebSocket message as bytes. */
function frameBytes(data: unknown): Uint8Array | undefined {
  if (data instanceof ArrayBuffer) {
    return new Uint8Array(data);
  }
  if (ArrayBuffer.isView(data)) {
    const view = data as ArrayBufferView;
    return new Uint8Array(view.buffer, view.byteOffset, view.byteLength);
  }
  // A string/Blob frame is not a relay binary frame — ignore it (the relay
  // speaks binary MessagePack only). Returning undefined drops it silently,
  // which is correct: it is not addressed to this driver.
  return undefined;
}

function defaultWebSocketFactory(url: string): WebSocketLike {
  const Ctor = (globalThis as { WebSocket?: new (url: string) => WebSocketLike }).WebSocket;
  if (!Ctor) {
    throw new Error(
      "no global WebSocket is available — pass options.createWebSocket to supply one (Deno/Workers/ws/Node).",
    );
  }
  return new Ctor(url);
}

export class WebSocketRelaySocket implements JsSocket {
  readonly #url: string;
  readonly #createWebSocket: (url: string) => WebSocketLike;
  readonly #reconnectEnabled: boolean;
  readonly #initialDelayMs: number;
  readonly #maxDelayMs: number;
  readonly #factor: number;
  readonly #onError: ((error: ScpError) => void) | undefined;

  #ws: WebSocketLike | undefined;
  #handlers: RelayPumpHandlers | undefined;
  #userClosed = false;
  #reconnectAttempt = 0;
  #reconnectTimer: ReturnType<typeof setTimeout> | undefined;

  constructor(options: WebSocketRelaySocketOptions) {
    this.#url = options.url;
    this.#createWebSocket = options.createWebSocket ?? defaultWebSocketFactory;
    const r = options.reconnect ?? {};
    this.#reconnectEnabled = r.enabled ?? true;
    this.#initialDelayMs = r.initialDelayMs ?? 500;
    this.#maxDelayMs = r.maxDelayMs ?? 30_000;
    this.#factor = r.factor ?? 2;
    this.#onError = options.onError;
  }

  /**
   * Writes one serialized relay frame to the socket.
   *
   * Throws if the socket is not OPEN — surfaced as `[SCP-TRANS-5010]` at the
   * client boundary (the wasm `RelaySink` adapter re-codes the thrown exception).
   * A frame is never silently dropped.
   */
  send(frame: Uint8Array): void {
    if (!this.#ws || this.#ws.readyState !== WS_OPEN) {
      throw new Error(
        `relay WebSocket is not open (readyState=${this.#ws?.readyState ?? "none"}); cannot send frame`,
      );
    }
    this.#ws.send(frame);
  }

  /**
   * Wires the inbound pump and opens the connection (phase 3 of the two-phase
   * attach). Call once, after the client that owns `handlers` exists.
   */
  attach(handlers: RelayPumpHandlers): void {
    this.#handlers = handlers;
    this.#open();
  }

  /** Closes the connection and disables reconnect. Idempotent. */
  close(): void {
    this.#userClosed = true;
    if (this.#reconnectTimer !== undefined) {
      clearTimeout(this.#reconnectTimer);
      this.#reconnectTimer = undefined;
    }
    this.#ws?.close();
    this.#ws = undefined;
  }

  #open(): void {
    const handlers = this.#handlers;
    if (!handlers) {
      return;
    }
    const ws = this.#createWebSocket(this.#url);
    ws.binaryType = "arraybuffer";
    this.#ws = ws;

    ws.onopen = () => {
      this.#reconnectAttempt = 0;
      // Re-drive subscriptions on initial open AND every reconnect. Best-effort;
      // never throws (the client's resubscribeAll swallows).
      handlers.onOpen();
    };

    ws.onmessage = (event) => {
      const bytes = frameBytes(event.data);
      if (!bytes) {
        return;
      }
      try {
        handlers.onFrame(bytes);
      } catch (error) {
        // A genuine driver error routes to onError and MUST NOT kill the pump.
        const mapped = mapWasmError(error);
        (handlers.onError ?? this.#onError)?.(mapped);
      }
    };

    ws.onclose = () => {
      this.#ws = undefined;
      this.#scheduleReconnect();
    };

    ws.onerror = () => {
      // Surface transport errors to the consumer; the close handler drives
      // reconnect. Not fatal to the pump.
      this.#onError?.(mapWasmError(new Error("[SCP-TRANS-5010] relay WebSocket error")));
    };
  }

  #scheduleReconnect(): void {
    if (this.#userClosed || !this.#reconnectEnabled || !this.#handlers) {
      return;
    }
    const delay = Math.min(
      this.#maxDelayMs,
      this.#initialDelayMs * this.#factor ** this.#reconnectAttempt,
    );
    this.#reconnectAttempt += 1;
    this.#reconnectTimer = setTimeout(() => {
      this.#reconnectTimer = undefined;
      if (!this.#userClosed) {
        this.#open();
      }
    }, delay);
  }
}
