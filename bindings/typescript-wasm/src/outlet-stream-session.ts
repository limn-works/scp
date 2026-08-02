/**
 * {@link BrowserInvokerStreamSession} — the in-browser INVOKER side of a §5.4.5
 * cross-context outlet streaming saga (SCP-OUT-048), strictly within the ADR-057
 * scope fence.
 *
 * ## The fence (node-delegated coordination)
 *
 * The browser is the ORIGINATING invoker: it **participates** (signs its own
 * control-plane messages) but does **not coordinate**. Per the ADR-057 scope
 * fence ("cross-context saga coordination … node-delegated; the browser
 * participates but does not coordinate"), everything that needs an always-on host
 * and `scp-runtime` — the saga FSM, the off-mailbox pump, the `SagaId`-keyed
 * durable capture, escrow settlement, and receipt **signing** (SCP-OUT-046/047) —
 * is delegated to the node behind an injected {@link NodeStreamCoordinator}. This
 * session performs ONLY the invoker-side pure-crypto work IN-TAB, keys on-device:
 *
 * - **Signs its own control plane.** `OutletStreamOpen` (the §5.4.5
 *   `caveats_binding` + the caller-supplied UCAN), each `OutletStreamCredit`
 *   grant, and its `OutletStreamCancel` — via the pure `scp-protocol` predicates
 *   ({@link import("./client").outletStreamSignCredit} /
 *   {@link import("./client").outletStreamSignCancel}), then routes the signed
 *   wire bytes to the node coordinator.
 * - **Decrypts + verifies the data plane on-device.** The node re-encrypts each
 *   operator chunk to the hosting context and forwards the (still-encrypted)
 *   frame; the browser MLS-decrypts it via the existing {@link ScpBrowserClient}
 *   receive path ({@link ScpBrowserClient.handleRelayFrame} →
 *   {@link ScpBrowserClient.drainEvents}) and verifies each chunk's operator
 *   signature locally via {@link import("./client").outletStreamVerifyChunkSignature}.
 *   The node never sees plaintext and never holds a key.
 *
 * The UCAN is **caller-supplied** — this session never mints one (UCAN minting is
 * outside the wasm participant surface). The `scp-client-wasm` crate carries no
 * `scp-runtime` dependency and no saga pump/seal/receipt-signing code; this TS
 * layer adds none either.
 */

import type { ScpBrowserClient } from "./client";
import {
  outletStreamComputeCaveatsBinding,
  outletStreamSignCancel,
  outletStreamSignCredit,
  outletStreamVerifyChunkSignature,
} from "./client";
import { OutletError } from "./errors";

/**
 * The invoker's signed `OutletStreamOpen` request the node's 047 saga opens the
 * stream from. The browser computes the §5.4.5 `caveatsBinding` and attaches the
 * caller-supplied UCAN in-tab; the node coordinates the open.
 */
export interface OutletStreamOpenRequest {
  /** Hosting context id. */
  readonly contextId: string;
  /** Target outlet id. */
  readonly outletId: string;
  /** Stream identifier (16 bytes). */
  readonly requestId: Uint8Array;
  /** The invoking DID. */
  readonly invokerDid: string;
  /** The caller-supplied authorizing UCAN (this session never mints one). */
  readonly ucanToken: string;
  /** Declared upper bound on billable chunks (bound into `caveatsBinding`). */
  readonly estimatedChunkCount: number;
  /** The §5.4.5 32-byte caveats binding computed in-tab. */
  readonly caveatsBinding: Uint8Array;
}

/**
 * The node-side coordinator seam (SCP-OUT-047). The browser routes the
 * control-plane messages it SIGNS in-tab through this port, and pulls the
 * re-encrypted chunk frames the node FORWARDS through it — the node coordinates
 * the saga (FSM, pump, escrow, receipts); the browser only signs and decrypts.
 *
 * An embedder implements this over its own MLS/relay channel to the node (e.g. a
 * management-message request/response, or a WebSocket control channel). It is a
 * plain injected port, consistent with the ADR-057 `JsSocket`/`JsKeyCustody`
 * injection model.
 */
export interface NodeStreamCoordinator {
  /** Routes the invoker's signed `OutletStreamOpen` to the node; the node opens the saga. */
  open(request: OutletStreamOpenRequest): Promise<void>;
  /** Routes an in-tab-signed `OutletStreamCredit` (JSON wire bytes) to the node saga. */
  grantCredit(signedCredit: Uint8Array): Promise<void>;
  /** Routes an in-tab-signed `OutletStreamCancel` (JSON wire bytes) to the node saga. */
  cancel(signedCancel: Uint8Array): Promise<void>;
  /**
   * Pulls the next re-encrypted chunk frame the node forwarded — a relay frame
   * carrying an MLS ciphertext the node re-encrypted to the hosting context — or
   * `null` when the node signals no more are pending. The browser decrypts it
   * in-tab; the node never sees plaintext.
   */
  pollNext(): Promise<Uint8Array | null>;
}

/** Flat construction options for {@link BrowserInvokerStreamSession}. */
export interface BrowserInvokerStreamSessionOptions {
  /** The in-tab participant client (owns MLS decrypt + on-device verify). */
  readonly client: ScpBrowserClient;
  /** The injected node-side saga coordinator. */
  readonly coordinator: NodeStreamCoordinator;
  /** Hosting context id. */
  readonly contextId: string;
  /** Target outlet id. */
  readonly outletId: string;
  /** Stream identifier (16 bytes). */
  readonly requestId: Uint8Array;
  /** The invoking DID (pinned at open). */
  readonly invokerDid: string;
  /**
   * The invoker's 32-byte outlet-signing seed, held on-device. Used to sign
   * credit/cancel in-tab. Never leaves the browser; never sent to the node.
   */
  readonly invokerSigningSeed: Uint8Array;
  /** The operator's Ed25519 public key (32 bytes), pinned at open for chunk verification. */
  readonly operatorPk: Uint8Array;
  /** The caller-supplied authorizing UCAN. */
  readonly ucanToken: string;
  /** The §5.4.5 32-byte caveats binding (see {@link caveatsBindingFor}). */
  readonly caveatsBinding: Uint8Array;
  /** The hosting context's MLS epoch pinned at open (bound into credit preimages). */
  readonly streamEpoch: bigint;
  /** Declared upper bound on billable chunks. */
  readonly estimatedChunkCount: number;
}

/** The terminal aggregate an outlet stream resolves to (the `End` chunk). */
export interface StreamAggregate {
  /** Aggregate output value (matches the outlet's `aggregate_schema`). */
  readonly value: unknown;
  /** Provenance metadata for the full stream output. */
  readonly provenance: Record<string, unknown>;
  /** Wall-clock execution time in milliseconds, summed across the stream. */
  readonly executionTimeMs: number;
}

/** One decoded, on-device-verified chunk yielded by iterating the session. */
export interface OutletStreamChunkView {
  /** Strictly monotonic per-stream sequence, from 0. */
  readonly sequence: number;
  /** Payload variant discriminator. */
  readonly kind: "data" | "progress" | "end" | "error";
  /** The decoded `payload` object (`@type` + variant fields). */
  readonly payload: Record<string, unknown>;
  /** `true` for `End` and terminal `Error` — the chunk that closes the stream. */
  readonly isTerminal: boolean;
}

/** The raw JSON shape of a §5.4.5 `OutletStreamChunk` (`serde_bytes` → number arrays). */
interface RawChunk {
  request_id: number[];
  sequence: number;
  payload: Record<string, unknown>;
  sig: number[];
}

const DECODER = new TextDecoder();

/**
 * Computes the §5.4.5 `caveatsBinding` a browser invoker binds into its open,
 * credit, cancel, and chunk-verification calls — a thin, self-documenting alias
 * over {@link import("./client").outletStreamComputeCaveatsBinding} so a caller
 * building a session has one obvious helper. `effectiveCaveatsJcs` MUST be the
 * RFC 8785 JCS bytes of the post-narrowing caveats.
 */
export function caveatsBindingFor(
  ucanCid: Uint8Array,
  requestId: Uint8Array,
  invokerDid: string,
  estimatedChunkCount: number,
  effectiveCaveatsJcs: Uint8Array,
): Uint8Array {
  return outletStreamComputeCaveatsBinding(
    ucanCid,
    requestId,
    invokerDid,
    estimatedChunkCount,
    effectiveCaveatsJcs,
  );
}

/**
 * A browser-invoker outlet streaming session (SCP-OUT-048).
 *
 * Iterate it (`for await (const chunk of session)`) to drain each on-device
 * verified {@link OutletStreamChunkView} up to and including the terminal chunk,
 * or call {@link aggregate} to drain to the terminal and get the `End`
 * {@link StreamAggregate}. Extend the lifecycle with {@link grantCredit} and
 * {@link cancel}, both of which SIGN in-tab and route the signed wire to the node.
 *
 * Single consumer: the drain is not re-entrant. `open` is lazy — the first
 * {@link grantCredit}, iteration, or {@link aggregate} opens the stream via the
 * coordinator exactly once.
 */
export class BrowserInvokerStreamSession implements AsyncIterable<OutletStreamChunkView> {
  readonly #opts: BrowserInvokerStreamSessionOptions;
  #opened = false;
  #openPromise: Promise<void> | null = null;
  #closed = false;
  #draining = false;
  /** Strictly-monotonic credit grant counter, from 0 (§5.4.5 `monotonic_seq`). */
  #creditSeq = 0n;
  /** Receiver-side cursor: the sequence the NEXT chunk must carry. */
  #expectedSequence = 0;
  /** Decoded+verified chunks awaiting consumption (one frame may carry one). */
  readonly #pending: OutletStreamChunkView[] = [];
  #aggregate: StreamAggregate | null = null;
  #error: OutletError | null = null;

  constructor(options: BrowserInvokerStreamSessionOptions) {
    this.#opts = options;
  }

  /** The stream identifier (16 bytes) this session drives. */
  get requestId(): Uint8Array {
    return this.#opts.requestId;
  }

  /**
   * Opens the stream exactly once (idempotent): routes the invoker's signed
   * `OutletStreamOpen` (the in-tab `caveatsBinding` + caller UCAN) to the node
   * coordinator, which opens the 047 saga.
   */
  async open(): Promise<void> {
    if (this.#opened) {
      return;
    }
    if (this.#openPromise === null) {
      const o = this.#opts;
      const request: OutletStreamOpenRequest = {
        contextId: o.contextId,
        outletId: o.outletId,
        requestId: o.requestId,
        invokerDid: o.invokerDid,
        ucanToken: o.ucanToken,
        estimatedChunkCount: o.estimatedChunkCount,
        caveatsBinding: o.caveatsBinding,
      };
      this.#openPromise = o.coordinator
        .open(request)
        .then(() => {
          this.#opened = true;
        })
        .catch((cause) => {
          // Reset so a later call can retry rather than re-awaiting a rejection.
          this.#openPromise = null;
          throw cause;
        });
    }
    return this.#openPromise;
  }

  /**
   * Signs an `OutletStreamCredit` grant IN-TAB (auto-assigning the strictly
   * monotonic `monotonic_seq`) and routes the signed wire bytes to the node
   * coordinator. Opens the stream first if needed. Returns the signed
   * `OutletStreamCredit` JSON wire bytes it routed (so a caller can inspect /
   * re-verify the artifact it produced).
   *
   * @throws {OutletError} `SCP-OUTLET-6100` if the stream has already closed.
   */
  async grantCredit(grant: number): Promise<Uint8Array> {
    if (this.#closed) {
      throw new OutletError(
        "cannot grant credit: the outlet stream has already closed",
        "SCP-OUTLET-6100",
      );
    }
    await this.open();
    const o = this.#opts;
    const signed = outletStreamSignCredit(
      o.invokerSigningSeed,
      o.contextId,
      o.outletId,
      o.requestId,
      grant,
      this.#creditSeq,
      o.streamEpoch,
      o.caveatsBinding,
    );
    this.#creditSeq += 1n;
    await o.coordinator.grantCredit(signed);
    return signed;
  }

  /**
   * Signs an `OutletStreamCancel` IN-TAB at the current receiver cursor and
   * routes the signed wire bytes to the node coordinator. Marks the session
   * closed. Returns the signed `OutletStreamCancel` JSON wire bytes it routed.
   *
   * @throws {OutletError} `SCP-OUTLET-6100` if the stream has already closed.
   */
  async cancel(): Promise<Uint8Array> {
    if (this.#closed) {
      throw new OutletError(
        "cannot cancel: the outlet stream has already closed",
        "SCP-OUTLET-6100",
      );
    }
    await this.open();
    const o = this.#opts;
    const signed = outletStreamSignCancel(
      o.invokerSigningSeed,
      o.contextId,
      o.outletId,
      o.requestId,
      BigInt(this.#expectedSequence),
      o.caveatsBinding,
    );
    this.#closed = true;
    await o.coordinator.cancel(signed);
    return signed;
  }

  [Symbol.asyncIterator](): AsyncIterator<OutletStreamChunkView, undefined> {
    return this;
  }

  /**
   * Pulls, decrypts, and verifies the next chunk. Each call routes through the
   * node coordinator for the next re-encrypted frame, MLS-decrypts it in-tab via
   * the {@link ScpBrowserClient} receive path, and verifies the operator
   * signature on-device before yielding.
   *
   * @throws {OutletError} `SCP-OUTLET-6110` on a chunk whose operator signature
   *   does not verify; `SCP-OUTLET-6131` on a §5.4.5 sequence gap.
   */
  async next(): Promise<IteratorResult<OutletStreamChunkView, undefined>> {
    if (this.#closed && this.#pending.length === 0) {
      return { done: true, value: undefined };
    }
    if (this.#draining) {
      throw new OutletError(
        "the outlet stream has a single shared drain — do not iterate it from two " +
          "async contexts concurrently",
        "SCP-OUTLET-6100",
      );
    }
    this.#draining = true;
    try {
      await this.open();
      // Refill from the node until we have a chunk for this stream, or the node
      // signals no more frames are pending.
      while (this.#pending.length === 0) {
        const frame = await this.#opts.coordinator.pollNext();
        if (frame === null) {
          // Abnormal terminal: the node has no more frames but no `End` arrived.
          this.#closed = true;
          return { done: true, value: undefined };
        }
        this.#ingestFrame(frame);
      }
      const chunk = this.#pending.shift() as OutletStreamChunkView;
      if (chunk.sequence !== this.#expectedSequence) {
        // §5.4.5 "Ordering and gaps": a non-contiguous sequence is a
        // receiver-detected gap. Close, best-effort cancel through the signed
        // path, and throw WITHOUT yielding the offending chunk.
        this.#closed = true;
        const gap = new OutletError(
          `outlet stream sequence gap: expected ${this.#expectedSequence}, got ` +
            `${chunk.sequence} (§5.4.5)`,
          "SCP-OUTLET-6131",
        );
        this.#error = gap;
        this.#pending.length = 0;
        throw gap;
      }
      this.#expectedSequence += 1;
      if (chunk.isTerminal) {
        this.#closed = true;
        if (chunk.kind === "end") {
          this.#aggregate = {
            value: chunk.payload.aggregate,
            provenance: asRecord(chunk.payload.provenance),
            executionTimeMs: Number(chunk.payload.execution_time_ms ?? 0),
          };
        } else if (chunk.kind === "error") {
          this.#error = new OutletError(
            String(chunk.payload.message ?? "outlet stream error"),
            String(chunk.payload.code ?? "SCP-OUTLET-6000"),
          );
        }
      }
      return { done: false, value: chunk };
    } finally {
      this.#draining = false;
    }
  }

  /**
   * Drains the stream to its terminal and resolves the `End`
   * {@link StreamAggregate}. Idempotent: a fully-drained stream returns the
   * cached aggregate. A terminal `Error` chunk rejects with the typed
   * {@link OutletError} it carried; a stream that ends without an `End` rejects
   * with `SCP-OUTLET-6100`.
   */
  async aggregate(): Promise<StreamAggregate> {
    while (!this.#closed || this.#pending.length > 0) {
      const result = await this.next();
      if (result.done === true) {
        break;
      }
    }
    if (this.#error !== null) {
      throw this.#error;
    }
    if (this.#aggregate === null) {
      throw new OutletError("outlet stream closed without an End chunk", "SCP-OUTLET-6100");
    }
    return this.#aggregate;
  }

  /**
   * Decrypts one re-encrypted frame in-tab via the {@link ScpBrowserClient}
   * receive path, then verifies + buffers every chunk it yielded for THIS stream.
   */
  #ingestFrame(frame: Uint8Array): void {
    const o = this.#opts;
    // In-tab MLS decrypt through the existing receive path (keys on-device).
    o.client.handleRelayFrame(frame);
    for (const event of o.client.drainEvents(o.contextId)) {
      if (event.kind !== "MessageReceived") {
        continue;
      }
      const raw = decodeChunk(event.payload);
      if (raw === null || !bytesEqual(raw.request_id, o.requestId)) {
        // Not a chunk of this stream (a co-tenant message / unparseable) — skip.
        continue;
      }
      // On-device operator-signature verification over the EXACT decrypted bytes.
      const verified = outletStreamVerifyChunkSignature(
        event.payload,
        o.operatorPk,
        o.contextId,
        o.outletId,
        o.caveatsBinding,
      );
      if (!verified) {
        this.#closed = true;
        throw new OutletError(
          `outlet stream chunk ${raw.sequence}: operator signature did not verify ` +
            "on-device (§5.4.5)",
          "SCP-OUTLET-6110",
        );
      }
      this.#pending.push(toChunkView(raw));
    }
  }
}

/** Parses a decrypted payload as a §5.4.5 chunk, or `null` if it is not one. */
function decodeChunk(payload: Uint8Array): RawChunk | null {
  let parsed: unknown;
  try {
    parsed = JSON.parse(DECODER.decode(payload));
  } catch {
    return null;
  }
  if (
    typeof parsed !== "object" ||
    parsed === null ||
    !Array.isArray((parsed as RawChunk).request_id) ||
    typeof (parsed as RawChunk).sequence !== "number" ||
    typeof (parsed as RawChunk).payload !== "object"
  ) {
    return null;
  }
  return parsed as RawChunk;
}

function toChunkView(raw: RawChunk): OutletStreamChunkView {
  const kind = String(raw.payload["@type"]) as OutletStreamChunkView["kind"];
  const isTerminal = kind === "end" || (kind === "error" && raw.payload.terminal === true);
  return { sequence: raw.sequence, kind, payload: raw.payload, isTerminal };
}

function bytesEqual(a: number[], b: Uint8Array): boolean {
  if (a.length !== b.length) {
    return false;
  }
  for (let i = 0; i < a.length; i += 1) {
    if (a[i] !== b[i]) {
      return false;
    }
  }
  return true;
}

function asRecord(value: unknown): Record<string, unknown> {
  return typeof value === "object" && value !== null ? (value as Record<string, unknown>) : {};
}
