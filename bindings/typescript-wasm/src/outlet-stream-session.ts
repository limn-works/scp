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
 *   `caveats_binding` + the caller-supplied UCAN) and each `OutletStreamCredit`
 *   grant — via the pure `scp-protocol` predicate
 *   ({@link import("./client").outletStreamSignCredit}), then routes the signed
 *   wire bytes to the node coordinator. Browser-initiated CANCEL is NOT part of
 *   this surface: §5.4.5 binds a cancel's `next_seq` to the runtime's live
 *   emission cursor ("never a value supplied by the caller"), which a remote
 *   browser invoker cannot read — cancel stays node-delegated (ADR-057), and a
 *   detected sequence gap surfaces `StreamGap` instead (see the class doc).
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
import { outletStreamSignCredit, outletStreamVerifyChunkSignature } from "./client";
import type { Credit } from "./credit";
import { OutletError, ValidationError } from "./errors";

/**
 * Tracks the single live stream consumer per `(client, contextId)`.
 *
 * A session drains the client's ENTIRE per-context receive buffer on every
 * frame ingest ({@link ScpBrowserClient.drainEvents}), keeping only events whose
 * `request_id` matches its stream and discarding the rest. Two sessions sharing
 * one client + context would therefore steal (and silently drop) each other's
 * chunks and any co-tenant traffic. This registry rejects constructing a second
 * live session on a `(client, contextId)` that already has one. Keyed WEAKLY by
 * client so a garbage-collected client drops its claims automatically; the claim
 * is released when the session closes (see `#markClosed`). This module is the
 * browser tier (`bindings/typescript-wasm`), outside the `bindings/typescript`
 * no-module-`let` gate — and this is a `const` binding regardless.
 */
const liveStreamConsumers = new WeakMap<ScpBrowserClient, Set<string>>();

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
  /**
   * Pulls the next re-encrypted chunk frame the node forwarded — a relay frame
   * carrying an MLS ciphertext the node re-encrypted to the hosting context — or
   * `null` when the node signals no more are pending. The browser decrypts it
   * in-tab; the node never sees plaintext.
   */
  pollNext(): Promise<Uint8Array | null>;
}

/**
 * Flat construction options for {@link BrowserInvokerStreamSession}.
 *
 * IMPORTANT: a session requires a DEDICATED `(client, contextId)` — it drains
 * the client's entire per-context receive buffer on every ingest and keeps only
 * its own stream's chunks (see {@link BrowserInvokerStreamSession}). Constructing
 * a second live session on a `(client, contextId)` that already has one throws
 * `SCP-VALID-7028`.
 */
export interface BrowserInvokerStreamSessionOptions {
  /**
   * The in-tab participant client (owns MLS decrypt + on-device verify).
   *
   * MUST be dedicated to this stream's context: co-tenant traffic and other
   * concurrent streams on the same `(client, contextId)` are drained and
   * discarded by this session's ingest. Use a separate client or context per
   * stream.
   */
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
   * credit grants in-tab. Never leaves the browser; never sent to the node.
   */
  readonly invokerSigningSeed: Uint8Array;
  /**
   * The operator's Ed25519 public key (32 bytes), pinned at open for chunk
   * verification.
   *
   * CALLER TRUST: on-device chunk verification is only as sound as this key.
   * The caller MUST pin the operator key it learned from the MLS-authenticated
   * outlet registration — a wrong/attacker-supplied key makes verification
   * meaningless.
   */
  readonly operatorPk: Uint8Array;
  /** The caller-supplied authorizing UCAN. */
  readonly ucanToken: string;
  /**
   * The §5.4.5 32-byte caveats binding — compute it with
   * {@link import("./client").outletStreamComputeCaveatsBinding} over the RFC
   * 8785 JCS bytes of the post-narrowing caveats.
   */
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
 * A browser-invoker outlet streaming session (SCP-OUT-048).
 *
 * Iterate it (`for await (const chunk of session)`) to drain each on-device
 * verified {@link OutletStreamChunkView} up to and including the terminal chunk,
 * or call {@link aggregate} to drain to the terminal and get the `End`
 * {@link StreamAggregate}. Extend the lifecycle with {@link grantCredit}, which
 * SIGNS the grant in-tab and routes the signed wire to the node.
 *
 * Browser-initiated CANCEL is out of scope for this slice: §5.4.5 (Cancel
 * signature) binds a cancel's `next_seq` to the runtime's live emission cursor
 * ("never a value supplied by the caller"), which a remote browser invoker
 * cannot read — cancel stays node-delegated (ADR-057; outlet.json CRITICAL #3),
 * deferred to a future cross-context-cancel slice. On a detected sequence gap
 * this session surfaces `StreamGap` (`SCP-OUTLET-6131`) to its caller and relies
 * on node-side credit-stall / timeout (§5.4.5 `stream_credit_stall_secs`) to
 * reclaim the stream.
 *
 * Single consumer: the drain is not re-entrant, AND a `(client, contextId)`
 * admits only ONE live session at a time (a second construction throws
 * `SCP-VALID-7028`). `open` is lazy — the first {@link grantCredit}, iteration,
 * or {@link aggregate} opens the stream via the coordinator exactly once.
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
    // A session drains the client's ENTIRE per-context receive buffer on ingest
    // and discards everything not matching its own stream — so two live sessions
    // on one (client, contextId) would starve each other and drop co-tenant
    // traffic. Reject a second live consumer on this (client, contextId).
    const claimed = liveStreamConsumers.get(options.client);
    if (claimed?.has(options.contextId)) {
      throw new ValidationError(
        `[SCP-VALID-7028] a BrowserInvokerStreamSession is already live on this client for ` +
          `context "${options.contextId}". A stream session drains the client's entire ` +
          `per-context receive buffer, so it requires a DEDICATED client/context — construct ` +
          `the second stream on its own ScpBrowserClient or context.`,
        "SCP-VALID-7028",
      );
    }
    if (claimed === undefined) {
      liveStreamConsumers.set(options.client, new Set([options.contextId]));
    } else {
      claimed.add(options.contextId);
    }
    this.#opts = options;
  }

  /** The stream identifier (16 bytes) this session drives. */
  get requestId(): Uint8Array {
    return this.#opts.requestId;
  }

  /**
   * Marks the session closed exactly once and releases its `(client, contextId)`
   * live-consumer claim so a fresh session can be constructed on it. Idempotent.
   */
  #markClosed(): void {
    if (this.#closed) {
      return;
    }
    this.#closed = true;
    liveStreamConsumers.get(this.#opts.client)?.delete(this.#opts.contextId);
  }

  /**
   * Throws `SCP-OUTLET-6100` if the stream has already reached a terminal /
   * closed state. `action` names the attempted operation for the message.
   */
  #throwIfClosed(action: string): void {
    if (this.#closed) {
      throw new OutletError(
        `cannot ${action}: the outlet stream has already closed`,
        "SCP-OUTLET-6100",
      );
    }
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
   * `grant` is a validated {@link Credit} (a non-zero `u32`) — the branded type
   * makes `grantCredit(4)` a `tsc` error, forcing the caller through the
   * validating {@link Credit} constructor (which throws `InvalidGrant` on a
   * value outside `[1, 2**32)`), matching the native `grantCredit(Credit)`
   * surface.
   *
   * @throws {OutletError} `SCP-OUTLET-6100` if the stream has already closed
   *   (checked both before and after the lazy open, which may race with a
   *   terminal chunk arriving on a concurrent drain).
   */
  async grantCredit(grant: Credit): Promise<Uint8Array> {
    this.#throwIfClosed("grant credit");
    await this.open();
    // Re-check after the await: a concurrent drain may have reached a terminal
    // chunk (closing the session) while `open()` was in flight. Re-check BEFORE
    // signing / advancing the monotonic counter so we never emit a grant, or
    // burn a `monotonic_seq`, on an already-closed stream.
    this.#throwIfClosed("grant credit");
    const o = this.#opts;
    const signed = outletStreamSignCredit({
      signingKeySeed: o.invokerSigningSeed,
      contextId: o.contextId,
      outletId: o.outletId,
      requestId: o.requestId,
      grant: grant.value,
      monotonicSeq: this.#creditSeq,
      streamEpoch: o.streamEpoch,
      caveatsBinding: o.caveatsBinding,
    });
    this.#creditSeq += 1n;
    await o.coordinator.grantCredit(signed);
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
      // A caller bug — the single shared drain was entered re-entrantly — NOT a
      // stream lifecycle state, so it gets its own local-validation code
      // distinct from the `SCP-OUTLET-6100` lifecycle-closed cases (an operator
      // can filter caller misuse apart from protocol/lifecycle errors).
      throw new ValidationError(
        "[SCP-VALID-7027] the outlet stream has a single shared drain — do not iterate it " +
          "from two async contexts concurrently",
        "SCP-VALID-7027",
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
          this.#markClosed();
          return { done: true, value: undefined };
        }
        this.#ingestFrame(frame);
      }
      const chunk = this.#pending.shift() as OutletStreamChunkView;
      if (chunk.sequence !== this.#expectedSequence) {
        // §5.4.5 "Ordering and gaps" (05-contexts.md:515): a non-contiguous
        // sequence is a receiver-detected gap. The browser is the REMOTE
        // invoker-side drain; per ADR-057 + §5.4.5 (Cancel signature,
        // 05-contexts.md:547) it does NOT sign an OutletCancel here — the
        // cancel `next_seq` is the runtime's live emission cursor, which a
        // remote invoker cannot read — so on a gap it surfaces `StreamGap` to
        // the caller and node-side reclamation (credit-stall / timeout,
        // §5.4.5 `stream_credit_stall_secs`, 05-contexts.md:530) reclaims the
        // stream. Browser-initiated active cancel is deferred to a future
        // cross-context-cancel slice. Close and throw WITHOUT yielding the
        // offending chunk.
        const gap = new OutletError(
          `outlet stream sequence gap: expected ${this.#expectedSequence}, got ` +
            `${chunk.sequence} (§5.4.5)`,
          "SCP-OUTLET-6131",
        );
        this.#error = gap;
        this.#pending.length = 0;
        this.#markClosed();
        throw gap;
      }
      this.#expectedSequence += 1;
      if (chunk.isTerminal) {
        this.#markClosed();
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
      // `sequence` is a §5.4.5 `u64`; a JS `number` is exact only up to
      // Number.MAX_SAFE_INTEGER. Beyond that the gap check would diverge from
      // the exact Rust verify, so reject fail-closed rather than compare a lossy
      // value. (Theoretical: >2^53 chunks in one stream.)
      if (raw.sequence > Number.MAX_SAFE_INTEGER) {
        this.#pending.length = 0;
        this.#markClosed();
        throw new ValidationError(
          `[SCP-VALID-7010] outlet stream chunk sequence ${raw.sequence} exceeds ` +
            "Number.MAX_SAFE_INTEGER — not representable exactly as a JS number",
          "SCP-VALID-7010",
        );
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
        // Fail closed and match the gap path: clear any already-buffered chunks
        // and record the error so a subsequent `.next()` returns done (never a
        // residual chunk) and `aggregate()` resurfaces the failure.
        this.#error = new OutletError(
          `outlet stream chunk ${raw.sequence}: operator signature did not verify ` +
            "on-device (§5.4.5)",
          "SCP-OUTLET-6110",
        );
        this.#pending.length = 0;
        this.#markClosed();
        throw this.#error;
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
