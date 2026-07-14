/**
 * Outlets module for the SCP TypeScript SDK.
 *
 * Provides {@link defineOutletDefinition} — a pure helper that builds
 * validated {@link OutletDefinition} objects for registration via
 * `Context.registerOutlet()`.
 *
 * The cross-context and stateful-session entry points
 * (`outletInvokeCrossContext`, `outletSessionCreate`,
 * `outletSessionInvoke`, `outletSessionClose`) moved onto the {@link SCP}
 * class in Phase 4 PR 4 (#1549, ADR-048) as
 * `scp.outletInvokeCrossContext(...)`, `scp.outletSessionCreate(...)`,
 * `scp.outletSessionInvoke(...)`, `scp.outletSessionClose(...)`. The
 * free-function shims that predated ADR-048 were deleted in the same
 * commit.
 *
 * See ADR-010 (Outlet Registry), ADR-022 in `.docs/adrs/phase-4.md`, and
 * spec sections 6.2 / 6.2.1 for cross-context invocation and stateful sessions.
 */

import {
  InvalidGrant,
  mapBridgeError,
  OutletError,
  ProtocolError,
  StreamAlreadyClosed,
  ValidationError,
} from "./errors";
import type { OutletCost, OutletDefinition, OutletKind, TestVector } from "./types";

// ---------------------------------------------------------------------------
// Outlet definition builder
// ---------------------------------------------------------------------------

/**
 * Creates a validated `OutletDefinition` object.
 *
 * Validates required fields and returns an immutable outlet definition suitable
 * for registration via `Context.registerOutlet()`.
 *
 * @param params - Outlet definition parameters.
 * @returns A validated `OutletDefinition`.
 * @throws {ValidationError} If required fields are missing or invalid.
 */
export function defineOutletDefinition(params: {
  readonly name: string;
  readonly description: string;
  readonly kind: OutletKind;
  readonly inputSchema: Readonly<Record<string, unknown>>;
  readonly outputSchema: Readonly<Record<string, unknown>>;
  readonly operator: string;
  readonly testVectors?: readonly TestVector[];
  readonly implementationHash?: Uint8Array;
  readonly cost?: OutletCost;
}): OutletDefinition {
  if (params.name.length === 0) {
    throw new ValidationError("Outlet name must not be empty", "SCP-VALID-7010");
  }

  if (params.description.length === 0) {
    throw new ValidationError("Outlet description must not be empty", "SCP-VALID-7011");
  }

  if (params.operator.length === 0) {
    throw new ValidationError("Outlet operator DID must not be empty", "SCP-VALID-7012");
  }

  const result: OutletDefinition = {
    name: params.name,
    description: params.description,
    kind: params.kind,
    inputSchema: params.inputSchema,
    outputSchema: params.outputSchema,
    operator: params.operator,
  };

  if (params.testVectors !== undefined) {
    (result as { testVectors: readonly TestVector[] }).testVectors = params.testVectors;
  }

  if (params.implementationHash !== undefined) {
    (result as { implementationHash: Uint8Array }).implementationHash = params.implementationHash;
  }

  if (params.cost !== undefined) {
    (result as { cost: OutletCost }).cost = params.cost;
  }

  return result;
}

// ---------------------------------------------------------------------------
// Progressive output (streaming) — the single public invoke() verb (§5.4.5)
// ---------------------------------------------------------------------------
//
// SCP-OUT-006 / SCP-OUT-038: the public SDK surface exposes EXACTLY ONE verb —
// `ctx.outlets.invoke(...)` — returning an {@link InvocationHandle} that is
// simultaneously `PromiseLike<Aggregate>` (`await handle` drains to the
// aggregated `End` result) and `AsyncIterable<OutletStreamChunk>` (`for await`
// yields each chunk). There is no public `invokeStream` / `pollNext` /
// `grantCredit` free function: the streaming NAPI ops (`outletStreamOpen` /
// `outletStreamPollNext` / `outletStreamGrantCredit` / `outletStreamCancel`)
// are wrapped BEHIND the handle. A non-streaming outlet is the degenerate
// two-chunk case (`Data` then `End`); the wire contract is always the
// streaming form (§5.4.5 "Non-streaming invocation").

/** Exclusive upper bound of the `u32` credit-grant range: `1 <= grant < 2**32`. */
const U32_CEIL = 2 ** 32;

/**
 * The minimal native streaming surface the handle dispatches through — the
 * `outletStream*` methods on the NAPI `SCP` addon (see
 * `crates/scp-ffi/napi/src/scp.rs`). `outletStreamOpen` takes the raw context
 * handle object; the poll / grant / cancel ops take the bridge-minted
 * `handleId` string plus the pinned caller DID.
 *
 * @internal
 */
export interface OutletStreamNative {
  outletStreamOpen(
    handle: unknown,
    outletId: string,
    inputJson: string,
    callerDid: string,
    ucanToken: string,
    proofTokens?: readonly string[],
    spendingUcan?: string,
    timeoutMs?: number,
    estimatedChunkCount?: number,
  ): Promise<string>;
  outletStreamPollNext(handleId: string): Promise<Uint8Array | number[] | null>;
  outletStreamGrantCredit(handleId: string, callerDid: string, grant: number): Promise<void>;
  outletStreamCancel(handleId: string, callerDid: string): Promise<void>;
}

/**
 * A validated, non-zero `u32` stream-credit grant (§5.4.5).
 *
 * Construct with `new Credit(n)`. `n` MUST be an integer in the half-open
 * interval `[1, 2**32)`. Any other value — `0`, a negative, `>= 2**32`, or a
 * non-integer / non-number — throws {@link InvalidGrant} at construction (the
 * SCP-OUT-031 round-6 uniform rule; never a bare `RangeError` / `TypeError`).
 *
 * {@link InvocationHandle.grantCredit} consumes a `Credit`, never a raw
 * `number` — the private brand makes `handle.grantCredit(10)` a `tsc` type
 * error (there is no implicit `number` → `Credit` coercion), forcing the
 * caller through the validating constructor. The canonical accessor field is
 * `.value` in every SDK.
 *
 * @example
 * ```ts
 * await handle.grantCredit(new Credit(4));
 * ```
 */
export class Credit {
  /**
   * Nominal brand: a `private` member makes `Credit` structurally unforgeable,
   * so neither a raw `number` nor a bare `{ value: n }` object satisfies the
   * type — only an instance minted by this validating constructor.
   */
  private readonly __creditBrand = true;

  /** The validated grant magnitude (a non-zero `u32`). */
  readonly value: number;

  constructor(value: number) {
    if (typeof value !== "number" || !Number.isInteger(value)) {
      throw new InvalidGrant(`Credit must be an integer in [1, 2**32), got ${String(value)}`);
    }
    if (value < 1 || value >= U32_CEIL) {
      throw new InvalidGrant(`Credit must be a non-zero u32 in [1, 2**32), got ${value}`);
    }
    // Touch the brand so it is not reported as an unused private member.
    void this.__creditBrand;
    this.value = value;
  }
}

/**
 * The aggregated terminal result of an outlet invocation (§5.4.5 `End`).
 *
 * Returned by `await handle` / {@link InvocationHandle.aggregate}. Carries the
 * full `End` chunk payload: the aggregate output value (matching the outlet's
 * `aggregate_schema`, validated executor-side per §5.4.5), the provenance
 * record for the stream output, and the summed wall-clock execution time.
 */
export interface Aggregate {
  /**
   * Aggregate output value — the `End.aggregate` field (matches the outlet's
   * `aggregate_schema`, or the last `Data` value when the outlet declares
   * none, per §5.4.5).
   */
  readonly value: unknown;
  /** Provenance metadata for the full stream output (§5.4.5 `End.provenance`). */
  readonly provenance: Readonly<Record<string, unknown>>;
  /**
   * Total wall-clock execution time in milliseconds, summed across the
   * stream's lifetime.
   */
  readonly executionTimeMs: number;
}

/** Renders a bridge byte field (a `number[]`, a `Uint8Array`, or a hex string) as lowercase hex. */
function bytesToHex(raw: unknown): string {
  if (typeof raw === "string") {
    return raw;
  }
  if (raw instanceof Uint8Array) {
    return Array.from(raw, (b) => b.toString(16).padStart(2, "0")).join("");
  }
  if (Array.isArray(raw)) {
    return raw.map((b) => (Number(b) & 0xff).toString(16).padStart(2, "0")).join("");
  }
  return String(raw);
}

/** Coerce a bridge-supplied provenance field to a record (empty when absent). */
function asRecord(value: unknown): Readonly<Record<string, unknown>> {
  if (typeof value === "object" && value !== null && !Array.isArray(value)) {
    return value as Record<string, unknown>;
  }
  return {};
}

/** Normalize a `outletStreamPollNext` result to raw bytes for decoding. */
function toBytes(raw: Uint8Array | number[]): Uint8Array {
  return raw instanceof Uint8Array ? raw : Uint8Array.from(raw);
}

/**
 * One chunk in an outlet stream (§5.4.5).
 *
 * Yielded by iterating an {@link InvocationHandle}. `Progress` chunks are
 * surfaced (not filtered), so a consumer sees the full `Data` / `Progress` /
 * `End` / `Error` sequence in order.
 */
export class OutletStreamChunk {
  /** Strictly monotonic per-stream sequence number, starting at `0`. */
  readonly sequence: number;

  /** Payload variant tag: `"data"`, `"progress"`, `"end"`, or `"error"` (the wire `@type`). */
  readonly kind: string;

  /**
   * The variant's fields, minus the `@type` tag. For `data`: `{ value }`;
   * `progress`: `{ pct, note }`; `end`: `{ aggregate, provenance,
   * execution_time_ms }`; `error`: `{ code, message, terminal }`.
   */
  readonly payload: Readonly<Record<string, unknown>>;

  /** Stream identifier as a lowercase hex string (opaque to the SDK). */
  readonly requestId: string;

  /**
   * Operator's per-chunk Ed25519 signature as a lowercase hex string (opaque
   * to the SDK; verified runtime-side per §5.4.5).
   */
  readonly signature: string;

  constructor(
    sequence: number,
    kind: string,
    payload: Readonly<Record<string, unknown>>,
    requestId: string,
    signature: string,
  ) {
    this.sequence = sequence;
    this.kind = kind;
    this.payload = payload;
    this.requestId = requestId;
    this.signature = signature;
  }

  /** `true` for the chunk that closes the stream (`End`, or an `Error` with `terminal: true`). */
  get isTerminal(): boolean {
    if (this.kind === "end") {
      return true;
    }
    if (this.kind === "error") {
      return this.payload.terminal === true;
    }
    return false;
  }

  /**
   * Parse the JSON-serialized `OutletStreamChunk` returned by
   * `outletStreamPollNext`. Throws {@link OutletError} if the bytes are not a
   * well-formed chunk (a bridge / transport invariant violation).
   *
   * @internal
   */
  static _fromBridgeBytes(raw: Uint8Array): OutletStreamChunk {
    let obj: unknown;
    try {
      obj = JSON.parse(new TextDecoder().decode(raw));
    } catch (cause) {
      throw new OutletError(
        `malformed outlet stream chunk from bridge: ${(cause as Error)?.message ?? String(cause)}`,
        "SCP-OUTLET-6100",
      );
    }
    if (typeof obj !== "object" || obj === null || Array.isArray(obj)) {
      throw new OutletError(
        "malformed outlet stream chunk from bridge: expected an object",
        "SCP-OUTLET-6100",
      );
    }
    const record = obj as Record<string, unknown>;
    const payload = record.payload;
    if (
      typeof payload !== "object" ||
      payload === null ||
      Array.isArray(payload) ||
      !("@type" in payload)
    ) {
      throw new OutletError(
        "malformed outlet stream chunk from bridge: missing payload/@type",
        "SCP-OUTLET-6100",
      );
    }
    const payloadRecord = payload as Record<string, unknown>;
    const variant: Record<string, unknown> = {};
    for (const [key, val] of Object.entries(payloadRecord)) {
      if (key !== "@type") {
        variant[key] = val;
      }
    }
    return new OutletStreamChunk(
      Number(record.sequence ?? 0),
      String(payloadRecord["@type"]),
      variant,
      bytesToHex(record.request_id ?? ""),
      bytesToHex(record.sig ?? ""),
    );
  }
}

/**
 * The immutable `outletStreamOpen` argument set, captured at
 * {@link Outlets.invoke} and replayed on the (lazy) first open.
 *
 * @internal
 */
interface StreamOpenParams {
  readonly contextHandle: unknown;
  readonly outletId: string;
  readonly input: Readonly<Record<string, unknown>>;
  readonly callerDid: string;
  readonly ucanToken: string;
  readonly proofTokens: readonly string[] | undefined;
  readonly spendingUcan: string | undefined;
  readonly timeoutMs: number | undefined;
  readonly estimatedChunkCount: number | undefined;
}

/**
 * The single object returned by `ctx.outlets.invoke(...)` (SCP-OUT-038).
 *
 * An `InvocationHandle` is simultaneously:
 *
 * - **`PromiseLike<Aggregate>`** — `await handle` (equivalently
 *   `await handle.aggregate()`) drains the stream to its terminal and resolves
 *   the {@link Aggregate} built from the `End` chunk. A terminal `Error` chunk
 *   rejects with a typed {@link OutletError} carrying the chunk's
 *   `SCP-OUTLET-NNNN` code.
 * - **`AsyncIterable<OutletStreamChunk>`** — `for await (const chunk of handle)`
 *   yields each {@link OutletStreamChunk} (`Data` and `Progress` included) up
 *   to and including the terminal chunk.
 *
 * `aggregate()` is the DOCUMENTED PRIMARY drain verb; `await handle` is sugar
 * over it. Because the handle is a thenable, returning it from an `async`
 * function or passing it to `Promise.resolve(...)` will ALSO drain it via
 * `aggregate()` — treat `await` / `Promise.resolve` on a handle as an
 * aggregate, and prefer the explicit `.aggregate()` where intent matters.
 *
 * **One shared drain, three directions.** Both surfaces consume the SAME
 * underlying stream and share one terminal-capture; the executor's chunk
 * sequence is drained exactly once. So:
 *
 * 1. **iterate then aggregate** — after `for await` runs to the terminal,
 *    `await handle` / {@link aggregate} returns the CACHED `Aggregate` (no
 *    re-drain).
 * 2. **aggregate then iterate** — after `await handle`, a subsequent
 *    `for await` yields NOTHING (the stream is already fully drained).
 * 3. **partial-iterate then aggregate** — `aggregate` drains the REMAINING
 *    chunks to the terminal and returns the executor's `End.aggregate`.
 *
 * A stream has a single consumer: driving it from two async contexts
 * concurrently (two `for await` loops, or `await` racing iteration) rejects
 * with {@link ProtocolError} on the second driver rather than silently
 * splitting the chunk sequence between them.
 *
 * Two control-plane methods extend the handle: {@link grantCredit} and
 * {@link cancel}. Both reject with {@link StreamAlreadyClosed} once the stream
 * has reached a terminal chunk (the §5.4.5 lifecycle guard).
 *
 * The stream is opened lazily — `invoke` returns immediately without blocking,
 * and the `outletStreamOpen` NAPI call happens on the first iteration,
 * `await`, or `grantCredit` (a grant needs a live stream). `cancel` on a
 * never-opened handle is a local no-op close — it does NOT open the stream (no
 * escrow reservation / admission slot) just to cancel it. Any bridge rejection
 * is translated to the matching SDK error type ({@link
 * import("./errors").UcanPermissionError} / {@link ValidationError} / {@link
 * import("./errors").ContextError} / …) on every surface — data plane and
 * control plane alike.
 */
export class InvocationHandle implements PromiseLike<Aggregate>, AsyncIterable<OutletStreamChunk> {
  readonly #native: OutletStreamNative;
  readonly #params: StreamOpenParams;
  #handleId: string | null = null;
  /** Memoized open, so concurrent first-touches open only one stream. */
  #openPromise: Promise<string> | null = null;
  /** Set once a terminal chunk is observed, or the sender drops without one. */
  #closed = false;
  /** In-flight re-entrancy guard: `true` while a `next()` poll is outstanding. */
  #draining = false;
  /** Captured terminal state, read back by `aggregate()`. */
  #aggregate: Aggregate | null = null;
  #error: OutletError | null = null;

  /** @internal Construct via {@link Outlets.invoke}, never directly. */
  constructor(native: OutletStreamNative, params: StreamOpenParams) {
    this.#native = native;
    this.#params = params;
  }

  /** Open the stream exactly once (idempotent), returning the bridge handle id. */
  async #ensureOpen(): Promise<string> {
    if (this.#handleId !== null) {
      return this.#handleId;
    }
    if (this.#openPromise === null) {
      this.#openPromise = this.#open();
    }
    return await this.#openPromise;
  }

  async #open(): Promise<string> {
    const p = this.#params;
    try {
      const handleId = await this.#native.outletStreamOpen(
        p.contextHandle,
        p.outletId,
        JSON.stringify(p.input),
        p.callerDid,
        p.ucanToken,
        p.proofTokens,
        p.spendingUcan,
        p.timeoutMs,
        p.estimatedChunkCount,
      );
      this.#handleId = handleId;
      return handleId;
    } catch (cause) {
      // Reset so a subsequent await / iteration / grant can retry the open
      // rather than re-awaiting a memoized rejection.
      this.#openPromise = null;
      // Open rejections (UCAN denial, input-schema violation, escrow
      // InsufficientFunds/overflow) surface on the first await / iteration /
      // control call as the matching SDK type.
      throw mapBridgeError(cause);
    }
  }

  [Symbol.asyncIterator](): AsyncIterator<OutletStreamChunk, undefined> {
    return this;
  }

  async next(): Promise<IteratorResult<OutletStreamChunk, undefined>> {
    if (this.#closed) {
      return { done: true, value: undefined };
    }
    if (this.#draining) {
      throw new ProtocolError(
        "InvocationHandle is already being drained by another consumer; an outlet " +
          "stream has a single shared drain — do not iterate or await it from two " +
          "async contexts concurrently",
      );
    }
    this.#draining = true;
    try {
      const handleId = await this.#ensureOpen();
      let raw: Uint8Array | number[] | null;
      try {
        raw = await this.#native.outletStreamPollNext(handleId);
      } catch (cause) {
        // A mid-drain bridge rejection (unknown handle, transport fault)
        // surfaces on `for await` / `aggregate` as the matching SDK type.
        throw mapBridgeError(cause);
      }
      if (raw === null) {
        // Abnormal terminal: sender dropped without a terminal chunk.
        this.#closed = true;
        return { done: true, value: undefined };
      }
      const chunk = OutletStreamChunk._fromBridgeBytes(toBytes(raw));
      if (chunk.isTerminal) {
        // Terminal chunk closes the stream. Capture the terminal state for
        // aggregate(), mark closed, then still YIELD the terminal chunk so an
        // iterating consumer observes it (End counts toward the visible
        // chunk sequence).
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

  // biome-ignore lint/suspicious/noThenProperty: InvocationHandle is deliberately PromiseLike<Aggregate> — the SCP-OUT-038 canonical contract makes `await handle` sugar over the primary `handle.aggregate()` verb.
  then<TResult1 = Aggregate, TResult2 = never>(
    onfulfilled?: ((value: Aggregate) => TResult1 | PromiseLike<TResult1>) | null,
    onrejected?: ((reason: unknown) => TResult2 | PromiseLike<TResult2>) | null,
  ): Promise<TResult1 | TResult2> {
    return this.aggregate().then(onfulfilled, onrejected);
  }

  /**
   * Drain the stream to its terminal and resolve the {@link Aggregate}. This
   * is the PRIMARY drain verb; `await handle` is sugar over it.
   *
   * Idempotent: if the stream has already been drained (by `await` or by full
   * iteration), the captured `Aggregate` is returned without re-draining. A
   * terminal `Error` chunk rejects with the typed {@link OutletError} it
   * carried; a stream that ends without an `End` chunk rejects with
   * {@link ProtocolError}.
   *
   * The resolved `value` matches the outlet's `aggregate_schema`: conformance
   * is enforced executor-side at `End` emission (§5.4.5), so the SDK surfaces
   * the validated aggregate faithfully rather than re-running JSON-Schema
   * validation the executor already performed.
   */
  async aggregate(): Promise<Aggregate> {
    while (!this.#closed) {
      const result = await this.next();
      if (result.done === true) {
        break;
      }
    }
    if (this.#error !== null) {
      throw this.#error;
    }
    if (this.#aggregate === null) {
      throw new ProtocolError("outlet stream closed without an End chunk");
    }
    return this.#aggregate;
  }

  /**
   * Grant `grant` additional billable chunks of credit to the live stream
   * (§5.4.5 credit-based backpressure).
   *
   * `grant` is a validated {@link Credit}, never a raw `number`. The NAPI
   * bridge signs the `OutletStreamCredit` internally under the pinned
   * invoker's custody key and auto-assigns the strictly-monotonic
   * `monotonic_seq` — the SDK never touches the invoker key or a replay
   * counter (ADR-006).
   *
   * Opens the stream first if it is not yet open. Rejects with
   * {@link StreamAlreadyClosed} if the stream has already reached a terminal
   * chunk; otherwise propagates any bridge rejection (e.g. `SCP-PERM-3001`
   * for a non-invoker caller, or an escrow `InsufficientFunds` /
   * `EscrowOverflow`).
   */
  async grantCredit(grant: Credit): Promise<void> {
    if (!(grant instanceof Credit)) {
      // Defense in depth: tsc already rejects a raw number, but a
      // dynamically-typed (JS / `any`) caller must still fail loud and uniform.
      throw new InvalidGrant(`grantCredit requires a Credit, got ${typeof grant}`);
    }
    if (this.#closed) {
      throw new StreamAlreadyClosed("cannot grant credit: the outlet stream has already closed");
    }
    const handleId = await this.#ensureOpen();
    try {
      await this.#native.outletStreamGrantCredit(handleId, this.#params.callerDid, grant.value);
    } catch (cause) {
      throw mapBridgeError(cause);
    }
  }

  /**
   * Request cancellation of the live stream (§5.4.5 cancellation).
   *
   * The NAPI bridge signs the `OutletCancel` internally under the pinned
   * invoker's custody key at the runtime-derived cursor (the SDK never
   * supplies a `next_seq`). The executor emits exactly one terminal
   * cancel-ack chunk within `stream_cancel_ack_secs`; billing reflects the
   * `cancel_ack_seq`.
   *
   * Cancelling a handle whose stream was never opened is a local no-op close:
   * it marks the handle closed WITHOUT opening the stream, so a cancel never
   * reserves escrow / an admission slot (and never surfaces an open-time
   * rejection) just to tear the stream down.
   *
   * Rejects with {@link StreamAlreadyClosed} if the stream has already reached
   * a terminal chunk; otherwise propagates any bridge rejection (e.g.
   * `SCP-PERM-3001` for a non-invoker caller).
   */
  async cancel(): Promise<void> {
    if (this.#closed) {
      throw new StreamAlreadyClosed("cannot cancel: the outlet stream has already closed");
    }
    const handleId = this.#handleId;
    if (handleId === null) {
      // Never opened — cancel is a local close, not a bridge round-trip.
      this.#closed = true;
      return;
    }
    try {
      await this.#native.outletStreamCancel(handleId, this.#params.callerDid);
    } catch (cause) {
      throw mapBridgeError(cause);
    }
  }
}

/**
 * Options for {@link Outlets.invoke}. Every field beyond the outlet id and
 * input is a named, optional member of a single flat config object (agent-first
 * API: no positional soup, no builder).
 */
export interface InvokeOptions {
  /** The invoker's authorizing UCAN (required). */
  readonly ucanToken: string;
  /**
   * The invoking DID. Defaults to the context's `identityDid` when omitted;
   * must equal the DID pinned as the stream invoker for the control-plane
   * methods to authorize.
   */
  readonly callerDid?: string;
  /** Optional UCAN delegation-chain proof tokens. */
  readonly proofTokens?: readonly string[];
  /** Optional spending-authorization UCAN for a paid (Action) outlet. */
  readonly spendingUcan?: string;
  /** Optional per-stream timeout in milliseconds. */
  readonly timeoutMs?: number;
  /**
   * Optional invoker-declared upper bound on billable chunks (feeds the
   * §5.4.5 `caveats_binding`).
   */
  readonly estimatedChunkCount?: number;
}

/**
 * The `ctx.outlets` accessor — the home of the single `invoke` verb.
 *
 * Bound to one {@link import("./context").Context}: it carries the context's
 * raw bridge handle and the caller DID that context is scoped to, and
 * dispatches to the context's owning NAPI bridge. Obtain it via
 * `ctx.outlets`, never construct it directly.
 */
export class Outlets {
  readonly #native: OutletStreamNative;
  readonly #contextHandle: unknown;
  readonly #defaultCallerDid: string;

  /** @internal Obtain via `ctx.outlets`, never directly. */
  constructor(native: OutletStreamNative, contextHandle: unknown, defaultCallerDid: string) {
    this.#native = native;
    this.#contextHandle = contextHandle;
    this.#defaultCallerDid = defaultCallerDid;
  }

  /**
   * Invoke `outletId` and return its {@link InvocationHandle}.
   *
   * This is the ONLY public invocation verb (SCP-OUT-006). The returned handle
   * is both `PromiseLike<Aggregate>` (`await handle`) and
   * `AsyncIterable<OutletStreamChunk>` (`for await (const chunk of handle)`);
   * the streaming NAPI ops are wrapped behind it. `invoke` itself performs no
   * I/O and does not block or throw — the stream opens lazily on the first
   * `await` / iteration / control-plane call, where open-time rejections
   * surface as the matching typed SDK error.
   *
   * @param outletId Registration id of the target outlet.
   * @param input JSON-compatible input value (validated against the outlet's
   *   `input_schema` at open).
   * @param options Named invocation options; `ucanToken` is required.
   */
  invoke(
    outletId: string,
    input: Readonly<Record<string, unknown>>,
    options: InvokeOptions,
  ): InvocationHandle {
    const params: StreamOpenParams = {
      contextHandle: this.#contextHandle,
      outletId,
      input,
      callerDid: options.callerDid ?? this.#defaultCallerDid,
      ucanToken: options.ucanToken,
      proofTokens: options.proofTokens,
      spendingUcan: options.spendingUcan,
      timeoutMs: options.timeoutMs,
      estimatedChunkCount: options.estimatedChunkCount,
    };
    return new InvocationHandle(this.#native, params);
  }
}
