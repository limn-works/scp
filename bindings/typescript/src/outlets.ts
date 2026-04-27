/**
 * Outlets module for the SCP TypeScript SDK (SCP-OUT-006).
 *
 * Exposes {@link OutletNamespace} — mounted on {@link Context} as
 * `ctx.outlets` — with the full outlet verb set plus two sub-namespaces:
 *
 * - `ctx.outlets.sessions` — stateful outlet sessions (§6.2.1.1)
 * - `ctx.outlets.offers`   — cross-context outlet interface offers (§6.2.0.1)
 *
 * Plus:
 *
 * - {@link InvocationHandle} — dual-mode (PromiseLike<Aggregate> +
 *   AsyncIterable<OutletStreamChunk>) handle returned by
 *   `ctx.outlets.invoke(id, input)`.
 * - {@link InvokeCrossContextOptions} — options-object form for
 *   `ctx.outlets.invokeCrossContext` (API MAJOR 22).
 * - {@link SessionId} — branded string, distinct from OutletId (API MAJOR 28).
 * - Caveat helpers at {@link caveats} — spendingCap / timeBounded /
 *   rateLimited / forTarget each returning a builder with `.build()`.
 *
 * Error-code prefix remains `SCP-TOOL-*` (§9.18 — registered namespace).
 */

import { OutletError, OutletExecutionError, ValidationError } from "./errors";
import type { Bridge, BridgeContextHandle } from "./internal/bridge";
import { getBridge } from "./internal/bridge";
import type {
  CrossContextInvocationResult,
  TestVector,
  ToolCost,
  ToolDefinition,
  ToolSessionInvokeResult,
} from "./types";

// ---------------------------------------------------------------------------
// Branded types (API MAJOR 28).
// ---------------------------------------------------------------------------

/**
 * Branded string type — a UUIDv7 session identifier.
 *
 * Used by `ctx.outlets.sessions.invoke` / `ctx.outlets.sessions.close` to
 * distinguish a session id from a plain outlet id at the type level
 * (both are strings at the wire layer).
 */
export type SessionId = string & { readonly __brand: "SessionId" };

/** Branded string — an outlet id. */
export type OutletId = string & { readonly __brand: "OutletId" };

/** Branded string — a DID. */
export type DID = string & { readonly __brand: "DID" };

const UUID7_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const UUID7_SKEW_TOLERANCE_MS = 10 * 60 * 1000;

export function validateSessionId(
  raw: string,
  nowMs: number = Date.now(),
): asserts raw is SessionId {
  if (typeof raw !== "string") {
    throw new ValidationError(`SessionId must be string, got ${typeof raw}`, "SCP-VALID-7010");
  }
  if (!UUID7_RE.test(raw)) {
    throw new ValidationError(
      `SessionId must be a canonical UUIDv7; got ${JSON.stringify(raw)}`,
      "SCP-VALID-7010",
    );
  }
  const tsHex = raw.slice(0, 8) + raw.slice(9, 13);
  const tsMs = Number.parseInt(tsHex, 16);
  if (tsMs < nowMs - UUID7_SKEW_TOLERANCE_MS) {
    throw new ValidationError(
      `SessionId timestamp ${tsMs} is more than 10 minutes in the past (now ${nowMs})`,
      "SCP-VALID-7010",
    );
  }
  if (tsMs > nowMs + UUID7_SKEW_TOLERANCE_MS) {
    throw new ValidationError(
      `SessionId timestamp ${tsMs} is more than 10 minutes in the future (now ${nowMs})`,
      "SCP-VALID-7010",
    );
  }
}

/**
 * Construct a {@link SessionId} from a caller-supplied string after
 * UUIDv7 + timestamp-window validation.
 */
export function sessionId(raw: string): SessionId {
  validateSessionId(raw);
  return raw;
}

/**
 * Mint a fresh UUIDv7 SessionId using `crypto.getRandomValues` for the 74
 * random bits (rand_b) as required by §6.2.1.1(a).
 */
export function newSessionId(): SessionId {
  const tsMs = Date.now();
  const bytes = new Uint8Array(16);
  // 48-bit big-endian unix-ms timestamp.
  bytes[0] = (tsMs / 2 ** 40) & 0xff;
  bytes[1] = (tsMs / 2 ** 32) & 0xff;
  bytes[2] = (tsMs / 2 ** 24) & 0xff;
  bytes[3] = (tsMs / 2 ** 16) & 0xff;
  bytes[4] = (tsMs / 2 ** 8) & 0xff;
  bytes[5] = tsMs & 0xff;
  const rand = new Uint8Array(10);
  // Use Web Crypto / Node crypto as the CSPRNG — never Math.random.
  if (typeof crypto !== "undefined" && typeof crypto.getRandomValues === "function") {
    crypto.getRandomValues(rand);
  } else {
    // Node fallback.
    // biome-ignore lint/style/noNonNullAssertion: Node always provides require here.
    const nodeCrypto = require("node:crypto") as { randomFillSync: (b: Uint8Array) => void };
    nodeCrypto.randomFillSync(rand);
  }
  // Version nibble 7 in high 4 bits of bytes[6].
  bytes[6] = 0x70 | ((rand[0] ?? 0) & 0x0f);
  bytes[7] = rand[1] ?? 0;
  // Variant bits 0b10 in top 2 bits of bytes[8].
  bytes[8] = 0x80 | ((rand[2] ?? 0) & 0x3f);
  bytes[9] = rand[3] ?? 0;
  bytes.set(rand.slice(4, 10), 10);
  const hex = Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
  const raw =
    `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-` +
    `${hex.slice(16, 20)}-${hex.slice(20, 32)}`;
  return raw as SessionId;
}

// ---------------------------------------------------------------------------
// Streaming + caveats SDK-layer types (§5.4.5, §7.3.8).
// ---------------------------------------------------------------------------

export interface OutletStreamChunk {
  readonly requestId: Uint8Array;
  readonly sequence: number;
  readonly payloadType: "data" | "progress" | "end" | "error";
  readonly value?: unknown;
  readonly pct?: number;
  readonly note?: string;
  readonly aggregate?: unknown;
  readonly provenance?: Readonly<Record<string, unknown>>;
  readonly executionTimeMs?: number;
  readonly code?: string;
  readonly message?: string;
  readonly terminal?: boolean;
}

export interface Aggregate {
  readonly value: unknown;
  readonly provenance?: Readonly<Record<string, unknown>>;
  readonly executionTimeMs?: number;
}

/** Narrowed UCAN invocation caveats (§7.3.8, 11 fields). */
export interface InvocationCaveats {
  readonly amountMaxPerCall?: number;
  readonly amountMaxCumulative?: number;
  readonly validFrom?: number;
  readonly validUntil?: number;
  readonly hoursOfDay?: number;
  readonly daysOfWeek?: number;
  readonly maxCalls?: number;
  readonly rateWindow?: number;
  readonly inputSchema?: Readonly<Record<string, unknown>>;
  readonly allowedAdapters?: readonly string[];
  readonly allowedTargetDids?: readonly string[];
  readonly originKind?: "Query" | "Action";
}

// ---------------------------------------------------------------------------
// Caveat builder helpers (review item 33).
// ---------------------------------------------------------------------------

/**
 * Mutable in-builder shape of {@link InvocationCaveats}. Callers never see
 * this — the `.build()` return is the readonly published record.
 */
type MutableInvocationCaveats = {
  -readonly [K in keyof InvocationCaveats]: InvocationCaveats[K];
};

export class CaveatBuilder {
  private fields: MutableInvocationCaveats = {};

  spendingCap(args: { perCall?: number; cumulative?: number }): this {
    if (args.perCall !== undefined) this.fields.amountMaxPerCall = args.perCall;
    if (args.cumulative !== undefined) this.fields.amountMaxCumulative = args.cumulative;
    return this;
  }

  timeBounded(args: {
    validFrom?: number;
    validUntil?: number;
    hoursOfDay?: number;
    daysOfWeek?: number;
  }): this {
    if (args.validFrom !== undefined) this.fields.validFrom = args.validFrom;
    if (args.validUntil !== undefined) this.fields.validUntil = args.validUntil;
    if (args.hoursOfDay !== undefined) {
      if (args.hoursOfDay < 0 || args.hoursOfDay >= 1 << 24) {
        throw new Error(`hoursOfDay must be a 24-bit bitmask, got ${args.hoursOfDay}`);
      }
      this.fields.hoursOfDay = args.hoursOfDay;
    }
    if (args.daysOfWeek !== undefined) {
      if (args.daysOfWeek < 0 || args.daysOfWeek >= 1 << 7) {
        throw new Error(`daysOfWeek must be a 7-bit bitmask, got ${args.daysOfWeek}`);
      }
      this.fields.daysOfWeek = args.daysOfWeek;
    }
    return this;
  }

  rateLimited(args: { maxCalls?: number; rateWindow?: number }): this {
    if (args.maxCalls !== undefined) this.fields.maxCalls = args.maxCalls;
    if (args.rateWindow !== undefined) this.fields.rateWindow = args.rateWindow;
    return this;
  }

  forTarget(args: {
    allowedTargetDids?: readonly string[];
    allowedAdapters?: readonly string[];
  }): this {
    if (args.allowedTargetDids !== undefined)
      this.fields.allowedTargetDids = [...args.allowedTargetDids];
    if (args.allowedAdapters !== undefined) this.fields.allowedAdapters = [...args.allowedAdapters];
    return this;
  }

  inputSchema(schema: Readonly<Record<string, unknown>>): this {
    this.fields.inputSchema = schema;
    return this;
  }

  originKind(kind: "Query" | "Action"): this {
    if (kind !== "Query" && kind !== "Action") {
      throw new Error(`originKind must be 'Query' or 'Action', got ${kind}`);
    }
    this.fields.originKind = kind;
    return this;
  }

  build(): InvocationCaveats {
    return { ...this.fields };
  }
}

/**
 * Caveat helper namespace — reduces 11-field InvocationCaveats friction at
 * call sites (review item 33).
 *
 * Usage::
 *
 *     import { caveats } from "@limn-works/scp-ts";
 *     const c = caveats.spendingCap({ perCall: 100 })
 *       .timeBounded({ validUntil: Date.now() + 3600_000 })
 *       .build();
 */
export const caveats = {
  spendingCap: (args: { perCall?: number; cumulative?: number }): CaveatBuilder =>
    new CaveatBuilder().spendingCap(args),
  timeBounded: (args: {
    validFrom?: number;
    validUntil?: number;
    hoursOfDay?: number;
    daysOfWeek?: number;
  }): CaveatBuilder => new CaveatBuilder().timeBounded(args),
  rateLimited: (args: { maxCalls?: number; rateWindow?: number }): CaveatBuilder =>
    new CaveatBuilder().rateLimited(args),
  forTarget: (args: {
    allowedTargetDids?: readonly string[];
    allowedAdapters?: readonly string[];
  }): CaveatBuilder => new CaveatBuilder().forTarget(args),
  builder: (): CaveatBuilder => new CaveatBuilder(),
};

// ---------------------------------------------------------------------------
// OutletKind — outlet semantic class (Query vs Action), SCP-OUT-017.
// ---------------------------------------------------------------------------

/**
 * Outlet semantic class (§5.4.2).
 *
 * `'query'` outlets are read-only and idempotent (UCAN stem
 * `outlet_query:{id}`); `'action'` outlets may mutate state (UCAN stem
 * `outlet_call:{id}`).
 *
 * Required at the SDK surface across all 4 bindings (SCP-OUT-017). The
 * lowercase string-literal union matches the §5.4.2 wire vocabulary
 * directly so callers do not have to import an enum.
 */
export type OutletKind = "query" | "action";

/** Allowed values for {@link OutletKind} — useful for `as const` consumers. */
export const OUTLET_KINDS: readonly OutletKind[] = ["query", "action"] as const;

/**
 * Validate that a string is a valid {@link OutletKind} value. Throws
 * {@link ValidationError} with code `SCP-VALID-7050` on mismatch.
 */
export function assertOutletKind(value: unknown): asserts value is OutletKind {
  if (value !== "query" && value !== "action") {
    throw new ValidationError(
      `OutletKind must be 'query' or 'action' (§5.4.2 wire vocabulary), got ${JSON.stringify(value)}`,
      "SCP-VALID-7050",
    );
  }
}

// ---------------------------------------------------------------------------
// Outlet type aliases (public surface — ToolDefinition/ToolCost kept at wire
// level for internal bridge compat; re-exported under outlet names here).
// ---------------------------------------------------------------------------

/**
 * Outlet registration definition (§5.4.1) — public SDK surface.
 *
 * SCP-OUT-017 makes `kind` REQUIRED. Omitting `kind` is a TypeScript
 * compile error; passing `undefined` is rejected at runtime via the
 * type-narrowing at the bridge boundary.
 */
export interface OutletDefinition extends ToolDefinition {
  /** Outlet semantic class (Query vs Action — §5.4.2). REQUIRED. */
  readonly kind: OutletKind;
}
/** Alias for per-invocation cost metadata (§5.4.1). */
export type OutletCost = ToolCost;

// ---------------------------------------------------------------------------
// InvocationHandle — dual consumption (await aggregate / async iterate chunks).
// ---------------------------------------------------------------------------

/**
 * Handle returned by `ctx.outlets.invoke(id, input)`.
 *
 * Supports BOTH consumption patterns (API MAJOR 21, review item 32):
 *
 * * `const aggregate = await handle;` — PromiseLike<Aggregate>; resolves
 *   to the terminal `end` chunk's aggregate value.
 * * `for await (const chunk of handle) { … }` — AsyncIterable<OutletStreamChunk>;
 *   yields chunks as they arrive.
 *
 * The two styles are mutually exclusive per handle; once one is chosen, the
 * other throws `OutletError`.
 */
export class InvocationHandle implements PromiseLike<Aggregate>, AsyncIterable<OutletStreamChunk> {
  private consumed: "aggregate" | "stream" | null = null;
  private resolved: Aggregate | null = null;
  private rejected: unknown = null;
  private deferredResolvers: Array<(a: Aggregate) => void> = [];
  private deferredRejecters: Array<(e: unknown) => void> = [];
  private chunks: Array<OutletStreamChunk | Error | null> = [];
  private chunkReaders: Array<(val: OutletStreamChunk | Error | null) => void> = [];

  constructor(pump: (sink: InvocationHandleSink) => void) {
    const sink: InvocationHandleSink = {
      chunk: (c) => this.enqueueChunk(c),
      end: (aggregate) => {
        // Synthesize an `end` chunk and finish.
        const endChunk: OutletStreamChunk = {
          requestId: new Uint8Array(16),
          sequence: this.chunks.length,
          payloadType: "end",
          aggregate: aggregate.value,
          ...(aggregate.provenance !== undefined && { provenance: aggregate.provenance }),
          ...(aggregate.executionTimeMs !== undefined && {
            executionTimeMs: aggregate.executionTimeMs,
          }),
        };
        this.enqueueChunk(endChunk);
        this.enqueueChunk(null);
        this.resolved = aggregate;
        for (const r of this.deferredResolvers) r(aggregate);
        this.deferredResolvers = [];
      },
      error: (err) => {
        this.rejected = err;
        this.enqueueChunk(err instanceof Error ? err : new Error(String(err)));
        this.enqueueChunk(null);
        for (const r of this.deferredRejecters) r(err);
        this.deferredRejecters = [];
      },
    };
    pump(sink);
  }

  private enqueueChunk(c: OutletStreamChunk | Error | null): void {
    const reader = this.chunkReaders.shift();
    if (reader) {
      reader(c);
    } else {
      this.chunks.push(c);
    }
  }

  private guard(mode: "aggregate" | "stream"): void {
    if (this.consumed !== null && this.consumed !== mode) {
      throw new OutletError(
        `InvocationHandle already consumed as ${this.consumed}; cannot switch to ${mode}`,
        "SCP-TOOL-6020",
      );
    }
    this.consumed = mode;
  }

  // PromiseLike: enables `await handle`. The `then` member is intentional —
  // it is what makes the class a thenable, which is load-bearing for the
  // PRD's dual-consumption API (API MAJOR 21, review item 32).
  // biome-ignore lint/suspicious/noThenProperty: intentional thenable class.
  then<TResult1 = Aggregate, TResult2 = never>(
    onfulfilled?: ((value: Aggregate) => TResult1 | PromiseLike<TResult1>) | null,
    onrejected?: ((reason: unknown) => TResult2 | PromiseLike<TResult2>) | null,
  ): PromiseLike<TResult1 | TResult2> {
    this.guard("aggregate");
    return new Promise<Aggregate>((resolve, reject) => {
      if (this.resolved !== null) resolve(this.resolved);
      else if (this.rejected !== null) reject(this.rejected);
      else {
        this.deferredResolvers.push(resolve);
        this.deferredRejecters.push(reject);
      }
    }).then(onfulfilled, onrejected);
  }

  // AsyncIterable: enables `for await (const chunk of handle)`.
  [Symbol.asyncIterator](): AsyncIterator<OutletStreamChunk> {
    this.guard("stream");
    return {
      next: () =>
        new Promise<IteratorResult<OutletStreamChunk>>((resolve, reject) => {
          const handleItem = (item: OutletStreamChunk | Error | null): void => {
            if (item === null) {
              resolve({ value: undefined, done: true });
              return;
            }
            if (item instanceof Error) {
              reject(item);
              return;
            }
            if (item.payloadType === "end") {
              resolve({ value: undefined, done: true });
              return;
            }
            resolve({ value: item, done: false });
          };
          const queued = this.chunks.shift();
          if (queued !== undefined) handleItem(queued);
          else this.chunkReaders.push(handleItem);
        }),
    };
  }
}

/** Internal sink passed to the InvocationHandle pump closure. */
interface InvocationHandleSink {
  chunk: (c: OutletStreamChunk) => void;
  end: (a: Aggregate) => void;
  error: (e: unknown) => void;
}

// ---------------------------------------------------------------------------
// invokeCrossContext options (API MAJOR 22).
// ---------------------------------------------------------------------------

export interface InvokeCrossContextOptions {
  readonly target: string;
  readonly outletId: string;
  readonly input: Readonly<Record<string, unknown>>;
  readonly ucan: string;
  readonly chainDepth?: number;
  readonly proofTokens?: readonly string[];
}

// ---------------------------------------------------------------------------
// Outlet sub-namespaces.
// ---------------------------------------------------------------------------

export class OutletOffersNamespace {
  constructor(private readonly handle: BridgeContextHandle) {}

  async propose(
    outletId: string,
    targetContextId: string,
    rateLimitJson?: string,
  ): Promise<Readonly<Record<string, unknown>>> {
    const bridge = await getBridge();
    const result = await bridge.toolInterfaceExpose(
      this.handle,
      outletId,
      targetContextId,
      rateLimitJson,
    );
    return JSON.parse(result) as Record<string, unknown>;
  }

  async accept(interfaceJson: string): Promise<Readonly<Record<string, unknown>>> {
    const bridge = await getBridge();
    const result = await bridge.toolInterfaceAccept(this.handle, interfaceJson);
    return JSON.parse(result) as Record<string, unknown>;
  }

  async revoke(interfaceIdHex: string): Promise<Readonly<Record<string, unknown>>> {
    const bridge = await getBridge();
    const result = await bridge.toolInterfaceRevoke(this.handle, interfaceIdHex);
    return JSON.parse(result) as Record<string, unknown>;
  }

  /**
   * List outbound outlet-interface offers for this context.
   *
   * The bridge does not yet surface an offer-listing endpoint
   * (offers are visible via the event log); returns an empty array as a
   * stable no-op at the SDK layer.
   */
  async list(): Promise<ReadonlyArray<Readonly<Record<string, unknown>>>> {
    return [];
  }
}

export class OutletSessionsNamespace {
  constructor(
    private readonly handle: BridgeContextHandle,
    private readonly creatorDid: string,
  ) {}

  async open(outletId: string, sourceContextId: string, ttlSeconds?: number): Promise<SessionId> {
    if (ttlSeconds !== undefined && (!Number.isInteger(ttlSeconds) || ttlSeconds < 0)) {
      throw new ValidationError(
        `ttlSeconds must be a non-negative integer, got ${ttlSeconds}`,
        "SCP-VALID-7002",
      );
    }
    const bridge = await getBridge();
    const raw = await bridge.toolSessionCreate(this.handle, outletId, sourceContextId, ttlSeconds);
    // Only validate format if the returned id matches UUIDv7; pre-OUT-040
    // stores return UUIDv4 strings which we accept transparently.
    if (UUID7_RE.test(raw)) {
      validateSessionId(raw);
    }
    return raw as SessionId;
  }

  async invoke(
    sid: SessionId,
    input: Readonly<Record<string, unknown>>,
    invokerDid: string,
    ucanToken: string,
    proofTokens?: readonly string[],
  ): Promise<ToolSessionInvokeResult> {
    if (typeof sid !== "string") {
      throw new ValidationError(
        `sessionId must be a SessionId (string), got ${typeof sid}`,
        "SCP-VALID-7010",
      );
    }
    const bridge = await getBridge();
    const output = await bridge.toolSessionInvoke(
      this.handle,
      sid,
      JSON.stringify(input),
      invokerDid,
      ucanToken,
      proofTokens,
    );
    return {
      output,
      sessionId: sid,
      contextId: this.handle.contextId,
      invokerDid,
      timestamp: Date.now(),
    };
  }

  async close(sid: SessionId): Promise<void> {
    if (typeof sid !== "string") {
      throw new ValidationError(
        `sessionId must be a SessionId (string), got ${typeof sid}`,
        "SCP-VALID-7010",
      );
    }
    const bridge = await getBridge();
    await bridge.toolSessionClose(this.handle, sid);
  }

  // Discourage use of the creatorDid field alone — satisfies TS unused-param.
  protected _creatorDid(): string {
    return this.creatorDid;
  }
}

// ---------------------------------------------------------------------------
// OutletNamespace — top-level `ctx.outlets` surface.
// ---------------------------------------------------------------------------

export class OutletNamespace {
  public readonly sessions: OutletSessionsNamespace;
  public readonly offers: OutletOffersNamespace;

  constructor(
    private readonly handle: BridgeContextHandle,
    private readonly creatorDid: string,
  ) {
    this.sessions = new OutletSessionsNamespace(handle, creatorDid);
    this.offers = new OutletOffersNamespace(handle);
  }

  /**
   * Register an outlet in the context.
   *
   * SCP-OUT-017 makes `kind` REQUIRED on `OutletDefinition`. Omitting
   * `kind` is a TypeScript compile error; the bridge re-enforces the
   * requirement as defense in depth.
   */
  async register(definition: OutletDefinition): Promise<string> {
    if (definition.kind !== "query" && definition.kind !== "action") {
      throw new ValidationError(
        `OutletDefinition.kind must be 'query' or 'action' (§5.4.2 wire vocabulary, ` +
          `SCP-OUT-017), got ${JSON.stringify(definition.kind)}`,
        "SCP-VALID-7050",
      );
    }
    const bridge = await getBridge();
    return bridge.toolRegister(this.handle, definition);
  }

  /**
   * Convenience: register an outlet with `kind: 'query'`.
   *
   * Equivalent to {@link register} with `kind` overridden to `'query'`.
   * Useful for the common path where the outlet is read-only.
   */
  async registerQuery(definition: Omit<OutletDefinition, "kind">): Promise<string> {
    return this.register({ ...definition, kind: "query" });
  }

  /**
   * Convenience: register an outlet with `kind: 'action'`.
   *
   * Equivalent to {@link register} with `kind` overridden to `'action'`.
   */
  async registerAction(definition: Omit<OutletDefinition, "kind">): Promise<string> {
    return this.register({ ...definition, kind: "action" });
  }

  /**
   * Invoke an outlet in the context.
   *
   * Returns an {@link InvocationHandle} — a single handle that is BOTH a
   * PromiseLike<Aggregate> and AsyncIterable<OutletStreamChunk>. One method,
   * two consumption styles (API MAJOR 21, review item 32).
   */
  invoke(
    outletId: string,
    input: Readonly<Record<string, unknown>>,
    options?: {
      ucanToken?: string;
      invokerDid?: string;
      proofTokens?: readonly string[];
      spendingUcan?: string;
    },
  ): InvocationHandle {
    const invokerDid = options?.invokerDid ?? this.creatorDid;
    const ucanToken = options?.ucanToken;
    const proofTokens = options?.proofTokens;
    const spendingUcan = options?.spendingUcan;
    const handle = this.handle;
    return new InvocationHandle((sink) => {
      (async () => {
        try {
          if (ucanToken === undefined) {
            throw new ValidationError(
              "ucanToken is required for ctx.outlets.invoke()",
              "SCP-VALID-7003",
            );
          }
          const bridge = await getBridge();
          const output = await bridge.toolInvoke(
            handle,
            outletId,
            JSON.stringify(input),
            invokerDid,
            ucanToken,
            proofTokens,
            spendingUcan,
          );
          // Non-streaming bridge — synthesize a single `end` with the aggregate.
          sink.end({
            value: output,
          });
        } catch (err) {
          sink.error(err);
        }
      })();
    });
  }

  async update(
    outletId: string,
    definition: OutletDefinition,
    updaterDid?: string,
  ): Promise<string> {
    const bridge = await getBridge();
    // Bridge update path (napi camelCase: contextOutletUpdate) may not be
    // surfaced on the shared Bridge shim; call via the addon when present.
    const maybeUpdate = (
      bridge as Bridge & {
        outletUpdate?: (
          h: BridgeContextHandle,
          id: string,
          def: OutletDefinition,
          updater: string,
        ) => Promise<string>;
      }
    ).outletUpdate;
    if (typeof maybeUpdate !== "function") {
      throw new OutletError(
        "outlet.update requires the NAPI/UniFFI bridge; WASM bridge has it via outletUpdate",
        "SCP-TOOL-6030",
      );
    }
    return maybeUpdate(this.handle, outletId, definition, updaterDid ?? this.creatorDid);
  }

  async get(outletId: string): Promise<Readonly<Record<string, unknown>>> {
    const bridge = await getBridge();
    const maybeGet = (
      bridge as Bridge & {
        outletGet?: (h: BridgeContextHandle, id: string) => Promise<string>;
      }
    ).outletGet;
    if (typeof maybeGet !== "function") {
      throw new OutletError(
        "outlet.get requires the outlet-expanded bridge (NAPI/UniFFI/WASM)",
        "SCP-TOOL-6031",
      );
    }
    const resultJson = await maybeGet(this.handle, outletId);
    return JSON.parse(resultJson) as Record<string, unknown>;
  }

  async list(): Promise<readonly string[]> {
    const bridge = await getBridge();
    const maybeList = (
      bridge as Bridge & {
        outletList?: (h: BridgeContextHandle) => Promise<string[]>;
      }
    ).outletList;
    if (typeof maybeList !== "function") {
      throw new OutletError(
        "outlet.list requires the outlet-expanded bridge (NAPI/UniFFI/WASM)",
        "SCP-TOOL-6032",
      );
    }
    return maybeList(this.handle);
  }

  async verify(
    outletId: string,
  ): Promise<{ outletId: string; passed: boolean; failures: readonly string[] }> {
    const bridge = await getBridge();
    const result = await bridge.toolVerify(this.handle, outletId);
    return {
      outletId: result.toolId ?? outletId,
      passed: result.passed,
      failures: result.failures ?? [],
    };
  }

  async deregister(outletId: string, actorDid?: string): Promise<void> {
    const bridge = await getBridge();
    const maybeDereg = (
      bridge as Bridge & {
        outletDeregister?: (h: BridgeContextHandle, id: string, actor: string) => Promise<void>;
      }
    ).outletDeregister;
    if (typeof maybeDereg !== "function") {
      throw new OutletError(
        "outlet.deregister requires the outlet-expanded bridge (NAPI/UniFFI/WASM)",
        "SCP-TOOL-6033",
      );
    }
    await maybeDereg(this.handle, outletId, actorDid ?? this.creatorDid);
  }

  /**
   * Invoke an outlet in a target context (API MAJOR 22).
   *
   * Options-object form ONLY at the public surface — positional two-string
   * invocation is not exposed because `target` and `outletId` are both
   * strings and can silently swap.
   */
  async invokeCrossContext(
    options: InvokeCrossContextOptions,
  ): Promise<CrossContextInvocationResult> {
    if (
      options === null ||
      typeof options !== "object" ||
      typeof options.target !== "string" ||
      typeof options.outletId !== "string"
    ) {
      throw new ValidationError(
        "invokeCrossContext requires an options object with { target, outletId, input, ucan }",
        "SCP-VALID-7002",
      );
    }
    const chainDepth = options.chainDepth ?? 0;
    if (!Number.isInteger(chainDepth) || chainDepth < 0 || chainDepth > 255) {
      throw new ValidationError(
        `chainDepth must be an integer in range 0-255, got ${chainDepth}`,
        "SCP-VALID-7002",
      );
    }
    const bridge = await getBridge();
    // The bridge interface still uses the `toolInvokeCrossContext` name at the
    // TS-internal layer; the NAPI-facing name is `contextOutletInvokeCrossContext`.
    // Source is this handle; target is opaque — callers supply the context id.
    // Cross-context target handle shape is bridge-internal; forward the id.
    const targetHandle: BridgeContextHandle = {
      contextId: options.target,
    } as BridgeContextHandle;
    const output = await bridge.toolInvokeCrossContext(
      this.handle,
      targetHandle,
      options.outletId,
      JSON.stringify(options.input),
      this.creatorDid,
      options.ucan,
      chainDepth,
      options.proofTokens,
    );
    return {
      output,
      sourceContextId: this.handle.contextId,
      targetContextId: options.target,
      invokerDid: this.creatorDid,
      chainDepth,
      timestamp: Date.now(),
    };
  }
}

// ---------------------------------------------------------------------------
// Re-exports for public outlets surface.
// ---------------------------------------------------------------------------

export type { TestVector };
export { OutletError, OutletExecutionError };

/**
 * Constructor helper — matches the pre-rename `defineToolDefinition` API,
 * renamed for outlet vocabulary (AC2).
 *
 * SCP-OUT-017 makes `kind` REQUIRED. Omitting `kind` is a TypeScript
 * compile error.
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
  assertOutletKind(params.kind);
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

/**
 * SCP-OUT-041d catalog-rotation dwell-time validator (TypeScript SDK).
 *
 * Calls the bridge `outletCatalogRotationValidator` — pure function,
 * no context state required. Resolves with `void` on success; throws
 * the typed `OutletProtocolError` (`CatalogRotationTooFrequent`) when
 * the new registration is within the §5.4.4 round-5 24-hour dwell
 * floor of the prior.
 */
export async function outletCatalogRotationValidator(opts: {
  priorCatalog: ReadonlyArray<{ key: string; template: string }>;
  newCatalog: ReadonlyArray<{ key: string; template: string }>;
  priorAppendTimeSecs: number;
  newAppendTimeSecs: number;
}): Promise<void> {
  const { getBridge } = await import("./internal/bridge");
  const bridge = await getBridge();
  const json = await bridge.outletCatalogRotationValidator(
    JSON.stringify(opts.priorCatalog),
    JSON.stringify(opts.newCatalog),
    opts.priorAppendTimeSecs,
    opts.newAppendTimeSecs,
  );
  if (json.length === 0) {
    return;
  }
  const wire = JSON.parse(json) as Record<string, unknown>;
  throw OutletError.fromWire(wire);
}
