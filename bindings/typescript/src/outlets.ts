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

import { Ajv, type ValidateFunction } from "ajv";
import {
  Credit,
  mapBridgeError,
  OutletError,
  OutletExecutionError,
  OutletProtocolError,
  OutputError,
  StreamAlreadyClosed,
  ValidationError,
} from "./errors";
import type {
  Bridge,
  BridgeContextHandle,
  BridgeOutletInvocationStream,
  BridgeOutletStreamChunk,
} from "./internal/bridge";
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
// Aggregate-schema validation (SCP-OUT-038 AC12).
// ---------------------------------------------------------------------------

/**
 * Shared Ajv instance used to compile and run §5.4.5 `aggregate_schema`
 * validators on the End-chunk aggregate.
 *
 * Configured to MATCH the Python reference (`jsonschema.validate` with its
 * default checker):
 *
 * - `allErrors: false` — short-circuit on the first failure, mirroring
 *   `jsonschema`'s default single-error raise (we only surface one message).
 * - `strict: false` — `jsonschema` tolerates unknown keywords and does not
 *   reject schemas that use draft features Ajv would otherwise flag in
 *   strict mode; disabling strict mode keeps the two validators lenient in
 *   the same places.
 * - No `ajv-formats` plugin — Python's default `jsonschema` validator treats
 *   `format` as an annotation only (it does NOT assert formats unless a
 *   format-checker is explicitly attached), so we MUST NOT assert `format`
 *   either. Leaving the plugin out makes Ajv ignore `format`, matching the
 *   reference's annotation-only behavior.
 *
 * Ajv is pure JavaScript with no Node built-in dependencies, so it is
 * isomorphic and ships unchanged in the browser/WASM bundle.
 */
const aggregateAjv = new Ajv({ allErrors: false, strict: false });

/**
 * Compiled-validator cache keyed by the bound schema object. `validateAggregate`
 * runs on EVERY End chunk; compiling once per schema (not per chunk) keeps the
 * receive path cheap. A `WeakMap` lets the compiled validator be collected when
 * the schema object itself is released.
 */
const aggregateValidatorCache = new WeakMap<object, ValidateFunction>();

/** Returns the cached compiled validator for `schema`, compiling on first use. */
function compiledAggregateValidator(schema: object): ValidateFunction {
  const cached = aggregateValidatorCache.get(schema);
  if (cached !== undefined) {
    return cached;
  }
  const validate = aggregateAjv.compile(schema);
  aggregateValidatorCache.set(schema, validate);
  return validate;
}

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
 *   yields chunks as they arrive (including the terminal `end` chunk per
 *   SCP-OUT-038 AC14: 10 Data + End ⇒ 11 chunks observed).
 *
 * The two styles are mutually exclusive per handle; once one is chosen, the
 * other throws `OutletError`.
 *
 * SCP-OUT-038 control plane (AC2-3): every handle exposes
 * `grantCredit(grant: Credit)` and `cancel()`. When the handle was opened
 * against the §5.4.5 streaming bridge it carries a real `requestIdHex` and
 * the control-plane methods route to the bridge. When the handle wraps a
 * degenerate single-shot invocation (no streaming bridge open), the
 * synthesized `End` chunk arrives synchronously so the handle is
 * pre-terminated and `grantCredit` / `cancel` raise
 * {@link StreamAlreadyClosed} per AC13.
 *
 * Lifecycle guard (AC13): once a terminal chunk (`End` or
 * `Error{terminal: true}`) is observed via the iterator OR the await
 * path, subsequent `grantCredit` / `cancel` calls raise
 * {@link StreamAlreadyClosed}.
 */
export class InvocationHandle
  implements PromiseLike<Aggregate>, AsyncIterable<OutletStreamChunk>, AsyncDisposable
{
  private consumed: "aggregate" | "stream" | null = null;
  private resolved: Aggregate | null = null;
  private rejected: unknown = null;
  private deferredResolvers: Array<(a: Aggregate) => void> = [];
  private deferredRejecters: Array<(e: unknown) => void> = [];
  private chunks: Array<OutletStreamChunk | Error | null> = [];
  private chunkReaders: Array<(val: OutletStreamChunk | Error | null) => void> = [];

  /** §5.4.5 16-byte `request_id` rendered as 32-char lowercase hex.
   * `null` for handles backed by the non-streaming bridge. */
  private requestIdHex: string | null;

  /** Promise that resolves once the streaming bridge open completes
   *  and `requestIdHex` is known. Resolves to `null` for the
   *  non-streaming (degenerate single-shot) path. `undefined` when no
   *  promise was attached (legacy callers).
   *
   *  This replaces the prior `Promise.resolve().then(...)` patch hack:
   *  the previous code set `requestIdHex` in the next microtask but the
   *  bridge `await` resolved later, so `captured` was still `null` when
   *  the patch ran and `grantCredit` always threw `StreamAlreadyClosed`.
   *  Storing a real promise that the streaming open closure resolves
   *  closes the race deterministically. */
  private readonly requestIdPromise: Promise<string | null> | undefined;

  /** Optional aggregate-schema for End-chunk validation (AC12). */
  private readonly aggregateSchema: Readonly<Record<string, unknown>> | null;

  /** True once a terminal chunk has been observed (AC13). */
  private terminated = false;

  /** True once {@link close} has run (idempotency latch). */
  private closed = false;

  /** Teardown closures run exactly once by {@link close}. The streaming
   *  factory registers an `AbortController.abort()` here so an unconsumed
   *  handle can stop the §5.4.5 revocation re-check loop deterministically.
   *  Empty for the degenerate single-shot path (no background work). */
  private closeHandlers: Array<() => void> = [];

  /** Pinned invoker DID; threaded through to every control-plane
   *  bridge call as `callerDid` so the bridge can verify against its
   *  registry's pinned identity. CRITICAL #1 fix. */
  private readonly invokerDid: string | null;

  constructor(
    pump: (sink: InvocationHandleSink) => void,
    options?: {
      requestIdHex?: string;
      requestIdPromise?: Promise<string | null>;
      invokerDid?: string;
      aggregateSchema?: Readonly<Record<string, unknown>>;
    },
  ) {
    this.requestIdHex = options?.requestIdHex ?? null;
    this.requestIdPromise = options?.requestIdPromise;
    this.invokerDid = options?.invokerDid ?? null;
    this.aggregateSchema = options?.aggregateSchema ?? null;
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
        this.terminated = true;
        try {
          this.validateAggregate(aggregate.value);
        } catch (err) {
          this.rejected = err;
          for (const r of this.deferredRejecters) r(err);
          this.deferredRejecters = [];
          this.deferredResolvers = [];
          return;
        }
        this.resolved = aggregate;
        for (const r of this.deferredResolvers) r(aggregate);
        this.deferredResolvers = [];
      },
      error: (err) => {
        this.rejected = err;
        this.terminated = true;
        this.enqueueChunk(err instanceof Error ? err : new Error(String(err)));
        this.enqueueChunk(null);
        for (const r of this.deferredRejecters) r(err);
        this.deferredRejecters = [];
      },
    };
    pump(sink);
  }

  /** Opaque per-stream identifier; `null` for the degenerate single-shot
   *  path. Exposed read-only for callers that need to address the stream
   *  out-of-band (e.g. for diagnostics). */
  get requestId(): string | null {
    return this.requestIdHex;
  }

  /** Internal — caches the resolved streaming `request_id` so the
   *  synchronous {@link close} can address the runtime session for its
   *  best-effort cancel even when no `grantCredit` / `cancel` ran first.
   *  The streaming factory calls this the instant the bridge open yields a
   *  request id. No-op once a value is pinned (the id never changes). */
  setRequestIdHex(ridHex: string): void {
    if (this.requestIdHex === null) {
      this.requestIdHex = ridHex;
    }
  }

  /** True once a terminal chunk has been observed (AC13). */
  get isTerminated(): boolean {
    return this.terminated;
  }

  private enqueueChunk(c: OutletStreamChunk | Error | null): void {
    if (c !== null && !(c instanceof Error)) {
      const isTerminalChunk =
        c.payloadType === "end" || (c.payloadType === "error" && c.terminal === true);
      if (isTerminalChunk) {
        this.terminated = true;
      }
    }
    const reader = this.chunkReaders.shift();
    if (reader) {
      reader(c);
    } else {
      this.chunks.push(c);
    }
  }

  private guard(mode: "aggregate" | "stream"): void {
    if (this.consumed !== null && this.consumed !== mode) {
      // Dual-consumption guard — a handle backed by a single underlying
      // source cannot be drained as BOTH `await handle` (aggregate) and
      // `for await … of handle` (stream). The cross-SDK convergence
      // target (Kotlin reference, OUT-038 AC13 lifecycle-under-Protocol)
      // is the Protocol-class shape: code `SCP-TOOL-6020`, slug
      // `protocol.handle-double-consumed`.
      throw new OutletProtocolError(
        `InvocationHandle already consumed as ${this.consumed}; cannot switch to ${mode}`,
        "SCP-TOOL-6020",
        { slug: "protocol.handle-double-consumed", retry: { policy: "never" } },
      );
    }
    this.consumed = mode;
  }

  /**
   * Validates a candidate End.aggregate against the registered
   * `aggregate_schema` (SCP-OUT-038 AC12). No-op when no schema is bound
   * to the handle (matches the Python reference's
   * `if schema is None: return`).
   *
   * Runs the FULL JSON-schema validator via {@link aggregateAjv}, the same
   * coverage the Python reference gets from `jsonschema.validate`. The
   * compiled validator is cached per schema object (see
   * {@link compiledAggregateValidator}) so compilation happens once, not on
   * every End chunk.
   *
   * On failure: throws {@link OutputError} with code `SCP-TOOL-6140` and a
   * message matching Python's shape (`End.aggregate does not match
   * aggregate_schema: …`). A `null` aggregate against a bound schema is
   * rejected the same way the reference does — `null` is fed to the
   * validator, which fails unless the schema admits `null`.
   */
  private validateAggregate(value: unknown): void {
    if (this.aggregateSchema === null) {
      return;
    }
    const validate = compiledAggregateValidator(this.aggregateSchema);
    // `undefined` is not a JSON value — normalize to `null` so the schema
    // engine evaluates the same instance the wire would have carried.
    const instance = value === undefined ? null : value;
    if (!validate(instance)) {
      throw new OutputError(
        `End.aggregate does not match aggregate_schema: ${aggregateAjv.errorsText(validate.errors)}`,
        "SCP-TOOL-6140",
      );
    }
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

  // AsyncIterable: enables `for await (const chunk of handle)`. Per
  // SCP-OUT-038 AC14 the iterator yields the terminal `end` chunk
  // (10 Data + End ⇒ 11 chunks observed).
  /**
   * Resolve one iterator step from a dequeued channel item. Returns the
   * {@link IteratorResult} to hand back, or throws the error the iterator
   * must reject with. Extracted from the {@link Symbol.asyncIterator}
   * closure to keep that closure's cognitive complexity in budget.
   *
   * `state.endYielded` carries the per-iterator terminal-observation flag
   * by reference so this method can flip it on End / terminal Error.
   */
  private iteratorStep(
    item: OutletStreamChunk | Error | null,
    state: { endYielded: boolean },
  ): IteratorResult<OutletStreamChunk> {
    if (item === null) {
      // Clean end-of-iteration vs. abnormal closure (mirrors the Python
      // `__anext__` contract exactly):
      // - terminal chunk already yielded ⇒ this `null` is the normal
      //   end-of-queue marker ⇒ done.
      // - otherwise the bridge receiver closed without the executor ever
      //   emitting a terminal chunk ⇒ surface `SCP-TOOL-6131` (no slug)
      //   so the caller sees a real error, not silent completion.
      if (state.endYielded) {
        return { value: undefined, done: true };
      }
      throw new OutletExecutionError("stream closed without terminal chunk", "SCP-TOOL-6131");
    }
    if (item instanceof Error) {
      throw item;
    }
    // AC14: yield End as a chunk; subsequent next() resolves done.
    if (item.payloadType === "end") {
      state.endYielded = true;
      this.validateAggregate(item.aggregate);
      return { value: item, done: false };
    }
    if (item.payloadType === "error" && item.terminal === true) {
      state.endYielded = true;
    }
    return { value: item, done: false };
  }

  [Symbol.asyncIterator](): AsyncIterator<OutletStreamChunk> {
    this.guard("stream");
    const state = { endYielded: false };
    return {
      next: () =>
        new Promise<IteratorResult<OutletStreamChunk>>((resolve, reject) => {
          if (state.endYielded) {
            resolve({ value: undefined, done: true });
            return;
          }
          const handleItem = (item: OutletStreamChunk | Error | null): void => {
            try {
              resolve(this.iteratorStep(item, state));
            } catch (err) {
              reject(err);
            }
          };
          const queued = this.chunks.shift();
          if (queued !== undefined) handleItem(queued);
          else this.chunkReaders.push(handleItem);
        }),
    };
  }

  /**
   * SCP-OUT-038 AC2/AC3 — issues an additional credit grant for the stream.
   *
   * The argument MUST be a typed {@link Credit} value; `tsc` rejects a
   * raw `number` at the type level (the {@link Credit} factory enforces
   * the runtime range check too, throwing {@link InvalidGrant} for
   * `raw <= 0` or `raw > 2^32 - 1`).
   *
   * @throws {@link StreamAlreadyClosed} (AC13) when the stream has
   *   already emitted a terminal chunk.
   */
  async grantCredit(grant: Credit): Promise<number> {
    // Real runtime check — Credit is now a class, so `instanceof` is a
    // load-bearing guard that rejects raw integers reaching the bridge.
    if (!(grant instanceof Credit)) {
      throw new ValidationError(
        `grantCredit requires a typed Credit; pass Credit.of(n) or new Credit(n) to wrap a raw number`,
        "SCP-VALID-7060",
      );
    }
    // Resolve the request id BEFORE the terminal/null check — the
    // streaming-mode constructor stores a `requestIdPromise` that
    // resolves once the bridge open completes. Awaiting first lets a
    // caller invoke `grantCredit` immediately after `invoke()` returns
    // without racing the bridge's first chunk.
    const ridHex = await this.resolveRequestId();
    // Race-check terminated AFTER the await — a terminal chunk may
    // have arrived while we were waiting on the bridge open.
    if (this.terminated) {
      throw new StreamAlreadyClosed(
        "grantCredit rejected: stream has already emitted a terminal chunk",
      );
    }
    if (ridHex === null) {
      throw new StreamAlreadyClosed(
        "grantCredit rejected: handle was opened without a streaming session " +
          "(degenerate single-shot invoke; the End chunk arrived synchronously)",
      );
    }
    if (this.invokerDid === null) {
      throw new StreamAlreadyClosed(
        "grantCredit rejected: handle has no pinned invoker DID — bridge " +
          "caller authentication unavailable",
      );
    }
    const bridge = await getBridge();
    // The runtime is authoritative for the grant-after-close lifecycle
    // violation: a grant that races the pump's terminal exit (local
    // `terminated` still false above) reaches the bridge, which rejects with
    // `SCP-TOOL-6101`. `mapBridgeError` routes that code onto the same typed
    // `StreamAlreadyClosed` the SDK raises locally, so callers see one error
    // type regardless of which side observed the close first.
    try {
      return await bridge.outletStreamGrantCredit(ridHex, this.invokerDid, grant.raw);
    } catch (error) {
      throw mapBridgeError(error);
    }
  }

  /** Internal — resolves to the streaming `request_id` (32-char hex)
   *  or `null` for the non-streaming path. Prefers the synchronous
   *  field when set; otherwise awaits the promise the streaming-mode
   *  constructor attached. */
  private async resolveRequestId(): Promise<string | null> {
    if (this.requestIdHex !== null) {
      return this.requestIdHex;
    }
    if (this.requestIdPromise !== undefined) {
      const resolved = await this.requestIdPromise;
      // Cache the resolved value for subsequent calls.
      if (resolved !== null) {
        this.requestIdHex = resolved;
      }
      return resolved;
    }
    return null;
  }

  /**
   * SCP-OUT-038 AC2/AC3 — cancels the active stream (§5.4.5 cancel-ack).
   *
   * @returns the recorded cancel-ack sequence, or `null` when the stream
   *   had already terminated at the moment the cancel reached the runtime
   *   (idempotent per §5.4.5).
   * @throws {@link StreamAlreadyClosed} (AC13) when the stream has
   *   already emitted a terminal chunk.
   */
  async cancel(): Promise<number | null> {
    // Mirror `grantCredit` — resolve the request id (awaiting the
    // streaming-mode bridge open if necessary), THEN race-check
    // terminated state.
    //
    // CRITICAL #3: caller-supplied `nextSeq` is removed. The bridge
    // derives the canonical next-emission cursor from runtime state.
    const ridHex = await this.resolveRequestId();
    if (this.terminated) {
      throw new StreamAlreadyClosed("cancel rejected: stream has already emitted a terminal chunk");
    }
    if (ridHex === null) {
      throw new StreamAlreadyClosed(
        "cancel rejected: handle was opened without a streaming session " +
          "(degenerate single-shot invoke; the End chunk arrived synchronously)",
      );
    }
    if (this.invokerDid === null) {
      throw new StreamAlreadyClosed(
        "cancel rejected: handle has no pinned invoker DID — bridge " +
          "caller authentication unavailable",
      );
    }
    const bridge = await getBridge();
    // See `grantCredit`: the runtime is authoritative for the
    // grant/cancel-after-close lifecycle violation. A cancel that races the
    // pump's terminal exit reaches the bridge, which rejects with
    // `SCP-TOOL-6101`; `mapBridgeError` routes it onto the typed
    // `StreamAlreadyClosed`.
    try {
      return await bridge.outletStreamCancel(ridHex, this.invokerDid);
    } catch (error) {
      throw mapBridgeError(error);
    }
  }

  /**
   * Registers a teardown closure run by {@link close} (and only by
   * {@link close}). The streaming factory registers the §5.4.5
   * revocation re-check loop's `AbortController.abort()` here. If the
   * handle is already closed the closure fires immediately so a late
   * registration cannot leak. Internal — only the SDK's own factory wires
   * teardown.
   */
  registerCloseHandler(handler: () => void): void {
    if (this.closed) {
      handler();
      return;
    }
    this.closeHandlers.push(handler);
  }

  /**
   * Releases the handle's background work — for a streaming handle, the
   * §5.4.5 receiver-side revocation re-check loop AND the eager chunk pump.
   * Idempotent: the first call marks the handle terminated and runs each
   * registered teardown exactly once; later calls are no-ops.
   *
   * After `close()` the control-plane methods (`grantCredit` / `cancel`)
   * throw {@link StreamAlreadyClosed} because the terminal flag is set.
   *
   * A control-plane-only caller — one that opens a streaming handle, calls
   * `grantCredit` / `cancel`, then abandons it WITHOUT consuming the chunk
   * stream — MUST call `close()` (idiomatically via `await using handle =
   * ctx.outlets.invoke(...)`). For an UNBOUNDED stream the detached recheck
   * IIFE polls `ucanValidate` until the handle is terminated AND the eager
   * chunk pump loops `await stream.next()` for the process lifetime, growing
   * `this.chunks` without bound; without `close()` (or a terminal chunk) both
   * run forever. `close()` aborts the pump (its loop checks the registered
   * `pumpAbort` signal after each `await`), aborts the recheck loop, and
   * best-effort cancels the runtime stream session so the bridge stops
   * producing chunks. Consuming the stream to its terminal chunk already
   * terminates the handle, so calling `close()` afterward is a harmless
   * no-op. Mirrors the Swift `close()` / `defer`, the Kotlin `close()` /
   * `use {}`, and the Python `aclose()` / `async with` teardown idioms.
   *
   * Awaiters parity (Finding 2): a caller doing `handle.close(); await
   * handle;` (or `await using` then awaiting the aggregate) must ERROR
   * cleanly, never hang. When `close()` runs before any terminal outcome was
   * produced it settles the consumption channels — pending aggregate
   * awaiters reject with {@link StreamAlreadyClosed} and any waiting
   * async-iterator reader is unblocked via the abnormal-closure sentinel —
   * matching Swift, which rejects the aggregate continuation on close.
   */
  close(): void {
    if (this.closed) {
      return;
    }
    // Capture whether a terminal chunk had already been observed BEFORE we
    // flip the terminated latch. A handle that completed normally (its End /
    // terminal Error already arrived) must NOT be cancelled again — the
    // runtime session is gone and `cancel()` would double-cancel. Only an
    // abandoned, still-live stream needs the best-effort runtime cancel.
    const wasTerminal = this.terminated;
    this.closed = true;
    this.terminated = true;

    // Settle the consumption channels so `await handle` / `for await` after
    // close resolve deterministically instead of hanging. Only settle when no
    // terminal outcome was produced — a normal completion already settled
    // them via the End/Error sink path.
    if (!wasTerminal && this.resolved === null && this.rejected === null) {
      const closedErr = new StreamAlreadyClosed(
        "handle closed before the stream produced a terminal chunk",
      );
      this.rejected = closedErr;
      for (const r of this.deferredRejecters) r(closedErr);
      this.deferredRejecters = [];
      this.deferredResolvers = [];
      // Push the abnormal-closure sentinel so a waiting `for await` reader
      // exits through `iteratorStep`'s no-terminal-chunk path (SCP-TOOL-6131)
      // rather than blocking forever.
      this.enqueueChunk(null);
    }

    // Best-effort release of the runtime stream session for an abandoned,
    // still-live stream. Routed through the existing cancel control-plane
    // verb — closing an unconsumed stream is exactly "tell the runtime to
    // stop". Skipped when the stream had already terminated (no live session)
    // or when the handle never opened a streaming session (degenerate
    // single-shot path, or no pinned invoker DID to authenticate the cancel).
    if (!wasTerminal && this.requestIdHex !== null && this.invokerDid !== null) {
      const ridHex = this.requestIdHex;
      const callerDid = this.invokerDid;
      void (async () => {
        try {
          const bridge = await getBridge();
          await bridge.outletStreamCancel(ridHex, callerDid);
        } catch {
          // Best-effort — AlreadyTerminated / transport drop are fine; the
          // stream has left the runtime control plane either way.
        }
      })();
    }

    const handlers = this.closeHandlers;
    this.closeHandlers = [];
    for (const handler of handlers) {
      handler();
    }
  }

  /**
   * Explicit-resource-management hook — enables
   * `await using handle = ctx.outlets.invoke(...)`. Delegates to
   * {@link close} so an unconsumed streaming handle's revocation re-check
   * loop is released at block exit. `async` to satisfy the
   * `AsyncDisposable` contract even though `close()` itself is synchronous.
   */
  async [Symbol.asyncDispose](): Promise<void> {
    this.close();
  }
}

/** Internal sink passed to the InvocationHandle pump closure. */
interface InvocationHandleSink {
  chunk: (c: OutletStreamChunk) => void;
  end: (a: Aggregate) => void;
  error: (e: unknown) => void;
}

/**
 * Internal helper: pump a {@link BridgeOutletInvocationStream} into an
 * {@link InvocationHandleSink}. Reads chunks from the bridge's
 * `next()` until the stream emits `null` (end of stream) or a terminal
 * chunk. Translates each {@link BridgeOutletStreamChunk} to the
 * SDK-shaped {@link OutletStreamChunk} variant.
 *
 * Used by `OutletNamespace.invoke()` when streaming-mode is engaged
 * (a `caveatsBinding` + `streamEpoch` pair was supplied). Internal —
 * not part of the public surface (SCP-OUT-038 AC1: ONE public verb).
 *
 * Abnormal-closure handling: if the bridge receiver returns `null`
 * BEFORE a terminal chunk (`End` / `Error{terminal: true}`) was
 * observed, the SDK surfaces an {@link OutletExecutionError} with code
 * `SCP-TOOL-6131` and NO slug per §5.4.4 — synthesising a degenerate
 * `End{value: null}` would mask a transport drop, executor crash, or
 * bridge fault as a successful aggregate-null outcome. The code matches
 * the abnormal-closure error every SDK emits on the consumer side
 * (Python / Swift / Kotlin); none of them attaches a slug, since the
 * spec registers no slug for this condition.
 */
async function pumpStreamingBridge(
  stream: BridgeOutletInvocationStream,
  sink: InvocationHandleSink,
  pumpSignal: AbortSignal,
): Promise<void> {
  let terminalObserved = false;
  try {
    while (true) {
      if (pumpSignal.aborted) {
        // `close()` aborted the handle — stop polling the bridge so an
        // unconsumed control-plane-only handle does not loop `stream.next()`
        // (and grow the handle's chunk buffer) for the process lifetime. The
        // runtime session is released separately by `close()`'s best-effort
        // `outletStreamCancel`. Settle the IIFE without emitting anything:
        // `close()` already settled the consumption channels.
        return;
      }
      const chunk: BridgeOutletStreamChunk | null = await stream.next();
      // Re-check after the await — the abort may have fired while the bridge
      // call was in flight.
      if (pumpSignal.aborted) {
        return;
      }
      if (chunk === null) {
        if (!terminalObserved) {
          // Abnormal closure — the bridge receiver closed without the
          // executor emitting a terminal chunk. Surface as an
          // OutletExecutionError (SCP-TOOL-6131, no slug) instead of
          // synthesising an aggregate-null End so callers cannot
          // mistake a transport drop / executor crash for a successful
          // run that simply returned `null`.
          sink.error(
            new OutletExecutionError("stream closed without terminal chunk", "SCP-TOOL-6131"),
          );
        }
        return;
      }
      const sdkChunk = bridgeChunkToSdk(chunk);
      sink.chunk(sdkChunk);
      if (
        sdkChunk.payloadType === "end" ||
        (sdkChunk.payloadType === "error" && sdkChunk.terminal === true)
      ) {
        terminalObserved = true;
        if (sdkChunk.payloadType === "end") {
          sink.end({
            value: sdkChunk.aggregate ?? null,
            ...(sdkChunk.provenance !== undefined && { provenance: sdkChunk.provenance }),
            ...(sdkChunk.executionTimeMs !== undefined && {
              executionTimeMs: sdkChunk.executionTimeMs,
            }),
          });
        } else {
          sink.error(
            new OutletExecutionError(
              sdkChunk.message ?? "outlet stream errored",
              sdkChunk.code ?? "SCP-TOOL-6200",
            ),
          );
        }
        return;
      }
    }
  } catch (err) {
    sink.error(err);
  }
}

/**
 * Sleeps `ms` milliseconds, resolving early if `signal` aborts. Used by the
 * §5.4.5 revocation re-check loop so `InvocationHandle.close()` interrupts
 * the inter-tick wait immediately rather than letting the loop sleep up to
 * `ucanRecheckSecs` before observing termination. Always resolves (never
 * rejects) — the caller re-checks `signal.aborted` after awaiting. The
 * abort listener is removed on resolution so a long-lived signal does not
 * accumulate listeners across ticks.
 */
function sleepUnlessAborted(ms: number, signal: AbortSignal): Promise<void> {
  return new Promise<void>((resolve) => {
    if (signal.aborted) {
      resolve();
      return;
    }
    const onAbort = (): void => {
      clearTimeout(timer);
      resolve();
    };
    const timer = setTimeout(() => {
      signal.removeEventListener("abort", onAbort);
      resolve();
    }, ms);
    signal.addEventListener("abort", onAbort, { once: true });
  });
}

/** Translate a bridge-shaped chunk into the SDK-shaped variant. */
function bridgeChunkToSdk(chunk: BridgeOutletStreamChunk): OutletStreamChunk {
  const base = {
    requestId: chunk.requestId,
    sequence: chunk.sequence,
    payloadType: chunk.payloadType,
  } as const;
  switch (chunk.payloadType) {
    case "data":
      return {
        ...base,
        ...(chunk.valueJson !== undefined && {
          value: JSON.parse(chunk.valueJson) as unknown,
        }),
      };
    case "progress":
      return {
        ...base,
        ...(chunk.pct !== undefined && { pct: chunk.pct }),
        ...(chunk.note !== undefined && { note: chunk.note }),
      };
    case "end":
      return {
        ...base,
        ...(chunk.aggregateJson !== undefined && {
          aggregate: JSON.parse(chunk.aggregateJson) as unknown,
        }),
        ...(chunk.provenanceJson !== undefined && {
          provenance: JSON.parse(chunk.provenanceJson) as Readonly<Record<string, unknown>>,
        }),
        ...(chunk.executionTimeMs !== undefined && { executionTimeMs: chunk.executionTimeMs }),
      };
    case "error":
      return {
        ...base,
        ...(chunk.code !== undefined && { code: chunk.code }),
        ...(chunk.message !== undefined && { message: chunk.message }),
        ...(chunk.terminal !== undefined && { terminal: chunk.terminal }),
      };
  }
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
   * Invoke an outlet in the context — the ONE public verb (SCP-OUT-038 AC1).
   *
   * Returns an {@link InvocationHandle} — a single handle that is BOTH a
   * PromiseLike<Aggregate> and AsyncIterable<OutletStreamChunk>. One method,
   * two consumption styles (API MAJOR 21, review item 32). The handle also
   * exposes {@link InvocationHandle.grantCredit} /
   * {@link InvocationHandle.cancel} control-plane methods (AC2-3).
   *
   * When `caveatsBinding` AND `streamEpoch` are supplied, opens a real
   * §5.4.5 streaming session via the `contextOutletInvokeStream` bridge
   * — the returned handle carries a real `request_id` and grant_credit /
   * cancel route to the runtime. When omitted, falls back to the
   * non-streaming bridge (degenerate single-chunk per §5.4.5) and the
   * handle's lifecycle ends synchronously — control-plane methods then
   * raise {@link StreamAlreadyClosed} per AC13.
   */
  invoke(
    outletId: string,
    input: Readonly<Record<string, unknown>>,
    options?: {
      ucanToken?: string;
      invokerDid?: string;
      proofTokens?: readonly string[];
      spendingUcan?: string;
      /** 32-byte SHA-256 over the §5.4.5 `SCP-OUTLET-CAVEAT-BIND-V1:`
       * preimage. When supplied (with `streamEpoch`), opens a real
       * streaming session. */
      caveatsBinding?: Uint8Array;
      /** Hosting context's MLS epoch counter at acceptance — required
       * when `caveatsBinding` is set. */
      streamEpoch?: number;
      /** Initial credit-window override; defaults to §5.4.5
       * `DEFAULT_CREDIT_WINDOW` (32). Streaming-mode only. */
      creditWindow?: number;
      /** Invoker-declared upper bound on billable Data chunks.
       * Streaming-mode only. */
      estimatedChunkCount?: number;
      /** Optional JSON Schema for the End chunk's `aggregate` value
       * (§5.4.5). When supplied, the handle validates the End chunk's
       * aggregate against this schema before resolving the awaitable
       * (AC12). */
      aggregateSchema?: Readonly<Record<string, unknown>>;
      /** Period (seconds) for the receiver-side framework to re-check
       * the opening UCAN's revocation status during the lifetime of
       * an active stream (§5.4.5 receiver-side revocation re-check).
       * On observed revocation the stream closes with
       * `RevokedMidStream` (SCP-TOOL-6110). Default 10, range
       * `[1, 60]`. Streaming-mode only. */
      ucanRecheckSecs?: number;
    },
  ): InvocationHandle {
    const invokerDid = options?.invokerDid ?? this.creatorDid;
    const ucanToken = options?.ucanToken;
    const proofTokens = options?.proofTokens;
    const spendingUcan = options?.spendingUcan;
    const caveatsBinding = options?.caveatsBinding;
    const streamEpoch = options?.streamEpoch;
    const creditWindow = options?.creditWindow;
    const estimatedChunkCount = options?.estimatedChunkCount;
    const aggregateSchema = options?.aggregateSchema;
    const handle = this.handle;

    // Streaming mode requires BOTH caveatsBinding and streamEpoch.
    if (
      (caveatsBinding !== undefined && streamEpoch === undefined) ||
      (caveatsBinding === undefined && streamEpoch !== undefined)
    ) {
      throw new ValidationError(
        "streaming-mode invoke requires BOTH caveatsBinding (32 bytes) and streamEpoch; " +
          "pass them together or omit both for the degenerate single-shot path",
        "SCP-VALID-7002",
      );
    }
    if (caveatsBinding !== undefined && caveatsBinding.byteLength !== 32) {
      throw new ValidationError(
        `caveatsBinding must be exactly 32 bytes, got ${caveatsBinding.byteLength}`,
        "SCP-VALID-7000",
      );
    }

    // Streaming-mode path — open a real §5.4.5 session.
    if (caveatsBinding !== undefined && streamEpoch !== undefined) {
      if (ucanToken === undefined) {
        throw new ValidationError(
          "streaming-mode invoke requires ucanToken (the bridge re-runs the " +
            "11-step ADR-016 pipeline at open)",
          "SCP-VALID-7002",
        );
      }
      const caveatsBindingHex = bytesToHexString(caveatsBinding);
      // Resolver pair for the request-id promise. The streaming open
      // closure resolves it as soon as the bridge yields its
      // synchronously-known request_id; `grantCredit` / `cancel` await
      // this promise before reading `requestIdHex`. This replaces a
      // prior microtask hack that read `captured` synchronously and
      // saw `null` because the bridge `await` had not yet resolved.
      let resolveRid: (value: string | null) => void = () => {
        /* assigned below */
      };
      let rejectRid: (err: unknown) => void = () => {
        /* assigned below */
      };
      const requestIdPromise = new Promise<string | null>((resolve, reject) => {
        resolveRid = resolve;
        rejectRid = reject;
      });
      // Swallow rejections so an unobserved promise does not surface
      // as an unhandled-rejection warning. `grantCredit` / `cancel`
      // will surface the rejection via the await path; aggregate /
      // iterator paths surface the error through the pump's `sink.error`.
      requestIdPromise.catch(() => {
        /* observed lazily by control-plane methods */
      });
      // AbortController for the eager chunk pump. `close()` aborts it so an
      // unconsumed control-plane-only handle stops polling `stream.next()`
      // (and stops growing the handle's chunk buffer) immediately rather than
      // looping for the process lifetime. Distinct from the recheck loop's
      // `recheckAbort` below, though both fire on the same `close()`.
      const pumpAbort = new AbortController();
      const handleFactory = (sink: InvocationHandleSink): void => {
        (async () => {
          try {
            const bridge = await getBridge();
            const stream = await bridge.contextOutletInvokeStream(
              handle,
              outletId,
              JSON.stringify(input),
              invokerDid,
              ucanToken,
              caveatsBindingHex,
              streamEpoch,
              proofTokens,
              creditWindow,
              estimatedChunkCount,
              spendingUcan,
            );
            // Resolve the request-id promise before we start pumping
            // chunks — control-plane methods that raced to grantCredit
            // immediately after `invoke()` will now unblock with a
            // valid request id rather than a stale `null`. Also pin the id on
            // the handle so the synchronous `close()` can address the runtime
            // session for its best-effort cancel even with no prior
            // `grantCredit` / `cancel`.
            resolveRid(stream.requestId);
            sdkHandle.setRequestIdHex(stream.requestId);
            await pumpStreamingBridge(stream, sink, pumpAbort.signal);
          } catch (err) {
            // Surface the open failure on BOTH paths: control-plane
            // (via the request-id promise) and the chunk pump.
            rejectRid(err);
            sink.error(err);
          }
        })();
      };
      const sdkHandle = new InvocationHandle(handleFactory, {
        requestIdPromise,
        invokerDid,
        ...(aggregateSchema !== undefined && { aggregateSchema }),
      });
      // `close()` (and `[Symbol.asyncDispose]`) abort the chunk pump.
      sdkHandle.registerCloseHandler(() => pumpAbort.abort());

      // §5.4.5 receiver-side revocation re-check (RevokedMidStream /
      // SCP-TOOL-6110). Per spec the SDK framework MUST periodically
      // re-check the opening UCAN's revocation status during the
      // stream's active lifetime, every `stream_ucan_recheck_secs`,
      // and on observed revocation MUST terminate the stream.
      //
      // Re-validates the UCAN against the same context — a token
      // revoked since open surfaces as a UcanError from the bridge's
      // 11-step pipeline (Step 10 revocation check). The recheck loop
      // calls `bridge.outletStreamTerminate` which routes through
      // `StreamSessionHandle::terminate_with_error` on the runtime and
      // emits a synthetic terminal Error chunk under the pinned operator
      // key. Already-emitted chunks remain authorized; the stream
      // closes at or before `ucanRecheckSecs` after the revocation
      // event regardless of executor behavior.
      const ucanRecheckSecs = options?.ucanRecheckSecs ?? 10;
      const capability = `tool_invoke:${outletId}`;
      // AbortController lets `close()` stop the recheck loop PROMPTLY — it
      // both flips the loop's guard (via `signal.aborted`) and interrupts
      // the in-flight `setTimeout` sleep, so a control-plane-only caller
      // that `close()`s an UNBOUNDED handle does not wait up to
      // `ucanRecheckSecs` for the next tick. Registered on the handle so
      // `close()` (and `[Symbol.asyncDispose]`) trigger it.
      const recheckAbort = new AbortController();
      sdkHandle.registerCloseHandler(() => recheckAbort.abort());
      void (async () => {
        try {
          const rid = await requestIdPromise;
          if (rid === null) {
            return;
          }
          const bridge = await getBridge();
          while (!sdkHandle.isTerminated && !recheckAbort.signal.aborted) {
            await sleepUnlessAborted(Math.max(1, ucanRecheckSecs) * 1000, recheckAbort.signal);
            if (sdkHandle.isTerminated || recheckAbort.signal.aborted) {
              break;
            }
            try {
              await bridge.ucanValidate(handle, ucanToken, capability);
            } catch {
              // Any UcanError signals the token is no longer
              // valid — terminate with the spec's RevokedMidStream
              // slug + code. Bridge surfaces revocation as
              // UcanError; treat the broader UcanError class as
              // sufficient signal so expired/malformed tokens that
              // also indicate "no longer authorized" close the
              // stream too.
              try {
                // The bridge accepts a closed-set
                // `TerminateReasonSlug` and derives the §5.4.4 code
                // from it; the message extension is the only caller-
                // supplied human text.
                await bridge.outletStreamTerminate(
                  rid,
                  invokerDid,
                  "authorization.revoked-mid-stream",
                  "ucan revoked or invalid mid-stream",
                );
              } catch {
                // Terminate is recoverable from the SDK's
                // perspective — AlreadyTerminated/AlreadyPending
                // mean the stream has already left the runtime
                // control plane. Stop the recheck loop either way.
              }
              break;
            }
          }
        } catch {
          // Open path failed; recheck has nothing to do.
        }
      })();

      return sdkHandle;
    }

    // Degenerate single-shot path — the legacy non-streaming bridge.
    if (ucanToken === undefined) {
      throw new ValidationError("ucanToken is required for ctx.outlets.invoke()", "SCP-VALID-7003");
    }
    const ucanTokenChecked = ucanToken;
    return new InvocationHandle(
      (sink) => {
        (async () => {
          try {
            const bridge = await getBridge();
            const output = await bridge.toolInvoke(
              handle,
              outletId,
              JSON.stringify(input),
              invokerDid,
              ucanTokenChecked,
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
      },
      {
        ...(aggregateSchema !== undefined && { aggregateSchema }),
      },
    );
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
// Internal test surface — exported under an underscore-prefixed name so the
// abnormal-closure test in `tests/invocation-handle-streaming.test.ts` can
// drive `pumpStreamingBridge` against a synthetic `BridgeOutletInvocationStream`.
// Not part of the public SDK API.
export {
  type InvocationHandleSink as __InternalInvocationHandleSink,
  OutletError,
  OutletExecutionError,
  pumpStreamingBridge as __internalPumpStreamingBridge,
};

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
 * Internal — render a `Uint8Array` to lowercase hex.
 */
function bytesToHexString(bytes: Uint8Array): string {
  let out = "";
  for (let i = 0; i < bytes.length; i++) {
    const b = bytes[i] ?? 0;
    out += b.toString(16).padStart(2, "0");
  }
  return out;
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
