/**
 * Mock native `SCP` handle factory for integration testing.
 *
 * After Phase 4 PR 4 (#1549, ADR-048), the TypeScript SDK routes every
 * stateful operation through the {@link SCP} class, which forwards
 * calls to its private `#native` handle. This module provides a
 * Proxy-backed stand-in for that handle so tests can drive the SDK
 * without loading the real `@limn-works/scp-ts-napi-*` addon.
 *
 * Strategy
 * --------
 *
 * The previous mock implemented the flat `Bridge` interface and relied
 * on `_setBridge(scp, mockBridge)` to swap in a mock. Both the flat
 * bridge indirection and the namespace-class factories were collapsed
 * in B1 — every call on a live SDK now lands on a `SCP.*` method, which
 * dispatches directly to `this.#native.methodName(...)`.
 *
 * The mock therefore needs to shadow the NAPI `Scp` class surface
 * (~181 methods + `instanceId` + `suspend`/`resume`/`shutdown`). Rather
 * than hand-rolling a full reimplementation, the factory returns a
 * `Proxy` that:
 *
 * 1. Intercepts every `get` on the fake handle.
 * 2. If the caller has configured a stub for that method name via
 *    `stub(name, fn)`, routes the call to the stub.
 * 3. Otherwise applies a strict-by-default policy:
 *    - For `instanceId`, returns a deterministic string.
 *    - For lifecycle methods in {@link SAFE_DEFAULT_METHODS}
 *      (`suspend`, `resume`, `shutdown`), returns a safe no-op — sync
 *      `undefined` for `suspend`, `Promise.resolve(undefined)` otherwise.
 *    - For every other unstubbed method, **throws** an explanatory
 *      `Error`. This prevents the silent-success failure mode flagged
 *      by cryptographer finding M-1 (a "verify succeeds" test passing
 *      trivially on `Promise.resolve(undefined)` when the method was
 *      never stubbed).
 * 4. Tests that genuinely want lenient "every method resolves to
 *    undefined" behaviour (e.g. forwarder-plumbing assertions that only
 *    inspect arguments) opt in explicitly with
 *    `createMockNativeScp({ strict: false })`. Strict remains the
 *    default so assertions that check *results* cannot silently pass
 *    on `undefined`.
 * 5. Records every invocation for test assertions (method name, args,
 *    result). Helpers `calls(name?)`, `lastCall(name)`, and `reset()`
 *    expose the recording.
 *
 * A companion helper, `mountMockScp`, constructs a real {@link SCP}
 * seeded with the mock native handle — bypassing the normal addon
 * load so tests run even when no platform `@limn-works/scp-ts-napi-*`
 * package is installed.
 *
 * See ADR-048, the Phase 4 PR 4 (#1549) B-track plan, and cryptographer
 * finding M-1 for the strict-by-default rationale.
 */

import { __constructScpWithNativeForTests, type SCP } from "../src/scp";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/** A single recorded invocation on the mock native handle. */
export interface MockCall {
  /** Method name as invoked on the proxy. */
  readonly method: string;
  /** Arguments passed to the method. */
  readonly args: readonly unknown[];
  /** Whatever the stub or default returned (may be a Promise). */
  readonly result: unknown;
}

/**
 * A function that stubs out a single method on the mock native handle.
 * The mock Proxy invokes this with `(...args)` when the matching
 * method is called; the return value is what the SDK sees.
 */
export type MockStub = (...args: readonly unknown[]) => unknown;

/**
 * A mock native `Scp` handle. Conforms structurally to the shape that
 * the TypeScript SDK's {@link SCP} class expects of its `#native`
 * field, and carries test-only inspection helpers.
 */
export interface MockNativeScp {
  // ── NAPI `Scp` surface the SDK relies on ───────────────────────────
  readonly instanceId: string;
  suspend(): void;
  resume(): Promise<void>;
  shutdown(timeoutMillis: bigint): Promise<void>;
  // Every other property access is dispatched through the Proxy. We
  // model that with an index signature so TypeScript accepts the many
  // SDK forwarder call sites (`this.#native.identityCreate`, etc).
  readonly [method: string]: unknown;

  // ── Test-inspection helpers (prefixed `__` to stay out of the way) ──

  /**
   * Configures a stub for a single method. When the SDK calls
   * `native.<name>(...args)`, the Proxy invokes `fn(...args)` and
   * returns the result verbatim. Overwrites any previous stub for
   * the same name; pass `null` to clear a stub.
   */
  __stub(name: string, fn: MockStub | null): void;

  /**
   * Returns the recorded invocations. When `method` is supplied,
   * returns only calls whose method name matches exactly; otherwise
   * returns every recorded call in order.
   */
  __calls(method?: string): readonly MockCall[];

  /** Returns the most recent recorded call matching the given method, or `undefined`. */
  __lastCall(method: string): MockCall | undefined;

  /** Clears the call log and all stubs. */
  __reset(): void;

  /**
   * Clears the call log but keeps stubs. Useful between assertions
   * in the same test when a caller wants to reuse the stub setup.
   */
  __resetCalls(): void;
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/**
 * JS runtime / Promise interop hooks. The Proxy returns `undefined`
 * for these and `has` reports them as absent so `await mock` won't
 * mistakenly follow a thenable path and `util.inspect(mock)` doesn't
 * try to spelunk through the dispatcher.
 */
const RUNTIME_HOOKS: ReadonlySet<string | symbol> = new Set<string | symbol>([
  "then",
  "catch",
  "finally",
  "constructor",
  "valueOf",
  "toString",
  "toJSON",
  "inspect",
  Symbol.toPrimitive,
  Symbol.toStringTag,
  Symbol.iterator,
  Symbol.asyncIterator,
  Symbol.for("nodejs.util.inspect.custom"),
]);

/** Methods on the NAPI `Scp` surface that are synchronous by contract. */
const SYNC_METHODS: ReadonlySet<string> = new Set<string>(["suspend"]);

/**
 * Methods where an unstubbed call is safe to treat as a no-op even in
 * strict mode. These are lifecycle operations whose void return is
 * semantically `undefined` — tests that invoke `await scp.shutdown()`
 * in an `afterEach` should not have to configure a stub just to let
 * teardown complete. Every method in this set either returns `void`
 * or `Promise<void>` on the real NAPI bridge, so a mock that resolves
 * to `undefined` cannot accidentally hide a result-dependent assertion.
 *
 * Extend with care: the whole point of strict mode is that an unstubbed
 * call with an inspectable return value throws rather than masquerading
 * as success. A method belongs here only if:
 *   - It has no meaningful return value (`void` / `Promise<void>`), and
 *   - Tests routinely invoke it for teardown / lifecycle purposes
 *     without caring about the outcome.
 */
export const SAFE_DEFAULT_METHODS: readonly string[] = Object.freeze([
  "suspend",
  "resume",
  "shutdown",
]);

const SAFE_DEFAULT_METHOD_SET: ReadonlySet<string> = new Set<string>(SAFE_DEFAULT_METHODS);

/**
 * Safe default return value for an unstubbed invocation of a
 * lifecycle method. Returns `undefined` synchronously for methods
 * whose real signatures are sync (`suspend`), and `Promise.resolve(undefined)`
 * for the async lifecycle methods.
 */
function safeDefaultReturn(method: string): unknown {
  if (SYNC_METHODS.has(method)) {
    return undefined;
  }
  return Promise.resolve(undefined);
}

/**
 * Builds the strict-mode error raised when a test invokes a method
 * on the mock handle that has no stub and is not in
 * {@link SAFE_DEFAULT_METHODS}.
 */
function unstubbedMethodError(method: string): Error {
  return new Error(
    `MockNativeScp: method \`${method}\` was called without a stub. ` +
      `Strict mode (default) rejects silent "resolved to undefined" ` +
      `returns that would let result-dependent assertions pass ` +
      `trivially (cryptographer finding M-1). Either configure a stub ` +
      `with \`handle.__stub("${method}", fn)\`, or opt out of strict ` +
      `mode for this handle with \`createMockNativeScp({ strict: false })\`.`,
  );
}

// ---------------------------------------------------------------------------
// Factory
// ---------------------------------------------------------------------------

/**
 * Options accepted by {@link createMockNativeScp}.
 */
export interface CreateMockNativeScpOptions {
  /**
   * Explicit instance id for this handle. Omit to auto-generate a
   * monotonic numeric id (matches the real NAPI class's behaviour).
   */
  readonly instanceId?: string;
  /**
   * Whether unstubbed calls throw. Defaults to `true` — the
   * strict-by-default policy introduced in response to cryptographer
   * finding M-1. Pass `false` to restore the historical "every
   * unstubbed method resolves to undefined" behaviour; useful only
   * for tests that intentionally exercise control flow through the
   * SDK without caring about any return value.
   */
  readonly strict?: boolean;
}

/**
 * Monotonic counter so each `createMockNativeScp()` returns a handle
 * with a distinct `instanceId`, matching the real NAPI class's
 * behavior and letting tests pin instances through assertions.
 */
let _nextMockInstanceId = 1;

/**
 * Builds a Proxy-backed mock native `Scp` handle.
 *
 * Strict mode (default): unstubbed method calls throw, except for the
 * lifecycle methods in {@link SAFE_DEFAULT_METHODS}
 * (`suspend` / `resume` / `shutdown`) which keep their historical
 * safe-no-op defaults because tests frequently call them for teardown.
 * Tests that assert on method *results* must configure explicit stubs;
 * this prevents "verify-succeeds" assertions from passing trivially on
 * `Promise.resolve(undefined)` when the method was never stubbed
 * (cryptographer finding M-1).
 *
 * Lenient mode (`{ strict: false }`): every unstubbed method returns
 * `Promise.resolve(undefined)` (async default) or `undefined` (sync
 * default). Provided as an explicit opt-out for tests that exercise
 * SDK control flow without inspecting return values.
 */
export function createMockNativeScp(options: CreateMockNativeScpOptions = {}): MockNativeScp {
  const stubs = new Map<string, MockStub>();
  const calls: MockCall[] = [];
  const instanceId = options.instanceId ?? String(_nextMockInstanceId++);
  const strict = options.strict ?? true;

  // The Proxy target is a plain object; we never use it directly — the
  // `get` trap owns the whole lookup path.
  const target: Record<string | symbol, unknown> = {};

  const handle = new Proxy(target, {
    get(_target, prop, _receiver): unknown {
      // Intrinsic properties bypass both stub dispatch and the call log.
      if (prop === "instanceId") {
        return instanceId;
      }
      if (prop === "__stub") {
        return (name: string, fn: MockStub | null): void => {
          if (fn === null) {
            stubs.delete(name);
            return;
          }
          stubs.set(name, fn);
        };
      }
      if (prop === "__calls") {
        return (method?: string): readonly MockCall[] =>
          method === undefined ? calls.slice() : calls.filter((c) => c.method === method);
      }
      if (prop === "__lastCall") {
        return (method: string): MockCall | undefined => {
          for (let i = calls.length - 1; i >= 0; i--) {
            const call = calls[i];
            if (call !== undefined && call.method === method) {
              return call;
            }
          }
          return undefined;
        };
      }
      if (prop === "__reset") {
        return (): void => {
          stubs.clear();
          calls.length = 0;
        };
      }
      if (prop === "__resetCalls") {
        return (): void => {
          calls.length = 0;
        };
      }
      if (RUNTIME_HOOKS.has(prop)) {
        // JS runtime / Promise interop probes — return undefined so
        // `await mock` doesn't follow a thenable path and `util.inspect`
        // doesn't recurse through the dispatcher.
        return undefined;
      }

      // Everything else is treated as a method dispatch. Symbols that
      // aren't in RUNTIME_HOOKS can't meaningfully round-trip — no
      // SDK call site uses symbol-keyed lookups on the native handle.
      if (typeof prop === "symbol") {
        return undefined;
      }

      const method = prop;
      return (...args: readonly unknown[]): unknown => {
        const stub = stubs.get(method);
        if (stub !== undefined) {
          const result = stub(...args);
          calls.push({ method, args: args.slice(), result });
          return result;
        }

        // Unstubbed dispatch — apply the strict-vs-lenient policy.
        if (strict && !SAFE_DEFAULT_METHOD_SET.has(method)) {
          // Record the call before throwing so tests that assert on
          // "method foo was called (and then threw)" can still inspect
          // the call log after catching the error.
          const err = unstubbedMethodError(method);
          calls.push({ method, args: args.slice(), result: err });
          throw err;
        }

        const result = safeDefaultReturn(method);
        calls.push({ method, args: args.slice(), result });
        return result;
      };
    },

    // Report presence for NAPI surface lookups so `'identityCreate' in
    // handle` returns `true` the way the real NAPI `Scp` class would.
    // Runtime hooks (`then`, `Symbol.toPrimitive`, etc) report absent
    // so JS runtime coercion/iteration paths don't false-match.
    has(_target, prop): boolean {
      if (RUNTIME_HOOKS.has(prop)) {
        return false;
      }
      if (typeof prop !== "string") {
        return false;
      }
      return true;
    },
  }) as unknown as MockNativeScp;

  return handle;
}

/**
 * Constructs a fresh {@link SCP} whose `#native` handle is a
 * Proxy-backed mock. Equivalent to:
 *
 * ```ts
 * const mock = createMockNativeScp();
 * const scp = __constructScpWithNativeForTests(mock);
 * ```
 *
 * plus a convenience handle returned alongside the SCP so tests can
 * configure stubs and inspect the call log.
 *
 * @param mockNativeScp Optional pre-built mock. If omitted a fresh
 *   strict-mode mock is created. Passing a caller-built mock lets tests
 *   share setup across multiple SCP instances or opt into lenient mode
 *   via `createMockNativeScp({ strict: false })`.
 */
export function mountMockScp(mockNativeScp?: MockNativeScp): {
  scp: SCP;
  native: MockNativeScp;
} {
  const native = mockNativeScp ?? createMockNativeScp();
  const scp = __constructScpWithNativeForTests(native);
  return { scp, native };
}

// `replaceNativeWithMock` removed in round-3 cleanup (BLACK-PR5-003). The
// post-construction swap via `__setNativeForTests` + a WeakMap was only
// visible to `__getNativeScp` consumers; the ~180 SCP class methods
// dispatched through `this.#native` directly and bypassed the override,
// producing silent-half-mocked state. No test used this helper; the only
// supported mock path is `mountMockScp` which mounts the mock via
// `__constructScpWithNativeForTests` at construction time so every class
// method sees it.
