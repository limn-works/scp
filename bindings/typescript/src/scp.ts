/**
 * SDK-level `SCP` class for the TypeScript SDK.
 *
 * See ADR-048 ("SCP multi-instance bridge + check-handle-affinity gate")
 * for the design rationale. Each `SCP` instance owns an independent
 * `BridgeInstance` (registries, transport, context manager), so tests,
 * multi-identity apps, and per-tenant services can hold distinct
 * instances without sharing state.
 *
 * ```ts
 * import { SCP, Identity } from "@limn-works/scp-ts";
 *
 * const scp = new SCP();                 // fresh in-memory instance
 * const identity = await Identity.create(scp);
 * await scp.resume();                    // async — reconnects transport
 * await scp.shutdown(5);                 // graceful shutdown
 *
 * // PR 3: encrypted on-disk storage (closes #1260, #1491).
 * const persistent = new SCP({
 *   storage: { type: "sqlite", path: "/var/lib/scp", key: new Uint8Array(32) },
 * });
 * ```
 *
 * PR 3 (#1549) expanded the surface in two ways:
 * - `StorageConfig` gained the `sqlite` variant, backed by SQLCipher
 *   through `scp-platform`. Closes #1260 / #1491 (encrypted filesystem
 *   storage).
 * - `resume()` became async end-to-end (#1678) — the NAPI bridge
 *   reconnects transport from pending relay URLs and restores any
 *   persisted context snapshots before the promise settles, so
 *   transport-dependent code can run immediately after `await`.
 *
 * NOTE: `SCP` is a NAPI-only feature. The WASM bridge
 * does not expose a multi-instance class surface; attempting to
 * construct `SCP` in a browser environment throws `ValidationError`
 * with `SCP-VALID-7005`.
 */

import { createRequire } from "node:module";

import { ValidationError } from "./errors";

/**
 * Shape of the native addon — a subset sufficient to describe the
 * `SCP` class and its static factories.
 */
type NativeAddon = {
  // The raw addon exports `SCP` as an opaque napi-rs class. We refine to
  // `NativeScpCtor` after a runtime `typeof` check; `unknown` keeps
  // biome's `noExplicitAny` happy while the check provides the real type.
  SCP?: unknown;
};

/**
 * Raw NAPI `SCP` class type once resolved. `withPersistence` is
 * intentionally omitted from this interface — the native factory
 * still exists for internal use, but the SDK surface does not expose
 * it until a real `ContextPersistence` trait is wired through (see
 * #1260 and #1491).
 *
 * PR 3 extends the native factory surface with SQLite-backed storage
 * via `withStorage({ type: "sqlite", path, key })`. The NAPI layer
 * (#1678) also turned `resume()` into a real async call backed by
 * transport reconnect from pending relay URLs.
 */
interface NativeScpCtor {
  new (): NativeScpInstance;
  withStorage: (configJson: string) => NativeScpInstance;
}

interface NativeScpInstance {
  readonly instanceId: string;
  suspend(): void;
  /**
   * Resumes the underlying bridge. Real async on NAPI — the bridge
   * reconnects transport from pending relay URLs and restores any
   * persisted context snapshots before the returned promise settles
   * (#1678).
   */
  resume(): Promise<void>;
  /**
   * #1692: NAPI `shutdown(timeoutMillis: u64)` — `u64` maps to JS
   * `BigInt` on the napi-rs wire, so the native method accepts a
   * `bigint`. The SDK public wrapper (`SCP.shutdown`) keeps a
   * `number`-valued seconds budget and converts at the boundary.
   */
  shutdown(timeoutMillis: bigint): Promise<void>;
}

/**
 * Resolves the platform-specific napi package name.
 *
 * Mirrors the mapping in `internal/native.ts` so that `SCP` can load
 * the addon directly without going through the `Bridge` interface
 * (which doesn't expose class constructors).
 */
function resolveNapiPackage(): string {
  const platform = process.platform;
  const arch = process.arch;

  const platformMap: Record<string, string> = {
    "linux-x64": "@limn-works/scp-ts-napi-linux-x64-gnu",
    "linux-arm64": "@limn-works/scp-ts-napi-linux-arm64-gnu",
    "darwin-x64": "@limn-works/scp-ts-napi-darwin-x64",
    "darwin-arm64": "@limn-works/scp-ts-napi-darwin-arm64",
    "win32-x64": "@limn-works/scp-ts-napi-win32-x64-msvc",
  };

  const key = `${platform}-${arch}`;
  const pkg = platformMap[key];

  if (pkg === undefined) {
    // Unsupported host platform — no per-platform NAPI package exists.
    // Distinct message from the "package present on disk but failed to
    // load" and "addon lacks SCP class" branches so bug reports and logs
    // clearly identify which of the three failure modes tripped
    // (round 2 api-design finding).
    //
    // `SCP-VALID-7005` — structural unavailability, not a transport-layer
    // fault. Using a validation code matches the Rust bridge's treatment
    // of unknown storage types and keeps transport error codes reserved
    // for actual relay connectivity failures.
    throw new ValidationError(
      `Native addon not found — the @limn-works/scp-ts-napi-* package for ` +
        `platform ${key} is not published. Install the matching platform package ` +
        "for your host, or use the WASM bridge in a browser environment.",
      "SCP-VALID-7005",
    );
  }

  return pkg;
}

/**
 * Loads the raw native addon and extracts the `SCP` class constructor.
 *
 * Cached on first successful load.
 *
 * @throws {ValidationError} If the addon cannot be loaded or lacks the
 *   `SCP` class — code `SCP-VALID-7005`.
 */
let _nativeScp: NativeScpCtor | null = null;

function nativeScp(): NativeScpCtor {
  if (_nativeScp !== null) {
    return _nativeScp;
  }

  // Three distinct failure modes, three distinct messages — all sharing
  // `SCP-VALID-7005` for "structural unavailability" so a catch-by-code
  // still groups them, but the body tells the caller exactly what to do
  // (round 2 api-design finding).

  // Failure mode 1: running in a browser with no `process` / `module`
  // APIs. Structural incompatibility, not a transport fault — the WASM
  // bridge does not expose a multi-instance class surface (ADR-034 /
  // ADR-048).
  if (typeof process === "undefined" || !process.versions?.node) {
    throw new ValidationError(
      "SCP class is not available in WASM runtime — the browser build of " +
        "@limn-works/scp-ts does not expose a multi-instance class (ADR-034 / " +
        "ADR-048). Use @limn-works/scp-sdk-napi in a Node.js or Bun process.",
      "SCP-VALID-7005",
    );
  }

  const packageName = resolveNapiPackage();
  let addon: NativeAddon;
  try {
    const req = createRequire(import.meta.url);
    addon = req(packageName) as NativeAddon;
  } catch (cause) {
    // Failure mode 2: platform NAPI package resolves but the addon
    // itself fails to load at require-time. Usually a missing binary
    // for the current libc/glibc variant, an ABI mismatch, or a
    // partially-installed package. Preserve the underlying error so
    // bug reports carry actionable detail.
    const underlying = (cause as Error)?.message ?? String(cause);
    throw new ValidationError(
      `Native addon failed to load: ${underlying}. Package ${packageName} ` +
        "was resolved but could not be instantiated — check that the binary " +
        "for your host is installed, then reinstall with " +
        `\`bun install ${packageName}\`.`,
      "SCP-VALID-7005",
    );
  }

  if (typeof addon.SCP !== "function") {
    // Failure mode 3: the addon loaded, but it pre-dates ADR-048 and
    // does not export the `SCP` class surface. Callers need to rebuild
    // or upgrade the NAPI package.
    throw new ValidationError(
      `Native addon loaded but does not export the SCP class — ` +
        `${packageName} was built before the Phase 4 PR 1 multi-instance ` +
        "surface landed. Upgrade the package or rebuild from the current " +
        "codebase with `cargo build -p scp-ffi-napi`.",
      "SCP-VALID-7005",
    );
  }

  _nativeScp = addon.SCP as unknown as NativeScpCtor;
  return _nativeScp;
}

// ---------------------------------------------------------------------------
// Internal helpers (exported for tests, not part of the public API)
// ---------------------------------------------------------------------------

/**
 * Clamps a float-seconds timeout into a millisecond count suitable for
 * the NAPI `shutdown(timeoutMillis)` boundary. Exposed as an internal
 * export so the regression tests around `Infinity` / `NaN` handling
 * can exercise the clamp without needing a live native addon.
 *
 * The ceiling is pinned to `Number.MAX_SAFE_INTEGER` (2^53 − 1 ms, ≈ 285
 * million years) rather than the full `u64::MAX` — the public SDK API
 * still takes a JS `number`, so anything above `MAX_SAFE_INTEGER` cannot
 * be represented losslessly anyway. The NAPI bridge itself is `u64`
 * (#1692), so wider values are technically supported on the wire; any
 * caller that needs billion-year timeouts can hit the NAPI binding
 * directly with a `bigint` literal.
 *
 * @internal
 */
export function __clampShutdownMillisForTests(timeoutSecs: number): number {
  // Largest millisecond count representable losslessly as a JS `number`.
  // The NAPI binding accepts the full `u64` range via `BigInt`, but the
  // SDK seconds-valued input is a `number`, so `MAX_SAFE_INTEGER` is
  // the safe upper bound for this helper.
  const MAX_MILLIS = Number.MAX_SAFE_INTEGER;
  // Order matters: +Infinity must be caught BEFORE !isFinite, otherwise
  // Infinity collapses to the NaN/negative abort branch (Number.isFinite
  // is false for both Infinity and NaN).
  if (timeoutSecs === Number.POSITIVE_INFINITY) {
    return MAX_MILLIS;
  }
  if (!Number.isFinite(timeoutSecs) || timeoutSecs <= 0) {
    // NaN, negative, negative-infinity, or zero → immediate abort.
    return 0;
  }
  if (timeoutSecs * 1000 > MAX_MILLIS) {
    return MAX_MILLIS;
  }
  return Math.round(timeoutSecs * 1000);
}

/**
 * Serializes a {@link StorageConfig} into the JSON shape accepted by
 * the NAPI `SCP.withStorage(configJson: string)` factory.
 *
 * - `in_memory` passes through unchanged.
 * - `sqlite` forwards `path` verbatim and normalizes `key`:
 *   - `Uint8Array` → JSON byte array (`number[]`) — required because
 *     `JSON.stringify` on a `Uint8Array` produces an object-with-numeric-
 *     keys, not an array, which the Rust side would reject.
 *   - `string` → passed through as a hex-encoded string; the NAPI layer
 *     accepts either shape.
 *
 * Exported for tests so the wire format can be asserted without a live
 * native addon.
 *
 * @internal
 */
export function __serializeStorageConfigForTests(config: StorageConfig): string {
  return serializeStorageConfig(config);
}

function serializeStorageConfig(config: StorageConfig): string {
  if (config.type === "sqlite") {
    const key = typeof config.key === "string" ? config.key : Array.from(config.key as Uint8Array);
    return JSON.stringify({ type: "sqlite", path: config.path, key });
  }
  return JSON.stringify(config);
}

// ---------------------------------------------------------------------------
// Options
// ---------------------------------------------------------------------------

/**
 * Storage configuration forwarded to the native `SCP.withStorage`
 * factory.
 *
 * Two variants are supported today:
 * - `{ type: "in_memory" }` — encrypted in-memory storage (ephemeral).
 * - `{ type: "sqlite"; path; key }` — SQLCipher-encrypted storage on
 *   disk at `{path}/scp.db`, backed by `scp-platform::sqlite::SqliteStorage`.
 *   `key` accepts either a raw `Uint8Array` of key material or a hex-
 *   encoded string (JSON has no native bytes type; the NAPI layer
 *   accepts either shape). The key is consumed across the FFI boundary
 *   and the Rust side zeroizes its internal copy on drop — callers
 *   should zero their own copy after construction.
 *
 * Intentionally a closed union — the open `{ type: string; ... }`
 * branch swallowed typos and drifted from the Rust-side enum.
 *
 * Closes #1260 / #1491 (encrypted filesystem storage). See also #1678
 * for the resume() reconnect wiring that complements persistent
 * storage.
 */
export type StorageConfig =
  | { type: "in_memory" }
  | { type: "sqlite"; path: string; key: Uint8Array | string };

/**
 * Constructor options for `new SCP(...)`.
 */
export interface ScpOptions {
  /** Storage configuration. Defaults to in-memory when omitted. */
  storage?: StorageConfig;
}

// ---------------------------------------------------------------------------
// SCP class
// ---------------------------------------------------------------------------

/**
 * Module-private symbol for internal accessors that surface the raw
 * native handle to other SDK modules (notably
 * `internal/native.ts`, `server.ts`, `mcp.ts`, `lifecycle.ts`).
 *
 * External callers cannot reach this — the Symbol is not exported.
 * Internal callers import {@link __getNativeScp} from this module to
 * obtain the raw NAPI `SCP` handle for direct method invocation.
 *
 * @internal
 */
const NATIVE_HANDLE: unique symbol = Symbol("scp.nativeHandle");

/**
 * Caller-owned SCP instance — the preferred SDK entry point.
 *
 * Each `SCP` wraps an independent native `BridgeInstance`. See
 * ADR-048 for the multi-instance design.
 */
export class SCP {
  /**
   * The native NAPI `SCP` handle. `readonly` + private so TypeScript
   * consumers can't reach for the raw addon surface (which is
   * unstable across releases).
   */
  readonly #native: NativeScpInstance;

  /**
   * Constructs a fresh `SCP` instance.
   *
   * @param options Optional constructor options.
   * @throws {ValidationError} If no NAPI addon is available (browser
   *   runtime or missing platform package) — code `SCP-VALID-7005`.
   */
  constructor(options: ScpOptions = {}) {
    const NativeScp = nativeScp();
    if (options.storage !== undefined) {
      this.#native = NativeScp.withStorage(serializeStorageConfig(options.storage));
    } else {
      this.#native = new NativeScp();
    }
  }

  /**
   * Monotonic identifier for this bridge instance, returned as a
   * base-10 string because u64 exceeds JavaScript's safe-integer
   * range (53-bit mantissa).
   */
  get instanceId(): string {
    return this.#native.instanceId;
  }

  /**
   * Suspends this bridge instance (mobile/desktop backgrounding).
   *
   * Disconnects transport and marks the instance suspended.
   * Transport-dependent operations fail until `resume()` is called.
   *
   * @throws {TransportError} If the transport lock is poisoned.
   */
  suspend(): void {
    this.#native.suspend();
  }

  /**
   * Resumes a suspended bridge instance.
   *
   * Clears the suspended flag and chains the per-bridge async resume
   * work: transport reconnect from pending relay URLs and restoration
   * of any persisted context snapshots (#1678). The returned promise
   * settles only after those steps complete, so callers can `await`
   * resume and then safely issue transport-dependent operations.
   *
   * **Breaking change (#1549 Phase 4 PR 3)**: `resume()` is async now.
   * Previous releases returned `void`; the method always performed a
   * flag flip only and callers re-established the relay connection
   * separately via `Transport.connect(...)`. The NAPI `Scp::resume`
   * became `async` in the Rust layer, and this wrapper follows it so
   * errors surfacing during reconnect / restoration are observable at
   * the SDK boundary instead of fire-and-forget.
   *
   * @throws {ContextError} If the instance has been permanently shut
   *   down — mapped from `SCP-CTX-2000`.
   */
  async resume(): Promise<void> {
    await this.#native.resume();
  }

  /**
   * Shuts down the instance with a graceful deadline.
   *
   * Drains in-flight tasks within `timeoutSecs` seconds. Second and
   * subsequent calls are no-ops.
   *
   * Fractional seconds (e.g. `0.25`) are preserved to millisecond
   * resolution before crossing the FFI boundary — the native side
   * takes a `u64` millisecond count (widened from `u32` in #1692).
   *
   * `timeoutSecs` is clamped defensively:
   * - `NaN` or values `<= 0` → `0` (abort in-flight tasks immediately).
   * - `Infinity` or values that exceed `Number.MAX_SAFE_INTEGER` ms
   *   → `Number.MAX_SAFE_INTEGER` (effectively unbounded — `u64` on the
   *   wire comfortably holds this).
   * - Finite values in range → rounded to the nearest millisecond.
   *
   * Previously used `Math.floor`, which silently lost up to 0.999 ms
   * of caller budget; and passed `NaN` straight through to the NAPI
   * boundary, where the earlier `u32` conversion silently yielded `0`
   * instead of erroring (round 2 api-design + bug-catcher findings).
   *
   * Round 5 RED-2001 tightened the branch ordering: `Infinity` must be
   * tested BEFORE `!Number.isFinite`, because `Number.isFinite(Infinity)`
   * is `false` and the isFinite branch otherwise collapses Infinity to
   * the abort path — which contradicts this docstring.
   *
   * @param timeoutSecs Maximum seconds to wait. Defaults to 5.
   *   Floats are honored at 1 ms granularity.
   */
  async shutdown(timeoutSecs: number = 5): Promise<void> {
    const millis = __clampShutdownMillisForTests(timeoutSecs);
    // #1692: NAPI widened `timeoutMillis` to `u64`, exposed as JS
    // `BigInt` on the wire. The clamp above already produces an integer
    // number of millis inside `u64` range — coerce to `bigint` for the
    // FFI call.
    await this.#native.shutdown(BigInt(millis));
  }

  /**
   * Internal accessor exposing the raw native NAPI `SCP` handle.
   *
   * The Symbol-keyed getter is used by other SDK modules
   * (`internal/native.ts`, `server.ts`, `mcp.ts`) to dispatch SDK calls
   * directly against this instance's class methods. The module-level
   * free-function façade that predated ADR-048 was DELETED in PR 4
   * (not deprecated) — no process-wide default instance exists. The
   * Symbol is not exported, so external code cannot retrieve the
   * native handle through this channel.
   *
   * @internal
   */
  get [NATIVE_HANDLE](): NativeScpInstance {
    return this.#native;
  }
}

/**
 * Retrieve the raw NAPI `SCP` handle from an {@link SCP} wrapper for
 * internal routing. Intended for use only by other SDK modules that
 * need to invoke class methods directly (e.g.
 * `internal/native.ts::createNativeBridge`).
 *
 * @internal
 */
export function __getNativeScp(scp: SCP): NativeScpInstance {
  return scp[NATIVE_HANDLE];
}
