/**
 * SDK-level `SCP` class for the TypeScript SDK.
 *
 * See ADR-048 ("SCP multi-instance bridge + check-handle-affinity gate")
 * for the design rationale. Each `SCP` instance owns an independent
 * `BridgeInstance` (registries, transport, context manager), so tests,
 * multi-identity apps, and per-tenant services can hold distinct
 * instances without sharing state.
 *
 * The free-function façade (`Identity.create`, `Context.create`, etc.)
 * currently operates on the process-wide default instance and emits a
 * one-time `console.warn` on first use (see `internal/deprecation.ts`).
 * Removal target: two release cycles after Phase 4 merge.
 *
 * ```ts
 * import { SCP } from "@limn-works/scp-ts";
 *
 * const scp = new SCP();                 // fresh in-memory instance
 * const shared = SCP.default();          // shared process-wide default
 * await scp.shutdown(5);                 // graceful shutdown
 * ```
 *
 * NOTE: `SCP` is a NAPI-only feature in Phase 4 PR 1. The WASM bridge
 * does not expose a multi-instance class surface; attempting to
 * construct `SCP` in a browser environment throws `TransportError`
 * with `SCP-TRANS-5001`. WASM callers continue to use the free-function
 * façade (which is a no-op for lifecycle methods on WASM per
 * `internal/wasm.ts`).
 */

import { createRequire } from "node:module";

import { TransportError } from "./errors";

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
 * Raw NAPI `SCP` class type once resolved.
 */
interface NativeScpCtor {
  new (): NativeScpInstance;
  default: () => NativeScpInstance;
  withStorage: (configJson: string) => NativeScpInstance;
  withPersistence: () => NativeScpInstance;
}

interface NativeScpInstance {
  readonly instanceId: string;
  suspend(): void;
  resume(): void;
  shutdown(timeoutSecs: number): Promise<void>;
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
    throw new TransportError(
      `No native addon available for platform ${key}. ` +
        "Install the appropriate @limn-works/scp-ts-napi-* package or use the WASM bridge in a browser environment.",
      "SCP-TRANS-5001",
    );
  }

  return pkg;
}

/**
 * Loads the raw native addon and extracts the `SCP` class constructor.
 *
 * Cached on first successful load.
 *
 * @throws {TransportError} If the addon cannot be loaded or lacks the
 *   `SCP` class.
 */
let _nativeScp: NativeScpCtor | null = null;

function nativeScp(): NativeScpCtor {
  if (_nativeScp !== null) {
    return _nativeScp;
  }

  // Running in a browser with no `process` / `module` APIs.
  if (typeof process === "undefined" || !process.versions?.node) {
    throw new TransportError(
      "SCP class is not available in browser (WASM) environments. " +
        "Use the free-function façade for WASM or move the SCP() call to a Node/Bun server.",
      "SCP-TRANS-5001",
    );
  }

  const packageName = resolveNapiPackage();
  let addon: NativeAddon;
  try {
    const req = createRequire(import.meta.url);
    addon = req(packageName) as NativeAddon;
  } catch (cause) {
    throw new TransportError(
      `Failed to load native addon ${packageName}: ${(cause as Error)?.message ?? cause}. ` +
        `Ensure the package is installed: bun install ${packageName}`,
      "SCP-TRANS-5001",
    );
  }

  if (typeof addon.SCP !== "function") {
    throw new TransportError(
      `${packageName} does not export the SCP class. ` +
        "Rebuild the native addon with the Phase 4 PR 1 codebase (cargo build -p scp-ffi-napi).",
      "SCP-TRANS-5001",
    );
  }

  _nativeScp = addon.SCP as unknown as NativeScpCtor;
  return _nativeScp;
}

// ---------------------------------------------------------------------------
// Options
// ---------------------------------------------------------------------------

/**
 * Storage configuration forwarded to the native `SCP.withStorage`
 * factory.
 *
 * Phase 4 PR 1 accepts only `{ type: "in_memory" }`. PR 3 adds
 * SQLite-backed storage. Unknown types raise `SCP-VALID-7005`.
 */
export type StorageConfig = { type: "in_memory" } | { type: string; [k: string]: unknown };

/**
 * Constructor options for `new SCP(...)`.
 */
export interface ScpOptions {
  /** Storage configuration. Defaults to in-memory when omitted. */
  storage?: StorageConfig;
  /**
   * Opaque persistence provider placeholder. Reserved for PR 3 where
   * the real `ContextPersistence` trait is wired through NAPI.
   * Providing any non-null value currently constructs an in-memory
   * instance identical to the default path.
   */
  persistence?: unknown;
}

// ---------------------------------------------------------------------------
// SCP class
// ---------------------------------------------------------------------------

/**
 * Internal marker used by the `SCP.default()` factory to bypass the
 * public `constructor`'s native-SCP initialization path and inject an
 * externally-obtained handle. The marker is a module-local Symbol so
 * it is impossible to forge from outside this module.
 */
const ADOPT_HANDLE: unique symbol = Symbol("scp.adoptHandle");

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
   * @throws {TransportError} If no NAPI addon is available (browser
   *   runtime or missing platform package).
   */
  constructor(options: ScpOptions = {}) {
    // Internal fast-path used by the `default()` factory to adopt a
    // pre-existing native handle without invoking the usual
    // constructor factories. External callers cannot synthesize this
    // path because `ADOPT_HANDLE` is a module-private symbol.
    if ((options as { [ADOPT_HANDLE]?: NativeScpInstance })[ADOPT_HANDLE] !== undefined) {
      this.#native = (options as { [ADOPT_HANDLE]: NativeScpInstance })[ADOPT_HANDLE];
      return;
    }

    const NativeScp = nativeScp();
    if (options.persistence !== undefined && options.persistence !== null) {
      // PR 1 placeholder — the native factory currently returns a
      // fresh in-memory instance identical to `new NativeScp()`. PR 3
      // wires the real persistence provider through.
      this.#native = NativeScp.withPersistence();
    } else if (options.storage !== undefined) {
      this.#native = NativeScp.withStorage(JSON.stringify(options.storage));
    } else {
      this.#native = new NativeScp();
    }
  }

  /**
   * Returns an `SCP` wrapping the process-wide default instance.
   *
   * Repeated calls return distinct wrapper objects sharing the same
   * underlying native handle — `instanceId` is stable across calls.
   *
   * This is what the deprecated free-function façade uses under the
   * hood. Prefer explicit construction (`new SCP()`) in new code.
   *
   * @throws {TransportError} If the NAPI addon is unavailable.
   */
  static default(): SCP {
    const NativeScp = nativeScp();
    const native = NativeScp.default();
    return new SCP({ [ADOPT_HANDLE]: native } as ScpOptions);
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
   * Clears the suspended flag. Callers must re-establish the relay
   * connection explicitly.
   *
   * @throws {ContextError} If the instance has been permanently shut
   *   down.
   */
  resume(): void {
    this.#native.resume();
  }

  /**
   * Shuts down the instance with a graceful deadline.
   *
   * Drains in-flight tasks within `timeoutSecs` seconds. Second and
   * subsequent calls are no-ops.
   *
   * @param timeoutSecs Maximum seconds to wait. Defaults to 5.
   */
  async shutdown(timeoutSecs: number = 5): Promise<void> {
    await this.#native.shutdown(timeoutSecs);
  }
}
