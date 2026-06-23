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
 * // Storage selection is required — there is no default (spec §17.6).
 * const scp = new SCP({ storage: { type: "in_memory" } }); // dev/test storage
 * const identity = await scp.identityCreate("in_memory");
 * await scp.resume();                    // async — reconnects transport
 * await scp.shutdown(5);                 // graceful shutdown
 * ```
 *
 * Phase 4 PR 4 (#1549, ADR-048) expanded the `SCP` surface so every NAPI
 * bridge operation has a corresponding instance method on `SCP`. The
 * process-wide default-instance façade and free-function shorthands were
 * deleted — callers construct an explicit `new SCP()` and invoke methods
 * directly (e.g. `scp.identityCreate("in_memory")`).
 *
 * NOTE: `SCP` is a NAPI-only feature. The WASM bridge
 * does not expose a multi-instance class surface; attempting to
 * construct `SCP` in a browser environment throws `ValidationError`
 * with `SCP-VALID-7005`.
 */

// Deferred imports of opaque classes. The classes import `SCP` for
// typing, so importing them eagerly here creates a module cycle at
// evaluation time. Using type-only imports keeps the SCP module
// standalone at runtime — the handle-wrapping helpers call
// `_fromHandle` statics which are resolved lazily inside the SCP
// methods via dynamic `import()` calls.
import type { BridgeCredential } from "./bridge";
import type { Context } from "./context";
import type { PaymentReceiptVerificationResult } from "./economy";
import { mapBridgeError, ValidationError } from "./errors";
import type { Identity } from "./identity";
import { getBridge } from "./internal/bridge";
import { loadNativeAddon, type NativeAddon as RawNativeAddon } from "./internal/native";
import { assertTestEnvironment } from "./internal/test-guard";
import type { Node, Relay } from "./server";

/**
 * Refined view of the native addon used by this module. The shared
 * loader in `internal/native.ts` returns the raw addon as
 * `Record<string, unknown>`; we narrow here to surface the names that
 * `scp.ts` cares about (the `SCP` class constructor + the four
 * module-level pure-helper exports per ADR-048 §1).
 *
 * Both `internal/native.ts` and this module read from the same
 * `loadNativeAddon`-cached addon — there is one cache, one freeze,
 * one platform package resolution.
 */
type NativeAddon = RawNativeAddon & {
  SCP?: unknown;
  // Pure protocol helpers — exported at module scope per ADR-048 §1
  // because they touch no per-instance state. The `SCP` class methods
  // for these names route to these module-level exports per ADR-048 §7
  // (TS keeps the method shape as a TS-local ergonomic choice).
  metadataRecordFromJson?: unknown;
  templateGetParams?: unknown;
  validateAgainstTemplate?: unknown;
  validateContextParams?: unknown;
  checkScopedCapability?: unknown;
  identityVerifyLinkAttestation?: unknown;
};

/**
 * Raw NAPI `SCP` class type once resolved. The only construction paths
 * are the `new (configJson)` constructor and the `withStorage` factory —
 * both take an explicit JSON storage-config string (spec §17.6 — storage
 * selection is mandatory). There is no zero-argument constructor.
 */
interface NativeScpCtor {
  // The native constructor now requires a JSON storage-config string
  // (spec §17.6 — storage selection is mandatory). The SDK routes
  // construction through `withStorage` rather than the raw `new`, so the
  // raw constructor signature is kept here only for type accuracy.
  new (configJson: string): NativeScpInstance;
  withStorage: (configJson: string) => NativeScpInstance;
}

/**
 * Raw NAPI `Scp` instance — the method surface is erased to
 * `(...args) => unknown` because each forwarder narrows the per-call
 * signature at its own call site, and duplicating the 178 method
 * signatures here would drift from the Rust source of truth.
 */
interface NativeScpInstance {
  readonly instanceId: string;
  suspend(): void;
  resume(): Promise<void>;
  shutdown(timeoutMillis: bigint): Promise<void>;
  // The full Scp class surface is reached via indexed access
  // (see `#native` usage below). Keeping the type erased matches the
  // pattern in `internal/native.ts` and `server.ts`.
  [method: string]: unknown;
}

/**
 * Resolves the cached native addon and validates the SCP-class export.
 *
 * Routes through the shared `loadNativeAddon` cache in
 * `internal/native.ts` so this module and the bridge factory share a
 * single frozen addon reference. The shared loader throws
 * `TransportError` (`SCP-TRANS-5001`) on platform-package missing or
 * load failure; this wrapper layers an additional WASM-runtime check
 * and a stale-addon (no `SCP` class) check, both surfaced as
 * `ValidationError` (`SCP-VALID-7005`) — the public-API code that
 * SDK consumers see when they call `new SCP(...)`.
 */
function loadAddon(): NativeAddon {
  if (typeof process === "undefined" || !process.versions?.node) {
    throw new ValidationError(
      "SCP class is not available in WASM runtime — the browser build of " +
        "@limn-works/scp-ts does not expose a multi-instance class (ADR-034 / " +
        "ADR-048). Use @limn-works/scp-sdk-napi in a Node.js or Bun process.",
      "SCP-VALID-7005",
    );
  }

  let addon: NativeAddon;
  try {
    addon = loadNativeAddon() as NativeAddon;
  } catch (cause) {
    const underlying = (cause as Error)?.message ?? String(cause);
    throw new ValidationError(
      `Native addon failed to load: ${underlying}. ` +
        "Ensure the matching @limn-works/scp-ts-napi-* platform package is " +
        "installed, then reinstall with `bun install`.",
      "SCP-VALID-7005",
    );
  }

  if (typeof addon.SCP !== "function") {
    throw new ValidationError(
      "Native addon loaded but does not export the SCP class — " +
        "the platform addon was built before the Phase 4 PR 1 multi-instance " +
        "surface landed. Upgrade the package or rebuild from the current " +
        "codebase with `cargo build -p scp-ffi-napi`.",
      "SCP-VALID-7005",
    );
  }

  return addon;
}

let _nativeScp: NativeScpCtor | null = null;

function nativeScp(): NativeScpCtor {
  if (_nativeScp !== null) {
    return _nativeScp;
  }
  const addon = loadAddon();
  _nativeScp = addon.SCP as unknown as NativeScpCtor;
  return _nativeScp;
}

/**
 * Returns the loaded native addon's module-level export for a pure
 * protocol helper. Pure helpers live at module scope on the addon per
 * ADR-048 §1; `SCP` class methods that wrap them route through this
 * accessor instead of `this.#native[name]`.
 *
 * Throws `SCP-VALID-7005` if the addon is unloadable or does not
 * export the named function (e.g., a stale prebuilt addon predating
 * the §1 split).
 */
function nativeFreeFn<T>(name: keyof NativeAddon): T {
  const addon = loadAddon();
  const fn = addon[name];
  if (typeof fn !== "function") {
    throw new ValidationError(
      `Native addon does not export the module-level free function "${String(name)}" — ` +
        "the addon may be stale (predating ADR-048 §1 pure-helper split). " +
        "Rebuild with `cargo build -p scp-ffi-napi` or upgrade the platform package.",
      "SCP-VALID-7005",
    );
  }
  return fn as T;
}

// ---------------------------------------------------------------------------
// Internal helpers (exported for tests, not part of the public API)
// ---------------------------------------------------------------------------

/**
 * Clamps a float-seconds timeout into a millisecond count suitable for
 * the NAPI `shutdown(timeoutMillis)` boundary.
 *
 * @internal
 */
export function __clampShutdownMillisForTests(timeoutSecs: number): number {
  const MAX_MILLIS = Number.MAX_SAFE_INTEGER;
  if (timeoutSecs === Number.POSITIVE_INFINITY) {
    return MAX_MILLIS;
  }
  if (!Number.isFinite(timeoutSecs) || timeoutSecs <= 0) {
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
 * - `sqlite` + `key` forwards `path` verbatim and normalizes `key`:
 *   - `Uint8Array` → JSON byte array (`number[]`) — required because
 *     `JSON.stringify` on a `Uint8Array` produces an object-with-numeric-
 *     keys, not an array, which the Rust side would reject.
 *   - `string` → passed through as a hex-encoded string; the NAPI layer
 *     accepts either shape.
 * - `sqlite` + `passphrase` forwards `path` and the `passphrase` string
 *   verbatim; the NAPI layer derives the SQLCipher key via Argon2id
 *   (spec §17.6). Whichever of `key`/`passphrase` is present is forwarded;
 *   the exactly-one (XOR) decision is deferred to the NAPI layer
 *   (SCP-VALID-7005), so a caller that supplies BOTH reaches the guard and
 *   is rejected rather than having one field silently dropped.
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
    // Forward whichever key-material fields are present, verbatim, so the
    // NAPI layer remains the single authority on the `key` XOR `passphrase`
    // mutual-exclusion rule (spec §17.6, SCP-VALID-7005). We must NOT
    // short-circuit on the presence of one field and silently drop the
    // other: a caller that bypasses the TS union type and supplies BOTH
    // must reach the NAPI guard so it can reject them, rather than have the
    // serializer quietly discard one and let an ambiguous config through.
    const out: { type: "sqlite"; path: string; key?: number[] | string; passphrase?: string } = {
      type: "sqlite",
      path: config.path,
    };
    // `key` may be absent on the passphrase arm; access via a widened view
    // so we forward it only when actually supplied.
    const rawKey = (config as { key?: Uint8Array | string }).key;
    if (rawKey !== undefined) {
      // A Uint8Array must be normalized to a number[] because
      // `JSON.stringify(Uint8Array)` yields an object, not an array.
      out.key = typeof rawKey === "string" ? rawKey : Array.from(rawKey);
    }
    const passphrase = (config as { passphrase?: string }).passphrase;
    if (passphrase !== undefined) {
      // Passphrase mode (spec §17.6): forward verbatim. The NAPI layer moves
      // it into zeroizing memory and derives the SQLCipher key via Argon2id.
      out.passphrase = passphrase;
    }
    return JSON.stringify(out);
  }
  return JSON.stringify(config);
}

// ---------------------------------------------------------------------------
// Options
// ---------------------------------------------------------------------------

/**
 * Storage configuration forwarded to the native `SCP.withStorage` factory.
 *
 * Three variants are supported today:
 * - `{ type: "in_memory" }` — encrypted in-memory storage (ephemeral).
 * - `{ type: "sqlite"; path; key }` — SQLCipher-encrypted storage on
 *   disk at `{path}/scp.db`, keyed by raw encryption key material.
 *   `key` accepts either a raw `Uint8Array` of key material or a hex-
 *   encoded string (JSON has no native bytes type; the NAPI layer
 *   accepts either shape). The key is consumed across the FFI boundary
 *   and the Rust side zeroizes its internal copy on drop — callers
 *   should zero their own copy after construction.
 * - `{ type: "sqlite"; path; passphrase }` — SQLCipher-encrypted storage
 *   whose key is derived from a human-chosen `passphrase` via Argon2id
 *   (spec §17.6). The passphrase is moved into zeroizing memory on the
 *   Rust side.
 *
 * For the `sqlite` type, exactly ONE of `key` or `passphrase` must be
 * supplied — providing both, or neither, is rejected by the NAPI layer
 * with `SCP-VALID-7005`. The two `sqlite` shapes are modeled as separate
 * union arms so the type system enforces the mutual exclusion.
 *
 * Intentionally a closed union — the open `{ type: string; ... }`
 * branch swallowed typos and drifted from the Rust-side enum.
 */
export type StorageConfig =
  | { type: "in_memory" }
  | { type: "sqlite"; path: string; key: Uint8Array | string }
  | { type: "sqlite"; path: string; passphrase: string };

/** Constructor options for `new SCP(...)`. */
export interface ScpOptions {
  /**
   * Storage configuration. **Required** — storage selection is mandatory
   * and fail-closed (spec §17.6); there is no default backend. Use
   * `{ type: "in_memory" }` for development/test or `{ type: "sqlite", ... }`
   * for production.
   */
  storage: StorageConfig;
}

/**
 * Snapshot of an `SCP` instance's MCP stdio allowlist state.
 *
 * Returned by {@link SCP.mcpGetStdioAllowlist}. Mirrors the Rust
 * `scp_mcp::allowlist::AllowlistState` shape and the Python
 * `McpAllowlistState` `TypedDict` so consumers get IDE autocomplete on
 * the snapshot fields.
 */
export interface McpAllowlistState {
  /** Sorted list of allowed binary basenames. */
  readonly allowed: readonly string[];
  /** `true` if enforcement is disabled (unrestricted mode). */
  readonly unrestricted: boolean;
}

/** Offline-tier classification reported per reconnected context (ADR-029). */
export type ReconnectTier = "short" | "extended" | "long";

/** Per-context reconnection outcome reported by {@link SCP.reconnect}. */
export type ReconnectOutcome =
  | "fully_caught_up"
  | "fast_forwarded"
  | "reset"
  | "context_gone"
  | "failed"
  | "pending";

/**
 * Per-context result of {@link SCP.reconnect} (ADR-029).
 */
export interface ContextReconnectResult {
  /** Context that was reconnected. */
  readonly contextId: string;
  /** Offline tier classification. */
  readonly tier: ReconnectTier;
  /** Per-context reconnection outcome. */
  readonly outcome: ReconnectOutcome;
  /** MLS epochs caught up. */
  readonly epochsCaughtUp: number;
  /** Event-log events recovered. */
  readonly eventsRecovered: number;
  /** Whether an MLS Update was issued (§9.12). */
  readonly mlsUpdateIssued: boolean;
  /**
   * Number of equivocation alerts surfaced during this context's sync
   * (§9.9.3). Each alert's divergent local/remote Merkle roots are delivered
   * per-event via the receive stream (`EquivocationDetected` events) and
   * persisted in the event log; this field is the count only.
   */
  readonly equivocationsDetected: number;
  /** Whether `needsReconnect` was cleared on success. */
  readonly needsReconnectCleared: boolean;
}

/**
 * Aggregate result of {@link SCP.reconnect} (ADR-029).
 */
export interface ReconnectReport {
  /** Per-context results. */
  readonly contexts: readonly ContextReconnectResult[];
  /** Total queued messages drained (Phase 6). */
  readonly messagesDrained: number;
  /** Total queued messages discarded. */
  readonly messagesDiscarded: number;
  /** Total reconnection duration in milliseconds. */
  readonly totalDurationMs: number;
}

/**
 * Caller-supplied custody backend for {@link SCP.identityCreateWithCustody}.
 *
 * Implement this to back a DID's key material with a platform keystore (OS
 * keychain, hardware token, HSM wrapper, etc.). The private key material never
 * crosses into the native core — every cryptographic operation is delegated
 * back to your callbacks (ADR-006). Mirrors the Swift/Kotlin (`UniFFI`)
 * `KeyCustodyProvider` callback interface and the Python `KeyCustodyProvider`
 * protocol so all SDKs share an identical contract.
 *
 * Callbacks are invoked synchronously from the native bridge (marshalled onto
 * the Node.js event loop). Key identifiers are opaque, numeric-string handles
 * your implementation assigns in {@link generateKeypair}. Byte values are
 * passed and returned as `Uint8Array`.
 *
 * Only available on the NAPI (Node.js / Bun) backend — the browser/WASM build
 * does not expose the multi-instance `SCP` class (ADR-034 / ADR-048).
 */
export interface KeyCustodyProvider {
  /** Generate a keypair (`"ed25519"` or `"x25519"`); return its opaque id. */
  generateKeypair(keyType: string): string;
  /** Return the 64-byte Ed25519 signature of `message` under `keyId`. */
  sign(keyId: string, message: Uint8Array): Uint8Array;
  /** Return the 32 public-key bytes for `keyId`. */
  getPublicKey(keyId: string): Uint8Array;
  /** Destroy key material for `keyId`; subsequent operations must fail. */
  destroyKey(keyId: string): void;
  /** Return the 32-byte X25519 shared secret with `peerPublic`. */
  dhAgree(keyId: string, peerPublic: Uint8Array): Uint8Array;
  /**
   * Derive a context-scoped pseudonym keypair. Returns
   * `publicKey(32) || keyIdUtf8` — the 32-byte pseudonym public key
   * concatenated with the UTF-8 numeric id of the derived signing key.
   */
  derivePseudonym(keyId: string, contextId: Uint8Array): Uint8Array;
  /**
   * Derive a rotatable (epoch-versioned) context-scoped pseudonym keypair.
   * Identical layout to {@link derivePseudonym} — returns
   * `publicKey(32) || keyIdUtf8` — but the derivation mixes the big-endian
   * 64-bit `pseudonymEpoch` and a distinct domain separator so rotating the
   * epoch yields an unlinkable new keypair (spec §9.10.4.A).
   */
  deriveRotatablePseudonym(
    keyId: string,
    contextId: Uint8Array,
    pseudonymEpoch: bigint,
  ): Uint8Array;
  /**
   * Return the 32 raw Ed25519 private-seed bytes for `keyId`.
   *
   * Hardware-bound / sign-only custody that cannot surface raw bytes should
   * throw. The throw is handled differently per call site: best-effort callers
   * (the §9.10.4 pseudonym announcement emitted on context join/import) catch it
   * and silently skip the announcement — peers recover on the next explicit
   * announcement — whereas callers that strictly require the raw key (governance
   * vote signing via {@link SCP.identityCreateWithCustody}) surface a hard error.
   */
  exportSigningKeyBytes(keyId: string): Uint8Array;
  /** Return `"hardware"`, `"software"`, or `"in_memory"`. */
  custodyType(keyId: string): string;
}

// ---------------------------------------------------------------------------
// SCP class
// ---------------------------------------------------------------------------

/**
 * Module-private WeakMap of real native handles keyed by their owning
 * {@link SCP} instance.
 *
 * The constructor populates this from the caller-supplied/addon-loaded
 * native. Module-level helpers (`__getNativeScp`) read from it. The
 * WeakMap is never exported; the only way to reach it from outside
 * this file is via those helpers. Handles cannot be swapped out once
 * set — there is no mutator exposed on the class or at the module
 * level.
 *
 * Closes round-2 security finding HIGH: the prior design used
 * Symbol-keyed accessors on the `SCP` prototype, reachable via
 * `Object.getOwnPropertySymbols(SCP.prototype)`. Any in-realm code
 * could swap the native bridge. WeakMap storage eliminates that
 * enumeration path.
 *
 * @internal
 */
const nativeHandles = new WeakMap<SCP, NativeScpInstance>();

// Post-construction native swaps were removed in round-3 cleanup. The only
// way to mount a mock is via `__constructScpWithNativeForTests` which
// populates `#native` at construction time so every class method sees the
// mock. `__getNativeScp` reads from `nativeHandles` directly (no override
// path). See BLACK-PR5-003 finding.

/**
 * Module-private symbol used to smuggle a pre-constructed native handle
 * into the `SCP` constructor, bypassing the addon-loading path. Only
 * the test helper `__constructScpWithNativeForTests` knows about this
 * key — production callers cannot hit it. Safe because it is never
 * placed on a live object (options-bag-only key).
 *
 * @internal
 */
const NATIVE_OVERRIDE: unique symbol = Symbol("scp.nativeOverride");

/**
 * Caller-owned SCP instance — the sole SDK entry point.
 *
 * Each `SCP` wraps an independent native `BridgeInstance`. Every NAPI
 * bridge operation is exposed as an instance method; callers should
 * invoke `scp.identityCreate(...)`, `scp.contextCreate(...)` etc.
 * directly (ADR-048 per-instance routing).
 *
 * Handle-returning methods wrap the raw NAPI handle in the
 * corresponding opaque SDK class (e.g. {@link Identity}, {@link Context},
 * {@link Relay}, {@link Node}). Transport and MCP handles are returned
 * as opaque `unknown` — callers pass them back to other `SCP` methods
 * verbatim. Methods that return primitive values or JSON strings pass
 * through unchanged.
 */
export class SCP {
  /**
   * The native NAPI `SCP` handle. Private (`#`-prefixed so it isn't
   * even accessible by name outside this class). Sibling SDK modules
   * that need to dispatch through the raw addon go through the
   * module-level `__getNativeScp` helper, which reads a companion
   * WeakMap populated from the constructor.
   */
  readonly #native: NativeScpInstance;

  /**
   * Constructs a fresh `SCP` instance.
   *
   * Storage selection is **mandatory** and fail-closed (spec §17.6):
   * `options.storage` is required, so `new SCP()` (no argument) is a
   * compile error. There is no default backend.
   *
   * @param options Constructor options; `options.storage` is required.
   * @throws {ValidationError} If no NAPI addon is available — code `SCP-VALID-7005`.
   */
  constructor(options: ScpOptions) {
    // Runtime fail-closed guard (spec §17.6): the TS type makes
    // `options.storage` mandatory, but a JS caller — or TS that defeats the
    // types via `any` or a type-suppression directive — can still reach here
    // with `new SCP()` or `new SCP({})`. Guard BEFORE dereferencing
    // `options.storage`, so a missing selection surfaces the documented
    // storage-selection error rather than a cryptic "cannot read properties
    // of undefined" TypeError.
    if (options == null) {
      throw new ValidationError(
        'storage selection is required: pass { storage: { type: "in_memory" } } ' +
          '(development) or { storage: { type: "sqlite", ... } } (production). ' +
          "There is no default storage.",
        "SCP-STORAGE-8000",
      );
    }
    // Test-only escape hatch: if a pre-built native handle is smuggled
    // via the (non-exported) `NATIVE_OVERRIDE` symbol, skip addon
    // loading entirely. Only reachable from `__constructScpWithNativeForTests`.
    const override = (options as { [NATIVE_OVERRIDE]?: NativeScpInstance })[NATIVE_OVERRIDE];
    if (override !== undefined) {
      this.#native = override;
    } else {
      // Storage selection is required — there is no in-memory default
      // (spec §17.6). Guard the missing-selection case here so a JS/`any`
      // caller gets the documented `SCP-STORAGE-8000` rather than the native
      // factory's lower-level error; the native `withStorage` factory then
      // fails closed on an unknown `type`.
      if (options.storage === undefined) {
        throw new ValidationError(
          'storage selection is required: pass { storage: { type: "in_memory" } } ' +
            '(development) or { storage: { type: "sqlite", ... } } (production). ' +
            "There is no default storage.",
          "SCP-STORAGE-8000",
        );
      }
      const NativeScp = nativeScp();
      this.#native = NativeScp.withStorage(serializeStorageConfig(options.storage));
    }
    // Expose the handle to sibling SDK modules via a module-local
    // WeakMap. Production code paths (~180 methods on this class) use
    // `this.#native` directly; only SDK modules that need to dispatch
    // through the raw addon (server.ts, internal/native.ts, mcp.ts)
    // reach via `__getNativeScp(scp)`.
    nativeHandles.set(this, this.#native);
  }

  /**
   * Monotonic identifier for this bridge instance, returned as a
   * base-10 string because u64 exceeds JavaScript's safe-integer range.
   */
  get instanceId(): string {
    return this.#native.instanceId;
  }

  // ───────────────────────────────────────────────────────────────────────
  // Lifecycle
  // ───────────────────────────────────────────────────────────────────────

  /**
   * Suspends this bridge instance (mobile/desktop backgrounding).
   *
   * Disconnects transport and marks the instance suspended.
   * Transport-dependent operations fail until `resume()` is called.
   */
  suspend(): void {
    try {
      this.#native.suspend();
    } catch (err) {
      throw mapBridgeError(err);
    }
  }

  /**
   * Resumes a suspended bridge instance. Awaits transport reconnect
   * and persisted context-snapshot restoration (#1678).
   */
  async resume(): Promise<void> {
    try {
      await this.#native.resume();
    } catch (err) {
      throw mapBridgeError(err);
    }
  }

  /**
   * Shuts down the instance with a graceful deadline.
   *
   * @param timeoutSecs Maximum seconds to wait. Defaults to 5.
   */
  async shutdown(timeoutSecs: number = 5): Promise<void> {
    try {
      const millis = __clampShutdownMillisForTests(timeoutSecs);
      await this.#native.shutdown(BigInt(millis));
    } catch (err) {
      throw mapBridgeError(err);
    }
  }

  // ───────────────────────────────────────────────────────────────────────
  // Domain: Identity
  // ───────────────────────────────────────────────────────────────────────

  async identityCreate(custody: string = "in_memory"): Promise<Identity> {
    try {
      const raw = await (this.#native.identityCreate as (c: string) => Promise<unknown>)(custody);
      const { Identity: IdentityCls } = await import("./identity");
      return IdentityCls._fromHandle(this, raw);
    } catch (err) {
      throw mapBridgeError(err);
    }
  }

  async identityCreateWithAgentKey(custody: string = "in_memory"): Promise<Identity> {
    try {
      const raw = await (
        this.#native.identityCreateWithAgentKey as (c: string) => Promise<unknown>
      )(custody);
      const { Identity: IdentityCls } = await import("./identity");
      return IdentityCls._fromHandle(this, raw);
    } catch (err) {
      throw mapBridgeError(err);
    }
  }

  /**
   * Create a DID whose key material lives in a caller-provided custody backend.
   *
   * `provider` is any object implementing {@link KeyCustodyProvider} — the
   * private key material never crosses into the native core (ADR-006). Use this
   * to back a DID with an OS keychain, hardware token, or HSM wrapper.
   *
   * Node.js / Bun only: the browser (WASM) build of `@limn-works/scp-ts` does
   * not expose the `SCP` class (ADR-034 / ADR-048), so calling `new SCP(...)`
   * there already throws before this method is reachable.
   *
   * @throws ValidationError if the provider is missing required methods, or
   *   IdentityError if key/DID creation fails inside the provider.
   */
  async identityCreateWithCustody(provider: KeyCustodyProvider): Promise<Identity> {
    // Validate provider completeness up front. The byte-converting adapter
    // below always supplies all nine closures, so a provider missing a method
    // would otherwise surface only later as a cryptic native "oneshot canceled"
    // failure. Checking here makes the returned promise reject early with a
    // clear, actionable error. Mirrors the nine methods on KeyCustodyProvider.
    const REQUIRED = [
      "generateKeypair",
      "sign",
      "getPublicKey",
      "destroyKey",
      "dhAgree",
      "derivePseudonym",
      "deriveRotatablePseudonym",
      "exportSigningKeyBytes",
      "custodyType",
    ] as const;
    for (const method of REQUIRED) {
      if (typeof (provider as unknown as Record<string, unknown>)[method] !== "function") {
        throw new ValidationError(
          `KeyCustodyProvider is missing required method: ${method}`,
          "SCP-VALID-7005",
        );
      }
    }
    // NAPI marshals each provider method as a ThreadsafeFunction WITHOUT
    // preserving `this`, and Rust `Vec<u8>` crosses the wire as a JS
    // `Array<number>` (not `Uint8Array`). The adapter below (a) closes over
    // `provider` in each arrow so `this` is bound, and (b) converts byte args
    // inbound (`Array<number>` → `Uint8Array`) and byte returns outbound
    // (`Uint8Array` → `Array<number>`). Methods with no byte payload
    // (`generateKeypair`, `destroyKey`, `custodyType`) pass through unchanged.
    // Additionally, napi-rs delivers a multi-element Rust tuple
    // (`(String, Vec<u8>)`) to the JS callback as a SINGLE `[keyId, bytes]`
    // array argument — not as two positional args — so the tuple callbacks
    // (`sign`, `dhAgree`, `derivePseudonym`) accept one array and destructure
    // it. Single-value callbacks receive their positional argument normally.
    const adapter = {
      generateKeypair: (keyType: string): string => provider.generateKeypair(keyType),
      // napi-rs delivers a `(String, Vec<u8>)` tuple as a single `[keyId, bytes]`
      // array arg (not positional), so the two-value callbacks destructure it.
      sign: ([keyId, message]: [string, number[]]): number[] =>
        Array.from(provider.sign(keyId, Uint8Array.from(message))),
      getPublicKey: (keyId: string): number[] => Array.from(provider.getPublicKey(keyId)),
      destroyKey: (keyId: string): void => provider.destroyKey(keyId),
      dhAgree: ([keyId, peerPublic]: [string, number[]]): number[] =>
        Array.from(provider.dhAgree(keyId, Uint8Array.from(peerPublic))),
      derivePseudonym: ([keyId, contextId]: [string, number[]]): number[] =>
        Array.from(provider.derivePseudonym(keyId, Uint8Array.from(contextId))),
      // The Rust `(String, Vec<u8>, u64)` tuple likewise arrives as a single
      // `[keyId, contextId, epoch]` array; the `u64` epoch crosses as a JS
      // `bigint` (the field's declared `ts_type`).
      deriveRotatablePseudonym: ([keyId, contextId, epoch]: [string, number[], bigint]): number[] =>
        Array.from(provider.deriveRotatablePseudonym(keyId, Uint8Array.from(contextId), epoch)),
      // A sign-only / hardware / secure-enclave custody throws here to signal it
      // cannot export raw private-key bytes (ADR-006). Translate that into the
      // native error channel by returning an empty array (the Rust bridge's
      // 32-byte check then yields `Err`): §9.10.4 best-effort paths — e.g. the
      // post-create / post-import `PseudonymAnnouncement`, which signs via the
      // exported key — skip gracefully, while required callers surface a custody
      // error. Returning a value rather than re-throwing keeps the provider's
      // synchronous exception from leaking into the host's unhandled-exception
      // tracking (which would spuriously fail tests) while preserving the
      // fail-closed contract. Signing itself never uses this path — it goes
      // through `KeyCustody::sign` — so sign-only custody can still produce a
      // signed export.
      exportSigningKeyBytes: (keyId: string): number[] => {
        try {
          return Array.from(provider.exportSigningKeyBytes(keyId));
        } catch {
          return [];
        }
      },
      custodyType: (keyId: string): string => provider.custodyType(keyId),
    };
    try {
      const raw = await (
        this.#native.identityCreateWithCustody as (p: typeof adapter) => Promise<unknown>
      )(adapter);
      const { Identity: IdentityCls } = await import("./identity");
      return IdentityCls._fromHandle(this, raw);
    } catch (err) {
      throw mapBridgeError(err);
    }
  }

  async identityLoad(did: string): Promise<Identity> {
    try {
      const raw = await (this.#native.identityLoad as (d: string) => Promise<unknown>)(did);
      const { Identity: IdentityCls } = await import("./identity");
      return IdentityCls._fromHandle(this, raw);
    } catch (err) {
      throw mapBridgeError(err);
    }
  }

  // The five identity-lifecycle operations below act on the identity HANDLE,
  // not on the `Scp` class: the NAPI bridge implements them as methods on the
  // `NapiIdentity` handle (`handle.rotateKey()`, `handle.migrate()`, …) and the
  // WASM bridge as `identity_*` free functions. Both are surfaced uniformly
  // through the per-instance `Bridge` (`getBridge(this)`), so these wrappers
  // route through the bridge rather than `this.#native` (which is the `Scp`
  // class and does not expose them). The returned `BridgeIdentityHandle` is
  // re-wrapped into an {@link Identity}.

  /**
   * Rotates the `#active` signing key for an identity, publishing the updated
   * DID document (spec §9.12, ADR-003). The old key is retired; the returned
   * {@link Identity} carries the same DID with the rotated key material.
   *
   * @param identity The identity whose `#active` key to rotate.
   * @returns The updated {@link Identity} (same DID, new key).
   */
  async identityRotateKey(identity: Identity): Promise<Identity> {
    try {
      const bridge = await getBridge(this);
      const raw = await bridge.identityRotateKey(identity._rawHandle);
      const { Identity: IdentityCls } = await import("./identity");
      return IdentityCls._fromHandle(this, raw);
    } catch (err) {
      throw mapBridgeError(err);
    }
  }

  /**
   * Migrates an identity across a custody or device boundary (spec §9.12,
   * ADR-003 §4b). Migration reveals the pre-rotation key and publishes
   * a new DID document, creating an identity with a **NEW DID** — the
   * returned {@link Identity} has a different DID from the input.
   *
   * The returned handle carries a `rotationEventJson` field (a serialized
   * `scp_identity::DidRotationEvent`). Callers **MUST** distribute this
   * rotation event to all active context members (spec §9.12, ADR-003 §4b)
   * so peers can update their routing tables. Access it via
   * `identity.rotationEventJson` on the returned `Identity`.
   *
   * Use {@link identityRotateKey} instead when you need to renew the
   * `#active` signing key while preserving the same DID.
   *
   * @param identity The identity to migrate.
   * @returns The migrated {@link Identity} with a NEW DID.
   */
  async identityMigrate(identity: Identity): Promise<Identity> {
    try {
      const bridge = await getBridge(this);
      const raw = await bridge.identityMigrate(identity._rawHandle);
      const { Identity: IdentityCls } = await import("./identity");
      return IdentityCls._fromHandle(this, raw);
    } catch (err) {
      throw mapBridgeError(err);
    }
  }

  /**
   * Adds an `#agent` delegation key to an identity's DID document (spec §9.12,
   * ADR-003), enabling agent-scoped capability delegation distinct from the
   * human-bound `#active` key.
   *
   * @param identity The identity to add an agent key to.
   * @returns The updated {@link Identity}.
   */
  async identityAddAgentKey(identity: Identity): Promise<Identity> {
    try {
      const bridge = await getBridge(this);
      const raw = await bridge.identityAddAgentKey(identity._rawHandle);
      const { Identity: IdentityCls } = await import("./identity");
      return IdentityCls._fromHandle(this, raw);
    } catch (err) {
      throw mapBridgeError(err);
    }
  }

  /**
   * Rotates the `#agent` delegation key for an identity, retiring the prior
   * agent key and publishing the updated DID document (spec §9.12, ADR-003).
   *
   * @param identity The identity whose `#agent` key to rotate.
   * @returns The updated {@link Identity}.
   */
  async identityRotateAgentKey(identity: Identity): Promise<Identity> {
    try {
      const bridge = await getBridge(this);
      const raw = await bridge.identityRotateAgentKey(identity._rawHandle);
      const { Identity: IdentityCls } = await import("./identity");
      return IdentityCls._fromHandle(this, raw);
    } catch (err) {
      throw mapBridgeError(err);
    }
  }

  /**
   * Removes the `#agent` delegation key from an identity's DID document
   * (spec §9.12, ADR-003), revoking agent-scoped delegation for this DID.
   *
   * @param identity The identity whose `#agent` key to remove.
   * @returns The updated {@link Identity}.
   */
  async identityRemoveAgentKey(identity: Identity): Promise<Identity> {
    try {
      const bridge = await getBridge(this);
      const raw = await bridge.identityRemoveAgentKey(identity._rawHandle);
      const { Identity: IdentityCls } = await import("./identity");
      return IdentityCls._fromHandle(this, raw);
    } catch (err) {
      throw mapBridgeError(err);
    }
  }

  async identityResolve(did: string): Promise<unknown> {
    try {
      return await (this.#native.identityResolve as (d: string) => Promise<unknown>)(did);
    } catch (err) {
      throw mapBridgeError(err);
    }
  }

  identityRemove(did: string): void {
    try {
      (this.#native.identityRemove as (d: string) => void)(did);
    } catch (err) {
      throw mapBridgeError(err);
    }
  }

  identityRemoveIfPresent(did: string): boolean {
    try {
      return (this.#native.identityRemoveIfPresent as (d: string) => boolean)(did);
    } catch (err) {
      throw mapBridgeError(err);
    }
  }

  async identityAttestDevice(did: string): Promise<string> {
    try {
      return await (this.#native.identityAttestDevice as (d: string) => Promise<string>)(did);
    } catch (err) {
      throw mapBridgeError(err);
    }
  }

  async identityVerifyDeviceAttestation(did: string, tokenBase64: string): Promise<boolean> {
    try {
      return await (
        this.#native.identityVerifyDeviceAttestation as (d: string, t: string) => Promise<boolean>
      )(did, tokenBase64);
    } catch (err) {
      throw mapBridgeError(err);
    }
  }

  async identityCreateLinkAttestation(
    did: string,
    platform: string,
    handle: string,
    proof: string,
    verificationMethod: string,
    platformId?: string | null,
  ): Promise<string> {
    try {
      return await (
        this.#native.identityCreateLinkAttestation as (
          d: string,
          p: string,
          h: string,
          pr: string,
          vm: string,
          pid: string | null | undefined,
        ) => Promise<string>
      )(did, platform, handle, proof, verificationMethod, platformId ?? null);
    } catch (err) {
      throw mapBridgeError(err);
    }
  }

  identityLinkAttestations(did: string): string {
    try {
      return (this.#native.identityLinkAttestations as (d: string) => string)(did);
    } catch (err) {
      throw mapBridgeError(err);
    }
  }

  identityRemoveLinkAttestation(did: string, attestationId: string): boolean {
    try {
      return (this.#native.identityRemoveLinkAttestation as (d: string, a: string) => boolean)(
        did,
        attestationId,
      );
    } catch (err) {
      throw mapBridgeError(err);
    }
  }

  async identityVerifyLinkAttestation(
    attestationJson: string,
    issuerPublicKeyHex: string,
  ): Promise<boolean> {
    // ADR-048 §1: pure Ed25519 signature verification, routed through the
    // addon's module-level free fn (the `Scp::identity_verify_link_attestation`
    // method was deleted in PR-E #28 along with its `let _ = &self.inner;`
    // gate-defang). Surface stays async for SDK ABI stability; the underlying
    // call is sync.
    const fn = nativeFreeFn<(j: string, k: string) => boolean>("identityVerifyLinkAttestation");
    try {
      return fn(attestationJson, issuerPublicKeyHex);
    } catch (err) {
      throw mapBridgeError(err);
    }
  }

  identityExecuteRecovery(did: string, tier: string, contextIds: readonly string[]): string {
    try {
      return (
        this.#native.identityExecuteRecovery as (
          d: string,
          t: string,
          c: readonly string[],
        ) => string
      )(did, tier, contextIds);
    } catch (err) {
      throw mapBridgeError(err);
    }
  }

  identityExecuteCustodyMigration(
    did: string,
    target: string,
    contextIds: readonly string[],
  ): string {
    try {
      return (
        this.#native.identityExecuteCustodyMigration as (
          d: string,
          t: string,
          c: readonly string[],
        ) => string
      )(did, target, contextIds);
    } catch (err) {
      throw mapBridgeError(err);
    }
  }

  // ───────────────────────────────────────────────────────────────────────
  // Domain: Petname
  // ───────────────────────────────────────────────────────────────────────

  petnameSet(ownerDid: string, targetDid: string, name: string): void {
    try {
      (this.#native.petnameSet as (o: string, t: string, n: string) => void)(
        ownerDid,
        targetDid,
        name,
      );
    } catch (err) {
      throw mapBridgeError(err);
    }
  }

  petnameRemove(ownerDid: string, targetDid: string): void {
    try {
      (this.#native.petnameRemove as (o: string, t: string) => void)(ownerDid, targetDid);
    } catch (err) {
      throw mapBridgeError(err);
    }
  }

  petnameSetContext(ownerDid: string, contextId: string, name: string): void {
    try {
      (this.#native.petnameSetContext as (o: string, c: string, n: string) => void)(
        ownerDid,
        contextId,
        name,
      );
    } catch (err) {
      throw mapBridgeError(err);
    }
  }

  petnameRemoveContext(ownerDid: string, contextId: string): void {
    try {
      (this.#native.petnameRemoveContext as (o: string, c: string) => void)(ownerDid, contextId);
    } catch (err) {
      throw mapBridgeError(err);
    }
  }

  petnameResolveDid(ownerDid: string, name: string): string {
    try {
      return (this.#native.petnameResolveDid as (o: string, n: string) => string)(ownerDid, name);
    } catch (err) {
      throw mapBridgeError(err);
    }
  }

  petnameResolveContext(ownerDid: string, name: string): string {
    try {
      return (this.#native.petnameResolveContext as (o: string, n: string) => string)(
        ownerDid,
        name,
      );
    } catch (err) {
      throw mapBridgeError(err);
    }
  }

  petnameGetForDid(ownerDid: string, targetDid: string): string | null {
    try {
      return (this.#native.petnameGetForDid as (o: string, t: string) => string | null)(
        ownerDid,
        targetDid,
      );
    } catch (err) {
      throw mapBridgeError(err);
    }
  }

  petnameGetForContext(ownerDid: string, contextId: string): string | null {
    try {
      return (this.#native.petnameGetForContext as (o: string, c: string) => string | null)(
        ownerDid,
        contextId,
      );
    } catch (err) {
      throw mapBridgeError(err);
    }
  }

  petnameApplyEvent(ownerDid: string, eventJson: string): void {
    try {
      (this.#native.petnameApplyEvent as (o: string, e: string) => void)(ownerDid, eventJson);
    } catch (err) {
      throw mapBridgeError(err);
    }
  }

  petnameDidCount(ownerDid: string): number {
    try {
      return (this.#native.petnameDidCount as (o: string) => number)(ownerDid);
    } catch (err) {
      throw mapBridgeError(err);
    }
  }

  petnameContextCount(ownerDid: string): number {
    try {
      return (this.#native.petnameContextCount as (o: string) => number)(ownerDid);
    } catch (err) {
      throw mapBridgeError(err);
    }
  }

  // ───────────────────────────────────────────────────────────────────────
  // Domain: Handle / Scope / Address
  // ───────────────────────────────────────────────────────────────────────

  handleRegister(
    discoveryContextId: string,
    handle: string,
    targetJson: string,
    registrantDid: string,
    description?: string,
    tags?: readonly string[],
  ): string {
    try {
      return (
        this.#native.handleRegister as (
          d: string,
          h: string,
          t: string,
          r: string,
          desc: string | undefined,
          tags: readonly string[] | undefined,
        ) => string
      )(discoveryContextId, handle, targetJson, registrantDid, description, tags);
    } catch (err) {
      throw mapBridgeError(err);
    }
  }

  handleLookup(discoveryContextId: string, handle: string, typeFilter?: string): string {
    try {
      return (this.#native.handleLookup as (d: string, h: string, f: string | undefined) => string)(
        discoveryContextId,
        handle,
        typeFilter,
      );
    } catch (err) {
      throw mapBridgeError(err);
    }
  }

  handleDeregister(discoveryContextId: string, handle: string, did: string): string {
    try {
      return (this.#native.handleDeregister as (d: string, h: string, did: string) => string)(
        discoveryContextId,
        handle,
        did,
      );
    } catch (err) {
      throw mapBridgeError(err);
    }
  }

  scopeRegister(
    scopeContextId: string,
    name: string,
    targetContextId: string,
    relayUrls: readonly string[],
    registrantDid: string,
    description?: string,
    tags?: readonly string[],
  ): string {
    try {
      return (
        this.#native.scopeRegister as (
          sc: string,
          n: string,
          tc: string,
          r: readonly string[],
          rd: string,
          d: string | undefined,
          t: readonly string[] | undefined,
        ) => string
      )(scopeContextId, name, targetContextId, relayUrls, registrantDid, description, tags);
    } catch (err) {
      throw mapBridgeError(err);
    }
  }

  scopeLookup(scopeContextId: string, name: string): string {
    try {
      return (this.#native.scopeLookup as (sc: string, n: string) => string)(scopeContextId, name);
    } catch (err) {
      throw mapBridgeError(err);
    }
  }

  scopeDeregister(scopeContextId: string, name: string, did: string): string {
    try {
      return (this.#native.scopeDeregister as (sc: string, n: string, d: string) => string)(
        scopeContextId,
        name,
        did,
      );
    } catch (err) {
      throw mapBridgeError(err);
    }
  }

  async addressResolve(
    ownerDid: string,
    address: string,
    knownContextsJson?: string,
  ): Promise<string> {
    try {
      return await (
        this.#native.addressResolve as (
          o: string,
          a: string,
          k: string | undefined,
        ) => Promise<string>
      )(ownerDid, address, knownContextsJson);
    } catch (err) {
      throw mapBridgeError(err);
    }
  }

  // ───────────────────────────────────────────────────────────────────────
  // Domain: Context
  // ───────────────────────────────────────────────────────────────────────

  async contextCreate(identity: Identity, paramsJson: string): Promise<Context> {
    try {
      const raw = await (
        this.#native.contextCreate as (id: unknown, p: string) => Promise<unknown>
      )(identity._rawHandle, paramsJson);
      const { Context: ContextCls } = await import("./context");
      return ContextCls._fromHandle(this, raw as never, identity.did);
    } catch (err) {
      throw mapBridgeError(err);
    }
  }

  async contextJoin(
    handle: unknown,
    identityDid: string,
    spendingUcanJwt?: string | null,
  ): Promise<void> {
    try {
      await (
        this.#native.contextJoin as (h: unknown, d: string, s: string | null) => Promise<void>
      )(handle, identityDid, spendingUcanJwt ?? null);
    } catch (err) {
      throw mapBridgeError(err);
    }
  }

  /**
   * Test-only: seed a peer's per-context pseudonym routing ID (§9.10.4) into
   * this bridge's supervisor, simulating a delivered pseudonym announcement so
   * multi-member encrypted sends do not fail closed with `SCP-CTX-2095`.
   *
   * Only available on builds compiled with the `allow_in_memory_custody`
   * feature; never present in production builds.
   */
  async contextSeedPeerPseudonym(
    handle: unknown,
    peerDid: string,
    pseudonym: Uint8Array | Buffer,
  ): Promise<void> {
    try {
      await (
        this.#native.contextSeedPeerPseudonym as (
          h: unknown,
          p: string,
          ps: Uint8Array | Buffer,
        ) => Promise<void>
      )(handle, peerDid, pseudonym);
    } catch (err) {
      throw mapBridgeError(err);
    }
  }

  async contextLeave(handle: unknown, identityDid: string): Promise<void> {
    try {
      await (this.#native.contextLeave as (h: unknown, d: string) => Promise<void>)(
        handle,
        identityDid,
      );
    } catch (err) {
      throw mapBridgeError(err);
    }
  }

  async contextClose(handle: unknown, identityDid: string): Promise<void> {
    try {
      await (this.#native.contextClose as (h: unknown, d: string) => Promise<void>)(
        handle,
        identityDid,
      );
    } catch (err) {
      throw mapBridgeError(err);
    }
  }

  /**
   * Send an encrypted message to a context.
   *
   * @throws A typed `ContextError` with code `SCP-CTX-2095` when this is a
   * multi-member encrypted context and no peer has announced its routing ID
   * yet (§9.10.4): the send fails closed and is rolled back (no charge, no
   * event); retry once peers' pseudonym-announcement messages have been
   * delivered. A lone-member send is a no-op; broadcast contexts are unaffected.
   */
  async contextSend(
    handle: unknown,
    identityDid: string,
    payload: Uint8Array | readonly number[],
    spendingUcanJwt?: string | null,
  ): Promise<void> {
    try {
      const payloadArray = ArrayBuffer.isView(payload)
        ? Array.from(payload as Uint8Array)
        : (payload as readonly number[]);
      await (
        this.#native.contextSend as (
          h: unknown,
          d: string,
          p: readonly number[],
          s: string | null,
        ) => Promise<void>
      )(handle, identityDid, payloadArray, spendingUcanJwt ?? null);
    } catch (err) {
      throw mapBridgeError(err);
    }
  }

  async contextSubscribe(
    handle: unknown,
    identityDid: string,
    onMessage: (message: unknown) => void,
  ): Promise<void> {
    try {
      await (
        this.#native.contextSubscribe as (
          h: unknown,
          d: string,
          cb: (m: unknown) => void,
        ) => Promise<void>
      )(handle, identityDid, onMessage);
    } catch (err) {
      throw mapBridgeError(err);
    }
  }

  contextCancelSubscription(handle: unknown): void {
    try {
      (this.#native.contextCancelSubscription as (h: unknown) => void)(handle);
    } catch (err) {
      throw mapBridgeError(err);
    }
  }

  async contextMemberCount(handle: unknown): Promise<number> {
    try {
      return await (this.#native.contextMemberCount as (h: unknown) => Promise<number>)(handle);
    } catch (err) {
      throw mapBridgeError(err);
    }
  }

  async contextIsMember(handle: unknown, did: string): Promise<boolean> {
    try {
      return await (this.#native.contextIsMember as (h: unknown, d: string) => Promise<boolean>)(
        handle,
        did,
      );
    } catch (err) {
      throw mapBridgeError(err);
    }
  }

  async contextMemberDids(handle: unknown): Promise<readonly string[]> {
    try {
      return await (this.#native.contextMemberDids as (h: unknown) => Promise<readonly string[]>)(
        handle,
      );
    } catch (err) {
      throw mapBridgeError(err);
    }
  }

  async contextMemberRole(handle: unknown, did: string): Promise<string | null> {
    try {
      return await (
        this.#native.contextMemberRole as (h: unknown, d: string) => Promise<string | null>
      )(handle, did);
    } catch (err) {
      throw mapBridgeError(err);
    }
  }

  async contextDrainEvents(handle: unknown): Promise<readonly string[]> {
    try {
      return await (this.#native.contextDrainEvents as (h: unknown) => Promise<readonly string[]>)(
        handle,
      );
    } catch (err) {
      throw mapBridgeError(err);
    }
  }

  async contextRestore(contextId: string): Promise<void> {
    try {
      await (this.#native.contextRestore as (id: string) => Promise<void>)(contextId);
    } catch (err) {
      throw mapBridgeError(err);
    }
  }

  async contextRestoreAll(): Promise<string> {
    try {
      return await (this.#native.contextRestoreAll as () => Promise<string>)();
    } catch (err) {
      throw mapBridgeError(err);
    }
  }

  async contextTombstoneMigrated(handle: unknown): Promise<void> {
    try {
      await (this.#native.contextTombstoneMigrated as (h: unknown) => Promise<void>)(handle);
    } catch (err) {
      throw mapBridgeError(err);
    }
  }

  async contextMigrationState(handle: unknown): Promise<string | null> {
    try {
      return await (this.#native.contextMigrationState as (h: unknown) => Promise<string | null>)(
        handle,
      );
    } catch (err) {
      throw mapBridgeError(err);
    }
  }

  async contextExport(handle: unknown): Promise<Uint8Array> {
    try {
      const raw = await (
        this.#native.contextExport as (h: unknown) => Promise<Uint8Array | Buffer>
      )(handle);
      return new Uint8Array(raw);
    } catch (err) {
      throw mapBridgeError(err);
    }
  }

  /**
   * Imports a context from a signed export (ADR-050) and re-homes it under the
   * local member's identity.
   *
   * @param data Serialized `ContextExport` bytes, as produced by
   *   {@link contextExport}.
   * @param importerDid DID of the LOCAL member re-homing the context — the
   *   caller's own identity, distinct from the snapshot creator. Used to derive
   *   this member's own per-context pseudonym (§9.10.4). Must already be a
   *   member of the imported snapshot, otherwise the import is rejected with
   *   `SCP-CTX-2092`.
   * @returns The imported context's id.
   */
  async contextImport(data: Uint8Array | readonly number[], importerDid: string): Promise<string> {
    try {
      const dataArray = ArrayBuffer.isView(data)
        ? Array.from(data as Uint8Array)
        : (data as readonly number[]);
      return await (
        this.#native.contextImport as (d: readonly number[], did: string) => Promise<string>
      )(dataArray, importerDid);
    } catch (err) {
      throw mapBridgeError(err);
    }
  }

  contextSetEconomicPolicy(handle: unknown, policyJson: string): void {
    try {
      (this.#native.contextSetEconomicPolicy as (h: unknown, p: string) => void)(
        handle,
        policyJson,
      );
    } catch (err) {
      throw mapBridgeError(err);
    }
  }

  contextGetEconomicPolicy(handle: unknown): string | null {
    try {
      return (this.#native.contextGetEconomicPolicy as (h: unknown) => string | null)(handle);
    } catch (err) {
      throw mapBridgeError(err);
    }
  }

  // ───────────────────────────────────────────────────────────────────────
  // Domain: Broadcast / Access
  // ───────────────────────────────────────────────────────────────────────

  async accessKeyGenerate(contextId: string, memberDid: string, callerDid: string): Promise<void> {
    try {
      await (this.#native.accessKeyGenerate as (c: string, m: string, k: string) => Promise<void>)(
        contextId,
        memberDid,
        callerDid,
      );
    } catch (err) {
      throw mapBridgeError(err);
    }
  }

  async accessKeyRevoke(contextId: string, memberDid: string, callerDid: string): Promise<void> {
    try {
      await (this.#native.accessKeyRevoke as (c: string, m: string, k: string) => Promise<void>)(
        contextId,
        memberDid,
        callerDid,
      );
    } catch (err) {
      throw mapBridgeError(err);
    }
  }

  async accessKeyRestore(contextId: string, memberDid: string, callerDid: string): Promise<void> {
    try {
      await (this.#native.accessKeyRestore as (c: string, m: string, k: string) => Promise<void>)(
        contextId,
        memberDid,
        callerDid,
      );
    } catch (err) {
      throw mapBridgeError(err);
    }
  }

  async contextBroadcastSubscriberCount(handle: unknown): Promise<number | null> {
    try {
      return await (
        this.#native.contextBroadcastSubscriberCount as (h: unknown) => Promise<number | null>
      )(handle);
    } catch (err) {
      throw mapBridgeError(err);
    }
  }

  async contextIsBroadcastSubscriber(handle: unknown, did: string): Promise<boolean> {
    try {
      return await (
        this.#native.contextIsBroadcastSubscriber as (h: unknown, d: string) => Promise<boolean>
      )(handle, did);
    } catch (err) {
      throw mapBridgeError(err);
    }
  }

  async contextBroadcastAdmission(handle: unknown): Promise<string | null> {
    try {
      return await (
        this.#native.contextBroadcastAdmission as (h: unknown) => Promise<string | null>
      )(handle);
    } catch (err) {
      throw mapBridgeError(err);
    }
  }

  async broadcastSubscribe(handle: unknown, subscriberDid: string): Promise<void> {
    try {
      await (this.#native.broadcastSubscribe as (h: unknown, d: string) => Promise<void>)(
        handle,
        subscriberDid,
      );
    } catch (err) {
      throw mapBridgeError(err);
    }
  }

  async broadcastUnsubscribe(
    handle: unknown,
    subscriberDid: string,
    rotateKeys?: boolean,
  ): Promise<void> {
    try {
      await (
        this.#native.broadcastUnsubscribe as (
          h: unknown,
          d: string,
          r: boolean | undefined,
        ) => Promise<void>
      )(handle, subscriberDid, rotateKeys);
    } catch (err) {
      throw mapBridgeError(err);
    }
  }

  async broadcastPublish(
    handle: unknown,
    authorDid: string,
    payload: Uint8Array | readonly number[],
  ): Promise<void> {
    try {
      const payloadArray = ArrayBuffer.isView(payload)
        ? Array.from(payload as Uint8Array)
        : (payload as readonly number[]);
      await (
        this.#native.broadcastPublish as (
          h: unknown,
          d: string,
          p: readonly number[],
        ) => Promise<void>
      )(handle, authorDid, payloadArray);
    } catch (err) {
      throw mapBridgeError(err);
    }
  }

  async broadcastPublishAsset(
    handle: unknown,
    authorDid: string,
    asset: { path: string; contentType: string; body: readonly number[] },
    deployId?: string | null,
  ): Promise<unknown> {
    try {
      return await (
        this.#native.broadcastPublishAsset as (
          h: unknown,
          d: string,
          a: { path: string; contentType: string; body: readonly number[] },
          did: string | null,
        ) => Promise<unknown>
      )(handle, authorDid, asset, deployId ?? null);
    } catch (err) {
      throw mapBridgeError(err);
    }
  }

  async broadcastPublishAssets(
    handle: unknown,
    authorDid: string,
    assets: readonly { path: string; contentType: string; body: readonly number[] }[],
    deployId?: string | null,
  ): Promise<unknown> {
    try {
      return await (
        this.#native.broadcastPublishAssets as (
          h: unknown,
          d: string,
          a: readonly { path: string; contentType: string; body: readonly number[] }[],
          did: string | null,
        ) => Promise<unknown>
      )(handle, authorDid, assets, deployId ?? null);
    } catch (err) {
      throw mapBridgeError(err);
    }
  }

  async broadcastBlockSubscriber(
    handle: unknown,
    subscriberDid: string,
    blockerDid: string,
  ): Promise<void> {
    try {
      await (
        this.#native.broadcastBlockSubscriber as (h: unknown, s: string, b: string) => Promise<void>
      )(handle, subscriberDid, blockerDid);
    } catch (err) {
      throw mapBridgeError(err);
    }
  }

  async broadcastUnblockSubscriber(
    handle: unknown,
    subscriberDid: string,
    unblockerDid: string,
  ): Promise<void> {
    try {
      await (
        this.#native.broadcastUnblockSubscriber as (
          h: unknown,
          s: string,
          u: string,
        ) => Promise<void>
      )(handle, subscriberDid, unblockerDid);
    } catch (err) {
      throw mapBridgeError(err);
    }
  }

  /**
   * Seals the author's current broadcast key to the requester's 32-byte
   * X25519 `wrappingPubkey` (HPKE, spec §5.14.2).
   *
   * On grant, returns a JSON string encoding the sealed broadcast key; feed
   * that exact string into {@link broadcastOpenKey} together with the X25519
   * `wrappingSecret` matching the `wrappingPubkey` presented here to recover
   * the raw key. On deny (§5.14.8 — a blocked, unregistered, or unauthorized
   * requester), returns `null` and no key material is produced. The raw
   * AES-256 broadcast key never crosses the FFI boundary; only sealed material
   * is returned.
   *
   * @param wrappingPubkey - the requester's 32-byte X25519 public key.
   */
  async broadcastHandleKeyRequest(
    handle: unknown,
    authorDid: string,
    requesterDid: string,
    wrappingPubkey: Uint8Array,
  ): Promise<string | null> {
    try {
      // NAPI Vec<u8> IN params map to number[] in JS, not Uint8Array.
      const wrappingArray = Array.from(wrappingPubkey) as unknown as number[];
      return await (
        this.#native.broadcastHandleKeyRequest as (
          h: unknown,
          a: string,
          r: string,
          w: number[],
        ) => Promise<string | null>
      )(handle, authorDid, requesterDid, wrappingArray);
    } catch (err) {
      throw mapBridgeError(err);
    }
  }

  /**
   * Opens an HPKE-sealed broadcast key (spec §5.14.2) using the subscriber's
   * 32-byte X25519 `wrappingSecret`, returning the raw 32-byte AES-256
   * broadcast key.
   *
   * `sealedJson` is the JSON string returned by
   * {@link broadcastHandleKeyRequest} on grant; `wrappingSecret` must match the
   * `wrappingPubkey` presented on that request. Pure crypto — no instance
   * state.
   *
   * @param sealedJson - the sealed-key JSON from `broadcastHandleKeyRequest`.
   * @param wrappingSecret - the subscriber's 32-byte X25519 secret.
   */
  // why: `broadcastOpenKey` is a module-level NAPI free function
  // (`#[napi] pub fn broadcast_open_key`), not an SCP-class method, so it
  // routes through `nativeFreeFn` per ADR-048 §1 rather than `this.#native`.
  // The Rust fn is synchronous; the returned Uint8Array is surfaced via this
  // async method's Promise.
  async broadcastOpenKey(sealedJson: string, wrappingSecret: Uint8Array): Promise<Uint8Array> {
    // NAPI Vec<u8> IN params map to number[] in JS; the Vec<u8> return is a
    // Buffer (a Uint8Array).
    const secretArray = Array.from(wrappingSecret) as unknown as number[];
    const fn = nativeFreeFn<(s: string, w: number[]) => Uint8Array>("broadcastOpenKey");
    try {
      return fn(sealedJson, secretArray);
    } catch (err) {
      throw mapBridgeError(err);
    }
  }

  // ───────────────────────────────────────────────────────────────────────
  // Domain: Governance
  // ───────────────────────────────────────────────────────────────────────

  async contextExecuteGovernanceAction(
    handle: unknown,
    actionJson: string,
    proposerDid: string,
  ): Promise<string> {
    try {
      return await (
        this.#native.contextExecuteGovernanceAction as (
          h: unknown,
          a: string,
          p: string,
        ) => Promise<string>
      )(handle, actionJson, proposerDid);
    } catch (err) {
      throw mapBridgeError(err);
    }
  }

  async contextGovernancePropose(
    handle: unknown,
    actionJson: string,
    proposerDid: string,
  ): Promise<string> {
    try {
      return await (
        this.#native.contextGovernancePropose as (
          h: unknown,
          a: string,
          p: string,
        ) => Promise<string>
      )(handle, actionJson, proposerDid);
    } catch (err) {
      throw mapBridgeError(err);
    }
  }

  async contextGovernanceApprove(
    handle: unknown,
    proposalIdHex: string,
    voterDid: string,
  ): Promise<string> {
    try {
      return await (
        this.#native.contextGovernanceApprove as (
          h: unknown,
          p: string,
          v: string,
        ) => Promise<string>
      )(handle, proposalIdHex, voterDid);
    } catch (err) {
      throw mapBridgeError(err);
    }
  }

  async contextGovernanceReject(
    handle: unknown,
    proposalIdHex: string,
    voterDid: string,
  ): Promise<string> {
    try {
      return await (
        this.#native.contextGovernanceReject as (
          h: unknown,
          p: string,
          v: string,
        ) => Promise<string>
      )(handle, proposalIdHex, voterDid);
    } catch (err) {
      throw mapBridgeError(err);
    }
  }

  async contextGovernanceWithdraw(
    handle: unknown,
    proposalIdHex: string,
    voterDid: string,
  ): Promise<string> {
    try {
      return await (
        this.#native.contextGovernanceWithdraw as (
          h: unknown,
          p: string,
          v: string,
        ) => Promise<string>
      )(handle, proposalIdHex, voterDid);
    } catch (err) {
      throw mapBridgeError(err);
    }
  }

  async contextGovernanceGetProposal(handle: unknown, proposalIdHex: string): Promise<string> {
    try {
      return await (
        this.#native.contextGovernanceGetProposal as (h: unknown, p: string) => Promise<string>
      )(handle, proposalIdHex);
    } catch (err) {
      throw mapBridgeError(err);
    }
  }

  async contextGovernanceListProposals(handle: unknown): Promise<string> {
    try {
      return await (this.#native.contextGovernanceListProposals as (h: unknown) => Promise<string>)(
        handle,
      );
    } catch (err) {
      throw mapBridgeError(err);
    }
  }

  async contextApplyPendingCeilingModification(
    handle: unknown,
    currentTimestamp: number,
  ): Promise<boolean> {
    try {
      return await (
        this.#native.contextApplyPendingCeilingModification as (
          h: unknown,
          t: number,
        ) => Promise<boolean>
      )(handle, currentTimestamp);
    } catch (err) {
      throw mapBridgeError(err);
    }
  }

  async contextFinalizeClose(handle: unknown): Promise<void> {
    try {
      await (this.#native.contextFinalizeClose as (h: unknown) => Promise<void>)(handle);
    } catch (err) {
      throw mapBridgeError(err);
    }
  }

  async contextCreateGovernanceCheckpoint(
    handle: unknown,
    checkpointSeq: number,
    merkleRootHex: string,
    eventCount: number,
    lastEventHashHex: string,
    stateSnapshotHashHex: string,
    creatorDid: string,
    creatorSignatureHex: string,
  ): Promise<string> {
    try {
      return await (
        this.#native.contextCreateGovernanceCheckpoint as (
          h: unknown,
          seq: number,
          root: string,
          count: number,
          lastHash: string,
          stateHash: string,
          creator: string,
          sig: string,
        ) => Promise<string>
      )(
        handle,
        checkpointSeq,
        merkleRootHex,
        eventCount,
        lastEventHashHex,
        stateSnapshotHashHex,
        creatorDid,
        creatorSignatureHex,
      );
    } catch (err) {
      throw mapBridgeError(err);
    }
  }

  async contextAddCheckpointCosignature(
    handle: unknown,
    checkpointJson: string,
    signerDid: string,
    signatureHex: string,
  ): Promise<string> {
    try {
      return await (
        this.#native.contextAddCheckpointCosignature as (
          h: unknown,
          c: string,
          s: string,
          sig: string,
        ) => Promise<string>
      )(handle, checkpointJson, signerDid, signatureHex);
    } catch (err) {
      throw mapBridgeError(err);
    }
  }

  // ───────────────────────────────────────────────────────────────────────
  // Domain: TTL / Migration
  // ───────────────────────────────────────────────────────────────────────

  async contextHandleTtlExpiry(handle: unknown): Promise<void> {
    try {
      await (this.#native.contextHandleTtlExpiry as (h: unknown) => Promise<void>)(handle);
    } catch (err) {
      throw mapBridgeError(err);
    }
  }

  async contextProposeTtlExtension(
    handle: unknown,
    proposerDid: string,
    extensionSecs: number,
  ): Promise<boolean> {
    try {
      return await (
        this.#native.contextProposeTtlExtension as (
          h: unknown,
          d: string,
          s: number,
        ) => Promise<boolean>
      )(handle, proposerDid, extensionSecs);
    } catch (err) {
      throw mapBridgeError(err);
    }
  }

  async contextResetTtlTimer(handle: unknown, newDurationSecs: number): Promise<void> {
    try {
      await (this.#native.contextResetTtlTimer as (h: unknown, s: number) => Promise<void>)(
        handle,
        newDurationSecs,
      );
    } catch (err) {
      throw mapBridgeError(err);
    }
  }

  /**
   * Reconnect `identityDid`'s contexts after an offline period.
   *
   * Runs the ADR-029 six-phase reconnection protocol for each context in
   * `contextIds` flagged `needsReconnect` (§23.11). The driver lives at the
   * FFI relay-client layer: it pulls relay-buffered messages via the
   * `TransportManager` and reaches actor-owned reconnection state (MLS epoch,
   * Commit/Welcome processing, checkpoint build/compare, MLS update) through
   * the `Supervisor`. On success each context's `needsReconnect` flag is
   * cleared.
   *
   * `lastRelayContacts` maps context id to last-relay-contact Unix seconds
   * (used to classify the offline tier); absent contexts default to the most
   * conservative tier.
   *
   * Requires an active relay connection (call `transportConnect` first).
   *
   * Key resolution: this backend (NAPI / Python) takes the `identityDid`
   * **string** and resolves the local member's signing key from the bridge's
   * identity registry. The Swift / Kotlin SDKs instead take the opaque
   * `Identity` object directly (`reconnect(identity:…)`) — same protocol, only
   * the argument shape differs per the UniFFI object-handle convention.
   *
   * Catch-up integrity (§9.9.3, §23.7): equivocation where a peer reports the
   * **same** event count with a **different** Merkle root IS detected and
   * surfaced (per-context {@link ContextReconnectResult.equivocationsDetected}).
   * However, reconnection catch-up does NOT yet verify suffix integrity — the
   * Merkle consistency proof confirming that fetched events genuinely extend
   * this member's own history is specified separately. An equivocating relay
   * that keeps a member perpetually *behind* (never reaching equal count) is
   * therefore not yet detected on the catch-up path.
   */
  async reconnect(
    identityDid: string,
    contextIds: readonly string[],
    lastRelayContacts?: Readonly<Record<string, number>>,
  ): Promise<ReconnectReport> {
    try {
      return await (
        this.#native.contextReconnect as (
          did: string,
          ids: readonly string[],
          contacts: Readonly<Record<string, number>> | undefined,
        ) => Promise<ReconnectReport>
      )(identityDid, contextIds, lastRelayContacts);
    } catch (err) {
      throw mapBridgeError(err);
    }
  }

  // ───────────────────────────────────────────────────────────────────────
  // Domain: Capability / Invitation / Metadata
  // ───────────────────────────────────────────────────────────────────────

  validateCapabilityDeclaration(
    declarationJson: string,
    ceilingCapabilities: readonly string[],
    roleCapabilities: readonly string[],
  ): string {
    try {
      return (
        this.#native.validateCapabilityDeclaration as (
          d: string,
          c: readonly string[],
          r: readonly string[],
        ) => string
      )(declarationJson, ceilingCapabilities, roleCapabilities);
    } catch (err) {
      throw mapBridgeError(err);
    }
  }

  checkScopedCapability(
    grantedCapabilities: readonly string[],
    requiredCapability: string,
  ): boolean {
    // ADR-048 §1: pure helper, routed to the addon's module-level free fn
    // (the `SCP::check_scoped_capability` method was deleted in PR-E #28).
    const fn = nativeFreeFn<(g: string[], r: string) => boolean>("checkScopedCapability");
    try {
      return fn([...grantedCapabilities], requiredCapability);
    } catch (err) {
      throw mapBridgeError(err);
    }
  }

  evaluateInvitation(
    paramsJson: string,
    inviterDid: string,
    identityDid: string,
    policyJson?: string | null,
    spendingJson?: string | null,
    trustedDidsJson?: string | null,
  ): unknown {
    try {
      return (
        this.#native.evaluateInvitation as (
          p: string,
          i: string,
          id: string,
          pol: string | null,
          sp: string | null,
          td: string | null,
        ) => unknown
      )(
        paramsJson,
        inviterDid,
        identityDid,
        policyJson ?? null,
        spendingJson ?? null,
        trustedDidsJson ?? null,
      );
    } catch (err) {
      throw mapBridgeError(err);
    }
  }

  metadataRecordToJson(
    contextId: string,
    sequence: number,
    signerDid: string,
    timestamp: number,
    structuralJson: string,
    operationalJson: string,
    signatureHex: string,
  ): string {
    try {
      return (
        this.#native.metadataRecordToJson as (
          c: string,
          s: number,
          sd: string,
          t: number,
          st: string,
          op: string,
          sig: string,
        ) => string
      )(contextId, sequence, signerDid, timestamp, structuralJson, operationalJson, signatureHex);
    } catch (err) {
      throw mapBridgeError(err);
    }
  }

  // The four pure protocol helpers below are method-shaped on `SCP` for
  // TS-local ergonomic consistency (ADR-048 §7), but the FFI Rust source
  // exposes them as module-level free functions per ADR-048 §1 (no
  // per-instance state to read). Each method routes to the addon's
  // module-level NAPI export; the `this` receiver carries no runtime
  // weight in these calls.

  metadataRecordFromJson(jsonStr: string): string {
    const fn = nativeFreeFn<(j: string) => string>("metadataRecordFromJson");
    try {
      return fn(jsonStr);
    } catch (err) {
      throw mapBridgeError(err);
    }
  }

  templateGetParams(templateId: string): string {
    const fn = nativeFreeFn<(t: string) => string>("templateGetParams");
    try {
      return fn(templateId);
    } catch (err) {
      throw mapBridgeError(err);
    }
  }

  validateAgainstTemplate(paramsJson: string): string | null {
    const fn = nativeFreeFn<(p: string) => string | null>("validateAgainstTemplate");
    try {
      return fn(paramsJson);
    } catch (err) {
      throw mapBridgeError(err);
    }
  }

  validateContextParams(paramsJson: string): string | null {
    const fn = nativeFreeFn<(p: string) => string | null>("validateContextParams");
    try {
      return fn(paramsJson);
    } catch (err) {
      throw mapBridgeError(err);
    }
  }

  // ───────────────────────────────────────────────────────────────────────
  // Domain: Tool
  // ───────────────────────────────────────────────────────────────────────

  async toolRegister(handle: unknown, definition: unknown): Promise<string> {
    try {
      return await (this.#native.toolRegister as (h: unknown, d: unknown) => Promise<string>)(
        handle,
        definition,
      );
    } catch (err) {
      throw mapBridgeError(err);
    }
  }

  async toolInvoke(
    handle: unknown,
    toolId: string,
    inputJson: string,
    identityDid: string,
    ucanToken: string,
    proofTokens?: readonly string[],
    spendingUcanJwt?: string,
  ): Promise<string> {
    try {
      return await (
        this.#native.toolInvoke as (
          h: unknown,
          t: string,
          i: string,
          d: string,
          u: string,
          p: readonly string[] | undefined,
          s: string | undefined,
        ) => Promise<string>
      )(handle, toolId, inputJson, identityDid, ucanToken, proofTokens, spendingUcanJwt);
    } catch (err) {
      throw mapBridgeError(err);
    }
  }

  async toolVerify(handle: unknown, toolId: string): Promise<unknown> {
    try {
      return await (this.#native.toolVerify as (h: unknown, t: string) => Promise<unknown>)(
        handle,
        toolId,
      );
    } catch (err) {
      throw mapBridgeError(err);
    }
  }

  async toolInvokeCrossContext(
    sourceHandle: unknown,
    targetHandle: unknown,
    toolId: string,
    inputJson: string,
    invokerDid: string,
    ucanToken: string,
    chainDepth: number,
    proofTokens?: readonly string[],
  ): Promise<string> {
    try {
      return await (
        this.#native.toolInvokeCrossContext as (
          s: unknown,
          t: unknown,
          tool: string,
          input: string,
          did: string,
          ucan: string,
          depth: number,
          proofs: readonly string[] | undefined,
        ) => Promise<string>
      )(
        sourceHandle,
        targetHandle,
        toolId,
        inputJson,
        invokerDid,
        ucanToken,
        chainDepth,
        proofTokens,
      );
    } catch (err) {
      throw mapBridgeError(err);
    }
  }

  async toolSessionCreate(
    handle: unknown,
    toolId: string,
    sourceContextId: string,
    ttlSeconds?: number,
  ): Promise<string> {
    try {
      return await (
        this.#native.toolSessionCreate as (
          h: unknown,
          t: string,
          s: string,
          ttl: number | undefined,
        ) => Promise<string>
      )(handle, toolId, sourceContextId, ttlSeconds);
    } catch (err) {
      throw mapBridgeError(err);
    }
  }

  async toolSessionInvoke(
    handle: unknown,
    sessionId: string,
    inputJson: string,
    invokerDid: string,
    ucanToken: string,
    proofTokens?: readonly string[],
  ): Promise<string> {
    try {
      return await (
        this.#native.toolSessionInvoke as (
          h: unknown,
          sid: string,
          input: string,
          did: string,
          ucan: string,
          proofs: readonly string[] | undefined,
        ) => Promise<string>
      )(handle, sessionId, inputJson, invokerDid, ucanToken, proofTokens);
    } catch (err) {
      throw mapBridgeError(err);
    }
  }

  async toolSessionClose(handle: unknown, sessionId: string): Promise<void> {
    try {
      await (this.#native.toolSessionClose as (h: unknown, sid: string) => Promise<void>)(
        handle,
        sessionId,
      );
    } catch (err) {
      throw mapBridgeError(err);
    }
  }

  async toolInterfaceExpose(
    handle: unknown,
    toolId: string,
    targetContextId: string,
    rateLimitJson?: string,
  ): Promise<string> {
    try {
      return await (
        this.#native.toolInterfaceExpose as (
          h: unknown,
          t: string,
          tc: string,
          rl: string | undefined,
        ) => Promise<string>
      )(handle, toolId, targetContextId, rateLimitJson);
    } catch (err) {
      throw mapBridgeError(err);
    }
  }

  async toolInterfaceAccept(handle: unknown, interfaceJson: string): Promise<string> {
    try {
      return await (
        this.#native.toolInterfaceAccept as (h: unknown, ij: string) => Promise<string>
      )(handle, interfaceJson);
    } catch (err) {
      throw mapBridgeError(err);
    }
  }

  async toolInterfaceRevoke(handle: unknown, interfaceIdHex: string): Promise<string> {
    try {
      return await (
        this.#native.toolInterfaceRevoke as (h: unknown, id: string) => Promise<string>
      )(handle, interfaceIdHex);
    } catch (err) {
      throw mapBridgeError(err);
    }
  }

  // ───────────────────────────────────────────────────────────────────────
  // Domain: UCAN
  // ───────────────────────────────────────────────────────────────────────

  async ucanValidate(
    handle: unknown,
    token: string,
    capability: string,
    presentingAgentDid?: string,
    proofTokens?: readonly string[],
  ): Promise<void> {
    try {
      await (
        this.#native.ucanValidate as (
          h: unknown,
          t: string,
          c: string,
          pa: string | undefined,
          pt: readonly string[] | undefined,
        ) => Promise<void>
      )(handle, token, capability, presentingAgentDid, proofTokens);
    } catch (err) {
      throw mapBridgeError(err);
    }
  }

  async ucanMint(
    handle: unknown,
    memberDid: string,
    capabilities: readonly string[],
    proofs?: readonly string[],
  ): Promise<unknown> {
    try {
      return await (
        this.#native.ucanMint as (
          h: unknown,
          d: string,
          c: readonly string[],
          p: readonly string[] | undefined,
        ) => Promise<unknown>
      )(handle, memberDid, capabilities, proofs);
    } catch (err) {
      throw mapBridgeError(err);
    }
  }

  async ucanDelegate(
    handle: unknown,
    delegatorDid: string,
    delegateeDid: string,
    parentToken: string,
    capabilities: readonly string[],
  ): Promise<unknown> {
    try {
      return await (
        this.#native.ucanDelegate as (
          h: unknown,
          from: string,
          to: string,
          parent: string,
          caps: readonly string[],
        ) => Promise<unknown>
      )(handle, delegatorDid, delegateeDid, parentToken, capabilities);
    } catch (err) {
      throw mapBridgeError(err);
    }
  }

  async ucanRevoke(handle: unknown, token: string, revokerDid: string): Promise<void> {
    try {
      await (this.#native.ucanRevoke as (h: unknown, t: string, r: string) => Promise<void>)(
        handle,
        token,
        revokerDid,
      );
    } catch (err) {
      throw mapBridgeError(err);
    }
  }

  // ───────────────────────────────────────────────────────────────────────
  // Domain: Event log
  // ───────────────────────────────────────────────────────────────────────

  async eventLogQuery(handle: unknown, filterJson?: string): Promise<readonly unknown[]> {
    try {
      return await (
        this.#native.eventLogQuery as (
          h: unknown,
          f: string | undefined,
        ) => Promise<readonly unknown[]>
      )(handle, filterJson);
    } catch (err) {
      throw mapBridgeError(err);
    }
  }

  async eventLogVerify(handle: unknown, claimJson: string): Promise<unknown> {
    try {
      return await (this.#native.eventLogVerify as (h: unknown, c: string) => Promise<unknown>)(
        handle,
        claimJson,
      );
    } catch (err) {
      throw mapBridgeError(err);
    }
  }

  eventLogCheckpoint(handle: unknown, identity: Identity, epoch: number): unknown {
    try {
      return (this.#native.eventLogCheckpoint as (h: unknown, i: unknown, e: number) => unknown)(
        handle,
        identity._rawHandle,
        epoch,
      );
    } catch (err) {
      throw mapBridgeError(err);
    }
  }

  eventLogCheckpointByDid(handle: unknown, did: string, epoch: number): unknown {
    try {
      return (
        this.#native.eventLogCheckpointByDid as (h: unknown, d: string, e: number) => unknown
      )(handle, did, epoch);
    } catch (err) {
      throw mapBridgeError(err);
    }
  }

  // ───────────────────────────────────────────────────────────────────────
  // Domain: Transport
  // ───────────────────────────────────────────────────────────────────────

  async transportConnect(relayUrl: string): Promise<unknown> {
    try {
      return await (this.#native.transportConnect as (u: string) => Promise<unknown>)(relayUrl);
    } catch (err) {
      throw mapBridgeError(err);
    }
  }

  async transportStatus(manager: unknown): Promise<unknown> {
    try {
      return await (this.#native.transportStatus as (m: unknown) => Promise<unknown>)(manager);
    } catch (err) {
      throw mapBridgeError(err);
    }
  }

  async transportDisconnect(manager: unknown): Promise<void> {
    try {
      await (this.#native.transportDisconnect as (m: unknown) => Promise<void>)(manager);
    } catch (err) {
      throw mapBridgeError(err);
    }
  }

  configureLocalTransport(localDid: string): void {
    try {
      (this.#native.configureLocalTransport as (d: string) => void)(localDid);
    } catch (err) {
      throw mapBridgeError(err);
    }
  }

  async configureRelayTransport(relayUrl: string, localDid: string): Promise<void> {
    try {
      await (this.#native.configureRelayTransport as (u: string, d: string) => Promise<void>)(
        relayUrl,
        localDid,
      );
    } catch (err) {
      throw mapBridgeError(err);
    }
  }

  async transportAddRelay(relayUrl: string): Promise<number> {
    try {
      return await (this.#native.transportAddRelay as (u: string) => Promise<number>)(relayUrl);
    } catch (err) {
      throw mapBridgeError(err);
    }
  }

  transportAssignRelaySet(contextId: string): readonly number[] {
    try {
      return (this.#native.transportAssignRelaySet as (c: string) => readonly number[])(contextId);
    } catch (err) {
      throw mapBridgeError(err);
    }
  }

  transportAdapterCount(): number {
    try {
      return (this.#native.transportAdapterCount as () => number)();
    } catch (err) {
      throw mapBridgeError(err);
    }
  }

  transportReliability(adapterIndex: number): unknown {
    try {
      return (this.#native.transportReliability as (i: number) => unknown)(adapterIndex);
    } catch (err) {
      throw mapBridgeError(err);
    }
  }

  // ───────────────────────────────────────────────────────────────────────
  // Domain: Economy
  // ───────────────────────────────────────────────────────────────────────

  economyEstimateCost(policyJson: string, actionType: string, metricsJson: string): number {
    try {
      return (this.#native.economyEstimateCost as (p: string, a: string, m: string) => number)(
        policyJson,
        actionType,
        metricsJson,
      );
    } catch (err) {
      throw mapBridgeError(err);
    }
  }

  economyPolicyRequiresPayment(policyJson: string): boolean {
    try {
      return (this.#native.economyPolicyRequiresPayment as (p: string) => boolean)(policyJson);
    } catch (err) {
      throw mapBridgeError(err);
    }
  }

  economyAutoAcceptBlocked(policyJson: string): boolean {
    try {
      return (this.#native.economyAutoAcceptBlocked as (p: string) => boolean)(policyJson);
    } catch (err) {
      throw mapBridgeError(err);
    }
  }

  economyCheckPolicyLock(policyJson: string): boolean {
    try {
      return (this.#native.economyCheckPolicyLock as (p: string) => boolean)(policyJson);
    } catch (err) {
      throw mapBridgeError(err);
    }
  }

  economyValidatePolicyChange(currentJson: string, proposedJson: string): boolean {
    try {
      return (this.#native.economyValidatePolicyChange as (c: string, p: string) => boolean)(
        currentJson,
        proposedJson,
      );
    } catch (err) {
      throw mapBridgeError(err);
    }
  }

  economyEvaluateFormula(formulaJson: string, metricsJson: string): number {
    try {
      return (this.#native.economyEvaluateFormula as (f: string, m: string) => number)(
        formulaJson,
        metricsJson,
      );
    } catch (err) {
      throw mapBridgeError(err);
    }
  }

  economyBudgetRemaining(contextId: string, did: string): number {
    try {
      return (this.#native.economyBudgetRemaining as (c: string, d: string) => number)(
        contextId,
        did,
      );
    } catch (err) {
      throw mapBridgeError(err);
    }
  }

  economyBudgetGrant(contextId: string, did: string, amount: number): void {
    try {
      (this.#native.economyBudgetGrant as (c: string, d: string, a: number) => void)(
        contextId,
        did,
        amount,
      );
    } catch (err) {
      throw mapBridgeError(err);
    }
  }

  economyBudgetRecordSpend(contextId: string, did: string, amount: number): void {
    try {
      (this.#native.economyBudgetRecordSpend as (c: string, d: string, a: number) => void)(
        contextId,
        did,
        amount,
      );
    } catch (err) {
      throw mapBridgeError(err);
    }
  }

  economyAntispamRecord(contextId: string, senderDid: string, timestamp: number): void {
    try {
      (this.#native.economyAntispamRecord as (c: string, s: string, t: number) => void)(
        contextId,
        senderDid,
        timestamp,
      );
    } catch (err) {
      throw mapBridgeError(err);
    }
  }

  economyAntispamVelocity(contextId: string, senderDid: string, now: number): number {
    try {
      return (this.#native.economyAntispamVelocity as (c: string, s: string, n: number) => number)(
        contextId,
        senderDid,
        now,
      );
    } catch (err) {
      throw mapBridgeError(err);
    }
  }

  economyAntispamEscalatedCost(
    contextId: string,
    senderDid: string,
    now: number,
    baseCost: number,
    thresholdsJson: string,
    floor?: number | null,
    cap?: number | null,
  ): number {
    try {
      return (
        this.#native.economyAntispamEscalatedCost as (
          c: string,
          s: string,
          n: number,
          b: number,
          t: string,
          f: number | null,
          cp: number | null,
        ) => number
      )(contextId, senderDid, now, baseCost, thresholdsJson, floor ?? null, cap ?? null);
    } catch (err) {
      throw mapBridgeError(err);
    }
  }

  /**
   * Verifies a batch of payment receipts against the configured payment
   * adapter. Maximum 10,000 receipts per call.
   *
   * `allValid` is `true` iff every entry both reached the adapter and the
   * adapter reported the receipt valid; it is vacuously `true` for an empty
   * batch. `ok` means the adapter *responded* — NOT that the payment is valid;
   * check `valid` / `allValid` for validity.
   *
   * @param receipts Array of receipt objects to verify. Each object shape is
   *   adapter-specific; the bridge serializes the array to JSON internally.
   * @returns Typed {@link PaymentReceiptVerificationResult} with `allValid`
   *   and per-receipt `results`.
   */
  economyVerifyPaymentReceipts(
    receipts: readonly Record<string, unknown>[],
  ): PaymentReceiptVerificationResult {
    try {
      const raw = (this.#native.economyVerifyPaymentReceipts as (r: string) => string)(
        JSON.stringify(receipts),
      );
      // The Rust bridge emits snake_case keys; map to the SDK's camelCase convention.
      const parsed = JSON.parse(raw) as {
        all_valid: boolean;
        results: Array<{
          ok: boolean;
          receipt_id?: string;
          valid?: boolean;
          result?: unknown;
          error?: string;
        }>;
      };
      return {
        allValid: parsed.all_valid,
        results: parsed.results.map((entry) => {
          const mapped: import("./economy").PaymentReceiptVerificationEntry = { ok: entry.ok };
          if (entry.receipt_id !== undefined) mapped.receiptId = entry.receipt_id;
          if (entry.valid !== undefined) mapped.valid = entry.valid;
          if (entry.result !== undefined)
            mapped.result = entry.result as Readonly<Record<string, unknown>>;
          if (entry.error !== undefined) mapped.error = entry.error;
          return mapped;
        }),
      };
    } catch (err) {
      throw mapBridgeError(err);
    }
  }

  // ───────────────────────────────────────────────────────────────────────
  // Domain: Trust
  // ───────────────────────────────────────────────────────────────────────

  trustQueryScore(did: string, contextId: string): unknown {
    try {
      return (this.#native.trustQueryScore as (d: string, c: string) => unknown)(did, contextId);
    } catch (err) {
      throw mapBridgeError(err);
    }
  }

  trustVerifyAttestation(attestationJson: string): unknown {
    try {
      return (this.#native.trustVerifyAttestation as (j: string) => unknown)(attestationJson);
    } catch (err) {
      throw mapBridgeError(err);
    }
  }

  trustCreateChallenge(targetDid: string): unknown {
    try {
      return (this.#native.trustCreateChallenge as (d: string) => unknown)(targetDid);
    } catch (err) {
      throw mapBridgeError(err);
    }
  }

  trustVerifyResponse(challengeJson: string, responseJson: string): boolean {
    try {
      return (this.#native.trustVerifyResponse as (c: string, r: string) => boolean)(
        challengeJson,
        responseJson,
      );
    } catch (err) {
      throw mapBridgeError(err);
    }
  }

  verifyParticipationRequirements(profileJson: string, requirementsJson: string): boolean {
    try {
      return (this.#native.verifyParticipationRequirements as (p: string, r: string) => boolean)(
        profileJson,
        requirementsJson,
      );
    } catch (err) {
      throw mapBridgeError(err);
    }
  }

  aggregateTrustInput(
    contextId: string,
    subjectDid: string,
    eventsJson: string,
    merkleRootJson: string,
    consequenceRulesJson: string,
    thresholdRequirementsJson: string,
    attestorSetsJson: string,
    cachedAttestationsJson: string,
    challengeResultsJson: string,
  ): string {
    try {
      return (
        this.#native.aggregateTrustInput as (
          ctx: string,
          subj: string,
          ev: string,
          mr: string,
          cr: string,
          tr: string,
          as: string,
          ca: string,
          cres: string,
        ) => string
      )(
        contextId,
        subjectDid,
        eventsJson,
        merkleRootJson,
        consequenceRulesJson,
        thresholdRequirementsJson,
        attestorSetsJson,
        cachedAttestationsJson,
        challengeResultsJson,
      );
    } catch (err) {
      throw mapBridgeError(err);
    }
  }

  // ───────────────────────────────────────────────────────────────────────
  // Domain: Relay / Node
  // ───────────────────────────────────────────────────────────────────────

  async relayStartInMemory(): Promise<Relay> {
    try {
      const raw = await (this.#native.relayStartInMemory as () => Promise<unknown>)();
      const { Relay: RelayCls } = await import("./server");
      return RelayCls._fromHandle(raw, this);
    } catch (err) {
      throw mapBridgeError(err);
    }
  }

  async relayStartLocal(dataDir: string): Promise<Relay> {
    try {
      const raw = await (this.#native.relayStartLocal as (d: string) => Promise<unknown>)(dataDir);
      const { Relay: RelayCls } = await import("./server");
      return RelayCls._fromHandle(raw, this);
    } catch (err) {
      throw mapBridgeError(err);
    }
  }

  async nodeStartInMemory(identityDid?: string | null): Promise<Node> {
    try {
      const raw = await (this.#native.nodeStartInMemory as (d: string | null) => Promise<unknown>)(
        identityDid ?? null,
      );
      const { Node: NodeCls } = await import("./server");
      return NodeCls._fromHandle(raw, this);
    } catch (err) {
      throw mapBridgeError(err);
    }
  }

  async nodeStartLocal(
    dataDir: string,
    identityDid?: string | null,
    passphrase?: string | null,
  ): Promise<Node> {
    try {
      const raw = await (
        this.#native.nodeStartLocal as (
          d: string,
          id: string | null,
          p: string | null,
        ) => Promise<unknown>
      )(dataDir, identityDid ?? null, passphrase ?? null);
      const { Node: NodeCls } = await import("./server");
      return NodeCls._fromHandle(raw, this);
    } catch (err) {
      throw mapBridgeError(err);
    }
  }

  // ───────────────────────────────────────────────────────────────────────
  // Domain: MCP
  // ───────────────────────────────────────────────────────────────────────

  async mcpServerCreate(config: unknown): Promise<unknown> {
    try {
      return await (this.#native.mcpServerCreate as (c: unknown) => Promise<unknown>)(config);
    } catch (err) {
      throw mapBridgeError(err);
    }
  }

  async mcpServerStop(handle: unknown): Promise<void> {
    try {
      await (this.#native.mcpServerStop as (h: unknown) => Promise<void>)(handle);
    } catch (err) {
      throw mapBridgeError(err);
    }
  }

  /**
   * Connect an MCP client via stdio transport.
   *
   * `command[0]` is validated against THIS instance's stdio allowlist
   * (per-instance — disabling enforcement on another `SCP` does not
   * affect this one). To permit a binary not in the default allowlist,
   * call {@link mcpConfigureStdioAllowlist} first; use
   * {@link mcpGetStdioAllowlist} to inspect the current state.
   */
  async mcpClientConnectStdio(command: readonly string[]): Promise<unknown> {
    try {
      return await (
        this.#native.mcpClientConnectStdio as (c: readonly string[]) => Promise<unknown>
      )(command);
    } catch (err) {
      throw mapBridgeError(err);
    }
  }

  async mcpClientConnectSse(url: string): Promise<unknown> {
    try {
      return await (this.#native.mcpClientConnectSse as (u: string) => Promise<unknown>)(url);
    } catch (err) {
      throw mapBridgeError(err);
    }
  }

  async mcpClientDisconnect(handle: unknown): Promise<void> {
    try {
      await (this.#native.mcpClientDisconnect as (h: unknown) => Promise<void>)(handle);
    } catch (err) {
      throw mapBridgeError(err);
    }
  }

  async mcpClientListTools(handle: unknown): Promise<readonly unknown[]> {
    try {
      return await (this.#native.mcpClientListTools as (h: unknown) => Promise<readonly unknown[]>)(
        handle,
      );
    } catch (err) {
      throw mapBridgeError(err);
    }
  }

  async mcpClientInvoke(
    handle: unknown,
    toolName: string,
    inputJson: string,
    contextId: string,
    invokerDid: string,
  ): Promise<unknown> {
    try {
      return await (
        this.#native.mcpClientInvoke as (
          h: unknown,
          t: string,
          i: string,
          c: string,
          d: string,
        ) => Promise<unknown>
      )(handle, toolName, inputJson, contextId, invokerDid);
    } catch (err) {
      throw mapBridgeError(err);
    }
  }

  mcpConfigureStdioAllowlist(additionalBinaries: readonly string[]): void {
    try {
      (this.#native.mcpConfigureStdioAllowlist as (b: readonly string[]) => void)(
        additionalBinaries,
      );
    } catch (err) {
      throw mapBridgeError(err);
    }
  }

  /**
   * Disable this instance's stdio allowlist (unrestricted mode).
   *
   * Allows **any** binary to be spawned by `mcpClientConnectStdio` on this
   * `SCP` — other instances are unaffected. Requires explicit
   * `iTrustAllCommands: true` to confirm acknowledgement of the security
   * implication. A warning is also written to `console.warn`.
   */
  mcpDisableStdioAllowlist(opts?: { iTrustAllCommands?: boolean }): void {
    if (!opts?.iTrustAllCommands) {
      throw new Error(
        "Disabling the stdio allowlist allows any binary to be spawned by " +
          "this SCP instance. Pass { iTrustAllCommands: true } to confirm.",
      );
    }
    console.warn(
      "[scp] MCP stdio allowlist enforcement disabled — arbitrary subprocess " +
        "spawning is now permitted on this instance",
    );
    try {
      (this.#native.mcpDisableStdioAllowlist as () => void)();
    } catch (err) {
      throw mapBridgeError(err);
    }
  }

  mcpResetStdioAllowlist(): void {
    try {
      (this.#native.mcpResetStdioAllowlist as () => void)();
    } catch (err) {
      throw mapBridgeError(err);
    }
  }

  mcpGetStdioAllowlist(): McpAllowlistState {
    try {
      return (this.#native.mcpGetStdioAllowlist as () => McpAllowlistState)();
    } catch (err) {
      throw mapBridgeError(err);
    }
  }

  // ───────────────────────────────────────────────────────────────────────
  // Domain: Fullstack (E2E test harness)
  // ───────────────────────────────────────────────────────────────────────

  fullstackCreateNode(did: string): unknown {
    try {
      return (this.#native.fullstackCreateNode as (d: string) => unknown)(did);
    } catch (err) {
      throw mapBridgeError(err);
    }
  }

  fullstackResetNetwork(): void {
    try {
      (this.#native.fullstackResetNetwork as () => void)();
    } catch (err) {
      throw mapBridgeError(err);
    }
  }

  fullstackCreateContext(node: unknown, contextId: string, ceilingJson: string): string {
    try {
      return (this.#native.fullstackCreateContext as (n: unknown, c: string, j: string) => string)(
        node,
        contextId,
        ceilingJson,
      );
    } catch (err) {
      throw mapBridgeError(err);
    }
  }

  fullstackAddMember(node: unknown, contextId: string, memberDid: string): void {
    try {
      (this.#native.fullstackAddMember as (n: unknown, c: string, m: string) => void)(
        node,
        contextId,
        memberDid,
      );
    } catch (err) {
      throw mapBridgeError(err);
    }
  }

  fullstackJoinFromWelcome(node: unknown, contextId: string): void {
    try {
      (this.#native.fullstackJoinFromWelcome as (n: unknown, c: string) => void)(node, contextId);
    } catch (err) {
      throw mapBridgeError(err);
    }
  }

  fullstackSyncSenderKeys(nodeA: unknown, nodeB: unknown, contextId: string): void {
    try {
      (this.#native.fullstackSyncSenderKeys as (a: unknown, b: unknown, c: string) => void)(
        nodeA,
        nodeB,
        contextId,
      );
    } catch (err) {
      throw mapBridgeError(err);
    }
  }

  fullstackSendMessage(node: unknown, contextId: string, payload: Uint8Array | Buffer): Uint8Array {
    try {
      const raw = (
        this.#native.fullstackSendMessage as (
          n: unknown,
          c: string,
          p: Uint8Array | Buffer,
        ) => Uint8Array | Buffer
      )(node, contextId, payload);
      return new Uint8Array(raw);
    } catch (err) {
      throw mapBridgeError(err);
    }
  }

  fullstackDecryptMessage(
    node: unknown,
    contextId: string,
    ciphertext: Uint8Array | Buffer,
    senderDid: string,
  ): Uint8Array {
    try {
      const raw = (
        this.#native.fullstackDecryptMessage as (
          n: unknown,
          c: string,
          ct: Uint8Array | Buffer,
          s: string,
        ) => Uint8Array | Buffer
      )(node, contextId, ciphertext, senderDid);
      return new Uint8Array(raw);
    } catch (err) {
      throw mapBridgeError(err);
    }
  }

  fullstackRemoveMember(node: unknown, contextId: string, memberDid: string): void {
    try {
      (this.#native.fullstackRemoveMember as (n: unknown, c: string, m: string) => void)(
        node,
        contextId,
        memberDid,
      );
    } catch (err) {
      throw mapBridgeError(err);
    }
  }

  /**
   * Test-only: seed a peer's per-context pseudonym routing ID (§9.10.4) into a
   * full-stack node's supervisor, simulating a delivered pseudonym
   * announcement so multi-member encrypted sends do not fail closed with
   * `SCP-CTX-2095`.
   */
  fullstackSeedPeerPseudonym(
    node: unknown,
    contextId: string,
    peerDid: string,
    pseudonym: Uint8Array | Buffer,
  ): void {
    try {
      (
        this.#native.fullstackSeedPeerPseudonym as (
          n: unknown,
          c: string,
          p: string,
          ps: Uint8Array | Buffer,
        ) => void
      )(node, contextId, peerDid, pseudonym);
    } catch (err) {
      throw mapBridgeError(err);
    }
  }

  // ───────────────────────────────────────────────────────────────────────
  // Domain: Media
  // ───────────────────────────────────────────────────────────────────────

  mediaCheckCapability(ceiling: readonly string[], capability: string): boolean {
    try {
      return (this.#native.mediaCheckCapability as (c: readonly string[], cap: string) => boolean)(
        ceiling,
        capability,
      );
    } catch (err) {
      throw mapBridgeError(err);
    }
  }

  mediaInitiateSession(
    contextId: string,
    ceiling: readonly string[],
    capabilities: readonly string[],
    participants: readonly string[],
    timestamp: number,
  ): string {
    try {
      return (
        this.#native.mediaInitiateSession as (
          c: string,
          cl: readonly string[],
          caps: readonly string[],
          p: readonly string[],
          t: number,
        ) => string
      )(contextId, ceiling, capabilities, participants, timestamp);
    } catch (err) {
      throw mapBridgeError(err);
    }
  }

  mediaActivateSession(sessionJson: string): string {
    try {
      return (this.#native.mediaActivateSession as (s: string) => string)(sessionJson);
    } catch (err) {
      throw mapBridgeError(err);
    }
  }

  mediaJoinSession(sessionJson: string, participantDid: string): string {
    try {
      return (this.#native.mediaJoinSession as (s: string, p: string) => string)(
        sessionJson,
        participantDid,
      );
    } catch (err) {
      throw mapBridgeError(err);
    }
  }

  mediaEndSession(sessionJson: string, timestamp: number): string {
    try {
      return (this.#native.mediaEndSession as (s: string, t: number) => string)(
        sessionJson,
        timestamp,
      );
    } catch (err) {
      throw mapBridgeError(err);
    }
  }

  mediaCreateOffer(sessionId: string, sdp: string, senderDid: string): string {
    try {
      return (this.#native.mediaCreateOffer as (s: string, sdp: string, d: string) => string)(
        sessionId,
        sdp,
        senderDid,
      );
    } catch (err) {
      throw mapBridgeError(err);
    }
  }

  mediaCreateAnswer(sessionId: string, sdp: string, senderDid: string): string {
    try {
      return (this.#native.mediaCreateAnswer as (s: string, sdp: string, d: string) => string)(
        sessionId,
        sdp,
        senderDid,
      );
    } catch (err) {
      throw mapBridgeError(err);
    }
  }

  mediaCreateIceCandidate(
    sessionId: string,
    candidate: string,
    senderDid: string,
    sdpMid?: string,
    sdpMlineIndex?: number,
  ): string {
    try {
      return (
        this.#native.mediaCreateIceCandidate as (
          s: string,
          c: string,
          d: string,
          m: string | undefined,
          i: number | undefined,
        ) => string
      )(sessionId, candidate, senderDid, sdpMid, sdpMlineIndex);
    } catch (err) {
      throw mapBridgeError(err);
    }
  }

  mediaCreateSessionEnd(sessionId: string, senderDid: string): string {
    try {
      return (this.#native.mediaCreateSessionEnd as (s: string, d: string) => string)(
        sessionId,
        senderDid,
      );
    } catch (err) {
      throw mapBridgeError(err);
    }
  }

  mediaSendSignaling(signalingJson: string): string {
    try {
      return (this.#native.mediaSendSignaling as (s: string) => string)(signalingJson);
    } catch (err) {
      throw mapBridgeError(err);
    }
  }

  mediaVerifySenderAttribution(signalingJson: string, envelopeSenderDid: string): boolean {
    try {
      return (this.#native.mediaVerifySenderAttribution as (s: string, e: string) => boolean)(
        signalingJson,
        envelopeSenderDid,
      );
    } catch (err) {
      throw mapBridgeError(err);
    }
  }

  // ───────────────────────────────────────────────────────────────────────
  // Domain: Provenance
  // ───────────────────────────────────────────────────────────────────────

  async evaluateProvenanceQuality(
    sourceContext: string | undefined,
    sourceType: string,
    contextState: string,
    counterparties?: readonly string[],
  ): Promise<number> {
    try {
      return await (
        this.#native.evaluateProvenanceQuality as (
          sc: string | undefined,
          st: string,
          cs: string,
          cp: readonly string[] | undefined,
        ) => Promise<number>
      )(sourceContext, sourceType, contextState, counterparties);
    } catch (err) {
      throw mapBridgeError(err);
    }
  }

  provenanceAttach(
    sourceContextId: string,
    sourceType: string,
    memoryScope: string,
    members: readonly string[],
    targetContextId: string,
    actorDid: string,
    existingChainDepth?: number,
    discoveryMethod?: string,
    purpose?: string,
    counterpartyPolicy?: string,
  ): string {
    try {
      return (
        this.#native.provenanceAttach as (
          sc: string,
          st: string,
          ms: string,
          m: readonly string[],
          tc: string,
          ad: string,
          e: number | undefined,
          dm: string | undefined,
          p: string | undefined,
          cp: string | undefined,
        ) => string
      )(
        sourceContextId,
        sourceType,
        memoryScope,
        members,
        targetContextId,
        actorDid,
        existingChainDepth,
        discoveryMethod,
        purpose,
        counterpartyPolicy,
      );
    } catch (err) {
      throw mapBridgeError(err);
    }
  }

  provenanceCheckChainDepth(chainDepth: number, maxDepth?: number): boolean {
    try {
      return (
        this.#native.provenanceCheckChainDepth as (c: number, m: number | undefined) => boolean
      )(chainDepth, maxDepth);
    } catch (err) {
      throw mapBridgeError(err);
    }
  }

  provenanceRedactCounterparties(provenanceJson: string): string {
    try {
      return (this.#native.provenanceRedactCounterparties as (j: string) => string)(provenanceJson);
    } catch (err) {
      throw mapBridgeError(err);
    }
  }

  provenancePseudonymizeCounterparties(provenanceJson: string, pseudonymKeyHex: string): string {
    try {
      return (
        this.#native.provenancePseudonymizeCounterparties as (j: string, k: string) => string
      )(provenanceJson, pseudonymKeyHex);
    } catch (err) {
      throw mapBridgeError(err);
    }
  }

  provenanceUpdateSourceType(provenanceJson: string, newState: string): string {
    try {
      return (this.#native.provenanceUpdateSourceType as (j: string, s: string) => string)(
        provenanceJson,
        newState,
      );
    } catch (err) {
      throw mapBridgeError(err);
    }
  }

  // ───────────────────────────────────────────────────────────────────────
  // Domain: Sync
  // ───────────────────────────────────────────────────────────────────────

  syncClassifyOffline(lastRelayContact: number, now: number): string {
    try {
      return (this.#native.syncClassifyOffline as (l: number, n: number) => string)(
        lastRelayContact,
        now,
      );
    } catch (err) {
      throw mapBridgeError(err);
    }
  }

  syncGetPolicy(): unknown {
    try {
      return (this.#native.syncGetPolicy as () => unknown)();
    } catch (err) {
      throw mapBridgeError(err);
    }
  }

  syncClassifyOfflineCustom(
    lastRelayContact: number,
    now: number,
    tier1ThresholdSecs: number,
    tier2ThresholdSecs: number,
  ): string {
    try {
      return (
        this.#native.syncClassifyOfflineCustom as (
          l: number,
          n: number,
          t1: number,
          t2: number,
        ) => string
      )(lastRelayContact, now, tier1ThresholdSecs, tier2ThresholdSecs);
    } catch (err) {
      throw mapBridgeError(err);
    }
  }

  // ───────────────────────────────────────────────────────────────────────
  // Domain: Bridge
  // ───────────────────────────────────────────────────────────────────────

  bridgeCreateShadow(
    bridgeId: string,
    platformHandle: string,
    bridgeMode: string,
    contextId?: string,
  ): unknown {
    try {
      return (
        this.#native.bridgeCreateShadow as (
          b: string,
          p: string,
          m: string,
          c: string | undefined,
        ) => unknown
      )(bridgeId, platformHandle, bridgeMode, contextId);
    } catch (err) {
      throw mapBridgeError(err);
    }
  }

  // ───────────────────────────────────────────────────────────────────────
  // Domain: Bridge credentials (spec §12.11)
  //
  // Per-instance credential store ops. Each routes through `this.#native`
  // (the NAPI SCP handle) — credentials are isolated to THIS instance's
  // store (ADR-048 §1). The SCP class is native-only by construction (the
  // WASM build throws at `new SCP(...)`), so there is no WASM path here;
  // the credential store lives only in scp-runtime (ADR-034).
  // ───────────────────────────────────────────────────────────────────────

  /** Provisions (stores) an encrypted credential for a bridge instance. */
  bridgeCredentialProvision(
    bridgeId: string,
    credentialType: string,
    plaintext: Uint8Array | readonly number[],
    bridgeCredentialKey: Uint8Array | readonly number[],
  ): BridgeCredential {
    try {
      // NAPI marshals Rust `Vec<u8>` as a JS `Array<number>`, not `Uint8Array`;
      // convert byte inputs before crossing the boundary (cf. `broadcastPublish`).
      const plaintextArray = ArrayBuffer.isView(plaintext)
        ? Array.from(plaintext as Uint8Array)
        : (plaintext as readonly number[]);
      const keyArray = ArrayBuffer.isView(bridgeCredentialKey)
        ? Array.from(bridgeCredentialKey as Uint8Array)
        : (bridgeCredentialKey as readonly number[]);
      return (
        this.#native.bridgeCredentialProvision as (
          b: string,
          t: string,
          p: readonly number[],
          k: readonly number[],
        ) => BridgeCredential
      )(bridgeId, credentialType, plaintextArray, keyArray);
    } catch (err) {
      throw mapBridgeError(err);
    }
  }

  /** Retrieves and decrypts a credential for a bridge instance. */
  bridgeCredentialRetrieve(
    bridgeId: string,
    credentialType: string,
    bridgeCredentialKey: Uint8Array | readonly number[],
  ): Uint8Array {
    try {
      const keyArray = ArrayBuffer.isView(bridgeCredentialKey)
        ? Array.from(bridgeCredentialKey as Uint8Array)
        : (bridgeCredentialKey as readonly number[]);
      const raw = (
        this.#native.bridgeCredentialRetrieve as (
          b: string,
          t: string,
          k: readonly number[],
        ) => number[]
      )(bridgeId, credentialType, keyArray);
      return Uint8Array.from(raw as readonly number[]);
    } catch (err) {
      throw mapBridgeError(err);
    }
  }

  /** Rotates (replaces) a credential for a bridge instance. */
  bridgeCredentialRotate(
    bridgeId: string,
    credentialType: string,
    newPlaintext: Uint8Array | readonly number[],
    bridgeCredentialKey: Uint8Array | readonly number[],
  ): BridgeCredential {
    try {
      const newPlaintextArray = ArrayBuffer.isView(newPlaintext)
        ? Array.from(newPlaintext as Uint8Array)
        : (newPlaintext as readonly number[]);
      const keyArray = ArrayBuffer.isView(bridgeCredentialKey)
        ? Array.from(bridgeCredentialKey as Uint8Array)
        : (bridgeCredentialKey as readonly number[]);
      return (
        this.#native.bridgeCredentialRotate as (
          b: string,
          t: string,
          p: readonly number[],
          k: readonly number[],
        ) => BridgeCredential
      )(bridgeId, credentialType, newPlaintextArray, keyArray);
    } catch (err) {
      throw mapBridgeError(err);
    }
  }

  /** Revokes all credentials for a bridge instance. */
  bridgeCredentialRevoke(bridgeId: string): void {
    try {
      (this.#native.bridgeCredentialRevoke as (b: string) => void)(bridgeId);
    } catch (err) {
      throw mapBridgeError(err);
    }
  }

  /** Lists all credential types stored for a bridge instance. */
  bridgeCredentialList(bridgeId: string): string[] {
    try {
      return (this.#native.bridgeCredentialList as (b: string) => string[])(bridgeId);
    } catch (err) {
      throw mapBridgeError(err);
    }
  }

  /** Stores a bridge credential key in the custody boundary. */
  bridgeCredentialStoreKey(bridgeId: string, key: Uint8Array | readonly number[]): void {
    try {
      const keyArray = ArrayBuffer.isView(key)
        ? Array.from(key as Uint8Array)
        : (key as readonly number[]);
      (this.#native.bridgeCredentialStoreKey as (b: string, k: readonly number[]) => void)(
        bridgeId,
        keyArray,
      );
    } catch (err) {
      throw mapBridgeError(err);
    }
  }

  /** Retrieves a bridge credential key from the custody boundary. */
  bridgeCredentialGetKey(bridgeId: string): Uint8Array {
    try {
      const raw = (this.#native.bridgeCredentialGetKey as (b: string) => number[])(bridgeId);
      return Uint8Array.from(raw as readonly number[]);
    } catch (err) {
      throw mapBridgeError(err);
    }
  }

  /** Deletes and zeroizes a bridge credential key. */
  bridgeCredentialDeleteKey(bridgeId: string): void {
    try {
      (this.#native.bridgeCredentialDeleteKey as (b: string) => void)(bridgeId);
    } catch (err) {
      throw mapBridgeError(err);
    }
  }

  // ───────────────────────────────────────────────────────────────────────
  // Domain: SCPID
  // ───────────────────────────────────────────────────────────────────────

  scpidChallenge(audience: string, ttlSeconds: number): string {
    try {
      return (this.#native.scpidChallenge as (a: string, t: number) => string)(
        audience,
        ttlSeconds,
      );
    } catch (err) {
      throw mapBridgeError(err);
    }
  }

  scpidSign(did: string, signingKeyId: string, challengeJson: string): string {
    try {
      return (this.#native.scpidSign as (d: string, k: string, c: string) => string)(
        did,
        signingKeyId,
        challengeJson,
      );
    } catch (err) {
      throw mapBridgeError(err);
    }
  }

  scpidVerify(responseJson: string, challengeJson: string): string {
    try {
      return (this.#native.scpidVerify as (r: string, c: string) => string)(
        responseJson,
        challengeJson,
      );
    } catch (err) {
      throw mapBridgeError(err);
    }
  }

  // ───────────────────────────────────────────────────────────────────────
  // Internal — `__nativeForInternalUseOnly` is **NOT** a method or getter;
  // access routes through module-private functions below so the handle
  // cannot be reached from outside this file via prototype enumeration.
  // ───────────────────────────────────────────────────────────────────────
}

/**
 * Retrieve the raw NAPI `SCP` handle from an {@link SCP} wrapper for
 * internal routing. Exported for use by sibling modules in this package
 * that need to dispatch directly through the native class (e.g.
 * `server.ts`, `internal/native.ts`, `mcp.ts`). The `__`-prefix marks
 * it as internal; it is not part of the public `@limn-works/scp-ts`
 * surface.
 *
 * @internal
 */
export function __getNativeScp(scp: SCP): NativeScpInstance {
  const native = nativeHandles.get(scp);
  if (native === undefined) {
    throw new Error("SCP instance has no native handle — was it constructed with `new SCP()`?");
  }
  return native;
}

// `__setNativeForTests` + `replaceNativeWithMock` removed in round-3 cleanup:
// black-hat finding BLACK-PR5-003 noted that post-construction swaps via the
// `nativeTestOverrides` WeakMap were invisible to the ~180 class methods
// (which dispatch through `this.#native` directly). Only the construction-
// time path via `__constructScpWithNativeForTests` mounts a mock that
// intercepts every method call. No test currently needs post-construction
// swap; removing the partial API closes the footgun.

/**
 * Construct a fresh {@link SCP} whose `#native` slot is seeded with the
 * caller-supplied handle, skipping the real addon load. Intended for
 * `tests/mock-bridge.ts` only — lets tests spin up an `SCP` wrapping a
 * Proxy-backed mock without requiring `@limn-works/scp-ts-napi-*` to
 * be installed for the host platform.
 *
 * Guarded: throws in production — only allowed when NODE_ENV is "test" or
 * "development", or when BUN_TEST is set. Closes the round-3 red-hat
 * RED-PR5-007 attack chain (smuggled-native SCP injection into a downstream
 * library).
 *
 * @internal
 */
export function __constructScpWithNativeForTests(native: unknown): SCP {
  assertTestEnvironment("__constructScpWithNativeForTests");
  return new SCP({
    [NATIVE_OVERRIDE]: native as NativeScpInstance,
  } as unknown as ScpOptions);
}
