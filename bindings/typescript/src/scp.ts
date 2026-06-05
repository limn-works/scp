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
import { ValidationError } from "./errors";
import type { Identity } from "./identity";
import { loadNativeAddon, type NativeAddon as RawNativeAddon } from "./internal/native";
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
 * Raw NAPI `SCP` class type once resolved. `withPersistence` is
 * intentionally omitted from this interface — the native factory
 * still exists for internal use, but the SDK surface does not expose
 * it until a real `ContextPersistence` trait is wired through (see
 * #1260 and #1491).
 */
interface NativeScpCtor {
  new (): NativeScpInstance;
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
 * Storage configuration forwarded to the native `SCP.withStorage` factory.
 *
 * - `{ type: "in_memory" }` — encrypted in-memory storage (ephemeral).
 * - `{ type: "sqlite"; path; key }` — SQLCipher-encrypted storage on
 *   disk at `{path}/scp.db`. Closes #1260 / #1491.
 */
export type StorageConfig =
  | { type: "in_memory" }
  | { type: "sqlite"; path: string; key: Uint8Array | string };

/** Constructor options for `new SCP(...)`. */
export interface ScpOptions {
  /** Storage configuration. Defaults to in-memory when omitted. */
  storage?: StorageConfig;
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
   * Return the 32 raw Ed25519 private-seed bytes for `keyId`. Required for
   * governance vote signing; hardware-bound custody should throw.
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
   * @param options Optional constructor options.
   * @throws {ValidationError} If no NAPI addon is available — code `SCP-VALID-7005`.
   */
  constructor(options: ScpOptions = {}) {
    // Test-only escape hatch: if a pre-built native handle is smuggled
    // via the (non-exported) `NATIVE_OVERRIDE` symbol, skip addon
    // loading entirely. Only reachable from `__constructScpWithNativeForTests`.
    const override = (options as { [NATIVE_OVERRIDE]?: NativeScpInstance })[NATIVE_OVERRIDE];
    if (override !== undefined) {
      this.#native = override;
    } else {
      const NativeScp = nativeScp();
      if (options.storage !== undefined) {
        this.#native = NativeScp.withStorage(serializeStorageConfig(options.storage));
      } else {
        this.#native = new NativeScp();
      }
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
    this.#native.suspend();
  }

  /**
   * Resumes a suspended bridge instance. Awaits transport reconnect
   * and persisted context-snapshot restoration (#1678).
   */
  async resume(): Promise<void> {
    await this.#native.resume();
  }

  /**
   * Shuts down the instance with a graceful deadline.
   *
   * @param timeoutSecs Maximum seconds to wait. Defaults to 5.
   */
  async shutdown(timeoutSecs: number = 5): Promise<void> {
    const millis = __clampShutdownMillisForTests(timeoutSecs);
    await this.#native.shutdown(BigInt(millis));
  }

  // ───────────────────────────────────────────────────────────────────────
  // Domain: Identity
  // ───────────────────────────────────────────────────────────────────────

  async identityCreate(custody: string = "in_memory"): Promise<Identity> {
    const raw = await (this.#native.identityCreate as (c: string) => Promise<unknown>)(custody);
    const { Identity: IdentityCls } = await import("./identity");
    return IdentityCls._fromHandle(this, raw);
  }

  async identityCreateWithAgentKey(custody: string = "in_memory"): Promise<Identity> {
    const raw = await (this.#native.identityCreateWithAgentKey as (c: string) => Promise<unknown>)(
      custody,
    );
    const { Identity: IdentityCls } = await import("./identity");
    return IdentityCls._fromHandle(this, raw);
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
      exportSigningKeyBytes: (keyId: string): number[] =>
        Array.from(provider.exportSigningKeyBytes(keyId)),
      custodyType: (keyId: string): string => provider.custodyType(keyId),
    };
    const raw = await (
      this.#native.identityCreateWithCustody as (p: typeof adapter) => Promise<unknown>
    )(adapter);
    const { Identity: IdentityCls } = await import("./identity");
    return IdentityCls._fromHandle(this, raw);
  }

  async identityLoad(did: string): Promise<Identity> {
    const raw = await (this.#native.identityLoad as (d: string) => Promise<unknown>)(did);
    const { Identity: IdentityCls } = await import("./identity");
    return IdentityCls._fromHandle(this, raw);
  }

  async identityResolve(did: string): Promise<unknown> {
    return await (this.#native.identityResolve as (d: string) => Promise<unknown>)(did);
  }

  identityRemove(did: string): void {
    (this.#native.identityRemove as (d: string) => void)(did);
  }

  identityRemoveIfPresent(did: string): boolean {
    return (this.#native.identityRemoveIfPresent as (d: string) => boolean)(did);
  }

  async identityAttestDevice(did: string): Promise<string> {
    return await (this.#native.identityAttestDevice as (d: string) => Promise<string>)(did);
  }

  async identityVerifyDeviceAttestation(did: string, tokenBase64: string): Promise<boolean> {
    return await (
      this.#native.identityVerifyDeviceAttestation as (d: string, t: string) => Promise<boolean>
    )(did, tokenBase64);
  }

  async identityCreateLinkAttestation(
    did: string,
    platform: string,
    handle: string,
    proof: string,
    verificationMethod: string,
    platformId?: string | null,
  ): Promise<string> {
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
  }

  identityLinkAttestations(did: string): string {
    return (this.#native.identityLinkAttestations as (d: string) => string)(did);
  }

  identityRemoveLinkAttestation(did: string, attestationId: string): boolean {
    return (this.#native.identityRemoveLinkAttestation as (d: string, a: string) => boolean)(
      did,
      attestationId,
    );
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
    return fn(attestationJson, issuerPublicKeyHex);
  }

  identityExecuteRecovery(did: string, tier: string, contextIds: readonly string[]): string {
    return (
      this.#native.identityExecuteRecovery as (d: string, t: string, c: readonly string[]) => string
    )(did, tier, contextIds);
  }

  identityExecuteCustodyMigration(
    did: string,
    target: string,
    contextIds: readonly string[],
  ): string {
    return (
      this.#native.identityExecuteCustodyMigration as (
        d: string,
        t: string,
        c: readonly string[],
      ) => string
    )(did, target, contextIds);
  }

  // ───────────────────────────────────────────────────────────────────────
  // Domain: Petname
  // ───────────────────────────────────────────────────────────────────────

  petnameSet(ownerDid: string, targetDid: string, name: string): void {
    (this.#native.petnameSet as (o: string, t: string, n: string) => void)(
      ownerDid,
      targetDid,
      name,
    );
  }

  petnameRemove(ownerDid: string, targetDid: string): void {
    (this.#native.petnameRemove as (o: string, t: string) => void)(ownerDid, targetDid);
  }

  petnameSetContext(ownerDid: string, contextId: string, name: string): void {
    (this.#native.petnameSetContext as (o: string, c: string, n: string) => void)(
      ownerDid,
      contextId,
      name,
    );
  }

  petnameRemoveContext(ownerDid: string, contextId: string): void {
    (this.#native.petnameRemoveContext as (o: string, c: string) => void)(ownerDid, contextId);
  }

  petnameResolveDid(ownerDid: string, name: string): string {
    return (this.#native.petnameResolveDid as (o: string, n: string) => string)(ownerDid, name);
  }

  petnameResolveContext(ownerDid: string, name: string): string {
    return (this.#native.petnameResolveContext as (o: string, n: string) => string)(ownerDid, name);
  }

  petnameGetForDid(ownerDid: string, targetDid: string): string | null {
    return (this.#native.petnameGetForDid as (o: string, t: string) => string | null)(
      ownerDid,
      targetDid,
    );
  }

  petnameGetForContext(ownerDid: string, contextId: string): string | null {
    return (this.#native.petnameGetForContext as (o: string, c: string) => string | null)(
      ownerDid,
      contextId,
    );
  }

  petnameApplyEvent(ownerDid: string, eventJson: string): void {
    (this.#native.petnameApplyEvent as (o: string, e: string) => void)(ownerDid, eventJson);
  }

  petnameDidCount(ownerDid: string): number {
    return (this.#native.petnameDidCount as (o: string) => number)(ownerDid);
  }

  petnameContextCount(ownerDid: string): number {
    return (this.#native.petnameContextCount as (o: string) => number)(ownerDid);
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
  }

  handleLookup(discoveryContextId: string, handle: string, typeFilter?: string): string {
    return (this.#native.handleLookup as (d: string, h: string, f: string | undefined) => string)(
      discoveryContextId,
      handle,
      typeFilter,
    );
  }

  handleDeregister(discoveryContextId: string, handle: string, did: string): string {
    return (this.#native.handleDeregister as (d: string, h: string, did: string) => string)(
      discoveryContextId,
      handle,
      did,
    );
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
  }

  scopeLookup(scopeContextId: string, name: string): string {
    return (this.#native.scopeLookup as (sc: string, n: string) => string)(scopeContextId, name);
  }

  scopeDeregister(scopeContextId: string, name: string, did: string): string {
    return (this.#native.scopeDeregister as (sc: string, n: string, d: string) => string)(
      scopeContextId,
      name,
      did,
    );
  }

  async addressResolve(
    ownerDid: string,
    address: string,
    knownContextsJson?: string,
  ): Promise<string> {
    return await (
      this.#native.addressResolve as (
        o: string,
        a: string,
        k: string | undefined,
      ) => Promise<string>
    )(ownerDid, address, knownContextsJson);
  }

  // ───────────────────────────────────────────────────────────────────────
  // Domain: Context
  // ───────────────────────────────────────────────────────────────────────

  async contextCreate(identity: Identity, paramsJson: string): Promise<Context> {
    const raw = await (this.#native.contextCreate as (id: unknown, p: string) => Promise<unknown>)(
      identity._rawHandle,
      paramsJson,
    );
    const { Context: ContextCls } = await import("./context");
    return ContextCls._fromHandle(this, raw as never, identity.did);
  }

  async contextJoin(
    handle: unknown,
    identityDid: string,
    spendingUcanJwt?: string | null,
  ): Promise<void> {
    await (this.#native.contextJoin as (h: unknown, d: string, s: string | null) => Promise<void>)(
      handle,
      identityDid,
      spendingUcanJwt ?? null,
    );
  }

  async contextLeave(handle: unknown, identityDid: string): Promise<void> {
    await (this.#native.contextLeave as (h: unknown, d: string) => Promise<void>)(
      handle,
      identityDid,
    );
  }

  async contextClose(handle: unknown, identityDid: string): Promise<void> {
    await (this.#native.contextClose as (h: unknown, d: string) => Promise<void>)(
      handle,
      identityDid,
    );
  }

  async contextSend(
    handle: unknown,
    identityDid: string,
    payload: Uint8Array | readonly number[],
    spendingUcanJwt?: string | null,
  ): Promise<void> {
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
  }

  async contextSubscribe(
    handle: unknown,
    identityDid: string,
    onMessage: (message: unknown) => void,
  ): Promise<void> {
    await (
      this.#native.contextSubscribe as (
        h: unknown,
        d: string,
        cb: (m: unknown) => void,
      ) => Promise<void>
    )(handle, identityDid, onMessage);
  }

  contextCancelSubscription(handle: unknown): void {
    (this.#native.contextCancelSubscription as (h: unknown) => void)(handle);
  }

  async contextMemberCount(handle: unknown): Promise<number> {
    return await (this.#native.contextMemberCount as (h: unknown) => Promise<number>)(handle);
  }

  async contextIsMember(handle: unknown, did: string): Promise<boolean> {
    return await (this.#native.contextIsMember as (h: unknown, d: string) => Promise<boolean>)(
      handle,
      did,
    );
  }

  async contextMemberDids(handle: unknown): Promise<readonly string[]> {
    return await (this.#native.contextMemberDids as (h: unknown) => Promise<readonly string[]>)(
      handle,
    );
  }

  async contextMemberRole(handle: unknown, did: string): Promise<string | null> {
    return await (
      this.#native.contextMemberRole as (h: unknown, d: string) => Promise<string | null>
    )(handle, did);
  }

  async contextDrainEvents(handle: unknown): Promise<readonly string[]> {
    return await (this.#native.contextDrainEvents as (h: unknown) => Promise<readonly string[]>)(
      handle,
    );
  }

  async contextRestore(contextId: string): Promise<void> {
    await (this.#native.contextRestore as (id: string) => Promise<void>)(contextId);
  }

  async contextRestoreAll(): Promise<string> {
    return await (this.#native.contextRestoreAll as () => Promise<string>)();
  }

  async contextTombstoneMigrated(handle: unknown): Promise<void> {
    await (this.#native.contextTombstoneMigrated as (h: unknown) => Promise<void>)(handle);
  }

  async contextMigrationState(handle: unknown): Promise<string | null> {
    return await (this.#native.contextMigrationState as (h: unknown) => Promise<string | null>)(
      handle,
    );
  }

  async contextExport(handle: unknown): Promise<Uint8Array> {
    const raw = await (this.#native.contextExport as (h: unknown) => Promise<Uint8Array | Buffer>)(
      handle,
    );
    return new Uint8Array(raw);
  }

  async contextImport(data: Uint8Array | readonly number[]): Promise<string> {
    const dataArray = ArrayBuffer.isView(data)
      ? Array.from(data as Uint8Array)
      : (data as readonly number[]);
    return await (this.#native.contextImport as (d: readonly number[]) => Promise<string>)(
      dataArray,
    );
  }

  contextSetEconomicPolicy(handle: unknown, policyJson: string): void {
    (this.#native.contextSetEconomicPolicy as (h: unknown, p: string) => void)(handle, policyJson);
  }

  contextGetEconomicPolicy(handle: unknown): string | null {
    return (this.#native.contextGetEconomicPolicy as (h: unknown) => string | null)(handle);
  }

  // ───────────────────────────────────────────────────────────────────────
  // Domain: Broadcast / Access
  // ───────────────────────────────────────────────────────────────────────

  async accessKeyGenerate(contextId: string, memberDid: string, callerDid: string): Promise<void> {
    await (this.#native.accessKeyGenerate as (c: string, m: string, k: string) => Promise<void>)(
      contextId,
      memberDid,
      callerDid,
    );
  }

  async accessKeyRevoke(contextId: string, memberDid: string, callerDid: string): Promise<void> {
    await (this.#native.accessKeyRevoke as (c: string, m: string, k: string) => Promise<void>)(
      contextId,
      memberDid,
      callerDid,
    );
  }

  async accessKeyRestore(contextId: string, memberDid: string, callerDid: string): Promise<void> {
    await (this.#native.accessKeyRestore as (c: string, m: string, k: string) => Promise<void>)(
      contextId,
      memberDid,
      callerDid,
    );
  }

  async contextBroadcastSubscriberCount(handle: unknown): Promise<number | null> {
    return await (
      this.#native.contextBroadcastSubscriberCount as (h: unknown) => Promise<number | null>
    )(handle);
  }

  async contextIsBroadcastSubscriber(handle: unknown, did: string): Promise<boolean> {
    return await (
      this.#native.contextIsBroadcastSubscriber as (h: unknown, d: string) => Promise<boolean>
    )(handle, did);
  }

  async contextBroadcastAdmission(handle: unknown): Promise<string | null> {
    return await (this.#native.contextBroadcastAdmission as (h: unknown) => Promise<string | null>)(
      handle,
    );
  }

  async broadcastSubscribe(handle: unknown, subscriberDid: string): Promise<void> {
    await (this.#native.broadcastSubscribe as (h: unknown, d: string) => Promise<void>)(
      handle,
      subscriberDid,
    );
  }

  async broadcastUnsubscribe(
    handle: unknown,
    subscriberDid: string,
    rotateKeys?: boolean,
  ): Promise<void> {
    await (
      this.#native.broadcastUnsubscribe as (
        h: unknown,
        d: string,
        r: boolean | undefined,
      ) => Promise<void>
    )(handle, subscriberDid, rotateKeys);
  }

  async broadcastPublish(
    handle: unknown,
    authorDid: string,
    payload: Uint8Array | readonly number[],
  ): Promise<void> {
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
  }

  async broadcastPublishAsset(
    handle: unknown,
    authorDid: string,
    asset: { path: string; contentType: string; body: readonly number[] },
    deployId?: string | null,
  ): Promise<unknown> {
    return await (
      this.#native.broadcastPublishAsset as (
        h: unknown,
        d: string,
        a: { path: string; contentType: string; body: readonly number[] },
        did: string | null,
      ) => Promise<unknown>
    )(handle, authorDid, asset, deployId ?? null);
  }

  async broadcastPublishAssets(
    handle: unknown,
    authorDid: string,
    assets: readonly { path: string; contentType: string; body: readonly number[] }[],
    deployId?: string | null,
  ): Promise<unknown> {
    return await (
      this.#native.broadcastPublishAssets as (
        h: unknown,
        d: string,
        a: readonly { path: string; contentType: string; body: readonly number[] }[],
        did: string | null,
      ) => Promise<unknown>
    )(handle, authorDid, assets, deployId ?? null);
  }

  async broadcastBlockSubscriber(
    handle: unknown,
    subscriberDid: string,
    blockerDid: string,
  ): Promise<void> {
    await (
      this.#native.broadcastBlockSubscriber as (h: unknown, s: string, b: string) => Promise<void>
    )(handle, subscriberDid, blockerDid);
  }

  async broadcastUnblockSubscriber(
    handle: unknown,
    subscriberDid: string,
    unblockerDid: string,
  ): Promise<void> {
    await (
      this.#native.broadcastUnblockSubscriber as (h: unknown, s: string, u: string) => Promise<void>
    )(handle, subscriberDid, unblockerDid);
  }

  async broadcastHandleKeyRequest(
    handle: unknown,
    authorDid: string,
    requesterDid: string,
  ): Promise<string> {
    return await (
      this.#native.broadcastHandleKeyRequest as (
        h: unknown,
        a: string,
        r: string,
      ) => Promise<string>
    )(handle, authorDid, requesterDid);
  }

  // ───────────────────────────────────────────────────────────────────────
  // Domain: Governance
  // ───────────────────────────────────────────────────────────────────────

  async contextExecuteGovernanceAction(
    handle: unknown,
    actionJson: string,
    proposerDid: string,
  ): Promise<string> {
    return await (
      this.#native.contextExecuteGovernanceAction as (
        h: unknown,
        a: string,
        p: string,
      ) => Promise<string>
    )(handle, actionJson, proposerDid);
  }

  async contextGovernancePropose(
    handle: unknown,
    actionJson: string,
    proposerDid: string,
  ): Promise<string> {
    return await (
      this.#native.contextGovernancePropose as (h: unknown, a: string, p: string) => Promise<string>
    )(handle, actionJson, proposerDid);
  }

  async contextGovernanceApprove(
    handle: unknown,
    proposalIdHex: string,
    voterDid: string,
  ): Promise<string> {
    return await (
      this.#native.contextGovernanceApprove as (h: unknown, p: string, v: string) => Promise<string>
    )(handle, proposalIdHex, voterDid);
  }

  async contextGovernanceReject(
    handle: unknown,
    proposalIdHex: string,
    voterDid: string,
  ): Promise<string> {
    return await (
      this.#native.contextGovernanceReject as (h: unknown, p: string, v: string) => Promise<string>
    )(handle, proposalIdHex, voterDid);
  }

  async contextGovernanceWithdraw(
    handle: unknown,
    proposalIdHex: string,
    voterDid: string,
  ): Promise<string> {
    return await (
      this.#native.contextGovernanceWithdraw as (
        h: unknown,
        p: string,
        v: string,
      ) => Promise<string>
    )(handle, proposalIdHex, voterDid);
  }

  async contextGovernanceGetProposal(handle: unknown, proposalIdHex: string): Promise<string> {
    return await (
      this.#native.contextGovernanceGetProposal as (h: unknown, p: string) => Promise<string>
    )(handle, proposalIdHex);
  }

  async contextGovernanceListProposals(handle: unknown): Promise<string> {
    return await (this.#native.contextGovernanceListProposals as (h: unknown) => Promise<string>)(
      handle,
    );
  }

  async contextApplyPendingCeilingModification(
    handle: unknown,
    currentTimestamp: number,
  ): Promise<boolean> {
    return await (
      this.#native.contextApplyPendingCeilingModification as (
        h: unknown,
        t: number,
      ) => Promise<boolean>
    )(handle, currentTimestamp);
  }

  async contextFinalizeClose(handle: unknown): Promise<void> {
    await (this.#native.contextFinalizeClose as (h: unknown) => Promise<void>)(handle);
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
  }

  async contextAddCheckpointCosignature(
    handle: unknown,
    checkpointJson: string,
    signerDid: string,
    signatureHex: string,
  ): Promise<string> {
    return await (
      this.#native.contextAddCheckpointCosignature as (
        h: unknown,
        c: string,
        s: string,
        sig: string,
      ) => Promise<string>
    )(handle, checkpointJson, signerDid, signatureHex);
  }

  // ───────────────────────────────────────────────────────────────────────
  // Domain: TTL / Migration
  // ───────────────────────────────────────────────────────────────────────

  async contextHandleTtlExpiry(handle: unknown): Promise<void> {
    await (this.#native.contextHandleTtlExpiry as (h: unknown) => Promise<void>)(handle);
  }

  async contextProposeTtlExtension(
    handle: unknown,
    proposerDid: string,
    extensionSecs: number,
  ): Promise<boolean> {
    return await (
      this.#native.contextProposeTtlExtension as (
        h: unknown,
        d: string,
        s: number,
      ) => Promise<boolean>
    )(handle, proposerDid, extensionSecs);
  }

  async contextResetTtlTimer(handle: unknown, newDurationSecs: number): Promise<void> {
    await (this.#native.contextResetTtlTimer as (h: unknown, s: number) => Promise<void>)(
      handle,
      newDurationSecs,
    );
  }

  // ───────────────────────────────────────────────────────────────────────
  // Domain: Capability / Invitation / Metadata
  // ───────────────────────────────────────────────────────────────────────

  validateCapabilityDeclaration(
    declarationJson: string,
    ceilingCapabilities: readonly string[],
    roleCapabilities: readonly string[],
  ): string {
    return (
      this.#native.validateCapabilityDeclaration as (
        d: string,
        c: readonly string[],
        r: readonly string[],
      ) => string
    )(declarationJson, ceilingCapabilities, roleCapabilities);
  }

  checkScopedCapability(
    grantedCapabilities: readonly string[],
    requiredCapability: string,
  ): boolean {
    // ADR-048 §1: pure helper, routed to the addon's module-level free fn
    // (the `SCP::check_scoped_capability` method was deleted in PR-E #28).
    const fn = nativeFreeFn<(g: string[], r: string) => boolean>("checkScopedCapability");
    return fn([...grantedCapabilities], requiredCapability);
  }

  evaluateInvitation(
    paramsJson: string,
    inviterDid: string,
    identityDid: string,
    policyJson?: string | null,
    spendingJson?: string | null,
    trustedDidsJson?: string | null,
  ): unknown {
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
  }

  // The four pure protocol helpers below are method-shaped on `SCP` for
  // TS-local ergonomic consistency (ADR-048 §7), but the FFI Rust source
  // exposes them as module-level free functions per ADR-048 §1 (no
  // per-instance state to read). Each method routes to the addon's
  // module-level NAPI export; the `this` receiver carries no runtime
  // weight in these calls.

  metadataRecordFromJson(jsonStr: string): string {
    const fn = nativeFreeFn<(j: string) => string>("metadataRecordFromJson");
    return fn(jsonStr);
  }

  templateGetParams(templateId: string): string {
    const fn = nativeFreeFn<(t: string) => string>("templateGetParams");
    return fn(templateId);
  }

  validateAgainstTemplate(paramsJson: string): string | null {
    const fn = nativeFreeFn<(p: string) => string | null>("validateAgainstTemplate");
    return fn(paramsJson);
  }

  validateContextParams(paramsJson: string): string | null {
    const fn = nativeFreeFn<(p: string) => string | null>("validateContextParams");
    return fn(paramsJson);
  }

  // ───────────────────────────────────────────────────────────────────────
  // Domain: Tool
  // ───────────────────────────────────────────────────────────────────────

  async toolRegister(handle: unknown, definition: unknown): Promise<string> {
    return await (this.#native.toolRegister as (h: unknown, d: unknown) => Promise<string>)(
      handle,
      definition,
    );
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
  }

  async toolVerify(handle: unknown, toolId: string): Promise<unknown> {
    return await (this.#native.toolVerify as (h: unknown, t: string) => Promise<unknown>)(
      handle,
      toolId,
    );
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
  }

  async toolSessionCreate(
    handle: unknown,
    toolId: string,
    sourceContextId: string,
    ttlSeconds?: number,
  ): Promise<string> {
    return await (
      this.#native.toolSessionCreate as (
        h: unknown,
        t: string,
        s: string,
        ttl: number | undefined,
      ) => Promise<string>
    )(handle, toolId, sourceContextId, ttlSeconds);
  }

  async toolSessionInvoke(
    handle: unknown,
    sessionId: string,
    inputJson: string,
    invokerDid: string,
    ucanToken: string,
    proofTokens?: readonly string[],
  ): Promise<string> {
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
  }

  async toolSessionClose(handle: unknown, sessionId: string): Promise<void> {
    await (this.#native.toolSessionClose as (h: unknown, sid: string) => Promise<void>)(
      handle,
      sessionId,
    );
  }

  async toolInterfaceExpose(
    handle: unknown,
    toolId: string,
    targetContextId: string,
    rateLimitJson?: string,
  ): Promise<string> {
    return await (
      this.#native.toolInterfaceExpose as (
        h: unknown,
        t: string,
        tc: string,
        rl: string | undefined,
      ) => Promise<string>
    )(handle, toolId, targetContextId, rateLimitJson);
  }

  async toolInterfaceAccept(handle: unknown, interfaceJson: string): Promise<string> {
    return await (this.#native.toolInterfaceAccept as (h: unknown, ij: string) => Promise<string>)(
      handle,
      interfaceJson,
    );
  }

  async toolInterfaceRevoke(handle: unknown, interfaceIdHex: string): Promise<string> {
    return await (this.#native.toolInterfaceRevoke as (h: unknown, id: string) => Promise<string>)(
      handle,
      interfaceIdHex,
    );
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
    await (
      this.#native.ucanValidate as (
        h: unknown,
        t: string,
        c: string,
        pa: string | undefined,
        pt: readonly string[] | undefined,
      ) => Promise<void>
    )(handle, token, capability, presentingAgentDid, proofTokens);
  }

  async ucanMint(
    handle: unknown,
    memberDid: string,
    capabilities: readonly string[],
    proofs?: readonly string[],
  ): Promise<unknown> {
    return await (
      this.#native.ucanMint as (
        h: unknown,
        d: string,
        c: readonly string[],
        p: readonly string[] | undefined,
      ) => Promise<unknown>
    )(handle, memberDid, capabilities, proofs);
  }

  async ucanDelegate(
    handle: unknown,
    delegatorDid: string,
    delegateeDid: string,
    parentToken: string,
    capabilities: readonly string[],
  ): Promise<unknown> {
    return await (
      this.#native.ucanDelegate as (
        h: unknown,
        from: string,
        to: string,
        parent: string,
        caps: readonly string[],
      ) => Promise<unknown>
    )(handle, delegatorDid, delegateeDid, parentToken, capabilities);
  }

  async ucanRevoke(handle: unknown, token: string, revokerDid: string): Promise<void> {
    await (this.#native.ucanRevoke as (h: unknown, t: string, r: string) => Promise<void>)(
      handle,
      token,
      revokerDid,
    );
  }

  // ───────────────────────────────────────────────────────────────────────
  // Domain: Event log
  // ───────────────────────────────────────────────────────────────────────

  async eventLogQuery(handle: unknown, filterJson?: string): Promise<readonly unknown[]> {
    return await (
      this.#native.eventLogQuery as (
        h: unknown,
        f: string | undefined,
      ) => Promise<readonly unknown[]>
    )(handle, filterJson);
  }

  async eventLogVerify(handle: unknown, claimJson: string): Promise<unknown> {
    return await (this.#native.eventLogVerify as (h: unknown, c: string) => Promise<unknown>)(
      handle,
      claimJson,
    );
  }

  eventLogCheckpoint(handle: unknown, identity: Identity, epoch: number): unknown {
    return (this.#native.eventLogCheckpoint as (h: unknown, i: unknown, e: number) => unknown)(
      handle,
      identity._rawHandle,
      epoch,
    );
  }

  eventLogCheckpointByDid(handle: unknown, did: string, epoch: number): unknown {
    return (this.#native.eventLogCheckpointByDid as (h: unknown, d: string, e: number) => unknown)(
      handle,
      did,
      epoch,
    );
  }

  // ───────────────────────────────────────────────────────────────────────
  // Domain: Transport
  // ───────────────────────────────────────────────────────────────────────

  async transportConnect(relayUrl: string): Promise<unknown> {
    return await (this.#native.transportConnect as (u: string) => Promise<unknown>)(relayUrl);
  }

  async transportStatus(manager: unknown): Promise<unknown> {
    return await (this.#native.transportStatus as (m: unknown) => Promise<unknown>)(manager);
  }

  async transportDisconnect(manager: unknown): Promise<void> {
    await (this.#native.transportDisconnect as (m: unknown) => Promise<void>)(manager);
  }

  configureLocalTransport(localDid: string): void {
    (this.#native.configureLocalTransport as (d: string) => void)(localDid);
  }

  async configureRelayTransport(relayUrl: string, localDid: string): Promise<void> {
    await (this.#native.configureRelayTransport as (u: string, d: string) => Promise<void>)(
      relayUrl,
      localDid,
    );
  }

  async transportAddRelay(relayUrl: string): Promise<number> {
    return await (this.#native.transportAddRelay as (u: string) => Promise<number>)(relayUrl);
  }

  transportAssignRelaySet(contextId: string): readonly number[] {
    return (this.#native.transportAssignRelaySet as (c: string) => readonly number[])(contextId);
  }

  transportAdapterCount(): number {
    return (this.#native.transportAdapterCount as () => number)();
  }

  transportReliability(adapterIndex: number): unknown {
    return (this.#native.transportReliability as (i: number) => unknown)(adapterIndex);
  }

  // ───────────────────────────────────────────────────────────────────────
  // Domain: Economy
  // ───────────────────────────────────────────────────────────────────────

  economyEstimateCost(policyJson: string, actionType: string, metricsJson: string): number {
    return (this.#native.economyEstimateCost as (p: string, a: string, m: string) => number)(
      policyJson,
      actionType,
      metricsJson,
    );
  }

  economyPolicyRequiresPayment(policyJson: string): boolean {
    return (this.#native.economyPolicyRequiresPayment as (p: string) => boolean)(policyJson);
  }

  economyAutoAcceptBlocked(policyJson: string): boolean {
    return (this.#native.economyAutoAcceptBlocked as (p: string) => boolean)(policyJson);
  }

  economyCheckPolicyLock(policyJson: string): boolean {
    return (this.#native.economyCheckPolicyLock as (p: string) => boolean)(policyJson);
  }

  economyValidatePolicyChange(currentJson: string, proposedJson: string): boolean {
    return (this.#native.economyValidatePolicyChange as (c: string, p: string) => boolean)(
      currentJson,
      proposedJson,
    );
  }

  economyEvaluateFormula(formulaJson: string, metricsJson: string): number {
    return (this.#native.economyEvaluateFormula as (f: string, m: string) => number)(
      formulaJson,
      metricsJson,
    );
  }

  economyBudgetRemaining(contextId: string, did: string): number {
    return (this.#native.economyBudgetRemaining as (c: string, d: string) => number)(
      contextId,
      did,
    );
  }

  economyBudgetGrant(contextId: string, did: string, amount: number): void {
    (this.#native.economyBudgetGrant as (c: string, d: string, a: number) => void)(
      contextId,
      did,
      amount,
    );
  }

  economyBudgetRecordSpend(contextId: string, did: string, amount: number): void {
    (this.#native.economyBudgetRecordSpend as (c: string, d: string, a: number) => void)(
      contextId,
      did,
      amount,
    );
  }

  economyAntispamRecord(contextId: string, senderDid: string, timestamp: number): void {
    (this.#native.economyAntispamRecord as (c: string, s: string, t: number) => void)(
      contextId,
      senderDid,
      timestamp,
    );
  }

  economyAntispamVelocity(contextId: string, senderDid: string, now: number): number {
    return (this.#native.economyAntispamVelocity as (c: string, s: string, n: number) => number)(
      contextId,
      senderDid,
      now,
    );
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
  }

  // ───────────────────────────────────────────────────────────────────────
  // Domain: Trust
  // ───────────────────────────────────────────────────────────────────────

  trustQueryScore(did: string, contextId: string): unknown {
    return (this.#native.trustQueryScore as (d: string, c: string) => unknown)(did, contextId);
  }

  trustVerifyAttestation(attestationJson: string): unknown {
    return (this.#native.trustVerifyAttestation as (j: string) => unknown)(attestationJson);
  }

  trustCreateChallenge(targetDid: string): unknown {
    return (this.#native.trustCreateChallenge as (d: string) => unknown)(targetDid);
  }

  trustVerifyResponse(challengeJson: string, responseJson: string): boolean {
    return (this.#native.trustVerifyResponse as (c: string, r: string) => boolean)(
      challengeJson,
      responseJson,
    );
  }

  verifyParticipationRequirements(profileJson: string, requirementsJson: string): boolean {
    return (this.#native.verifyParticipationRequirements as (p: string, r: string) => boolean)(
      profileJson,
      requirementsJson,
    );
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
  }

  // ───────────────────────────────────────────────────────────────────────
  // Domain: Relay / Node
  // ───────────────────────────────────────────────────────────────────────

  async relayStartInMemory(): Promise<Relay> {
    const raw = await (this.#native.relayStartInMemory as () => Promise<unknown>)();
    const { Relay: RelayCls } = await import("./server");
    return RelayCls._fromHandle(raw, this);
  }

  async relayStartLocal(dataDir: string): Promise<Relay> {
    const raw = await (this.#native.relayStartLocal as (d: string) => Promise<unknown>)(dataDir);
    const { Relay: RelayCls } = await import("./server");
    return RelayCls._fromHandle(raw, this);
  }

  async nodeStartInMemory(identityDid?: string | null): Promise<Node> {
    const raw = await (this.#native.nodeStartInMemory as (d: string | null) => Promise<unknown>)(
      identityDid ?? null,
    );
    const { Node: NodeCls } = await import("./server");
    return NodeCls._fromHandle(raw, this);
  }

  async nodeStartLocal(
    dataDir: string,
    identityDid?: string | null,
    passphrase?: string | null,
  ): Promise<Node> {
    const raw = await (
      this.#native.nodeStartLocal as (
        d: string,
        id: string | null,
        p: string | null,
      ) => Promise<unknown>
    )(dataDir, identityDid ?? null, passphrase ?? null);
    const { Node: NodeCls } = await import("./server");
    return NodeCls._fromHandle(raw, this);
  }

  // ───────────────────────────────────────────────────────────────────────
  // Domain: MCP
  // ───────────────────────────────────────────────────────────────────────

  async mcpServerCreate(config: unknown): Promise<unknown> {
    return await (this.#native.mcpServerCreate as (c: unknown) => Promise<unknown>)(config);
  }

  async mcpServerStop(handle: unknown): Promise<void> {
    await (this.#native.mcpServerStop as (h: unknown) => Promise<void>)(handle);
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
    return await (this.#native.mcpClientConnectStdio as (c: readonly string[]) => Promise<unknown>)(
      command,
    );
  }

  async mcpClientConnectSse(url: string): Promise<unknown> {
    return await (this.#native.mcpClientConnectSse as (u: string) => Promise<unknown>)(url);
  }

  async mcpClientDisconnect(handle: unknown): Promise<void> {
    await (this.#native.mcpClientDisconnect as (h: unknown) => Promise<void>)(handle);
  }

  async mcpClientListTools(handle: unknown): Promise<readonly unknown[]> {
    return await (this.#native.mcpClientListTools as (h: unknown) => Promise<readonly unknown[]>)(
      handle,
    );
  }

  async mcpClientInvoke(
    handle: unknown,
    toolName: string,
    inputJson: string,
    contextId: string,
    invokerDid: string,
  ): Promise<unknown> {
    return await (
      this.#native.mcpClientInvoke as (
        h: unknown,
        t: string,
        i: string,
        c: string,
        d: string,
      ) => Promise<unknown>
    )(handle, toolName, inputJson, contextId, invokerDid);
  }

  mcpConfigureStdioAllowlist(additionalBinaries: readonly string[]): void {
    (this.#native.mcpConfigureStdioAllowlist as (b: readonly string[]) => void)(additionalBinaries);
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
    (this.#native.mcpDisableStdioAllowlist as () => void)();
  }

  mcpResetStdioAllowlist(): void {
    (this.#native.mcpResetStdioAllowlist as () => void)();
  }

  mcpGetStdioAllowlist(): McpAllowlistState {
    return (this.#native.mcpGetStdioAllowlist as () => McpAllowlistState)();
  }

  // ───────────────────────────────────────────────────────────────────────
  // Domain: Fullstack (E2E test harness)
  // ───────────────────────────────────────────────────────────────────────

  fullstackCreateNode(did: string): unknown {
    return (this.#native.fullstackCreateNode as (d: string) => unknown)(did);
  }

  fullstackResetNetwork(): void {
    (this.#native.fullstackResetNetwork as () => void)();
  }

  fullstackCreateContext(node: unknown, contextId: string, ceilingJson: string): string {
    return (this.#native.fullstackCreateContext as (n: unknown, c: string, j: string) => string)(
      node,
      contextId,
      ceilingJson,
    );
  }

  fullstackAddMember(node: unknown, contextId: string, memberDid: string): void {
    (this.#native.fullstackAddMember as (n: unknown, c: string, m: string) => void)(
      node,
      contextId,
      memberDid,
    );
  }

  fullstackJoinFromWelcome(node: unknown, contextId: string): void {
    (this.#native.fullstackJoinFromWelcome as (n: unknown, c: string) => void)(node, contextId);
  }

  fullstackSyncSenderKeys(nodeA: unknown, nodeB: unknown, contextId: string): void {
    (this.#native.fullstackSyncSenderKeys as (a: unknown, b: unknown, c: string) => void)(
      nodeA,
      nodeB,
      contextId,
    );
  }

  fullstackSendMessage(node: unknown, contextId: string, payload: Uint8Array | Buffer): Uint8Array {
    const raw = (
      this.#native.fullstackSendMessage as (
        n: unknown,
        c: string,
        p: Uint8Array | Buffer,
      ) => Uint8Array | Buffer
    )(node, contextId, payload);
    return new Uint8Array(raw);
  }

  fullstackDecryptMessage(
    node: unknown,
    contextId: string,
    ciphertext: Uint8Array | Buffer,
    senderDid: string,
  ): Uint8Array {
    const raw = (
      this.#native.fullstackDecryptMessage as (
        n: unknown,
        c: string,
        ct: Uint8Array | Buffer,
        s: string,
      ) => Uint8Array | Buffer
    )(node, contextId, ciphertext, senderDid);
    return new Uint8Array(raw);
  }

  fullstackRemoveMember(node: unknown, contextId: string, memberDid: string): void {
    (this.#native.fullstackRemoveMember as (n: unknown, c: string, m: string) => void)(
      node,
      contextId,
      memberDid,
    );
  }

  // ───────────────────────────────────────────────────────────────────────
  // Domain: Media
  // ───────────────────────────────────────────────────────────────────────

  mediaCheckCapability(ceiling: readonly string[], capability: string): boolean {
    return (this.#native.mediaCheckCapability as (c: readonly string[], cap: string) => boolean)(
      ceiling,
      capability,
    );
  }

  mediaInitiateSession(
    contextId: string,
    ceiling: readonly string[],
    capabilities: readonly string[],
    participants: readonly string[],
    timestamp: number,
  ): string {
    return (
      this.#native.mediaInitiateSession as (
        c: string,
        cl: readonly string[],
        caps: readonly string[],
        p: readonly string[],
        t: number,
      ) => string
    )(contextId, ceiling, capabilities, participants, timestamp);
  }

  mediaActivateSession(sessionJson: string): string {
    return (this.#native.mediaActivateSession as (s: string) => string)(sessionJson);
  }

  mediaJoinSession(sessionJson: string, participantDid: string): string {
    return (this.#native.mediaJoinSession as (s: string, p: string) => string)(
      sessionJson,
      participantDid,
    );
  }

  mediaEndSession(sessionJson: string, timestamp: number): string {
    return (this.#native.mediaEndSession as (s: string, t: number) => string)(
      sessionJson,
      timestamp,
    );
  }

  mediaCreateOffer(sessionId: string, sdp: string, senderDid: string): string {
    return (this.#native.mediaCreateOffer as (s: string, sdp: string, d: string) => string)(
      sessionId,
      sdp,
      senderDid,
    );
  }

  mediaCreateAnswer(sessionId: string, sdp: string, senderDid: string): string {
    return (this.#native.mediaCreateAnswer as (s: string, sdp: string, d: string) => string)(
      sessionId,
      sdp,
      senderDid,
    );
  }

  mediaCreateIceCandidate(
    sessionId: string,
    candidate: string,
    senderDid: string,
    sdpMid?: string,
    sdpMlineIndex?: number,
  ): string {
    return (
      this.#native.mediaCreateIceCandidate as (
        s: string,
        c: string,
        d: string,
        m: string | undefined,
        i: number | undefined,
      ) => string
    )(sessionId, candidate, senderDid, sdpMid, sdpMlineIndex);
  }

  mediaCreateSessionEnd(sessionId: string, senderDid: string): string {
    return (this.#native.mediaCreateSessionEnd as (s: string, d: string) => string)(
      sessionId,
      senderDid,
    );
  }

  mediaSendSignaling(signalingJson: string): string {
    return (this.#native.mediaSendSignaling as (s: string) => string)(signalingJson);
  }

  mediaVerifySenderAttribution(signalingJson: string, envelopeSenderDid: string): boolean {
    return (this.#native.mediaVerifySenderAttribution as (s: string, e: string) => boolean)(
      signalingJson,
      envelopeSenderDid,
    );
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
    return await (
      this.#native.evaluateProvenanceQuality as (
        sc: string | undefined,
        st: string,
        cs: string,
        cp: readonly string[] | undefined,
      ) => Promise<number>
    )(sourceContext, sourceType, contextState, counterparties);
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
  }

  provenanceCheckChainDepth(chainDepth: number, maxDepth?: number): boolean {
    return (
      this.#native.provenanceCheckChainDepth as (c: number, m: number | undefined) => boolean
    )(chainDepth, maxDepth);
  }

  provenanceRedactCounterparties(provenanceJson: string): string {
    return (this.#native.provenanceRedactCounterparties as (j: string) => string)(provenanceJson);
  }

  provenancePseudonymizeCounterparties(provenanceJson: string, pseudonymKeyHex: string): string {
    return (this.#native.provenancePseudonymizeCounterparties as (j: string, k: string) => string)(
      provenanceJson,
      pseudonymKeyHex,
    );
  }

  provenanceUpdateSourceType(provenanceJson: string, newState: string): string {
    return (this.#native.provenanceUpdateSourceType as (j: string, s: string) => string)(
      provenanceJson,
      newState,
    );
  }

  // ───────────────────────────────────────────────────────────────────────
  // Domain: Sync
  // ───────────────────────────────────────────────────────────────────────

  syncClassifyOffline(lastRelayContact: number, now: number): string {
    return (this.#native.syncClassifyOffline as (l: number, n: number) => string)(
      lastRelayContact,
      now,
    );
  }

  syncGetPolicy(): unknown {
    return (this.#native.syncGetPolicy as () => unknown)();
  }

  syncClassifyOfflineCustom(
    lastRelayContact: number,
    now: number,
    tier1ThresholdSecs: number,
    tier2ThresholdSecs: number,
  ): string {
    return (
      this.#native.syncClassifyOfflineCustom as (
        l: number,
        n: number,
        t1: number,
        t2: number,
      ) => string
    )(lastRelayContact, now, tier1ThresholdSecs, tier2ThresholdSecs);
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
    return (
      this.#native.bridgeCreateShadow as (
        b: string,
        p: string,
        m: string,
        c: string | undefined,
      ) => unknown
    )(bridgeId, platformHandle, bridgeMode, contextId);
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
  }

  /** Retrieves and decrypts a credential for a bridge instance. */
  bridgeCredentialRetrieve(
    bridgeId: string,
    credentialType: string,
    bridgeCredentialKey: Uint8Array | readonly number[],
  ): Uint8Array {
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
  }

  /** Rotates (replaces) a credential for a bridge instance. */
  bridgeCredentialRotate(
    bridgeId: string,
    credentialType: string,
    newPlaintext: Uint8Array | readonly number[],
    bridgeCredentialKey: Uint8Array | readonly number[],
  ): BridgeCredential {
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
  }

  /** Revokes all credentials for a bridge instance. */
  bridgeCredentialRevoke(bridgeId: string): void {
    (this.#native.bridgeCredentialRevoke as (b: string) => void)(bridgeId);
  }

  /** Lists all credential types stored for a bridge instance. */
  bridgeCredentialList(bridgeId: string): string[] {
    return (this.#native.bridgeCredentialList as (b: string) => string[])(bridgeId);
  }

  /** Stores a bridge credential key in the custody boundary. */
  bridgeCredentialStoreKey(bridgeId: string, key: Uint8Array | readonly number[]): void {
    const keyArray = ArrayBuffer.isView(key)
      ? Array.from(key as Uint8Array)
      : (key as readonly number[]);
    (this.#native.bridgeCredentialStoreKey as (b: string, k: readonly number[]) => void)(
      bridgeId,
      keyArray,
    );
  }

  /** Retrieves a bridge credential key from the custody boundary. */
  bridgeCredentialGetKey(bridgeId: string): Uint8Array {
    const raw = (this.#native.bridgeCredentialGetKey as (b: string) => number[])(bridgeId);
    return Uint8Array.from(raw as readonly number[]);
  }

  /** Deletes and zeroizes a bridge credential key. */
  bridgeCredentialDeleteKey(bridgeId: string): void {
    (this.#native.bridgeCredentialDeleteKey as (b: string) => void)(bridgeId);
  }

  // ───────────────────────────────────────────────────────────────────────
  // Domain: SCPID
  // ───────────────────────────────────────────────────────────────────────

  scpidChallenge(audience: string, ttlSeconds: number): string {
    return (this.#native.scpidChallenge as (a: string, t: number) => string)(audience, ttlSeconds);
  }

  scpidSign(did: string, signingKeyId: string, challengeJson: string): string {
    return (this.#native.scpidSign as (d: string, k: string, c: string) => string)(
      did,
      signingKeyId,
      challengeJson,
    );
  }

  scpidVerify(responseJson: string, challengeJson: string): string {
    return (this.#native.scpidVerify as (r: string, c: string) => string)(
      responseJson,
      challengeJson,
    );
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

/**
 * Production guard for the two test-only native-handle mutators.
 * Throws when the current runtime looks like a production build so
 * that even if a supply-chain attacker deep-imports `dist/scp.js` and
 * reaches these helpers they cannot swap the native bridge behind a
 * user's back (round-3 red-hat RED-PR5-001/007).
 *
 * The gate uses `process.env.NODE_ENV === "production"` — the widely-
 * honoured React/Node build-flag. Apps that ship with
 * `NODE_ENV=production` get the guard; tests run with `NODE_ENV=test`
 * or unset, which passes through. `process` may be undefined in
 * browser/Deno contexts — we treat that as "not production" since the
 * WASM bridge has no `SCP` class at all.
 */
function assertTestHookAllowed(hookName: string): void {
  const env: string | undefined = (() => {
    try {
      return (globalThis as { process?: { env?: { NODE_ENV?: string } } }).process?.env?.NODE_ENV;
    } catch {
      return undefined;
    }
  })();
  if (env === "production") {
    throw new Error(
      `${hookName} is a test-only hook and must not be called in a production build ` +
        `(NODE_ENV=production). If you're seeing this in legitimate code, your build is ` +
        `mis-configured or a dependency is attempting to swap the SCP native bridge.`,
    );
  }
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
 * Guarded by `NODE_ENV === "production"` throw to close the
 * round-3 red-hat RED-PR5-007 attack chain (smuggled-native SCP
 * injection into a downstream library).
 *
 * @internal
 */
export function __constructScpWithNativeForTests(native: unknown): SCP {
  assertTestHookAllowed("__constructScpWithNativeForTests");
  return new SCP({
    [NATIVE_OVERRIDE]: native as NativeScpInstance,
  } as unknown as ScpOptions);
}
