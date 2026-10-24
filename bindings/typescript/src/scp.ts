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
 * const identity = await scp.identityCreate("encrypted_file");
 * await scp.resume();                    // async — reconnects transport
 * await scp.shutdown(5);                 // graceful shutdown
 * ```
 *
 * Phase 4 PR 4 (#1549, ADR-048) expanded the `SCP` surface so every NAPI
 * bridge operation has a corresponding instance method on `SCP`. The
 * process-wide default-instance façade and free-function shorthands were
 * deleted — callers construct an explicit `new SCP()` and invoke methods
 * directly (e.g. `scp.identityCreate("encrypted_file")`).
 *
 * NOTE: `SCP` requires a Node.js or Bun runtime with the native addon.
 * Browser clients run the full protocol in-tab (keys on-device) via the
 * sibling `@limn-works/scp-ts-wasm` package over `scp-client-wasm` (ADR-057,
 * which amends ADR-055's remote-thin-client browser model); constructing
 * `SCP` outside a Node.js/Bun runtime throws `ValidationError` with
 * `SCP-VALID-7005`.
 */

// The handle classes (`Context`, `Identity`, `McpServer`, `McpClient`,
// `TransportManager`) are value imports: every public method checks its
// handle argument synchronously with the class's private-field brand check
// before any bridge call. `context.ts` imports `__getNativeScp` from this
// module, so the two modules form an import cycle; it is safe because
// neither module touches the other's exports while it evaluates, only
// inside function bodies. The `server.ts` classes stay lazily imported.
import { Context } from "./context";
import type { PaymentReceiptVerificationResult } from "./economy";
import {
  ContextError,
  IdentityError,
  mapBridgeError,
  mapSagaError,
  ScpError,
  ValidationError,
} from "./errors";
import { type CustodyType, Identity } from "./identity";
import {
  type BridgeContextHandle,
  type BridgeIdentityHandle,
  getBridge,
  toCapabilityValidation,
} from "./internal/bridge";
import { toNativeCustodyProvider } from "./internal/custody-adapter";
import {
  loadNativeAddon,
  NATIVE_ADDON_ABSENT_CODE,
  NATIVE_ADDON_LOAD_FAILED_CODE,
  type NativeNodeStart,
  type NativeAddon as RawNativeAddon,
} from "./internal/native";
import { assertTestEnvironment } from "./internal/test-guard";
import { McpClient, McpServer } from "./mcp";
import type { StreamingSagaNative, StreamingSagaOptions } from "./outlets";
import { StreamingSagaHandle } from "./outlets";
import { decodeProvenanceRecord, type ProvenanceRecord } from "./provenance";
import type { Node, NodeStartConfig, Relay } from "./server";
import { TransportManager } from "./transport";
import type {
  AttestationType,
  AttestorInfo,
  BehavioralRecord,
  CachedAttestation,
  CachedAttestationEnvelope,
  CapabilityRequirement,
  CapabilityValidation,
  ChallengePolicy,
  ChallengeRequest,
  ChallengeResponse,
  ChallengeVerification,
  ConsequenceRule,
  CreateChallengeConfig,
  EventLogEntry,
  GovernanceActionResult,
  GradedChallenge,
  InviteMemberOutcome,
  MemberRole,
  OutletDefinition,
  ParticipationProfile,
  RequireParticipation,
  SagaResult,
  SealedInvitation,
  TestOutput,
  ThresholdRequirement,
  TrustEvaluation,
} from "./types";
import {
  checkProposalResponse,
  decodeCaseResults,
  decodeChallengeRequest,
  decodeChallengeResponse,
  decodeChallengeVerification,
  encodeAttestation,
  encodeAttestorSets,
  encodeCachedAttestations,
  encodeCapabilityRequirements,
  encodeChallengeRequest,
  encodeChallengeResponse,
  encodeChallengeVerifications,
  encodeConsequenceRules,
  encodeEventLogEntries,
  encodeMerkleRoot,
  encodeParticipationProfile,
  encodeRequireParticipation,
  encodeTestCases,
  encodeTestOutputs,
  encodeThresholdRequirements,
  evaluatorContextOf,
  governanceActionResultFromBridge,
  memberRoleFromBridge,
} from "./types";

/**
 * Stable error code (spec §7.3.2) the core surfaces when a context has no
 * recorded participation facts yet (an empty event log). {@link
 * SCP.evaluateTrust} branches Layer 2 on this structured code — NOT on error
 * prose — folding "no facts yet" into a zeroed behavioral record while letting
 * every other failure propagate. Maps from `ContextError::NoParticipationFacts`
 * across all bridges.
 */
const NO_PARTICIPATION_FACTS_CODE = "SCP-CTX-2076";

/**
 * Code an identity-creating method raises, before any bridge call, when an
 * untyped caller passes no custody (`IDENT_1116` in
 * `crates/scp-ffi/common/src/error_codes.rs`; SCP-294).
 */
export const CUSTODY_REQUIRED_CODE = "SCP-IDENT-1116";

/**
 * Code {@link SCP.suspend} throws, as a `StorageError`, when a context
 * snapshot did not persist or the flush missed the deadline; the instance
 * stays running with its transport connected (`STORAGE_8014` in
 * `crates/scp-ffi/common/src/error_codes.rs`).
 */
export const SUSPEND_FLUSH_FAILED_CODE = "SCP-STORAGE-8014";

/**
 * Code {@link SCP.shutdown} throws, as a `StorageError`, when the instance
 * shut down and released its store but a context snapshot did not persist
 * within the deadline (`STORAGE_8015` in
 * `crates/scp-ffi/common/src/error_codes.rs`).
 */
export const SHUTDOWN_FLUSH_FAILED_CODE = "SCP-STORAGE-8015";

/** Remedy for a method whose custody argument is a {@link CustodyType}. */
const CUSTODY_VALUE_REMEDY =
  'pass "encrypted_file" (an encrypted key file at $HOME/.scp/keys.bin, sealed under ' +
  "SCP_KEY_PASSPHRASE), or call identityCreateWithCustody() with a KeyCustodyProvider for " +
  '"os_keystore" (the host key store)';

/** Remedy for a method whose custody argument is a {@link KeyCustodyProvider}. */
const CUSTODY_PROVIDER_REMEDY =
  "pass a KeyCustodyProvider, or call identityCreate() with a CustodyType " +
  "to use a key store this SDK builds";

function custodyRequiredError(method: string, remedy: string): IdentityError {
  return new IdentityError(
    `${method}() requires a custody argument and this SDK names no default key store: ${remedy}`,
    CUSTODY_REQUIRED_CODE,
  );
}

/**
 * Rejects a custody argument the type checker would have rejected: absent,
 * `null`, or not a string. A string goes on to the bridge, which answers a
 * string it builds no key store from with its own typed error.
 */
function requireCustody(method: string, custody: unknown): void {
  if (custody === undefined || custody === null) {
    throw custodyRequiredError(method, CUSTODY_VALUE_REMEDY);
  }
  if (typeof custody !== "string") {
    throw new ValidationError(
      `${method}() custody must be a string naming a key store; got ${typeof custody}`,
      "SCP-VALID-7005",
    );
  }
}

// ---------------------------------------------------------------------------
// Handle arguments
// ---------------------------------------------------------------------------

/** Names what a caller passed in place of a handle, for the error message. */
function describeArgument(value: unknown): string {
  if (value === null) return "null";
  if (typeof value !== "object") return typeof value;
  const name = (value as { constructor?: { name?: unknown } }).constructor?.name;
  return typeof name === "string" && name !== "" ? `an object of class ${name}` : "an object";
}

/**
 * The typed error a public `SCP` method throws when a handle argument is not
 * the SDK object the SDK returned. A raw native handle (a `Context`'s private
 * `_rawHandle`, say) fails here too: the methods take the SDK object only.
 */
function invalidHandleError(
  method: string,
  param: string,
  expected: string,
  value: unknown,
): ValidationError {
  return new ValidationError(
    `${method}() ${param} must be a ${expected} this SDK returned; got ${describeArgument(value)}`,
    "SCP-VALID-7005",
  );
}

/** Returns the bridge handle of a `Context`, or throws `SCP-VALID-7005`. */
function contextHandle(method: string, param: string, value: unknown): BridgeContextHandle {
  if (!Context._isContext(value)) throw invalidHandleError(method, param, "Context", value);
  return value._rawHandle;
}

/** Returns the bridge handle of an `Identity`, or throws `SCP-VALID-7005`. */
function identityHandle(method: string, param: string, value: unknown): BridgeIdentityHandle {
  if (!Identity._isIdentity(value)) throw invalidHandleError(method, param, "Identity", value);
  return value._rawHandle;
}

/** The params field the SDK encodes before `contextCreate` reaches the bridge. */
const CAPABILITY_REQUIREMENTS_FIELD = "capabilityRequirements";

/** Returns the index of the first non-whitespace character at or after `i`. */
function skipJsonWhitespace(text: string, i: number): number {
  let at = i;
  while (at < text.length && " \t\n\r".includes(text.charAt(at))) at++;
  return at;
}

/** Returns the index just past the JSON string whose opening quote is at `i`. */
function endOfJsonString(text: string, i: number): number {
  let at = i + 1;
  while (text.charAt(at) !== '"') at += text.charAt(at) === "\\" ? 2 : 1;
  return at + 1;
}

/**
 * Returns the index just past the JSON value that starts at `i` in `text`,
 * which the caller has already checked parses. A string ends at its closing
 * quote; an object or array at its matching bracket; a number or literal at
 * the next delimiter.
 */
function endOfJsonValue(text: string, i: number): number {
  let depth = 0;
  let at = i;
  while (at < text.length) {
    const ch = text.charAt(at);
    if (ch === '"') {
      at = endOfJsonString(text, at);
      if (depth === 0) return at;
      continue;
    }
    if (ch === "{" || ch === "[") {
      depth++;
    } else if (ch === "}" || ch === "]") {
      if (depth <= 1) return depth === 0 ? at : at + 1;
      depth--;
    } else if (depth === 0 && (ch === "," || " \t\n\r".includes(ch))) {
      return at;
    }
    at++;
  }
  return at;
}

/**
 * Returns the `[start, end)` source span of each value the top-level object
 * in `text` holds under `key`, comparing keys as `JSON.parse` decodes them.
 * `text` must already parse as a JSON object.
 */
function topLevelValueSpans(text: string, key: string): [number, number][] {
  const spans: [number, number][] = [];
  let at = skipJsonWhitespace(text, 0) + 1;
  for (;;) {
    at = skipJsonWhitespace(text, at);
    if (text.charAt(at) === "}") return spans;
    const keyEnd = endOfJsonValue(text, at);
    const name: unknown = JSON.parse(text.slice(at, keyEnd));
    at = skipJsonWhitespace(text, keyEnd) + 1;
    const valueStart = skipJsonWhitespace(text, at);
    const valueEnd = endOfJsonValue(text, valueStart);
    if (name === key) spans.push([valueStart, valueEnd]);
    at = skipJsonWhitespace(text, valueEnd);
    if (text.charAt(at) === ",") at++;
  }
}

/**
 * Returns the params JSON `contextCreate` sends to the bridge: `paramsJson`
 * with the value of its top-level `capabilityRequirements`, a list of typed
 * {@link CapabilityRequirement}s, replaced by the wire-form JSON string
 * {@link encodeCapabilityRequirements} returns. Every other byte of
 * `paramsJson` reaches the bridge as the caller wrote it, so an integer
 * above 2^53 keeps its value.
 *
 * Params JSON that does not parse to an object, or that names no
 * requirements, goes to the bridge unchanged, so the bridge reports its
 * other defects with its own codes.
 *
 * @throws ValidationError `SCP-VALID-7001` when `capabilityRequirements` is
 *   not a list, such as a JSON string of the wire form;
 *   {@link INVALID_REQUIREMENT_CODE} or `SCP-VALID-7001` for an entry
 *   {@link encodeCapabilityRequirements} refuses.
 */
function encodeContextParamsJson(paramsJson: string): string {
  let params: unknown;
  try {
    params = JSON.parse(paramsJson);
  } catch {
    return paramsJson;
  }
  if (params === null || typeof params !== "object" || Array.isArray(params)) {
    return paramsJson;
  }
  let encoded = paramsJson;
  // Right to left, so each replacement leaves the earlier spans in place.
  for (const [start, end] of topLevelValueSpans(
    paramsJson,
    CAPABILITY_REQUIREMENTS_FIELD,
  ).reverse()) {
    // Only the requirements are parsed: they are typed SDK values, which
    // encodeCapabilityRequirements reads as JavaScript values.
    const requirements: unknown = JSON.parse(paramsJson.slice(start, end));
    if (requirements === null) continue;
    if (!Array.isArray(requirements)) {
      throw new ValidationError(
        `contextCreate() params.capabilityRequirements must be a list of CapabilityRequirement, got ${JSON.stringify(requirements)}`,
        "SCP-VALID-7001",
      );
    }
    encoded = `${encoded.slice(0, start)}${JSON.stringify(encodeCapabilityRequirements(requirements))}${encoded.slice(end)}`;
  }
  return encoded;
}

/** Returns the bridge handle of a `TransportManager`, or throws `SCP-VALID-7005`. */
function transportManagerHandle(method: string, param: string, value: unknown): unknown {
  if (!TransportManager._isTransportManager(value)) {
    throw invalidHandleError(method, param, "TransportManager", value);
  }
  return value._rawHandle;
}

/** Returns the bridge handle of an `McpServer`, or throws `SCP-VALID-7005`. */
function mcpServerHandle(method: string, param: string, value: unknown): unknown {
  if (!McpServer._isMcpServer(value)) throw invalidHandleError(method, param, "McpServer", value);
  return value._rawHandle;
}

/** Returns the bridge handle of an `McpClient`, or throws `SCP-VALID-7005`. */
function mcpClientHandle(method: string, param: string, value: unknown): unknown {
  if (!McpClient._isMcpClient(value)) throw invalidHandleError(method, param, "McpClient", value);
  return value._rawHandle;
}

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
  // P-256 pseudonym point helpers (§9.10.4.A), module-level free functions.
  p256PseudonymPoint?: unknown;
  p256SoftwarePseudonymPoint?: unknown;
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
  suspend(timeoutMillis: bigint): Promise<void>;
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
 * `ValidationError` (`SCP-VALID-7081`) when the platform package is
 * missing, which this wrapper rethrows under the same code with the
 * reinstall instruction SDK consumers see when they call `new SCP(...)`.
 * An installed addon that failed to load passes through as the loader's
 * `ValidationError` (`SCP-VALID-7082`), and an addon that loaded without the `SCP`
 * class throws the same code, so neither is reported as a missing package.
 */
function loadAddon(): NativeAddon {
  if (typeof process === "undefined" || !process.versions?.node) {
    throw new ValidationError(
      "SCP class requires a Node.js or Bun runtime — @limn-works/scp-ts is a " +
        "native (napi-rs) SDK. Browser clients run the full protocol in-tab via " +
        "@limn-works/scp-ts-wasm (ADR-057, keys on-device).",
      "SCP-VALID-7005",
    );
  }

  let addon: NativeAddon;
  try {
    addon = loadNativeAddon() as NativeAddon;
  } catch (cause) {
    throw addonLoadError(cause);
  }

  requireAddonExport(addon, "SCP");
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
 * Throws `SCP-VALID-7081` if no addon is installed. Throws
 * `SCP-VALID-7082` if the addon is installed and failed to load, and
 * also if it loaded without the named function (e.g., a stale prebuilt
 * addon predating the §1 split).
 */
function nativeFreeFn<T>(name: keyof NativeAddon): T {
  return requireAddonExport<T>(loadAddon(), String(name));
}

// ---------------------------------------------------------------------------
// Internal helpers (exported for tests, not part of the public API)
// ---------------------------------------------------------------------------

/**
 * Maps an error `loadNativeAddon` threw to the error `loadAddon` throws.
 *
 * Only the loader's absence error — an `ScpError` carrying
 * `SCP-VALID-7081`, which the loader throws when the platform package does
 * not resolve — becomes absence: a `ValidationError` with that code and the
 * reinstall instruction. Every other `ScpError`, the loader's `SCP-VALID-7082` among
 * them, is returned unchanged. Any other thrown value is a failure the
 * loader did not classify, raised while an addon package may well be
 * installed, so it becomes a `ValidationError` with the load-failure code
 * `SCP-VALID-7082` and never counts as absence.
 *
 * @internal
 */
export function addonLoadError(cause: unknown): ScpError {
  const underlying = (cause as Error)?.message ?? String(cause);
  if (cause instanceof ScpError && cause.code === NATIVE_ADDON_ABSENT_CODE) {
    return new ValidationError(
      `Native addon is not installed: ${underlying}. ` +
        "Ensure the matching @limn-works/scp-ts-napi-* platform package is " +
        "installed, then reinstall with `bun install`.",
      NATIVE_ADDON_ABSENT_CODE,
    );
  }
  if (cause instanceof ScpError) {
    return cause;
  }
  const error = new ValidationError(
    `Native addon failed to load: ${underlying}.`,
    NATIVE_ADDON_LOAD_FAILED_CODE,
  );
  Object.defineProperty(error, "cause", { value: cause, enumerable: false });
  return error;
}

/**
 * Returns `addon[name]` when it is a function.
 *
 * An addon that loaded without an export the SDK calls — the `SCP` class or
 * an ADR-048 §1 module-level free function — is installed and stale or
 * partially built, not absent. This function throws the loader's
 * load-failure code `SCP-VALID-7082`, so no caller mistakes the stale
 * addon for the absence code `SCP-VALID-7081`.
 *
 * @throws {ValidationError} `SCP-VALID-7082` when `addon[name]` is not a function.
 * @internal
 */
export function requireAddonExport<T>(addon: NativeAddon, name: string): T {
  const value = addon[name];
  if (typeof value !== "function") {
    throw new ValidationError(
      `Native addon loaded but does not export "${name}" — the installed ` +
        "platform addon is stale or partially built. Rebuild it with " +
        "`cargo build -p scp-ffi-napi` or upgrade the platform package.",
      NATIVE_ADDON_LOAD_FAILED_CODE,
    );
  }
  return value as T;
}

/**
 * Clamps a float-seconds timeout into a millisecond count suitable for
 * the NAPI `shutdown(timeoutMillis)` boundary.
 *
 * @internal
 */
export function clampShutdownMillis(timeoutSecs: number): number {
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
 * Passes `args` to the native P-256 helper `fn` and returns its result as
 * the one `Uint8Array` the host owns.
 *
 * NAPI `Vec<u8>` parameters and returns are `number[]` in JS. The
 * `number[]` copies of the arguments, and the `number[]` result once it is
 * copied into the returned `Uint8Array`, are wiped with `fill(0)`.
 *
 * @internal
 */
export function __p256HostInvokeForTests(
  fn: (...a: number[][]) => number[],
  args: readonly Uint8Array[],
): Uint8Array {
  const raw = args.map((a) => Array.from(a));
  let out: number[] | undefined;
  try {
    out = fn(...raw);
    return Uint8Array.from(out);
  } catch (err) {
    throw mapBridgeError(err);
  } finally {
    for (const r of raw) {
      r.fill(0);
    }
    out?.fill(0);
  }
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
  /**
   * Offline tier classification; absent when the context's
   * `last_relay_contact` is absent or unreadable, so no tier was classified
   * (see {@link ContextReconnectResult.failureCode}).
   */
  readonly tier?: ReconnectTier;
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
  /**
   * Envelopes the actor accepted as application messages during this
   * context's reconnection.
   */
  readonly envelopesDelivered: number;
  /**
   * Why writing the context's `last_relay_contact` failed after
   * `needsReconnect` was cleared; absent when the write succeeded or no write
   * was due.
   */
  readonly relayContactError?: string;
  /**
   * The code of a failure that ended this context's reconnection before its
   * tier was classified: `SCP-TRANS-5102` when no `last_relay_contact` is
   * stored, `SCP-TRANS-5103` when reading it failed. Absent for a classified
   * context, whose `outcome` carries the result.
   */
  readonly failureCode?: string;
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
 * The opaque `(reservationId, keyPackagePublic)` pair returned by
 * {@link SCP.reserveKeyPackage} (ADR-049 Phase 2J).
 *
 * The joiner's private signer state never leaves the native core — only the
 * PUBLIC `KeyPackage` bytes cross the FFI boundary. Hand `keyPackagePublic` to
 * the context creator (out of band) so it can mint a Welcome addressed to this
 * reservation, then pass `reservationId` back to
 * {@link SCP.contextJoinFromWelcome}.
 */
export interface KeyPackageReservation {
  /**
   * Opaque reservation id — a lookup key, not a capability. Pass back to
   * {@link SCP.contextJoinFromWelcome} for the Welcome this `KeyPackage`
   * addresses.
   */
  readonly reservationId: string;
  /**
   * PUBLIC MLS `KeyPackage` bytes to hand (out of band) to the context creator,
   * who adds them to its MLS group to mint the addressed Welcome.
   */
  readonly keyPackagePublic: Uint8Array;
}

/**
 * The type of a custody key: Ed25519, `"p256"` (ECDSA P-256 signing) or
 * `"hpke-p256"` (P-256 ECDH for HPKE).
 */
export type CustodyKeyType = "ed25519" | "p256" | "hpke-p256";

/**
 * The role a custody key was minted in: `"identity"` (the only source a
 * pseudonym derives from) or `"operational"`.
 */
export type CustodyKeyRole = "identity" | "operational";

/** A custody key's type, public key and role, returned by {@link KeyCustodyProvider.getPublicKey}. */
export interface CustodyPublicKey {
  /** The key's type. */
  keyType: CustodyKeyType;
  /** The public key in the exact encoding its type names. */
  publicKey: Uint8Array;
  /** The role the key was minted in. */
  role: CustodyKeyRole;
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
 * the Node.js event loop). Byte values are passed and returned as `Uint8Array`.
 *
 * Key identifiers are handles your implementation assigns in
 * {@link generateKeypair}. Each is the canonical
 * decimal form of an unsigned 64-bit integer, as `String(n)` writes it for a
 * `bigint` `n` in `[0, 2^64 - 1]`: ASCII digits only, with no sign, no leading
 * zero (`"0"` itself is allowed) and no whitespace. The bridge rejects any
 * other id (`"007"`, `"+7"`, `" 7"`, a UUID) with the custody error
 * `SCP-CRYPTO-4060`.
 *
 * A pseudonym has no private key (spec §9.10.4): your implementation stores no
 * pseudonym key and signs with none, so `sign`, `getPublicKey` and
 * `destroyKey` never receive a pseudonym.
 *
 * A callback reports failure by throwing. Throw an error whose `code` is
 * `"SCP-CRYPTO-4006"` (key not found), such as
 * `new CryptoError(msg, "SCP-CRYPTO-4006")`, for a key id that was destroyed or
 * never existed; the SDK call then rejects with a `CryptoError` carrying that
 * code. Any other throw, whatever its code or value, rejects the SDK call with
 * the custody error `SCP-CRYPTO-4060` carrying the thrown code and message.
 * Every SDK operation that calls the provider reports these two codes,
 * including the pseudonym derivation inside `createContext` and the identity
 * key reads and signatures of identity operations. There are two exceptions:
 * `SCP-IDENT-1055`, reported when the bytes a {@link derivePseudonym} or
 * {@link deriveRotatablePseudonym} call returned are not a compressed P-256
 * point, and `SCP-IDENT-1037`, which
 * `scpidSign` reports for any custody failure (spec §3.11.4).
 *
 * Every callback must be synchronous and return the type its signature names.
 * A callback that returns a Promise or other thenable, or a value of the wrong
 * type, fails the SDK call with `SCP-CRYPTO-4060`; the SDK attaches a handler
 * to a returned thenable, so its rejection is swallowed. No throw, returned
 * value or rejected thenable reaches the process as an uncaught exception or
 * an unhandled rejection.
 *
 * Only available on the NAPI (Node.js / Bun) backend — the SDK requires the
 * native addon (ADR-048). The browser tier (`@limn-works/scp-ts-wasm`, ADR-057)
 * runs the full protocol in-tab and does not use this native custody callback.
 */
export interface KeyCustodyProvider {
  /**
   * Generate a keypair and return its id, a canonical decimal `u64` string
   * (`SCP-CRYPTO-4060` otherwise). Record `role` and report it from
   * {@link getPublicKey} for the key's lifetime; the bridge refuses and
   * destroys a key whose reported type or role differs. Never reuse a key
   * id: an id returned here names no other key for the provider's lifetime,
   * even after that key is destroyed.
   */
  generateKeypair(keyType: CustodyKeyType, role: CustodyKeyRole): string;
  /**
   * Sign `message` under `keyId`. An Ed25519 key returns the 64-byte
   * signature. A `"p256"` key receives a 32-byte digest (§9.5.1, no second
   * hash) and returns raw `r || s` (64 bytes) or DER; the bridge normalises
   * it to low-s and verifies it strictly against the key's public key, and
   * any mismatch is an error. A software implementation MUST derive the
   * ECDSA nonce by RFC 6979 with SHA-256; a hardware keystore may use a
   * random nonce.
   */
  sign(keyId: string, message: Uint8Array): Uint8Array;
  /**
   * Return the type, public key and role of `keyId`. `keyType` is the type
   * the key was generated with.
   * `publicKey` is 32 bytes for Ed25519, the 33-byte compressed
   * SEC1 point for `"p256"`, and the 65-byte uncompressed SEC1 point for
   * `"hpke-p256"`. The bridge registers the key under the stated type and
   * rejects a length that does not match it. A provider that holds no key
   * for `keyId` throws a `KeyNotFoundError` (or any error whose `code` is
   * `"SCP-CRYPTO-4006"`), which callers receive as key-not-found.
   *
   * `role` is the role {@link generateKeypair} minted the key in, reported in
   * every session. A key id the bridge has not seen binds as an identity only
   * when `role` is `"identity"`, so an identity from an earlier session can
   * still derive pseudonyms. The bridge cannot check this answer: a provider
   * that reports `"identity"` for a key it minted as `"operational"` lets
   * that key derive pseudonyms, and that is outside the native core's
   * control.
   */
  getPublicKey(keyId: string): CustodyPublicKey;
  /**
   * Destroy key material for `keyId`; subsequent operations must fail,
   * including pseudonym derivation under a destroyed identity key, which
   * throws key-not-found `SCP-CRYPTO-4006` (spec §9.10.4.A).
   */
  destroyKey(keyId: string): void;
  /**
   * Return the 32-byte shared secret with `peerPublic`. Only an
   * `"hpke-p256"` key agrees: it receives the 65-byte uncompressed SEC1 peer
   * point, already validated on the curve, and returns the ECDH
   * x-coordinate.
   */
  dhAgree(keyId: string, peerPublic: Uint8Array): Uint8Array;
  /**
   * Derive the context-scoped P-256 pseudonym point of identity key `keyId`
   * (spec §9.10.4, §9.10.4.A) and return its 33 compressed bytes and nothing
   * else. The bridge fails the operation with `SCP-IDENT-1055` when the bytes
   * are not a valid compressed P-256 point. Throw key-not-found
   * (`SCP-CRYPTO-4006`) when `keyId` was destroyed or never existed.
   *
   * Canonical recipe (spec §9.10.4, §9.10.4.A; every software host MUST
   * produce identical bytes; `ikm` is the identity private key material, the
   * 32-byte Ed25519 seed until the identity key moves to P-256 (SCP-315)):
   *   1. `pseudonym_secret = HKDF-SHA256(ikm, salt="scp-pseudonym-secret-v1", info="", L=32)`
   *   2. `seed = HMAC-SHA256(pseudonym_secret, context_id || "scp-pseudonym")`
   *   3. `d = seed_to_scalar("SCP-PSEUDONYM-P256-V1", seed)`; return the
   *      compressed point `d·G`. `d` is discarded, never stored.
   *
   * The HMAC key is the 32-byte `pseudonym_secret`, never the public key:
   * public key bytes would be a membership-enumeration oracle (§9.10.4.A).
   */
  derivePseudonym(keyId: string, contextId: Uint8Array): Uint8Array;
  /**
   * Derive a rotatable (epoch-versioned) context-scoped pseudonym point
   * (spec §9.10.4.1). Same return shape and checks as
   * {@link derivePseudonym}.
   *
   * Canonical recipe: steps 1 and 3 of {@link derivePseudonym}, with step 2
   * replaced by
   *   `seed = HMAC-SHA256(pseudonym_secret, context_id || BE64(pseudonymEpoch) || "scp-pseudonym-v2")`
   * where `BE64` is the 8-byte big-endian epoch. The `"scp-pseudonym-v2"`
   * separator differs from the v1 `"scp-pseudonym"`, so epoch 0 yields a
   * pseudonym distinct from the static v1 one, and rotating the epoch yields
   * an unlinkable new point. The HMAC key is the `pseudonym_secret`, never
   * the public key.
   */
  deriveRotatablePseudonym(
    keyId: string,
    contextId: Uint8Array,
    pseudonymEpoch: bigint,
  ): Uint8Array;
  /** Return `"hardware"`, `"software"`, or `"in_memory"`. */
  custodyType(keyId: string): string;
}

// ---------------------------------------------------------------------------
// P-256 custody-host helpers
// ---------------------------------------------------------------------------

/**
 * Returns the 33-byte SEC1 compressed pseudonym point of a 32-byte §9.10.4
 * `context_seed` (v1 or v2), for a host that computes the seed itself, such
 * as inside a keystore.
 *
 * The seed is reduced to a scalar under the fixed `SCP-PSEUDONYM-P256-V1`
 * label (FIPS 186-5 A.2.1) and only the point `d·G` is returned: no scalar
 * reaches the host.
 *
 * @throws {ValidationError} `SCP-VALID-7005` when `contextSeed` is not 32 bytes.
 */
export function p256PseudonymPoint(contextSeed: Uint8Array): Uint8Array {
  return __p256HostInvokeForTests(
    nativeFreeFn<(...a: number[][]) => number[]>("p256PseudonymPoint"),
    [contextSeed],
  );
}

/**
 * Returns the 33-byte SEC1 compressed pseudonym point that a software custody
 * derives from its 32-byte identity key material `ikm` (spec §9.10.4.A):
 * `pseudonym_secret = HKDF-SHA256(ikm, "scp-pseudonym-secret-v1")`, the v1
 * context seed when `epoch` is omitted and the v2 seed at `epoch` otherwise,
 * then the point. No scalar reaches the host.
 *
 * @param epoch The rotation epoch, an unsigned 64-bit value.
 * @throws {ValidationError} `SCP-VALID-7005` when `ikm` is not 32 bytes or
 *   `epoch` is negative or wider than 64 bits.
 */
export function p256SoftwarePseudonymPoint(
  ikm: Uint8Array,
  contextId: Uint8Array,
  epoch?: bigint,
): Uint8Array {
  const native = nativeFreeFn<(i: number[], c: number[], e?: bigint) => number[]>(
    "p256SoftwarePseudonymPoint",
  );
  return __p256HostInvokeForTests((i, c) => native(i, c, epoch), [ikm, contextId]);
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
   * @throws {ValidationError} If no NAPI addon is installed — code `SCP-VALID-7081`.
   * @throws {ScpError} If the NAPI addon is installed and failed to load, or
   *   loaded without the `SCP` class — code `SCP-VALID-7082`.
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
   * Flushes every context snapshot to storage, then disconnects
   * transport and marks the instance suspended. Transport-dependent
   * operations fail until `resume()` is called.
   *
   * `timeoutSecs` bounds the whole call, clamped as {@link SCP.shutdown}
   * clamps its deadline. A flush that misses it fails the suspend with
   * `SCP-STORAGE-8014` and leaves the instance running. The suspend runs
   * to completion, or reverts, even if the caller stops awaiting it.
   *
   * @param timeoutSecs Maximum seconds the suspend may take. Defaults to 5.
   * @throws {StorageError} With `SCP-STORAGE-8014`
   *   ({@link SUSPEND_FLUSH_FAILED_CODE}) when a context snapshot did not
   *   persist or the flush missed `timeoutSecs`. The instance stays running
   *   with its transport connected, and a retried `suspend()` flushes again.
   * @throws {TransportError} With `SCP-TRANS-5001` when transport cleanup
   *   fails. The instance stays running.
   */
  async suspend(timeoutSecs: number = 5): Promise<void> {
    try {
      const millis = clampShutdownMillis(timeoutSecs);
      await this.#native.suspend(BigInt(millis));
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
   * @throws {StorageError} With `SCP-STORAGE-8005` when the durable store
   *   still holds its advisory lock after the call, or with
   *   `SCP-STORAGE-8015` ({@link SHUTDOWN_FLUSH_FAILED_CODE}) when the store
   *   was released but a context snapshot did not persist within
   *   `timeoutSecs`. The instance is shut down either way; an unflushed
   *   context restores from its last persisted snapshot.
   */
  async shutdown(timeoutSecs: number = 5): Promise<void> {
    try {
      const millis = clampShutdownMillis(timeoutSecs);
      await this.#native.shutdown(BigInt(millis));
    } catch (err) {
      throw mapBridgeError(err);
    }
  }

  // ───────────────────────────────────────────────────────────────────────
  // Domain: Identity
  // ───────────────────────────────────────────────────────────────────────

  /**
   * Create an identity whose keys live in the key store `custody` names.
   *
   * `custody` is required and carries no default: which key store holds a
   * private key decides who can reach that key, so this SDK picks none for the
   * caller. Read {@link CustodyType} for what each value reaches.
   *
   * @throws IdentityError `SCP-IDENT-1116` when `custody` is `undefined` or
   *   `null`, before any bridge call.
   * @throws ValidationError `SCP-VALID-7005` when `custody` is not a string,
   *   or names no custody request.
   * @throws IdentityError `SCP-IDENT-1003` for `"os_keystore"`, which needs
   *   the provider {@link SCP.identityCreateWithCustody} takes.
   * @throws ValidationError `SCP-VALID-7001` for `"encrypted_file"` when `HOME`
   *   or `SCP_KEY_PASSPHRASE` is unset, empty, or (for `HOME`) relative.
   * @throws IdentityError `SCP-IDENT-1008` for `"encrypted_file"` when the key
   *   file does not open.
   * @throws IdentityError `SCP-IDENT-1059` on a shipped addon, which has no
   *   pre-rotation custody backend.
   */
  async identityCreate(custody: CustodyType): Promise<Identity> {
    requireCustody("identityCreate", custody);
    try {
      const raw = await (this.#native.identityCreate as (c: string) => Promise<unknown>)(custody);
      return Identity._fromHandle(this, raw);
    } catch (err) {
      throw mapBridgeError(err);
    }
  }

  /**
   * Same as {@link SCP.identityCreate}, and the identity also carries an agent key.
   *
   * @throws IdentityError `SCP-IDENT-1116` when `custody` is `undefined` or
   *   `null`, before any bridge call.
   * @throws ValidationError `SCP-VALID-7005` when `custody` is not a string,
   *   or names no custody request.
   * @throws The other errors {@link SCP.identityCreate} throws, for the same
   *   custody values.
   */
  async identityCreateWithAgentKey(custody: CustodyType): Promise<Identity> {
    requireCustody("identityCreateWithAgentKey", custody);
    try {
      const raw = await (
        this.#native.identityCreateWithAgentKey as (c: string) => Promise<unknown>
      )(custody);
      return Identity._fromHandle(this, raw);
    } catch (err) {
      throw mapBridgeError(err);
    }
  }

  /**
   * Create a DID whose key material lives in a caller-provided custody backend:
   * custody `"os_keystore"` (spec `03-identity.md` §3.2.2), which the returned
   * identity's `custodyType` reports.
   *
   * `provider` is any object implementing {@link KeyCustodyProvider} — the
   * private key material never crosses into the native core (ADR-006). Use this
   * to back a DID with an OS keychain, hardware token, or HSM wrapper.
   *
   * Node.js / Bun only: the SDK requires the native addon (ADR-048), so calling
   * `new SCP(...)` outside a Node.js/Bun runtime already throws before this
   * method is reachable. Browser callers use `@limn-works/scp-ts-wasm` (ADR-057).
   *
   * @throws IdentityError `SCP-IDENT-1116` when `provider` is `undefined` or
   *   `null`, before any bridge call.
   * @throws ValidationError if the provider is missing required methods, or
   *   IdentityError if key/DID creation fails inside the provider.
   */
  async identityCreateWithCustody(provider: KeyCustodyProvider): Promise<Identity> {
    if (provider === undefined || provider === null) {
      throw custodyRequiredError("identityCreateWithCustody", CUSTODY_PROVIDER_REMEDY);
    }
    // Validate provider completeness up front. The byte-converting adapter
    // below always supplies all eight closures, so a provider missing a method
    // would otherwise surface only later as a cryptic native "oneshot canceled"
    // failure. Checking here makes the returned promise reject early with a
    // clear, actionable error. Mirrors the eight methods on KeyCustodyProvider.
    const REQUIRED = [
      "generateKeypair",
      "sign",
      "getPublicKey",
      "destroyKey",
      "dhAgree",
      "derivePseudonym",
      "deriveRotatablePseudonym",
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
    const adapter = toNativeCustodyProvider(provider);
    try {
      const raw = await (
        this.#native.identityCreateWithCustody as (p: typeof adapter) => Promise<unknown>
      )(adapter);
      return Identity._fromHandle(this, raw);
    } catch (err) {
      throw mapBridgeError(err);
    }
  }

  async identityLoad(did: string): Promise<Identity> {
    try {
      const raw = await (this.#native.identityLoad as (d: string) => Promise<unknown>)(did);
      return Identity._fromHandle(this, raw);
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
    const rawIdentity = identityHandle("identityRotateKey", "identity", identity);
    try {
      const bridge = await getBridge(this);
      const raw = await bridge.identityRotateKey(rawIdentity);
      return Identity._fromHandle(this, raw);
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
    const rawIdentity = identityHandle("identityMigrate", "identity", identity);
    try {
      const bridge = await getBridge(this);
      const raw = await bridge.identityMigrate(rawIdentity);
      return Identity._fromHandle(this, raw);
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
    const rawIdentity = identityHandle("identityAddAgentKey", "identity", identity);
    try {
      const bridge = await getBridge(this);
      const raw = await bridge.identityAddAgentKey(rawIdentity);
      return Identity._fromHandle(this, raw);
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
    const rawIdentity = identityHandle("identityRotateAgentKey", "identity", identity);
    try {
      const bridge = await getBridge(this);
      const raw = await bridge.identityRotateAgentKey(rawIdentity);
      return Identity._fromHandle(this, raw);
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
    const rawIdentity = identityHandle("identityRemoveAgentKey", "identity", identity);
    try {
      const bridge = await getBridge(this);
      const raw = await bridge.identityRemoveAgentKey(rawIdentity);
      return Identity._fromHandle(this, raw);
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

  /**
   * Verifies an identity link attestation per spec §3.5.4.
   *
   * Routes to the per-instance NAPI method
   * `Scp::identity_verify_link_attestation`, which resolves an issuer's DID
   * document through this instance's resolver before any signature check
   * (§3.5.4 step 1). GitHub issue #2335 finding 2 recorded the earlier route
   * through a module-level free function, which checked a caller-supplied
   * attestation against a caller-supplied key and answered `true` for an
   * attacker who supplied both. That free function now declines with
   * `SCP-IDENT-1060`.
   *
   * `issuerPublicKeyHex` states which key a caller believes belongs to this
   * issuer; this method checks that statement against an issuer's resolved
   * document rather than trusting it.
   *
   * `referenceProof` reports what this caller did about a class 2
   * (`signed_post` / `dns_record`) proof resource, per §3.5.4 Class 2 step 2.
   * `"confirmed"` reports that this caller fetched the resource
   * `evidence.proof` names and found in it what step 2 requires (this issuer's
   * DID, plus the nonce for `signed_post`), which yields a `true` or a `false`.
   * `"not_fetched"` reports that this caller fetched nothing, which raises
   * `SCP-IDENT-1062` for a class 2 attestation. A class 1 (`did_control`)
   * attestation ignores this argument. Any other string raises
   * `SCP-IDENT-1044`.
   *
   * @throws `SCP-IDENT-1044` for a malformed argument, `SCP-IDENT-1060` when an
   * issuer's DID document does not resolve, `SCP-IDENT-1061` when an issuer
   * publishes an `AttestationRevocations` service endpoint no bridge fetches,
   * and `SCP-IDENT-1062` for an unfetched class 2 proof resource.
   */
  async identityVerifyLinkAttestation(
    attestationJson: string,
    issuerPublicKeyHex: string,
    referenceProof: string,
  ): Promise<boolean> {
    try {
      return await (
        this.#native.identityVerifyLinkAttestation as (
          j: string,
          k: string,
          r: string,
        ) => Promise<boolean>
      )(attestationJson, issuerPublicKeyHex, referenceProof);
    } catch (err) {
      throw mapBridgeError(err);
    }
  }

  /**
   * Execute §9.12 compromise recovery for `did`.
   *
   * **Fails closed (#2240).** The recovery WIRE (a real backend plus step-1
   * key rotation) is not yet built — it is tracked as #2240 Part B and needs
   * human design sign-off. Until then this call **always throws** a
   * `SCP-IDENT-1022` "recovery backend not configured" error rather than
   * fabricating a success; it never reports a recovery that did not happen.
   * A `did` this SCP instance does not host is rejected with `SCP-IDENT-1020`,
   * and an unknown `tier` with `SCP-IDENT-1021`, before the fail-closed return.
   * Because this wrapper delegates to the native (NAPI) binding, a `contextIds`
   * list over 1024 entries is rejected with `SCP-VALID-7120` and a concurrent
   * recovery flood with `SCP-VALID-7140` (runtime DoS bounds absent from the
   * other bindings until #2240 Part B wires them uniformly).
   */
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

  /**
   * Resolves a human-readable address (spec section 22.8).
   *
   * Returns a JSON string holding one object with two keys. `resolutions`
   * carries the AddressResolution entries sorted by trust level, highest
   * first. `unavailable_layers` carries every layer nobody queried, each with
   * a `layer` name and a `reason`. Both keys are always present.
   *
   * Read `unavailable_layers` before acting on the first entry in
   * `resolutions`: section 22.8.2 ranks by trust, so a layer nobody queried
   * may hold a binding that outranks every entry there. This binding
   * configures no domain, so an unscoped address always reports the domain
   * layer.
   */
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

  /**
   * Creates a context owned by `identity` from `paramsJson`, the JSON of a
   * {@link ContextParams}.
   *
   * The SDK encodes `capabilityRequirements` itself, from the typed
   * {@link CapabilityRequirement}s, to the bridge's wire form.
   *
   * @throws ValidationError `SCP-VALID-7005` when `identity` is not an
   *   `Identity` this SDK returned; {@link INVALID_REQUIREMENT_CODE} for a
   *   `ChallengeVerified` requirement with no trusted verifier;
   *   `SCP-VALID-7001` when `capabilityRequirements` is not a list of typed
   *   requirements. The bridge refuses other malformed params with its own
   *   codes.
   */
  async contextCreate(identity: Identity, paramsJson: string): Promise<Context> {
    const rawIdentity = identityHandle("contextCreate", "identity", identity);
    const bridgeParamsJson = encodeContextParamsJson(paramsJson);
    try {
      const raw = await (
        this.#native.contextCreate as (id: unknown, p: string) => Promise<unknown>
      )(rawIdentity, bridgeParamsJson);
      return Context._fromHandle(this, raw as never, identity.did);
    } catch (err) {
      throw mapBridgeError(err);
    }
  }

  /**
   * Runs one native call and rethrows its rejection, or a synchronous throw
   * from argument conversion, as the typed SDK error `mapBridgeError` derives
   * from the `[SCP-…]` code in its message.
   */
  async #mapNativeErrors<T>(call: () => Promise<T>): Promise<T> {
    try {
      return await call();
    } catch (err) {
      throw mapBridgeError(err);
    }
  }

  /**
   * Reserves a pooled MLS `KeyPackage` under the joiner's own identity for a
   * spawn-from-Welcome join (ADR-049 Phase 2J).
   *
   * The join-side peer of {@link contextCreate}: a node that intends to JOIN by
   * receiving a Welcome first reserves a single-use `KeyPackage` under its own
   * identity. The returned PUBLIC bytes are handed (out of band) to the context
   * creator, who mints a Welcome addressed to this reservation; the
   * `reservationId` is passed back to {@link contextJoinFromWelcome}. The
   * joiner's private signer state never leaves the native core.
   *
   * @param owningDid The joiner's own DID. MUST be a locally-custodied identity
   *   (same trust model as {@link contextCreate}); a non-custodied DID fails
   *   closed with `SCP-IDENT-1001`.
   * @returns The opaque `{ reservationId, keyPackagePublic }` pair.
   *
   * @example
   * const reservation = await scp.reserveKeyPackage(joiner.did);
   * // Hand reservation.keyPackagePublic to the creator out of band; it seals a
   * // signed invitation bundle addressed to this reservation via
   * // `scp.inviteMember(...)`, which you then open:
   * const ctx = await scp.contextJoinFromWelcome(
   *   joiner.did,
   *   sealed, // the SealedInvitation from the creator's `inviteMember`
   *   reservation.reservationId,
   * );
   */
  async reserveKeyPackage(owningDid: string): Promise<KeyPackageReservation> {
    const raw = await this.#mapNativeErrors(() =>
      (
        this.#native.reserveKeyPackage as (
          d: string,
        ) => Promise<{ reservationId: string; keyPackagePublic: ArrayLike<number> }>
      )(owningDid),
    );
    return {
      reservationId: raw.reservationId,
      keyPackagePublic: new Uint8Array(raw.keyPackagePublic),
    };
  }

  /**
   * Joins an existing SCP context by opening a received sealed, signed
   * invitation bundle, standing the local (joiner) identity up as a send-capable
   * participant (ADR-049 Phase 2J; FFI-02 Option A).
   *
   * Completes the reserve → invite → join handshake begun by
   * {@link reserveKeyPackage}: given the {@link SealedInvitation} the creator
   * produced with {@link inviteMember}, this opens and AUTHENTICATES the bundle,
   * installs the joined MLS group, derives the joiner's §9.10.4 routing pseudonym
   * from its locally-custodied identity (never caller-supplied), and returns an
   * active {@link Context} rebuilt from the AUTHENTICATED bundle params. Without
   * it a Welcome-joined node can DECRYPT but cannot SEND. A non-custodied joiner
   * hard-fails before the single-use `KeyPackage` is consumed.
   *
   * The joiner supplies NO loose `params`/`welcomeBytes`: the authoritative
   * genesis params + MLS Welcome travel INSIDE the signed `sealed` bundle, which
   * the native core opens and verifies. `sealed.contextId` / `sealed.creatorDid`
   * are UNTRUSTED binding hints only — authority derives from the signed bundle.
   *
   * @param owningDid The joiner's own DID (the reservation holder).
   * @param sealed The {@link SealedInvitation} bundle produced by the creator's
   *   {@link inviteMember} and delivered to this joiner.
   * @param reservationId The id returned by {@link reserveKeyPackage} for the
   *   `KeyPackage` this bundle addresses.
   * @returns An active {@link Context} for the joined context.
   *
   * @example
   * const ctx = await scp.contextJoinFromWelcome(
   *   joiner.did,
   *   outcome.bundle, // the SealedInvitation from the creator's `inviteMember`
   *   reservation.reservationId,
   * );
   */
  async contextJoinFromWelcome(
    owningDid: string,
    sealed: SealedInvitation,
    reservationId: string,
  ): Promise<Context> {
    // napi surfaces the bundle's `enc`/`ciphertext` as Rust `Vec<u8>` fields;
    // marshal them to plain number[] on the wire (the same normalization the
    // reserve/import byte paths use), never a Uint8Array the napi Vec<u8>
    // deserializer would reject.
    const nativeSealed = {
      contextId: sealed.contextId,
      creatorDid: sealed.creatorDid,
      enc: Array.from(sealed.enc),
      ciphertext: Array.from(sealed.ciphertext),
    };
    const raw = await this.#mapNativeErrors(() =>
      (
        this.#native.contextJoinFromWelcome as (
          o: string,
          s: {
            contextId: string;
            creatorDid: string;
            enc: readonly number[];
            ciphertext: readonly number[];
          },
          r: string,
        ) => Promise<unknown>
      )(owningDid, nativeSealed, reservationId),
    );
    return Context._fromHandle(this, raw as never, owningDid);
  }

  /**
   * Invites a member to an existing context, producing a sealed, signed
   * invitation bundle (ADR-049 Phase 2J; FFI-02 Option A).
   *
   * The creator (or admin) seals the context's genesis params + MLS Welcome for
   * the invitee under RFC 9180 HPKE, binding them to the invitee's `KeyPackage`.
   * Only a `SingleAdmin` context is supported today: the invite is unilateral
   * and returns an {@link InviteMemberOutcome} whose `bundle` is the sealed
   * {@link SealedInvitation} — pass it straight to the invitee's
   * {@link contextJoinFromWelcome} (no re-assembly). A voting-governed context
   * THROWS (governed-context invitations are not yet implemented).
   *
   * The invite routes through the actor governance gate, which requires the
   * inviter to hold the `governance:propose` capability. The creator of a
   * `SingleAdmin` context holds the admin role, which grants every capability
   * in the context's declared ceiling, so the creator can invite only when
   * that ceiling includes `governance:propose`.
   *
   * `creatorDid` MUST be a locally-custodied identity; the invite is signed
   * under its `#active` key.
   *
   * The bundle carries the context's stored relay set (§5.12.3.1
   * `relay_urls`), which the runtime reads; the caller supplies none.
   *
   * @param contextId The context to invite the member into.
   * @param creatorDid The inviting creator/admin DID (locally custodied).
   * @param inviteeDid The DID of the member being invited.
   * @param inviteeKeyPackage The invitee's PUBLIC MLS `KeyPackage` bytes (from
   *   the invitee's {@link reserveKeyPackage}).
   * @returns The {@link InviteMemberOutcome} — the sealed `bundle` plus the
   *   `delivered` flag.
   *
   * @example
   * const outcome = await scp.inviteMember(
   *   ctx.contextId,
   *   creator.did,
   *   invitee.did,
   *   reservation.keyPackagePublic,
   * );
   * // `outcome.bundle` is directly usable — no manual re-assembly:
   * const joined = await joinerScp.contextJoinFromWelcome(
   *   invitee.did,
   *   outcome.bundle,
   *   reservationId,
   * );
   */
  async inviteMember(
    contextId: string,
    creatorDid: string,
    inviteeDid: string,
    inviteeKeyPackage: Uint8Array | readonly number[],
  ): Promise<InviteMemberOutcome> {
    const keyPackageArray = ArrayBuffer.isView(inviteeKeyPackage)
      ? Array.from(inviteeKeyPackage as Uint8Array)
      : (inviteeKeyPackage as readonly number[]);
    const raw = await this.#mapNativeErrors(() =>
      (
        this.#native.inviteMember as (
          ctx: string,
          c: string,
          i: string,
          kp: readonly number[],
        ) => Promise<{
          bundle: {
            contextId: string;
            creatorDid: string;
            enc: ArrayLike<number>;
            ciphertext: ArrayLike<number>;
          };
          delivered: boolean;
        }>
      )(contextId, creatorDid, inviteeDid, keyPackageArray),
    );

    // Project the flat napi object into the SDK outcome. The `bundle` is a
    // SealedInvitation directly usable as the join input. A voting-governed
    // context does not reach here — the native bridge throws for it.
    return {
      bundle: {
        contextId: raw.bundle.contextId,
        creatorDid: raw.bundle.creatorDid,
        enc: new Uint8Array(raw.bundle.enc),
        ciphertext: new Uint8Array(raw.bundle.ciphertext),
      },
      delivered: raw.delivered,
    };
  }

  async contextJoin(
    context: Context,
    identityDid: string,
    spendingUcanJwt?: string | null,
  ): Promise<void> {
    const handle = contextHandle("contextJoin", "context", context);
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
   * Only available on builds compiled with the `testing`
   * feature; never present in production builds.
   */
  async contextSeedPeerPseudonym(
    context: Context,
    peerDid: string,
    pseudonym: Uint8Array | Buffer,
  ): Promise<void> {
    const handle = contextHandle("contextSeedPeerPseudonym", "context", context);
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

  async contextLeave(context: Context, identityDid: string): Promise<void> {
    const handle = contextHandle("contextLeave", "context", context);
    try {
      await (this.#native.contextLeave as (h: unknown, d: string) => Promise<void>)(
        handle,
        identityDid,
      );
    } catch (err) {
      throw mapBridgeError(err);
    }
  }

  async contextClose(context: Context, identityDid: string): Promise<void> {
    const handle = contextHandle("contextClose", "context", context);
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
    context: Context,
    identityDid: string,
    payload: Uint8Array | readonly number[],
    spendingUcanJwt?: string | null,
  ): Promise<void> {
    const handle = contextHandle("contextSend", "context", context);
    const payloadUint8 = ArrayBuffer.isView(payload)
      ? (payload as Uint8Array)
      : new Uint8Array(payload as readonly number[]);
    const bridge = await getBridge(this);
    return bridge.contextSend(handle, identityDid, payloadUint8, spendingUcanJwt ?? null);
  }

  async contextSubscribe(
    context: Context,
    identityDid: string,
    onMessage: (message: unknown) => void,
  ): Promise<void> {
    const handle = contextHandle("contextSubscribe", "context", context);
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

  contextCancelSubscription(context: Context): void {
    const handle = contextHandle("contextCancelSubscription", "context", context);
    try {
      (this.#native.contextCancelSubscription as (h: unknown) => void)(handle);
    } catch (err) {
      throw mapBridgeError(err);
    }
  }

  async contextMemberCount(context: Context): Promise<number> {
    const handle = contextHandle("contextMemberCount", "context", context);
    const bridge = await getBridge(this);
    return (await bridge.contextMemberCount(handle)) ?? 0;
  }

  async contextIsMember(context: Context, did: string): Promise<boolean> {
    const handle = contextHandle("contextIsMember", "context", context);
    try {
      return await (this.#native.contextIsMember as (h: unknown, d: string) => Promise<boolean>)(
        handle,
        did,
      );
    } catch (err) {
      throw mapBridgeError(err);
    }
  }

  async contextMemberDids(context: Context): Promise<readonly string[]> {
    const handle = contextHandle("contextMemberDids", "context", context);
    try {
      return await (this.#native.contextMemberDids as (h: unknown) => Promise<readonly string[]>)(
        handle,
      );
    } catch (err) {
      throw mapBridgeError(err);
    }
  }

  /**
   * Returns the role `did` holds in the context, or `null` for a non-member.
   *
   * @throws {UnknownGovernanceOutcomeError} `SCP-GOV-11040` when the bridge
   *   reports a role name {@link memberRoleFromBridge} cannot parse.
   */
  async contextMemberRole(context: Context, did: string): Promise<MemberRole | null> {
    const handle = contextHandle("contextMemberRole", "context", context);
    let raw: string | null;
    try {
      raw = await (
        this.#native.contextMemberRole as (h: unknown, d: string) => Promise<string | null>
      )(handle, did);
    } catch (err) {
      throw mapBridgeError(err);
    }
    if (raw === null) return null;
    return memberRoleFromBridge(raw);
  }

  async contextDrainEvents(context: Context): Promise<readonly string[]> {
    const handle = contextHandle("contextDrainEvents", "context", context);
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

  async contextTombstoneMigrated(context: Context): Promise<void> {
    const handle = contextHandle("contextTombstoneMigrated", "context", context);
    try {
      await (this.#native.contextTombstoneMigrated as (h: unknown) => Promise<void>)(handle);
    } catch (err) {
      throw mapBridgeError(err);
    }
  }

  async contextMigrationState(context: Context): Promise<string | null> {
    const handle = contextHandle("contextMigrationState", "context", context);
    try {
      return await (this.#native.contextMigrationState as (h: unknown) => Promise<string | null>)(
        handle,
      );
    } catch (err) {
      throw mapBridgeError(err);
    }
  }

  async contextExport(context: Context): Promise<Uint8Array> {
    const handle = contextHandle("contextExport", "context", context);
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

  contextSetEconomicPolicy(context: Context, policyJson: string): void {
    const handle = contextHandle("contextSetEconomicPolicy", "context", context);
    try {
      (this.#native.contextSetEconomicPolicy as (h: unknown, p: string) => void)(
        handle,
        policyJson,
      );
    } catch (err) {
      throw mapBridgeError(err);
    }
  }

  contextGetEconomicPolicy(context: Context): string | null {
    const handle = contextHandle("contextGetEconomicPolicy", "context", context);
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

  async contextBroadcastSubscriberCount(context: Context): Promise<number | null> {
    const handle = contextHandle("contextBroadcastSubscriberCount", "context", context);
    try {
      return await (
        this.#native.contextBroadcastSubscriberCount as (h: unknown) => Promise<number | null>
      )(handle);
    } catch (err) {
      throw mapBridgeError(err);
    }
  }

  async contextIsBroadcastSubscriber(context: Context, did: string): Promise<boolean> {
    const handle = contextHandle("contextIsBroadcastSubscriber", "context", context);
    try {
      return await (
        this.#native.contextIsBroadcastSubscriber as (h: unknown, d: string) => Promise<boolean>
      )(handle, did);
    } catch (err) {
      throw mapBridgeError(err);
    }
  }

  async contextBroadcastAdmission(context: Context): Promise<string | null> {
    const handle = contextHandle("contextBroadcastAdmission", "context", context);
    try {
      return await (
        this.#native.contextBroadcastAdmission as (h: unknown) => Promise<string | null>
      )(handle);
    } catch (err) {
      throw mapBridgeError(err);
    }
  }

  /**
   * Subscribe a DID to a broadcast context.
   *
   * For a GATED broadcast context, `messagesReadUcanJwt` must carry the
   * `messages:read` UCAN JWT issued to `subscriberDid` by the context
   * admin/creator (spec §5.14.4); the full UCAN validation pipeline runs on it.
   * It is unused for an OPEN context.
   */
  async broadcastSubscribe(
    context: Context,
    subscriberDid: string,
    messagesReadUcanJwt?: string,
  ): Promise<void> {
    const handle = contextHandle("broadcastSubscribe", "context", context);
    try {
      await (
        this.#native.broadcastSubscribe as (h: unknown, d: string, u?: string) => Promise<void>
      )(handle, subscriberDid, messagesReadUcanJwt);
    } catch (err) {
      throw mapBridgeError(err);
    }
  }

  async broadcastUnsubscribe(
    context: Context,
    subscriberDid: string,
    rotateKeys?: boolean,
  ): Promise<void> {
    const handle = contextHandle("broadcastUnsubscribe", "context", context);
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
    context: Context,
    authorDid: string,
    payload: Uint8Array | readonly number[],
  ): Promise<void> {
    const handle = contextHandle("broadcastPublish", "context", context);
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
    context: Context,
    authorDid: string,
    asset: { path: string; contentType: string; body: readonly number[] },
    deployId?: string | null,
  ): Promise<unknown> {
    const handle = contextHandle("broadcastPublishAsset", "context", context);
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
    context: Context,
    authorDid: string,
    assets: readonly { path: string; contentType: string; body: readonly number[] }[],
    deployId?: string | null,
  ): Promise<unknown> {
    const handle = contextHandle("broadcastPublishAssets", "context", context);
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
    context: Context,
    subscriberDid: string,
    blockerDid: string,
  ): Promise<void> {
    const handle = contextHandle("broadcastBlockSubscriber", "context", context);
    try {
      await (
        this.#native.broadcastBlockSubscriber as (h: unknown, s: string, b: string) => Promise<void>
      )(handle, subscriberDid, blockerDid);
    } catch (err) {
      throw mapBridgeError(err);
    }
  }

  async broadcastUnblockSubscriber(
    context: Context,
    subscriberDid: string,
    unblockerDid: string,
  ): Promise<void> {
    const handle = contextHandle("broadcastUnblockSubscriber", "context", context);
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
   * Seals the author's current broadcast key to the requester's
   * `wrappingPubkey`, a 65-byte uncompressed DHKEM(P-256) point (HPKE, spec
   * §5.14.2, §9.5). Any other length or an invalid point is rejected with a
   * validation error.
   *
   * On grant, returns a JSON string encoding the sealed broadcast key; feed
   * that exact string into {@link broadcastOpenKey} together with the P-256
   * `wrappingSecret` scalar matching the `wrappingPubkey` presented here to recover
   * the raw key. On deny (§5.14.8 — a blocked, unregistered, or unauthorized
   * requester), returns `null` and no key material is produced. The raw
   * AES-256 broadcast key never crosses the FFI boundary; only sealed material
   * is returned.
   *
   * @param wrappingPubkey - the requester's 65-byte uncompressed DHKEM(P-256)
   *   public key.
   */
  async broadcastHandleKeyRequest(
    context: Context,
    authorDid: string,
    requesterDid: string,
    wrappingPubkey: Uint8Array,
  ): Promise<string | null> {
    const handle = contextHandle("broadcastHandleKeyRequest", "context", context);
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
   * 32-byte DHKEM(P-256) `wrappingSecret` scalar, returning the raw 32-byte AES-256
   * broadcast key.
   *
   * `sealedJson` is the JSON string returned by
   * {@link broadcastHandleKeyRequest} on grant; `wrappingSecret` must match the
   * `wrappingPubkey` presented on that request. Pure crypto — no instance
   * state.
   *
   * @param sealedJson - the sealed-key JSON from `broadcastHandleKeyRequest`.
   * @param wrappingSecret - the subscriber's 32-byte DHKEM(P-256) scalar.
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

  /**
   * Execute a previously-approved governance proposal BY ID.
   *
   * The runtime resolves the authoritative proposal from the context actor's
   * own quorum-validated governance engine; the caller supplies no proposal,
   * action, or status. An untracked / unapproved id is rejected. The executor
   * and consequence subject are resolved from the tracked proposal's proposer,
   * never from a caller-supplied DID.
   *
   * The native addon has an internal transport and broadcasts any MLS commit
   * the action produces (for example the commit that evicts a removed member)
   * to the other context members, so the caller relays nothing.
   *
   * @returns The outcome naming which action ran.
   * @throws {UnknownGovernanceOutcomeError} `SCP-GOV-11040` when the bridge
   *   reports an outcome this SDK version does not name.
   */
  async contextExecuteGovernanceAction(
    context: Context,
    proposalIdHex: string,
  ): Promise<GovernanceActionResult> {
    const handle = contextHandle("contextExecuteGovernanceAction", "context", context);
    let raw: string;
    try {
      raw = await (
        this.#native.contextExecuteGovernanceAction as (h: unknown, p: string) => Promise<string>
      )(handle, proposalIdHex);
    } catch (err) {
      throw mapBridgeError(err);
    }
    // Parsed outside the try block, so an unknown name is never re-mapped as a
    // bridge error.
    return governanceActionResultFromBridge(raw);
  }

  /**
   * Proposes a governance action.
   *
   * @returns The bridge's JSON `{proposal_id, status, reason?, rejector?,
   *   execution_result}` after {@link checkProposalResponse} checks every name
   *   in it. `execution_result` names the action a `single_admin` context
   *   auto-executed, and is `null` while a proposal awaits votes.
   * @throws {UnknownGovernanceOutcomeError} `SCP-GOV-11040` when the response
   *   names a status, reason, or outcome this SDK version does not name.
   */
  async contextGovernancePropose(
    context: Context,
    actionJson: string,
    proposerDid: string,
  ): Promise<string> {
    const handle = contextHandle("contextGovernancePropose", "context", context);
    const bridge = await getBridge(this);
    return checkProposalResponse(
      await bridge.contextGovernancePropose(handle, actionJson, proposerDid),
    );
  }

  /**
   * Proposes `ModifyCapabilityRequirements` (spec 07 §7.3.4.4): replaces the
   * context's admission capability requirements with `requirements`. An
   * empty list clears them. The SDK encodes the typed list itself.
   *
   * @returns The bridge's JSON `{proposal_id, status, reason?, rejector?,
   *   execution_result}` after {@link checkProposalResponse} checks every name
   *   in it, as {@link contextGovernancePropose} returns it.
   * @throws ValidationError {@link INVALID_REQUIREMENT_CODE} for a
   *   `ChallengeVerified` requirement with no trusted verifier, before any
   *   bridge call; {@link NON_CANONICAL_IDENTIFIER_CODE} or
   *   {@link TOO_MANY_CAPABILITY_REQUIREMENTS_CODE} from the bridge.
   */
  async contextGovernanceModifyCapabilityRequirements(
    context: Context,
    requirements: readonly CapabilityRequirement[],
    proposerDid: string,
  ): Promise<string> {
    const handle = contextHandle(
      "contextGovernanceModifyCapabilityRequirements",
      "context",
      context,
    );
    const requirementsJson = encodeCapabilityRequirements(requirements);
    let raw: string;
    try {
      raw = await (
        this.#native.contextGovernanceModifyCapabilityRequirements as (
          h: unknown,
          r: string,
          p: string,
        ) => Promise<string>
      )(handle, requirementsJson, proposerDid);
    } catch (err) {
      throw mapBridgeError(err);
    }
    return checkProposalResponse(raw);
  }

  /**
   * Approves a governance proposal.
   *
   * @returns The bridge's JSON `{status, reason?, rejector?}` after
   *   {@link checkProposalResponse} checks every name in it.
   * @throws {UnknownGovernanceOutcomeError} `SCP-GOV-11040` when the response
   *   names a status or reason this SDK version does not name.
   */
  async contextGovernanceApprove(
    context: Context,
    proposalIdHex: string,
    voterDid: string,
  ): Promise<string> {
    const handle = contextHandle("contextGovernanceApprove", "context", context);
    let raw: string;
    try {
      raw = await (
        this.#native.contextGovernanceApprove as (
          h: unknown,
          p: string,
          v: string,
        ) => Promise<string>
      )(handle, proposalIdHex, voterDid);
    } catch (err) {
      throw mapBridgeError(err);
    }
    return checkProposalResponse(raw);
  }

  /**
   * Rejects a governance proposal.
   *
   * @returns The bridge's JSON `{status, reason?, rejector?}` after
   *   {@link checkProposalResponse} checks every name in it.
   * @throws {UnknownGovernanceOutcomeError} `SCP-GOV-11040` when the response
   *   names a status or reason this SDK version does not name.
   */
  async contextGovernanceReject(
    context: Context,
    proposalIdHex: string,
    voterDid: string,
  ): Promise<string> {
    const handle = contextHandle("contextGovernanceReject", "context", context);
    let raw: string;
    try {
      raw = await (
        this.#native.contextGovernanceReject as (
          h: unknown,
          p: string,
          v: string,
        ) => Promise<string>
      )(handle, proposalIdHex, voterDid);
    } catch (err) {
      throw mapBridgeError(err);
    }
    return checkProposalResponse(raw);
  }

  /**
   * Withdraws a governance proposal.
   *
   * @returns The bridge's JSON `{status, reason?, rejector?}` after
   *   {@link checkProposalResponse} checks every name in it.
   * @throws {UnknownGovernanceOutcomeError} `SCP-GOV-11040` when the response
   *   names a status or reason this SDK version does not name.
   */
  async contextGovernanceWithdraw(
    context: Context,
    proposalIdHex: string,
    voterDid: string,
  ): Promise<string> {
    const handle = contextHandle("contextGovernanceWithdraw", "context", context);
    let raw: string;
    try {
      raw = await (
        this.#native.contextGovernanceWithdraw as (
          h: unknown,
          p: string,
          v: string,
        ) => Promise<string>
      )(handle, proposalIdHex, voterDid);
    } catch (err) {
      throw mapBridgeError(err);
    }
    return checkProposalResponse(raw);
  }

  async contextGovernanceGetProposal(context: Context, proposalIdHex: string): Promise<string> {
    const handle = contextHandle("contextGovernanceGetProposal", "context", context);
    try {
      return await (
        this.#native.contextGovernanceGetProposal as (h: unknown, p: string) => Promise<string>
      )(handle, proposalIdHex);
    } catch (err) {
      throw mapBridgeError(err);
    }
  }

  async contextGovernanceListProposals(context: Context): Promise<string> {
    const handle = contextHandle("contextGovernanceListProposals", "context", context);
    try {
      return await (this.#native.contextGovernanceListProposals as (h: unknown) => Promise<string>)(
        handle,
      );
    } catch (err) {
      throw mapBridgeError(err);
    }
  }

  async contextApplyPendingCeilingModification(
    context: Context,
    currentTimestamp: number,
  ): Promise<boolean> {
    const handle = contextHandle("contextApplyPendingCeilingModification", "context", context);
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

  async contextFinalizeClose(context: Context): Promise<void> {
    const handle = contextHandle("contextFinalizeClose", "context", context);
    try {
      await (this.#native.contextFinalizeClose as (h: unknown) => Promise<void>)(handle);
    } catch (err) {
      throw mapBridgeError(err);
    }
  }

  async contextCreateGovernanceCheckpoint(
    context: Context,
    checkpointSeq: number,
    merkleRootHex: string,
    eventCount: number,
    lastEventHashHex: string,
    stateSnapshotHashHex: string,
    creatorDid: string,
    creatorSignatureHex: string,
  ): Promise<string> {
    const handle = contextHandle("contextCreateGovernanceCheckpoint", "context", context);
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
    context: Context,
    checkpointJson: string,
    signerDid: string,
    signatureHex: string,
  ): Promise<string> {
    const handle = contextHandle("contextAddCheckpointCosignature", "context", context);
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

  async contextHandleTtlExpiry(context: Context): Promise<void> {
    const handle = contextHandle("contextHandleTtlExpiry", "context", context);
    try {
      await (this.#native.contextHandleTtlExpiry as (h: unknown) => Promise<void>)(handle);
    } catch (err) {
      throw mapBridgeError(err);
    }
  }

  async contextProposeTtlExtension(
    context: Context,
    proposerDid: string,
    extensionSecs: number,
  ): Promise<boolean> {
    const handle = contextHandle("contextProposeTtlExtension", "context", context);
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

  async contextResetTtlTimer(context: Context, newDurationSecs: number): Promise<void> {
    const handle = contextHandle("contextResetTtlTimer", "context", context);
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
   * Each context's offline tier is classified from the `last_relay_contact`
   * the instance stores for it. A context whose value is absent or cannot be
   * read is reported `failed` with no `tier` and its own `failureCode`
   * (`SCP-TRANS-5102` absent, `SCP-TRANS-5103` unreadable) and keeps
   * `needsReconnect` set; the other contexts reconnect.
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
  async reconnect(identityDid: string, contextIds: readonly string[]): Promise<ReconnectReport> {
    try {
      return await (
        this.#native.contextReconnect as (
          did: string,
          ids: readonly string[],
        ) => Promise<ReconnectReport>
      )(identityDid, contextIds);
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

  /**
   * The `known_did` allowlist (the sole auto-accept trigger, §5.12.2) travels
   * inside `policyJson` -- the policy's `TrustRequirement` `KnownDid` variant.
   * There is no separate trusted-DID parameter.
   */
  evaluateInvitation(
    paramsJson: string,
    inviterDid: string,
    identityDid: string,
    policyJson?: string | null,
    spendingJson?: string | null,
  ): unknown {
    try {
      return (
        this.#native.evaluateInvitation as (
          p: string,
          i: string,
          id: string,
          pol: string | null,
          sp: string | null,
        ) => unknown
      )(paramsJson, inviterDid, identityDid, policyJson ?? null, spendingJson ?? null);
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
  // Domain: Outlet
  // ───────────────────────────────────────────────────────────────────────

  async outletRegister(context: Context, definition: OutletDefinition): Promise<string> {
    const handle = contextHandle("outletRegister", "context", context);
    try {
      // `#native` is the raw napi addon, whose `NapiOutletDefinition` uses
      // different field names than the public `OutletDefinition` (JSON-string
      // schemas, `operatorDid`). Convert here — mirrors `internal/native.ts`.
      const napiDef = {
        name: definition.name,
        description: definition.description,
        kind: definition.kind,
        inputSchemaJson: JSON.stringify(definition.inputSchema),
        outputSchemaJson: JSON.stringify(definition.outputSchema),
        operatorDid: definition.operator,
        testVectorsJson: definition.testVectors
          ? JSON.stringify(definition.testVectors)
          : undefined,
        implementationHash: definition.implementationHash
          ? Array.from(definition.implementationHash)
          : undefined,
        cost: definition.cost
          ? {
              amount: definition.cost.amount,
              currency: definition.cost.currency,
              payee: definition.cost.payee,
              costFormula: definition.cost.costFormula,
            }
          : undefined,
      };
      return await (
        this.#native.outletRegister as (h: unknown, d: typeof napiDef) => Promise<string>
      )(handle, napiDef);
    } catch (err) {
      throw mapBridgeError(err);
    }
  }

  async outletInvoke(
    context: Context,
    outletId: string,
    inputJson: string,
    identityDid: string,
    ucanToken: string,
    proofTokens?: readonly string[],
    spendingUcanJwt?: string,
  ): Promise<string> {
    const handle = contextHandle("outletInvoke", "context", context);
    const bridge = await getBridge(this);
    return bridge.outletInvoke(
      handle,
      outletId,
      inputJson,
      identityDid,
      ucanToken,
      proofTokens,
      spendingUcanJwt,
    );
  }

  async outletVerify(context: Context, outletId: string): Promise<unknown> {
    const handle = contextHandle("outletVerify", "context", context);
    return await (this.#native.outletVerify as (h: unknown, t: string) => Promise<unknown>)(
      handle,
      outletId,
    );
  }

  async outletInvokeCrossContext(
    sourceContext: Context,
    targetContext: Context,
    outletId: string,
    inputJson: string,
    invokerDid: string,
    ucanToken: string,
    chainDepth: number,
    proofTokens?: readonly string[],
  ): Promise<string> {
    const sourceHandle = contextHandle("outletInvokeCrossContext", "sourceContext", sourceContext);
    const targetHandle = contextHandle("outletInvokeCrossContext", "targetContext", targetContext);
    try {
      return await (
        this.#native.outletInvokeCrossContext as (
          s: unknown,
          t: unknown,
          outlet: string,
          input: string,
          did: string,
          ucan: string,
          depth: number,
          proofs: readonly string[] | undefined,
        ) => Promise<string>
      )(
        sourceHandle,
        targetHandle,
        outletId,
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

  /**
   * Runs the §6.2.4 atomic cross-context outlet-invocation saga (ADR-049 §3a).
   *
   * The saga either commits — resolving to a {@link SagaResult} carrying the
   * supervisor-minted `sagaId` plus the target's signed receipt and captured
   * output bytes — or reaches a typed terminal, which rejects as one of the
   * saga errors:
   *
   * - {@link SagaAbortedError} — the code tells its causes apart; carries
   *   `retryAfterMs` (`null`, never `0`, when no precise back-off exists).
   * - {@link SagaNeedsRepairError} — Commit retries exhausted; carries the
   *   durable `sagaId` repair handle.
   * - {@link SagaBusyError} — the participant context set overlapped an
   *   in-flight saga; carries `contendedContext`.
   *
   * `timestampMs` is a JS `bigint` (the bridge's `u64` freshness field) and
   * must be non-negative. `chainDepth` is the caller-asserted inbound
   * provenance depth and must be an integer in the closed range `0..255` (the
   * bridge's `u8`). Both are validated before the native dispatch (fail-fast).
   *
   * See spec §6.2.4 and ADR-049 §3a.
   */
  async outletInvokeCrossContextSaga(
    sourceContext: Context,
    targetContext: Context,
    callerDid: string,
    outletRegistrationId: string,
    inputJson: string,
    assertedNonceHex: string,
    timestampMs: bigint,
    chainDepth: number,
    ucanProofId?: string,
  ): Promise<SagaResult> {
    const sourceHandle = contextHandle(
      "outletInvokeCrossContextSaga",
      "sourceContext",
      sourceContext,
    );
    const targetHandle = contextHandle(
      "outletInvokeCrossContextSaga",
      "targetContext",
      targetContext,
    );
    if (typeof timestampMs !== "bigint" || timestampMs < 0n) {
      throw new ValidationError(
        `timestampMs must be a non-negative bigint, got ${String(timestampMs)}`,
        "SCP-VALID-7002",
      );
    }
    if (!Number.isInteger(chainDepth) || chainDepth < 0 || chainDepth > 255) {
      throw new ValidationError(
        `chainDepth must be an integer in range 0-255, got ${String(chainDepth)}`,
        "SCP-VALID-7002",
      );
    }

    let raw: { sagaId: string; receipt?: Uint8Array; output?: Uint8Array };
    try {
      raw = await (
        this.#native.outletInvokeCrossContextSaga as (
          s: unknown,
          t: unknown,
          caller: string,
          outlet: string,
          input: string,
          nonce: string,
          ts: bigint,
          depth: number,
          proof: string | undefined,
        ) => Promise<{ sagaId: string; receipt?: Uint8Array; output?: Uint8Array }>
      )(
        sourceHandle,
        targetHandle,
        callerDid,
        outletRegistrationId,
        inputJson,
        assertedNonceHex,
        timestampMs,
        chainDepth,
        ucanProofId,
      );
    } catch (e) {
      throw mapSagaError(e);
    }
    return {
      sagaId: raw.sagaId,
      receipt: raw.receipt ?? null,
      output: raw.output ?? null,
    };
  }

  /**
   * Opens the §5.4.5 / §6.2.4 cross-context STREAMING outlet-invocation saga
   * (SCP-OUT-047) and returns its {@link StreamingSagaHandle}.
   *
   * The STREAMING sibling of {@link outletInvokeCrossContextSaga}. Where the
   * unary saga BLOCKS until `Committed` (≤~95s) and returns the result inline,
   * the streaming saga returns its chunk receiver PROMPTLY at the
   * Commit-transition and reaches `Committed` ASYNCHRONOUSLY at seal-close (the
   * ADR-049 §3a streaming wait-model amendment) — an LLM stream can exceed the
   * unary bound, so the credit ceiling bounds chunk COUNT, not wall-clock.
   *
   * The returned handle is both `AsyncIterable<OutletStreamChunk>`
   * (`for await (const chunk of handle)`) and `PromiseLike<Aggregate>`
   * (`await handle`); its FIRST pull opens the saga
   * (`outletStreamingSagaOpen` mints the durable `sagaId` at the
   * Commit-transition) and its iteration drains chunks via
   * `outletStreamingSagaPollNext`. This method performs NO I/O and does not block
   * — the saga opens lazily on the first `await` / iteration, matching the
   * same-context `ctx.outlets.invoke(...)`.
   *
   * There is NO live control plane (grantCredit / cancel) for the cross-context
   * saga stream — per §6.2.5 / SCP-OUT-046 the credit window is fixed at open via
   * `estimatedChunkCount` (cancel_ack_ceiling = u64::MAX). An open rejection — the
   * §6.2.4 caller-principal binding (a `callerDid` this instance does not host /
   * not a member of the source context), a Prepare/Commit saga terminal, or an
   * input/UCAN rejection — surfaces on the first `await` / iteration as the
   * matching typed SDK error ({@link "./errors".SagaAbortedError} /
   * {@link "./errors".SagaBusyError} / {@link "./errors".SagaNeedsRepairError} /
   * {@link ValidationError} / {@link "./errors".UcanPermissionError}), and the
   * receiver is never handed out.
   *
   * `options.timestampMs` is a `bigint` (the bridge's `u64` freshness field) and
   * must be non-negative. `options.chainDepth` must be an integer in the closed
   * range `0..255` (the bridge's `u8`). Both are validated synchronously before
   * the handle is returned (fail-fast).
   *
   * See spec §6.2.4, §5.4.5, and ADR-049 §3a.
   *
   * @param options Named invocation options (a flat config object — the two
   *   leading `sourceHandle` / `targetHandle` fields are NAMED to prevent a
   *   silent caller/target handle-swap).
   */
  outletInvokeCrossContextStreamingSaga(options: StreamingSagaOptions): StreamingSagaHandle {
    if (typeof options.timestampMs !== "bigint" || options.timestampMs < 0n) {
      throw new ValidationError(
        `timestampMs must be a non-negative bigint, got ${String(options.timestampMs)}`,
        "SCP-VALID-7002",
      );
    }
    if (
      !Number.isInteger(options.chainDepth) ||
      options.chainDepth < 0 ||
      options.chainDepth > 255
    ) {
      throw new ValidationError(
        `chainDepth must be an integer in range 0-255, got ${String(options.chainDepth)}`,
        "SCP-VALID-7002",
      );
    }
    return new StreamingSagaHandle(this.#native as unknown as StreamingSagaNative, {
      sourceHandle: options.sourceHandle,
      targetHandle: options.targetHandle,
      callerDid: options.callerDid,
      outletRegistrationId: options.outletRegistrationId,
      input: options.input,
      assertedNonceHex: options.assertedNonceHex,
      timestampMs: options.timestampMs,
      chainDepth: options.chainDepth,
      ucanToken: options.ucanToken,
      proofTokens: options.proofTokens,
      ucanProofId: options.ucanProofId,
      timeoutMs: options.timeoutMs,
      estimatedChunkCount: options.estimatedChunkCount,
    });
  }

  /**
   * Drives the key-bearing in-session reconnect/repair truncated-close for a
   * cross-context streaming saga (SCP-OUT-046 #136 AC7, SCP-OUT-047).
   *
   * This is IN-SESSION reconnect/repair of a seal that stalled or went
   * `NeedsRepair` while THIS bridge process is still alive (e.g. a client
   * reconnects to the same live node). The saga registry is per-instance and
   * in-memory, so this does NOT survive a process/node restart — cross-restart
   * recovery replays the durable saga journal via a separate operator path, not
   * this surface.
   *
   * On FFI reconnect this authenticates the caller, surfaces the target
   * context's Active Signing Key (resolved per-call from custody, never
   * envelope-asserted), and calls the bridge recover op to seal a witness-absent
   * durable prefix and resolve the saga `Committed` — WITHOUT re-opening the
   * stream or re-invoking the outlet executor. Resolves with `void` on a
   * successful `Committed` resolution.
   *
   * `callerDid` MUST be an identity hosted by this bridge instance (the §6.2.4
   * channel-authenticated principal) AND the invoker pinned at open — recovery is
   * money-moving (it bills the invoker / credits the operator over B's durable
   * prefix), so a hosted-but-non-invoker caller is rejected with `SCP-PERM-3001`
   * (the SAME invoker gate the same-context grant/cancel/terminate siblings
   * enforce) BEFORE the signing key is resolved.
   *
   * Rejects with {@link ContextError} if `callerDid` is not hosted by this
   * instance or `sagaId` is unknown; with {@link "./errors".UcanPermissionError}
   * whose `.code` is `SCP-PERM-3001` when `callerDid` is hosted but is not the
   * pinned invoker (branch on `.code` for this money-moving gate, not only a
   * substring match); or {@link "./errors".SagaNeedsRepairError} if the seal
   * cannot complete (the saga stays unresolved for a later retry).
   */
  async recoverStreamingSagaTruncatedClose(sagaId: string, callerDid: string): Promise<void> {
    try {
      await (
        this.#native.outletStreamingSagaRecoverTruncatedClose as (
          id: string,
          did: string,
        ) => Promise<void>
      )(sagaId, callerDid);
    } catch (e) {
      throw mapSagaError(e);
    }
  }

  async outletSessionCreate(
    context: Context,
    outletId: string,
    sourceContextId: string,
    ttlSeconds?: number,
  ): Promise<string> {
    const handle = contextHandle("outletSessionCreate", "context", context);
    try {
      return await (
        this.#native.outletSessionCreate as (
          h: unknown,
          t: string,
          s: string,
          ttl: number | undefined,
        ) => Promise<string>
      )(handle, outletId, sourceContextId, ttlSeconds);
    } catch (err) {
      throw mapBridgeError(err);
    }
  }

  async outletSessionInvoke(
    context: Context,
    sessionId: string,
    inputJson: string,
    invokerDid: string,
    ucanToken: string,
    proofTokens?: readonly string[],
  ): Promise<string> {
    const handle = contextHandle("outletSessionInvoke", "context", context);
    return await (
      this.#native.outletSessionInvoke as (
        h: unknown,
        sid: string,
        input: string,
        did: string,
        ucan: string,
        proofs: readonly string[] | undefined,
      ) => Promise<string>
    )(handle, sessionId, inputJson, invokerDid, ucanToken, proofTokens);
  }

  async outletSessionClose(context: Context, sessionId: string): Promise<void> {
    const handle = contextHandle("outletSessionClose", "context", context);
    await (this.#native.outletSessionClose as (h: unknown, sid: string) => Promise<void>)(
      handle,
      sessionId,
    );
  }

  async outletInterfaceExpose(
    context: Context,
    outletId: string,
    targetContextId: string,
    rateLimitJson?: string,
  ): Promise<string> {
    const handle = contextHandle("outletInterfaceExpose", "context", context);
    return await (
      this.#native.outletInterfaceExpose as (
        h: unknown,
        t: string,
        tc: string,
        rl: string | undefined,
      ) => Promise<string>
    )(handle, outletId, targetContextId, rateLimitJson);
  }

  async outletInterfaceAccept(context: Context, interfaceJson: string): Promise<string> {
    const handle = contextHandle("outletInterfaceAccept", "context", context);
    return await (
      this.#native.outletInterfaceAccept as (h: unknown, ij: string) => Promise<string>
    )(handle, interfaceJson);
  }

  async outletInterfaceRevoke(context: Context, interfaceIdHex: string): Promise<string> {
    const handle = contextHandle("outletInterfaceRevoke", "context", context);
    return await (
      this.#native.outletInterfaceRevoke as (h: unknown, id: string) => Promise<string>
    )(handle, interfaceIdHex);
  }

  // ───────────────────────────────────────────────────────────────────────
  // Domain: UCAN
  // ───────────────────────────────────────────────────────────────────────

  /**
   * Enforcing UCAN gate: runs the full 11-step ADR-016 pipeline and throws a
   * typed {@link "./errors".ScpError} at the first failing stage (use
   * {@link ucanEvaluate} for the non-throwing diagnostic).
   *
   * FAIL CLOSED: `presentingAgentDid` is required by the bridge (no silent
   * security default). Omitting it makes the bridge reject the call rather than
   * defaulting the presenting agent to the token's own `aud` — defaulting would
   * make the step-5 audience check a tautology (`aud == aud`) that does NOT bind
   * the token to any external subject, passing a token addressed to someone else
   * (trust inflation). Pass the agent the token must be addressed to.
   *
   * Throws {@link "./errors".ContextError} carrying `SCP-CTX-2023` when the context is not active.
   *
   * @param context The context handle to validate against.
   * @param token The UCAN token string to validate.
   * @param capability The required capability URI (mandatory on this gate).
   * @param presentingAgentDid The DID the token must be addressed to. Required —
   *   an absent or empty value is rejected by the bridge.
   * @param proofTokens Optional delegation-chain proof tokens.
   */
  async ucanValidate(
    context: Context,
    token: string,
    capability: string,
    presentingAgentDid: string,
    proofTokens?: readonly string[],
  ): Promise<void> {
    const handle = contextHandle("ucanValidate", "context", context);
    const bridge = await getBridge(this);
    return bridge.ucanValidate(handle, token, capability, presentingAgentDid, proofTokens);
  }

  /**
   * Read-only, structured counterpart to {@link ucanValidate}.
   *
   * Runs the same 11-step ADR-016 validation pipeline but, instead of
   * throwing at the first failing stage, resolves to a
   * {@link CapabilityValidation} of six per-stage booleans (spec §7.2.4,
   * ADR-059). The probe never records the token's nonce, so calling it does
   * not consume the token. Capability/signature/expiry outcomes are reported
   * via the booleans; malformed FFI inputs (bad handle / token / capability)
   * reject. Throws {@link "./errors".ContextError} carrying `SCP-CTX-2023` when the context is not active.
   *
   * The six booleans cross the FFI already camelCased, so consumers read the
   * per-check breakdown directly and never reverse-engineer *which* check
   * failed by parsing error prose.
   *
   * NOT AN AUTHORIZATION DECISION: this is a diagnostic, never a gate. Only
   * {@link ucanValidate} (with its mandatory challenge capability) authorizes
   * an action. A no-capability (intrinsic-validity) result skips the
   * invoked-capability grant-match, so an all-`true` result does NOT establish
   * the token grants any particular capability — re-run {@link ucanValidate}
   * with the concrete capability to authorize (spec §7.2.4).
   *
   * FAIL CLOSED: `presentingAgentDid` is required by the bridge (no silent
   * security default). Omitting it makes the bridge reject the call rather than
   * defaulting the presenting agent to the token's own `aud` — defaulting would
   * make the step-5 audience check a tautology (`aud == aud`) that inflates
   * trust. It precedes `capability` in the signature because it is mandatory
   * while `capability` is optional.
   *
   * @param context The context handle to evaluate against.
   * @param token The UCAN token string to evaluate.
   * @param presentingAgentDid The DID under assessment — the agent the token
   *   must be addressed to. Required; an absent or empty value is rejected by
   *   the bridge.
   * @param capability Optional challenge capability URI. Omit it (or pass
   *   `null`/`undefined`) to evaluate the token's INTRINSIC validity with no
   *   invoked-capability grant-match challenge — the mode {@link evaluateTrust}
   *   uses. Pass a capability to additionally require the token grants it. (The
   *   enforcing {@link ucanValidate} gate keeps a mandatory capability.)
   * @param proofTokens Optional delegation-chain proof tokens.
   */
  async ucanEvaluate(
    context: Context,
    token: string,
    presentingAgentDid: string,
    capability?: string | null,
    proofTokens?: readonly string[],
  ): Promise<CapabilityValidation> {
    const handle = contextHandle("ucanEvaluate", "context", context);
    // Route the native dispatch through the single error chokepoint
    // (`mapBridgeError`) so a raw NAPI throw or rejection surfaces as a
    // typed `ScpError` keyed on its `[SCP-CAT-NNNN]` code, per ADR-059
    // Decision 4 (error typing routes through one mapping site, not per-call
    // prose inspection). `mapBridgeError` is idempotent on already-typed errors.
    let raw: CapabilityValidation;
    try {
      raw = await (
        this.#native.ucanEvaluate as (
          h: unknown,
          t: string,
          c: string | null,
          pa: string,
          pt: readonly string[] | null,
        ) => Promise<CapabilityValidation>
      )(handle, token, capability ?? null, presentingAgentDid, proofTokens ?? null);
    } catch (error) {
      throw mapBridgeError(error);
    }
    // Shared six-field projection — pins the canonical CapabilityValidation
    // shape in one place (mirrors the same call in `internal/native.ts`).
    return toCapabilityValidation(raw);
  }

  /**
   * Mints a UCAN from the context creator to `memberDid`, within the ceiling
   * the context holds. Throws {@link "./errors".ContextError} carrying `SCP-CTX-2023` when the context is not active.
   */
  async ucanMint(
    context: Context,
    memberDid: string,
    capabilities: readonly string[],
    proofs?: readonly string[],
  ): Promise<unknown> {
    const handle = contextHandle("ucanMint", "context", context);
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

  /**
   * Delegates a subset of `parentToken`'s capabilities from `delegatorDid` to
   * `delegateeDid`, within the ceiling the context holds. Throws {@link "./errors".ContextError} carrying `SCP-CTX-2023` when the context is not active.
   */
  async ucanDelegate(
    context: Context,
    delegatorDid: string,
    delegateeDid: string,
    parentToken: string,
    capabilities: readonly string[],
  ): Promise<unknown> {
    const handle = contextHandle("ucanDelegate", "context", context);
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

  /**
   * Revokes `token` in the context, as its issuer or the context creator.
   * Throws {@link "./errors".ContextError} carrying `SCP-CTX-2023` when the context is not active.
   */
  async ucanRevoke(context: Context, token: string, revokerDid: string): Promise<void> {
    const handle = contextHandle("ucanRevoke", "context", context);
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

  async eventLogQuery(context: Context, filterJson?: string): Promise<readonly unknown[]> {
    const handle = contextHandle("eventLogQuery", "context", context);
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

  async eventLogVerify(context: Context, claimJson: string): Promise<unknown> {
    const handle = contextHandle("eventLogVerify", "context", context);
    try {
      return await (this.#native.eventLogVerify as (h: unknown, c: string) => Promise<unknown>)(
        handle,
        claimJson,
      );
    } catch (err) {
      throw mapBridgeError(err);
    }
  }

  eventLogCheckpoint(context: Context, identity: Identity, epoch: number): unknown {
    const handle = contextHandle("eventLogCheckpoint", "context", context);
    const rawIdentity = identityHandle("eventLogCheckpoint", "identity", identity);
    try {
      return (this.#native.eventLogCheckpoint as (h: unknown, i: unknown, e: number) => unknown)(
        handle,
        rawIdentity,
        epoch,
      );
    } catch (err) {
      throw mapBridgeError(err);
    }
  }

  eventLogCheckpointByDid(context: Context, did: string, epoch: number): unknown {
    const handle = contextHandle("eventLogCheckpointByDid", "context", context);
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

  async transportConnect(relayUrl: string): Promise<TransportManager> {
    try {
      const raw = await (this.#native.transportConnect as (u: string) => Promise<unknown>)(
        relayUrl,
      );
      return TransportManager._fromHandle(raw);
    } catch (err) {
      throw mapBridgeError(err);
    }
  }

  async transportStatus(manager: TransportManager): Promise<unknown> {
    const handle = transportManagerHandle("transportStatus", "manager", manager);
    try {
      return await (this.#native.transportStatus as (m: unknown) => Promise<unknown>)(handle);
    } catch (err) {
      throw mapBridgeError(err);
    }
  }

  async transportDisconnect(manager: TransportManager): Promise<void> {
    const handle = transportManagerHandle("transportDisconnect", "manager", manager);
    try {
      await (this.#native.transportDisconnect as (m: unknown) => Promise<void>)(handle);
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

  economyEstimateCost(policyJson: string, actionType: string, metricsJson: string): bigint | null {
    try {
      // The napi bridge returns a `bigint` cost, signalling "no result / overflow"
      // with the sentinel `-1n`. Map that to `null` at the wrapper boundary so the
      // TS surface matches Python's `int | None` (ADR-060).
      const cost = (
        this.#native.economyEstimateCost as (p: string, a: string, m: string) => bigint
      )(policyJson, actionType, metricsJson);
      return cost === -1n ? null : cost;
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

  economyEvaluateFormula(formulaJson: string, metricsJson: string): bigint | null {
    try {
      // As with `economyEstimateCost`, the napi bridge signals "no result /
      // overflow" with the sentinel `-1n`; normalize it to `null` so the TS
      // surface matches Python's `int | None` (ADR-060).
      const cost = (this.#native.economyEvaluateFormula as (f: string, m: string) => bigint)(
        formulaJson,
        metricsJson,
      );
      return cost === -1n ? null : cost;
    } catch (err) {
      throw mapBridgeError(err);
    }
  }

  economyBudgetRemaining(contextId: string, did: string): bigint {
    return (this.#native.economyBudgetRemaining as (c: string, d: string) => bigint)(
      contextId,
      did,
    );
  }

  economyBudgetGrant(contextId: string, did: string, amount: bigint): void {
    (this.#native.economyBudgetGrant as (c: string, d: string, a: bigint) => void)(
      contextId,
      did,
      amount,
    );
  }

  economyBudgetRecordSpend(contextId: string, did: string, amount: bigint): void {
    try {
      (this.#native.economyBudgetRecordSpend as (c: string, d: string, a: bigint) => void)(
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
    baseCost: bigint,
    thresholdsJson: string,
    floor?: bigint | null,
    cap?: bigint | null,
  ): bigint {
    try {
      return (
        this.#native.economyAntispamEscalatedCost as (
          c: string,
          s: string,
          n: number,
          b: bigint,
          t: string,
          f: bigint | null,
          cp: bigint | null,
        ) => bigint
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
  async economyVerifyPaymentReceipts(
    receipts: readonly Record<string, unknown>[],
  ): Promise<PaymentReceiptVerificationResult> {
    try {
      const raw = await (
        this.#native.economyVerifyPaymentReceipts as (r: string) => Promise<string>
      )(JSON.stringify(receipts));
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

  /**
   * Verify an attestation's Ed25519 signature, evidence, expiry, its own
   * revocation status, and this instance's revocation list for `contextId`
   * (ADR-017, §7.4.4).
   *
   * Takes the typed attestation envelope ({@link CachedAttestationEnvelope})
   * and serializes it to the serde wire shape internally (ADR-058) before
   * crossing FFI. A revocation list that cannot be read throws; it never
   * reads as `valid: false`.
   */
  async trustVerifyAttestation(
    contextId: string,
    attestation: CachedAttestationEnvelope,
  ): Promise<unknown> {
    try {
      return await (
        this.#native.trustVerifyAttestation as (c: string, j: string) => Promise<unknown>
      )(contextId, encodeAttestation(attestation));
    } catch (err) {
      throw mapBridgeError(err);
    }
  }

  /**
   * Issue a challenge request signed by `config.verifier`'s `#active` key
   * (spec 07 §7.3.4 step 1, ADR-017).
   *
   * The challenger writes the cases with their answers. The returned request
   * carries each case's input and never its answer; the challenger's ledger
   * keeps the answers to grade with. The capability definition for
   * `config.capabilityUri` sets the pass threshold, the retries and the
   * cooldown; `config.policy` may only tighten them, on any URI.
   *
   * The SDK passes the one evaluator context the `CustomEval` cases name to
   * the bridge.
   *
   * @throws ValidationError `SCP-VALID-7005` when `config.verifier` is not an
   *   `Identity` this SDK returned; `SCP-VALID-7001` when two `CustomEval`
   *   cases name different evaluator contexts, before any bridge call;
   *   `SCP-VALID-7013` for a malformed DID;
   *   {@link CHALLENGE_SUITE_BELOW_MINIMUM_CODE} for too few cases;
   *   {@link POLICY_OUTSIDE_DEFINITION_CODE} for a policy looser than the
   *   definition; {@link NON_CANONICAL_IDENTIFIER_CODE} for a DID that is not
   *   canonical; {@link CHALLENGE_WINDOW_OPEN_CODE} while the last challenge
   *   to this subject for this capability is inside its window.
   * @throws ScpError `SCP-CRYPTO-4006` when the verifier's key is destroyed,
   *   or another custody failure.
   */
  async trustCreateChallenge(config: CreateChallengeConfig): Promise<ChallengeRequest> {
    identityHandle("trustCreateChallenge", "config.verifier", config.verifier);
    const evaluatorContextId = evaluatorContextOf(config.testCases);
    const testCasesJson = encodeTestCases(config.testCases);
    let created: { challengeId: string; requestJson: string };
    try {
      created = await (
        this.#native.trustCreateChallenge as (
          v: string,
          s: string,
          u: string,
          t: string,
          c: string,
          secs: number,
          e: string | undefined,
          p: ChallengePolicy | undefined,
        ) => Promise<{ challengeId: string; requestJson: string }>
      )(
        config.verifier.did,
        config.subject,
        config.capabilityUri,
        testCasesJson,
        config.contextId,
        config.windowSecs,
        evaluatorContextId,
        config.policy,
      );
    } catch (err) {
      throw mapBridgeError(err);
    }
    return decodeChallengeRequest(created.requestJson);
  }

  /**
   * Answer `request` for attempt `attempt`, signed by `subject`'s `#active`
   * key (spec 07 §7.3.4 step 2, ADR-017).
   *
   * The challenger's signature on `request` is checked against the key this
   * instance's DID resolver returns before anything is signed.
   *
   * @param subject The challenged identity, an identity of this instance;
   *   its custody signs the response.
   * @param request The signed request, as the challenger sent it.
   * @param outputs One output per case.
   * @param attempt The attempt number, starting at 1.
   * @throws ValidationError `SCP-VALID-7005` when `subject` is not an
   *   `Identity` this SDK returned; `SCP-VALID-7013` for a malformed DID; or
   *   a refusal when the request's signature, subject or window does not
   *   hold, such as {@link CHALLENGE_EXPIRED_CODE}.
   * @throws IdentityError `SCP-IDENT-1033` when this instance has no DID
   *   resolver.
   */
  async trustRespondToChallenge(
    subject: Identity,
    request: ChallengeRequest,
    outputs: readonly TestOutput[],
    attempt: number,
  ): Promise<ChallengeResponse> {
    identityHandle("trustRespondToChallenge", "subject", subject);
    const requestJson = encodeChallengeRequest(request);
    const outputsJson = encodeTestOutputs(outputs);
    let responseJson: string;
    try {
      responseJson = await (
        this.#native.trustRespondToChallenge as (
          s: string,
          r: string,
          o: string,
          a: number,
        ) => Promise<string>
      )(subject.did, requestJson, outputsJson, attempt);
    } catch (err) {
      throw mapBridgeError(err);
    }
    return decodeChallengeResponse(responseJson);
  }

  /**
   * Grade `response` to `request` and return the record, signed by
   * `verifier`'s `#active` key (spec 07 §7.3.4 steps 3 and 4, ADR-017).
   *
   * Both signatures are checked first. The challenger's ledger then checks
   * the attempt number, the cooldown and the window, grades each case
   * against its stored answer, and signs a record for the attempt, pass or
   * fail. The record is also written to this instance's trust store.
   *
   * @param verifier The identity that issued `request`, an identity of this
   *   instance; its custody signs the record.
   * @param request The signed request.
   * @param response The subject's signed response.
   * @throws ValidationError `SCP-VALID-7005` when `verifier` is not an
   *   `Identity` this SDK returned; `SCP-VALID-7013` for a malformed DID;
   *   `SCP-VALID-7003` for a response whose signature does not verify; a
   *   refusal when the attempt does not hold, such as
   *   {@link COOLDOWN_ACTIVE_CODE}; or {@link GRADING_CAPACITY_EXHAUSTED_CODE},
   *   {@link GRADING_IN_PROGRESS_CODE} or {@link GRADING_LEASE_LOST_CODE} for a
   *   grading that used no attempt. {@link isRetryable} tells a refusal worth
   *   retrying from a final one, and {@link retryAfter} reads when to retry.
   * @throws IdentityError `SCP-IDENT-1033` when this instance has no DID
   *   resolver.
   */
  async trustGradeResponse(
    verifier: Identity,
    request: ChallengeRequest,
    response: ChallengeResponse,
  ): Promise<GradedChallenge> {
    identityHandle("trustGradeResponse", "verifier", verifier);
    const requestJson = encodeChallengeRequest(request);
    const responseJson = encodeChallengeResponse(response);
    let graded: {
      recordJson: string;
      reasonsJson: string;
      trustStoreError?: { code: string; message: string } | null;
    };
    try {
      graded = await (
        this.#native.trustGradeResponse as (
          v: string,
          r: string,
          s: string,
        ) => Promise<{
          recordJson: string;
          reasonsJson: string;
          trustStoreError?: { code: string; message: string } | null;
        }>
      )(verifier.did, requestJson, responseJson);
    } catch (err) {
      throw mapBridgeError(err);
    }
    return {
      record: decodeChallengeVerification(graded.recordJson),
      caseResults: decodeCaseResults(graded.reasonsJson),
      trustStoreError: graded.trustStoreError ?? null,
    };
  }

  /**
   * Verify participation profiles against admission requirements.
   *
   * Returns normally when all requirements are satisfied; throws on any
   * failed requirement or malformed JSON.
   *
   * Security caveat — authenticity is not authorization: this verifies
   * signatures over the subject binding, not signer *legitimacy*. Because
   * `signerPublicKey` is self-certifying, a subject can present
   * genuinely-signed profiles from signers it controls (inflating
   * `minContexts`). Callers MUST establish signer legitimacy separately
   * (a trusted-signer set, a context-membership proof, or the §7.3.5
   * threshold/independence path) and MUST NOT treat success as authorization.
   *
   * @param expectedSubject DID of the agent being admitted. Profiles for any
   *   other subject are ignored (fail-closed).
   * @param requirements Typed {@link RequireParticipation} values. Serialized
   *   internally to the serde wire shape (ADR-058).
   * @param profiles Typed {@link ParticipationProfile} values. Serialized
   *   internally to the serde wire shape (ADR-058).
   */
  verifyParticipationRequirements(
    expectedSubject: string,
    requirements: readonly RequireParticipation[],
    profiles: readonly ParticipationProfile[],
  ): void {
    (this.#native.verifyParticipationRequirements as (s: string, r: string, p: string) => void)(
      expectedSubject,
      encodeRequireParticipation(requirements),
      encodeParticipationProfile(profiles),
    );
  }

  /**
   * Verify that an agent meets a context's capability requirements for
   * admission (spec 07 §7.3.4.4).
   *
   * The requirements are the ones the context's governance holds at the time
   * of the call, set through {@link ContextParams.capabilityRequirements} or
   * {@link contextGovernanceModifyCapabilityRequirements}; the caller cannot
   * supply them. A `ChallengeVerified` requirement is met only
   * by a passing record signed by one of its trusted verifiers, for this
   * subject and context, within the requirement's retry cap.
   *
   * Returns normally when all requirements are satisfied; throws on any unmet
   * requirement or malformed JSON.
   *
   * @param contextId The context the agent is being admitted to.
   * @param subjectDid DID of the agent being admitted.
   * @param agentCapabilities The agent's self-attested capability URIs.
   * @param challengeVerifications Typed {@link ChallengeVerification} records.
   * @throws ValidationError `SCP-VALID-7076` for an unmet requirement.
   */
  async checkCapabilityRequirements(
    contextId: string,
    subjectDid: string,
    agentCapabilities: readonly string[],
    challengeVerifications: readonly ChallengeVerification[],
  ): Promise<void> {
    const recordsJson = encodeChallengeVerifications(challengeVerifications);
    try {
      await (
        this.#native.checkCapabilityRequirements as (
          c: string,
          s: string,
          a: string,
          v: string,
        ) => Promise<void>
      )(contextId, subjectDid, JSON.stringify(agentCapabilities), recordsJson);
    } catch (err) {
      throw mapBridgeError(err);
    }
  }

  /**
   * Evaluate the trustworthiness of a participant within a context.
   *
   * Composes the structured trust model (spec §7.2.4, ADR-059). The protocol
   * provides the data, not the verdict — the caller decides what to do with it:
   *
   * - **Layer 1 — protocol enforcement.** Each supplied capability token is run
   *   through the read-only {@link ucanEvaluate} diagnostic, yielding six
   *   per-stage booleans. The booleans are AND-combined across the token set,
   *   so one token failing a stage makes that aggregate field `false`. This
   *   never inspects error prose — it reads the structured
   *   {@link CapabilityValidation} directly. With no tokens supplied, every
   *   field stays `false` (no stage was observed to pass).
   * - **Layer 2 — behavioral validation.** RECEIVES the subject's verifiable
   *   participation facts (§7.3.2) from the shared Rust core via
   *   {@link participationRecord} — the core gathers the full event log and
   *   flattens the facts ONCE, so the SDK never re-aggregates event-log
   *   collections (no cross-binding divergence). A context with no convergent
   *   events yet (an empty event log) is not an error here: the behavioral
   *   record is reported with all counts zeroed (the subject simply has no
   *   recorded facts), so a Layer-1-only caller never has to populate the log
   *   first. Use {@link participationRecord} directly when the empty-log case
   *   should surface as an error instead.
   *
   * The capability outcome is non-throwing (it reads booleans); malformed FFI
   * inputs (bad context handle / token / capability) propagate as a typed
   * {@link "./errors".ScpError}.
   *
   * NOT AN AUTHORIZATION DECISION. Layer 1 supplies no challenge capability, so
   * the core skips the invoked-capability grant-match and reports each token's
   * intrinsic validity. An all-`true` {@link CapabilityValidation} therefore
   * does NOT establish that the subject may perform any particular action — a
   * token declaring an empty `att` set reports all six fields `true`. §7.2.4 of
   * the trust spec names gating an action on a no-challenge diagnostic a
   * misuse: to authorize, call {@link ucanValidate} with the concrete
   * capability URI, which runs the grant-match and consumes the nonce.
   *
   * Layer 1 also passes no delegation-chain proof tokens, so a token that
   * depends on a proof chain reports `signaturesValid: false` here. Pass the
   * proofs to {@link ucanEvaluate} directly when a delegated token must be
   * assessed.
   *
   * SECURITY: the behavioral record's `attestationCount` (and any challenge
   * results, where consumed) are authentic-but-self-mintable signals — an
   * issuer/verifier is self-certifying, so a subject can mint them from DIDs it
   * controls. They MUST NOT be a sole trust or admission factor; use the
   * threshold/independence path (§7.3.5) for Sybil resistance.
   *
   * The evaluation is labeled with — and the Layer-2 lookup is keyed by — the
   * context id the `context`'s bridge handle carries, so the result is never
   * silently mislabeled. There is no separate context-id argument (matching
   * the Swift and Kotlin SDKs, which resolve from the `ContextHandle`).
   *
   * @param context The context to evaluate within.
   * @param subjectDid The DID of the participant being evaluated.
   * @param capabilityTokens Optional UCAN token strings to evaluate for Layer 1.
   * @returns A structured {@link TrustEvaluation} with Layers 1 and 2 populated.
   */
  async evaluateTrust(
    context: Context,
    subjectDid: string,
    capabilityTokens?: readonly string[],
  ): Promise<TrustEvaluation> {
    const handle = contextHandle("evaluateTrust", "context", context);
    // Layer 1: AND-combine the structured per-stage booleans across tokens.
    // Start from the all-true identity element of the boolean AND when at least
    // one token is present; with no tokens, every field stays false (the
    // dataclass default — no stage was observed to pass).
    let capabilityValidation: CapabilityValidation = {
      tokensValid: false,
      signaturesValid: false,
      withinCeiling: false,
      nonceValid: false,
      notRevoked: false,
      timeBoundsValid: false,
    };
    if (capabilityTokens !== undefined && capabilityTokens.length > 0) {
      let tokensValid = true;
      let signaturesValid = true;
      let withinCeiling = true;
      let nonceValid = true;
      let notRevoked = true;
      let timeBoundsValid = true;
      for (const token of capabilityTokens) {
        // Read-only diagnostic — does NOT throw on capability outcomes;
        // malformed FFI input and an inactive context reject (and propagate).
        // Pass the subject as the
        // presenting agent so the audience check evaluates against the DID under
        // assessment.
        //
        // No challenge capability is supplied: trust evaluation assesses each
        // token's GENERAL (intrinsic) validity — signatures, ceiling, nonce,
        // revocation, time bounds — not whether it grants one specific
        // capability. Passing a concrete URI (or the old `"*"` sentinel, which
        // the real bridge rejects) would wrongly impose an invoked-capability
        // grant-match the caller never asked for. See ADR-059 / spec §7.2.4:
        // the diagnostic's challenge capability is optional, and omitting it
        // means intrinsic-validity.
        const perToken = await this.ucanEvaluate(context, token, subjectDid);
        tokensValid &&= perToken.tokensValid;
        signaturesValid &&= perToken.signaturesValid;
        withinCeiling &&= perToken.withinCeiling;
        nonceValid &&= perToken.nonceValid;
        notRevoked &&= perToken.notRevoked;
        timeBoundsValid &&= perToken.timeBoundsValid;
      }
      // This is a per-FIELD AND ACROSS tokens (every token must pass each
      // stage), NOT the six-field collapse the `allValid` accessor performs on a
      // single record — so the accessor does not apply here. Consumers call
      // `allValid(capabilityValidation)` afterward to collapse the result.
      capabilityValidation = {
        tokensValid,
        signaturesValid,
        withinCeiling,
        nonceValid,
        notRevoked,
        timeBoundsValid,
      };
    }

    // Layer 2: behavioral record RECEIVED from the shared Rust core. The core
    // gathers the FULL event log and flattens the participation facts (§7.3.2)
    // ONCE in `Supervisor::participation_record`; the SDK never re-aggregates
    // event-log collections, so every binding observes identical facts for the
    // same context/subject (the divergence the old client-side classify
    // suffered).
    //
    // No cached attestations are supplied: `evaluateTrust` takes no attestation
    // set, so `attestationCount` reflects only what the bridge can source from
    // its own persistent trust store (verifier-relative, §7.3.2). This honestly
    // passes nothing rather than fabricating attestations.
    //
    // A context with no convergent events yet makes the core return
    // `NoParticipationFacts` (surfaced as a `ContextError` with the structured
    // code `SCP-CTX-2076`). That is not a failure for
    // a trust evaluation — it means "no recorded facts" — so it is folded into a
    // zeroed behavioral record rather than thrown, keeping `evaluateTrust`
    // usable on activity-free contexts (e.g. a Layer-1-only check). Any other
    // error (malformed input, provider failure) still propagates.
    // The native participation-record op keys the event log by the context's
    // canonical id — the 64-char hex `contextId` the handle carries, the same
    // value `eventLogQuery` derives from the handle. Resolve it from the handle
    // (matching Swift/Kotlin, which read `handle.contextId()`), so both the
    // Layer-2 lookup and the returned label come from the one authoritative
    // source and can never disagree.
    const resolvedContextId = handle.contextId;
    let behavioralRecord: BehavioralRecord;
    try {
      behavioralRecord = await this.participationRecord(resolvedContextId, subjectDid);
    } catch (error) {
      // Branch on the STRUCTURED code (`SCP-CTX-2076`), never error prose: the
      // typed `ContextError` carries the stable code the core assigned to
      // `NoParticipationFacts` (ADR-059 — structured, not prose, classification).
      // Anything else (NotInitialized, a provider failure, malformed input) is a
      // genuine error and propagates unchanged.
      if (error instanceof ContextError && error.code === NO_PARTICIPATION_FACTS_CODE) {
        behavioralRecord = {
          subjectDid,
          participationDurationSecs: 0,
          governanceActionsAgainst: 0,
          governanceActionsBy: 0,
          outletInvocationCount: 0,
          outletInvocationCountAnchored: false,
          contextCreationCount: 0,
          roleProgressionCount: 0,
          attestationCount: 0,
          attestationCountAnchored: false,
          computedAt: 0,
          eventLogRoot: "",
        };
      } else {
        throw error;
      }
    }

    return {
      subjectDid,
      // Label the evaluation with the SAME context the layers were computed
      // against (the handle's resolved context id) — the single source of truth.
      contextId: resolvedContextId,
      capabilityValidation,
      behavioralRecord,
      attestations: [],
    };
  }

  /**
   * Computes the structured participation record (§7.3.2) for `subjectDid` in
   * `contextId`.
   *
   * The shared Rust core gathers the FULL context event log and flattens the
   * participation facts ONCE (`Supervisor::participation_record`), and the NAPI
   * bridge sources the subject's accessible, currently-valid attestations from
   * its own persistent trust store (seeded by `cachedAttestations`). The
   * SDK RECEIVES the flattened {@link BehavioralRecord} — it never re-aggregates
   * event-log collections, so every binding observes identical facts for the
   * same context/subject.
   *
   * `attestationCount` is a credential-layer fact (§7.4): it is NOT a
   * context-event count and NOT Merkle-anchored, and is verifier-relative
   * (computed from the attestations the bridge can access). Pass the subject's
   * accessible attestations as `cachedAttestations` to populate it; the default
   * `[]` honestly reports only what the bridge's trust store already holds.
   *
   * THREAT MODEL: `attestationCount` is Sybil-inflatable by self-issuance — one
   * operator can self-issue (or co-issue across DIDs it controls) arbitrarily
   * many *authentic* attestations. It is a credential-layer claim count, NOT a
   * standalone trust score; Sybil resistance comes from the threshold/
   * independence path (§7.3.5) and DeviceAttestation binding (§9.3), not the
   * count itself. Separately, the membership/role-derived facts (participation
   * duration, governance actions, role progression) are committer-local —
   * verifier-relative, not independently Merkle-verifiable — until ADR-051
   * receive-side replication lands. In particular, `participationDurationSecs`
   * for the context creator (founder) is derived from the creator-assigned
   * context-creation timestamp — it is creator-timestamp-trusting and
   * committer-local until that replication lands (no independent receiver
   * corroborates the creator's clock).
   *
   * @param contextId The context the participation is scoped to.
   * @param subjectDid The DID whose participation facts are computed.
   * @param cachedAttestations Typed cached attestations to seed the bridge's
   *   trust store before sourcing the subject's verified set. Serialized to JSON
   *   internally — matching the Python SDK's `cached_attestations: list[dict]`.
   *   Defaults to `[]` (source only what is already persisted).
   * @returns The flattened participation facts as a {@link BehavioralRecord}.
   * @throws {@link "./errors".ScpError} on malformed FFI input or a behavioral
   *   compute failure (e.g. an empty event log → `SCP-CTX-2076`).
   */
  async participationRecord(
    contextId: string,
    subjectDid: string,
    cachedAttestations: readonly CachedAttestation[] = [],
  ): Promise<BehavioralRecord> {
    let record: BehavioralRecord;
    try {
      record = await (
        this.#native.participationRecord as (
          ctx: string,
          subj: string,
          ca: string,
        ) => Promise<BehavioralRecord>
      )(contextId, subjectDid, encodeCachedAttestations(cachedAttestations));
    } catch (error) {
      throw mapBridgeError(error);
    }
    // Project an explicit, documented SDK shape rather than passing the native
    // object through — the field set is stable and matches the Python SDK /
    // Rust `ParticipationFacts` 1:1.
    return {
      subjectDid: record.subjectDid,
      participationDurationSecs: record.participationDurationSecs,
      governanceActionsAgainst: record.governanceActionsAgainst,
      governanceActionsBy: record.governanceActionsBy,
      outletInvocationCount: record.outletInvocationCount,
      outletInvocationCountAnchored: record.outletInvocationCountAnchored,
      contextCreationCount: record.contextCreationCount,
      roleProgressionCount: record.roleProgressionCount,
      attestationCount: record.attestationCount,
      attestationCountAnchored: record.attestationCountAnchored,
      computedAt: record.computedAt,
      eventLogRoot: record.eventLogRoot,
    };
  }

  /**
   * Aggregate all trust engine layers into a single `TrustInput` (§7.3).
   *
   * Every structured input is typed; the SDK serializes to the serde wire
   * shapes internally before crossing FFI (ADR-058). An empty collection is
   * a real value ("no rules apply"), never a request for defaults — the
   * bridge receives `[]` / `{}` exactly as passed.
   *
   * @param contextId The context to aggregate trust inputs for.
   * @param subjectDid The DID of the subject to evaluate.
   * @param events Full signed event-log entries ({@link EventLogEntry}).
   * @param merkleRoot 32-byte Merkle root as a number array.
   * @param consequenceRules Typed {@link ConsequenceRule} values.
   * @param thresholdRequirements Typed {@link ThresholdRequirement} values
   *   keyed by {@link AttestationType}.
   * @param attestorSets Typed {@link AttestorInfo} lists keyed by
   *   {@link AttestationType}.
   * @param cachedAttestations Typed {@link CachedAttestation} values to seed
   *   the bridge's trust store.
   * @param challengeResults Typed {@link ChallengeVerification} records.
   * @returns The aggregated `TrustInput` as a JSON string.
   */
  async aggregateTrustInput(
    contextId: string,
    subjectDid: string,
    events: readonly EventLogEntry[],
    merkleRoot: readonly number[],
    consequenceRules: readonly ConsequenceRule[] = [],
    thresholdRequirements: Readonly<Partial<Record<AttestationType, ThresholdRequirement>>> = {},
    attestorSets: Readonly<Partial<Record<AttestationType, readonly AttestorInfo[]>>> = {},
    cachedAttestations: readonly CachedAttestation[] = [],
    challengeResults: readonly ChallengeVerification[] = [],
  ): Promise<string> {
    try {
      return await (
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
        ) => Promise<string>
      )(
        contextId,
        subjectDid,
        encodeEventLogEntries(events),
        encodeMerkleRoot(merkleRoot),
        encodeConsequenceRules(consequenceRules),
        encodeThresholdRequirements(thresholdRequirements),
        encodeAttestorSets(attestorSets),
        encodeCachedAttestations(cachedAttestations),
        encodeChallengeVerifications(challengeResults),
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

  /**
   * Starts a production node under the operator in `config.identity`, on
   * this instance's own storage (construction.md §"Node start —
   * `NodeStartConfig`", ADR-052). Call {@link Node.shutdown} to stop it.
   *
   * The SDK checks `config` and lowers it to the bridge's JSON before the
   * bridge runs; the bridge then checks the operator handle (ADR-048) before
   * it reads the config.
   *
   * @throws {ValidationError} `SCP-VALID-7005` when `config` is not an object
   *   or `config.identity` is not an {@link Identity} this SDK returned.
   * @throws {StorageError} `SCP-STORAGE-8007` for a config the SDK or the
   *   bridge cannot read, `SCP-STORAGE-8008` when the blob store cannot open,
   *   `SCP-STORAGE-8009` when the instance storage cannot.
   * @throws {UcanPermissionError} `SCP-PERM-3030` when `config.identity`
   *   belongs to another `SCP` instance.
   * @throws The typed error of every other code in sdk-common.md §"Node
   *   start error codes", with the code preserved.
   */
  async nodeStart(config: NodeStartConfig): Promise<Node> {
    const { Node: NodeCls, nodeStartConfigToWire } = await import("./server");
    const wire = nodeStartConfigToWire(config);
    const rawIdentity = identityHandle("nodeStart", "config.identity", config.identity);
    try {
      const raw = await (this.#native.nodeStart as NativeNodeStart)(
        JSON.stringify(wire),
        rawIdentity,
      );
      return NodeCls._fromHandle(raw, this);
    } catch (err) {
      throw mapBridgeError(err);
    }
  }

  /**
   * Starts a development node on encrypted in-memory storage.
   *
   * Development only: an addon built with the bridge's `testing` feature
   * starts the node; a shipped addon starts nothing. Production callers use
   * {@link SCP.nodeStart}.
   *
   * @throws {TransportError} `SCP-TRANS-5055` on a shipped addon.
   * @throws The typed error of any other code the bridge returns, with the
   *   code preserved.
   */
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

  /**
   * Starts a development node on this instance's own storage.
   *
   * Development only: an addon built with the bridge's `testing` feature
   * starts the node, keeping its blobs and any generated key under
   * `dataDir`; a shipped addon creates nothing. Production callers use
   * {@link SCP.nodeStart}.
   *
   * @throws {TransportError} `SCP-TRANS-5055` on a shipped addon.
   * @throws The typed error of any other code the bridge returns, with the
   *   code preserved.
   */
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

  async mcpServerCreate(config: unknown): Promise<McpServer> {
    try {
      const raw = await (this.#native.mcpServerCreate as (c: unknown) => Promise<unknown>)(config);
      return McpServer._fromHandle(raw);
    } catch (err) {
      throw mapBridgeError(err);
    }
  }

  async mcpServerStop(server: McpServer): Promise<void> {
    const handle = mcpServerHandle("mcpServerStop", "server", server);
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
  async mcpClientConnectStdio(command: readonly string[]): Promise<McpClient> {
    try {
      const raw = await (
        this.#native.mcpClientConnectStdio as (c: readonly string[]) => Promise<unknown>
      )(command);
      return McpClient._fromHandle(raw);
    } catch (err) {
      throw mapBridgeError(err);
    }
  }

  /**
   * Connects an MCP client to an SSE server. `authToken` is sent as
   * `Authorization: Bearer <token>` on every request; pass `null` only for a
   * server that runs no bearer check. An SCP SSE server always runs one
   * (ADR-015). The transport has no TLS, so a token is sent only to a
   * loopback host.
   */
  async mcpClientConnectSse(url: string, authToken: string | null): Promise<McpClient> {
    try {
      const raw = await (
        this.#native.mcpClientConnectSse as (u: string, t: string | null) => Promise<unknown>
      )(url, authToken);
      return McpClient._fromHandle(raw);
    } catch (err) {
      throw mapBridgeError(err);
    }
  }

  async mcpClientDisconnect(client: McpClient): Promise<void> {
    const handle = mcpClientHandle("mcpClientDisconnect", "client", client);
    try {
      await (this.#native.mcpClientDisconnect as (h: unknown) => Promise<void>)(handle);
    } catch (err) {
      throw mapBridgeError(err);
    }
  }

  async mcpClientListTools(client: McpClient): Promise<readonly unknown[]> {
    const handle = mcpClientHandle("mcpClientListTools", "client", client);
    try {
      return await (this.#native.mcpClientListTools as (h: unknown) => Promise<readonly unknown[]>)(
        handle,
      );
    } catch (err) {
      throw mapBridgeError(err);
    }
  }

  async mcpClientInvoke(
    client: McpClient,
    outletName: string,
    inputJson: string,
    contextId: string,
    invokerDid: string,
  ): Promise<unknown> {
    const handle = mcpClientHandle("mcpClientInvoke", "client", client);
    try {
      return await (
        this.#native.mcpClientInvoke as (
          h: unknown,
          t: string,
          i: string,
          c: string,
          d: string,
        ) => Promise<unknown>
      )(handle, outletName, inputJson, contextId, invokerDid);
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
  ): ProvenanceRecord {
    try {
      const raw = (
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
      // The native bridge returns the raw snake_case JSON wire string; decode it
      // into the SDK's typed camelCase surface (ADR-060 `paymentAmount` bigint).
      return decodeProvenanceRecord(raw);
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
