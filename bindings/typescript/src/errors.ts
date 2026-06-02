/**
 * SCP error hierarchy for the TypeScript SDK.
 *
 * All errors thrown by the SDK are instances of `ScpError`. Each subclass maps
 * to one category in the cross-SDK error hierarchy defined in
 * `.docs/standards/sdk-common.md`.
 *
 * §5.4.4 sealed `OutletError` hierarchy
 * --------------------------------------
 *
 * The §5.4.4 envelope is rendered as a sealed TypeScript class hierarchy
 * rooted at `OutletError`. Each `OutletErrorClass` variant maps to one of
 * eight concrete subclasses with a static `code` discriminator and a
 * runtime type-guard:
 *
 *   * `OutletProtocolError`     (named to avoid collision with MLS protocol
 *                                error symbols elsewhere in the SDK)
 *   * `AuthorizationError`
 *   * `InputError`
 *   * `ExecutionError`
 *   * `OutputError`
 *   * `EconomicError`
 *   * `OutletTransportError`    (suffixed `Outlet` to coexist with the legacy
 *                                top-level `TransportError` category class)
 *   * `OutletGovernanceError`
 *
 * Branded newtypes (`Credit`, `CatalogKey`, `OutletId`) are nominal at the
 * type level — passing a raw `number`/`string` where the brand is expected
 * fails to type-check. Runtime factories validate inputs and throw
 * `InvalidGrant` (under `OutletProtocolError`) on out-of-range data.
 *
 * Construction
 * ~~~~~~~~~~~~
 *
 * `OutletError.new(opts)` is an options-object factory — the adjacent
 * string fields `outletId` and `catalogKey` are positional-swap-resistant
 * because the only construction path is named-field. A positional shape is
 * not exposed.
 *
 * `instanceof` survival across the napi-rs FFI boundary is preserved by
 * (a) class inheritance via standard `extends` chains and (b) a class-tag
 * field (`scpClassTag`) that the runtime guard `OutletError.isAuthorizationError`
 * checks if `instanceof` returns `false` (e.g., when an error crossed a
 * realm boundary in a worker). The factory-fallback path is exercised by
 * the conformance test.
 *
 * PII redaction
 * ~~~~~~~~~~~~~
 *
 * `redactPii(message)` strips emails and DIDs before surfacing the raw
 * `message` to developer-facing logs:
 *
 *   * email regex `/[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/` →
 *     `[redacted]`;
 *   * DID regex   `/did:(dht|web|key):[A-Za-z0-9._-]+/`              →
 *     `[redacted]`.
 *
 * Conformance fixtures include both regex matches.
 */

import { Buffer } from "node:buffer";

// ---------------------------------------------------------------------------
// Root SCP error hierarchy (legacy categories, retained verbatim).
// ---------------------------------------------------------------------------

/**
 * Base error class for all SCP SDK errors.
 *
 * Every error thrown by the SDK is an instance of `ScpError`. Use `instanceof`
 * checks against subclasses for programmatic error handling. The `code` field
 * provides a stable, machine-readable identifier that does not change across
 * SDK versions.
 */
export class ScpError extends Error {
  readonly code: string;

  constructor(message: string, code: string) {
    super(message);
    this.name = "ScpError";
    this.code = code;
  }
}

/** DID creation, resolution, key rotation failures. */
export class IdentityError extends ScpError {
  constructor(message: string, code: string) {
    super(message, code);
    this.name = "IdentityError";
  }
}

/** Context lifecycle (create, join, leave, close) failures. */
export class ContextError extends ScpError {
  constructor(message: string, code: string) {
    super(message, code);
    this.name = "ContextError";
  }
}

/** UCAN capability validation failures. */
export class UcanPermissionError extends ScpError {
  constructor(message: string, code: string) {
    super(message, code);
    this.name = "UcanPermissionError";
  }
}

/** @deprecated Use `UcanPermissionError`. */
export const PermissionError = UcanPermissionError;

/** Encryption, decryption, signature failures. */
export class CryptoError extends ScpError {
  constructor(message: string, code: string) {
    super(message, code);
    this.name = "CryptoError";
  }
}

/** Network, relay, connection failures. */
export class TransportError extends ScpError {
  constructor(message: string, code: string) {
    super(message, code);
    this.name = "TransportError";
  }
}

/** Input validation, schema, parameter failures. */
export class ValidationError extends ScpError {
  constructor(message: string, code: string) {
    super(message, code);
    this.name = "ValidationError";
  }
}

/** Storage read, write, or serialization failures. */
export class StorageError extends ScpError {
  constructor(message: string, code: string) {
    super(message, code);
    this.name = "StorageError";
  }
}

/** Device attestation or attestation chain verification failures. */
export class AttestationError extends ScpError {
  constructor(message: string, code: string) {
    super(message, code);
    this.name = "AttestationError";
  }
}

/** MCP server, client, or protocol failures. */
export class McpError extends ScpError {
  constructor(message: string, code: string) {
    super(message, code);
    this.name = "McpError";
  }
}

/** Governance proposal / vote / dispatch failures (SCP-GOV-* range). */
export class GovernanceError extends ScpError {
  constructor(message: string, code: string) {
    super(message, code);
    this.name = "GovernanceError";
  }
}

/** Economy / payment / spending UCAN / budget failures (SCP-ECON-*). */
export class EconomyError extends ScpError {
  constructor(message: string, code: string) {
    super(message, code);
    this.name = "EconomyError";
  }
}

/**
 * The browser (WASM) bridge cannot enforce a paid context's economic policy
 * because `scp-runtime`'s `enforce_economy` pipeline does not compile to
 * `wasm32` per ADR-034. Subclass of [`EconomyError`].
 */
export class EconomicPolicyUnsupportedOnWasm extends EconomyError {
  constructor(message: string, code: string) {
    super(message, code);
    this.name = "EconomicPolicyUnsupportedOnWasm";
  }
}

/**
 * The browser (WASM) bridge cannot validate a spending UCAN. Subclass of
 * [`EconomyError`].
 */
export class WasmCannotValidateSpendingUcan extends EconomyError {
  constructor(message: string, code: string) {
    super(message, code);
    this.name = "WasmCannotValidateSpendingUcan";
  }
}

// ---------------------------------------------------------------------------
// §5.4.4 Outlet error sealed hierarchy
// ---------------------------------------------------------------------------

/** Wire-form `OutletErrorClass` discriminant. */
export type OutletErrorClassWire =
  | "protocol"
  | "authorization"
  | "input"
  | "execution"
  | "output"
  | "economic"
  | "transport"
  | "governance";

const OUTLET_ERROR_CLASSES: ReadonlySet<OutletErrorClassWire> = new Set([
  "protocol",
  "authorization",
  "input",
  "execution",
  "output",
  "economic",
  "transport",
  "governance",
]);

const CATALOG_KEY_RE = /^[a-z][a-z0-9-]{0,63}(\.[a-z][a-z0-9-]{0,63})*$/;
const CATALOG_KEY_MAX_BYTES = 256;

// --- Branded newtypes -----------------------------------------------------

const CREDIT_MAX = 0xff_ff_ff_ff;

/**
 * Real runtime class for an Outlet credit grant — replaces the prior
 * `number & __brand` type alias.
 *
 * The previous bare-`number` brand was erased at runtime: `typeof grant ===
 * "number"` passed for any plain integer, so the runtime guard in
 * `grantCredit` accepted unwrapped numbers and the brand was security
 * theater. `Credit` is now a real class, so `instanceof Credit` is a
 * load-bearing runtime check that rejects raw integers reaching
 * `bridge.outletStreamGrantCredit`.
 *
 * Construct via `Credit.of(raw)` (preferred, type-safe) or
 * `new Credit(raw)`. Round-5 used per-language `RangeError` for
 * out-of-range input; round-6 unified the rejection error to
 * `InvalidGrant` under the `OutletError` hierarchy.
 */
export class Credit {
  readonly raw: number;

  constructor(raw: number) {
    if (typeof raw !== "number" || !Number.isInteger(raw) || raw <= 0 || raw > CREDIT_MAX) {
      throw new InvalidGrant(typeof raw === "number" ? raw : 0);
    }
    this.raw = raw;
  }

  /** Static factory — equivalent to `new Credit(raw)`. Reads more naturally
   *  at call sites that previously used `Credit(raw)` as a function. */
  static of(raw: number): Credit {
    return new Credit(raw);
  }

  /** Stable string form for logs / equality checks. */
  toString(): string {
    return `Credit(${this.raw})`;
  }

  /** JSON helper — serializes to the underlying integer so wire shapes are unchanged. */
  toJSON(): number {
    return this.raw;
  }
}

/**
 * Branded string newtype for §5.4.4 catalog keys (`message_catalog` keys
 * and slugs share the same regex). Use `CatalogKey(raw)` to construct.
 */
export type CatalogKey = string & { readonly __brand: "CatalogKey" };

/**
 * Construct a `CatalogKey`; throws `OutletProtocolError` (slug
 * `protocol.malformed-catalog-key`) on regex / length failure.
 */
export function CatalogKey(raw: string): CatalogKey {
  if (typeof raw !== "string" || raw.length === 0) {
    throw new OutletProtocolError(
      `catalog key must be a non-empty string, got ${typeof raw}`,
      "SCP-TOOL-6100",
      { slug: "protocol.malformed-catalog-key", retry: { policy: "never" } },
    );
  }
  if (Buffer.byteLength(raw, "utf-8") > CATALOG_KEY_MAX_BYTES) {
    throw new OutletProtocolError(
      `catalog key exceeds ${CATALOG_KEY_MAX_BYTES} bytes`,
      "SCP-TOOL-6100",
      { slug: "protocol.malformed-catalog-key", retry: { policy: "never" } },
    );
  }
  if (!CATALOG_KEY_RE.test(raw)) {
    throw new OutletProtocolError(
      `malformed catalog key: ${JSON.stringify(raw)}`,
      "SCP-TOOL-6100",
      { slug: "protocol.malformed-catalog-key", retry: { policy: "never" } },
    );
  }
  return raw as CatalogKey;
}

// `OutletId` is defined as a branded type in `./outlets.ts`. We re-use
// that type here rather than re-declaring it to avoid a duplicate-export
// collision on the package barrel.
import type { OutletId } from "./outlets";

/**
 * Construct an `OutletId` from a raw string. Throws `ValidationError`
 * on empty input. Round-6 / OUT-031: typed wrapper for the outlet-id
 * argument to `OutletError.new`.
 */
export function makeOutletId(raw: string): OutletId {
  if (typeof raw !== "string" || raw.length === 0) {
    throw new ValidationError("outletId must be non-empty string", "SCP-VALID-7000");
  }
  return raw as OutletId;
}

export type { OutletId };

// --- RetryPolicy + ContextHop ---------------------------------------------

/** §5.4.4 tag-5 retry guidance — wire-shape discriminated union. */
export type RetryPolicy =
  | { readonly policy: "never" }
  | { readonly policy: "immediate" }
  | { readonly policy: "after"; readonly delayMs: number }
  | { readonly policy: "with-backoff"; readonly minMs: number; readonly maxMs: number };

/** §5.4.4 tag-8 source-chain entry. */
export interface ContextHop {
  readonly contextId: string;
  readonly hopIndex: number;
  readonly wrappedCode: string;
}

// --- Per-class detail schemas --------------------------------------------

export type OutletErrorDetail =
  | { readonly rule: string }
  | { readonly capability: string }
  | { readonly fieldPath: string; readonly violation: string }
  | { readonly elapsedMs: number }
  | { readonly panicLocationHash: string }
  | { readonly needed: number; readonly currency: string }
  | { readonly adapterId: string }
  | { readonly retryAfterSecs: number }
  | { readonly relayUrlKind: "wss" | "ws-loopback" | "unknown" }
  | { readonly action: string }
  | Record<string, never>;

/** Per-class detail-shape conformance — wire-layer rejection. */
function validateDetailShape(class_: OutletErrorClassWire, detail: unknown): void {
  if (detail === undefined || detail === null) return;
  if (typeof detail !== "object" || Array.isArray(detail)) {
    throw new ValidationError(
      `OutletError.detail must be object, got ${typeof detail}`,
      "SCP-VALID-7000",
    );
  }
  const keys = Object.keys(detail).sort();
  const matches = (expected: string[]): boolean =>
    keys.length === expected.length && keys.every((k, i) => k === expected[i]);
  let ok = false;
  if (class_ === "protocol") {
    ok = matches(["rule"]);
  } else if (class_ === "authorization") {
    ok = matches(["capability"]);
  } else if (class_ === "governance") {
    ok = matches(["action"]);
  } else if (class_ === "input" || class_ === "output") {
    ok = matches(["fieldPath", "violation"]);
  } else if (class_ === "execution") {
    ok = keys.length === 0 || matches(["elapsedMs"]) || matches(["panicLocationHash"]);
  } else if (class_ === "economic") {
    ok = matches(["adapterId"]) || matches(["currency", "needed"]);
  } else if (class_ === "transport") {
    ok = matches(["retryAfterSecs"]) || matches(["relayUrlKind"]);
  }
  if (!ok) {
    throw new ValidationError(
      `OutletError.detail shape mismatch for class "${class_}"`,
      "SCP-VALID-7000",
    );
  }
}

// --- PII redaction --------------------------------------------------------

const EMAIL_RE = /[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/g;
const DID_RE = /did:(dht|web|key):[A-Za-z0-9._-]+/g;

/** Redact emails and DIDs before surfacing `message` to logs. */
export function redactPii(message: string): string {
  if (typeof message !== "string") return message as unknown as string;
  return message.replace(EMAIL_RE, "[redacted]").replace(DID_RE, "[redacted]");
}

// --- Options-object input for `OutletError.new` ---------------------------

export interface OutletErrorNewOpts {
  readonly outletId: OutletId;
  readonly catalogKey: CatalogKey;
  readonly class: OutletErrorClassWire;
  readonly code?: string;
  readonly slug?: string;
  readonly retry?: RetryPolicy;
  readonly detail?: OutletErrorDetail;
  readonly sourceChain?: readonly ContextHop[];
  readonly padNonce?: Uint8Array;
  readonly registrationEventId?: Uint8Array;
  /**
   * SCP-OUT-041d: when both `contextId` and `registrationEventId` are
   * supplied the constructor delegates to the NAPI/WASM FFI export
   * `outletErrorNew` so the §5.4.4 wire-message HMAC happens at the
   * bridge boundary using the pinned `outlet_message_key`. The SDK
   * never sees the raw key.
   */
  readonly contextId?: string;
}

// --- OutletError base + concrete subclasses ------------------------------

/**
 * Base class for the §5.4.4 sealed outlet-error hierarchy.
 *
 * Concrete subclasses each carry a static `code` and a static `class` tag;
 * legacy callers may still construct `new OutletError(message, code)`
 * directly, in which case the instance is treated as a generic outlet-class
 * error (no `class` discriminant is set).
 */
export class OutletError extends ScpError {
  /** Static class-tag string used by the runtime guards. */
  static readonly scpClassTag: string = "OutletError";

  /** Wire-form `OutletErrorClass` for this concrete subclass. Empty on the
   *  abstract-ish base. Subclasses override to one of the eight values. */
  readonly classWire: OutletErrorClassWire | null;

  readonly slug: string | undefined;
  readonly retry: RetryPolicy | undefined;
  readonly detail: OutletErrorDetail | undefined;
  readonly sourceChain: readonly ContextHop[];
  readonly padNonce: Uint8Array | undefined;
  readonly registrationEventId: Uint8Array | undefined;

  constructor(
    message: string,
    code: string,
    extra?: {
      classWire?: OutletErrorClassWire | null;
      slug?: string | undefined;
      retry?: RetryPolicy | undefined;
      detail?: OutletErrorDetail | undefined;
      sourceChain?: readonly ContextHop[];
      padNonce?: Uint8Array | undefined;
      registrationEventId?: Uint8Array | undefined;
    },
  ) {
    super(redactPii(message), code);
    this.name = "OutletError";
    this.classWire = extra?.classWire ?? null;
    this.slug = extra?.slug;
    this.retry = extra?.retry;
    this.detail = extra?.detail;
    this.sourceChain = extra?.sourceChain ?? [];
    this.padNonce = extra?.padNonce;
    this.registrationEventId = extra?.registrationEventId;
  }

  /**
   * Construct a typed concrete subclass from a keyword-only options object.
   * `outletId` and `catalogKey` are adjacent string arguments — the
   * options-object shape eliminates the round-6 swap-risk.
   *
   * SCP-OUT-041d: when `contextId` AND `registrationEventId` are both
   * supplied, the construction is delegated to the FFI bridge which
   * performs the §5.4.4 wire-message HMAC using the pinned
   * `outlet_message_key` — the SDK never sees the raw key. Use
   * `OutletError.newViaBridge` directly for the async FFI form.
   */
  static new(opts: OutletErrorNewOpts): OutletError {
    if (!OUTLET_ERROR_CLASSES.has(opts.class)) {
      throw new ValidationError(
        `unknown OutletErrorClass: ${JSON.stringify(opts.class)}`,
        "SCP-VALID-7000",
      );
    }
    if (typeof opts.catalogKey !== "string" || !CATALOG_KEY_RE.test(opts.catalogKey)) {
      throw new OutletProtocolError(
        `catalogKey ${JSON.stringify(opts.catalogKey)} is not a valid CatalogKey`,
        "SCP-TOOL-6100",
        { slug: "protocol.malformed-catalog-key", retry: { policy: "never" } },
      );
    }
    if (typeof opts.outletId !== "string" || opts.outletId.length === 0) {
      throw new ValidationError("outletId must be a non-empty string", "SCP-VALID-7000");
    }
    if (opts.detail !== undefined) {
      validateDetailShape(opts.class, opts.detail);
    }
    const Ctor = CLASS_CTOR[opts.class];
    return new Ctor(redactPii(opts.catalogKey), opts.code ?? Ctor.defaultCode, {
      classWire: opts.class,
      slug: opts.slug ?? opts.catalogKey,
      retry: opts.retry ?? { policy: "never" },
      detail: opts.detail,
      sourceChain: opts.sourceChain ?? [],
      padNonce: opts.padNonce,
      registrationEventId: opts.registrationEventId,
    });
  }

  /**
   * SCP-OUT-041d FFI form of {@link OutletError.new} — delegates to the
   * bridge `outletErrorNew` so the §5.4.4 wire-message HMAC happens at
   * the FFI boundary using the pinned per-outlet `outlet_message_key`.
   * The SDK never sees the raw key.
   */
  static async newViaBridge(opts: {
    handle: { contextId: string; state: string; creatorDid: string };
    outletId: string;
    registrationEventId: Uint8Array;
    catalogKey: CatalogKey;
    class: OutletErrorClassWire;
    code?: string;
    slug?: string;
    retry?: RetryPolicy;
    detail?: OutletErrorDetail;
    sourceChain?: readonly ContextHop[];
    padNonce?: Uint8Array;
  }): Promise<OutletError> {
    const { getBridge } = await import("./internal/bridge");
    const bridge = await getBridge();
    if (!OUTLET_ERROR_CLASSES.has(opts.class)) {
      throw new ValidationError(
        `unknown OutletErrorClass: ${JSON.stringify(opts.class)}`,
        "SCP-VALID-7000",
      );
    }
    if (typeof opts.catalogKey !== "string" || !CATALOG_KEY_RE.test(opts.catalogKey)) {
      throw new OutletProtocolError(
        `catalogKey ${JSON.stringify(opts.catalogKey)} is not a valid CatalogKey`,
        "SCP-TOOL-6100",
        { slug: "protocol.malformed-catalog-key", retry: { policy: "never" } },
      );
    }
    if (opts.registrationEventId.length !== 32) {
      throw new ValidationError("registrationEventId must be 32 bytes", "SCP-VALID-7000");
    }
    const padNonce = opts.padNonce ?? crypto.getRandomValues(new Uint8Array(16));
    if (padNonce.length !== 16) {
      throw new ValidationError("padNonce must be 16 bytes", "SCP-VALID-7000");
    }
    const Ctor = CLASS_CTOR[opts.class];
    const codeStr = opts.code ?? Ctor.defaultCode;
    const slugStr = opts.slug ?? String(opts.catalogKey);
    const retryStr = (opts.retry ?? { policy: "never" }).policy;
    const detailJson = opts.detail !== undefined ? JSON.stringify(opts.detail) : undefined;
    const sourceChainJson =
      opts.sourceChain !== undefined ? JSON.stringify(opts.sourceChain) : undefined;
    const json = await bridge.outletErrorNew(
      opts.handle,
      opts.outletId,
      bytesToHex(opts.registrationEventId),
      String(opts.catalogKey),
      opts.class,
      codeStr,
      slugStr,
      retryStr,
      bytesToHex(padNonce),
      detailJson,
      sourceChainJson,
    );
    const wire = JSON.parse(json) as Record<string, unknown>;
    return OutletError.fromWire(wire);
  }

  /** Serialize to a wire-form object. */
  toWire(): Record<string, unknown> {
    const out: Record<string, unknown> = {
      code: this.code,
      slug: this.slug,
      class: this.classWire,
      message: this.message,
      retry: this.retry ?? { policy: "never" },
      sourceChain: this.sourceChain,
    };
    if (this.detail !== undefined) out.detail = this.detail;
    if (this.padNonce !== undefined) out.padNonce = bytesToHex(this.padNonce);
    if (this.registrationEventId !== undefined)
      out.registrationEventId = bytesToHex(this.registrationEventId);
    return out;
  }

  /** Deserialize from a wire-form object — re-types into the right subclass.
   *
   * Accepts both camelCase fields (TypeScript native) and snake_case
   * fields (the SCP-OUT-041d bridge wire form). */
  static fromWire(value: Record<string, unknown>): OutletError {
    const class_ = String(value.class ?? "").toLowerCase() as OutletErrorClassWire;
    if (!OUTLET_ERROR_CLASSES.has(class_)) {
      throw new ValidationError(
        `unknown OutletErrorClass on wire: ${JSON.stringify(value.class)}`,
        "SCP-VALID-7000",
      );
    }
    if (value.detail !== undefined) {
      validateDetailShape(class_, value.detail);
    }
    const Ctor = CLASS_CTOR[class_];
    const padNonceRaw = value.padNonce ?? value.pad_nonce;
    const padNonce = typeof padNonceRaw === "string" ? hexToBytes(padNonceRaw) : undefined;
    const regIdRaw = value.registrationEventId ?? value.registration_event_id;
    const regId = typeof regIdRaw === "string" ? hexToBytes(regIdRaw) : undefined;
    const sourceChain = (value.sourceChain ?? value.source_chain ?? []) as readonly ContextHop[];
    return new Ctor(String(value.message ?? ""), String(value.code ?? Ctor.defaultCode), {
      classWire: class_,
      slug: value.slug !== undefined ? String(value.slug) : undefined,
      retry: (value.retry ?? { policy: "never" }) as RetryPolicy,
      detail: value.detail as OutletErrorDetail | undefined,
      sourceChain,
      padNonce,
      registrationEventId: regId,
    });
  }

  // --- Runtime type guards (factory-fallback path) ----------------------

  static isOutletError(err: unknown): err is OutletError {
    if (err instanceof OutletError) return true;
    // Realm-crossing fallback: any object whose `scpClassTag` matches one
    // of the known outlet-hierarchy class tags is treated as an
    // `OutletError`.
    if (err === null || typeof err !== "object") return false;
    const tag = (err as { scpClassTag?: unknown }).scpClassTag;
    return (
      typeof tag === "string" &&
      (tag === "OutletError" ||
        tag === "OutletProtocolError" ||
        tag === "AuthorizationError" ||
        tag === "InputError" ||
        tag === "ExecutionError" ||
        tag === "OutputError" ||
        tag === "EconomicError" ||
        tag === "OutletTransportError" ||
        tag === "OutletGovernanceError" ||
        tag === "InvalidGrant" ||
        tag === "StreamAlreadyClosed")
    );
  }
  static isOutletProtocolError(err: unknown): err is OutletProtocolError {
    return err instanceof OutletProtocolError || hasScpClassTag(err, "OutletProtocolError");
  }
  static isAuthorizationError(err: unknown): err is AuthorizationError {
    return err instanceof AuthorizationError || hasScpClassTag(err, "AuthorizationError");
  }
  static isInputError(err: unknown): err is InputError {
    return err instanceof InputError || hasScpClassTag(err, "InputError");
  }
  static isExecutionError(err: unknown): err is ExecutionError {
    return err instanceof ExecutionError || hasScpClassTag(err, "ExecutionError");
  }
  static isOutputError(err: unknown): err is OutputError {
    return err instanceof OutputError || hasScpClassTag(err, "OutputError");
  }
  static isEconomicError(err: unknown): err is EconomicError {
    return err instanceof EconomicError || hasScpClassTag(err, "EconomicError");
  }
  static isOutletTransportError(err: unknown): err is OutletTransportError {
    return err instanceof OutletTransportError || hasScpClassTag(err, "OutletTransportError");
  }
  static isOutletGovernanceError(err: unknown): err is OutletGovernanceError {
    return err instanceof OutletGovernanceError || hasScpClassTag(err, "OutletGovernanceError");
  }
  static isInvalidGrant(err: unknown): err is InvalidGrant {
    return err instanceof InvalidGrant || hasScpClassTag(err, "InvalidGrant");
  }
  static isStreamAlreadyClosed(err: unknown): err is StreamAlreadyClosed {
    return err instanceof StreamAlreadyClosed || hasScpClassTag(err, "StreamAlreadyClosed");
  }
}

function hasScpClassTag(err: unknown, tag: string): boolean {
  if (err === null || typeof err !== "object") return false;
  const candidate = (err as { scpClassTag?: unknown }).scpClassTag;
  return typeof candidate === "string" && candidate === tag;
}

type OutletErrorCtor = (new (
  message: string,
  code: string,
  extra?: ConstructorParameters<typeof OutletError>[2],
) => OutletError) & { defaultCode: string };

/** §5.4.4 `Protocol` class — registration / validation / classification. */
export class OutletProtocolError extends OutletError {
  static readonly scpClassTag: string = "OutletProtocolError";
  static readonly defaultCode: string = "SCP-TOOL-6100";
  constructor(
    message: string,
    code: string = OutletProtocolError.defaultCode,
    extra?: ConstructorParameters<typeof OutletError>[2],
  ) {
    super(message, code, { ...extra, classWire: extra?.classWire ?? "protocol" });
    this.name = "OutletProtocolError";
    (this as unknown as { scpClassTag: string }).scpClassTag = "OutletProtocolError";
  }
}

/** §5.4.4 `Authorization` class. */
export class AuthorizationError extends OutletError {
  static readonly scpClassTag: string = "AuthorizationError";
  static readonly defaultCode: string = "SCP-TOOL-6110";
  constructor(
    message: string,
    code: string = AuthorizationError.defaultCode,
    extra?: ConstructorParameters<typeof OutletError>[2],
  ) {
    super(message, code, { ...extra, classWire: extra?.classWire ?? "authorization" });
    this.name = "AuthorizationError";
    (this as unknown as { scpClassTag: string }).scpClassTag = "AuthorizationError";
  }
}

/** §5.4.4 `Input` class. */
export class InputError extends OutletError {
  static readonly scpClassTag: string = "InputError";
  static readonly defaultCode: string = "SCP-TOOL-6120";
  constructor(
    message: string,
    code: string = InputError.defaultCode,
    extra?: ConstructorParameters<typeof OutletError>[2],
  ) {
    super(message, code, { ...extra, classWire: extra?.classWire ?? "input" });
    this.name = "InputError";
    (this as unknown as { scpClassTag: string }).scpClassTag = "InputError";
  }
}

/** §5.4.4 `Execution` class. */
export class ExecutionError extends OutletError {
  static readonly scpClassTag: string = "ExecutionError";
  static readonly defaultCode: string = "SCP-TOOL-6130";
  constructor(
    message: string,
    code: string = ExecutionError.defaultCode,
    extra?: ConstructorParameters<typeof OutletError>[2],
  ) {
    super(message, code, { ...extra, classWire: extra?.classWire ?? "execution" });
    this.name = "ExecutionError";
    (this as unknown as { scpClassTag: string }).scpClassTag = "ExecutionError";
  }
}

/** §5.4.4 `Output` class. */
export class OutputError extends OutletError {
  static readonly scpClassTag: string = "OutputError";
  static readonly defaultCode: string = "SCP-TOOL-6140";
  constructor(
    message: string,
    code: string = OutputError.defaultCode,
    extra?: ConstructorParameters<typeof OutletError>[2],
  ) {
    super(message, code, { ...extra, classWire: extra?.classWire ?? "output" });
    this.name = "OutputError";
    (this as unknown as { scpClassTag: string }).scpClassTag = "OutputError";
  }
}

/** §5.4.4 `Economic` class. */
export class EconomicError extends OutletError {
  static readonly scpClassTag: string = "EconomicError";
  static readonly defaultCode: string = "SCP-TOOL-6150";
  constructor(
    message: string,
    code: string = EconomicError.defaultCode,
    extra?: ConstructorParameters<typeof OutletError>[2],
  ) {
    super(message, code, { ...extra, classWire: extra?.classWire ?? "economic" });
    this.name = "EconomicError";
    (this as unknown as { scpClassTag: string }).scpClassTag = "EconomicError";
  }
}

/**
 * §5.4.4 `Transport` class. Suffixed `Outlet` to disambiguate from the
 * top-level `TransportError` legacy category class.
 */
export class OutletTransportError extends OutletError {
  static readonly scpClassTag: string = "OutletTransportError";
  static readonly defaultCode: string = "SCP-TOOL-6160";
  constructor(
    message: string,
    code: string = OutletTransportError.defaultCode,
    extra?: ConstructorParameters<typeof OutletError>[2],
  ) {
    super(message, code, { ...extra, classWire: extra?.classWire ?? "transport" });
    this.name = "OutletTransportError";
    (this as unknown as { scpClassTag: string }).scpClassTag = "OutletTransportError";
  }
}

/** §5.4.4 `Governance` class. */
export class OutletGovernanceError extends OutletError {
  static readonly scpClassTag: string = "OutletGovernanceError";
  static readonly defaultCode: string = "SCP-TOOL-6170";
  constructor(
    message: string,
    code: string = OutletGovernanceError.defaultCode,
    extra?: ConstructorParameters<typeof OutletError>[2],
  ) {
    super(message, code, { ...extra, classWire: extra?.classWire ?? "governance" });
    this.name = "OutletGovernanceError";
    (this as unknown as { scpClassTag: string }).scpClassTag = "OutletGovernanceError";
  }
}

/**
 * Round-6 unified zero-credit-grant rejection. Lives under
 * `OutletProtocolError` so all four SDKs surface the same exception class
 * (replaces the per-language `RangeError` / `ValueError` /
 * `IllegalArgumentException` inconsistency that round-5 shipped).
 */
export class InvalidGrant extends OutletProtocolError {
  static override readonly scpClassTag: string = "InvalidGrant";
  static override readonly defaultCode = "SCP-TOOL-6101";
  readonly grant: number;
  constructor(grant: number) {
    super(`invalid grant ${grant}: must be in (0, 2^32 - 1]`, InvalidGrant.defaultCode, {
      slug: "protocol.invalid-grant",
      retry: { policy: "never" },
    });
    this.name = "InvalidGrant";
    (this as unknown as { scpClassTag: string }).scpClassTag = "InvalidGrant";
    this.grant = grant;
  }
}

/**
 * SCP-OUT-038 lifecycle-violation error. Raised when control-plane
 * methods (`grantCredit`, `cancel`) are invoked on an
 * {@link InvocationHandle} whose stream has already emitted a terminal
 * chunk (`End` or `Error{terminal: true}`).
 *
 * Per AC13 the lifecycle error sits at the SAME inheritance depth as
 * the other protocol-class siblings (`StreamAlreadyOpen`,
 * `UnknownSession`, catalog-rotation): the parent class is
 * {@link OutletProtocolError}, NOT {@link OutletError} directly. This
 * makes `instanceof OutletProtocolError` catch every protocol-class
 * violation uniformly across SDKs.
 */
export class StreamAlreadyClosed extends OutletProtocolError {
  static override readonly scpClassTag: string = "StreamAlreadyClosed";
  static override readonly defaultCode = "SCP-TOOL-6101";
  constructor(message?: string) {
    super(
      message ?? "stream has already terminated; control-plane methods rejected",
      StreamAlreadyClosed.defaultCode,
      {
        slug: "protocol.stream-already-closed",
        retry: { policy: "never" },
      },
    );
    this.name = "StreamAlreadyClosed";
    (this as unknown as { scpClassTag: string }).scpClassTag = "StreamAlreadyClosed";
  }
}

const CLASS_CTOR: Record<OutletErrorClassWire, OutletErrorCtor> = {
  protocol: OutletProtocolError as unknown as OutletErrorCtor,
  authorization: AuthorizationError as unknown as OutletErrorCtor,
  input: InputError as unknown as OutletErrorCtor,
  execution: ExecutionError as unknown as OutletErrorCtor,
  output: OutputError as unknown as OutletErrorCtor,
  economic: EconomicError as unknown as OutletErrorCtor,
  transport: OutletTransportError as unknown as OutletErrorCtor,
  governance: OutletGovernanceError as unknown as OutletErrorCtor,
};

// --- Legacy aliases for pre-OUT-031 code ---------------------------------

/**
 * Pre-OUT-031 leaf class — referenced outlet does not exist. Now an alias
 * for `OutletProtocolError` so existing call-sites keep compiling.
 */
export class OutletNotFoundError extends OutletProtocolError {
  constructor(message: string, code = "SCP-TOOL-6100") {
    super(message, code);
    this.name = "OutletNotFoundError";
    (this as unknown as { scpClassTag: string }).scpClassTag = "OutletNotFoundError";
  }
}

/**
 * Pre-OUT-031 leaf class — execution failure. Now an alias for
 * `ExecutionError` so existing call-sites keep compiling. The pre-redesign
 * default code `SCP-TOOL-6200` lies outside the §5.4.4 6100-6199 sub-block;
 * round-6 ``OutletError.new()`` does not emit this code, but the legacy
 * shim retains it for back-compat with stored logs.
 */
export class OutletExecutionError extends ExecutionError {
  constructor(message: string, code = "SCP-TOOL-6200") {
    super(message, code);
    this.name = "OutletExecutionError";
    (this as unknown as { scpClassTag: string }).scpClassTag = "OutletExecutionError";
  }
}

// ---------------------------------------------------------------------------
// Bridge error parser
// ---------------------------------------------------------------------------

type ScpErrorConstructor = new (message: string, code: string) => ScpError;

const ERROR_PREFIX_MAP: ReadonlyArray<readonly [string, ScpErrorConstructor]> = [
  ["SCP-IDENT-", IdentityError],
  ["SCP-CTX-", ContextError],
  ["SCP-PERM-", UcanPermissionError],
  ["SCP-CRYPTO-", CryptoError],
  ["SCP-TRANS-", TransportError],
  ["SCP-TOOL-", OutletProtocolError],
  ["SCP-VALID-", ValidationError],
  ["SCP-STORAGE-", StorageError],
  ["SCP-ATTEST-", AttestationError],
  ["SCP-MCP-", McpError],
  ["SCP-GOV-", GovernanceError],
  ["SCP-ECON-", EconomyError],
];

const ERROR_CODE_OVERRIDES: ReadonlyMap<string, ScpErrorConstructor> = new Map<
  string,
  ScpErrorConstructor
>([
  ["SCP-ECON-12095", EconomicPolicyUnsupportedOnWasm],
  ["SCP-ECON-12096", WasmCannotValidateSpendingUcan],
]);

/**
 * Parses a bridge error message and constructs the appropriate `ScpError`
 * subclass.
 */
export function mapBridgeError(error: unknown): ScpError {
  const message = error instanceof Error ? error.message : String(error);
  const codeMatch = /\[([A-Z]+-[A-Z]+-\d+)\]/.exec(message);
  const code = codeMatch?.[1] ?? "SCP-UNKNOWN-0000";

  const Override = ERROR_CODE_OVERRIDES.get(code);
  if (Override !== undefined) {
    return new Override(message, code);
  }
  for (const [prefix, ErrorClass] of ERROR_PREFIX_MAP) {
    if (code.startsWith(prefix)) {
      return new ErrorClass(message, code);
    }
  }
  return new ScpError(message, code);
}

// ---------------------------------------------------------------------------
// Hex helpers (used by toWire / fromWire)
// ---------------------------------------------------------------------------

function bytesToHex(bytes: Uint8Array): string {
  let out = "";
  for (let i = 0; i < bytes.length; i++) {
    const b = bytes[i] ?? 0;
    out += b.toString(16).padStart(2, "0");
  }
  return out;
}

function hexToBytes(hex: string): Uint8Array {
  if (hex.length % 2 !== 0) {
    throw new ValidationError("hex string has odd length", "SCP-VALID-7000");
  }
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    const byte = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
    if (Number.isNaN(byte)) {
      throw new ValidationError("invalid hex digit", "SCP-VALID-7000");
    }
    out[i] = byte;
  }
  return out;
}

// (Buffer is imported at the top of the file.)
