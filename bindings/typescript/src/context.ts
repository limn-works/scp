/**
 * Context module for the SCP TypeScript SDK.
 *
 * After Phase 4 PR 4 (#1549, ADR-048) Agent B1, `Context` collapses
 * to a pure handle type: no `#scp` backing, no instance methods that
 * touch the bridge, no static factories other than `_fromHandle`. All
 * context lifecycle and content operations (create, join, send,
 * receive, leave, close, tool registration, governance, broadcast,
 * economic policy, TTL, export/import, event drain, etc.) live as
 * methods on the {@link SCP} class.
 *
 * Value interfaces defined in this module describe wire payloads the
 * SDK exchanges with the bridge (e.g. capability declaration results,
 * invitation decisions, metadata records). They remain exported as
 * types so callers can strongly type the JSON they pass to and
 * receive from `SCP` methods.
 *
 * See ADR-022 in `.docs/adrs/phase-4.md`, ADR-048, and
 * `.docs/scaffold/typescript.md`.
 */

import { ValidationError } from "./errors";
import type { BridgeContextHandle } from "./internal/bridge";
import type { SCP } from "./scp";

// ---------------------------------------------------------------------------
// EconomicPolicy schema validation (§19.3, ADR-034)
// ---------------------------------------------------------------------------

/**
 * Validates that a JSON string conforms to the `EconomicPolicy` schema.
 *
 * Defense-in-depth for the WASM path: the WASM bridge can only validate
 * that the input is well-formed JSON (ADR-034 prevents importing scp-core
 * types). This function checks required fields and basic types so schema
 * violations are caught before crossing the FFI boundary.
 *
 * @throws {ValidationError} if the JSON is malformed or missing required fields.
 * @internal Exported as `_validateEconomicPolicyJson` for testing.
 */
export function _validateEconomicPolicyJson(json: string): void {
  let parsed: unknown;
  try {
    parsed = JSON.parse(json);
  } catch {
    throw new ValidationError("invalid economic policy JSON: syntax error", "SCP-VALID-7001");
  }

  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
    throw new ValidationError("invalid economic policy JSON: expected an object", "SCP-VALID-7001");
  }

  const obj = parsed as Record<string, unknown>;

  if (typeof obj.locked !== "boolean") {
    throw new ValidationError(
      "invalid economic policy JSON: 'locked' must be a boolean",
      "SCP-VALID-7001",
    );
  }

  if (typeof obj.cost_schedule !== "object" || obj.cost_schedule === null) {
    throw new ValidationError(
      "invalid economic policy JSON: 'cost_schedule' must be an object",
      "SCP-VALID-7001",
    );
  }

  if (!Array.isArray(obj.payment_adapters)) {
    throw new ValidationError(
      "invalid economic policy JSON: 'payment_adapters' must be an array",
      "SCP-VALID-7001",
    );
  }

  if (typeof obj.payee !== "string") {
    throw new ValidationError(
      "invalid economic policy JSON: 'payee' must be a string",
      "SCP-VALID-7001",
    );
  }
}

// ---------------------------------------------------------------------------
// Client-side validation (SCP-297, spec §18.11.9)
// ---------------------------------------------------------------------------

/** Maximum content path length in bytes. */
const MAX_CONTENT_PATH_BYTES = 1024;

/** Maximum deploy ID length in bytes. */
const MAX_DEPLOY_ID_BYTES = 128;

/**
 * Returns true for Unicode formatting/invisible characters.
 * Mirrors the Rust `is_unicode_formatting` helper.
 */
function _isUnicodeFormatting(cp: number): boolean {
  return (
    cp === 0x00a0 || // NBSP
    cp === 0x1680 || // Ogham space mark
    (cp >= 0x2000 && cp <= 0x200f) || // Typographic spaces (2000-200A) + ZWSP..RLM (200B-200F)
    cp === 0x2028 ||
    cp === 0x2029 ||
    (cp >= 0x202a && cp <= 0x202f) || // Bidi embedding controls + narrow no-break space
    cp === 0x205f ||
    (cp >= 0x2060 && cp <= 0x206f) ||
    cp === 0x3000 ||
    cp === 0xfeff ||
    cp === 0xfffe ||
    cp === 0xffff
  );
}

/** RFC 7230 §3.2.6 tchar test (minus '%'). */
const TCHAR_RE = /^[a-zA-Z0-9!#$&'*+\-.^_`|~]+$/;

/** Forbidden substrings in content paths, paired with error messages. */
const _CONTENT_PATH_FORBIDDEN: [string, string][] = [
  ["\\", "ContentPath must not contain backslashes"],
  ["%", "ContentPath must not contain percent-encoded bytes"],
  ["?", "ContentPath must not contain query strings ('?')"],
  ["#", "ContentPath must not contain fragments ('#')"],
  ["\0", "ContentPath must not contain null bytes"],
  ["//", "ContentPath must not contain '//'"],
];

/** Formats a code point as a zero-padded uppercase hex string. */
function _cpHex(cp: number): string {
  return cp.toString(16).toUpperCase().padStart(4, "0");
}

/** Checks for forbidden substrings, control characters, and formatting chars. */
function _contentPathCharError(path: string): string | null {
  for (const [sub, msg] of _CONTENT_PATH_FORBIDDEN) {
    if (path.includes(sub)) return msg;
  }
  for (const ch of path) {
    const cp = ch.codePointAt(0) ?? 0;
    // C0 controls (U+0000-U+001F), DEL (U+007F), and C1 controls (U+0080-U+009F)
    if (cp <= 0x1f || cp === 0x7f || (cp >= 0x80 && cp <= 0x9f)) {
      return `ContentPath must not contain control character U+${_cpHex(cp)}`;
    }
  }
  for (const ch of path) {
    const cp = ch.codePointAt(0) ?? 0;
    if (cp > 0x7f && _isUnicodeFormatting(cp)) {
      return `ContentPath must not contain non-ASCII whitespace/formatting U+${_cpHex(cp)}`;
    }
  }
  return null;
}

/** Checks structural rules (prefix, length, trailing slash, segments). */
function _contentPathStructureError(path: string): string | null {
  if (!path.startsWith("/")) return "ContentPath must start with '/'";
  if (new TextEncoder().encode(path).length > MAX_CONTENT_PATH_BYTES) {
    return `ContentPath exceeds ${MAX_CONTENT_PATH_BYTES} bytes`;
  }
  if (path.length > 1 && path.endsWith("/")) {
    return "ContentPath must not have trailing slash (except root '/')";
  }
  for (const segment of path.split("/").slice(1)) {
    if (segment === ".") return "ContentPath must not contain '.' segments";
    if (segment === "..") return "ContentPath must not contain '..' segments (directory traversal)";
  }
  return null;
}

/**
 * Validates a content path before FFI crossing (SCP-297).
 *
 * Mirrors the Rust `ContentPath::new` validation from
 * `crates/scp-core/src/context/broadcast_content.rs`.
 *
 * @throws {ValidationError} If the path is invalid.
 * @internal Exported for testing.
 */
export function _validateContentPath(path: string): void {
  // NFC-normalize before validation
  const normalized = path.normalize("NFC");
  const error = _contentPathStructureError(normalized) ?? _contentPathCharError(normalized);
  if (error) throw new ValidationError(error, "SCP-VALID-7010");
}

/**
 * Validates a MIME type before FFI crossing (SCP-297).
 *
 * Mirrors the Rust `MimeType::new` validation from
 * `crates/scp-core/src/context/broadcast_content.rs`.
 *
 * @throws {ValidationError} If the MIME type is invalid.
 * @internal Exported for testing.
 */
export function _validateMimeType(contentType: string): void {
  if (!contentType) {
    throw new ValidationError("MimeType must not be empty", "SCP-VALID-7011");
  }
  for (const ch of contentType) {
    const cp = ch.codePointAt(0) ?? 0;
    // C0 controls (U+0000-U+001F), DEL (U+007F), and C1 controls (U+0080-U+009F)
    if (cp <= 0x1f || cp === 0x7f || (cp >= 0x80 && cp <= 0x9f)) {
      throw new ValidationError(
        `MimeType must not contain control character U+${cp.toString(16).toUpperCase().padStart(4, "0")}`,
        "SCP-VALID-7011",
      );
    }
  }
  if (contentType.includes(";")) {
    throw new ValidationError(
      "MimeType must not contain parameters (';' not allowed)",
      "SCP-VALID-7011",
    );
  }
  const slashCount = [...contentType].filter((c) => c === "/").length;
  if (slashCount !== 1) {
    throw new ValidationError(
      "MimeType must be 'type/subtype' (exactly one '/')",
      "SCP-VALID-7011",
    );
  }
  const [typePart, subtypePart] = contentType.split("/", 2);
  if (!typePart || !subtypePart) {
    throw new ValidationError("MimeType type and subtype must both be non-empty", "SCP-VALID-7011");
  }
  // RFC 7230 §3.2.6 tchar validation
  if (!TCHAR_RE.test(typePart)) {
    throw new ValidationError("MimeType type part contains invalid characters", "SCP-VALID-7011");
  }
  if (!TCHAR_RE.test(subtypePart)) {
    throw new ValidationError(
      "MimeType subtype part contains invalid characters",
      "SCP-VALID-7011",
    );
  }
}

/**
 * Validates a deploy ID before FFI crossing (SCP-297).
 *
 * Mirrors the Rust `validate_deploy_id` from
 * `crates/scp-core/src/context/broadcast_content.rs`.
 *
 * @throws {ValidationError} If the deploy ID is invalid.
 * @internal Exported for testing.
 */
export function _validateDeployId(deployId: string): void {
  if (!deployId) {
    throw new ValidationError("deploy_id must not be empty", "SCP-VALID-7012");
  }
  if (new TextEncoder().encode(deployId).length > MAX_DEPLOY_ID_BYTES) {
    throw new ValidationError(`deploy_id exceeds ${MAX_DEPLOY_ID_BYTES} bytes`, "SCP-VALID-7012");
  }
  if (!/^[a-zA-Z0-9\-_]+$/.test(deployId)) {
    throw new ValidationError(
      "deploy_id must be ASCII alphanumeric, '-', or '_'",
      "SCP-VALID-7012",
    );
  }
}

// ---------------------------------------------------------------------------
// Context
// ---------------------------------------------------------------------------

/**
 * An opaque handle to an SCP context — a bounded, encrypted interaction
 * space.
 *
 * After Phase 4 PR 4 Agent B1, `Context` is a pure handle type: it
 * carries the context ID, the raw bridge handle, and the joined
 * identity DID. All lifecycle operations (`create`, `import`,
 * `leave`, `close`, `send`, `receive`, tool registration, governance,
 * broadcast, economic policy, TTL, event drain, etc.) live as methods
 * on the {@link SCP} class. Pass a `Context` wherever the underlying
 * bridge call needs the context handle.
 *
 * Callers invoke lifecycle directly:
 *
 * ```typescript
 * const ctx = await scp.contextCreate(identity, paramsJson);
 * try {
 *   await scp.contextSend(ctx, identity.did, payload);
 * } finally {
 *   await scp.contextLeave(ctx, identity.did);
 * }
 * ```
 *
 * There is no `AsyncDisposable` integration: a pure handle cannot
 * self-leave because it no longer carries an `SCP` reference.
 */
export class Context {
  /** The unique identifier for this context. */
  readonly contextId: string;

  /** @internal Opaque bridge handle — not part of the public API. */
  readonly _rawHandle: BridgeContextHandle;

  /** The DID of the identity that created/joined this context. */
  readonly identityDid: string;

  private constructor(contextId: string, rawHandle: BridgeContextHandle, identityDid: string) {
    this.contextId = contextId;
    this._rawHandle = rawHandle;
    this.identityDid = identityDid;
  }

  /**
   * Constructs a `Context` from an existing bridge handle.
   *
   * The `scp` parameter is retained for API symmetry with the other
   * `_fromHandle` statics — the handle itself is self-contained so no
   * `SCP` reference is stored.
   *
   * @internal Phase 4 PR 4 (#1549, ADR-048) — used by `SCP.contextCreate`
   *   and related forwarders.
   */
  static _fromHandle(_scp: SCP, raw: BridgeContextHandle, identityDid: string): Context {
    return new Context(raw.contextId, raw, identityDid);
  }
}

// ---------------------------------------------------------------------------
// App Sandboxing (spec §8.4.1, §8.4.2, issue #595)
// ---------------------------------------------------------------------------

/** Result of validating a capability declaration. */
export interface DeclarationValidationResult {
  valid: boolean;
  grantedCapabilities: readonly string[];
  error: string | null;
  appDid: string;
}

// ---------------------------------------------------------------------------
// Invitation evaluation (#614)
// ---------------------------------------------------------------------------

/**
 * Result of evaluating a context invitation.
 */
export interface InvitationEvaluationResult {
  /** The pipeline decision: `"auto_accept"` or `"prompt_agent"`. */
  readonly decision: "auto_accept" | "prompt_agent";
}

// ---------------------------------------------------------------------------
// MetadataRecord inspection (§5.7.2, #615)
// ---------------------------------------------------------------------------

/** Structural metadata fields -- always visible before joining. */
export interface StructuralMetadata {
  template_id: string | null;
  ceiling: string[];
  ceiling_policy: string;
  roles: unknown[];
  governance: string;
  ttl: number | null;
  promotion_policy: string;
  memory_scope: string;
  mode: string;
  visibility_policy: Record<string, string>;
}

/** Operational metadata fields -- visibility governed by policy. */
export interface OperationalMetadata {
  member_count: number | null;
  context_age_secs: number | null;
  creator_did: string | null;
  name: string | null;
  description: string | null;
  economic_policy: string | null;
  tool_count: number | null;
  child_contexts: string[] | null;
}

/** A signed context metadata record published for pre-join inspection (§5.7.2). */
export interface MetadataRecord {
  context_id: string;
  sequence: number;
  signer_did: string;
  timestamp: number;
  structural: StructuralMetadata;
  operational: OperationalMetadata;
  signature: number[];
}
