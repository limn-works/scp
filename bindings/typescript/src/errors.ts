/**
 * SCP error hierarchy for the TypeScript SDK.
 *
 * All errors thrown by the SDK are instances of `ScpError`. Each subclass maps
 * to one category in the cross-SDK error hierarchy defined in
 * `.docs/standards/sdk-common.md`.
 *
 * Error codes follow the `SCP-{CATEGORY}-{NUMBER}` format:
 *
 * | Category prefix | Range       | Category          |
 * |-----------------|-------------|-------------------|
 * | `SCP-IDENT-`    | 1000-1999   | Identity errors   |
 * | `SCP-CTX-`      | 2000-2999   | Context errors    |
 * | `SCP-PERM-`     | 3000-3999   | Permission errors |
 * | `SCP-CRYPTO-`   | 4000-4999   | Crypto errors     |
 * | `SCP-TRANS-`    | 5000-5999   | Transport errors  |
 * | `SCP-TOOL-`     | 6000-6999   | Tool errors       |
 * | `SCP-VALID-`    | 7000-7999   | Validation errors |
 *
 * See ADR-022 in `.docs/adrs/phase-4.md`.
 */

// ---------------------------------------------------------------------------
// ScpError — root of the error hierarchy
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

  constructor(
    message: string,
    /** Stable error code, e.g. `"SCP-CTX-2001"`. */
    code: string,
  ) {
    super(message);
    this.name = "ScpError";
    this.code = code;
  }
}

// ---------------------------------------------------------------------------
// Subclasses — one per error category
// ---------------------------------------------------------------------------

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
export class PermissionError extends ScpError {
  constructor(message: string, code: string) {
    super(message, code);
    this.name = "PermissionError";
  }
}

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

/** Tool registration, invocation, verification failures. */
export class ToolError extends ScpError {
  constructor(message: string, code: string) {
    super(message, code);
    this.name = "ToolError";
  }
}

/** Input validation, schema, parameter failures. */
export class ValidationError extends ScpError {
  constructor(message: string, code: string) {
    super(message, code);
    this.name = "ValidationError";
  }
}

// ---------------------------------------------------------------------------
// Error parsing — bridge error message to typed ScpError
// ---------------------------------------------------------------------------

/**
 * Error code prefix to ScpError subclass mapping.
 *
 * The napi-rs bridge encodes errors as `"[{code}] {category} error: {message}"`.
 * The WASM bridge encodes errors as `"[{code}] {message}"`.
 * Both include a bracketed code prefix that this function parses.
 */
type ScpErrorConstructor = new (message: string, code: string) => ScpError;

const ERROR_PREFIX_MAP: ReadonlyArray<readonly [string, ScpErrorConstructor]> = [
  ["SCP-IDENT-", IdentityError],
  ["SCP-CTX-", ContextError],
  ["SCP-PERM-", PermissionError],
  ["SCP-CRYPTO-", CryptoError],
  ["SCP-TRANS-", TransportError],
  ["SCP-TOOL-", ToolError],
  ["SCP-VALID-", ValidationError],
];

/**
 * Parses a bridge error message and constructs the appropriate `ScpError`
 * subclass.
 *
 * Bridge errors follow the format `"[SCP-CATEGORY-NUMBER] description"`.
 * If the error message does not match any known prefix, a generic `ScpError`
 * is returned.
 *
 * @param error - The raw error from the bridge layer (Error, string, or unknown).
 * @returns A typed `ScpError` subclass instance.
 */
export function mapBridgeError(error: unknown): ScpError {
  const message = error instanceof Error ? error.message : String(error);

  // Try to extract the bracketed error code: "[SCP-IDENT-1001]"
  const codeMatch = /\[([A-Z]+-[A-Z]+-\d+)\]/.exec(message);
  const code = codeMatch?.[1] ?? "SCP-UNKNOWN-0000";

  for (const [prefix, ErrorClass] of ERROR_PREFIX_MAP) {
    if (code.startsWith(prefix)) {
      return new ErrorClass(message, code);
    }
  }

  return new ScpError(message, code);
}
