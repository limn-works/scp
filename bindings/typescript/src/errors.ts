/**
 * SCP error hierarchy for the TypeScript SDK.
 *
 * All errors thrown by the SDK are instances of `ScpError`. Each subclass maps
 * to one category in the cross-SDK error hierarchy defined in
 * `.docs/standards/sdk-common.md`.
 *
 * Error codes follow the `SCP-{CATEGORY}-{NUMBER}` format:
 *
 * | Category prefix | Range       | Category            |
 * |-----------------|-------------|---------------------|
 * | `SCP-IDENT-`    | 1000-1999   | Identity errors     |
 * | `SCP-CTX-`      | 2000-2999   | Context errors      |
 * | `SCP-PERM-`     | 3000-3999   | Permission errors   |
 * | `SCP-CRYPTO-`   | 4000-4999   | Crypto errors       |
 * | `SCP-TRANS-`    | 5000-5999   | Transport errors    |
 * | `SCP-TOOL-`     | 6000-6999   | Outlet errors         |
 * | `SCP-VALID-`    | 7000-7999   | Validation errors   |
 * | `SCP-STORAGE-`  | 8000-8999   | Storage errors      |
 * | `SCP-ATTEST-`   | 9000-9999   | Attestation errors  |
 * | `SCP-MCP-`      | 10000-10999 | MCP errors          |
 * | `SCP-GOV-`      | 11000-11999 | Governance errors   |
 * | `SCP-ECON-`     | 12000-12999 | Economy errors      |
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

/**
 * UCAN capability validation failures.
 *
 * Named `UcanPermissionError` to avoid shadowing the global `PermissionError`
 * in environments that define it (consistent with Python SDK naming convention
 * per `.docs/standards/sdk-common.md`).
 */
export class UcanPermissionError extends ScpError {
  constructor(message: string, code: string) {
    super(message, code);
    this.name = "UcanPermissionError";
  }
}

/**
 * @deprecated Use `UcanPermissionError` instead. This alias exists for
 * backward compatibility during the rename transition.
 */
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

/** Outlet registration, invocation, verification failures. */
export class OutletError extends ScpError {
  constructor(message: string, code: string) {
    super(message, code);
    this.name = "OutletError";
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

/** Governance proposal, vote, or dispatch failures (SCP-GOV-* range). */
export class GovernanceError extends ScpError {
  constructor(message: string, code: string) {
    super(message, code);
    this.name = "GovernanceError";
  }
}

/** Economy / payment / spending UCAN / budget failures (SCP-ECON-* range). */
export class EconomyError extends ScpError {
  constructor(message: string, code: string) {
    super(message, code);
    this.name = "EconomyError";
  }
}

// ---------------------------------------------------------------------------
// Cross-context outlet-invocation saga (§6.2.4 / ADR-049 §3a) terminal errors
// ---------------------------------------------------------------------------
//
// These three subclasses surface the typed terminal space of the §6.2.4
// cross-context outlet-invocation saga. They extend `OutletError` (the saga is a
// outlet operation) and each carries the structured terminal datum the contract
// makes load-bearing as a NAMED, read-only field. The napi bridge collapses the
// typed `SagaError` into a single `Error` whose only payload is the
// `ScpNapiError` Display string; `mapSagaError` reverses that string back into
// the matching class below, preserving the datum.

/**
 * A §6.2.4 saga aborted at a Prepare phase (authorization, freshness, rate
 * limit, co-residency, or a transiently-unavailable participant actor).
 *
 * An `Aborted` terminal may be a PERMANENT rejection the caller must not
 * blindly retry, OR a RETRYABLE transient (rate limit / participant-actor
 * unavailable); the two are distinguished by the `SCP-SAGA-*` code.
 */
export class SagaAbortedError extends OutletError {
  /**
   * Rate-limit back-off hint in milliseconds when the tripped limiter can
   * compute one, or `null` when no precise back-off instant exists. NEVER `0`
   * — a `0` would read as "retry immediately" and re-trip the same hard limit.
   */
  readonly retryAfterMs: number | null;

  constructor(message: string, code = "SCP-SAGA-13067", retryAfterMs: number | null = null) {
    super(message, code);
    this.name = "SagaAbortedError";
    this.retryAfterMs = retryAfterMs;
  }
}

/**
 * A §6.2.4 saga exhausted its Commit retries and may have diverged (a partial
 * commit requiring operator repair).
 */
export class SagaNeedsRepairError extends OutletError {
  /** The durable operator-repair handle for the diverged saga. */
  readonly sagaId: string;

  constructor(message: string, code = "SCP-SAGA-13065", sagaId = "") {
    super(message, code);
    this.name = "SagaNeedsRepairError";
    this.sagaId = sagaId;
  }
}

/**
 * A §6.2.4 saga's participant context set overlapped an in-flight saga
 * (per-participant-context-set gating, §5.15.4).
 */
export class SagaBusyError extends OutletError {
  /** The shared context id that overlapped an in-flight saga. */
  readonly contendedContext: string;

  constructor(message: string, code = "SCP-SAGA-13066", contendedContext = "") {
    super(message, code);
    this.name = "SagaBusyError";
    this.contendedContext = contendedContext;
  }
}

// ---------------------------------------------------------------------------
// Error parsing — bridge error message to typed ScpError
// ---------------------------------------------------------------------------

/**
 * Error code prefix to ScpError subclass mapping.
 *
 * The napi-rs bridge encodes errors as `"[{code}] {category} error: {message}"`,
 * which includes a bracketed code prefix that this function parses.
 */
type ScpErrorConstructor = new (message: string, code: string) => ScpError;

const ERROR_PREFIX_MAP: ReadonlyArray<readonly [string, ScpErrorConstructor]> = [
  ["SCP-IDENT-", IdentityError],
  ["SCP-CTX-", ContextError],
  ["SCP-PERM-", UcanPermissionError],
  ["SCP-CRYPTO-", CryptoError],
  ["SCP-TRANS-", TransportError],
  ["SCP-TOOL-", OutletError],
  ["SCP-VALID-", ValidationError],
  ["SCP-STORAGE-", StorageError],
  ["SCP-ATTEST-", AttestationError],
  ["SCP-MCP-", McpError],
  ["SCP-GOV-", GovernanceError],
  ["SCP-ECON-", EconomyError],
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
  // Pass already-typed SDK errors through untouched. SDK guard layers throw
  // fully-formed `ScpError` subclasses whose stable `.code` is the constructor
  // argument, not embedded in the message text. Re-deriving the code from the
  // message via the
  // bracket regex below cannot find a `[SCP-CAT-NNNN]` token in those messages,
  // so it would fall back to `SCP-UNKNOWN-0000` and downgrade a precise typed
  // error (e.g. `TransportError` → generic `ScpError`). An already-typed error
  // already carries the structured truth; re-mapping can only lose information.
  if (error instanceof ScpError) {
    return error;
  }

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

/**
 * Maps a §6.2.4 cross-context outlet-invocation saga terminal error onto its SDK
 * exception class.
 *
 * The napi bridge collapses the typed `SagaError` terminal into a single
 * `Error` whose only payload is the `ScpNapiError` Display string:
 *
 *   - `[{code}] saga aborted: {message} (retry_after_ms={null|<u64>})`
 *   - `[{code}] saga needs repair: {message} (saga_id={saga_id})`
 *   - `[{code}] saga busy: {message} (contended_context={contended_context})`
 *
 * where `{code}` is a `SCP-SAGA-#####` code. This function reverses the
 * structured terminal datum out of that suffix. The Display suffix is ALWAYS
 * terminal, so the datum regexes are end-anchored (`\s*$`); end-anchored is
 * therefore last-anchored — a decoy `(retry_after_ms=…)` embedded inside
 * `{message}` is non-terminal and cannot match, so only the genuine trailing
 * datum is read.
 *
 * Errors that do not carry a `SCP-SAGA-` code are not saga terminals; they
 * delegate to {@link mapBridgeError} unchanged.
 *
 * @param error - The raw error from the bridge layer (Error, string, or unknown).
 * @returns A typed saga `ScpError` subclass, or whatever `mapBridgeError` yields.
 */
export function mapSagaError(error: unknown): ScpError {
  const message = error instanceof Error ? error.message : String(error);

  // Saga codes are `SCP-SAGA-#####`. Anchor at the start so a `SCP-SAGA-`
  // appearing only inside `{message}` text cannot masquerade as the code.
  const codeMatch = /^\s*\[(SCP-SAGA-\d+)\]/.exec(message);
  const code = codeMatch?.[1];
  if (code === undefined) {
    // Not a saga terminal — defer to the generic bridge error mapping.
    return mapBridgeError(error);
  }

  // Dispatch on the phrase ANCHORED immediately after the `[{code}] ` prefix.
  // The NAPI Display format (crates/scp-ffi/napi/src/error.rs:127-170) fixes the
  // phrase there; a phrase substring appearing only inside {message} is
  // non-terminal and must not win — same anchoring discipline as the
  // start-anchored code and end-anchored datum extraction.
  const phraseMatch = /^\s*\[SCP-SAGA-\d+\] saga (aborted|needs repair|busy):/.exec(message);
  switch (phraseMatch?.[1]) {
    case "aborted": {
      const m = /\(retry_after_ms=(null|\d+)\)\s*$/.exec(message);
      const datum = m?.[1];
      // null / absent ⇒ null, NEVER 0 (a `0` would read as "retry immediately").
      const retryAfterMs = datum === undefined || datum === "null" ? null : Number(datum);
      return new SagaAbortedError(message, code, retryAfterMs);
    }
    case "needs repair": {
      const m = /\(saga_id=([^()]*)\)\s*$/.exec(message);
      return new SagaNeedsRepairError(message, code, m?.[1] ?? "");
    }
    case "busy": {
      const m = /\(contended_context=([^()]*)\)\s*$/.exec(message);
      return new SagaBusyError(message, code, m?.[1] ?? "");
    }
    default:
      // An SCP-SAGA code with an unrecognized phrase → preserve classification
      // as OutletError rather than silently dropping it.
      return new OutletError(message, code);
  }
}
