/**
 * Trust module for the SCP TypeScript SDK.
 *
 * Provides {@link evaluateTrust} and the {@link TrustEvaluation} type for
 * assessing the trustworthiness of a participant within an SCP context, plus
 * the aggregation/participation wire types. Trust evaluation is agent-level —
 * the engine provides validated inputs (capability validation, behavioral
 * records, attestations, challenge results), not trust scores or verdicts.
 *
 * {@link evaluateTrust} is a four-layer model, mirroring the Python SDK's
 * `scp_sdk.trust.evaluate_trust`:
 *
 * 1. **Protocol enforcement** — mechanical pass/fail (UCAN validity,
 *    signatures, capability ceiling, nonce, revocation, expiry).
 * 2. **Behavioral validation** — verified facts from the event log
 *    (participation history, tool usage).
 * 3. **Attestation authenticity** — verified signatures and evidence
 *    freshness from attestations.
 * 4. **Trust evaluation inputs** — endorsements, challenge results, and
 *    consequence structures for agent judgment.
 *
 * The remaining functional entry points (`aggregateTrustInput`,
 * `verifyParticipationRequirements`) live on the {@link SCP} class as
 * `scp.aggregateTrustInput(...)` / `scp.verifyParticipationRequirements(...)`
 * (Phase 4 PR 4, ADR-048).
 *
 * See ADR-017 (Trust Engine), ADR-022 in `.docs/adrs/phase-4.md`, and
 * `.docs/sketch.md` section `SCP.Trust.evaluate`.
 */

import type { Context } from "./context";
import type { SCP } from "./scp";
import type {
  AttestationType,
  AttestorInfo,
  CachedAttestation,
  ChallengeVerification,
  ConsequenceRule,
  EventLogEntry,
  ThresholdRequirement,
} from "./types";

// ---------------------------------------------------------------------------
// Trust aggregation (spec section 7.3)
// ---------------------------------------------------------------------------

/**
 * Input parameters for trust aggregation.
 *
 * Contains all the data needed to compute an aggregated `TrustInput`
 * for a subject DID within a context. Every structured field is typed
 * (ADR-058); the SDK serializes to the serde wire shapes internally.
 */
export interface AggregationInput {
  /** The context to aggregate trust inputs for. */
  contextId: string;
  /** The DID of the subject to evaluate. */
  subjectDid: string;
  /** Full signed event-log entries for the context. */
  events: readonly EventLogEntry[];
  /** 32-byte Merkle root as an array of numbers. */
  merkleRoot: readonly number[];
  /**
   * Consequence rules declared at context creation (ADR-017).
   *
   * Typed {@link ConsequenceRule} array — the SDK serializes to the JSON
   * wire shape before forwarding to the bridge.
   */
  consequenceRules?: readonly ConsequenceRule[];
  /** Typed threshold requirements per attestation type. */
  thresholdRequirements?: Readonly<Partial<Record<AttestationType, ThresholdRequirement>>>;
  /** Typed attestor information per attestation type. */
  attestorSets?: Readonly<Partial<Record<AttestationType, readonly AttestorInfo[]>>>;
  /** Typed cached attestations to pre-populate the trust store. */
  cachedAttestations?: readonly CachedAttestation[];
  /** Typed challenge verifications to pre-populate the trust store. */
  challengeResults?: readonly ChallengeVerification[];
}

/**
 * Aggregated trust input for agent-level evaluation.
 *
 * Contains verified attestations, participation record, challenge results,
 * consequence structure, and threshold counts.
 */
export interface AggregatedTrustInput {
  /** Verified attestations (Layer 3). */
  verified_attestations: readonly Record<string, unknown>[];
  /** Participation record (Layer 2). */
  participation_record: Readonly<Record<string, unknown>>;
  /** Challenge-response results (Layer 3). */
  challenge_results: readonly Record<string, unknown>[];
  /** Consequence rules (Layer 4). */
  consequence_structure: readonly Record<string, unknown>[];
  /** Threshold counts per attestation type: [met, required]. */
  threshold_counts: Readonly<Record<string, readonly [number, number]>>;
}

// ---------------------------------------------------------------------------
// Four-layer trust evaluation (spec §7.2–7.5, ADR-017)
// ---------------------------------------------------------------------------

/**
 * Layer 1: Protocol enforcement results (mechanical, pass/fail).
 *
 * All fields must be `true` for the subject to be considered protocol-
 * compliant. Each field is set independently from the classified UCAN
 * validation failure, mirroring the Python `CapabilityValidation` dataclass.
 */
export interface CapabilityValidation {
  /** UCAN tokens parse and have valid structure. */
  tokensValid: boolean;
  /** All signatures verify against the claimed DIDs. */
  signaturesValid: boolean;
  /** Requested capabilities are within the context's ceiling. */
  withinCeiling: boolean;
  /** Nonce validation passed (step 9: no reuse, not stale, valid format). */
  nonceValid: boolean;
  /** No tokens have been revoked. */
  notRevoked: boolean;
  /** Token time bounds are valid (not expired, not pre-dated, valid range). */
  timeBoundsValid: boolean;
}

/** Layer 2: Behavioral validation (verified facts from the event log). */
export interface BehavioralRecord {
  /** Number of contexts the subject has participated in. */
  contextsParticipated: number;
  /** Total participation duration in seconds. */
  totalDuration: number;
  /** Number of governance actions taken against the subject. */
  governanceActionsAgainst: number;
  /** Tool invocation history as `{ type, count }` records. */
  toolInvocations: readonly { readonly type: string; readonly count: number }[];
  /** Role change history. */
  roleHistory: readonly Record<string, unknown>[];
  /** Endorsement accuracy score (0.0–1.0), if available. */
  endorsementAccuracy?: number | undefined;
}

/** Layer 3: A single verified attestation. */
export interface Attestation {
  /** Attestation type identifier. */
  type: string;
  /** Whether the attestation signature is valid. */
  signatureValid: boolean;
  /** Whether the evidence is valid (if applicable). */
  evidenceValid?: boolean | undefined;
  /** Whether the attestation is within its renewal interval. */
  fresh: boolean;
  /** DID of the attestation issuer. */
  issuer: string;
  /** The claim content. */
  claim: Readonly<Record<string, unknown>>;
}

/** Layer 4: An endorsement from another participant. */
export interface Endorsement {
  /** DID of the endorser. */
  fromDid: string;
  /** The capability being endorsed. */
  capability: string;
  /** Behavioral summary of the endorser. */
  endorserBehavioralRecord: Readonly<Record<string, unknown>>;
}

/** Layer 4: Result of a capability challenge. */
export interface ChallengeResult {
  /** The capability that was challenged. */
  capability: string;
  /** Whether the challenge was passed. */
  passed: boolean;
  /** ISO 8601 timestamp when the challenge was verified. */
  verifiedAt: string;
}

/**
 * Complete trust evaluation result for a subject in a context.
 *
 * Contains the four-layer trust model: protocol enforcement, behavioral
 * validation, attestation authenticity, and trust evaluation inputs. The
 * agent/client decides what to do with this information — the protocol
 * provides the data, not the verdict. Mirrors the Python `TrustEvaluation`
 * dataclass.
 *
 * See `.docs/sketch.md` section `SCP.Trust.evaluate`.
 */
export interface TrustEvaluation {
  /** DID of the evaluated subject. */
  subjectDid: string;
  /** ID of the context the evaluation applies to. */
  contextId: string;
  /**
   * Layer 1: Protocol enforcement (mechanical pass/fail).
   *
   * Layer 1 validates each token's declared capabilities against the token's
   * own `aud`. Binding tokens to `subjectDid` (i.e., ensuring the token's
   * `aud` is `subjectDid`) is the responsibility of the upstream credential
   * issuance flow, not this function.
   */
  capabilityValidation: CapabilityValidation;
  /** Layer 2: Behavioral validation (verified facts), or `null` if unavailable. */
  behavioralRecord: BehavioralRecord | null;
  /** Layer 3: Attestation authenticity (verified signatures). */
  attestations: readonly Attestation[];
  /** Layer 4: Endorsements from other participants. */
  endorsements: readonly Endorsement[];
  /** Layer 4: Challenge results. */
  challengeResults: readonly ChallengeResult[];
  /** Layer 4: Consequence rules defined by the context, or `null`. */
  consequenceStructure: readonly Record<string, unknown>[] | null;
}

// ---------------------------------------------------------------------------
// UCAN error classification for Layer 1 independent checks
// ---------------------------------------------------------------------------
//
// The 11-step validation pipeline (validate.rs):
//   parse(1) → sig(2) → chain(3-5) → key_scope(5a/b) → cap_match(6)
//   → cat_A(6b) → attenuation(7) → ceiling(8) → nonce(9)
//   → revocation(10) → expiry(11)
//
// We classify each UCAN failure into the stage that failed, then infer which
// independent CapabilityValidation fields are known to have passed.

/**
 * Error-message prefixes that indicate an early token-structure failure
 * (pipeline step 1). More specific `malformed token:` sub-patterns are matched
 * before this list so they route to the correct stage.
 */
const TOKEN_PARSE_PREFIXES: readonly string[] = [
  "malformed token:",
  "deserialization failed:",
  "unsupported algorithm:",
  "unsupported UCAN version:",
];

/**
 * Error-message prefixes that indicate a signature/chain integrity failure
 * (pipeline steps 2–7). Includes DID-resolution failures (step 2) that the
 * Rust bridge wraps as `MalformedToken`, and parent-token expiry/revocation in
 * the delegation chain (wrapped as `DelegationChainBroken`), which classify
 * conservatively as `signatures`.
 */
const SIGNATURE_CHAIN_PREFIXES: readonly string[] = [
  "signature verification failed",
  "invalid issuer:",
  "audience mismatch:",
  "delegation chain broken:",
  "circular delegation detected:",
  "attenuation violation:",
  "key scope mismatch:",
  "self-delegation",
  "Category A violation:",
  "malformed token: DID not found",
  "malformed token: invalid DID document",
  "malformed token: network unavailable",
  "malformed token: DID revoked/downgraded",
  "malformed token: verification method",
  "malformed token: unrecognized signing key ID",
  "malformed token: z-base-32 decode failed",
  "malformed token: DID public key must be 32 bytes",
  "malformed token: hex decode failed",
  "malformed token: unsupported DID method",
];

/**
 * Error-message prefixes that indicate a capability ceiling/scope failure
 * (pipeline steps 6, 8). Includes capability-URI parse failures (step 6) that
 * the Rust bridge wraps as `MalformedToken`.
 */
const CAPABILITY_CEILING_PREFIXES: readonly string[] = [
  "capability outside ceiling:",
  "capability not granted:",
  "malformed token: unparseable capability",
];

/** Error-message prefixes for nonce failures (step 9). */
const NONCE_PREFIXES: readonly string[] = [
  "nonce reused:",
  "nonce too old:",
  "nonce from the future:",
  "invalid nonce format:",
  "nonce tracker full:",
];

/** Error-message prefixes that indicate a revocation failure (step 10). */
const REVOCATION_PREFIXES: readonly string[] = ["token revoked:"];

/** Error-message prefixes for expiry/time-bounds failures (step 11). */
const EXPIRY_PREFIXES: readonly string[] = [
  "token expired",
  "token not yet valid",
  "invalid time range:",
  "expiry too far in the future:",
];

/** Pipeline stage a UCAN failure is classified into. */
export type UcanFailureCategory =
  | "token_parse"
  | "signatures"
  | "ceiling"
  | "nonce"
  | "revoked"
  | "expiry"
  | "unknown";

/**
 * Extracts the first declared capability URI from a UCAN JWT's (unverified)
 * payload, for use as the `capability` argument to `scp.ucanValidate`.
 *
 * UCAN tokens are `header.payload.signature` triples; the base64url payload
 * declares granted capabilities in `att[0].with` (the full
 * `scp:ctx:{id}/{resource}:{action}` URI minted by the bridge). Reading the
 * unverified payload here is safe: `scp.ucanValidate` performs the actual
 * cryptographic verification — this only selects which URI to validate
 * against. (`"*"` is NOT a valid `CapabilityUri`; the bridge rejects it with
 * `InvalidCapabilityUri`, which would make Layer 1 unconditionally all-false.)
 *
 * @returns the capability URI, or `null` if the token is malformed or declares
 *   no capabilities (both are treated as a fail-closed all-false verdict).
 * @internal Exported for unit tests.
 * @deprecated Use {@link __extractAllCapabilityUris} instead.
 */
export function __extractCapabilityUri(token: string): string | null {
  let capUri: string;
  try {
    const payloadSegment = token.split(".")[1];
    if (payloadSegment === undefined) return null;
    const rawPayload = JSON.parse(Buffer.from(payloadSegment, "base64url").toString("utf8")) as {
      att?: readonly { with?: string }[];
    };
    const att = Array.isArray(rawPayload?.att) ? rawPayload.att : [];
    capUri = typeof att[0]?.with === "string" ? att[0].with : "";
  } catch {
    return null;
  }
  return capUri === "" ? null : capUri;
}

/**
 * Extracts ALL declared capability URIs from a UCAN JWT's (unverified)
 * payload, for use in {@link evaluateLayer1} to validate every declared
 * capability against the context ceiling.
 *
 * A UCAN with multiple `att` entries could have `att[1]` violating the ceiling
 * while `att[0]` passes, producing a false `withinCeiling: true` verdict if
 * only `att[0]` is checked. This function returns every non-empty `att[i].with`
 * value so {@link evaluateLayer1} can validate ALL declared capabilities.
 *
 * Reading the unverified payload is safe for the same reason as
 * {@link __extractCapabilityUri}: `scp.ucanValidate` performs the actual
 * cryptographic verification — this only extracts which URIs to validate.
 *
 * @returns An array of all declared capability URIs (non-empty strings from
 *   `att[i].with`), or `null` if the token is malformed OR if the resulting
 *   array is empty. Both `null` and `[]` are treated as fail-closed: a token
 *   that declares no valid capabilities is structurally invalid.
 * @internal Exported for unit tests.
 */
export function __extractAllCapabilityUris(token: string): string[] | null {
  try {
    const payloadSegment = token.split(".")[1];
    if (payloadSegment === undefined) return null;
    const rawPayload = JSON.parse(Buffer.from(payloadSegment, "base64url").toString("utf8")) as {
      att?: readonly { with?: string }[];
    };
    const att = Array.isArray(rawPayload?.att) ? rawPayload.att : [];
    const uris = att
      .map((entry) => (typeof entry?.with === "string" ? entry.with : ""))
      .filter((uri) => uri !== "");
    return uris.length > 0 ? uris : null;
  } catch {
    return null;
  }
}

/**
 * Extracts the core `UcanError` Display text from a bridge error message.
 *
 * The Rust bridge formats UCAN errors as:
 *
 *   `[SCP-PERM-3001] permission error: <UcanError Display> — <advice>`
 *
 * This strips the code prefix and trailing advice (separated by an em dash,
 * U+2014) to yield the raw `UcanError` Display text for prefix matching.
 *
 * @internal Exported for unit tests.
 */
export function __extractCoreError(errorMessage: string): string {
  let core = errorMessage;
  const permMarker = "] permission error: ";
  const permIdx = core.indexOf(permMarker);
  if (permIdx !== -1) {
    core = core.slice(permIdx + permMarker.length);
  }
  // Strip the trailing advice suffix (em dash U+2014) added by the Rust
  // From<UcanError> impl.
  const dashIdx = core.indexOf(" — ");
  if (dashIdx !== -1) {
    core = core.slice(0, dashIdx);
  }
  return core;
}

/**
 * Classifies a UCAN validation error into a fine-grained pipeline stage.
 *
 * More specific `malformed token:` sub-patterns are matched before the generic
 * `token_parse` catch-all, so e.g. `malformed token: DID not found` →
 * `signatures` (step 2) and `malformed token: unparseable capability` →
 * `ceiling` (step 6) instead of falling through to `token_parse` (step 1).
 *
 * @internal Exported for unit tests.
 */
export function __classifyUcanError(errorMessage: string): UcanFailureCategory {
  const core = __extractCoreError(errorMessage);

  for (const prefix of SIGNATURE_CHAIN_PREFIXES) {
    if (core.startsWith(prefix)) {
      return "signatures";
    }
  }
  for (const prefix of CAPABILITY_CEILING_PREFIXES) {
    if (core.startsWith(prefix)) {
      return "ceiling";
    }
  }
  for (const prefix of TOKEN_PARSE_PREFIXES) {
    if (core.startsWith(prefix)) {
      return "token_parse";
    }
  }
  for (const prefix of NONCE_PREFIXES) {
    if (core.startsWith(prefix)) {
      return "nonce";
    }
  }
  for (const prefix of REVOCATION_PREFIXES) {
    if (core.startsWith(prefix)) {
      return "revoked";
    }
  }
  for (const prefix of EXPIRY_PREFIXES) {
    if (core.startsWith(prefix)) {
      return "expiry";
    }
  }
  return "unknown";
}

/**
 * Maps each pipeline stage to the set of {@link CapabilityValidation} fields
 * known to have passed when that stage fails, based on the 11-step sequential
 * pipeline. The failing field is NOT in the set (set to `false`); fields after
 * the failure never ran and are also absent. Mirrors Python's `_PASSED_BEFORE`.
 *
 * @internal Exported for unit tests.
 */
export const __PASSED_BEFORE: Readonly<Record<UcanFailureCategory, ReadonlySet<string>>> = {
  token_parse: new Set(),
  signatures: new Set(["tokensValid"]),
  ceiling: new Set(["tokensValid", "signaturesValid"]),
  nonce: new Set(["tokensValid", "signaturesValid", "withinCeiling"]),
  revoked: new Set(["tokensValid", "signaturesValid", "withinCeiling", "nonceValid"]),
  expiry: new Set(["tokensValid", "signaturesValid", "withinCeiling", "nonceValid", "notRevoked"]),
  unknown: new Set(),
};

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

const ALL_LAYER1_FIELDS_FALSE: CapabilityValidation = {
  tokensValid: false,
  signaturesValid: false,
  withinCeiling: false,
  nonceValid: false,
  notRevoked: false,
  timeBoundsValid: false,
};

/**
 * Validates a single capability token against one of its declared URIs.
 *
 * Throws if the error is not a UCAN permission error (non-UCAN errors and
 * handle-affinity misuse propagate to the caller). Returns a narrowed
 * {@link CapabilityValidation} on UCAN failure, or `null` on success.
 *
 * Extracted to reduce cognitive complexity of {@link evaluateLayer1}.
 */
async function validateOneCapUri(
  scp: SCP,
  handle: unknown,
  token: string,
  capUri: string,
): Promise<CapabilityValidation | null> {
  try {
    await scp.ucanValidate(handle, token, capUri);
    return null; // success
  } catch (error) {
    // `scp.ucanValidate` routes through `mapBridgeError`, so this is a typed
    // `ScpError` whose message preserves the original `[SCP-PERM-NNNN]` code
    // prefix verbatim. We classify on that prefix (rather than `instanceof`)
    // to mirror the Python port's code-based dispatch and stay robust to the
    // exact subclass. Any non-UCAN error is a genuine fault and propagates.
    const msg = error instanceof Error ? error.message : String(error);
    if (!/^\[SCP-PERM-\d+\]/.test(msg)) {
      throw error;
    }
    // Re-raise handle-affinity errors — these are caller misuse, not UCAN
    // failures.
    if (/^\[SCP-PERM-3030\]/.test(msg)) {
      throw error;
    }
    const passed = __PASSED_BEFORE[__classifyUcanError(msg)];
    return {
      tokensValid: passed.has("tokensValid"),
      signaturesValid: passed.has("signaturesValid"),
      withinCeiling: passed.has("withinCeiling"),
      nonceValid: passed.has("nonceValid"),
      notRevoked: passed.has("notRevoked"),
      timeBoundsValid: passed.has("timeBoundsValid"),
    };
  }
}

/** Returns `true` when every field in a {@link CapabilityValidation} is `false`. */
function isAllFalse(cv: CapabilityValidation): boolean {
  return (
    !cv.tokensValid &&
    !cv.signaturesValid &&
    !cv.withinCeiling &&
    !cv.nonceValid &&
    !cv.notRevoked &&
    !cv.timeBoundsValid
  );
}

/** Returns `true` when any field in a {@link CapabilityValidation} is `false`. */
function hasAnyFalse(cv: CapabilityValidation): boolean {
  return (
    !cv.tokensValid ||
    !cv.signaturesValid ||
    !cv.withinCeiling ||
    !cv.nonceValid ||
    !cv.notRevoked ||
    !cv.timeBoundsValid
  );
}

/**
 * Runs Layer 1 (protocol enforcement) over the supplied capability tokens.
 *
 * Each token is validated against ALL of its declared capability URIs (see
 * `__extractAllCapabilityUris`). The result starts optimistic (all fields
 * `true`) and is narrowed by the first failure: the failing UCAN pipeline stage
 * is classified (`__classifyUcanError`) and only the stages known to have
 * passed before it (`__PASSED_BEFORE`) stay `true`. A malformed / no-capability
 * token is fail-closed (all-false) and never reaches the bridge.
 *
 * Non-UCAN errors (anything without an `[SCP-PERM-NNNN]` prefix) and
 * handle-affinity misuse (`[SCP-PERM-3030]`) propagate to the caller rather
 * than being absorbed into a false verdict.
 *
 * **What Layer 1 measures**: token self-consistency — is this token
 * structurally valid, cryptographically signed, within the context ceiling,
 * and unexpired/unrevoked? The capability URI validated against is the token's
 * OWN declared capability (from `att[i].with`). Layer 1 does NOT answer
 * "does this token authorize action X?" Callers that need to verify authority
 * for a specific operation must call `scp.ucanValidate(handle, token, uri)`
 * directly with a caller-supplied `uri`.
 */
async function evaluateLayer1(
  scp: SCP,
  handle: unknown,
  capabilityTokens: readonly string[] | undefined,
): Promise<CapabilityValidation> {
  if (capabilityTokens === undefined || capabilityTokens.length === 0) {
    return { ...ALL_LAYER1_FIELDS_FALSE };
  }

  // Start optimistic: assume all pass until a failure proves otherwise.
  let result: CapabilityValidation = {
    tokensValid: true,
    signaturesValid: true,
    withinCeiling: true,
    nonceValid: true,
    notRevoked: true,
    timeBoundsValid: true,
  };

  for (const token of capabilityTokens) {
    const capUris = __extractAllCapabilityUris(token);
    if (capUris === null) {
      // Malformed token or one that declares no capabilities: structurally
      // invalid / grants nothing. Fail-closed; the bridge is not called.
      return { ...ALL_LAYER1_FIELDS_FALSE };
    }
    for (const capUri of capUris) {
      const narrowed = await validateOneCapUri(scp, handle, token, capUri);
      if (narrowed !== null) {
        result = narrowed;
        // Fail-fast: stop checking more URIs on this token once one fails.
        break;
      }
    }
    // If any field was narrowed to false, stop processing further tokens.
    if (hasAnyFalse(result)) {
      return isAllFalse(result) ? { ...ALL_LAYER1_FIELDS_FALSE } : result;
    }
  }

  return result;
}

/**
 * Evaluates the trustworthiness of a participant in a context.
 *
 * Performs the four-layer trust evaluation model (spec §7.2–7.5, ADR-017):
 *
 * 1. **Protocol enforcement** — validates each provided UCAN token via
 *    `scp.ucanValidate`, classifying any failure into the independent Layer 1
 *    {@link CapabilityValidation} fields.
 * 2. **Behavioral validation** — queries the event log via
 *    `scp.eventLogQuery` for the subject's participation history.
 * 3. **Attestation authenticity** — reserved for attestation verification.
 * 4. **Trust evaluation inputs** — reserved for endorsements, challenge
 *    results, and consequence structures.
 *
 * Mirrors the Python SDK's `scp_sdk.trust.evaluate_trust`. Unlike the Python
 * signature (which dispatches by `context_id` string because the PyO3 bridge
 * resolves contexts by ID), this takes a {@link Context} handle: the NAPI/WASM
 * bridge's `ucanValidate`/`eventLogQuery` operations require a context handle,
 * which the TS layer obtains from `scp.contextCreate(...)` / `contextJoin(...)`.
 * The context's `contextId` is recorded on the result.
 *
 * Layer 1 validates each token's declared capabilities against the token's own
 * `aud` (i.e., each `att[i].with`). Binding tokens to `subjectDid` (ensuring
 * the token's `aud` is `subjectDid`) is the responsibility of the upstream
 * credential issuance flow, not this function.
 *
 * @param scp The {@link SCP} instance to dispatch bridge calls on.
 * @param subjectDid The DID of the participant to evaluate.
 * @param context The {@link Context} to evaluate trust within.
 * @param capabilityTokens Optional UCAN token strings to validate.
 * @returns A {@link TrustEvaluation} with all four layers populated.
 */
export async function evaluateTrust(
  scp: SCP,
  subjectDid: string,
  context: Context,
  capabilityTokens?: readonly string[],
): Promise<TrustEvaluation> {
  const handle = context._rawHandle;
  const contextId = context.contextId;

  // Layer 1: validate capability tokens (if any) against the context handle.
  const capabilityValidation = await evaluateLayer1(scp, handle, capabilityTokens);

  // Layer 2: query behavioral record from the event log.
  let behavioralRecord: BehavioralRecord | null = null;
  try {
    // `scp.eventLogQuery` returns the raw NAPI event objects, which carry an
    // `eventType` field (the only field this layer reads). The filter JSON
    // uses snake_case `actor_did`, the key the bridge's filter parser expects.
    const raw = await scp.eventLogQuery(handle, JSON.stringify({ actor_did: subjectDid }));
    const events = raw as readonly { readonly eventType: string }[];
    // This thin facade only computes toolInvocations from the raw event stream.
    // contextsParticipated, totalDuration, and governanceActionsAgainst are not
    // computable from the NAPI event objects returned by eventLogQuery — they
    // require aggregate queries not yet exposed over the bridge. Values are set
    // to 0 (not computed) rather than fabricated. Use the Python SDK for full
    // behavioral analysis, or await a future native TS aggregate endpoint.
    behavioralRecord = {
      contextsParticipated: 0,
      totalDuration: 0,
      governanceActionsAgainst: 0,
      // Each ToolInvoked event becomes one entry with count: 1.
      // No aggregation by tool ID — thin facade over the bridge.
      toolInvocations: events
        .filter((e) => e.eventType === "ToolInvoked")
        .map((e) => ({ type: e.eventType, count: 1 })),
      roleHistory: [],
      endorsementAccuracy: undefined,
    };
  } catch (error) {
    // A missing/empty behavioral record is non-fatal: the subject simply has
    // no event-log history yet. Mirrors the Python port, which catches only
    // `ContextError` here — any other error is a genuine fault that propagates.
    //
    // `scp.eventLogQuery` routes through `mapBridgeError`, so this is a typed
    // `ScpError` whose message preserves the original `[SCP-CTX-NNNN]` code
    // prefix verbatim. We classify on that prefix (rather than `instanceof`) to
    // mirror the Python port's code-based dispatch and stay robust to the exact
    // subclass.
    const msg = error instanceof Error ? error.message : String(error);
    if (!/^\[SCP-CTX-\d+\]/.test(msg)) {
      throw error;
    }
  }

  return {
    subjectDid,
    contextId,
    capabilityValidation,
    behavioralRecord,
    attestations: [],
    endorsements: [],
    challengeResults: [],
    consequenceStructure: null,
  };
}
