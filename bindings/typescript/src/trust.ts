/**
 * Trust module for the SCP TypeScript SDK.
 *
 * Holds the trust-aggregation wire types ({@link AggregationInput},
 * {@link AggregatedTrustInput}) and the free-function {@link evaluateTrust}
 * entry point, which mirrors the Python SDK's `scp_sdk.trust.evaluate_trust`.
 *
 * {@link evaluateTrust} delegates to `SCP.evaluateTrust`, the canonical
 * implementation. That method composes the structured trust model of
 * §7.2.4 of `.docs/specs/07-trust-validation-and-capabilities.md`:
 *
 * 1. **Layer 1 — protocol enforcement.** Each capability token goes through the
 *    read-only `SCP.ucanEvaluate` diagnostic, which returns the six per-stage
 *    booleans of `CapabilityValidation` as typed data across the FFI. The SDK
 *    reads those booleans and AND-combines them across the token set. It never
 *    inspects an error message to decide which stage failed, because ADR-059
 *    ("Structured Capability/Trust Validation Across the FFI; SDKs Consume
 *    Typed Results, Not Prose", Decision 3) forbids that.
 * 2. **Layer 2 — behavioral validation.** The shared Rust core computes the
 *    participation facts of §7.3.2 in `Supervisor::participation_record` and
 *    the SDK receives them, so no binding re-aggregates the event log.
 * 3. **Layer 3 — attestation authenticity.** `SCP.evaluateTrust` reports the
 *    subject's attestation count inside the behavioral record; it does not
 *    return the attestation list, because the op takes no attestation set.
 *
 * `scp.aggregateTrustInput(...)` and `scp.verifyParticipationRequirements(...)`
 * gather the Layer-4 trust-evaluation inputs (endorsements, challenge results,
 * consequence structures) that {@link evaluateTrust} does not return.
 *
 * See ADR-059 in `.docs/adrs/phase-2.md`, ADR-017 (Trust Engine), and
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
  TrustEvaluation,
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
// Public API
// ---------------------------------------------------------------------------

/**
 * Evaluates the trustworthiness of a participant in a context.
 *
 * Free-function form of `SCP.evaluateTrust`, matching the Python SDK's
 * `scp_sdk.trust.evaluate_trust`. It resolves the context handle from
 * `context` and forwards every argument unchanged; `SCP.evaluateTrust` holds
 * the whole implementation, so the two entry points cannot report different
 * verdicts for the same inputs.
 *
 * Layer 1 reads the six typed `CapabilityValidation` booleans that
 * `SCP.ucanEvaluate` returns across the FFI. It classifies nothing from an
 * error message, and the diagnostic never records the token's nonce, so
 * calling this function does not consume a token.
 *
 * The Layer-1 diagnostic runs in intrinsic-validity mode: it supplies no
 * challenge capability, so the core skips the invoked-capability grant-match
 * and evaluates the token against every attenuation the token declares.
 * `evaluate_ucan` in `crates/scp-protocol/src/crypto/ucan/validate.rs` parses
 * the full `att` set (`parse_granted_caps`, fail-closed on any unparseable
 * URI), enforces the Category-A rule over every granted capability, checks the
 * context ceiling over every granted capability
 * (`verify_ceiling_compliance`), and re-checks attenuation at every edge of the
 * delegation chain. Spec §7.2.4 and ADR-059 Decision 2a state that omitting the
 * challenge never sets a `CapabilityValidation` field to `true` that another
 * check would set to `false`.
 *
 * Layer 2 receives the participation facts of §7.3.2 from the Rust core. The
 * SDK does not compute or estimate any count.
 *
 * @param scp The {@link SCP} instance to dispatch bridge calls on.
 * @param subjectDid The DID of the participant to evaluate.
 * @param context The {@link Context} to evaluate trust within.
 * @param capabilityTokens Optional UCAN token strings to evaluate for Layer 1.
 * @returns A {@link TrustEvaluation} carrying Layers 1 and 2.
 * @throws {@link "./errors".ScpError} when the bridge rejects an input (a
 *   malformed handle, token, or capability URI) or a provider fails. A
 *   capability outcome is reported through the booleans and never thrown.
 */
export async function evaluateTrust(
  scp: SCP,
  subjectDid: string,
  context: Context,
  capabilityTokens?: readonly string[],
): Promise<TrustEvaluation> {
  return await scp.evaluateTrust(context._rawHandle, subjectDid, capabilityTokens);
}
