/**
 * Trust-aggregation wire types for the SCP TypeScript SDK.
 *
 * This module holds types only. `SCP.evaluateTrust`, `SCP.aggregateTrustInput`,
 * and `SCP.verifyParticipationRequirements` are the entry points, and §7 of
 * ADR-048 ("SCP as First-Class Multi-Instance SDK Object") requires that: a
 * stateful operation — one that reads or mutates the per-instance
 * `BridgeInstance` state — is a method on `SCP` in every SDK, and the
 * per-language free-function latitude the same section grants covers pure
 * helpers only. Trust evaluation dispatches against a context handle, the
 * instance's trust store, and the instance's event log, so it is stateful.
 *
 * A free `evaluateTrust` lived here and delegated to the method until the
 * ADR-059 rebuild. It predated ADR-048, had no caller, and forced the
 * bridge-provenance `evaluateTrust` in `./bridge` to be re-exported under the
 * name `bridgeEvaluateTrust` to avoid the collision.
 *
 * See ADR-059 ("Structured Capability/Trust Validation Across the FFI; SDKs
 * Consume Typed Results, Not Prose") and §7 of ADR-048, both in `.docs/adrs/`,
 * plus §7.2.4 and §7.3 of
 * `.docs/specs/07-trust-validation-and-capabilities.md`.
 */

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
