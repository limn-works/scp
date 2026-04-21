/**
 * Trust module types for the SCP TypeScript SDK.
 *
 * Defines aggregation/participation wire types. Trust evaluation is
 * agent-level — the engine provides validated inputs (behavioral
 * records, attestations, challenge results), not trust scores.
 *
 * The functional entry points (`aggregateTrustInput`,
 * `verifyParticipationRequirements`, and the TS-side
 * `evaluateTrust` sugar) moved onto the {@link SCP} class in Phase 4
 * PR 4 (#1549, ADR-048) as `scp.aggregateTrustInput(...)` and
 * `scp.verifyParticipationRequirements(...)`. `evaluateTrust` was
 * pure TypeScript sugar over `eventLogQuery` — callers now compose
 * those primitives directly. The free-function shims that predated
 * ADR-048 were deleted in the same commit.
 *
 * See ADR-017 (Trust Engine) and ADR-022 in `.docs/adrs/phase-4.md`.
 */

import type { ConsequenceRule } from "./types";

// ---------------------------------------------------------------------------
// Trust aggregation (spec section 7.3)
// ---------------------------------------------------------------------------

/**
 * Input parameters for trust aggregation.
 *
 * Contains all the data needed to compute an aggregated `TrustInput`
 * for a subject DID within a context.
 */
export interface AggregationInput {
  /** The context to aggregate trust inputs for. */
  contextId: string;
  /** The DID of the subject to evaluate. */
  subjectDid: string;
  /** Event log entries for the context (as plain objects). */
  events: readonly Record<string, unknown>[];
  /** 32-byte Merkle root as an array of numbers. */
  merkleRoot: readonly number[];
  /**
   * Consequence rules declared at context creation (ADR-017, #1531).
   *
   * Typed {@link ConsequenceRule} array — the SDK serializes to the JSON
   * wire shape before forwarding to the bridge.
   */
  consequenceRules?: readonly ConsequenceRule[];
  /** Threshold requirements per attestation type. */
  thresholdRequirements?: Readonly<Record<string, unknown>>;
  /** Attestor information per attestation type. */
  attestorSets?: Readonly<Record<string, unknown>>;
  /** Cached attestations to pre-populate the trust store. */
  cachedAttestations?: readonly Record<string, unknown>[];
  /** Challenge results to pre-populate the trust store. */
  challengeResults?: readonly Record<string, unknown>[];
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
