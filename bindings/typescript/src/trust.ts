/**
 * Trust module for the SCP TypeScript SDK.
 *
 * Trust evaluation is agent-level — the engine provides validated inputs
 * (behavioral records, attestations, challenge results), not trust scores.
 * Each agent's evaluation logic consumes these inputs according to its own
 * criteria.
 *
 * See ADR-017 (Trust Engine) and ADR-022 in `.docs/adrs/phase-4.md`.
 */

import type { Context } from "./context";
import { mapBridgeError } from "./errors";
import { getBridge } from "./internal/bridge";
import type {
  AttestationSummary,
  BehavioralRecord,
  ParticipationProfile,
  RequireParticipation,
  TrustEvaluation,
} from "./types";

// ---------------------------------------------------------------------------
// Trust evaluation
// ---------------------------------------------------------------------------

/**
 * Evaluates trust for a participant in a context.
 *
 * Computes a behavioral record from the context's event log and collects
 * attestation summaries. The returned `TrustEvaluation` contains verifiable
 * facts — the calling agent decides what trust level these facts warrant.
 *
 * @param ctx - The context to evaluate trust in.
 * @param subjectDid - The DID of the participant to evaluate.
 * @returns A `TrustEvaluation` with behavioral record and attestations.
 * @throws {ContextError} If the context is not active or evaluation fails.
 */
export async function evaluateTrust(ctx: Context, subjectDid: string): Promise<TrustEvaluation> {
  try {
    const bridge = await getBridge();

    // Query the event log for the subject's participation events.
    const events = await bridge.eventLogQuery(ctx._handle, {
      actorDid: subjectDid,
    });

    // Compute behavioral record from events.
    const behavioralRecord: BehavioralRecord = {
      participationCount: events.length,
      participationDurationSeconds: 0,
      toolInvocations: {},
      governanceActionsBy: 0,
      governanceActionsAgainst: 0,
    };

    // Accumulate tool invocations and governance actions from events.
    for (const event of events) {
      if (event.eventType === "ToolInvoked") {
        const toolId = (event.payload as Readonly<Record<string, unknown>>).toolId as
          | string
          | undefined;
        if (toolId !== undefined) {
          const current = behavioralRecord.toolInvocations[toolId];
          (behavioralRecord.toolInvocations as Record<string, number>)[toolId] = (current ?? 0) + 1;
        }
      }

      if (event.eventType === "GovernanceAction") {
        (behavioralRecord as { governanceActionsBy: number }).governanceActionsBy += 1;
      }
    }

    // Attestations are fetched from the trust engine — currently empty.
    const attestations: readonly AttestationSummary[] = [];

    return {
      subjectDid,
      contextId: ctx.contextId,
      behavioralRecord,
      attestations,
    };
  } catch (error) {
    throw mapBridgeError(error);
  }
}

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
  /** Consequence rules declared at context creation. */
  consequenceRules?: readonly Record<string, unknown>[];
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

/**
 * Aggregates all trust engine layers into a single TrustInput for
 * agent-level evaluation.
 *
 * Combines participation records, attestation verification, challenge
 * results, consequence structure, and threshold counts. The returned
 * object contains verifiable facts -- agents apply their own criteria.
 *
 * @param input - The aggregation input parameters.
 * @returns An `AggregatedTrustInput` with all trust layers.
 * @throws {Error} If inputs are malformed or aggregation fails.
 */
export async function aggregateTrustInput(input: AggregationInput): Promise<AggregatedTrustInput> {
  try {
    const bridge = await getBridge();

    const resultJson = await bridge.aggregateTrustInput(
      input.contextId,
      input.subjectDid,
      JSON.stringify(input.events),
      JSON.stringify(input.merkleRoot),
      JSON.stringify(input.consequenceRules ?? []),
      JSON.stringify(input.thresholdRequirements ?? {}),
      JSON.stringify(input.attestorSets ?? {}),
      JSON.stringify(input.cachedAttestations ?? []),
      JSON.stringify(input.challengeResults ?? []),
    );

    return JSON.parse(resultJson) as AggregatedTrustInput;
  } catch (error) {
    throw mapBridgeError(error);
  }
}

// ---------------------------------------------------------------------------
// Participation verification (spec section 9.3, SCP-BA-004)
// ---------------------------------------------------------------------------

/**
 * Verifies whether a participant meets participation requirements.
 *
 * Evaluates the participant's profile against the requirement's thresholds.
 * This is a pure function — no bridge call needed.
 *
 * @param requirement - The participation requirement to verify against.
 * @param profile - The participant's participation profile.
 * @returns `true` if requirements are met, `false` otherwise.
 */
export function verifyParticipationRequirements(
  requirement: RequireParticipation,
  profile: ParticipationProfile,
): boolean {
  if (requirement.thresholds.length === 0) {
    return true;
  }

  const results: boolean[] = [];
  for (const threshold of requirement.thresholds) {
    const matchingFacts = profile.facts.filter((f) => f.factType === threshold.factType);
    if (matchingFacts.length === 0) {
      results.push(false);
      continue;
    }

    const totalValue = matchingFacts.reduce((sum, f) => sum + f.value, 0);
    const meetsMin = totalValue >= threshold.minimum;
    const meetsMax = threshold.maximum === undefined || totalValue <= threshold.maximum;
    results.push(meetsMin && meetsMax);
  }

  return requirement.requireAll ? results.every(Boolean) : results.some(Boolean);
}
