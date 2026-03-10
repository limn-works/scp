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
