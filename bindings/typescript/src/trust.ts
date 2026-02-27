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

import type { Context } from "./context.js";
import { mapBridgeError } from "./errors.js";
import { getBridge } from "./internal/bridge.js";
import type { AttestationSummary, BehavioralRecord, TrustEvaluation } from "./types.js";

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
