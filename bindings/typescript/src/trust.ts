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
import { getBridge, getBridgeSync } from "./internal/bridge";
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
// Participation verification (spec §7.3.2.1, SCP-BA-004)
// ---------------------------------------------------------------------------

/**
 * Converts a `ParticipationProfile` to the snake_case JSON representation
 * expected by the Rust bridge (matching `scp-core`'s serde format).
 */
function profileToBridgeJson(profile: ParticipationProfile): Record<string, unknown> {
  return {
    subject_did: profile.subjectDid,
    participation_duration_secs: profile.participationDurationSecs,
    governance_actions_against: profile.governanceActionsAgainst,
    governance_actions_by: profile.governanceActionsBy,
    tool_invocation_count: profile.toolInvocationCount,
    context_creation_count: profile.contextCreationCount,
    role_progression_count: profile.roleProgressionCount,
    attestation_count: profile.attestationCount,
    updated_at: profile.updatedAt,
    event_log_root: profile.eventLogRoot,
    signer_public_key: profile.signerPublicKey,
    signature: profile.signature,
  };
}

/**
 * Converts a `RequireParticipation` to the JSON representation expected by
 * the Rust bridge (matching `scp-core`'s serde format).
 */
function requirementToBridgeJson(requirement: RequireParticipation): Record<string, unknown> {
  return {
    fact: requirement.fact,
    threshold: requirement.threshold,
    max_age_secs: requirement.maxAgeSecs,
    min_contexts: requirement.minContexts,
  };
}

/**
 * Verifies participation profiles against admission requirements.
 *
 * Delegates to the Rust bridge (`scp-core` via NAPI, or the WASM local
 * re-implementation), which performs the full verification including:
 *
 * 1. Freshness/staleness checking (`maxAgeSecs`).
 * 2. Distinct signer counting (`minContexts`).
 * 3. Threshold operator semantics (`ParticipationThreshold`).
 * 4. Signature verification (NAPI only; WASM defers to WebCrypto).
 *
 * Success is indicated by returning without exception. Verification
 * failures throw an error with diagnostic details.
 *
 * @param requirements - The participation requirements to verify against.
 * @param profiles - The participation profiles to evaluate.
 * @throws {ValidationError} If verification fails (with diagnostic details).
 * @throws {ScpError} If the bridge module is not available.
 */
export function verifyParticipationRequirements(
  requirements: readonly RequireParticipation[],
  profiles: readonly ParticipationProfile[],
): void {
  const bridge = getBridgeSync();

  const profileJson = JSON.stringify(profiles.map(profileToBridgeJson));
  const requirementsJson = JSON.stringify(requirements.map(requirementToBridgeJson));

  try {
    bridge.verifyParticipationRequirements(profileJson, requirementsJson);
  } catch (error) {
    throw mapBridgeError(error);
  }
}
