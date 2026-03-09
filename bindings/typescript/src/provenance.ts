/**
 * Provenance module for the SCP TypeScript SDK.
 *
 * Provides functions for evaluating provenance quality, attaching provenance
 * metadata at cross-context boundaries, and checking chain depth limits.
 *
 * See spec section 24 (Provenance System) and ADR-019.
 */

import { mapBridgeError } from "./errors.js";
import { getBridge } from "./internal/bridge.js";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/** Provenance record returned by {@link provenanceAttach}. */
export interface ProvenanceRecord {
  readonly sourceContext: string;
  readonly sourceType: string;
  readonly chainDepth: number;
  readonly counterparties: readonly string[];
  readonly ageSecs: number;
  readonly memoryScope: string;
  readonly chainPath: string | null;
  readonly purpose: string | null;
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Evaluates the provenance quality tier for a data provenance record.
 *
 * @param options - Evaluation parameters.
 * @returns Quality tier as an integer (0-3).
 * @throws {ValidationError} If sourceType or contextState is invalid.
 */
export async function evaluateProvenanceQuality(options: {
  sourceContext?: string;
  sourceType?: string;
  contextState?: string;
  counterparties?: string[];
}): Promise<number> {
  try {
    const bridge = await getBridge();
    return await bridge.evaluateProvenanceQuality(
      options.sourceContext,
      options.sourceType ?? "persistent",
      options.contextState ?? "unknown",
      options.counterparties,
    );
  } catch (error) {
    throw mapBridgeError(error);
  }
}

/**
 * Attaches provenance metadata when data crosses a context boundary.
 *
 * @param sourceContextId - ID of the source context.
 * @param sourceType - `"persistent"`, `"ephemeral"`, or `"summary"`.
 * @param memoryScope - `"full"`, `"summary"`, or `"ephemeral"`.
 * @param members - Member DID strings from the source context.
 * @param targetContextId - ID of the target context.
 * @param existingChainDepth - Chain depth of existing provenance (if any).
 * @returns JSON string with the provenance record.
 * @throws {ValidationError} If sourceType or memoryScope is invalid.
 */
export async function provenanceAttach(
  sourceContextId: string,
  sourceType: string,
  memoryScope: string,
  members: string[],
  targetContextId: string,
  existingChainDepth?: number,
): Promise<string> {
  try {
    const bridge = await getBridge();
    return bridge.provenanceAttach(
      sourceContextId,
      sourceType,
      memoryScope,
      members,
      targetContextId,
      existingChainDepth,
    );
  } catch (error) {
    throw mapBridgeError(error);
  }
}

/**
 * Checks whether a provenance chain depth is within the allowed limit.
 *
 * @param chainDepth - The chain depth to check.
 * @param maxDepth - Optional custom max depth (default: 3).
 * @returns `true` if within limit, `false` otherwise.
 */
export async function provenanceCheckChainDepth(
  chainDepth: number,
  maxDepth?: number,
): Promise<boolean> {
  try {
    const bridge = await getBridge();
    return bridge.provenanceCheckChainDepth(chainDepth, maxDepth);
  } catch (error) {
    throw mapBridgeError(error);
  }
}
