/**
 * Provenance module for the SCP TypeScript SDK.
 *
 * Provides functions for evaluating provenance quality, attaching provenance
 * metadata at cross-context boundaries, and checking chain depth limits.
 *
 * See spec section 24 (Provenance System) and ADR-019.
 */

import { mapBridgeError } from "./errors";
import { getBridge } from "./internal/bridge";
import { safeJsonParse } from "./internal/json-utils";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/**
 * Discovery method describing how the data source was found (§24.2.3).
 *
 * - `"None"` — no protocol-level discovery path.
 * - `{ SharedContext: string }` — found via shared context membership.
 * - `{ Registry: string }` — found via a discovery registry context.
 */
export type DiscoveryMethod =
  | "None"
  | { readonly SharedContext: string }
  | { readonly Registry: string };

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
  /** How the data source was discovered (§24.2.3). */
  readonly discoveryMethod: DiscoveryMethod;
  /** Cost of producing this data in atomic units, if any (§24.3.4, §19.6). */
  readonly paymentAmount: number | null;
  /** Payment adapter used (e.g., `"lightning"`, `"stripe"`), if any. */
  readonly paymentAdapter: string | null;
  /** Hex-encoded 32-byte receipt ID for payment verification, if any. */
  readonly paymentReceiptId: string | null;
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
 * @param options - Optional additional provenance fields.
 * @param options.existingChainDepth - Chain depth of existing provenance (if any).
 * @param options.discoveryMethod - How the source was discovered: `"none"`,
 *   `"shared_context:<context_id>"`, or `"registry:<context_id>"`.
 * @param options.purpose - Human-readable purpose of the cross-context data flow.
 * @param options.counterpartyPolicy - `"full"`, `"pseudonymized"`, or `"redacted"`.
 * @returns Parsed provenance record with all 12 spec fields (§24.2.1).
 * @throws {ValidationError} If sourceType or memoryScope is invalid.
 */
export async function provenanceAttach(
  sourceContextId: string,
  sourceType: string,
  memoryScope: string,
  members: string[],
  targetContextId: string,
  options?: {
    existingChainDepth?: number;
    discoveryMethod?: string;
    purpose?: string;
    counterpartyPolicy?: string;
  },
): Promise<ProvenanceRecord> {
  try {
    const bridge = await getBridge();
    const raw = bridge.provenanceAttach(
      sourceContextId,
      sourceType,
      memoryScope,
      members,
      targetContextId,
      options?.existingChainDepth,
      options?.discoveryMethod,
      options?.purpose,
      options?.counterpartyPolicy,
    );
    const parsed = safeJsonParse(raw, "provenanceAttach") as Record<string, unknown>;
    // Map snake_case JSON keys from the bridge to camelCase TypeScript interface.
    const record: ProvenanceRecord = {
      sourceContext: parsed.source_context as string,
      sourceType: parsed.source_type as string,
      chainDepth: parsed.chain_depth as number,
      counterparties: parsed.counterparties as readonly string[],
      ageSecs: (parsed.age_secs as number) ?? 0,
      memoryScope: parsed.memory_scope as string,
      chainPath: (parsed.chain_path as readonly string[]) ?? null,
      purpose: (parsed.purpose as string) ?? null,
      discoveryMethod: (parsed.discovery_method as DiscoveryMethod) ?? "None",
      paymentAmount: (parsed.payment_amount as number) ?? null,
      paymentAdapter: (parsed.payment_adapter as string) ?? null,
      paymentReceiptId: (parsed.payment_receipt_id as string) ?? null,
    };
    return record;
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
