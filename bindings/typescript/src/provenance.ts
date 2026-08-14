/**
 * Provenance types for the SCP TypeScript SDK.
 *
 * Defines the wire types for provenance records and discovery-method
 * tagging. The functional entry points
 * (`evaluateProvenanceQuality`, `provenanceAttach`,
 * `provenanceCheckChainDepth`) moved onto the {@link SCP} class in
 * Phase 4 PR 4 (#1549, ADR-048) as
 * `scp.evaluateProvenanceQuality(...)`, `scp.provenanceAttach(...)`,
 * `scp.provenanceCheckChainDepth(...)`. The free-function shims that
 * predated ADR-048 were deleted in the same commit.
 *
 * See spec section 24 (Provenance System) and ADR-019.
 */

import { ValidationError } from "./errors";
import { safeJsonParse } from "./internal/json-utils";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/**
 * Discovery method describing how the data source was found (§24.2.3).
 *
 * - `"OutOfBand"` — no protocol-level discovery path (out-of-band introduction).
 * - `"None"` — backward-compatible alias for `"OutOfBand"`.
 * - `{ SharedContext: string }` — found via shared context membership.
 * - `{ Registry: string }` — found via a discovery registry context.
 */
export type DiscoveryMethod =
  | "OutOfBand"
  | "None"
  | { readonly SharedContext: string }
  | { readonly Registry: string };

/** Provenance record returned by `SCP.provenanceAttach(...)`. */
export interface ProvenanceRecord {
  readonly sourceContext: string;
  readonly sourceType: string;
  readonly chainDepth: number;
  readonly counterparties: readonly string[];
  readonly ageSecs: number;
  readonly memoryScope: string;
  readonly chainPath: readonly string[] | null;
  readonly purpose: string | null;
  /** How the data source was discovered (§24.2.3). */
  readonly discoveryMethod: DiscoveryMethod;
  /**
   * Cost of producing this data in smallest currency units, if any
   * (§24.3.4, §19.6).
   *
   * A `bigint` so the full `u64` range is exact — a JS `number` loses precision
   * above 2^53 (ADR-060 native-integer money surface). On the wire the value
   * crosses as its canonical base-10 decimal string (never a bare number),
   * parsed into a `bigint`.
   */
  readonly paymentAmount: bigint | null;
  /** Payment adapter used (e.g., `"lightning"`, `"stripe"`), if any. */
  readonly paymentAdapter: string | null;
  /** Hex-encoded 32-byte receipt ID for payment verification, if any. */
  readonly paymentReceiptId: string | null;
}

// ---------------------------------------------------------------------------
// Decoding
// ---------------------------------------------------------------------------

/**
 * Decodes the raw snake_case JSON string returned by the native
 * `provenanceAttach` bridge into a typed camelCase {@link ProvenanceRecord}.
 *
 * The wire shape is the bridge's canonical provenance record (identical across
 * the PyO3, NAPI, and UniFFI bridges). This decoder converts it to the SDK's
 * public camelCase surface, and — per ADR-060 — parses the `payment_amount`
 * decimal string into a `bigint` so the full `u64` range survives exactly (a
 * JS `number` would lose precision above 2^53).
 *
 * @param json - The raw JSON string from the native bridge.
 * @returns The decoded, typed provenance record.
 * @throws {ValidationError} If the JSON is malformed (`SCP-VALID-7001`) or a
 *   field has an unexpected type (`SCP-VALID-7005`).
 */
export function decodeProvenanceRecord(json: string): ProvenanceRecord {
  const raw = safeJsonParse(json, "provenanceAttach") as Record<string, unknown>;

  const paymentAmountRaw = raw.payment_amount;
  let paymentAmount: bigint | null;
  if (paymentAmountRaw === null || paymentAmountRaw === undefined) {
    paymentAmount = null;
  } else if (typeof paymentAmountRaw === "string") {
    try {
      // ADR-060: the wire value is a canonical base-10 decimal string.
      paymentAmount = BigInt(paymentAmountRaw);
    } catch {
      throw new ValidationError(
        `provenance payment_amount is not a valid decimal string: ${paymentAmountRaw}`,
        "SCP-VALID-7005",
      );
    }
  } else {
    throw new ValidationError(
      `provenance payment_amount must be a decimal string or null, got ${typeof paymentAmountRaw}`,
      "SCP-VALID-7005",
    );
  }

  const chainPathRaw = raw.chain_path;
  const chainPath =
    chainPathRaw === null || chainPathRaw === undefined
      ? null
      : (chainPathRaw as readonly string[]);

  return {
    sourceContext: raw.source_context as string,
    sourceType: raw.source_type as string,
    chainDepth: raw.chain_depth as number,
    counterparties: (raw.counterparties ?? []) as readonly string[],
    ageSecs: raw.age_secs as number,
    memoryScope: raw.memory_scope as string,
    chainPath,
    purpose: (raw.purpose ?? null) as string | null,
    discoveryMethod: raw.discovery_method as DiscoveryMethod,
    paymentAmount,
    paymentAdapter: (raw.payment_adapter ?? null) as string | null,
    paymentReceiptId: (raw.payment_receipt_id ?? null) as string | null,
  };
}
