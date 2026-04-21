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
  /** Cost of producing this data in atomic units, if any (§24.3.4, §19.6). */
  readonly paymentAmount: number | null;
  /** Payment adapter used (e.g., `"lightning"`, `"stripe"`), if any. */
  readonly paymentAdapter: string | null;
  /** Hex-encoded 32-byte receipt ID for payment verification, if any. */
  readonly paymentReceiptId: string | null;
}
