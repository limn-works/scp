/**
 * Economic governance types for the SCP TypeScript SDK.
 *
 * Defines wire types for cost estimation, budget tracking, and
 * antispam velocity. The functional entry points
 * (`estimateCost`, `budgetGrant`, `antispamVelocity`, etc.) moved onto
 * the {@link SCP} class in Phase 4 PR 4 (#1549, ADR-048) as
 * `scp.economyEstimateCost(...)`, `scp.economyBudgetGrant(...)`,
 * `scp.economyAntispamVelocity(...)` and so on. The free-function
 * shims that predated ADR-048 were deleted in the same commit.
 *
 * See spec section 19 (Economic Governance) and ADR-033.
 */

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/** Observable metrics for cost estimation and formula evaluation. */
export interface ObservableMetrics {
  /** Messages per minute in this context. */
  readonly contextMessageRate?: number;
  /** Current member count. */
  readonly memberCount?: number;
  /** Relay-level queue depth. */
  readonly relayQueueDepth?: number;
  /** UTC hour (0-23). */
  readonly timeOfDay?: number;
  /** Sender's messages in sliding window. */
  readonly senderVelocity?: number;
  /** Context storage usage in bytes. */
  readonly storageUsage?: number;
}

/** Paid action type for cost estimation. */
export type PaidActionType =
  | "MessageSend"
  | "ToolInvoke"
  | "ContextJoin"
  | "SubscriptionPeriod"
  | "ByteStored";

// ---------------------------------------------------------------------------
// Payment receipt verification
// ---------------------------------------------------------------------------

/** One entry in the per-receipt verification results array. */
export interface PaymentReceiptVerificationEntry {
  /** Whether the adapter successfully processed this receipt. */
  ok: boolean;
  /** Receipt identifier — present only when ok is true. */
  receipt_id?: string;
  /** Whether the receipt was cryptographically valid — present only when ok is true. */
  valid?: boolean;
  /** Structured verification detail — present only when ok is true. */
  result?: Readonly<Record<string, unknown>>;
  /** Error message — present only when ok is false. */
  error?: string;
}

/**
 * Result of verifying a batch of payment receipts via
 * {@link SCP.economyVerifyPaymentReceipts}.
 *
 * Mirrors the canonical wire shape produced by
 * `verification_results_to_json` in `scp-runtime/economy/receipt.rs`.
 * `all_valid` is `true` iff every entry reached the adapter and was
 * reported valid (vacuously `true` for an empty batch). Inspect `results`
 * for per-receipt detail. An entry with `ok === true` means the adapter
 * responded — NOT that the payment is valid; check `valid` / `all_valid`
 * for actual validity.
 */
export interface PaymentReceiptVerificationResult {
  /**
   * `true` iff every receipt both reached the adapter and the adapter
   * reported it valid. Vacuously `true` for an empty batch.
   */
  all_valid: boolean;
  /** Per-receipt verification outcomes. */
  results: PaymentReceiptVerificationEntry[];
}
