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

/** Per-receipt entry in a {@link PaymentReceiptVerificationResult}. */
export interface PaymentReceiptVerificationEntry {
  /** Opaque identifier for this receipt, as supplied by the caller. */
  receipt_id: string;
  /** Whether the payment adapter accepted the receipt as valid. */
  valid: boolean;
  /**
   * Human-readable reason for rejection, present when `valid` is `false`.
   * Absent when the receipt is valid.
   */
  reason?: string;
}

/**
 * Result of verifying a batch of payment receipts via
 * {@link SCP.economyVerifyPaymentReceipts}.
 *
 * Mirrors the Python SDK return shape for `economy_verify_payment_receipts`.
 * `ok` indicates that the adapter responded for all receipts; `all_valid`
 * is `true` iff every entry reached the adapter and was reported valid (and
 * is vacuously `true` for an empty batch). Inspect `results` for per-receipt
 * detail. `ok === true` means the adapter *responded* — NOT that the payment
 * is valid; check `valid` / `all_valid` for validity.
 */
export interface PaymentReceiptVerificationResult {
  /** `true` if the adapter responded for every receipt in the batch. */
  ok: boolean;
  /**
   * `true` iff every receipt both reached the adapter (`ok === true`) and
   * the adapter reported it valid (`result.valid === true`). Vacuously `true`
   * for an empty batch.
   */
  all_valid: boolean;
  /** Per-receipt verification outcomes. */
  results: PaymentReceiptVerificationEntry[];
}
