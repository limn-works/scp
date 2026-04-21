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
