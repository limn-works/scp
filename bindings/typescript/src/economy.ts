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

import { EconomyError } from "./errors";

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
  | "OutletCall"
  | "ContextJoin"
  | "SubscriptionPeriod"
  | "ByteStored";

// ---------------------------------------------------------------------------
// Amount display formatting (ADR-060 SDK display surface)
// ---------------------------------------------------------------------------

/**
 * Number of decimal places for well-known currencies, keyed by uppercase
 * currency code. The SCP protocol does NOT store per-currency decimals — the
 * wire form is always a smallest-unit integer — so this table lives entirely
 * in the SDK for display purposes. The same values are used across every SDK
 * (Python, Swift, Kotlin) for cross-binding consistency.
 */
const KNOWN_CURRENCY_DECIMALS: Readonly<Record<string, number>> = {
  USD: 2,
  EUR: 2,
  GBP: 2,
  BTC: 8,
  SAT: 0,
  SOL: 9,
  USDC: 6,
  ETH: 18,
};

function formatWithDecimals(amount: bigint, decimals: number): string {
  if (amount < 0n) {
    throw new EconomyError(
      `amount must be non-negative, got ${amount.toString()}`,
      "SCP-ECON-12070",
    );
  }
  if (!Number.isInteger(decimals) || decimals < 0 || decimals > 100) {
    throw new EconomyError(
      `decimals must be an integer in 0..=100, got ${decimals}`,
      "SCP-ECON-12070",
    );
  }
  if (decimals === 0) {
    // The amount is already expressed in whole display units — no fraction.
    return amount.toString();
  }
  const divisor = 10n ** BigInt(decimals);
  const whole = amount / divisor;
  const fraction = amount % divisor;
  const fractionStr = fraction.toString().padStart(decimals, "0");
  return `${whole.toString()}.${fractionStr}`;
}

/**
 * Formats a smallest-unit monetary amount as a human-readable decimal string,
 * applying the currency's decimal scale.
 *
 * Purely integer/string arithmetic (no floating point), so amounts far beyond
 * `Number.MAX_SAFE_INTEGER` (2^53) format exactly.
 *
 * @example
 * formatAmount(150n, "USD"); // "1.50"
 * formatAmount(100_000_000n, "BTC"); // "1.00000000"
 * formatAmount(1500n, { decimals: 3 }); // "1.500"
 *
 * @param amount Smallest-unit amount (e.g. cents, satoshis). Must be non-negative.
 * @param currencyOrOptions A known currency code (case-insensitive) or an
 *   explicit `{ decimals }` override for unknown/custom currencies.
 * @throws {EconomyError} If the currency is unknown and no `decimals` override
 *   is supplied, or if `amount`/`decimals` are out of range.
 */
export function formatAmount(amount: bigint, currency: string): string;
export function formatAmount(amount: bigint, options: { decimals: number }): string;
export function formatAmount(
  amount: bigint,
  currencyOrOptions: string | { decimals: number },
): string {
  if (typeof currencyOrOptions === "object") {
    return formatWithDecimals(amount, currencyOrOptions.decimals);
  }
  const decimals = KNOWN_CURRENCY_DECIMALS[currencyOrOptions.toUpperCase()];
  if (decimals === undefined) {
    throw new EconomyError(
      `unknown currency ${JSON.stringify(currencyOrOptions)} has no known decimals; ` +
        "pass an explicit { decimals } override",
      "SCP-ECON-12070",
    );
  }
  return formatWithDecimals(amount, decimals);
}
