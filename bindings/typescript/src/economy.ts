/**
 * Economic governance module for the SCP TypeScript SDK.
 *
 * Provides cost estimation, budget tracking, antispam velocity checking,
 * and pricing policy evaluation. All monetary values are in the smallest
 * currency unit (e.g., cents for USD, satoshis for BTC).
 *
 * See spec section 19 (Economic Governance) and ADR-033.
 */

import { mapBridgeError } from "./errors";
import { getBridge } from "./internal/bridge";

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
// Cost estimation
// ---------------------------------------------------------------------------

/**
 * Estimates the cost for an action in a context.
 *
 * @param policyJson - Economic policy JSON string (empty/"null" for free contexts).
 * @param actionType - The type of action to estimate.
 * @param metrics - Observable metrics (all optional, default to 0).
 * @returns Estimated cost (smallest currency unit), or -1 on overflow.
 */
export async function estimateCost(
  policyJson: string,
  actionType: PaidActionType,
  metrics?: ObservableMetrics,
): Promise<number> {
  try {
    const bridge = await getBridge();
    const metricsJson = JSON.stringify({
      context_message_rate: metrics?.contextMessageRate ?? 0,
      member_count: metrics?.memberCount ?? 0,
      relay_queue_depth: metrics?.relayQueueDepth ?? 0,
      time_of_day: metrics?.timeOfDay ?? 0,
      sender_velocity: metrics?.senderVelocity ?? 0,
      storage_usage: metrics?.storageUsage ?? 0,
    });
    return bridge.economyEstimateCost(policyJson, actionType, metricsJson);
  } catch (error) {
    throw mapBridgeError(error);
  }
}

/**
 * Checks whether an economic policy requires payment for any action.
 *
 * @param policyJson - Economic policy JSON string.
 * @returns `true` if payment is required.
 */
export async function policyRequiresPayment(policyJson: string): Promise<boolean> {
  try {
    const bridge = await getBridge();
    return bridge.economyPolicyRequiresPayment(policyJson);
  } catch (error) {
    throw mapBridgeError(error);
  }
}

/**
 * Checks whether auto-accept is blocked by the economic policy.
 *
 * @param policyJson - Economic policy JSON string.
 * @returns `true` if auto-accept is blocked.
 */
export async function autoAcceptBlocked(policyJson: string): Promise<boolean> {
  try {
    const bridge = await getBridge();
    return bridge.economyAutoAcceptBlocked(policyJson);
  } catch (error) {
    throw mapBridgeError(error);
  }
}

/**
 * Checks whether an economic policy is locked (immutable).
 *
 * @param policyJson - Economic policy JSON string.
 * @returns `true` if the policy is locked.
 */
export async function checkPolicyLock(policyJson: string): Promise<boolean> {
  try {
    const bridge = await getBridge();
    return bridge.economyCheckPolicyLock(policyJson);
  } catch (error) {
    throw mapBridgeError(error);
  }
}

/**
 * Validates a proposed economic policy change.
 *
 * @param currentJson - Current economic policy JSON string.
 * @param proposedJson - Proposed new policy JSON string.
 * @returns `true` if the change is valid.
 * @throws {ValidationError} If the policy is locked or invalid.
 */
export async function validatePolicyChange(
  currentJson: string,
  proposedJson: string,
): Promise<boolean> {
  try {
    const bridge = await getBridge();
    return bridge.economyValidatePolicyChange(currentJson, proposedJson);
  } catch (error) {
    throw mapBridgeError(error);
  }
}

/**
 * Evaluates a pricing formula against observable metrics.
 *
 * @param formulaJson - Pricing formula JSON string.
 * @param metrics - Observable metrics.
 * @returns Computed cost, or -1 on overflow.
 */
export async function evaluateFormula(
  formulaJson: string,
  metrics?: ObservableMetrics,
): Promise<number> {
  try {
    const bridge = await getBridge();
    const metricsJson = JSON.stringify({
      context_message_rate: metrics?.contextMessageRate ?? 0,
      member_count: metrics?.memberCount ?? 0,
      relay_queue_depth: metrics?.relayQueueDepth ?? 0,
      time_of_day: metrics?.timeOfDay ?? 0,
      sender_velocity: metrics?.senderVelocity ?? 0,
      storage_usage: metrics?.storageUsage ?? 0,
    });
    return bridge.economyEvaluateFormula(formulaJson, metricsJson);
  } catch (error) {
    throw mapBridgeError(error);
  }
}

// ---------------------------------------------------------------------------
// Budget tracking
// ---------------------------------------------------------------------------

/**
 * Queries the remaining budget for a member in a context.
 *
 * @param contextId - The context ID.
 * @param did - The member's DID.
 * @returns Remaining budget (smallest currency unit).
 */
export async function budgetRemaining(contextId: string, did: string): Promise<number> {
  try {
    const bridge = await getBridge();
    return bridge.economyBudgetRemaining(contextId, did);
  } catch (error) {
    throw mapBridgeError(error);
  }
}

/**
 * Grants spending budget to a member.
 *
 * @param contextId - The context ID.
 * @param did - The member's DID.
 * @param amount - Budget to grant (smallest currency unit).
 */
export async function budgetGrant(contextId: string, did: string, amount: number): Promise<void> {
  try {
    const bridge = await getBridge();
    bridge.economyBudgetGrant(contextId, did, amount);
  } catch (error) {
    throw mapBridgeError(error);
  }
}

/**
 * Records a spend against a member's budget.
 *
 * @param contextId - The context ID.
 * @param did - The member's DID.
 * @param amount - Amount spent (smallest currency unit).
 * @throws {ValidationError} If no budget exists or spend exceeds remaining.
 */
export async function budgetRecordSpend(
  contextId: string,
  did: string,
  amount: number,
): Promise<void> {
  try {
    const bridge = await getBridge();
    bridge.economyBudgetRecordSpend(contextId, did, amount);
  } catch (error) {
    throw mapBridgeError(error);
  }
}

// ---------------------------------------------------------------------------
// Antispam velocity tracking
// ---------------------------------------------------------------------------

/**
 * Records a message for antispam velocity tracking.
 *
 * @param contextId - The context ID.
 * @param senderDid - The sender's DID.
 * @param timestamp - Unix timestamp in seconds.
 */
export async function antispamRecord(
  contextId: string,
  senderDid: string,
  timestamp: number,
): Promise<void> {
  try {
    const bridge = await getBridge();
    bridge.economyAntispamRecord(contextId, senderDid, timestamp);
  } catch (error) {
    throw mapBridgeError(error);
  }
}

/**
 * Queries the sender's message velocity within the sliding window.
 *
 * @param contextId - The context ID.
 * @param senderDid - The sender's DID.
 * @param now - Current Unix timestamp in seconds.
 * @returns Number of messages within the window.
 */
export async function antispamVelocity(
  contextId: string,
  senderDid: string,
  now: number,
): Promise<number> {
  try {
    const bridge = await getBridge();
    return bridge.economyAntispamVelocity(contextId, senderDid, now);
  } catch (error) {
    throw mapBridgeError(error);
  }
}

/**
 * Computes the escalated cost for a sender based on antispam velocity.
 *
 * @param contextId - The context ID.
 * @param senderDid - The sender's DID.
 * @param now - Current Unix timestamp in seconds.
 * @param baseCost - Base cost (smallest currency unit).
 * @param thresholds - Array of [velocityThreshold, additionalCost] pairs.
 * @param floor - Optional minimum cost.
 * @param cap - Optional maximum cost.
 * @returns Escalated cost (smallest currency unit).
 */
export async function antispamEscalatedCost(
  contextId: string,
  senderDid: string,
  now: number,
  baseCost: number,
  thresholds: ReadonlyArray<readonly [number, number]>,
  floor?: number,
  cap?: number,
): Promise<number> {
  try {
    const bridge = await getBridge();
    const thresholdsJson = JSON.stringify(thresholds);
    return bridge.economyAntispamEscalatedCost(
      contextId,
      senderDid,
      now,
      baseCost,
      thresholdsJson,
      floor ?? null,
      cap ?? null,
    );
  } catch (error) {
    throw mapBridgeError(error);
  }
}
