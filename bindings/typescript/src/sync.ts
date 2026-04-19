/**
 * Sync/offline module for the SCP TypeScript SDK.
 *
 * Provides functions for classifying offline durations and querying
 * sync policy parameters.
 *
 * See ADR-029 in `.docs/adrs/phase-6.md`.
 */

import { mapBridgeError } from "./errors";
import { getBridge } from "./internal/bridge";
import type { SCP } from "./scp";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/** Sync policy parameters. */
export interface SyncPolicy {
  readonly tier1ThresholdSecs: number;
  readonly tier2ThresholdSecs: number;
  readonly gapTimeoutSecs: number;
  readonly reorderBufferCapacity: number;
  readonly maxSequentialCommits: number;
  readonly commitProcessTimeoutSecs: number;
  readonly senderKeyTimeoutSecs: number;
  readonly reconnectionDedupWindowSecs: number;
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Classifies an offline duration into the appropriate recovery tier.
 *
 * @param scp - The `SCP` wrapper whose bridge instance should own this call.
 * @param lastRelayContact - Unix timestamp (seconds) of last relay contact.
 * @param now - Current Unix timestamp (seconds).
 * @returns `"short"`, `"extended"`, or `"long"`.
 */
export async function classifyOffline(
  scp: SCP,
  lastRelayContact: number,
  now: number,
): Promise<string> {
  try {
    const bridge = await getBridge(scp);
    return bridge.syncClassifyOffline(lastRelayContact, now);
  } catch (error) {
    throw mapBridgeError(error);
  }
}

/**
 * Classifies an offline duration using custom policy thresholds.
 *
 * @param scp - The `SCP` wrapper whose bridge instance should own this call.
 * @param lastRelayContact - Unix timestamp (seconds) of last relay contact.
 * @param now - Current Unix timestamp (seconds).
 * @param tier1ThresholdSecs - Custom upper bound for short offline tier (seconds).
 * @param tier2ThresholdSecs - Custom upper bound for extended offline tier (seconds).
 * @returns `"short"`, `"extended"`, or `"long"`.
 */
export async function classifyOfflineCustom(
  scp: SCP,
  lastRelayContact: number,
  now: number,
  tier1ThresholdSecs: number,
  tier2ThresholdSecs: number,
): Promise<string> {
  try {
    const bridge = await getBridge(scp);
    return bridge.syncClassifyOfflineCustom(
      lastRelayContact,
      now,
      tier1ThresholdSecs,
      tier2ThresholdSecs,
    );
  } catch (error) {
    throw mapBridgeError(error);
  }
}

/**
 * Returns the default sync policy parameters.
 *
 * @param scp - The `SCP` wrapper whose bridge instance should own this call.
 * @returns A `SyncPolicy` with the default parameters.
 */
export async function getSyncPolicy(scp: SCP): Promise<SyncPolicy> {
  try {
    const bridge = await getBridge(scp);
    const raw = bridge.syncGetPolicy();
    return {
      tier1ThresholdSecs: raw.tier_1_threshold_secs,
      tier2ThresholdSecs: raw.tier_2_threshold_secs,
      gapTimeoutSecs: raw.gap_timeout_secs,
      reorderBufferCapacity: raw.reorder_buffer_capacity,
      maxSequentialCommits: raw.max_sequential_commits,
      commitProcessTimeoutSecs: raw.commit_process_timeout_secs,
      senderKeyTimeoutSecs: raw.sender_key_timeout_secs,
      reconnectionDedupWindowSecs: raw.reconnection_dedup_window_secs,
    };
  } catch (error) {
    throw mapBridgeError(error);
  }
}
