/**
 * Sync/offline module for the SCP TypeScript SDK.
 *
 * Provides functions for classifying offline durations and querying
 * sync policy parameters.
 *
 * See ADR-029 in `.docs/adrs/phase-6.md`.
 */

import { mapBridgeError } from "./errors.js";
import { getBridge } from "./internal/bridge.js";

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
 * @param lastRelayContact - Unix timestamp (seconds) of last relay contact.
 * @param now - Current Unix timestamp (seconds).
 * @returns `"short"`, `"extended"`, or `"long"`.
 */
export async function classifyOffline(lastRelayContact: number, now: number): Promise<string> {
  try {
    const bridge = await getBridge();
    return bridge.syncClassifyOffline(lastRelayContact, now);
  } catch (error) {
    throw mapBridgeError(error);
  }
}

/**
 * Returns the default sync policy parameters.
 *
 * @returns A `SyncPolicy` with the default parameters.
 */
export async function getSyncPolicy(): Promise<SyncPolicy> {
  try {
    const bridge = await getBridge();
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
