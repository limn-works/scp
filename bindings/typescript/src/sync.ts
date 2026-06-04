/**
 * Sync/offline types for the SCP TypeScript SDK.
 *
 * Defines the sync-policy wire type. The functional entry points
 * (`classifyOffline`, `classifyOfflineCustom`, `getSyncPolicy`)
 * moved onto the {@link SCP} class in Phase 4 PR 4 (#1549, ADR-048)
 * as `scp.syncClassifyOffline(...)`, `scp.syncClassifyOfflineCustom(...)`,
 * `scp.syncGetPolicy()`. The free-function shims that predated ADR-048
 * were deleted in the same commit.
 *
 * See ADR-029 in `.docs/adrs/phase-6.md`.
 */

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
