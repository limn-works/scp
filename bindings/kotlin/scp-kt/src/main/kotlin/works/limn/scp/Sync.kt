// Sync.kt — Kotlin SDK sync/offline wrappers (#421, SCP-RG-012)
//
// Wraps sync-related UniFFI bridge functions as suspend functions
// with proper dispatcher assignment per ADR-028. Pure Kotlin operations
// (getSyncPolicy) run on Dispatchers.Default via cpuBound.
//
// Provenance: §23.6 (Conflict Resolution), §23.11-23.13, SCP-RG-012

package works.limn.scp

import works.limn.scp.bridge.CoroutineBridge

/**
 * Native binding functions for sync/offline operations.
 *
 * All methods are blocking JNA calls into Rust and must be dispatched
 * on [kotlinx.coroutines.Dispatchers.IO].
 */
interface SyncBindings {
    /**
     * Classifies an offline duration into the appropriate recovery tier.
     *
     * @param lastRelayContact Unix timestamp of last relay contact (seconds).
     * @param now Current Unix timestamp (seconds).
     * @return One of "short", "extended", or "long".
     */
    fun syncClassifyOffline(
        lastRelayContact: Long,
        now: Long,
    ): String
}

/**
 * Default sync policy parameters (§23.6).
 *
 * **Important:** These are compile-time defaults matching `SyncPolicy::default()` in Rust.
 * Unlike the Python and TypeScript SDKs, which call bridge functions (`sync_get_policy`)
 * to obtain runtime-configured values, the UniFFI bridge does not currently expose a
 * `syncGetPolicy` function. Values returned here will diverge from runtime-configured
 * policies if the node operator overrides defaults. When a UniFFI `syncGetPolicy` export
 * is added, `SyncBridge.getPolicy()` should be updated to call it.
 *
 * @property tier1ThresholdSecs Threshold between "short" and "extended" tiers (seconds).
 * @property tier2ThresholdSecs Threshold between "extended" and "long" tiers (seconds).
 * @property conflictResolution Conflict resolution strategy name.
 * @property maxRetries Maximum retry count for sync operations.
 */
data class SyncPolicy(
    val tier1ThresholdSecs: Long = DEFAULT_TIER_1_THRESHOLD_SECS,
    val tier2ThresholdSecs: Long = DEFAULT_TIER_2_THRESHOLD_SECS,
    val conflictResolution: String = "first_writer_wins",
    val maxRetries: Int = DEFAULT_MAX_RETRIES,
) {
    companion object {
        /** Default tier 1 threshold: 4 hours (14,400 seconds). */
        const val DEFAULT_TIER_1_THRESHOLD_SECS: Long = 14_400L

        /** Default tier 2 threshold: 7 days (604,800 seconds). */
        const val DEFAULT_TIER_2_THRESHOLD_SECS: Long = 604_800L

        /** Default maximum retries for sync operations. */
        const val DEFAULT_MAX_RETRIES: Int = 3
    }
}

/**
 * Sync operations bridge. Wraps sync FFI calls as suspend functions.
 *
 * Handles offline classification and sync policy retrieval.
 * See §23 (Sync and Offline Strategy).
 */
class SyncBridge internal constructor(
    private val bindings: SyncBindings,
    private val bridge: CoroutineBridge,
) {
    /**
     * Classifies an offline duration into the appropriate recovery tier.
     *
     * @param lastRelayContact Unix timestamp of last relay contact (seconds).
     * @param now Current Unix timestamp (seconds).
     * @return One of "short", "extended", or "long".
     */
    suspend fun classifyOffline(
        lastRelayContact: Long,
        now: Long,
    ): String =
        bridge.ffiCall {
            bindings.syncClassifyOffline(lastRelayContact, now)
        }

    /**
     * Returns the default sync policy parameters.
     *
     * **Note:** This returns compile-time defaults, not runtime-configured values.
     * The UniFFI bridge does not yet expose a `syncGetPolicy` function, so this
     * cannot delegate to the Rust core like the Python and TypeScript SDKs do.
     * Values may diverge from operator-configured policies at runtime.
     *
     * Pure Kotlin operation — no FFI call.
     *
     * @return Default [SyncPolicy] with protocol-standard thresholds.
     */
    suspend fun getPolicy(): SyncPolicy = bridge.cpuBound { SyncPolicy() }
}
