// Sync.kt — Kotlin SDK sync/offline wrappers (#421, #528, SCP-RG-012)
//
// Wraps sync-related UniFFI bridge functions as suspend functions
// with proper dispatcher assignment per ADR-028.
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

    /**
     * Classifies an offline duration using custom policy thresholds.
     *
     * @param lastRelayContact Unix timestamp of last relay contact (seconds).
     * @param now Current Unix timestamp (seconds).
     * @param tier1ThresholdSecs Custom tier 1 upper bound in seconds.
     * @param tier2ThresholdSecs Custom tier 2 upper bound in seconds.
     * @return One of "short", "extended", or "long".
     */
    fun syncClassifyOfflineCustom(
        lastRelayContact: Long,
        now: Long,
        tier1ThresholdSecs: Long,
        tier2ThresholdSecs: Long,
    ): String

    /**
     * Returns the default sync policy from the Rust runtime.
     *
     * @return [SyncPolicy] populated from `SyncPolicy::default()` in Rust.
     */
    fun syncGetPolicy(): SyncPolicy
}

/**
 * Sync policy parameters (§23.6).
 *
 * Values are obtained from the Rust runtime via UniFFI `syncGetPolicy()`,
 * matching the Python and TypeScript SDKs.
 *
 * @property tier1ThresholdSecs Tier 1 upper bound in seconds (default 14,400 = 4 hours).
 * @property tier2ThresholdSecs Tier 2 upper bound in seconds (default 604,800 = 7 days).
 * @property gapTimeoutSecs Gap timeout in seconds (default 30).
 * @property reorderBufferCapacity Max buffered messages in the reorder buffer (default 100).
 * @property maxSequentialCommits Max sequential MLS Commits for epoch catch-up (default 100).
 * @property commitProcessTimeoutSecs Per-Commit processing timeout in seconds (default 5).
 * @property senderKeyTimeoutSecs Sender key re-acquisition timeout in seconds (default 60).
 * @property reconnectionDedupWindowSecs Reconnection dedup window in seconds (default 30).
 */
data class SyncPolicy(
    val tier1ThresholdSecs: Long = DEFAULT_TIER_1_THRESHOLD_SECS,
    val tier2ThresholdSecs: Long = DEFAULT_TIER_2_THRESHOLD_SECS,
    val gapTimeoutSecs: Long = DEFAULT_GAP_TIMEOUT_SECS,
    val reorderBufferCapacity: Int = DEFAULT_REORDER_BUFFER_CAPACITY,
    val maxSequentialCommits: Long = DEFAULT_MAX_SEQUENTIAL_COMMITS,
    val commitProcessTimeoutSecs: Long = DEFAULT_COMMIT_PROCESS_TIMEOUT_SECS,
    val senderKeyTimeoutSecs: Long = DEFAULT_SENDER_KEY_TIMEOUT_SECS,
    val reconnectionDedupWindowSecs: Long = DEFAULT_RECONNECTION_DEDUP_WINDOW_SECS,
) {
    companion object {
        /** Default tier 1 threshold: 4 hours (14,400 seconds). */
        const val DEFAULT_TIER_1_THRESHOLD_SECS: Long = 14_400L

        /** Default tier 2 threshold: 7 days (604,800 seconds). */
        const val DEFAULT_TIER_2_THRESHOLD_SECS: Long = 604_800L

        /** Default gap timeout: 30 seconds. */
        const val DEFAULT_GAP_TIMEOUT_SECS: Long = 30L

        /** Default reorder buffer capacity: 100 messages. */
        const val DEFAULT_REORDER_BUFFER_CAPACITY: Int = 100

        /** Default max sequential commits: 100. */
        const val DEFAULT_MAX_SEQUENTIAL_COMMITS: Long = 100L

        /** Default commit process timeout: 5 seconds. */
        const val DEFAULT_COMMIT_PROCESS_TIMEOUT_SECS: Long = 5L

        /** Default sender key timeout: 60 seconds. */
        const val DEFAULT_SENDER_KEY_TIMEOUT_SECS: Long = 60L

        /** Default reconnection dedup window: 30 seconds. */
        const val DEFAULT_RECONNECTION_DEDUP_WINDOW_SECS: Long = 30L
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
     * Classifies an offline duration using custom policy thresholds.
     *
     * @param lastRelayContact Unix timestamp of last relay contact (seconds).
     * @param now Current Unix timestamp (seconds).
     * @param tier1ThresholdSecs Custom tier 1 upper bound in seconds.
     * @param tier2ThresholdSecs Custom tier 2 upper bound in seconds.
     * @return One of "short", "extended", or "long".
     */
    suspend fun classifyOfflineCustom(
        lastRelayContact: Long,
        now: Long,
        tier1ThresholdSecs: Long,
        tier2ThresholdSecs: Long,
    ): String =
        bridge.ffiCall {
            bindings.syncClassifyOfflineCustom(
                lastRelayContact,
                now,
                tier1ThresholdSecs,
                tier2ThresholdSecs,
            )
        }

    /**
     * Returns the sync policy parameters from the Rust runtime.
     *
     * Delegates to UniFFI `syncGetPolicy()` for runtime-configured values.
     *
     * @return [SyncPolicy] with the runtime's sync policy values.
     */
    suspend fun getPolicy(): SyncPolicy =
        bridge.ffiCall { bindings.syncGetPolicy() }
}
