// Sync.kt — Kotlin SDK sync/offline wrappers (#421, SCP-RG-012)
//
// Wraps sync-related UniFFI bridge functions as suspend functions
// with proper dispatcher assignment per ADR-028. Pure Kotlin operations
// (getSyncPolicy) run on Dispatchers.Default via cpuBound.
//
// Provenance: §23.6 (Conflict Resolution), §23.11-23.13, SCP-RG-012

package com.limn.scp

import com.limn.scp.bridge.CoroutineBridge

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
 * Exposes the protocol-default thresholds for offline tier classification
 * and conflict resolution. These are compile-time constants matching the
 * Rust `SyncPolicy::default()` values.
 *
 * @property tier1ThresholdSecs Threshold between "short" and "extended" tiers (seconds).
 * @property tier2ThresholdSecs Threshold between "extended" and "long" tiers (seconds).
 * @property conflictResolution Conflict resolution strategy name.
 * @property maxRetries Maximum retry count for sync operations.
 */
data class SyncPolicy(
    val tier1ThresholdSecs: Long = DEFAULT_TIER_1_THRESHOLD_SECS,
    val tier2ThresholdSecs: Long = DEFAULT_TIER_2_THRESHOLD_SECS,
    val conflictResolution: String = "last_writer_wins",
    val maxRetries: Int = DEFAULT_MAX_RETRIES,
) {
    companion object {
        /** Default tier 1 threshold: 5 minutes (300 seconds). */
        const val DEFAULT_TIER_1_THRESHOLD_SECS: Long = 300L

        /** Default tier 2 threshold: 24 hours (86400 seconds). */
        const val DEFAULT_TIER_2_THRESHOLD_SECS: Long = 86_400L

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
     * Pure Kotlin operation — no FFI call. Returns the protocol-default
     * thresholds for offline tier classification.
     *
     * @return Default [SyncPolicy] with protocol-standard thresholds.
     */
    suspend fun getPolicy(): SyncPolicy = bridge.cpuBound { SyncPolicy() }
}
