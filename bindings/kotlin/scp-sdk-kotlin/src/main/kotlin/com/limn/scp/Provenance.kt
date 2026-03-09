// Provenance.kt — Kotlin SDK provenance wrappers (#421, SCP-RG-012)
//
// Wraps provenance-related UniFFI bridge functions as suspend functions
// with proper dispatcher assignment per ADR-028. All FFI calls are
// dispatched on Dispatchers.IO via the CoroutineBridge.
//
// Provenance: ADR-019 (Provenance Attachment), §24.3, SCP-RG-012

package com.limn.scp

import com.limn.scp.bridge.CoroutineBridge

/**
 * Parameters for attaching provenance metadata to cross-context data flow.
 *
 * @property sourceContextId Source context ID.
 * @property sourceType One of "persistent", "ephemeral", or "summary".
 * @property memoryScope One of "full", "summary", or "ephemeral".
 * @property members List of member DID strings from the source context.
 * @property targetContextId Target context ID.
 * @property existingChainDepth Existing chain depth, or null for first hop.
 */
data class ProvenanceAttachParams(
    val sourceContextId: String,
    val sourceType: String,
    val memoryScope: String,
    val members: List<String>,
    val targetContextId: String,
    val existingChainDepth: Byte? = null,
)

/**
 * Native binding functions for provenance operations.
 *
 * All methods are blocking JNA calls into Rust and must be dispatched
 * on [kotlinx.coroutines.Dispatchers.IO].
 */
interface ProvenanceBindings {
    /**
     * Evaluates provenance quality tier for data with given attributes.
     *
     * @param sourceContext Source context ID, or null if no source context.
     * @param sourceType One of "persistent", "ephemeral", or "summary".
     * @param contextState One of "active", "closed_with_summary_verified",
     *   "closed_with_summary_unverified", "closed_ephemeral", or "unknown".
     * @param counterparties List of counterparty DID strings.
     * @return Quality tier as an integer (higher = better).
     * @throws BridgeException if sourceType or contextState are invalid.
     */
    fun evaluateProvenanceQuality(
        sourceContext: String?,
        sourceType: String,
        contextState: String,
        counterparties: List<String>,
    ): Int

    /**
     * Attaches provenance metadata when data crosses a context boundary.
     *
     * @param params Provenance attachment parameters.
     * @return JSON string with the attached provenance record.
     * @throws BridgeException if sourceType or memoryScope are invalid.
     */
    fun provenanceAttach(params: ProvenanceAttachParams): String

    /**
     * Checks whether the provenance chain depth is within the allowed limit.
     *
     * @param chainDepth Current chain depth.
     * @param maxDepth Maximum allowed depth, or null for default.
     * @return true if the chain depth is within the limit.
     */
    fun provenanceCheckChainDepth(
        chainDepth: Byte,
        maxDepth: Byte?,
    ): Boolean
}

/**
 * Provenance operations bridge. Wraps provenance FFI calls as suspend functions.
 *
 * Provenance tracks the origin and chain of custody of data as it moves
 * between contexts. See ADR-019 and §24.3.
 */
class ProvenanceBridge internal constructor(
    private val bindings: ProvenanceBindings,
    private val bridge: CoroutineBridge,
) {
    /**
     * Evaluates provenance quality tier for data with given attributes.
     *
     * @param sourceContext Source context ID, or null if no source context.
     * @param sourceType One of "persistent", "ephemeral", or "summary".
     * @param contextState One of "active", "closed_with_summary_verified",
     *   "closed_with_summary_unverified", "closed_ephemeral", or "unknown".
     * @param counterparties List of counterparty DID strings.
     * @return Quality tier as an integer (higher = better).
     */
    suspend fun evaluateQuality(
        sourceContext: String?,
        sourceType: String,
        contextState: String,
        counterparties: List<String> = emptyList(),
    ): Int = bridge.ffiCall {
        bindings.evaluateProvenanceQuality(
            sourceContext,
            sourceType,
            contextState,
            counterparties,
        )
    }

    /**
     * Attaches provenance metadata when data crosses a context boundary.
     *
     * @param params Provenance attachment parameters.
     * @return JSON string with the attached provenance record.
     */
    suspend fun attach(params: ProvenanceAttachParams): String =
        bridge.ffiCall { bindings.provenanceAttach(params) }

    /**
     * Checks whether the provenance chain depth is within the allowed limit.
     *
     * @param chainDepth Current chain depth.
     * @param maxDepth Maximum allowed depth, or null for default.
     * @return true if the chain depth is within the limit.
     */
    suspend fun checkChainDepth(
        chainDepth: Byte,
        maxDepth: Byte? = null,
    ): Boolean = bridge.ffiCall {
        bindings.provenanceCheckChainDepth(chainDepth, maxDepth)
    }
}
