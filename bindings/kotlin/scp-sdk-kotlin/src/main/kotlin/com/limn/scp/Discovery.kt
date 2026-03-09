// Discovery.kt — Kotlin SDK discovery wrappers (#421, SCP-RG-012)
//
// Wraps discovery-related UniFFI bridge functions as suspend functions
// with proper dispatcher assignment per ADR-028. All FFI calls are
// dispatched on Dispatchers.IO via the CoroutineBridge.
//
// Provenance: §6.2.2 (Protocol-Level Discovery), SCP-RG-012

package com.limn.scp

import com.limn.scp.bridge.CoroutineBridge

/**
 * Native binding functions for discovery operations.
 *
 * All methods are blocking JNA calls into Rust and must be dispatched
 * on [kotlinx.coroutines.Dispatchers.IO].
 */
interface DiscoveryBindings {
    /**
     * Parses an SCP address string into its components.
     *
     * @param address The address string to parse.
     * @return JSON string with parsed address type and fields.
     * @throws BridgeException if the address is malformed.
     */
    fun discoveryParseAddress(address: String): String

    /**
     * Creates a discovery query as a JSON string.
     *
     * @param capabilities Optional capability filter list.
     * @param keywords Optional keyword filter list.
     * @param minHistorySecs Optional minimum history age in seconds.
     * @return JSON-encoded discovery query.
     */
    fun discoveryCreateQuery(
        capabilities: List<String>?,
        keywords: List<String>?,
        minHistorySecs: Long?,
    ): String

    /**
     * Normalizes an address string per SCP addressing rules.
     *
     * Lowercases and trims whitespace.
     *
     * @param address The address string to normalize.
     * @return Normalized address string.
     */
    fun discoveryNormalizeAddress(address: String): String
}

/**
 * Discovery operations bridge. Wraps discovery FFI calls as suspend functions.
 *
 * Provides address parsing, query construction, and normalization for the
 * SCP discovery protocol. See §6.2.2 (Protocol-Level Discovery).
 */
class DiscoveryBridge internal constructor(
    private val bindings: DiscoveryBindings,
    private val bridge: CoroutineBridge,
) {
    /**
     * Parses an SCP address string into its components.
     *
     * Returns a JSON string with parsed address type and fields.
     * Address types: "discovery_handle", "domain_handle",
     * "attestation_handle", "unscoped".
     *
     * @param address The address string to parse.
     * @return JSON string with parsed address components.
     */
    suspend fun parseAddress(address: String): String =
        bridge.ffiCall { bindings.discoveryParseAddress(address) }

    /**
     * Creates a discovery query as a JSON string.
     *
     * @param capabilities Optional list of required capabilities.
     * @param keywords Optional list of search keywords.
     * @param minHistorySecs Optional minimum history age in seconds.
     * @return JSON-encoded discovery query.
     */
    suspend fun createQuery(
        capabilities: List<String>? = null,
        keywords: List<String>? = null,
        minHistorySecs: Long? = null,
    ): String = bridge.ffiCall {
        bindings.discoveryCreateQuery(capabilities, keywords, minHistorySecs)
    }

    /**
     * Normalizes an address string per SCP addressing rules.
     *
     * Lowercases and trims whitespace.
     *
     * @param address The address string to normalize.
     * @return Normalized address string.
     */
    suspend fun normalizeAddress(address: String): String =
        bridge.ffiCall { bindings.discoveryNormalizeAddress(address) }
}
