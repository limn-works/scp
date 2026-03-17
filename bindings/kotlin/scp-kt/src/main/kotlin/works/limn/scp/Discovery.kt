// Discovery.kt — Kotlin SDK discovery wrappers (#421, SCP-RG-012)
//
// Wraps discovery-related UniFFI bridge functions as suspend functions
// with proper dispatcher assignment per ADR-028. All FFI calls are
// dispatched on Dispatchers.IO via the CoroutineBridge.
//
// Provenance: §6.2.2 (Protocol-Level Discovery), SCP-RG-012

package works.limn.scp

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonPrimitive
import works.limn.scp.bridge.CoroutineBridge

/**
 * Native binding functions for discovery operations.
 *
 * All methods are blocking JNA calls into Rust and must be dispatched
 * on [kotlinx.coroutines.Dispatchers.IO].
 */
@Suppress("TooManyFunctions")
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

    /**
     * Discovers contexts from a DID string or `scp://` URI.
     *
     * Detects whether the query is a DID or an `scp://` URI and delegates
     * to the appropriate core discovery function.
     *
     * @param query A DID string (e.g., `"did:dht:z6Mk..."`) or an `scp://` URI.
     * @return JSON string with an array of discovery results, each containing
     *   `context_id`, `relay_urls`, `publisher_did`, `discovery_source`,
     *   `mode`, and `metadata_summary`.
     * @throws BridgeException if DID resolution or URI parsing fails.
     */
    fun contextDiscover(query: String): String

    // Petname operations (§22.4)

    /** Sets a petname for a DID. */
    fun petnameSet(ownerDid: String, targetDid: String, name: String)

    /** Removes a petname from a DID. */
    fun petnameRemove(ownerDid: String, targetDid: String)

    /** Sets a petname for a context. */
    fun petnameSetContext(ownerDid: String, contextId: String, name: String)

    /** Removes a petname from a context. */
    fun petnameRemoveContext(ownerDid: String, contextId: String)

    /** Resolves a petname to DIDs. Returns a JSON array of DID strings. */
    fun petnameResolveDid(ownerDid: String, name: String): String

    /** Resolves a petname to context IDs. Returns a JSON array of strings. */
    fun petnameResolveContext(ownerDid: String, name: String): String

    /** Gets the petname for a DID. Returns null if none. */
    fun petnameGetForDid(ownerDid: String, targetDid: String): String?

    /** Gets the petname for a context. Returns null if none. */
    fun petnameGetForContext(ownerDid: String, contextId: String): String?

    // Handle registry operations (§22.3.1)

    /** Registers a handle in a discovery context. Returns JSON result. */
    @Suppress("LongParameterList")
    fun handleRegister(
        discoveryContextId: String,
        handle: String,
        targetJson: String,
        registrantDid: String,
        description: String?,
        tags: List<String>?,
    ): String

    /** Looks up a handle in a discovery context. Returns JSON result. */
    fun handleLookup(
        discoveryContextId: String,
        handle: String,
        typeFilter: String?,
    ): String

    /** Deregisters a handle from a discovery context. Returns JSON result. */
    fun handleDeregister(
        discoveryContextId: String,
        handle: String,
        did: String,
    ): String

    // Scope registry operations (§22.3.5, ADR-043)

    /** Registers a scope name in a scope registry. Returns JSON result. */
    @Suppress("LongParameterList")
    fun scopeRegister(
        scopeContextId: String,
        name: String,
        targetContextId: String,
        relayUrls: List<String>,
        registrantDid: String,
        description: String?,
        tags: List<String>?,
    ): String

    /** Looks up a scope name in a scope registry. Returns JSON result. */
    fun scopeLookup(
        scopeContextId: String,
        name: String,
    ): String

    /** Deregisters a scope name from a scope registry. Returns JSON result. */
    fun scopeDeregister(
        scopeContextId: String,
        name: String,
        did: String,
    ): String

    // Address resolution (§22.8)

    /** Resolves an address via multi-path resolution. Returns JSON array. */
    fun addressResolve(
        ownerDid: String,
        address: String,
        knownContextsJson: String?,
    ): String
}

/**
 * Discovery operations bridge. Wraps discovery FFI calls as suspend functions.
 *
 * Provides address parsing, query construction, and normalization for the
 * SCP discovery protocol. See §6.2.2 (Protocol-Level Discovery).
 */
@Suppress("TooManyFunctions")
class DiscoveryBridge internal constructor(
    private val bindings: DiscoveryBindings,
    private val bridge: CoroutineBridge,
) {
    /**
     * Parses an SCP address string into its components.
     *
     * Returns a JSON string with parsed address type and fields.
     * Address types: "DiscoveryHandle", "DomainHandle",
     * "AttestationHandle", "Unscoped".
     *
     * @param address The address string to parse.
     * @return JSON string with parsed address components.
     */
    suspend fun parseAddress(address: String): String = bridge.ffiCall { bindings.discoveryParseAddress(address) }

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
    ): String =
        bridge.ffiCall {
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

    /**
     * Discovers contexts from a DID string or `scp://` URI.
     *
     * Detects whether the query is a DID or an `scp://` URI and delegates
     * to the appropriate core discovery function.
     *
     * @param query A DID string (e.g., `"did:dht:z6Mk..."`) or an `scp://` URI.
     * @return JSON string with an array of discovery results.
     */
    suspend fun discover(query: String): String =
        bridge.ffiCall { bindings.contextDiscover(query) }

    // Petname operations (§22.4)

    /**
     * Assigns a petname to a DID within the owner's local namespace.
     *
     * @param ownerDid DID of the identity that owns this petname map.
     * @param targetDid DID to assign the petname to.
     * @param name The petname string.
     */
    suspend fun petnameSet(ownerDid: String, targetDid: String, name: String) {
        bridge.ffiCall { bindings.petnameSet(ownerDid, targetDid, name) }
    }

    /**
     * Removes a petname from a DID.
     *
     * @param ownerDid DID of the identity that owns this petname map.
     * @param targetDid DID to remove the petname from.
     */
    suspend fun petnameRemove(ownerDid: String, targetDid: String) {
        bridge.ffiCall { bindings.petnameRemove(ownerDid, targetDid) }
    }

    /**
     * Assigns a petname to a context within the owner's local namespace.
     *
     * @param ownerDid DID of the identity that owns this petname map.
     * @param contextId Context ID to assign the petname to.
     * @param name The petname string.
     */
    suspend fun petnameSetContext(ownerDid: String, contextId: String, name: String) {
        bridge.ffiCall { bindings.petnameSetContext(ownerDid, contextId, name) }
    }

    /**
     * Removes a petname from a context.
     *
     * @param ownerDid DID of the identity that owns this petname map.
     * @param contextId Context ID to remove the petname from.
     */
    suspend fun petnameRemoveContext(ownerDid: String, contextId: String) {
        bridge.ffiCall { bindings.petnameRemoveContext(ownerDid, contextId) }
    }

    /**
     * Resolves a petname to a list of DIDs.
     *
     * @param ownerDid DID of the identity that owns this petname map.
     * @param name The petname to resolve.
     * @return List of DID strings.
     */
    suspend fun petnameResolveDid(ownerDid: String, name: String): List<String> {
        val json = bridge.ffiCall { bindings.petnameResolveDid(ownerDid, name) }
        return parseJsonStringArray(json)
    }

    /**
     * Resolves a petname to a list of context IDs.
     *
     * @param ownerDid DID of the identity that owns this petname map.
     * @param name The petname to resolve.
     * @return List of context ID strings.
     */
    suspend fun petnameResolveContext(ownerDid: String, name: String): List<String> {
        val json = bridge.ffiCall { bindings.petnameResolveContext(ownerDid, name) }
        return parseJsonStringArray(json)
    }

    /**
     * Gets the petname assigned to a DID, if any.
     *
     * @param ownerDid DID of the identity that owns this petname map.
     * @param targetDid DID to look up.
     * @return The petname string, or null if no petname is assigned.
     */
    suspend fun petnameGetForDid(ownerDid: String, targetDid: String): String? =
        bridge.ffiCall { bindings.petnameGetForDid(ownerDid, targetDid) }

    /**
     * Gets the petname assigned to a context, if any.
     *
     * @param ownerDid DID of the identity that owns this petname map.
     * @param contextId Context ID to look up.
     * @return The petname string, or null if no petname is assigned.
     */
    suspend fun petnameGetForContext(ownerDid: String, contextId: String): String? =
        bridge.ffiCall { bindings.petnameGetForContext(ownerDid, contextId) }

    // Handle registry operations (§22.3.1)

    /**
     * Registers a handle in a discovery context.
     *
     * @param discoveryContextId ID of the discovery context.
     * @param handle The handle string to register.
     * @param targetJson JSON describing the target.
     * @param registrantDid DID of the registrant.
     * @param description Optional human-readable description.
     * @param tags Optional list of tag strings.
     * @return JSON string with the registration result.
     */
    @Suppress("LongParameterList")
    suspend fun handleRegister(
        discoveryContextId: String,
        handle: String,
        targetJson: String,
        registrantDid: String,
        description: String? = null,
        tags: List<String>? = null,
    ): String =
        bridge.ffiCall {
            bindings.handleRegister(
                discoveryContextId, handle, targetJson, registrantDid, description, tags,
            )
        }

    /**
     * Looks up a handle in a discovery context.
     *
     * @param discoveryContextId ID of the discovery context.
     * @param handle The handle string to look up.
     * @param typeFilter Optional filter: "identity" or "context".
     * @return JSON string with a results array of matching entries.
     */
    suspend fun handleLookup(
        discoveryContextId: String,
        handle: String,
        typeFilter: String? = null,
    ): String =
        bridge.ffiCall {
            bindings.handleLookup(discoveryContextId, handle, typeFilter)
        }

    /**
     * Deregisters a handle from a discovery context.
     *
     * @param discoveryContextId ID of the discovery context.
     * @param handle The handle string to deregister.
     * @param did DID of the registrant requesting deregistration.
     * @return JSON string with a removed boolean.
     */
    suspend fun handleDeregister(
        discoveryContextId: String,
        handle: String,
        did: String,
    ): String =
        bridge.ffiCall {
            bindings.handleDeregister(discoveryContextId, handle, did)
        }

    // Scope registry operations (§22.3.5, ADR-043)

    /**
     * Registers a scope name in a scope registry.
     *
     * @param scopeContextId ID of the context hosting the scope registry.
     * @param name Scope name to register.
     * @param targetContextId Context ID the scope name resolves to.
     * @param relayUrls Relay URLs for the target context.
     * @param registrantDid DID of the registrant.
     * @param description Optional human-readable description.
     * @param tags Optional list of tag strings.
     * @return JSON string with the registration result.
     */
    @Suppress("LongParameterList")
    suspend fun scopeRegister(
        scopeContextId: String,
        name: String,
        targetContextId: String,
        relayUrls: List<String>,
        registrantDid: String,
        description: String? = null,
        tags: List<String>? = null,
    ): String =
        bridge.ffiCall {
            bindings.scopeRegister(
                scopeContextId, name, targetContextId, relayUrls, registrantDid, description, tags,
            )
        }

    /**
     * Looks up a scope name in a scope registry.
     *
     * @param scopeContextId ID of the context hosting the scope registry.
     * @param name The scope name to look up.
     * @return JSON string with a results array of matching scope entries.
     */
    suspend fun scopeLookup(
        scopeContextId: String,
        name: String,
    ): String =
        bridge.ffiCall {
            bindings.scopeLookup(scopeContextId, name)
        }

    /**
     * Deregisters a scope name from a scope registry.
     *
     * @param scopeContextId ID of the context hosting the scope registry.
     * @param name The scope name to deregister.
     * @param did DID of the registrant requesting deregistration.
     * @return JSON string with a removed boolean.
     */
    suspend fun scopeDeregister(
        scopeContextId: String,
        name: String,
        did: String,
    ): String =
        bridge.ffiCall {
            bindings.scopeDeregister(scopeContextId, name, did)
        }

    // Address resolution (§22.8)

    /**
     * Resolves a human-readable address via multi-path resolution pipeline.
     *
     * @param ownerDid DID of the identity whose petname map to consult.
     * @param address The address string to resolve.
     * @param knownContextsJson Optional JSON object mapping context IDs to names.
     * @return List of parsed AddressResolution JSON elements.
     */
    suspend fun addressResolve(
        ownerDid: String,
        address: String,
        knownContextsJson: String? = null,
    ): List<JsonElement> {
        val json = bridge.ffiCall {
            bindings.addressResolve(ownerDid, address, knownContextsJson)
        }
        return Json.parseToJsonElement(json).jsonArray.toList()
    }
}

/** Parses a JSON string containing an array of strings into a `List<String>`. */
private fun parseJsonStringArray(json: String): List<String> =
    Json.parseToJsonElement(json).jsonArray.map { it.jsonPrimitive.content }
