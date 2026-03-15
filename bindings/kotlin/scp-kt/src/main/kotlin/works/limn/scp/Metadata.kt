// Metadata.kt — Kotlin SDK MetadataRecord and ContextTemplate wrappers (#615)
//
// Wraps metadata and template-related UniFFI bridge functions as suspend
// functions with proper dispatcher assignment per ADR-028.
//
// Provenance: spec §5.7.2 (MetadataRecord), §5.14 (ContextTemplate), #615

package works.limn.scp

import works.limn.scp.bridge.CoroutineBridge

/**
 * Native binding functions for MetadataRecord and ContextTemplate operations.
 *
 * All methods are blocking JNA calls into Rust and must be dispatched
 * on [kotlinx.coroutines.Dispatchers.IO].
 */
interface MetadataBindings {
    /**
     * Serializes a MetadataRecord to a JSON string.
     *
     * @param contextId The context this metadata describes.
     * @param sequence Monotonically increasing sequence number (starts at 1).
     * @param signerDid DID of the admin who signed this record.
     * @param timestamp Unix timestamp in milliseconds.
     * @param structuralJson Structural metadata as JSON.
     * @param operationalJson Operational metadata as JSON.
     * @param signatureHex Ed25519 signature as hex (128 hex chars).
     * @return JSON string of the MetadataRecord.
     * @throws BridgeException if any input is malformed.
     */
    fun metadataRecordToJson(
        contextId: String,
        sequence: ULong,
        signerDid: String,
        timestamp: ULong,
        structuralJson: String,
        operationalJson: String,
        signatureHex: String,
    ): String

    /**
     * Deserializes a MetadataRecord from a JSON string.
     *
     * @param jsonStr JSON string of a MetadataRecord.
     * @return Validated and re-serialized JSON string.
     * @throws BridgeException if the JSON is malformed.
     */
    fun metadataRecordFromJson(jsonStr: String): String

    /**
     * Returns the canonical ContextParams for a given template ID as JSON.
     *
     * @param templateId One of the well-known template identifiers.
     * @return JSON string of the canonical ContextParams.
     * @throws BridgeException if the template ID is not recognized.
     */
    fun templateGetParams(templateId: String): String

    /**
     * Validates that ContextParams match their template definition.
     *
     * @param paramsJson ContextParams as a JSON string.
     * @return `null` on success, or a string error message on failure.
     * @throws BridgeException if the JSON is malformed.
     */
    fun validateAgainstTemplate(paramsJson: String): String?

    /**
     * Validates cross-field invariants for ContextParams.
     *
     * @param paramsJson ContextParams as a JSON string.
     * @return `null` on success, or a string error message on failure.
     * @throws BridgeException if the JSON is malformed.
     */
    fun validateContextParams(paramsJson: String): String?
}

/**
 * Kotlin SDK wrapper for MetadataRecord and ContextTemplate operations.
 *
 * All operations delegate through the coroutine bridge to UniFFI-generated
 * Rust functions. See spec §5.7.2 (MetadataRecord) and §5.14 (ContextTemplate).
 */
class MetadataBridge internal constructor(
    private val bindings: MetadataBindings,
    private val bridge: CoroutineBridge,
) {

    /**
     * Serializes a MetadataRecord to a JSON string.
     *
     * @see MetadataBindings.metadataRecordToJson
     */
    suspend fun metadataRecordToJson(
        contextId: String,
        sequence: ULong,
        signerDid: String,
        timestamp: ULong,
        structuralJson: String,
        operationalJson: String,
        signatureHex: String,
    ): String = bridge.ffiCall {
        bindings.metadataRecordToJson(
            contextId, sequence, signerDid, timestamp,
            structuralJson, operationalJson, signatureHex,
        )
    }

    /**
     * Deserializes a MetadataRecord from a JSON string.
     *
     * @see MetadataBindings.metadataRecordFromJson
     */
    suspend fun metadataRecordFromJson(jsonStr: String): String = bridge.ffiCall {
        bindings.metadataRecordFromJson(jsonStr)
    }

    /**
     * Returns the canonical ContextParams for a given template ID as JSON.
     *
     * @see MetadataBindings.templateGetParams
     */
    suspend fun templateGetParams(templateId: String): String = bridge.ffiCall {
        bindings.templateGetParams(templateId)
    }

    /**
     * Validates that ContextParams match their template definition.
     *
     * @see MetadataBindings.validateAgainstTemplate
     */
    suspend fun validateAgainstTemplate(paramsJson: String): String? = bridge.ffiCall {
        bindings.validateAgainstTemplate(paramsJson)
    }

    /**
     * Validates cross-field invariants for ContextParams.
     *
     * @see MetadataBindings.validateContextParams
     */
    suspend fun validateContextParams(paramsJson: String): String? = bridge.ffiCall {
        bindings.validateContextParams(paramsJson)
    }
}
