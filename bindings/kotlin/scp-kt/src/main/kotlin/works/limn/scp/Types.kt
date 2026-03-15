// Types.kt — Kotlin SDK typed enums for stringly-typed parameters (M5)
//
// Provides type-safe enum classes for custody type, bridge mode, and
// shadow status parameters that were previously raw strings. Each enum
// has a rawValue matching the wire format expected by the FFI bridge.
//
// Provenance: §3.2 (Key Custody), §12.2 (Bridge Connectors), ADR-023

package works.limn.scp

import works.limn.scp.bridge.BridgeException

/**
 * Key custody method for identity key management (spec section 3.2).
 *
 * Determines where cryptographic keys are stored and managed. The
 * [rawValue] property returns the string expected by the FFI bridge.
 *
 * @property rawValue Wire-format string passed to the FFI bridge.
 */
enum class CustodyType(val rawValue: String) {
    /**
     * Platform-native secure storage (Keychain on macOS/iOS, Keystore
     * on Android, credential manager on Windows/Linux). Default.
     */
    PLATFORM("platform"),

    /**
     * Ephemeral in-memory key store, suitable for testing or
     * short-lived agents. Keys are lost on process exit.
     */
    IN_MEMORY("in_memory"),

    /**
     * Software-backed file-based key store with passphrase protection.
     */
    SOFTWARE("software"),
    ;

    companion object {
        /**
         * Parse a raw string into a [CustodyType], or null if unrecognized.
         */
        fun fromRawValue(value: String): CustodyType? = entries.find { it.rawValue == value }
    }
}

/**
 * Bridge operating mode (spec section 12.2).
 *
 * Determines how a bridge connector relays messages between an external
 * platform and an SCP context. The [rawValue] property returns the
 * string expected by the FFI bridge.
 *
 * @property rawValue Wire-format string passed to the FFI bridge.
 */
enum class BridgeMode(val rawValue: String) {
    /** Messages forwarded verbatim. Bridge is a transparent pipe. */
    RELAY("relay"),

    /**
     * Bridge controls external-side identity and can act on behalf
     * of participants.
     */
    PUPPET("puppet"),

    /** Bridge exposes a programmatic API rather than a chat interface. */
    API("api"),

    /** Both SCP and external participants have equal agency. */
    COOPERATIVE("cooperative"),
    ;

    companion object {
        /**
         * Parse a raw string into a [BridgeMode], or null if unrecognized.
         */
        fun fromRawValue(value: String): BridgeMode? = entries.find { it.rawValue == value }
    }
}

/**
 * Shadow identity provenance status (spec section 12.2).
 *
 * Indicates how a bridged participant's identity was established.
 * Used for trust evaluation. The [rawValue] property returns the
 * string expected by the FFI bridge.
 *
 * @property rawValue Wire-format string passed to the FFI bridge.
 */
enum class ShadowStatus(val rawValue: String) {
    /** Identity is a shadow -- no verified link to external identity. */
    SHADOW("shadow"),

    /** External participant has completed identity claim verification. */
    CLAIMED("claimed"),
    ;

    companion object {
        /**
         * Parse a raw string into a [ShadowStatus], or null if unrecognized.
         */
        fun fromRawValue(value: String): ShadowStatus? = entries.find { it.rawValue == value }
    }
}

// ---------------------------------------------------------------------------
// Tool definitions (spec §5.4.1, ADR-010)
// ---------------------------------------------------------------------------

/**
 * Per-invocation cost metadata for a tool (spec section 5.4.1).
 *
 * All monetary values are in the smallest currency unit (e.g., cents
 * for USD, satoshis for BTC).
 *
 * @property amount Cost per invocation in the smallest currency unit.
 * @property currency ISO 4217 or protocol-defined currency code.
 * @property payee DID of the payment recipient. May differ from the tool operator.
 * @property costFormula Optional pricing formula identifier for dynamic pricing (spec section 19.4).
 */
data class ToolCost(
    val amount: Long,
    val currency: String,
    val payee: String,
    val costFormula: String? = null,
)

/**
 * Definition of a tool that can be registered in an SCP context.
 *
 * Provides a typed Kotlin data class for constructing tool definitions
 * that are serialized to JSON for the FFI bridge layer.
 *
 * See ADR-010 (Tool Registry) and spec section 5.4.1.
 *
 * @property name Human-readable tool name.
 * @property description Tool description.
 * @property inputSchemaJson JSON Schema for tool input (as a JSON string).
 * @property outputSchemaJson JSON Schema for tool output (as a JSON string).
 * @property operatorDid DID of the tool operator (responsible party).
 * @property testVectorsJson Test vectors for integrity verification (serialized as JSON string).
 * @property implementationHashHex SHA-256 hash of the implementation binary as hex string.
 * @property cost Optional per-invocation cost metadata (spec section 5.4.1).
 */
data class ToolDefinition(
    val name: String,
    val description: String,
    val inputSchemaJson: String,
    val outputSchemaJson: String,
    val operatorDid: String,
    val testVectorsJson: String? = null,
    val implementationHashHex: String? = null,
    val cost: ToolCost? = null,
) {
    /**
     * Serializes this definition to a JSON string suitable for the FFI bridge.
     */
    fun toJson(): String = buildString {
        append("{")
        append("\"name\":\""); append(name); append("\",")
        append("\"description\":\""); append(description); append("\",")
        append("\"input_schema_json\":"); append(inputSchemaJson); append(",")
        append("\"output_schema_json\":"); append(outputSchemaJson); append(",")
        append("\"operator_did\":\""); append(operatorDid); append("\"")
        if (testVectorsJson != null) {
            append(",\"test_vectors_json\":"); append(testVectorsJson)
        }
        if (implementationHashHex != null) {
            append(",\"implementation_hash\":\""); append(implementationHashHex); append("\"")
        }
        if (cost != null) {
            append(",\"cost\":{")
            append("\"amount\":"); append(cost.amount); append(",")
            append("\"currency\":\""); append(cost.currency); append("\",")
            append("\"payee\":\""); append(cost.payee); append("\"")
            if (cost.costFormula != null) {
                append(",\"cost_formula\":\""); append(cost.costFormula); append("\"")
            }
            append("}")
        }
        append("}")
    }
}

// ---------------------------------------------------------------------------
// App Sandboxing (spec §8.4.1, §8.4.2, issue #595)
// ---------------------------------------------------------------------------

/**
 * Result of validating a capability declaration.
 *
 * See spec sections 8.4.1 and 8.4.2.
 */
data class DeclarationValidationResult(
    /** Whether the validation passed. */
    val valid: Boolean,
    /** Capabilities granted to the app (if valid). */
    val grantedCapabilities: List<String>,
    /** Error message if validation failed, null otherwise. */
    val error: String?,
    /** The DID of the app from the declaration. */
    val appDid: String,
)

/**
 * Capability-restricted context handle (spec §8.4.2).
 *
 * Wraps a context with a whitelist of allowed capabilities. All protocol
 * operations must check the whitelist before proceeding. An app cannot access
 * protocol operations beyond its declared capabilities.
 *
 * Once created, a [ScopedHandle] cannot gain additional capabilities
 * (no escalation guarantee, spec 8.4.2 rule 4).
 *
 * This is intentionally NOT a data class: the auto-generated `copy()` method
 * on data classes would allow callers to create a new handle with escalated
 * capabilities, bypassing the no-escalation guarantee.
 */
class ScopedHandle internal constructor(
    /** The context ID this handle is scoped to. */
    val contextId: String,
    grantedCapabilities: List<String>,
    /** The DID of the app. */
    val appDid: String,
) {
    /** The capabilities granted to this app binding (immutable). */
    val grantedCapabilities: List<String> = grantedCapabilities.toList()

    /**
     * Check whether a given capability is allowed.
     */
    fun hasCapability(capability: String): Boolean {
        if (grantedCapabilities.contains(capability)) return true
        // ToolInvokeAll covers any specific ToolInvoke
        if (capability.startsWith("tool:invoke:") &&
            capability != "tool:invoke:*" &&
            grantedCapabilities.contains("tool:invoke:*")
        ) {
            return true
        }
        return false
    }

    /**
     * Throws [BridgeException] if the capability is not granted.
     */
    fun checkCapability(capability: String) {
        if (!hasCapability(capability)) {
            throw BridgeException(
                "capability denied: $capability not granted to app $appDid",
                "SCP-CTX-2050",
            )
        }
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is ScopedHandle) return false
        return contextId == other.contextId &&
            grantedCapabilities == other.grantedCapabilities &&
            appDid == other.appDid
    }

    override fun hashCode(): Int {
        var result = contextId.hashCode()
        result = 31 * result + grantedCapabilities.hashCode()
        result = 31 * result + appDid.hashCode()
        return result
    }

    override fun toString(): String =
        "ScopedHandle(contextId=$contextId, appDid=$appDid, capabilities=${grantedCapabilities.size})"
}

// ---------------------------------------------------------------------------
// TestVector (spec §7.3.3, ADR-010)
// ---------------------------------------------------------------------------

/**
 * A known input-output pair for tool conformance testing.
 *
 * Mirrors `scp_core::context::tools::TestVector`. Any agent can invoke a
 * tool with test vector inputs and verify the output matches the expected
 * result.
 *
 * Provenance: spec §7.3.3, ADR-010 (phase-2)
 *
 * @property description Human-readable description of what this test vector validates.
 * @property input The serialized input value (JSON string).
 * @property expectedOutput The expected serialized output value (JSON string).
 */
data class TestVector(
    val description: String,
    val input: String,
    val expectedOutput: String,
)
