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
