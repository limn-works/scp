// Types.kt — Kotlin SDK typed enums for stringly-typed parameters (M5)
//
// Provides type-safe enum classes for custody type, bridge mode, and
// shadow status parameters that were previously raw strings. Each enum
// has a rawValue matching the wire format expected by the FFI bridge.
//
// Provenance: §3.2 (Key Custody), §12.2 (Bridge Connectors), ADR-023

package com.limn.scp

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
