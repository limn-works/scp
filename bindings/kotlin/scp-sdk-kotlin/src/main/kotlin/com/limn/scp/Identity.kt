// Identity.kt — Kotlin SDK identity advanced operation wrappers (#428, SCP-RG-019)
//
// Wraps advanced identity UniFFI bridge functions as suspend functions
// with proper dispatcher assignment per ADR-028. Extends the base
// IdentityBridge with agent key management, DID migration, and device
// attestation operations.
//
// Provenance: §3.2 (Key Custody), §3.4 (Linking Identities),
//   ADR-039 (Shared-DID Agent Binding), SCP-RG-019

package com.limn.scp

import com.limn.scp.bridge.CoroutineBridge

/**
 * Native binding functions for advanced identity operations.
 *
 * All methods are blocking JNA calls into Rust and must be dispatched
 * on [kotlinx.coroutines.Dispatchers.IO].
 */
interface IdentityAdvancedBindings {
    /**
     * Creates a new identity with an agent signing key (ADR-039).
     *
     * Combines identity creation with immediate agent key generation
     * in a single operation.
     *
     * @param custody Key custody method: "in_memory" or "platform".
     * @return Opaque identity handle with agent key.
     * @throws BridgeException if custody method is unsupported or creation fails.
     */
    fun identityCreateWithAgentKey(custody: String): Long

    /**
     * Adds an agent signing key to an existing identity (ADR-039).
     *
     * @param identityHandle Handle from identity create or load.
     * @return Updated opaque identity handle with agent key.
     * @throws BridgeException if identity already has an agent key.
     */
    fun identityAddAgentKey(identityHandle: Long): Long

    /**
     * Rotates the agent signing key for an identity (ADR-039).
     *
     * @param identityHandle Handle from identity create or load.
     * @return Updated opaque identity handle with new agent key.
     * @throws BridgeException if identity has no agent key to rotate.
     */
    fun identityRotateAgentKey(identityHandle: Long): Long

    /**
     * Removes the agent signing key from an identity (ADR-039).
     *
     * @param identityHandle Handle from identity create or load.
     * @return Updated opaque identity handle without agent key.
     * @throws BridgeException if identity has no agent key to remove.
     */
    fun identityRemoveAgentKey(identityHandle: Long): Long

    /**
     * Migrates an identity to a new DID.
     *
     * @param identityHandle Handle from identity create or load.
     * @return Updated opaque identity handle with new DID.
     * @throws BridgeException if migration fails.
     */
    fun identityMigrate(identityHandle: Long): Long

    /**
     * Generates a device attestation token for an identity.
     *
     * @param identityHandle Handle from identity create.
     * @return Base64-encoded device attestation token.
     * @throws BridgeException if attestation generation fails.
     */
    fun identityAttestDevice(identityHandle: Long): String

    /**
     * Verifies a device attestation token.
     *
     * @param did The DID string to verify against.
     * @param tokenBase64 Base64-encoded attestation token.
     * @return true if the attestation is valid.
     * @throws BridgeException if token is malformed or verification fails.
     */
    fun identityVerifyDeviceAttestation(
        did: String,
        tokenBase64: String,
    ): Boolean
}

/**
 * Advanced identity operations bridge. Wraps identity FFI calls for
 * agent key management, DID migration, and device attestation.
 *
 * These operations extend the base identity lifecycle with:
 * - **Agent keys** (ADR-039): Add, rotate, remove agent signing keys
 *   for human-agent shared DID patterns.
 * - **Migration**: Move an identity to a new DID while preserving
 *   attestation chains.
 * - **Device attestation** (§9.3): Prove device possession for
 *   sybil resistance.
 *
 * See §3.2 (Key Custody), §3.4 (Linking Identities), ADR-039.
 */
class IdentityAdvancedBridge internal constructor(
    private val bindings: IdentityAdvancedBindings,
    private val bridge: CoroutineBridge,
) {
    /**
     * Creates a new identity with an agent signing key (ADR-039).
     *
     * @param custody Key custody method: "in_memory" or "platform".
     * @return Opaque identity handle with agent key.
     */
    suspend fun createWithAgentKey(custody: String = "in_memory"): Long =
        bridge.ffiCall { bindings.identityCreateWithAgentKey(custody) }

    /**
     * Adds an agent signing key to an existing identity (ADR-039).
     *
     * @param identityHandle Handle from identity create or load.
     * @return Updated opaque identity handle with agent key.
     */
    suspend fun addAgentKey(identityHandle: Long): Long =
        bridge.ffiCall { bindings.identityAddAgentKey(identityHandle) }

    /**
     * Rotates the agent signing key for an identity (ADR-039).
     *
     * @param identityHandle Handle from identity create or load.
     * @return Updated opaque identity handle with new agent key.
     */
    suspend fun rotateAgentKey(identityHandle: Long): Long =
        bridge.ffiCall { bindings.identityRotateAgentKey(identityHandle) }

    /**
     * Removes the agent signing key from an identity (ADR-039).
     *
     * @param identityHandle Handle from identity create or load.
     * @return Updated opaque identity handle without agent key.
     */
    suspend fun removeAgentKey(identityHandle: Long): Long =
        bridge.ffiCall { bindings.identityRemoveAgentKey(identityHandle) }

    /**
     * Migrates an identity to a new DID.
     *
     * @param identityHandle Handle from identity create or load.
     * @return Updated opaque identity handle with new DID.
     */
    suspend fun migrate(identityHandle: Long): Long = bridge.ffiCall { bindings.identityMigrate(identityHandle) }

    /**
     * Generates a device attestation token for an identity.
     *
     * @param identityHandle Handle from identity create.
     * @return Base64-encoded device attestation token.
     */
    suspend fun attestDevice(identityHandle: Long): String =
        bridge.ffiCall { bindings.identityAttestDevice(identityHandle) }

    /**
     * Verifies a device attestation token.
     *
     * @param did The DID string to verify against.
     * @param tokenBase64 Base64-encoded attestation token.
     * @return true if the attestation is valid.
     */
    suspend fun verifyDeviceAttestation(
        did: String,
        tokenBase64: String,
    ): Boolean =
        bridge.ffiCall {
            bindings.identityVerifyDeviceAttestation(did, tokenBase64)
        }
}
