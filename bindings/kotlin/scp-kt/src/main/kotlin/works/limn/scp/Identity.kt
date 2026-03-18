// Identity.kt — Kotlin SDK identity advanced operation wrappers (#428, SCP-RG-019)
//
// Wraps advanced identity UniFFI bridge functions as suspend functions
// with proper dispatcher assignment per ADR-028. Extends the base
// IdentityBridge with agent key management, DID migration, and device
// attestation operations.
//
// Provenance: §3.2 (Key Custody), §3.4 (Linking Identities),
//   ADR-039 (Shared-DID Agent Binding), SCP-RG-019

package works.limn.scp

import works.limn.scp.bridge.CoroutineBridge

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
     * @param custody Key custody method: "in_memory", "platform", or "software".
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

    /**
     * Executes the compromise recovery protocol for a DID.
     *
     * @param did DID string to recover.
     * @param tier Compromise tier: "agent", "active_signing", or "identity_key".
     * @param contextIds Context IDs where the DID is a member.
     * @return JSON string with the recovery result.
     * @throws BridgeException if recovery fails.
     */
    fun identityExecuteRecovery(
        did: String,
        tier: String,
        contextIds: List<String>,
    ): String

    /**
     * Executes the custody migration protocol for a DID.
     *
     * @param did DID string to migrate.
     * @param target Target custody type.
     * @param contextIds Context IDs where the DID is a member.
     * @return JSON string with the migration result.
     * @throws BridgeException if migration fails.
     */
    fun identityExecuteCustodyMigration(
        did: String,
        target: String,
        contextIds: List<String>,
    ): String

    // Identity link attestation (§3.5.1)

    /**
     * Creates an identity link attestation for an external platform identity.
     *
     * @param identityHandle Handle from identity create.
     * @param platform Platform identifier (e.g., "github.com").
     * @param handle Handle on the platform.
     * @param proof Method-specific proof data.
     * @param verificationMethod One of "oauth", "signed_post", "dns_record", "challenge_response".
     * @param platformId Optional immutable platform user ID.
     * @return JSON string of the created attestation.
     */
    fun identityCreateLinkAttestation(
        identityHandle: Long,
        platform: String,
        handle: String,
        proof: String,
        verificationMethod: String,
        platformId: String?,
    ): String

    /**
     * Lists all identity link attestations for a DID.
     *
     * @param did The DID string.
     * @return JSON array string of attestation objects.
     */
    fun identityLinkAttestations(did: String): String

    /**
     * Removes an identity link attestation by its ID.
     *
     * @param did The DID string.
     * @param attestationId The deterministic attestation ID.
     * @return true if found and removed.
     */
    fun identityRemoveLinkAttestation(
        did: String,
        attestationId: String,
    ): Boolean

    /**
     * Verifies the Ed25519 signature on an identity link attestation.
     *
     * @param attestationJson JSON string of the attestation.
     * @param issuerPublicKeyHex Optional hex-encoded Ed25519 public key of the issuer.
     * @return true if valid.
     */
    fun identityVerifyLinkAttestation(
        attestationJson: String,
        issuerPublicKeyHex: String? = null,
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
     * @param custody Key custody method.
     * @return Opaque identity handle with agent key.
     */
    suspend fun createWithAgentKey(custody: CustodyType): Long =
        bridge.ffiCall { bindings.identityCreateWithAgentKey(custody.rawValue) }

    /**
     * Creates a new identity with an agent signing key (ADR-039).
     *
     * Overload accepting a raw string for backward compatibility.
     *
     * @param custody Key custody method: "in_memory", "platform", or "software".
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

    /**
     * Executes the compromise recovery protocol for the given DID.
     *
     * Runs the 6-step recovery protocol from spec section 9.12.
     *
     * @param did The DID string to recover.
     * @param tier Compromise tier: "agent", "active_signing", or "identity_key".
     * @param contextIds Context IDs where this DID is a member.
     * @return JSON string with the recovery result.
     */
    suspend fun executeRecovery(
        did: String,
        tier: String,
        contextIds: List<String> = emptyList(),
    ): String =
        bridge.ffiCall {
            bindings.identityExecuteRecovery(did, tier, contextIds)
        }

    /**
     * Executes the custody migration protocol for the given DID.
     *
     * Runs the 5-step migration protocol from spec section 3.2.1.
     *
     * @param did The DID string to migrate.
     * @param target Target custody type: "platform_managed", "hardware", "software", or "in_memory".
     * @param contextIds Context IDs where this DID is a member.
     * @return JSON string with the migration result.
     */
    suspend fun executeCustodyMigration(
        did: String,
        target: String,
        contextIds: List<String> = emptyList(),
    ): String =
        bridge.ffiCall {
            bindings.identityExecuteCustodyMigration(did, target, contextIds)
        }

    // Identity link attestation (§3.5.1)

    /**
     * Creates an identity link attestation for an external platform identity.
     *
     * @param identityHandle Handle from identity create.
     * @param platform Platform identifier (e.g., "github.com").
     * @param handle Handle on the platform (e.g., "@alice").
     * @param proof Method-specific proof data.
     * @param verificationMethod One of "oauth", "signed_post", "dns_record", "challenge_response".
     * @param platformId Optional immutable platform user ID.
     * @return JSON string of the created attestation.
     */
    suspend fun createLinkAttestation(
        identityHandle: Long,
        platform: String,
        handle: String,
        proof: String,
        verificationMethod: String = "oauth",
        platformId: String? = null,
    ): String =
        bridge.ffiCall {
            bindings.identityCreateLinkAttestation(
                identityHandle,
                platform,
                handle,
                proof,
                verificationMethod,
                platformId,
            )
        }

    /**
     * Lists all identity link attestations for a DID.
     *
     * @param did The DID string.
     * @return JSON array string of attestation objects.
     */
    suspend fun linkAttestations(did: String): String =
        bridge.ffiCall { bindings.identityLinkAttestations(did) }

    /**
     * Removes an identity link attestation by its ID.
     *
     * @param did The DID string.
     * @param attestationId The deterministic attestation ID.
     * @return true if found and removed.
     */
    suspend fun removeLinkAttestation(
        did: String,
        attestationId: String,
    ): Boolean =
        bridge.ffiCall { bindings.identityRemoveLinkAttestation(did, attestationId) }

    /**
     * Verifies the Ed25519 signature on an identity link attestation.
     *
     * @param attestationJson JSON string of the attestation.
     * @param issuerPublicKeyHex Optional hex-encoded Ed25519 public key of the issuer.
     * @return true if valid.
     */
    suspend fun verifyLinkAttestation(
        attestationJson: String,
        issuerPublicKeyHex: String? = null,
    ): Boolean =
        bridge.ffiCall { bindings.identityVerifyLinkAttestation(attestationJson, issuerPublicKeyHex) }
}
