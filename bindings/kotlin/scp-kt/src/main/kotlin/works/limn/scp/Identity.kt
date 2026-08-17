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

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.long
import kotlinx.serialization.json.longOrNull
import works.limn.scp.bridge.BridgeException
import works.limn.scp.bridge.CoroutineBridge

/**
 * Native binding functions for advanced identity operations.
 *
 * All methods are blocking JNA calls into Rust and must be dispatched
 * on [kotlinx.coroutines.Dispatchers.IO].
 *
 * **Handle type convention:** All `identityHandle` parameters use [Long]
 * (not [Int]). This is the correct UniFFI/JNA handle type — UniFFI
 * generates Rust `Arc<T>` handles as 64-bit pointers passed through JNA
 * as `long`/[Long]. Using [Int] would truncate on 64-bit platforms.
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
     * Returns the JSON-serialized `DidRotationEvent` produced when the
     * given handle was minted by [identityMigrate]. SDK callers MUST
     * distribute the event to active context members per spec
     * spec §9.12, ADR-003 §4b. Returns `null` for handles that did not change
     * the DID (e.g., create, rotate-key, agent-key ops, load).
     *
     * Mirrors the UniFFI-generated `Identity.rotationEventJson()`
     * accessor on the auto-generated Kotlin binding (and the
     * equivalent Swift `Identity.rotationEventJson()` /
     * Python `Identity.rotation_event_json` /
     * TypeScript `BridgeIdentityHandle.rotationEventJson`).
     *
     * @param identityHandle Handle from a migration operation.
     * @return JSON-serialized `DidRotationEvent` or `null`.
     * @throws BridgeException if the handle is invalid.
     */
    fun identityRotationEventJson(identityHandle: Long): String?

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
     *   An unknown tier is rejected with `SCP-IDENT-1021`.
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
    @Suppress("LongParameterList")
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
     * Verifies an identity link attestation per spec §3.5.4.
     *
     * A verifier resolves an issuer's DID document and takes a signing key
     * from it (§3.5.4 step 1), because attestations are signed with `#active`
     * or `#agent` keys (spec section 3.5.2), not the `#0` identity key
     * embedded in a DID. [issuerPublicKeyHex] states which key a caller
     * believes belongs to this issuer, and a verifier checks that statement
     * against an issuer's resolved document rather than trusting it.
     *
     * @param attestationJson JSON string of the attestation.
     * @param issuerPublicKeyHex Hex-encoded Ed25519 public key of the issuer.
     * @param referenceProof `"confirmed"` when this caller fetched the class 2
     *   proof resource `evidence.proof` names and found this issuer's DID in
     *   it (§3.5.4 Class 2 step 2), `"not_fetched"` when this caller fetched
     *   nothing. A class 1 (`did_control`) attestation ignores this argument.
     * @return true if valid.
     */
    fun identityVerifyLinkAttestation(
        attestationJson: String,
        issuerPublicKeyHex: String,
        referenceProof: String,
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
@Suppress("TooManyFunctions")
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
     * **Deprecated.** This overload silently drops the
     * `DidRotationEvent` that spec §9.12, ADR-003 §4b requires the caller
     * to distribute to every active context where the OLD DID is a
     * member. Without distribution, peers will reject subsequent
     * messages signed by the new DID's `#active` key as unauthorized,
     * and the migration is protocol-incomplete.
     *
     * Use [migrateWithRotationEvent] instead and forward the returned
     * [IdentityMigrateResult.rotationEventJson] to every active
     * context. Pre-context callers (no active contexts) may discard
     * the rotation event explicitly.
     *
     * @param identityHandle Handle from identity create or load.
     * @return Updated opaque identity handle with new DID.
     */
    @Deprecated(
        message =
            "Drops the DidRotationEvent required by spec §9.12, ADR-003 §4b. " +
                "Use migrateWithRotationEvent and distribute the rotation event to " +
                "all active contexts where the OLD DID is a member; pre-context callers " +
                "may discard the event explicitly.",
        replaceWith = ReplaceWith("migrateWithRotationEvent(identityHandle)"),
        level = DeprecationLevel.ERROR,
    )
    suspend fun migrate(identityHandle: Long): Long = bridge.ffiCall { bindings.identityMigrate(identityHandle) }

    /**
     * Migrates an identity to a new DID and returns both the new
     * handle and the JSON-serialized `DidRotationEvent`.
     *
     * SDK callers MUST distribute
     * [IdentityMigrateResult.rotationEventJson] to all active
     * contexts where the OLD DID is a member (spec §9.12, ADR-003 §4b).
     * Without distribution, peers will reject subsequent messages
     * signed by the new DID's `#active` key as unauthorized.
     *
     * Mirrors the rotation-event accessor exposed on the other
     * SDKs: Python `Identity.rotation_event_json`, TypeScript
     * `BridgeIdentityHandle.rotationEventJson`, Swift
     * `Identity.rotationEventJson()`.
     *
     * @param identityHandle Handle from identity create or load.
     * @return The new identity handle paired with the rotation
     *   event JSON.
     */
    suspend fun migrateWithRotationEvent(identityHandle: Long): IdentityMigrateResult =
        bridge.ffiCall {
            val newHandle = bindings.identityMigrate(identityHandle)
            val eventJson = bindings.identityRotationEventJson(newHandle)
            IdentityMigrateResult(handle = newHandle, rotationEventJson = eventJson)
        }

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
     * Executes the compromise recovery protocol for the given DID (spec §9.12).
     *
     * **Fails closed (#2240).** The §9.12 recovery WIRE (a real recovery backend
     * plus step-1 key rotation) is not yet built — it is tracked as #2240 Part B
     * and needs human design sign-off. Until it is wired, the underlying bridge
     * throws a typed `SCP-IDENT-1022` `BridgeException` ("recovery backend not
     * configured — provide a real backend via SDK layer") rather than
     * fabricating a success.
     *
     * @param did The DID string to recover. A DID this instance does not host
     *   is rejected with `SCP-IDENT-1020`.
     * @param tier Compromise tier: "agent", "active_signing", or "identity_key".
     *   An unknown tier is rejected with `SCP-IDENT-1021` (distinct from the
     *   `SCP-IDENT-1020` ownership rejection).
     * @param contextIds Context IDs where this DID is a member.
     * @return JSON string with the recovery result (once the backend is wired).
     * @throws BridgeException `SCP-IDENT-1021` for an unknown tier, or
     *   `SCP-IDENT-1022` while recovery is not configured.
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
    @Suppress("LongParameterList")
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
     * Verifies an identity link attestation per spec §3.5.4.
     *
     * A verifier resolves an issuer's DID document and takes a signing key
     * from it (§3.5.4 step 1), because attestations are signed with `#active`
     * or `#agent` keys (spec section 3.5.2), not the `#0` identity key
     * embedded in a DID. [issuerPublicKeyHex] states which key a caller
     * believes belongs to this issuer, and a verifier checks that statement
     * against an issuer's resolved document rather than trusting it.
     *
     * @param attestationJson JSON string of the attestation.
     * @param issuerPublicKeyHex Hex-encoded Ed25519 public key of the issuer.
     * @param referenceProof `"confirmed"` when this caller fetched the class 2
     *   proof resource `evidence.proof` names and found this issuer's DID in
     *   it (§3.5.4 Class 2 step 2), `"not_fetched"` when this caller fetched
     *   nothing. A class 1 (`did_control`) attestation ignores this argument.
     * @return true if valid.
     */
    suspend fun verifyLinkAttestation(
        attestationJson: String,
        issuerPublicKeyHex: String,
        referenceProof: String,
    ): Boolean =
        bridge.ffiCall {
            bindings.identityVerifyLinkAttestation(
                attestationJson,
                issuerPublicKeyHex,
                referenceProof,
            )
        }
}

// ---------------------------------------------------------------------------
// Identity migration result (§9.12, ADR-003 §4b)
// ---------------------------------------------------------------------------

/**
 * Result of [IdentityAdvancedBridge.migrateWithRotationEvent].
 *
 * The new opaque identity handle PLUS the JSON-serialized
 * `DidRotationEvent` that SDK callers MUST distribute to active
 * context members (spec §9.12, ADR-003 §4b).
 *
 * Mirrors the rotation-event accessor on the other SDKs:
 * Python `Identity.rotation_event_json`, TypeScript
 * `BridgeIdentityHandle.rotationEventJson`, Swift
 * `Identity.rotationEventJson()`.
 *
 * @property handle Opaque handle for the migrated identity (new DID).
 * @property rotationEventJson JSON-serialized `DidRotationEvent`,
 *   or `null` if the underlying handle did not change the DID
 *   (which is unusual for `migrate` and indicates an upstream FFI
 *   issue — production callers should treat `null` here as a
 *   distribution-skipped warning, not a normal case).
 */
data class IdentityMigrateResult(
    val handle: Long,
    val rotationEventJson: String?,
)

// ---------------------------------------------------------------------------
// Identity Link Attestation (§3.5)
// ---------------------------------------------------------------------------

/**
 * Revocation status for an identity attestation (§3.5).
 *
 * Mirrors the Rust `RevocationStatus` enum:
 *
 * - `Active` -> [RevocationStatus.Active]
 * - `Revoked { revoked_at, reason }` -> [RevocationStatus.Revoked]
 *
 * Provenance: §3.5 (Identity Link Attestations)
 */
sealed class RevocationStatus {
    /** The status string: `"active"` or `"revoked"`. Internal — use pattern matching. */
    internal abstract val status: String

    /** The attestation is active and valid. */
    data object Active : RevocationStatus() {
        override val status: String = "active"
    }

    /**
     * The attestation has been revoked.
     *
     * @property revokedAt Unix timestamp (seconds) when revoked (integer precision).
     * @property reason Optional human-readable revocation reason.
     */
    data class Revoked(
        val revokedAt: Long,
        val reason: String? = null,
    ) : RevocationStatus() {
        override val status: String = "revoked"
    }
}

/**
 * An identity link attestation binding a DID to an external platform (§3.5).
 *
 * Represents a cryptographically signed claim that the DID owner also
 * controls an identity on an external platform (e.g., GitHub, X, LinkedIn).
 *
 * The [id] is deterministically derived as
 * `hex(SHA-256(issuer || platform || handle || issued_at))`.
 *
 * Provenance: §3.5 (Identity Link Attestations)
 *
 * @property id Deterministic attestation ID.
 * @property platform Platform identifier (e.g., `"github.com"`).
 * @property platformHandle Platform handle or username.
 * @property verificationMethod DID verification method that signed this attestation.
 * @property verifiedAt Unix timestamp (seconds) when the evidence was last verified.
 * @property revocationStatus Revocation status.
 * @property platformId Optional platform-assigned unique identifier.
 */
data class IdentityAttestation(
    val id: String,
    val platform: String,
    val platformHandle: String,
    val verificationMethod: String,
    val verifiedAt: Long,
    val revocationStatus: RevocationStatus = RevocationStatus.Active,
    val platformId: String? = null,
) {
    internal companion object {
        /**
         * Parse an [IdentityAttestation] from a bridge JSON object.
         *
         * Revocation status decoding fails closed: unknown JSON shapes
         * throw [IllegalArgumentException] rather than defaulting to
         * [RevocationStatus.Active]. If the Rust enum adds a new
         * variant (e.g. `Suspended`), Kotlin SDK callers MUST see the
         * decode failure rather than silently mis-categorize a
         * suspended attestation as active — that would be a
         * security-relevant fail-open default.
         */
        fun fromJsonObject(obj: JsonObject): IdentityAttestation {
            val rsElement = obj["revocation_status"]
            val revocationStatus = when {
                rsElement == null -> RevocationStatus.Active
                rsElement is JsonPrimitive && rsElement.content == "Active" -> RevocationStatus.Active
                rsElement is JsonObject && rsElement.containsKey("Revoked") -> {
                    val revoked = rsElement["Revoked"]!!.jsonObject
                    RevocationStatus.Revoked(
                        revokedAt = revoked["revoked_at"]!!.jsonPrimitive.long,
                        reason = revoked["reason"]?.jsonPrimitive?.content,
                    )
                }
                else -> throw IllegalArgumentException(
                    "Unrecognized revocation_status JSON shape: $rsElement. " +
                        "Expected JsonPrimitive(\"Active\") or JsonObject({\"Revoked\": {...}}). " +
                        "Failing closed rather than defaulting to Active.",
                )
            }
            return IdentityAttestation(
                id = obj["id"]!!.jsonPrimitive.content,
                platform = obj["platform"]!!.jsonPrimitive.content,
                platformHandle = obj["platform_handle"]!!.jsonPrimitive.content,
                verificationMethod = obj["verification_method"]!!.jsonPrimitive.content,
                verifiedAt = obj["verified_at"]!!.jsonPrimitive.content.toLong(),
                revocationStatus = revocationStatus,
                platformId = obj["platform_id"]?.jsonPrimitive?.content,
            )
        }

        /** Parse an [IdentityAttestation] from a bridge JSON string. */
        fun fromJson(json: String): IdentityAttestation =
            fromJsonObject(Json.parseToJsonElement(json).jsonObject)

        /** Parse a list of [IdentityAttestation] from a bridge JSON array string. */
        fun listFromJson(json: String): List<IdentityAttestation> =
            Json.parseToJsonElement(json).jsonArray.map { fromJsonObject(it.jsonObject) }
    }
}

