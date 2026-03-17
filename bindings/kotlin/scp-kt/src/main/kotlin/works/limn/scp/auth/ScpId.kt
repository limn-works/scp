// ScpId.kt — Kotlin SDK SCPID authentication wrappers (#1059)
//
// Wraps UniFFI SCPID bridge functions for DID-based authentication
// against external services per spec section 3.11.
//
// The bridge functions exchange JSON strings; this wrapper layer
// deserializes them into typed Kotlin data classes for ergonomic
// consumption. All FFI calls are dispatched through CoroutineBridge.ffiCall
// on Dispatchers.IO per ADR-028.
//
// Provenance: spec section 3.11 (SCPID), ADR-039 (Shared-DID Agent Binding)

package works.limn.scp.auth

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.long
import works.limn.scp.bridge.CoroutineBridge

// ---------------------------------------------------------------------------
// Data Types
// ---------------------------------------------------------------------------

/**
 * SCPID challenge issued by a relying party (spec section 3.11.2).
 *
 * Contains a CSPRNG nonce, audience binding, and validity window.
 * Produced by [ScpIdBridge.challenge] and consumed by [ScpIdBridge.sign]
 * and [ScpIdBridge.verify].
 *
 * @property protocolVersion Protocol identifier and version (always `"scpid/1.0"`).
 * @property nonce 32-byte CSPRNG nonce for replay prevention (hex-encoded).
 * @property audience URI identifying the relying party.
 * @property issuedAt Unix timestamp (milliseconds) when the challenge was created.
 * @property expiresAt Unix timestamp (milliseconds) when the challenge expires.
 * @property json Raw JSON string returned by the bridge. Preserved for passing
 *   to [ScpIdBridge.sign] and [ScpIdBridge.verify] without re-serialization.
 */
data class ScpIdChallenge(
    val protocolVersion: String,
    val nonce: String,
    val audience: String,
    val issuedAt: Long,
    val expiresAt: Long,
    val json: String,
)

/**
 * SCPID signed response from the client (spec section 3.11.3).
 *
 * Contains the signer's DID, signing key selection, echoed challenge
 * fields, and the Ed25519 signature.
 *
 * @property protocolVersion Protocol identifier and version (always `"scpid/1.0"`).
 * @property did The signer's DID.
 * @property signingKeyId Which verification method signed: `"#active"` or `"#agent"`.
 * @property nonce Echo of the challenge nonce (hex-encoded).
 * @property audience Echo of the challenge audience URI.
 * @property signedAt Unix timestamp (milliseconds) when the client signed.
 * @property signature Ed25519 signature over the canonical hash (hex-encoded).
 * @property json Raw JSON string returned by the bridge. Preserved for passing
 *   to [ScpIdBridge.verify] without re-serialization.
 */
data class ScpIdResponse(
    val protocolVersion: String,
    val did: String,
    val signingKeyId: String,
    val nonce: String,
    val audience: String,
    val signedAt: Long,
    val signature: String,
    val json: String,
)

/**
 * Result of a successful SCPID verification (spec section 3.11.4).
 *
 * Returned by [ScpIdBridge.verify] when all verification steps pass.
 *
 * @property did The authenticated DID.
 * @property signingKeyId Which verification method produced the signature.
 * @property signedAt Unix timestamp (milliseconds) when the client signed.
 */
data class ScpIdAuthentication(
    val did: String,
    val signingKeyId: String,
    val signedAt: Long,
)

// ---------------------------------------------------------------------------
// Bindings Interface
// ---------------------------------------------------------------------------

/**
 * Native binding functions for SCPID operations.
 *
 * All methods are blocking JNA calls into Rust and must be dispatched
 * on [kotlinx.coroutines.Dispatchers.IO].
 */
interface ScpIdBindings {
    /**
     * Generates an SCPID challenge for the given audience.
     *
     * @param audience URI identifying the relying party.
     * @param ttlSeconds TTL in seconds (1-300).
     * @return JSON string of the challenge.
     * @throws Exception if audience is empty or TTL is out of range.
     */
    fun scpidChallenge(
        audience: String,
        ttlSeconds: Long,
    ): String

    /**
     * Signs an SCPID challenge with an identity's key.
     *
     * @param identityHandle Opaque identity handle from identity create.
     * @param signingKeyId `"#active"` or `"#agent"`.
     * @param challengeJson JSON string of the challenge.
     * @return JSON string of the signed response.
     * @throws Exception if identity lacks the requested key or signing fails.
     */
    fun scpidSign(
        identityHandle: Long,
        signingKeyId: String,
        challengeJson: String,
    ): String

    /**
     * Verifies a signed SCPID response against the original challenge.
     *
     * @param responseJson JSON string of the signed response.
     * @param challengeJson JSON string of the original challenge.
     * @return JSON string of the authentication result.
     * @throws Exception if verification fails.
     */
    fun scpidVerify(
        responseJson: String,
        challengeJson: String,
    ): String
}

// ---------------------------------------------------------------------------
// Bridge
// ---------------------------------------------------------------------------

/**
 * SCPID authentication bridge. Wraps SCPID FFI calls as suspend functions
 * with JSON deserialization into typed data classes.
 *
 * SCPID enables DID-based authentication against external services
 * (spec section 3.11). The flow is:
 * 1. Relying party calls [challenge] to generate a challenge.
 * 2. Client calls [sign] with their identity to produce a signed response.
 * 3. Relying party calls [verify] to validate the response.
 *
 * @property bindings The SCPID native bindings (or a test stub).
 * @property bridge The coroutine bridge for FFI dispatch.
 */
class ScpIdBridge internal constructor(
    private val bindings: ScpIdBindings,
    private val bridge: CoroutineBridge,
) {
    /**
     * Generates an SCPID challenge for the given audience (spec section 3.11.2).
     *
     * @param audience URI identifying the relying party.
     * @param ttlSeconds TTL in seconds (1-300). Defaults to 300.
     * @return An [ScpIdChallenge] with the challenge fields.
     */
    suspend fun challenge(
        audience: String,
        ttlSeconds: Long = 300,
    ): ScpIdChallenge {
        val json = bridge.ffiCall { bindings.scpidChallenge(audience, ttlSeconds) }
        return parseChallenge(json)
    }

    /**
     * Signs an SCPID challenge with an identity's key (spec section 3.11.3).
     *
     * @param identityHandle Opaque identity handle from identity create.
     * @param signingKeyId Which key to sign with: `"#active"` or `"#agent"`.
     * @param challenge The challenge to sign.
     * @return An [ScpIdResponse] with the signed response fields.
     */
    suspend fun sign(
        identityHandle: Long,
        signingKeyId: String,
        challenge: ScpIdChallenge,
    ): ScpIdResponse {
        val json = bridge.ffiCall { bindings.scpidSign(identityHandle, signingKeyId, challenge.json) }
        return parseResponse(json)
    }

    /**
     * Verifies a signed SCPID response against the original challenge (spec section 3.11.4).
     *
     * @param response The signed response to verify.
     * @param challenge The original challenge that was signed.
     * @return An [ScpIdAuthentication] with the verified identity fields.
     */
    suspend fun verify(
        response: ScpIdResponse,
        challenge: ScpIdChallenge,
    ): ScpIdAuthentication {
        val json = bridge.ffiCall { bindings.scpidVerify(response.json, challenge.json) }
        return parseAuthentication(json)
    }
}

// ---------------------------------------------------------------------------
// Companion object for static access (namespace pattern)
// ---------------------------------------------------------------------------

/**
 * Static SCPID authentication operations (spec section 3.11).
 *
 * Provides factory methods for JSON parsing. For bridge-dispatched operations,
 * use [ScpIdBridge] via [CoroutineBridge].
 */
object ScpId {
    /**
     * Parses a challenge JSON string into an [ScpIdChallenge].
     *
     * @param json JSON string from the bridge.
     * @return Parsed [ScpIdChallenge].
     */
    fun parseChallenge(json: String): ScpIdChallenge = works.limn.scp.auth.parseChallenge(json)

    /**
     * Parses a response JSON string into an [ScpIdResponse].
     *
     * @param json JSON string from the bridge.
     * @return Parsed [ScpIdResponse].
     */
    fun parseResponse(json: String): ScpIdResponse = works.limn.scp.auth.parseResponse(json)

    /**
     * Parses an authentication JSON string into an [ScpIdAuthentication].
     *
     * @param json JSON string from the bridge.
     * @return Parsed [ScpIdAuthentication].
     */
    fun parseAuthentication(json: String): ScpIdAuthentication = works.limn.scp.auth.parseAuthentication(json)
}

// ---------------------------------------------------------------------------
// JSON Parsing (private helpers)
// ---------------------------------------------------------------------------

private val jsonParser = Json { ignoreUnknownKeys = true }

/**
 * Parses a challenge JSON string into an [ScpIdChallenge].
 *
 * Uses kotlinx.serialization.json for consistent JSON handling with the SDK.
 */
internal fun parseChallenge(json: String): ScpIdChallenge {
    val obj = jsonParser.parseToJsonElement(json).jsonObject
    return ScpIdChallenge(
        protocolVersion = obj.stringField("protocol"),
        nonce = obj.stringField("nonce"),
        audience = obj.stringField("audience"),
        issuedAt = obj.longField("issued_at"),
        expiresAt = obj.longField("expires_at"),
        json = json,
    )
}

/**
 * Parses a response JSON string into an [ScpIdResponse].
 */
internal fun parseResponse(json: String): ScpIdResponse {
    val obj = jsonParser.parseToJsonElement(json).jsonObject
    return ScpIdResponse(
        protocolVersion = obj.stringField("protocol"),
        did = obj.stringField("did"),
        signingKeyId = obj.stringField("signing_key_id"),
        nonce = obj.stringField("nonce"),
        audience = obj.stringField("audience"),
        signedAt = obj.longField("signed_at"),
        signature = obj.stringField("signature"),
        json = json,
    )
}

/**
 * Parses an authentication JSON string into an [ScpIdAuthentication].
 */
internal fun parseAuthentication(json: String): ScpIdAuthentication {
    val obj = jsonParser.parseToJsonElement(json).jsonObject
    return ScpIdAuthentication(
        did = obj.stringField("did"),
        signingKeyId = obj.stringField("signing_key_id"),
        signedAt = obj.longField("signed_at"),
    )
}

private fun JsonObject.stringField(key: String): String = getValue(key).jsonPrimitive.content

private fun JsonObject.longField(key: String): Long = getValue(key).jsonPrimitive.long
