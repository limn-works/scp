// TrustAdmission.kt — Typed Kotlin SDK shapes for trust-admission inputs
// (ADR-058, the input-side analog of ADR-059).
//
// Mirrors `scp_protocol::trust::{admission, challenge, participation}`:
// VerificationLevel / RetryCap / CapabilityRequirement (§7.3.4.4),
// ChallengeVerification (§7.3.4, ADR-017), and
// ParticipationFact / ParticipationThreshold / RequireParticipation /
// ParticipationProfile (§7.3.2.1, SCP-BA-004). The SDK exposes typed shapes
// (no stringly-typed JSON) and serializes to the Rust serde wire format at the
// bridge boundary — [SCP.verifyParticipationRequirements] and
// [SCP.checkCapabilityRequirements] in SCP.kt call the encoders below before
// crossing FFI. Mirrors the Swift SDK `Trust.swift` admission types and the
// TypeScript SDK `types.ts` admission types field-for-field.
//
// Provenance: ADR-058 (.docs/adrs/phase-4.md), spec §7.3.2.1 / §7.3.4
// (.docs/specs/07-trust-validation-and-capabilities.md), ADR-017
// (.docs/adrs/phase-4.md).

package works.limn.scp

import kotlinx.serialization.KSerializer
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.SerializationException
import kotlinx.serialization.builtins.ListSerializer
import kotlinx.serialization.builtins.serializer
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonDecoder
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonEncoder
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.put

/**
 * The one [Json] configuration for trust-admission and challenge wire
 * encoding.
 *
 * `encodeDefaults = true` so defaulted fields ([CapabilityRequirement.trustedVerifiers],
 * an absent [CapabilityRequirement.retryCap]) serialize explicitly, as
 * `serde_json::to_string` of the Rust struct and the Swift/TypeScript SDK
 * encoders write them, rather than being omitted as kotlinx.serialization
 * would do for defaulted fields. Decoding refuses an unknown key and a missing
 * field, so a shape the bridge did not write fails at the boundary.
 */
internal val trustAdmissionJson = Json { encodeDefaults = true }

// ---------------------------------------------------------------------------
// Capability admission types (§7.3.4.4, ADR-058)
// ---------------------------------------------------------------------------

/**
 * How a capability must be verified for admission.
 *
 * Encodes to the bare variant name string (`"SelfAttested"` /
 * `"ChallengeVerified"`) to match the Rust `VerificationLevel` enum's default
 * (externally-tagged) serde representation. `ChallengeVerified` also satisfies
 * `SelfAttested`. Mirrors the Swift SDK `VerificationLevel` enum and the
 * TypeScript SDK `VerificationLevel` union 1:1.
 */
@Serializable
enum class VerificationLevel {
    /**
     * The agent claims the capability (present in its capability list); no
     * challenge proof required.
     */
    @SerialName("SelfAttested")
    SELF_ATTESTED,

    /** The capability was verified through the challenge-response protocol. */
    @SerialName("ChallengeVerified")
    CHALLENGE_VERIFIED,
}

/**
 * The most retries and the least cooldown a context accepts from a
 * challenger's standard (spec 07 §7.3.4.4). A record graded under more
 * retries or a shorter cooldown does not meet the requirement.
 *
 * @property maxRetries The most retries the challenger's standard may allow.
 * @property minCooldownSecs The shortest cooldown, in seconds, the
 *   challenger's standard may set.
 */
@Serializable
data class RetryCap(
    @SerialName("max_retries") val maxRetries: UInt,
    @SerialName("min_cooldown_secs") val minCooldownSecs: UInt,
)

/**
 * A single admission requirement: a capability URI, the minimum verification
 * level, and for `ChallengeVerified` the challengers whose records count
 * (spec 07 §7.3.4.4).
 *
 * A context's governance holds its requirements: set
 * `ContextParams.capabilityRequirementsJson` to
 * [encodeCapabilityRequirementsJson] of them when creating the context. The
 * serial names are the snake_case the Rust `RawCapabilityRequirement`
 * deserializes. Mirrors the Swift SDK `CapabilityRequirement`, the TypeScript
 * SDK `CapabilityRequirement`, and the Python SDK `CapabilityRequirement`.
 *
 * @property capability The capability URI that must be present.
 * @property verificationLevel The minimum verification level required.
 * @property trustedVerifiers DIDs of the challengers whose records meet a
 *   `ChallengeVerified` requirement. Required and non-empty for
 *   `ChallengeVerified`; empty for `SelfAttested`. The bridge enforces both.
 * @property retryCap The retry and cooldown bounds a record's standard must
 *   meet, if any. Only `ChallengeVerified` takes one.
 */
@Serializable
data class CapabilityRequirement(
    val capability: String,
    @SerialName("verification_level") val verificationLevel: VerificationLevel,
    @SerialName("trusted_verifiers") val trustedVerifiers: List<String> = emptyList(),
    @SerialName("retry_cap") val retryCap: RetryCap? = null,
)

/**
 * A signed record that a challenger graded a subject's response (spec 07
 * §7.3.4, ADR-017).
 *
 * [SCP.trustGradeResponse] returns one; pass a list of them to
 * [SCP.checkCapabilityRequirements] to meet `ChallengeVerified`
 * requirements. The serial names are the snake_case the Rust core
 * deserializes; [verifierSignature] is a 64-byte JSON number array. The
 * verifier's signature covers every field, so a record with any field altered
 * fails verification. Mirrors the Swift SDK `ChallengeVerification`, the
 * TypeScript SDK `ChallengeVerification`, and the Rust struct 1:1.
 *
 * @property verificationId The record's id, 64 lowercase hex characters.
 * @property verifier DID of the challenger that graded the response.
 * @property subject DID of the subject that answered.
 * @property capabilityUri The capability URI that was tested.
 * @property definitionDigest Digest of the capability definition, 64
 *   lowercase hex characters.
 * @property suiteDigest Digest of the graded test cases, 64 lowercase hex
 *   characters.
 * @property challengeId The graded request's id, 64 lowercase hex characters.
 * @property attempt The attempt this record grades, starting at 1.
 * @property responseDigest Digest of the graded response, 64 lowercase hex
 *   characters.
 * @property maxRetries Retries the challenger's standard allowed.
 * @property cooldownSecs Cooldown in seconds between attempts.
 * @property passThresholdBps Score in basis points needed to pass.
 * @property minCategoryCases Least cases per category the standard required.
 * @property passed Whether the subject passed.
 * @property score Score in basis points, 0 to 10000.
 * @property testCount Number of test cases graded.
 * @property passCount Number of test cases the subject passed.
 * @property challengeCreatedAt Unix seconds when the request was created.
 * @property challengeExpiresAt Unix seconds when the request expired.
 * @property timestamp Unix seconds of the grading.
 * @property expiresAt Unix seconds when this record expires.
 * @property contextId The context the challenge was administered for.
 * @property verifierSignature Ed25519 signature by the verifier's `#active`
 *   key over the record digest (64 bytes).
 */
@Serializable
data class ChallengeVerification(
    @SerialName("verification_id") val verificationId: String,
    val verifier: String,
    val subject: String,
    @SerialName("capability_uri") val capabilityUri: String,
    @SerialName("definition_digest") val definitionDigest: String,
    @SerialName("suite_digest") val suiteDigest: String,
    @SerialName("challenge_id") val challengeId: String,
    val attempt: UInt,
    @SerialName("response_digest") val responseDigest: String,
    @SerialName("max_retries") val maxRetries: UInt,
    @SerialName("cooldown_secs") val cooldownSecs: UInt,
    @SerialName("pass_threshold_bps") val passThresholdBps: UInt,
    @SerialName("min_category_cases") val minCategoryCases: UInt,
    val passed: Boolean,
    val score: UInt,
    @SerialName("test_count") val testCount: UInt,
    @SerialName("pass_count") val passCount: UInt,
    @SerialName("challenge_created_at") val challengeCreatedAt: ULong,
    @SerialName("challenge_expires_at") val challengeExpiresAt: ULong,
    val timestamp: ULong,
    @SerialName("expires_at") val expiresAt: ULong,
    @SerialName("context_id") val contextId: String,
    @SerialName("verifier_signature") val verifierSignature: List<UByte>,
)

// ---------------------------------------------------------------------------
// Participation admission types (§7.3.2.1, SCP-BA-004, ADR-058)
// ---------------------------------------------------------------------------

/**
 * Which category of participation fact to evaluate for admission.
 *
 * Each entry corresponds to one of the 7 fact categories in a
 * [ParticipationProfile]. Encodes to the bare PascalCase variant name string
 * (`"ParticipationDuration"`, …) to match the Rust `ParticipationFact` enum's
 * default (externally-tagged) serde representation. Mirrors the Swift SDK
 * `ParticipationFact` enum and the TypeScript SDK `ParticipationFact` union
 * 1:1. See §7.3.2.1.
 */
@Serializable
enum class ParticipationFact {
    /** Total seconds of context participation. */
    @SerialName("ParticipationDuration")
    PARTICIPATION_DURATION,

    /** Count of governance actions taken against the identity. */
    @SerialName("GovernanceActionsAgainst")
    GOVERNANCE_ACTIONS_AGAINST,

    /** Count of governance actions initiated by the identity. */
    @SerialName("GovernanceActionsBy")
    GOVERNANCE_ACTIONS_BY,

    /** Total outlet invocations across all outlet types. */
    @SerialName("OutletInvocationCount")
    OUTLET_INVOCATION_COUNT,

    /** Number of contexts created. */
    @SerialName("ContextCreationCount")
    CONTEXT_CREATION_COUNT,

    /** Number of role transitions. */
    @SerialName("RoleProgressionCount")
    ROLE_PROGRESSION_COUNT,

    /** Number of attestation events. */
    @SerialName("AttestationCount")
    ATTESTATION_COUNT,
}

/**
 * Comparison operator and value for participation admission thresholds.
 *
 * Used in [RequireParticipation] to specify the comparison a fact value must
 * satisfy. Serializes as the externally-tagged single-key object the Rust
 * `ParticipationThreshold` enum produces — `{"GreaterThan": 50}`,
 * `{"AtLeast": 100}`, etc. Mirrors the Swift SDK `ParticipationThreshold` and
 * the TypeScript SDK `ParticipationThreshold` union 1:1. See §7.3.2.1.
 */
@Serializable(with = ParticipationThresholdSerializer::class)
sealed class ParticipationThreshold {
    /** The threshold value the fact is compared against. */
    abstract val value: ULong

    /** Fact value must be strictly greater than [value]. */
    data class GreaterThan(override val value: ULong) : ParticipationThreshold()

    /** Fact value must be strictly less than [value]. */
    data class LessThan(override val value: ULong) : ParticipationThreshold()

    /** Fact value must be greater than or equal to [value]. */
    data class AtLeast(override val value: ULong) : ParticipationThreshold()

    /** Fact value must be less than or equal to [value]. */
    data class AtMost(override val value: ULong) : ParticipationThreshold()

    /** Fact value must equal [value] exactly. */
    data class Equals(override val value: ULong) : ParticipationThreshold()
}

/**
 * Custom serializer producing the Rust `ParticipationThreshold`
 * externally-tagged serde shape: a single-key object mapping the PascalCase
 * variant name to its u64 value (`{"AtLeast": 100}`). JSON-only by
 * construction (the wire format is JSON at the FFI boundary).
 */
object ParticipationThresholdSerializer : KSerializer<ParticipationThreshold> {
    override val descriptor: SerialDescriptor = JsonElement.serializer().descriptor

    override fun serialize(
        encoder: Encoder,
        value: ParticipationThreshold,
    ) {
        val jsonEncoder =
            encoder as? JsonEncoder
                ?: throw SerializationException("ParticipationThreshold is JSON-only")
        val tag =
            when (value) {
                is ParticipationThreshold.GreaterThan -> "GreaterThan"
                is ParticipationThreshold.LessThan -> "LessThan"
                is ParticipationThreshold.AtLeast -> "AtLeast"
                is ParticipationThreshold.AtMost -> "AtMost"
                is ParticipationThreshold.Equals -> "Equals"
            }
        val amount = jsonEncoder.json.encodeToJsonElement(ULong.serializer(), value.value)
        jsonEncoder.encodeJsonElement(buildJsonObject { put(tag, amount) })
    }

    override fun deserialize(decoder: Decoder): ParticipationThreshold {
        val jsonDecoder =
            decoder as? JsonDecoder
                ?: throw SerializationException("ParticipationThreshold is JSON-only")
        val obj = jsonDecoder.decodeJsonElement().jsonObject
        val (tag, element) =
            obj.entries.singleOrNull()
                ?: throw SerializationException(
                    "ParticipationThreshold must be a single-key object, got $obj",
                )
        val amount = jsonDecoder.json.decodeFromJsonElement(ULong.serializer(), element)
        return when (tag) {
            "GreaterThan" -> ParticipationThreshold.GreaterThan(amount)
            "LessThan" -> ParticipationThreshold.LessThan(amount)
            "AtLeast" -> ParticipationThreshold.AtLeast(amount)
            "AtMost" -> ParticipationThreshold.AtMost(amount)
            "Equals" -> ParticipationThreshold.Equals(amount)
            else -> throw SerializationException(
                "no known ParticipationThreshold operator key: $tag",
            )
        }
    }
}

/**
 * A participation admission requirement declared by a context.
 *
 * Each entry specifies a participation fact, a threshold, a freshness
 * requirement, and a minimum number of independent source contexts. The serial
 * names are the serde-canonical snake_case the Rust core deserializes
 * (`Vec<RequireParticipation>`). Mirrors the Swift SDK `RequireParticipation`,
 * the TypeScript SDK `RequireParticipation`, and the Rust struct 1:1.
 * See §7.3.2.1.
 *
 * @property fact Which participation category to evaluate.
 * @property threshold Comparison operator and value.
 * @property maxAgeSecs Maximum age in seconds for the profile's `updated_at`
 *   timestamp. Profiles older than this are rejected.
 * @property minContexts Minimum number of independent source contexts
 *   (distinct `signer_public_key` values) required to satisfy this
 *   requirement.
 */
@Serializable
data class RequireParticipation(
    val fact: ParticipationFact,
    val threshold: ParticipationThreshold,
    @SerialName("max_age_secs") val maxAgeSecs: ULong,
    @SerialName("min_contexts") val minContexts: UInt,
)

/**
 * A context-hosted participation profile attesting to a member's verifiable
 * participation facts.
 *
 * Produced by contexts for opted-in members and signed by a context-specific
 * Ed25519 key (derived with domain separation) so verifiers cannot correlate
 * which contexts share a signer. The serial names are the serde-canonical
 * snake_case the Rust core deserializes (`Vec<ParticipationProfile>`); the
 * three byte-array fields ([eventLogRoot]/[signerPublicKey], 32 bytes each;
 * [signature], 64 bytes) serialize as JSON number arrays, matching the Rust
 * `[u8; N]`/`serde_bytes` representation — [encodeParticipationProfileJson]
 * rejects wrong-length arrays before the bridge call, and the Rust side
 * rejects them again at deserialize time. Mirrors the Swift SDK `ParticipationProfile`,
 * the TypeScript SDK `ParticipationProfile`, and the Rust struct 1:1.
 * See §7.3.2.1.
 *
 * @property subjectDid DID of the member this profile is about.
 * @property participationDurationSecs Total seconds of context participation.
 * @property governanceActionsAgainst Count of governance actions taken against
 *   this identity.
 * @property governanceActionsBy Count of governance actions initiated by this
 *   identity.
 * @property outletInvocationCount Total outlet invocations across all outlet types.
 * @property outletInvocationCountAnchored Whether [outletInvocationCount] is
 *   anchored in the canonical Merkle log. `false` until ADR-051 makes
 *   `OutletInvoked` a convergent leaf — consumers MUST NOT treat the count as
 *   Merkle-proven while this is `false`. The flag is part of the signed
 *   preimage, so it cannot be stripped from a signed profile.
 * @property contextCreationCount Number of contexts created.
 * @property roleProgressionCount Number of role transitions.
 * @property attestationCount Number of attestation events.
 * @property updatedAt Unix timestamp (seconds) of the last update to this
 *   profile.
 * @property eventLogRoot Merkle root of the context's event log at profile
 *   computation time (32 bytes).
 * @property signerPublicKey Context-specific Ed25519 public key used to sign
 *   this profile (32 bytes).
 * @property signature Ed25519 signature over all fields except this one
 *   (64 bytes).
 */
@Serializable
data class ParticipationProfile(
    @SerialName("subject_did") val subjectDid: String,
    @SerialName("participation_duration_secs") val participationDurationSecs: ULong,
    @SerialName("governance_actions_against") val governanceActionsAgainst: ULong,
    @SerialName("governance_actions_by") val governanceActionsBy: ULong,
    @SerialName("outlet_invocation_count") val outletInvocationCount: ULong,
    @SerialName("outlet_invocation_count_anchored") val outletInvocationCountAnchored: Boolean,
    @SerialName("context_creation_count") val contextCreationCount: ULong,
    @SerialName("role_progression_count") val roleProgressionCount: ULong,
    @SerialName("attestation_count") val attestationCount: ULong,
    @SerialName("updated_at") val updatedAt: ULong,
    @SerialName("event_log_root") val eventLogRoot: List<UByte>,
    @SerialName("signer_public_key") val signerPublicKey: List<UByte>,
    val signature: List<UByte>,
)

// ---------------------------------------------------------------------------
// JSON encoding — typed shapes -> Rust serde wire format
// ---------------------------------------------------------------------------

/**
 * Encodes a typed [CapabilityRequirement] list to the JSON
 * `ContextParams.capabilityRequirementsJson` carries
 * (`Vec<RawCapabilityRequirement>`). [CapabilityRequirement.verificationLevel]
 * serializes as the bare variant string; the bridge validates the list when
 * the context is created.
 */
fun encodeCapabilityRequirementsJson(requirements: List<CapabilityRequirement>): String =
    trustAdmissionJson.encodeToString(
        ListSerializer(CapabilityRequirement.serializer()),
        requirements,
    )

/** Expected element count of a 32-byte field (Rust `[u8; 32]`). */
private const val BYTES_32 = 32

/** Expected element count of a 64-byte field (Rust `[u8; 64]`). */
private const val BYTES_64 = 64

/**
 * Throws [IllegalArgumentException] when a fixed-length byte-array field has
 * the wrong number of elements, so a malformed profile/verification fails at
 * encode time with a field-named error instead of surfacing as a Rust
 * `[u8; N]` deserialization error after the bridge call. Mirrors the Python
 * SDK's construction-time checks (ADR-058 misuse resistance).
 */
private fun requireByteLength(
    typeName: String,
    fieldName: String,
    expectedLength: Int,
    actual: List<UByte>,
) {
    require(actual.size == expectedLength) {
        "$typeName.$fieldName must be exactly $expectedLength elements, got ${actual.size}"
    }
}

/**
 * Encodes a typed [ChallengeVerification] list to the JSON wire shape the
 * bridge deserializes (`Vec<ChallengeVerification>`).
 *
 * @throws IllegalArgumentException if an id or digest is not 64 lowercase hex
 *   characters, [ChallengeVerification.score] exceeds 10000, or the signature
 *   is not 64 bytes (before any bridge call).
 */
fun encodeChallengeVerificationsJson(verifications: List<ChallengeVerification>): String {
    for (verification in verifications) {
        requireChallengeVerification(verification)
    }
    return trustAdmissionJson.encodeToString(
        ListSerializer(ChallengeVerification.serializer()),
        verifications,
    )
}

/**
 * Decodes the record JSON [SCP.trustGradeResponse]'s bridge returns.
 *
 * @throws IllegalArgumentException if the JSON is not a record (a field is
 *   missing or unknown), an id or digest is not 64 lowercase hex characters,
 *   [ChallengeVerification.score] exceeds 10000, or the signature is not 64
 *   bytes.
 */
fun decodeChallengeVerificationJson(json: String): ChallengeVerification {
    val verification =
        try {
            trustAdmissionJson.decodeFromString(ChallengeVerification.serializer(), json)
        } catch (e: SerializationException) {
            throw IllegalArgumentException("malformed ChallengeVerification JSON: ${e.message}", e)
        }
    requireChallengeVerification(verification)
    return verification
}

private const val MAX_SCORE_BASIS_POINTS = 10_000u

private fun requireChallengeVerification(verification: ChallengeVerification) {
    val type = "ChallengeVerification"
    requireLowerHex32(type, "verificationId", verification.verificationId)
    requireLowerHex32(type, "definitionDigest", verification.definitionDigest)
    requireLowerHex32(type, "suiteDigest", verification.suiteDigest)
    requireLowerHex32(type, "challengeId", verification.challengeId)
    requireLowerHex32(type, "responseDigest", verification.responseDigest)
    require(verification.score <= MAX_SCORE_BASIS_POINTS) {
        "ChallengeVerification.score must be in [0, 10000], got ${verification.score}"
    }
    requireByteLength(type, "verifierSignature", BYTES_64, verification.verifierSignature)
}

/**
 * Encodes the agent's self-attested capability URIs to the JSON wire shape the
 * bridge deserializes (`Vec<CapabilityUri>`). Each `CapabilityUri` serializes
 * as its plain URI string, so a `List<String>` maps directly onto the wire
 * array.
 */
fun encodeAgentCapabilitiesJson(capabilities: List<String>): String =
    trustAdmissionJson.encodeToString(ListSerializer(String.serializer()), capabilities)

/**
 * Encodes a typed [RequireParticipation] list to the JSON wire shape the
 * bridge deserializes (`Vec<RequireParticipation>`). [RequireParticipation.fact]
 * is a bare variant string and [RequireParticipation.threshold] is the
 * serde-canonical `{"<Op>": value}` shape.
 */
fun encodeRequireParticipationJson(requirements: List<RequireParticipation>): String =
    trustAdmissionJson.encodeToString(
        ListSerializer(RequireParticipation.serializer()),
        requirements,
    )

/**
 * Encodes a typed [ParticipationProfile] list to the JSON wire shape the
 * bridge deserializes (`Vec<ParticipationProfile>`). Byte-array fields pass
 * through as JSON number arrays.
 *
 * @throws IllegalArgumentException if [ParticipationProfile.eventLogRoot] /
 *   [ParticipationProfile.signerPublicKey] are not exactly 32 elements or
 *   [ParticipationProfile.signature] is not exactly 64 elements (before any
 *   bridge call).
 */
fun encodeParticipationProfileJson(profiles: List<ParticipationProfile>): String {
    for (profile in profiles) {
        requireByteLength("ParticipationProfile", "eventLogRoot", BYTES_32, profile.eventLogRoot)
        requireByteLength(
            "ParticipationProfile",
            "signerPublicKey",
            BYTES_32,
            profile.signerPublicKey,
        )
        requireByteLength("ParticipationProfile", "signature", BYTES_64, profile.signature)
    }
    return trustAdmissionJson.encodeToString(
        ListSerializer(ParticipationProfile.serializer()),
        profiles,
    )
}
