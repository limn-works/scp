// TrustAdmission.kt — Typed Kotlin SDK shapes for trust-admission inputs
// (ADR-058, the input-side analog of ADR-059).
//
// Mirrors `scp_protocol::trust::{admission, challenge, participation}`:
// VerificationLevel / CapabilityRequirement (§7.3.4.4, SCP-ACR-008),
// VerificationMethod / ChallengeVerification (§7.3.4.2, ADR-017), and
// ParticipationFact / ParticipationThreshold / RequireParticipation /
// ParticipationProfile (§7.3.2.1, SCP-BA-004). The SDK exposes typed shapes
// (no stringly-typed JSON) and serializes to the Rust serde wire format at the
// bridge boundary — [SCP.verifyParticipationRequirements] and
// [SCP.checkCapabilityRequirements] in Scp.kt call the encoders below before
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
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put

/**
 * The one [Json] configuration for trust-admission wire encoding.
 *
 * `encodeDefaults = true` so the optional [ChallengeVerification.score] /
 * [ChallengeVerification.contextId] fields serialize as explicit JSON `null`
 * when absent (matching `serde_json::to_string` of the Rust `Option<T>` fields
 * and the Swift/TypeScript SDK encoders), rather than being omitted as
 * kotlinx.serialization would do for defaulted fields. The Rust deserializer
 * accepts either shape, but explicit `null` keeps the wire form identical
 * across bindings.
 */
private val trustAdmissionJson = Json { encodeDefaults = true }

// ---------------------------------------------------------------------------
// Capability admission types (§7.3.4.4, SCP-ACR-008, ADR-058)
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
 * A single admission requirement: a capability URI and the minimum
 * verification level needed.
 *
 * The serial names are the serde-canonical snake_case the Rust core
 * deserializes (`Vec<CapabilityRequirement>`). Mirrors the Swift SDK
 * `CapabilityRequirement`, the TypeScript SDK `CapabilityRequirement`, and the
 * Rust struct 1:1. See §7.3.4.4.
 *
 * @property capability The capability URI that must be present.
 * @property verificationLevel The minimum verification level required.
 */
@Serializable
data class CapabilityRequirement(
    val capability: String,
    @SerialName("verification_level") val verificationLevel: VerificationLevel,
)

/**
 * How a capability was verified, as recorded in a [ChallengeVerification].
 *
 * Serializes as the bare string `"SelfAttested"` or the externally-tagged
 * `{"ChallengeVerified": {"challenge_type": "<uri>"}}`, matching the Rust
 * `VerificationMethod` enum. The inner `challenge_type` is a bare capability
 * URI string (the Rust `ChallengeType` serializes as its URI string). Mirrors
 * the Swift SDK `ChallengeVerificationMethod` and the TypeScript SDK
 * `ChallengeVerificationMethod` 1:1.
 *
 * SECURITY: `verification_method` is NOT covered by the verifier signature
 * (ADR-017 caveat) — consumers MUST NOT key trust decisions on it.
 */
@Serializable(with = ChallengeVerificationMethodSerializer::class)
sealed class ChallengeVerificationMethod {
    /** Self-attested — no challenge proof. */
    data object SelfAttested : ChallengeVerificationMethod()

    /** Challenge-verified, carrying the challenge type (a capability URI). */
    data class ChallengeVerified(val challengeType: String) : ChallengeVerificationMethod()
}

/**
 * Custom serializer producing the Rust `VerificationMethod` externally-tagged
 * serde shape: `"SelfAttested"` for the unit variant, and
 * `{"ChallengeVerified": {"challenge_type": "<uri>"}}` for the struct variant.
 * JSON-only by construction (the wire format is JSON at the FFI boundary).
 */
object ChallengeVerificationMethodSerializer : KSerializer<ChallengeVerificationMethod> {
    override val descriptor: SerialDescriptor = JsonElement.serializer().descriptor

    override fun serialize(
        encoder: Encoder,
        value: ChallengeVerificationMethod,
    ) {
        val jsonEncoder =
            encoder as? JsonEncoder
                ?: throw SerializationException("ChallengeVerificationMethod is JSON-only")
        val element: JsonElement =
            when (value) {
                ChallengeVerificationMethod.SelfAttested -> JsonPrimitive("SelfAttested")
                is ChallengeVerificationMethod.ChallengeVerified ->
                    buildJsonObject {
                        put(
                            "ChallengeVerified",
                            buildJsonObject { put("challenge_type", value.challengeType) },
                        )
                    }
            }
        jsonEncoder.encodeJsonElement(element)
    }

    override fun deserialize(decoder: Decoder): ChallengeVerificationMethod {
        val jsonDecoder =
            decoder as? JsonDecoder
                ?: throw SerializationException("ChallengeVerificationMethod is JSON-only")
        val element = jsonDecoder.decodeJsonElement()
        return parseMethod(element)
            ?: throw SerializationException("unsupported VerificationMethod shape: $element")
    }

    /**
     * Parses the two serde shapes, or returns `null` for anything else: the
     * bare `"SelfAttested"` string, or the
     * `{"ChallengeVerified": {"challenge_type": "<uri>"}}` tagged object.
     */
    private fun parseMethod(element: JsonElement): ChallengeVerificationMethod? =
        when {
            element is JsonPrimitive && element.isString && element.content == "SelfAttested" ->
                ChallengeVerificationMethod.SelfAttested
            element is JsonObject ->
                (element["ChallengeVerified"] as? JsonObject)
                    ?.get("challenge_type")
                    ?.jsonPrimitive
                    ?.contentOrNull
                    ?.let { ChallengeVerificationMethod.ChallengeVerified(it) }
            else -> null
        }
}

/**
 * A signed record that a specific verifier tested a capability and the agent
 * passed (spec §7.3.4.2, ADR-017).
 *
 * Pass a list of these to [SCP.checkCapabilityRequirements] to satisfy
 * `ChallengeVerified` requirements. The serial names are the serde-canonical
 * snake_case the Rust core deserializes (`Vec<ChallengeVerification>`);
 * [verifierSignature] is a 64-byte JSON number array. Mirrors the Swift SDK
 * `ChallengeVerification`, the TypeScript SDK `ChallengeVerification`, and the
 * Rust struct 1:1.
 *
 * SECURITY (ADR-017 caveat): only the *signed* fields bind trust —
 * `verification_id`, `verifier_did`, `subject_did`, `capability_uri`,
 * `challenge_type`, `passed`, `score`, `test_count`, `pass_count`,
 * `verified_at`, `expires_at`, `context_id`. The `result`, `completed_at`, and
 * `verification_method` fields are NOT signed and can be altered after minting
 * without invalidating the signature. Consumers MUST NOT key trust decisions
 * on those unsigned fields.
 *
 * @property verificationId Unique verification identifier (derived from the
 *   challenge ID).
 * @property verifierDid DID of the verifier who issued and verified the
 *   challenge.
 * @property subjectDid DID of the subject who answered the challenge.
 * @property capabilityUri The capability URI that was verified.
 * @property challengeType The type of challenge that was verified (a
 *   capability URI string).
 * @property verificationMethod How the capability was verified (unsigned
 *   metadata).
 * @property passed Whether the subject passed the challenge overall.
 * @property score Optional numeric score (0–100) for graded challenges.
 *   Serializes as explicit `null` when absent.
 * @property testCount Total number of test cases in the challenge.
 * @property passCount Number of test cases the subject passed.
 * @property result The challenge-specific result from the response (arbitrary
 *   JSON, unsigned).
 * @property completedAt Unix timestamp (seconds) when the response was
 *   completed (unsigned).
 * @property verifiedAt Unix timestamp (seconds) when the verification was
 *   performed.
 * @property expiresAt Unix timestamp (seconds) when this verification expires.
 * @property contextId Context in which the challenge was issued, if any.
 *   Serializes as explicit `null` when absent.
 * @property verifierSignature Ed25519 signature by the verifier over the
 *   verification record (64 bytes).
 */
@Serializable
data class ChallengeVerification(
    @SerialName("verification_id") val verificationId: String,
    @SerialName("verifier_did") val verifierDid: String,
    @SerialName("subject_did") val subjectDid: String,
    @SerialName("capability_uri") val capabilityUri: String,
    @SerialName("challenge_type") val challengeType: String,
    @SerialName("verification_method") val verificationMethod: ChallengeVerificationMethod,
    val passed: Boolean,
    val score: UInt? = null,
    @SerialName("test_count") val testCount: UInt,
    @SerialName("pass_count") val passCount: UInt,
    val result: JsonElement,
    @SerialName("completed_at") val completedAt: ULong,
    @SerialName("verified_at") val verifiedAt: ULong,
    @SerialName("expires_at") val expiresAt: ULong,
    @SerialName("context_id") val contextId: String? = null,
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
 * Encodes a typed [CapabilityRequirement] list to the JSON wire shape the
 * bridge deserializes (`Vec<CapabilityRequirement>`). [CapabilityRequirement.verificationLevel]
 * serializes as the bare variant string.
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
 * bridge deserializes (`Vec<ChallengeVerification>`). The
 * [ChallengeVerification.verificationMethod] discriminated union is encoded to
 * its serde-tagged shape; [ChallengeVerification.verifierSignature] passes
 * through as a number array; absent `score` / `context_id` serialize as
 * explicit `null`.
 *
 * @throws IllegalArgumentException if [ChallengeVerification.verifierSignature]
 *   is not exactly 64 elements (before any bridge call).
 */
fun encodeChallengeVerificationsJson(verifications: List<ChallengeVerification>): String {
    for (verification in verifications) {
        requireByteLength(
            "ChallengeVerification",
            "verifierSignature",
            BYTES_64,
            verification.verifierSignature,
        )
    }
    return trustAdmissionJson.encodeToString(
        ListSerializer(ChallengeVerification.serializer()),
        verifications,
    )
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
