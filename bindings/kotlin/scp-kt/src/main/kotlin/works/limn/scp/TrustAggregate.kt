// TrustAggregate.kt — Typed Kotlin SDK shapes for the trust-aggregation and
// challenge trust-input surfaces (ADR-058, Ops C/D of the typed trust-input
// convention).
//
// Mirrors `scp_event_log::Event` and `scp_protocol::trust::{attestation,
// aggregate, challenge}`: EventLogEntry (§7.3 aggregation events),
// AttestationType / ThresholdRequirement / AttestorInfo (§7.3.5 threshold
// verification). The SDK exposes typed shapes (no stringly-typed JSON) and
// serializes to the Rust serde wire format at the bridge boundary —
// [SCP.aggregateTrustInput] in SCP.kt calls the encoders below before
// crossing FFI. Models are plain data classes with `buildJsonObject` encoders
// (the Trust.kt cached-attestation family convention) because they interlock
// with [CachedAttestationEnvelope]; freeform fields are [JsonElement].
// Mirrors the Swift SDK `Trust.swift` aggregation types and the TypeScript
// SDK `types.ts` aggregation types field-for-field.
//
// Provenance: ADR-058 (.docs/adrs/ADR-058-typed-sdk-trust-input-surface.md),
// spec §7.3 (.docs/specs/07-trust-validation-and-capabilities.md), ADR-017 /
// ADR-011 (.docs/adrs/phase-4.md, phase-2.md).

package works.limn.scp

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.add
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put

/**
 * Attestation type (ADR-017).
 *
 * Mirrors the Rust `AttestationType` enum (`scp-core`) — the 8 unit variants
 * serialize as bare PascalCase strings ([wireName]), both as values and as
 * the `thresholdRequirements` / `attestorSets` map keys. Mirrors the Swift
 * SDK `AttestationType` enum and the TypeScript SDK `AttestationType` union
 * 1:1.
 *
 * @property wireName The serde-canonical variant string on the wire.
 */
enum class AttestationType(val wireName: String) {
    /** Links an identity to an external identifier. */
    IDENTITY_LINK("IdentityLink"),

    /** Delegates a capability to another DID. */
    CAPABILITY_DELEGATION("CapabilityDelegation"),

    /** Attests to the integrity of a outlet. */
    OUTLET_INTEGRITY("OutletIntegrity"),

    /** Attests to an agent's capability. */
    AGENT_CAPABILITY("AgentCapability"),

    /** A general endorsement. */
    ENDORSEMENT("Endorsement"),

    /** Assigns a role to a DID. */
    ROLE_ASSIGNMENT("RoleAssignment"),

    /** Endorses a context. */
    CONTEXT_ENDORSEMENT("ContextEndorsement"),

    /** Witnesses participation facts. */
    PARTICIPATION_WITNESS("ParticipationWitness"),
}

/**
 * Type-specific data carried by an [EventLogEntry].
 *
 * Mirrors the Rust `EventPayload` (`scp-event-log`): opaque payload bytes as
 * a JSON number array. An empty [data] list is the canonical representation
 * for non-parameterized events.
 *
 * @property data Opaque payload bytes. Interpretation depends on the event type.
 */
data class EventLogEntryPayload(
    val data: List<UByte>,
)

/**
 * A full signed protocol event in a context event log (ADR-011).
 *
 * The serde wire shape of the Rust `Event` (`scp-event-log`) the bridge
 * deserializes for [SCP.aggregateTrustInput] (`Vec<Event>`) — the INPUT wire
 * form, distinct from the projected event the event-log query surface returns
 * (which omits the hash-chain and signature fields). Mirrors the Swift SDK
 * `EventLogEntry` and the TypeScript/Python models 1:1.
 *
 * @property eventType Event type — a Rust `EventType` variant name (e.g.
 *   `"MessageSent"`).
 * @property actorDid DID of the actor who produced this event.
 * @property timestamp Unix timestamp (seconds) when the event was created.
 * @property sequence Monotonic event sequence number within the log
 *   (0-indexed).
 * @property payload Type-specific event data.
 * @property prevHash SHA-256 hash of the previous event (hash chain), exactly
 *   32 bytes. All zeros for the first event (genesis sentinel).
 * @property signature Ed25519 signature over the serialized event content
 *   (64 bytes).
 */
data class EventLogEntry(
    val eventType: String,
    val actorDid: String,
    val timestamp: ULong,
    val sequence: ULong,
    val payload: EventLogEntryPayload,
    val prevHash: List<UByte>,
    val signature: List<UByte>,
)

/** Rust serde default for `ThresholdRequirement.shared_context_penalty`. */
private const val DEFAULT_SHARED_CONTEXT_PENALTY = 0.1

/** Rust serde default for `ThresholdRequirement.shared_context_penalty_cap`. */
private const val DEFAULT_SHARED_CONTEXT_PENALTY_CAP = 0.5

/** Rust serde default for `ThresholdRequirement.mutual_endorsement_penalty`. */
private const val DEFAULT_MUTUAL_ENDORSEMENT_PENALTY = 0.2

/**
 * N-of-M threshold requirement for attestation verification (ADR-017 §7.3.5).
 *
 * Mirrors the Rust `ThresholdRequirement` struct (`scp-core`). The three
 * penalty properties default to the Rust serde defaults (0.1 / 0.5 / 0.2) and
 * are always emitted explicitly, so the wire form is identical across
 * bindings. Mirrors the Swift SDK `ThresholdRequirement` and the
 * TypeScript/Python models 1:1.
 *
 * @property requiredCount The minimum number of valid attestations required (N).
 * @property totalAttestors The total number of attestors in the set (M). Must
 *   be >= [requiredCount].
 * @property independenceThreshold Minimum independence score, in [0.0, 1.0].
 * @property sharedContextPenalty Independence penalty per shared context
 *   membership. Default: 0.1.
 * @property sharedContextPenaltyCap Maximum total shared-context penalty for
 *   a single pair. Default: 0.5.
 * @property mutualEndorsementPenalty Independence penalty per mutual
 *   endorsement direction. Default: 0.2.
 */
data class ThresholdRequirement(
    val requiredCount: UInt,
    val totalAttestors: UInt,
    val independenceThreshold: Double,
    val sharedContextPenalty: Double = DEFAULT_SHARED_CONTEXT_PENALTY,
    val sharedContextPenaltyCap: Double = DEFAULT_SHARED_CONTEXT_PENALTY_CAP,
    val mutualEndorsementPenalty: Double = DEFAULT_MUTUAL_ENDORSEMENT_PENALTY,
)

/**
 * Information about an attestor used for independence scoring (ADR-017
 * §7.3.5).
 *
 * Mirrors the Rust `AttestorInfo` struct (`scp-core`). The optional
 * [attestation] is a full attestation envelope
 * ([CachedAttestationEnvelope]); only attestations matching the required type
 * are considered. An absent attestation encodes as explicit JSON `null`
 * (matching `serde_json::to_string` of the Rust `Option<Attestation>`).
 *
 * @property did The DID of the attestor.
 * @property contextMemberships Context IDs the attestor is a member of.
 * @property endorsements DIDs this attestor has endorsed (mutual endorsements
 *   reduce independence).
 * @property attestation The attestation provided by this attestor, if any.
 */
data class AttestorInfo(
    val did: String,
    val contextMemberships: List<String>,
    val endorsements: List<String>,
    val attestation: CachedAttestationEnvelope? = null,
)

/** Expected element count of a 32-byte field (Rust `[u8; 32]`). */
private const val AGGREGATE_BYTES_32 = 32

/** Expected element count of a 64-byte field (Rust Ed25519 signature). */
private const val AGGREGATE_BYTES_64 = 64

/**
 * Throws [IllegalArgumentException] when a fixed-length byte-array field has
 * the wrong number of elements, so a malformed aggregation input fails at
 * encode time with a field-named error instead of surfacing as a Rust
 * deserialization (or silent verification) failure after the bridge call.
 * Mirrors the TrustAdmission.kt check (ADR-058 misuse resistance).
 */
private fun requireAggregateByteLength(
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
 * Encodes a typed [EventLogEntry] list to the JSON wire shape the bridge
 * deserializes (`Vec<scp_event_log::Event>`). Byte-array fields pass through
 * as JSON number arrays.
 *
 * @throws IllegalArgumentException if [EventLogEntry.prevHash] is not exactly
 *   32 elements or [EventLogEntry.signature] is not exactly 64 elements
 *   (before any bridge call).
 */
fun encodeEventLogEntriesJson(events: List<EventLogEntry>): String {
    for (event in events) {
        requireAggregateByteLength("EventLogEntry", "prevHash", AGGREGATE_BYTES_32, event.prevHash)
        requireAggregateByteLength(
            "EventLogEntry",
            "signature",
            AGGREGATE_BYTES_64,
            event.signature,
        )
    }
    return Json.encodeToString(
        JsonArray.serializer(),
        buildJsonArray { events.forEach { add(encodeEventLogEntryElement(it)) } },
    )
}

private fun encodeEventLogEntryElement(event: EventLogEntry): JsonObject =
    buildJsonObject {
        put("event_type", event.eventType)
        put("actor_did", event.actorDid)
        put("timestamp", event.timestamp.toLong())
        put("sequence", event.sequence.toLong())
        put(
            "payload",
            buildJsonObject {
                put("data", buildJsonArray { event.payload.data.forEach { add(it.toInt()) } })
            },
        )
        put("prev_hash", buildJsonArray { event.prevHash.forEach { add(it.toInt()) } })
        put("signature", buildJsonArray { event.signature.forEach { add(it.toInt()) } })
    }

/**
 * Encodes a 32-byte Merkle root to the JSON wire shape the bridge
 * deserializes (`[u8; 32]` as a number array).
 *
 * @throws IllegalArgumentException if [merkleRoot] is not exactly 32 elements
 *   (before any bridge call).
 */
fun encodeMerkleRootJson(merkleRoot: List<UByte>): String {
    requireAggregateByteLength(
        "AggregatedTrustInput",
        "merkleRoot",
        AGGREGATE_BYTES_32,
        merkleRoot,
    )
    return Json.encodeToString(
        JsonArray.serializer(),
        buildJsonArray { merkleRoot.forEach { add(it.toInt()) } },
    )
}

/**
 * Encodes a typed per-[AttestationType] [ThresholdRequirement] map to the
 * JSON wire shape the bridge deserializes
 * (`HashMap<AttestationType, ThresholdRequirement>`). Map keys are the bare
 * variant strings; the three penalty fields are always emitted explicitly
 * (the Rust serde defaults when not overridden).
 */
fun encodeThresholdRequirementsJson(requirements: Map<AttestationType, ThresholdRequirement>): String =
    Json.encodeToString(
        JsonObject.serializer(),
        buildJsonObject {
            requirements.forEach { (attestationType, requirement) ->
                put(
                    attestationType.wireName,
                    buildJsonObject {
                        put("required_count", requirement.requiredCount.toLong())
                        put("total_attestors", requirement.totalAttestors.toLong())
                        put("independence_threshold", requirement.independenceThreshold)
                        put("shared_context_penalty", requirement.sharedContextPenalty)
                        put("shared_context_penalty_cap", requirement.sharedContextPenaltyCap)
                        put("mutual_endorsement_penalty", requirement.mutualEndorsementPenalty)
                    },
                )
            }
        },
    )

/**
 * Encodes a typed per-[AttestationType] [AttestorInfo] map to the JSON wire
 * shape the bridge deserializes
 * (`HashMap<AttestationType, Vec<AttestorInfo>>`). Map keys are the bare
 * variant strings; a nested attestation envelope (when present) is encoded
 * exactly as [encodeCachedAttestationsJson] encodes it, and an absent one
 * encodes as explicit `null`.
 */
fun encodeAttestorSetsJson(attestorSets: Map<AttestationType, List<AttestorInfo>>): String =
    Json.encodeToString(
        JsonObject.serializer(),
        buildJsonObject {
            attestorSets.forEach { (attestationType, attestors) ->
                put(
                    attestationType.wireName,
                    buildJsonArray { attestors.forEach { add(encodeAttestorInfoElement(it)) } },
                )
            }
        },
    )

private fun encodeAttestorInfoElement(attestor: AttestorInfo): JsonObject =
    buildJsonObject {
        put("did", attestor.did)
        put(
            "context_memberships",
            buildJsonArray { attestor.contextMemberships.forEach { add(it) } },
        )
        put("endorsements", buildJsonArray { attestor.endorsements.forEach { add(it) } })
        put("attestation", encodeOptionalEnvelopeElement(attestor.attestation))
    }

private fun encodeOptionalEnvelopeElement(envelope: CachedAttestationEnvelope?): JsonElement =
    if (envelope == null) {
        JsonNull
    } else {
        encodeEnvelopeElement(envelope)
    }

// ---------------------------------------------------------------------------
// Challenge trust inputs (§7.3.4, ADR-058)
// ---------------------------------------------------------------------------

/**
 * The error code the bridges raise when a challenge for a protocol capability
 * URI has fewer test cases than its standard's minimum (spec 07 §7.3.4.3).
 */
const val CHALLENGE_SUITE_BELOW_MINIMUM_CODE: String = "SCP-VALID-7039"

/**
 * How a test case's output is judged (spec 07 §7.3.4.2).
 *
 * Encodes to the Rust `ExpectedOutput` enum's externally tagged serde shape,
 * for example `{"ExactMatch":{"value":...}}`. Mirrors the Swift SDK
 * `ExpectedOutput`, the TypeScript `ExpectedOutput` union and the Python
 * variant classes 1:1.
 */
sealed class ExpectedOutput {
    /** The output must equal [value]. */
    data class ExactMatch(val value: JsonElement) : ExpectedOutput()

    /** The output must validate against the JSON Schema [schema]. */
    data class SchemaMatch(val schema: JsonElement) : ExpectedOutput()

    /** The output must contain every string in [required]. */
    data class ContainsAll(val required: List<String>) : ExpectedOutput()

    /** The output must contain none of the strings in [forbidden]. */
    data class ContainsNone(val forbidden: List<String>) : ExpectedOutput()

    /** An outlet the verifier names judges the output. */
    data class CustomEval(val evaluatorOutletId: String) : ExpectedOutput()
}

/**
 * One challenger-written test case (spec 07 §7.3.4.2).
 *
 * @property testId Identifier unique within the challenge.
 * @property input The input the subject runs.
 * @property expected How the output is judged.
 * @property category The case's category; a BCP 47 language tag for
 *   `multilingual/v1`.
 * @property weight The case's weight in basis points; a protocol suite's
 *   weights sum to 10000.
 */
data class TestCase(
    val testId: String,
    val input: JsonElement,
    val expected: ExpectedOutput,
    val category: String,
    val weight: UInt,
)

/**
 * A signed challenge request (ADR-017, spec 07 §7.3.4).
 *
 * [SCP.trustCreateChallenge] returns one as JSON; [decodeChallengeRequestJson]
 * reads it and [encodeChallengeRequestJson] writes the serde wire shape
 * [SCP.trustVerifyResponse] takes. Mirrors the Swift SDK `ChallengeRequest` and
 * the TypeScript and Python models 1:1.
 *
 * @property challengeId 64 lowercase hex characters (32 random bytes).
 * @property capabilityUri The capability URI being tested (§7.3.4.1).
 * @property testCases The challenger-written test cases.
 * @property timeoutSecs Seconds the subject has to respond.
 * @property verifier DID of the verifier issuing the challenge.
 * @property subject DID of the entity being challenged.
 * @property verifierSignature Ed25519 signature by the verifier's `#active`
 *   key over the request digest (64 bytes).
 */
data class ChallengeRequest(
    val challengeId: String,
    val capabilityUri: String,
    val testCases: List<TestCase>,
    val timeoutSecs: UInt,
    val verifier: String,
    val subject: String,
    val verifierSignature: List<UByte>,
)

/**
 * A response to a challenge request (ADR-017, spec §7.3.4).
 *
 * The serde wire shape of the Rust `ChallengeResponse` (`scp-core`) the
 * bridge deserializes for [SCP.trustVerifyResponse]. Mirrors the Swift SDK
 * `ChallengeResponse` and the TypeScript/Python models 1:1.
 *
 * @property challengeId The challenge id this response answers: 64 lowercase
 *   hex characters.
 * @property responderDid DID of the entity responding to the challenge.
 * @property result Challenge-specific result data (pass/fail, metrics,
 *   evidence, etc.).
 * @property completedAt Unix timestamp (seconds) when the response was
 *   completed.
 * @property signature Ed25519 signature over the canonical response bytes
 *   (64 bytes).
 */
data class ChallengeResponse(
    val challengeId: String,
    val responderDid: String,
    val result: JsonElement,
    val completedAt: ULong,
    val signature: List<UByte>,
)

/**
 * Encodes a single typed attestation envelope ([CachedAttestationEnvelope])
 * to the JSON wire shape the bridge deserializes for
 * [SCP.trustVerifyAttestation] (`Attestation`) — exactly the shape
 * [encodeCachedAttestationsJson] nests per entry.
 */
fun encodeAttestationJson(attestation: CachedAttestationEnvelope): String =
    Json.encodeToString(JsonObject.serializer(), encodeEnvelopeElement(attestation))

private const val HEX_32_LENGTH = 64

/**
 * Requires [value] to be 64 lowercase hex characters, the wire form of a
 * 32-byte challenge id, verification id or suite digest.
 *
 * @throws IllegalArgumentException naming `typeName.fieldName` otherwise.
 */
internal fun requireLowerHex32(
    typeName: String,
    fieldName: String,
    value: String,
) {
    require(value.length == HEX_32_LENGTH && value.all { it in '0'..'9' || it in 'a'..'f' }) {
        "$typeName.$fieldName must be 64 lowercase hex characters"
    }
}

private fun encodeExpectedOutputElement(expected: ExpectedOutput): JsonObject =
    when (expected) {
        is ExpectedOutput.ExactMatch ->
            buildJsonObject { put("ExactMatch", buildJsonObject { put("value", expected.value) }) }
        is ExpectedOutput.SchemaMatch ->
            buildJsonObject { put("SchemaMatch", buildJsonObject { put("schema", expected.schema) }) }
        is ExpectedOutput.ContainsAll ->
            buildJsonObject {
                put(
                    "ContainsAll",
                    buildJsonObject {
                        put("required", buildJsonArray { expected.required.forEach { add(it) } })
                    },
                )
            }
        is ExpectedOutput.ContainsNone ->
            buildJsonObject {
                put(
                    "ContainsNone",
                    buildJsonObject {
                        put("forbidden", buildJsonArray { expected.forbidden.forEach { add(it) } })
                    },
                )
            }
        is ExpectedOutput.CustomEval ->
            buildJsonObject {
                put(
                    "CustomEval",
                    buildJsonObject { put("evaluator_outlet_id", expected.evaluatorOutletId) },
                )
            }
    }

private fun encodeTestCasesElement(testCases: List<TestCase>): JsonArray =
    buildJsonArray {
        for (case in testCases) {
            add(
                buildJsonObject {
                    put("test_id", case.testId)
                    put("input", case.input)
                    put("expected", encodeExpectedOutputElement(case.expected))
                    put("category", case.category)
                    put("weight", case.weight.toLong())
                },
            )
        }
    }

/**
 * Encodes typed test cases to the JSON array [SCP.trustCreateChallenge] passes
 * to the bridge (`Vec<TestCase>`).
 */
fun encodeTestCasesJson(testCases: List<TestCase>): String {
    val element = encodeTestCasesElement(testCases)
    return Json.encodeToString(JsonArray.serializer(), element)
}

/**
 * Encodes a typed [ChallengeRequest] to the JSON wire shape the bridge
 * deserializes (`ChallengeRequest`).
 *
 * @throws IllegalArgumentException if [ChallengeRequest.verifierSignature] is
 *   not exactly 64 elements or [ChallengeRequest.challengeId] is not 64
 *   lowercase hex characters (before any bridge call).
 */
fun encodeChallengeRequestJson(challenge: ChallengeRequest): String {
    requireLowerHex32("ChallengeRequest", "challengeId", challenge.challengeId)
    requireAggregateByteLength(
        "ChallengeRequest",
        "verifierSignature",
        AGGREGATE_BYTES_64,
        challenge.verifierSignature,
    )
    return Json.encodeToString(
        JsonObject.serializer(),
        buildJsonObject {
            put("challenge_id", challenge.challengeId)
            put("capability_uri", challenge.capabilityUri)
            put("test_cases", encodeTestCasesElement(challenge.testCases))
            put("timeout_secs", challenge.timeoutSecs.toLong())
            put("verifier", challenge.verifier)
            put("subject", challenge.subject)
            put(
                "verifier_signature",
                buildJsonArray { challenge.verifierSignature.forEach { add(it.toInt()) } },
            )
        },
    )
}

private fun JsonObject.field(
    typeName: String,
    name: String,
): JsonElement = this[name] ?: throw IllegalArgumentException("$typeName.$name is missing")

private fun JsonElement.string(path: String): String {
    val primitive = this as? JsonPrimitive
    require(primitive != null && primitive.isString) { "$path must be a string" }
    return primitive.content
}

private fun JsonElement.uint(path: String): UInt {
    val value = (this as? JsonPrimitive)?.takeIf { !it.isString }?.content?.toUIntOrNull()
    return requireNotNull(value) { "$path must be an unsigned 32-bit integer" }
}

private fun JsonElement.obj(path: String): JsonObject {
    require(this is JsonObject) { "$path must be an object" }
    return this
}

private fun JsonElement.array(path: String): JsonArray {
    require(this is JsonArray) { "$path must be an array" }
    return this
}

private fun decodeExpectedOutput(element: JsonElement): ExpectedOutput {
    val tagged = element.obj("TestCase.expected")
    require(tagged.size == 1) { "TestCase.expected must have exactly one variant key" }
    val (variant, body) = tagged.entries.first()
    val fields = body.obj("TestCase.expected.$variant")
    return when (variant) {
        "ExactMatch" -> ExpectedOutput.ExactMatch(fields.field(variant, "value"))
        "SchemaMatch" -> ExpectedOutput.SchemaMatch(fields.field(variant, "schema"))
        "ContainsAll" ->
            ExpectedOutput.ContainsAll(
                fields.field(variant, "required").array("$variant.required").map {
                    it.string("$variant.required[]")
                },
            )
        "ContainsNone" ->
            ExpectedOutput.ContainsNone(
                fields.field(variant, "forbidden").array("$variant.forbidden").map {
                    it.string("$variant.forbidden[]")
                },
            )
        "CustomEval" ->
            ExpectedOutput.CustomEval(
                fields.field(variant, "evaluator_outlet_id").string("$variant.evaluator_outlet_id"),
            )
        else -> throw IllegalArgumentException("unknown ExpectedOutput variant \"$variant\"")
    }
}

private const val BYTE_MAX = 255u

/**
 * Decodes the challenge JSON [SCP.trustCreateChallenge] returns into a typed
 * [ChallengeRequest].
 *
 * @throws IllegalArgumentException if the JSON is not a challenge request, an
 *   expected output names an unknown variant, the id is not 64 lowercase hex
 *   characters, or the signature is not 64 bytes.
 */
fun decodeChallengeRequestJson(json: String): ChallengeRequest {
    val root =
        try {
            Json.parseToJsonElement(json)
        } catch (e: kotlinx.serialization.SerializationException) {
            throw IllegalArgumentException("malformed ChallengeRequest JSON: ${e.message}", e)
        }.obj("ChallengeRequest")
    val type = "ChallengeRequest"
    val testCases =
        root.field(type, "test_cases").array("$type.test_cases").map { element ->
            val case = element.obj("$type.test_cases[]")
            TestCase(
                testId = case.field("TestCase", "test_id").string("TestCase.test_id"),
                input = case.field("TestCase", "input"),
                expected = decodeExpectedOutput(case.field("TestCase", "expected")),
                category = case.field("TestCase", "category").string("TestCase.category"),
                weight = case.field("TestCase", "weight").uint("TestCase.weight"),
            )
        }
    val signature =
        root.field(type, "verifier_signature").array("$type.verifier_signature").map {
            val byte = it.uint("$type.verifier_signature[]")
            require(byte <= BYTE_MAX) { "$type.verifier_signature[] must be a byte" }
            byte.toUByte()
        }
    val request =
        ChallengeRequest(
            challengeId = root.field(type, "challenge_id").string("$type.challenge_id"),
            capabilityUri = root.field(type, "capability_uri").string("$type.capability_uri"),
            testCases = testCases,
            timeoutSecs = root.field(type, "timeout_secs").uint("$type.timeout_secs"),
            verifier = root.field(type, "verifier").string("$type.verifier"),
            subject = root.field(type, "subject").string("$type.subject"),
            verifierSignature = signature,
        )
    requireLowerHex32(type, "challengeId", request.challengeId)
    requireAggregateByteLength(type, "verifierSignature", AGGREGATE_BYTES_64, request.verifierSignature)
    return request
}

/**
 * Encodes a typed [ChallengeResponse] to the JSON wire shape the bridge
 * deserializes (`ChallengeResponse`).
 *
 * @throws IllegalArgumentException if [ChallengeResponse.signature] is not
 *   exactly 64 elements (before any bridge call).
 */
fun encodeChallengeResponseJson(response: ChallengeResponse): String {
    requireAggregateByteLength(
        "ChallengeResponse",
        "signature",
        AGGREGATE_BYTES_64,
        response.signature,
    )
    return Json.encodeToString(
        JsonObject.serializer(),
        buildJsonObject {
            put("challenge_id", response.challengeId)
            put("responder_did", response.responderDid)
            put("result", response.result)
            put("completed_at", response.completedAt.toLong())
            put("signature", buildJsonArray { response.signature.forEach { add(it.toInt()) } })
        },
    )
}
