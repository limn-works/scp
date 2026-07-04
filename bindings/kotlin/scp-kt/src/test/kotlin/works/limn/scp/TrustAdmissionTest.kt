// TrustAdmissionTest.kt — Encoder wire-shape tests for the typed trust-input
// shapes (ADR-058, spec §7.3.2.1 / §7.3.4.4).
//
// These pin the TrustAdmission.kt encoders against the exact
// `serde_json::to_string` shapes the Rust bridge deserializes: bare variant
// strings, `{"<Op>": u64}` thresholds, snake_case struct fields, externally
// tagged `verification_method`, byte arrays as JSON number arrays, and
// explicit `null` for absent `score` / `context_id`. The fixtures mirror the
// TypeScript SDK `trust.test.ts` and Swift SDK `TrustAdmissionTests.swift`
// encoder tests 1:1. Pure serialization logic — no native library required.
// The real call-through against the Rust deserializers lives in
// TrustAdmissionFfiTest.kt (which skips when the native lib is absent).

package works.limn.scp

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import org.junit.jupiter.api.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class TrustAdmissionTest {
    /** A structurally-valid profile with real 32/32/64 byte arrays. */
    private fun makeProfile(): ParticipationProfile =
        ParticipationProfile(
            subjectDid = "did:dht:subject",
            participationDurationSecs = 3600uL,
            governanceActionsAgainst = 0uL,
            governanceActionsBy = 1uL,
            toolInvocationCount = 150uL,
            toolInvocationCountAnchored = false,
            contextCreationCount = 2uL,
            roleProgressionCount = 3uL,
            attestationCount = 4uL,
            updatedAt = 1_700_000_000uL,
            eventLogRoot = List(32) { it.toUByte() },
            signerPublicKey = List(32) { (it + 100).toUByte() },
            signature = List(64) { 7.toUByte() },
        )

    /** Asserts two JSON strings are structurally equal (order-independent). */
    private fun assertJsonEquals(
        expected: String,
        actual: String,
    ) {
        assertEquals(Json.parseToJsonElement(expected), Json.parseToJsonElement(actual))
    }

    @Test
    fun `capability requirement encodes snake_case fields and a bare level string`() {
        assertJsonEquals(
            """
            [{"capability":"scp:capability:schema-validation/v1",
              "verification_level":"ChallengeVerified"}]
            """.trimIndent(),
            encodeCapabilityRequirementsJson(
                listOf(
                    CapabilityRequirement(
                        capability = "scp:capability:schema-validation/v1",
                        verificationLevel = VerificationLevel.CHALLENGE_VERIFIED,
                    ),
                ),
            ),
        )
    }

    @Test
    fun `require participation encodes fact, tagged threshold, and snake_case scalars`() {
        assertJsonEquals(
            """
            [{"fact":"GovernanceActionsBy",
              "threshold":{"GreaterThan":5},
              "max_age_secs":604800,
              "min_contexts":3}]
            """.trimIndent(),
            encodeRequireParticipationJson(
                listOf(
                    RequireParticipation(
                        fact = ParticipationFact.GOVERNANCE_ACTIONS_BY,
                        threshold = ParticipationThreshold.GreaterThan(5uL),
                        maxAgeSecs = 604_800uL,
                        minContexts = 3u,
                    ),
                ),
            ),
        )
    }

    @Test
    fun `all five threshold operators encode as single-key tagged objects`() {
        val cases =
            mapOf<ParticipationThreshold, String>(
                ParticipationThreshold.GreaterThan(50uL) to """{"GreaterThan":50}""",
                ParticipationThreshold.LessThan(10uL) to """{"LessThan":10}""",
                ParticipationThreshold.AtLeast(100uL) to """{"AtLeast":100}""",
                ParticipationThreshold.AtMost(5uL) to """{"AtMost":5}""",
                ParticipationThreshold.Equals(0uL) to """{"Equals":0}""",
            )
        for ((threshold, expected) in cases) {
            val encoded =
                encodeRequireParticipationJson(
                    listOf(
                        RequireParticipation(
                            fact = ParticipationFact.TOOL_INVOCATION_COUNT,
                            threshold = threshold,
                            maxAgeSecs = 1uL,
                            minContexts = 1u,
                        ),
                    ),
                )
            val actual = Json.parseToJsonElement(encoded).jsonArray[0].jsonObject["threshold"]
            assertEquals(Json.parseToJsonElement(expected), actual)
        }
    }

    @Test
    fun `participation profile encodes all 13 snake_case fields with number-array bytes`() {
        val encoded = encodeParticipationProfileJson(listOf(makeProfile()))
        assertJsonEquals(
            """
            [{"subject_did":"did:dht:subject",
              "participation_duration_secs":3600,
              "governance_actions_against":0,
              "governance_actions_by":1,
              "tool_invocation_count":150,
              "tool_invocation_count_anchored":false,
              "context_creation_count":2,
              "role_progression_count":3,
              "attestation_count":4,
              "updated_at":1700000000,
              "event_log_root":${(0..31).joinToString(",", "[", "]")},
              "signer_public_key":${(100..131).joinToString(",", "[", "]")},
              "signature":${List(64) { 7 }.joinToString(",", "[", "]")}}]
            """.trimIndent(),
            encoded,
        )
        // Byte arrays keep their exact lengths — the Rust side rejects
        // wrong-length `[u8; 32]` / `[u8; 64]` fields at deserialize time.
        val profile = Json.parseToJsonElement(encoded).jsonArray[0].jsonObject
        assertEquals(32, profile["event_log_root"]?.jsonArray?.size)
        assertEquals(32, profile["signer_public_key"]?.jsonArray?.size)
        assertEquals(64, profile["signature"]?.jsonArray?.size)
    }

    @Test
    fun `challenge verification encodes the full 16-field snake_case record`() {
        val verification =
            ChallengeVerification(
                verificationId = "bridge-test-challenge",
                verifierDid = "did:dht:zVerifier",
                subjectDid = "did:dht:zResponder",
                capabilityUri = "scp:capability:prompt-injection-resistance/v1",
                challengeType = "scp:capability:prompt-injection-resistance/v1",
                verificationMethod =
                    ChallengeVerificationMethod.ChallengeVerified(
                        challengeType = "scp:capability:prompt-injection-resistance/v1",
                    ),
                passed = true,
                testCount = 1u,
                passCount = 1u,
                result = Json.parseToJsonElement("true"),
                completedAt = 1_700_000_000uL,
                verifiedAt = 1_700_000_000uL,
                expiresAt = 4_000_000_000uL,
                contextId = "ctx-admission",
                verifierSignature = List(64) { 9.toUByte() },
            )
        assertJsonEquals(
            """
            [{"verification_id":"bridge-test-challenge",
              "verifier_did":"did:dht:zVerifier",
              "subject_did":"did:dht:zResponder",
              "capability_uri":"scp:capability:prompt-injection-resistance/v1",
              "challenge_type":"scp:capability:prompt-injection-resistance/v1",
              "verification_method":{"ChallengeVerified":
                {"challenge_type":"scp:capability:prompt-injection-resistance/v1"}},
              "passed":true,
              "score":null,
              "test_count":1,
              "pass_count":1,
              "result":true,
              "completed_at":1700000000,
              "verified_at":1700000000,
              "expires_at":4000000000,
              "context_id":"ctx-admission",
              "verifier_signature":${List(64) { 9 }.joinToString(",", "[", "]")}}]
            """.trimIndent(),
            encodeChallengeVerificationsJson(listOf(verification)),
        )
    }

    @Test
    fun `absent score and context_id serialize as explicit JSON null`() {
        val encoded =
            encodeChallengeVerificationsJson(
                listOf(
                    ChallengeVerification(
                        verificationId = "v-1",
                        verifierDid = "did:dht:zVerifier",
                        subjectDid = "did:dht:zResponder",
                        capabilityUri = "scp:capability:tool-integrity/v1",
                        challengeType = "scp:capability:tool-integrity/v1",
                        verificationMethod = ChallengeVerificationMethod.SelfAttested,
                        passed = false,
                        testCount = 3u,
                        passCount = 0u,
                        result = JsonNull,
                        completedAt = 1uL,
                        verifiedAt = 2uL,
                        expiresAt = 3uL,
                        verifierSignature = List(64) { 0.toUByte() },
                    ),
                ),
            )
        val record = Json.parseToJsonElement(encoded).jsonArray[0].jsonObject
        // The keys are PRESENT with JsonNull values — not omitted. The Rust
        // deserializer accepts either shape, but explicit null keeps the wire
        // form identical to the Swift/TypeScript SDK encoders.
        assertTrue(record.containsKey("score"), "score must be present as explicit null")
        assertEquals(JsonNull, record["score"])
        assertTrue(record.containsKey("context_id"), "context_id must be present as explicit null")
        assertEquals(JsonNull, record["context_id"])
        // The SelfAttested method variant is the bare string, not an object.
        assertEquals(Json.parseToJsonElement("\"SelfAttested\""), record["verification_method"])
    }

    @Test
    fun `wrong-length byte arrays throw before any bridge call`() {
        val badProfile = makeProfile().copy(eventLogRoot = List(3) { 1.toUByte() })
        val profileError =
            assertFailsWith<IllegalArgumentException> {
                encodeParticipationProfileJson(listOf(badProfile))
            }
        assertEquals(
            "ParticipationProfile.eventLogRoot must be exactly 32 elements, got 3",
            profileError.message,
        )

        val badVerification =
            ChallengeVerification(
                verificationId = "v-bad",
                verifierDid = "did:dht:zVerifier",
                subjectDid = "did:dht:zResponder",
                capabilityUri = "scp:capability:tool-integrity/v1",
                challengeType = "scp:capability:tool-integrity/v1",
                verificationMethod = ChallengeVerificationMethod.SelfAttested,
                passed = true,
                testCount = 1u,
                passCount = 1u,
                result = JsonNull,
                completedAt = 1uL,
                verifiedAt = 2uL,
                expiresAt = 3uL,
                verifierSignature = List(63) { 9.toUByte() },
            )
        val verificationError =
            assertFailsWith<IllegalArgumentException> {
                encodeChallengeVerificationsJson(listOf(badVerification))
            }
        assertEquals(
            "ChallengeVerification.verifierSignature must be exactly 64 elements, got 63",
            verificationError.message,
        )
    }

    @Test
    fun `agent capabilities encode as a plain string array`() {
        assertJsonEquals(
            """["scp:capability:messages-write/v1","scp:capability:tool-invoke/v1"]""",
            encodeAgentCapabilitiesJson(
                listOf(
                    "scp:capability:messages-write/v1",
                    "scp:capability:tool-invoke/v1",
                ),
            ),
        )
    }

    @Test
    fun `threshold round-trips through decode`() {
        val original =
            RequireParticipation(
                fact = ParticipationFact.ROLE_PROGRESSION_COUNT,
                threshold = ParticipationThreshold.GreaterThan(42uL),
                maxAgeSecs = 10uL,
                minContexts = 3u,
            )
        val encoded = encodeRequireParticipationJson(listOf(original))
        val decoded = Json.decodeFromString<List<RequireParticipation>>(encoded)
        assertEquals(listOf(original), decoded)
    }

    @Test
    fun `verification method round-trips through decode`() {
        val methods =
            listOf(
                ChallengeVerificationMethod.SelfAttested,
                ChallengeVerificationMethod.ChallengeVerified(
                    challengeType = "scp:capability:tool-integrity/v1",
                ),
            )
        for (method in methods) {
            val encoded = Json.encodeToString(ChallengeVerificationMethodSerializer, method)
            val decoded = Json.decodeFromString(ChallengeVerificationMethodSerializer, encoded)
            assertEquals(method, decoded)
        }
    }
}
