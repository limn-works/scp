// TrustAdmissionTest.kt — Encoder wire-shape tests for the typed trust-input
// shapes (ADR-058, spec §7.3.2.1 / §7.3.4.4).
//
// These pin the TrustAdmission.kt encoders against the exact
// `serde_json::to_string` shapes the Rust bridge deserializes: bare variant
// strings, `{"<Op>": u64}` thresholds, snake_case struct fields, byte arrays
// as JSON number arrays, and explicit `null` for an absent `retry_cap`. The fixtures mirror the
// TypeScript SDK `trust.test.ts` and Swift SDK `TrustAdmissionTests.swift`
// encoder tests 1:1. Pure serialization logic — no native library required.
// The real call-through against the Rust deserializers lives in
// TrustAdmissionFfiTest.kt (which fails when the native lib is absent or does not load).

package works.limn.scp

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import org.junit.jupiter.api.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

class TrustAdmissionTest {
    /** A structurally-valid profile with real 32/32/64 byte arrays. */
    private fun makeProfile(): ParticipationProfile =
        ParticipationProfile(
            subjectDid = "did:dht:subject",
            participationDurationSecs = 3600uL,
            governanceActionsAgainst = 0uL,
            governanceActionsBy = 1uL,
            outletInvocationCount = 150uL,
            outletInvocationCountAnchored = false,
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
            [{"capability":"scp:capability:messages-write/v1",
              "verification_level":"SelfAttested",
              "trusted_verifiers":[],
              "retry_cap":null},
             {"capability":"scp:capability:schema-validation/v1",
              "verification_level":"ChallengeVerified",
              "trusted_verifiers":["did:dht:zVerifier"],
              "retry_cap":{"max_retries":2,"min_cooldown_secs":60}}]
            """.trimIndent(),
            encodeCapabilityRequirementsJson(
                listOf(
                    CapabilityRequirement(
                        capability = "scp:capability:messages-write/v1",
                        verificationLevel = VerificationLevel.SELF_ATTESTED,
                    ),
                    CapabilityRequirement(
                        capability = "scp:capability:schema-validation/v1",
                        verificationLevel = VerificationLevel.CHALLENGE_VERIFIED,
                        trustedVerifiers = listOf("did:dht:zVerifier"),
                        retryCap = RetryCap(maxRetries = 2u, minCooldownSecs = 60u),
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
                            fact = ParticipationFact.OUTLET_INVOCATION_COUNT,
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
              "outlet_invocation_count":150,
              "outlet_invocation_count_anchored":false,
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

    private val schemaUri = "scp:capability:schema-validation/v1"

    private fun makeVerification(): ChallengeVerification =
        ChallengeVerification(
            verificationId = "ab".repeat(32),
            verifier = "did:dht:zVerifier",
            subject = "did:dht:zResponder",
            capabilityUri = schemaUri,
            definitionDigest = "ef".repeat(32),
            suiteDigest = "cd".repeat(32),
            challengeId = "01".repeat(32),
            attempt = 1u,
            responseDigest = "02".repeat(32),
            maxRetries = 2u,
            cooldownSecs = 60u,
            passThresholdBps = 8_000u,
            minCategoryCases = 1u,
            passed = true,
            score = 10_000u,
            testCount = 20u,
            passCount = 20u,
            challengeCreatedAt = 1_700_000_000uL,
            challengeExpiresAt = 1_700_003_600uL,
            timestamp = 1_700_000_100uL,
            expiresAt = 1_700_086_400uL,
            contextId = "ctx-admission",
            verifierSignature = List(64) { 9.toUByte() },
        )

    private val verificationWire =
        """
        {"verification_id":"${"ab".repeat(32)}",
         "verifier":"did:dht:zVerifier",
         "subject":"did:dht:zResponder",
         "capability_uri":"scp:capability:schema-validation/v1",
         "definition_digest":"${"ef".repeat(32)}",
         "suite_digest":"${"cd".repeat(32)}",
         "challenge_id":"${"01".repeat(32)}",
         "attempt":1,
         "response_digest":"${"02".repeat(32)}",
         "max_retries":2,
         "cooldown_secs":60,
         "pass_threshold_bps":8000,
         "min_category_cases":1,
         "passed":true,
         "score":10000,
         "test_count":20,
         "pass_count":20,
         "challenge_created_at":1700000000,
         "challenge_expires_at":1700003600,
         "timestamp":1700000100,
         "expires_at":1700086400,
         "context_id":"ctx-admission",
         "verifier_signature":${List(64) { 9 }.joinToString(",", "[", "]")}}
        """.trimIndent()

    @Test
    fun `challenge verification encodes the full 23-field snake_case record`() {
        assertJsonEquals("[$verificationWire]", encodeChallengeVerificationsJson(listOf(makeVerification())))
        assertEquals(23, Json.parseToJsonElement(verificationWire).jsonObject.size)
    }

    @Test
    fun `challenge verification decodes the bridge record`() {
        assertEquals(makeVerification(), decodeChallengeVerificationJson(verificationWire))
    }

    @Test
    fun `challenge verification decode refuses a malformed record`() {
        val record = Json.parseToJsonElement(verificationWire).jsonObject

        fun encode(fields: Map<String, JsonElement>): String =
            Json.encodeToString(JsonObject.serializer(), JsonObject(fields))

        fun with(
            key: String,
            value: String,
        ): String = encode(record + (key to Json.parseToJsonElement(value)))
        assertEquals(
            "ChallengeVerification.verificationId must be 64 lowercase hex characters",
            assertFailsWith<IllegalArgumentException> {
                decodeChallengeVerificationJson(with("verification_id", "\"${"AB".repeat(32)}\""))
            }.message,
        )
        assertEquals(
            "ChallengeVerification.responseDigest must be 64 lowercase hex characters",
            assertFailsWith<IllegalArgumentException> {
                decodeChallengeVerificationJson(with("response_digest", "\"02\""))
            }.message,
        )
        assertEquals(
            "ChallengeVerification.score must be in [0, 10000], got 10001",
            assertFailsWith<IllegalArgumentException> {
                decodeChallengeVerificationJson(with("score", "10001"))
            }.message,
        )
        assertEquals(10_000u, decodeChallengeVerificationJson(with("score", "10000")).score)
        // A field the bridge did not write, or one it did write and is gone,
        // fails at the boundary.
        assertFailsWith<IllegalArgumentException> {
            decodeChallengeVerificationJson(with("verification_method", "\"SelfAttested\""))
        }
        assertFailsWith<IllegalArgumentException> {
            decodeChallengeVerificationJson(encode(record - "attempt"))
        }
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

        val verificationError =
            assertFailsWith<IllegalArgumentException> {
                encodeChallengeVerificationsJson(
                    listOf(makeVerification().copy(verifierSignature = List(63) { 9.toUByte() })),
                )
            }
        assertEquals(
            "ChallengeVerification.verifierSignature must be exactly 64 elements, got 63",
            verificationError.message,
        )
        assertEquals(
            "ChallengeVerification.suiteDigest must be 64 lowercase hex characters",
            assertFailsWith<IllegalArgumentException> {
                encodeChallengeVerificationsJson(listOf(makeVerification().copy(suiteDigest = "cd")))
            }.message,
        )
    }

    @Test
    fun `agent capabilities encode as a plain string array`() {
        assertJsonEquals(
            """["scp:capability:messages-write/v1","scp:capability:outlet-invoke/v1"]""",
            encodeAgentCapabilitiesJson(
                listOf(
                    "scp:capability:messages-write/v1",
                    "scp:capability:outlet-invoke/v1",
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
}
