// TrustAggregateTest.kt — Encoder wire-shape tests for the typed
// trust-aggregation input shapes (ADR-058, spec §7.3).
//
// These pin the TrustAggregate.kt encoders against the exact
// `serde_json::to_string` shapes the Rust bridge deserializes: snake_case
// struct fields, bare AttestationType map keys, byte arrays as JSON number
// arrays, explicit `null` for an absent attestor attestation, and the Rust
// serde defaults for the ThresholdRequirement penalty fields. The fixtures
// mirror the TypeScript SDK `trust.test.ts` and Swift SDK
// `TrustAggregateTests.swift` encoder tests 1:1. Pure serialization logic —
// no native library required.

package works.limn.scp

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.put
import org.junit.jupiter.api.Test
import uniffi.scp.ScpException
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNull
import kotlin.test.assertTrue

class TrustAggregateTest {
    /** A structurally-valid signed event with real 32/64 byte arrays. */
    private fun makeEvent(
        prevHash: List<UByte> = List(32) { 0.toUByte() },
        signature: List<UByte> = List(64) { 5.toUByte() },
        payloadData: List<UByte> = emptyList(),
    ): EventLogEntry =
        EventLogEntry(
            eventType = "MessageSent",
            actorDid = "did:dht:actor",
            timestamp = 1_700_000_000uL,
            sequence = 0uL,
            payload = EventLogEntryPayload(data = payloadData),
            prevHash = prevHash,
            signature = signature,
        )

    /** Asserts two JSON strings are structurally equal (order-independent). */
    private fun assertJsonEquals(
        expected: String,
        actual: String,
    ) {
        assertEquals(Json.parseToJsonElement(expected), Json.parseToJsonElement(actual))
    }

    @Test
    fun `event log entry encodes the full 7-field snake_case signed event`() {
        assertJsonEquals(
            """
            [{"event_type":"MessageSent",
              "actor_did":"did:dht:actor",
              "timestamp":1700000000,
              "sequence":0,
              "payload":{"data":[1,2,3]},
              "prev_hash":[${(0 until 32).joinToString(",")}],
              "signature":[${List(64) { 5 }.joinToString(",")}]}]
            """.trimIndent(),
            encodeEventLogEntriesJson(
                listOf(
                    makeEvent(
                        prevHash = List(32) { it.toUByte() },
                        payloadData = listOf(1u, 2u, 3u),
                    ),
                ),
            ),
        )
    }

    @Test
    fun `wrong-length event byte arrays throw before any bridge call`() {
        val wrongPrevHash =
            assertFailsWith<IllegalArgumentException> {
                encodeEventLogEntriesJson(
                    listOf(makeEvent(prevHash = listOf(1u, 2u, 3u))),
                )
            }
        assertTrue(
            wrongPrevHash.message!!.contains(
                "EventLogEntry.prevHash must be exactly 32 elements, got 3",
            ),
        )

        val wrongSignature =
            assertFailsWith<IllegalArgumentException> {
                encodeEventLogEntriesJson(
                    listOf(makeEvent(signature = List(63) { 5.toUByte() })),
                )
            }
        assertTrue(
            wrongSignature.message!!.contains(
                "EventLogEntry.signature must be exactly 64 elements, got 63",
            ),
        )
    }

    @Test
    fun `merkle root encodes as a 32-element number array`() {
        assertJsonEquals(
            "[${(0 until 32).joinToString(",")}]",
            encodeMerkleRootJson(List(32) { it.toUByte() }),
        )
    }

    @Test
    fun `wrong-length merkle root throws before any bridge call`() {
        val error =
            assertFailsWith<IllegalArgumentException> {
                encodeMerkleRootJson(listOf(1u, 2u, 3u))
            }
        assertTrue(
            error.message!!.contains(
                "AggregatedTrustInput.merkleRoot must be exactly 32 elements, got 3",
            ),
        )
    }

    @Test
    fun `threshold requirements encode with bare type keys and serde defaults`() {
        assertJsonEquals(
            """
            {"Endorsement":{
              "required_count":2,
              "total_attestors":3,
              "independence_threshold":0.5,
              "shared_context_penalty":0.1,
              "shared_context_penalty_cap":0.5,
              "mutual_endorsement_penalty":0.2}}
            """.trimIndent(),
            encodeThresholdRequirementsJson(
                mapOf(
                    AttestationType.ENDORSEMENT to
                        ThresholdRequirement(
                            requiredCount = 2u,
                            totalAttestors = 3u,
                            independenceThreshold = 0.5,
                        ),
                ),
            ),
        )
    }

    @Test
    fun `all eight attestation types carry the bare PascalCase wire name`() {
        assertEquals(
            setOf(
                "IdentityLink",
                "CapabilityDelegation",
                "OutletIntegrity",
                "AgentCapability",
                "Endorsement",
                "RoleAssignment",
                "ContextEndorsement",
                "ParticipationWitness",
            ),
            AttestationType.entries.map { it.wireName }.toSet(),
        )
    }

    @Test
    fun `attestor info encodes an explicit-null absent attestation`() {
        assertJsonEquals(
            """
            {"Endorsement":[{
              "did":"did:dht:attestor",
              "context_memberships":["ctx-1","ctx-2"],
              "endorsements":["did:dht:other"],
              "attestation":null}]}
            """.trimIndent(),
            encodeAttestorSetsJson(
                mapOf(
                    AttestationType.ENDORSEMENT to
                        listOf(
                            AttestorInfo(
                                did = "did:dht:attestor",
                                contextMemberships = listOf("ctx-1", "ctx-2"),
                                endorsements = listOf("did:dht:other"),
                            ),
                        ),
                ),
            ),
        )
    }

    @Test
    fun `attestor info encodes a nested envelope in the serde snake_case shape`() {
        assertJsonEquals(
            """
            {"Endorsement":[{
              "did":"did:dht:attestor",
              "context_memberships":[],
              "endorsements":[],
              "attestation":{
                "id":"att-1",
                "attestation_type":"Endorsement",
                "issuer":"did:dht:attestor",
                "subject":"did:dht:subject",
                "claim":{"endorsed":true},
                "issued_at":1000,
                "revocation_status":"Active",
                "signature":[1,2,3],
                "evidence":null,
                "expires_at":null,
                "renewal_interval":null,
                "renewed_at":null}}]}
            """.trimIndent(),
            encodeAttestorSetsJson(
                mapOf(
                    AttestationType.ENDORSEMENT to
                        listOf(
                            AttestorInfo(
                                did = "did:dht:attestor",
                                contextMemberships = emptyList(),
                                endorsements = emptyList(),
                                attestation =
                                    CachedAttestationEnvelope(
                                        id = "att-1",
                                        attestationType = "Endorsement",
                                        issuer = "did:dht:attestor",
                                        subject = "did:dht:subject",
                                        claim = buildJsonObject { put("endorsed", true) },
                                        issuedAt = 1000uL,
                                        revocationStatus =
                                            Json.parseToJsonElement("\"Active\""),
                                        signature = listOf(1u, 2u, 3u),
                                    ),
                            ),
                        ),
                ),
            ),
        )
    }
}

class ChallengeTrustInputTest {
    /** A structurally-valid attestation envelope for the verify path. */
    private fun makeEnvelope(): CachedAttestationEnvelope =
        CachedAttestationEnvelope(
            id = "att-1",
            attestationType = "AgentCapability",
            issuer = "did:dht:zIssuer",
            subject = "did:dht:zSubject",
            claim =
                buildJsonObject { put("capability", "scp:capability:schema-validation/v1") },
            issuedAt = 1_700_000_000uL,
            revocationStatus = Json.parseToJsonElement("\"Active\""),
            signature = List(64) { 3.toUByte() },
        )

    /** A structurally-valid ChallengeRequest with a real 64-byte signature. */
    private fun makeChallenge(signature: List<UByte> = List(64) { 8.toUByte() }): ChallengeRequest =
        ChallengeRequest(
            challengeId = "ab".repeat(32),
            capabilityUri = "scp:capability:schema-validation/v1",
            definitionDigest = "ef".repeat(32),
            testCases =
                listOf(
                    ChallengeCase(
                        testId = "t0",
                        input = buildJsonObject { put("i", 0) },
                        category = "basic",
                        weight = 10_000u,
                    ),
                ),
            createdAt = 1_700_000_000uL,
            expiresAt = 1_700_003_600uL,
            maxRetries = 2u,
            cooldownSecs = 60u,
            passThresholdBps = 8_000u,
            contextId = "ctx-challenge",
            verifier = "did:dht:zVerifier",
            subject = "did:dht:zSubject",
            verifierSignature = signature,
        )

    private val challengeWire =
        """
        {"challenge_id":"${"ab".repeat(32)}",
         "capability_uri":"scp:capability:schema-validation/v1",
         "definition_digest":"${"ef".repeat(32)}",
         "test_cases":[{"test_id":"t0","input":{"i":0},"category":"basic",
           "weight":10000}],
         "created_at":1700000000,
         "expires_at":1700003600,
         "max_retries":2,
         "cooldown_secs":60,
         "pass_threshold_bps":8000,
         "context_id":"ctx-challenge",
         "verifier":"did:dht:zVerifier",
         "subject":"did:dht:zSubject",
         "verifier_signature":[${List(64) { 8 }.joinToString(",")}]}
        """.trimIndent()

    /** A structurally-valid ChallengeResponse with a real 64-byte signature. */
    private fun makeResponse(signature: List<UByte> = List(64) { 4.toUByte() }): ChallengeResponse =
        ChallengeResponse(
            challengeId = "ab".repeat(32),
            requestDigest = "12".repeat(32),
            subject = "did:dht:zSubject",
            attempt = 1u,
            outputs = listOf(TestOutput(testId = "t0", output = buildJsonObject { put("ok", true) })),
            subjectSignature = signature,
        )

    private val responseWire =
        """
        {"challenge_id":"${"ab".repeat(32)}",
         "request_digest":"${"12".repeat(32)}",
         "subject":"did:dht:zSubject",
         "attempt":1,
         "outputs":[{"test_id":"t0","output":{"ok":true}}],
         "subject_signature":[${List(64) { 4 }.joinToString(",")}]}
        """.trimIndent()

    /** Asserts two JSON strings are structurally equal (order-independent). */
    private fun assertJsonEquals(
        expected: String,
        actual: String,
    ) {
        assertEquals(Json.parseToJsonElement(expected), Json.parseToJsonElement(actual))
    }

    @Test
    fun `attestation envelope encodes the single serde snake_case shape`() {
        assertJsonEquals(
            """
            {"id":"att-1",
             "attestation_type":"AgentCapability",
             "issuer":"did:dht:zIssuer",
             "subject":"did:dht:zSubject",
             "claim":{"capability":"scp:capability:schema-validation/v1"},
             "issued_at":1700000000,
             "revocation_status":"Active",
             "signature":[${List(64) { 3 }.joinToString(",")}],
             "evidence":null,
             "expires_at":null,
             "renewal_interval":null,
             "renewed_at":null}
            """.trimIndent(),
            encodeAttestationJson(makeEnvelope()),
        )
    }

    @Test
    fun `challenge request encodes the full 13-field snake_case record and decodes back`() {
        assertJsonEquals(challengeWire, encodeChallengeRequestJson(makeChallenge()))
        assertEquals(makeChallenge(), decodeChallengeRequestJson(challengeWire))
    }

    @Test
    fun `challenge request decode refuses an unknown or missing field`() {
        val request = Json.parseToJsonElement(challengeWire).jsonObject

        fun encode(fields: Map<String, JsonElement>): String =
            Json.encodeToString(JsonObject.serializer(), JsonObject(fields))
        assertFailsWith<IllegalArgumentException> {
            decodeChallengeRequestJson(encode(request + ("timeout_secs" to Json.parseToJsonElement("300"))))
        }
        assertFailsWith<IllegalArgumentException> { decodeChallengeRequestJson(encode(request - "definition_digest")) }
        // A case carries no field beyond test_id, input, category and weight.
        assertFailsWith<IllegalArgumentException> {
            decodeChallengeRequestJson(challengeWire.replace("\"weight\":10000}", "\"weight\":10000,\"extra\":\"x\"}"))
        }
    }

    @Test
    fun `every ExpectedOutput variant encodes externally tagged in the test cases`() {
        val variants =
            listOf(
                ExpectedOutput.ExactMatch(Json.parseToJsonElement("[1,\"a\"]")) to
                    """{"ExactMatch":{"value":[1,"a"]}}""",
                ExpectedOutput.SchemaMatch(buildJsonObject { put("type", "object") }) to
                    """{"SchemaMatch":{"schema":{"type":"object"}}}""",
                ExpectedOutput.ContainsAll(listOf("a", "b")) to """{"ContainsAll":{"required":["a","b"]}}""",
                ExpectedOutput.ContainsNone(listOf("x")) to """{"ContainsNone":{"forbidden":["x"]}}""",
                ExpectedOutput.CustomEval(evaluatorOutletId = "o-1", evaluatorContextId = "ctx-eval") to
                    """{"CustomEval":{"evaluator_outlet_id":"o-1"}}""",
            )
        for ((expected, wire) in variants) {
            val case =
                TestCase(
                    testId = "t0",
                    input = buildJsonObject { put("i", 0) },
                    expected = expected,
                    category = "basic",
                    weight = 10_000u,
                )
            assertJsonEquals(
                """[{"test_id":"t0","input":{"i":0},"expected":$wire,"category":"basic","weight":10000}]""",
                encodeTestCasesJson(listOf(case)),
            )
        }
    }

    @Test
    fun `CustomEval cases lift their one evaluator context and refuse two with SCP-VALID-7001`() {
        fun case(
            id: String,
            expected: ExpectedOutput,
        ) = TestCase(
            testId = id,
            input = buildJsonObject { put("i", 0) },
            expected = expected,
            category = "c",
            weight = 1u,
        )
        val exact = case("t0", ExpectedOutput.ExactMatch(buildJsonObject { put("ok", true) }))
        val evalA = case("t1", ExpectedOutput.CustomEval(evaluatorOutletId = "o-1", evaluatorContextId = "ctx-a"))
        val evalA2 = case("t2", ExpectedOutput.CustomEval(evaluatorOutletId = "o-2", evaluatorContextId = "ctx-a"))
        val evalB = case("t3", ExpectedOutput.CustomEval(evaluatorOutletId = "o-1", evaluatorContextId = "ctx-b"))
        assertNull(evaluatorContextOf(listOf(exact)))
        assertEquals("ctx-a", evaluatorContextOf(listOf(exact, evalA, evalA2)))
        val refused = assertFailsWith<ScpException.Validation> { evaluatorContextOf(listOf(evalA, evalB)) }
        assertEquals("SCP-VALID-7001", refused.code)
    }

    @Test
    fun `challenge response encodes the full 6-field snake_case record and decodes back`() {
        assertJsonEquals(responseWire, encodeChallengeResponseJson(makeResponse()))
        assertEquals(makeResponse(), decodeChallengeResponseJson(responseWire))
        assertJsonEquals(
            """[{"test_id":"t0","output":{"ok":true}}]""",
            encodeTestOutputsJson(makeResponse().outputs),
        )
    }

    @Test
    fun `case results decode a reason or its absence and refuse another shape`() {
        assertEquals(
            listOf(CaseResult(passed = true, reason = null), CaseResult(passed = false, reason = "mismatch")),
            decodeCaseResultsJson("""[{"passed":true,"reason":null},{"passed":false,"reason":"mismatch"}]"""),
        )
        assertFailsWith<IllegalArgumentException> { decodeCaseResultsJson("""[{"reason":null}]""") }
        assertFailsWith<IllegalArgumentException> { decodeCaseResultsJson("""{"passed":true}""") }
    }

    @Test
    fun `wrong-length challenge signatures and non-hex ids throw before any bridge call`() {
        assertEquals(
            "ChallengeRequest.verifierSignature must be exactly 64 elements, got 3",
            assertFailsWith<IllegalArgumentException> {
                encodeChallengeRequestJson(makeChallenge(signature = listOf(1u, 2u, 3u)))
            }.message,
        )
        assertEquals(
            "ChallengeRequest.challengeId must be 64 lowercase hex characters",
            assertFailsWith<IllegalArgumentException> {
                encodeChallengeRequestJson(makeChallenge().copy(challengeId = "chal-1"))
            }.message,
        )
        assertEquals(
            "ChallengeResponse.subjectSignature must be exactly 64 elements, got 63",
            assertFailsWith<IllegalArgumentException> {
                encodeChallengeResponseJson(makeResponse(signature = List(63) { 4.toUByte() }))
            }.message,
        )
        assertEquals(
            "ChallengeResponse.requestDigest must be 64 lowercase hex characters",
            assertFailsWith<IllegalArgumentException> {
                encodeChallengeResponseJson(makeResponse().copy(requestDigest = "12"))
            }.message,
        )
    }
}
