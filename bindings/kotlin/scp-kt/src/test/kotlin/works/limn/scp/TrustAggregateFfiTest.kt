// TrustAggregateFfiTest.kt — Real-FFI call-through tests for the typed
// trust-aggregation wrapper (ADR-058, spec §7.3).
//
// These invoke the bridge `aggregate_trust_input` op through the typed
// [SCP.aggregateTrustInput] wrapper, proving the TrustAggregate.kt-serialized
// JSON parses and evaluates on the real Rust deserializers — not just that
// the encoders emit the pinned shapes (TrustAggregateTest.kt covers that
// without the native lib).
//
// All tests require the compiled UniFFI cdylib. A cdylib that is absent or fails
// to load throws `UnsatisfiedLinkError` from the first native call and fails the
// test.

package works.limn.scp

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.put
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import uniffi.scp.ScpException
import uniffi.scp.StorageConfig
import works.limn.scp.bridge.CoroutineBridge
import works.limn.scp.conformance.ConformanceStubBindings
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds

class TrustAggregateFfiTest {
    private lateinit var scp: SCP

    private fun bridge(): CoroutineBridge =
        CoroutineBridge(
            nativeBindings = ConformanceStubBindings(),
            ioDispatcher = Dispatchers.IO,
            cpuDispatcher = Dispatchers.Default,
        )

    @BeforeEach
    fun setUp() {
        scp = SCP(StorageConfig.InMemory)
    }

    @AfterEach
    fun tearDown() {
        if (!this::scp.isInitialized) return
        runBlocking { scp.shutdown(bridge(), 1.seconds) }
    }

    /** A genesis `MemberJoined` event for the aggregated subject. */
    private fun genesisMemberJoined(): EventLogEntry =
        EventLogEntry(
            eventType = "MemberJoined",
            actorDid = "did:dht:zSubject",
            timestamp = 1_700_000_000uL,
            sequence = 0uL,
            payload = EventLogEntryPayload(data = emptyList()),
            prevHash = List(32) { 0.toUByte() },
            signature = List(64) { 0.toUByte() },
        )

    /**
     * A minimal typed aggregation (one genesis event, all-zero root, every
     * optional collection defaulted) crosses FFI and returns the aggregated
     * `TrustInput` JSON — proving the typed wrapper's serialized event and
     * `[]` / `{}` wire values parse on the real Rust deserializers.
     */
    @Test
    fun `aggregateTrustInput - typed inputs cross FFI and aggregate`() {
        val resultJson =
            runBlocking {
                scp.aggregateTrustInput(
                    contextId = "ctx-aggregate-ffi",
                    subjectDid = "did:dht:zSubject",
                    events = listOf(genesisMemberJoined()),
                    merkleRoot = List(32) { 0.toUByte() },
                )
            }
        val result = Json.parseToJsonElement(resultJson).jsonObject
        assertTrue("participation_record" in result, "missing participation_record: $resultJson")
        assertTrue("challenge_results" in result, "missing challenge_results: $resultJson")
    }

    /**
     * Typed threshold requirements and attestor sets (bare AttestationType
     * map keys, serde-default penalty fields, explicit-null attestor
     * attestation) parse on the real Rust `HashMap<AttestationType, _>`
     * deserializers.
     */
    @Test
    fun `aggregateTrustInput - typed threshold and attestor maps cross FFI`() {
        val resultJson =
            runBlocking {
                scp.aggregateTrustInput(
                    contextId = "ctx-aggregate-ffi",
                    subjectDid = "did:dht:zSubject",
                    events = listOf(genesisMemberJoined()),
                    merkleRoot = List(32) { 0.toUByte() },
                    thresholdRequirements =
                        mapOf(
                            AttestationType.ENDORSEMENT to
                                ThresholdRequirement(
                                    requiredCount = 1u,
                                    totalAttestors = 1u,
                                    independenceThreshold = 0.0,
                                ),
                        ),
                    attestorSets =
                        mapOf(
                            AttestationType.ENDORSEMENT to
                                listOf(
                                    AttestorInfo(
                                        did = "did:dht:zAttestor",
                                        contextMemberships = listOf("ctx-aggregate-ffi"),
                                        endorsements = emptyList(),
                                    ),
                                ),
                        ),
                )
            }
        val result = Json.parseToJsonElement(resultJson).jsonObject
        assertTrue("threshold_counts" in result, "missing threshold_counts: $resultJson")
    }

    // -----------------------------------------------------------------------
    // Challenge trust inputs (§7.3.4, ADR-058 Op D)
    // -----------------------------------------------------------------------

    /** A typed envelope whose 64-byte signature is all zeros. */
    private fun zeroSignedAttestation(issuer: String): CachedAttestationEnvelope =
        CachedAttestationEnvelope(
            id = "att-ffi-1",
            attestationType = "AgentCapability",
            issuer = issuer,
            subject = "did:dht:zSubject",
            claim =
                buildJsonObject {
                    put("capability", "scp:capability:schema-validation/v1")
                },
            issuedAt = 1_700_000_000uL,
            revocationStatus = Json.parseToJsonElement("\"Active\""),
            signature = List(64) { 0.toUByte() },
        )

    /**
     * An instance with no identity has no DID resolver, so the issuer's
     * `#active` key cannot be resolved: a coded SCP-VALID-7052 error, never a
     * verdict. The issuer DID in the message proves the typed envelope parsed
     * on the real Rust deserializer (a parse failure is SCP-VALID-7012).
     */
    @Test
    fun `trustVerifyAttestation - without a DID resolver fails closed with SCP-VALID-7052`() {
        runBlocking {
            val error =
                assertFailsWith<ScpException.Validation> {
                    scp.trustVerifyAttestation("ctx-ffi-1", zeroSignedAttestation("did:dht:zIssuer"))
                }
            assertEquals("SCP-VALID-7052", error.code)
            assertTrue(error.message.orEmpty().contains("did:dht:zIssuer"))
        }
    }

    /**
     * An issuer that resolves on this instance reaches the real verifier: a
     * dummy signature yields a structured `valid = false` verdict.
     */
    @Test
    fun `trustVerifyAttestation - resolvable issuer with a bad signature is valid false`() {
        runBlocking {
            val issuer = scp.identityCreateInMemory()
            val result = scp.trustVerifyAttestation("ctx-ffi-1", zeroSignedAttestation(issuer.did()))
            assertFalse(result.valid)
            assertTrue(result.errorMessage.contains("signature"))
        }
    }

    private val schemaUri = "scp:capability:schema-validation/v1"

    /** [n] exact-match cases whose weights sum to 10000. */
    private fun testCases(n: Int): List<TestCase> {
        val weight = 10_000 / n
        return List(n) { i ->
            TestCase(
                testId = "t$i",
                input = buildJsonObject { put("i", i) },
                expected = ExpectedOutput.ExactMatch(buildJsonObject { put("ok", true) }),
                category = "basic",
                weight = (if (i == 0) 10_000 - weight * (n - 1) else weight).toUInt(),
            )
        }
    }

    /** A protocol suite one case short of its standard's minimum is refused. */
    @Test
    fun `trustCreateChallenge - suite below minimum is SCP-VALID-7039`() {
        runBlocking {
            val verifier = scp.identityCreateInMemory()
            val subject = scp.identityCreateInMemory()
            val error =
                assertFailsWith<ScpException.Validation> {
                    scp.trustCreateChallenge(verifier, subject.did(), schemaUri, testCases(19))
                }
            assertEquals(CHALLENGE_SUITE_BELOW_MINIMUM_CODE, error.code)
        }
    }

    /**
     * A created request decodes into the SDK types, and a response with a
     * forged signature is refused by the real verifier.
     */
    @Test
    fun `trustCreateChallenge then trustVerifyResponse - forged response is refused`() {
        runBlocking {
            val verifier = scp.identityCreateInMemory()
            val subject = scp.identityCreateInMemory()
            val cases = testCases(20)
            val created = scp.trustCreateChallenge(verifier, subject.did(), schemaUri, cases)
            val challenge = decodeChallengeRequestJson(created.challengeJson)
            assertEquals(created.challengeId, challenge.challengeId)
            assertEquals(verifier.did(), challenge.verifier)
            assertEquals(subject.did(), challenge.subject)
            assertEquals(cases, challenge.testCases)

            val response =
                ChallengeResponse(
                    challengeId = challenge.challengeId,
                    responderDid = subject.did(),
                    result =
                        buildJsonObject {
                            put("passed", true)
                            put("score", 10_000)
                            put("test_count", 20)
                            put("pass_count", 20)
                        },
                    completedAt = (System.currentTimeMillis() / 1000).toULong(),
                    signature = List(64) { 0.toUByte() },
                )
            val error =
                assertFailsWith<ScpException.Validation> {
                    scp.trustVerifyResponse(verifier, challenge, response, "ctx-ffi")
                }
            assertEquals("SCP-VALID-7003", error.code)
        }
    }
}
