// TrustAggregateFfiTest.kt — Real-FFI call-through tests for the typed
// trust-aggregation wrapper (ADR-058, spec §7.3).
//
// These invoke the bridge `aggregate_trust_input` op through the typed
// [SCP.aggregateTrustInput] wrapper, and the challenge operations
// ([SCP.trustCreateChallenge], [SCP.trustRespondToChallenge],
// [SCP.trustGradeResponse], [SCP.checkCapabilityRequirements]), proving
// the TrustAggregate.kt-serialized JSON parses and evaluates on the real Rust
// deserializers — not just that the encoders emit the pinned shapes
// (TrustAggregateTest.kt covers that without the native lib).
//
// All tests require the compiled UniFFI cdylib. A cdylib that is absent or fails
// to load throws `UnsatisfiedLinkError` from the first native call and fails the
// test.

package works.limn.scp

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.put
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import uniffi.scp.CeilingPolicy
import uniffi.scp.ContextMode
import uniffi.scp.ContextParams
import uniffi.scp.GovernanceModel
import uniffi.scp.MemoryScope
import uniffi.scp.ScpException
import uniffi.scp.StorageConfig
import works.limn.scp.bridge.CoroutineBridge
import works.limn.scp.conformance.ConformanceStubBindings
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNull
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

    /** A context on [scp] whose governance requires [schemaUri] graded by [verifierDid]. */
    private suspend fun requiringContext(verifierDid: String): String {
        val creator = scp.identityCreateInMemory()
        val handle =
            scp.contextCreate(
                creator,
                ContextParams(
                    mode = ContextMode.ENCRYPTED,
                    ceiling = listOf("messages:read", "messages:write"),
                    ceilingPolicy = CeilingPolicy.IMMUTABLE,
                    governance = GovernanceModel.SINGLE_ADMIN,
                    memoryScope = MemoryScope.EPHEMERAL,
                    ttlSeconds = 3600uL,
                    promotable = false,
                    minProtocolVersion = 0.toUShort(),
                    maxChainDepth = null,
                    maxNestingDepth = null,
                    sessionCap = null,
                    economicPolicy = null,
                    consequenceRulesJson = null,
                    consequenceConfigJson = null,
                    capabilityRequirementsJson =
                        encodeCapabilityRequirementsJson(
                            listOf(
                                CapabilityRequirement(
                                    capability = schemaUri,
                                    verificationLevel = VerificationLevel.CHALLENGE_VERIFIED,
                                    trustedVerifiers = listOf(verifierDid),
                                ),
                            ),
                        ),
                ),
            )
        return handle.contextId()
    }

    /** An output that passes every case [testCases] writes. */
    private fun passingOutputs(cases: List<TestCase>): List<TestOutput> =
        cases.map { TestOutput(testId = it.testId, output = buildJsonObject { put("ok", true) }) }

    /** A protocol suite one case short of its standard's minimum is refused. */
    @Test
    fun `trustCreateChallenge - suite below minimum is SCP-VALID-7039`() {
        runBlocking {
            val verifier = scp.identityCreateInMemory()
            val subject = scp.identityCreateInMemory()
            val contextId = requiringContext(verifier.did())
            val error =
                assertFailsWith<ScpException.Validation> {
                    scp.trustCreateChallenge(verifier, subject.did(), schemaUri, testCases(19), contextId, 3_600u)
                }
            assertEquals(CHALLENGE_SUITE_BELOW_MINIMUM_CODE, error.code)
        }
    }

    /**
     * Test 38: one challenge from creation to admission through the real
     * bridge. The context's governance requires the capability, so the
     * subject is refused before it holds a record and admitted after.
     */
    @Test
    fun `challenge_round_trip`() {
        runBlocking {
            val verifier = scp.identityCreateInMemory()
            val subject = scp.identityCreateInMemory()
            val contextId = requiringContext(verifier.did())
            val cases = testCases(20)

            val request = scp.trustCreateChallenge(verifier, subject.did(), schemaUri, cases, contextId, 3_600u)
            pastCreationSecond(request)
            assertEquals(verifier.did(), request.verifier)
            assertEquals(subject.did(), request.subject)
            assertEquals(contextId, request.contextId)
            assertEquals(schemaUri, request.capabilityUri)
            assertEquals(cases.map { it.testId }, request.testCases.map { it.testId })
            assertEquals(3_600uL, request.expiresAt - request.createdAt)
            // The request commits to each answer and never carries it.
            assertFalse(encodeChallengeRequestJson(request).contains("ExactMatch"))

            val refused =
                assertFailsWith<ScpException.Validation> {
                    scp.checkCapabilityRequirements(contextId, subject.did(), emptyList(), emptyList())
                }
            assertEquals("SCP-VALID-7076", refused.code)

            val response = scp.trustRespondToChallenge(subject, request, passingOutputs(cases), 1u)
            assertEquals(request.challengeId, response.challengeId)
            assertEquals(subject.did(), response.subject)
            assertEquals(1u, response.attempt)

            val graded = scp.trustGradeResponse(verifier, request, response)
            assertNull(graded.trustStoreError)
            assertEquals(20, graded.caseResults.size)
            assertTrue(graded.caseResults.all { it.passed })
            val record = graded.record
            assertTrue(record.passed)
            assertEquals(1u, record.attempt)
            assertEquals(20u, record.passCount)
            assertEquals(20u, record.testCount)
            assertEquals(request.challengeId, record.challengeId)
            assertEquals(verifier.did(), record.verifier)
            assertEquals(subject.did(), record.subject)
            assertEquals(contextId, record.contextId)

            scp.checkCapabilityRequirements(contextId, subject.did(), emptyList(), listOf(record))
            // Every field is signed: a record whose attempt was altered is dropped.
            val altered =
                assertFailsWith<ScpException.Validation> {
                    scp.checkCapabilityRequirements(
                        contextId,
                        subject.did(),
                        emptyList(),
                        listOf(record.copy(attempt = 2u)),
                    )
                }
            assertEquals("SCP-VALID-7076", altered.code)
        }
    }

    /** A response with a forged signature is refused and uses no attempt. */
    @Test
    fun `trustGradeResponse - forged response is refused and grades nothing`() {
        runBlocking {
            val verifier = scp.identityCreateInMemory()
            val subject = scp.identityCreateInMemory()
            val contextId = requiringContext(verifier.did())
            val cases = testCases(20)
            val request = scp.trustCreateChallenge(verifier, subject.did(), schemaUri, cases, contextId, 3_600u)
            pastCreationSecond(request)
            val response = scp.trustRespondToChallenge(subject, request, passingOutputs(cases), 1u)
            assertFailsWith<ScpException> {
                scp.trustGradeResponse(
                    verifier,
                    request,
                    response.copy(subjectSignature = List(64) { 0.toUByte() }),
                )
            }
            // The forgery took no attempt: the real response still grades as attempt 1.
            val graded = scp.trustGradeResponse(verifier, request, response)
            assertEquals(1u, graded.record.attempt)
            assertTrue(graded.record.passed)
        }
    }

/**
 * Grading is strictly inside the challenge window (spec 07 §7.3.4), so a
 * grade in the second the challenge was created is refused. This waits that
 * second out on the wall clock the bridge reads.
 */
private suspend fun pastCreationSecond(request: ChallengeRequest) {
    while (System.currentTimeMillis() < (request.createdAt.toLong() + 1) * 1_000) {
        delay(50)
    }
}
