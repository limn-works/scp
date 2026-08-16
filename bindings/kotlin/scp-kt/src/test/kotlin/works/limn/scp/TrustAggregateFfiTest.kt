// TrustAggregateFfiTest.kt — Real-FFI call-through tests for the typed
// trust-aggregation wrapper (ADR-058, spec §7.3).
//
// These invoke the bridge `aggregate_trust_input` op through the typed
// [SCP.aggregateTrustInput] wrapper, proving the TrustAggregate.kt-serialized
// JSON parses and evaluates on the real Rust deserializers — not just that
// the encoders emit the pinned shapes (TrustAggregateTest.kt covers that
// without the native lib).
//
// All tests require the compiled UniFFI cdylib; if the native library is not
// loadable the suite skips via JUnit 5 assumptions, matching
// TrustAdmissionFfiTest.

package works.limn.scp

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.put
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assumptions.assumeTrue
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import uniffi.scp.StorageConfig
import works.limn.scp.bridge.CoroutineBridge
import works.limn.scp.conformance.ConformanceStubBindings
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds

class TrustAggregateFfiTest {
    companion object {
        private var nativeAvailable = false
        private var skipReason = ""

        @JvmStatic
        @BeforeAll
        fun probeNativeLibrary() {
            try {
                Class.forName("uniffi.scp.ScpKt")
                // Touch a UniFFI helper to force JNA library resolution.
                Class.forName("uniffi.scp.Scp\$Companion")
                nativeAvailable = true
            } catch (e: ClassNotFoundException) {
                skipReason = "UniFFI bindings not available: ${e.message}"
            } catch (e: UnsatisfiedLinkError) {
                skipReason = "Native library link error: ${e.message}"
            } catch (e: ExceptionInInitializerError) {
                skipReason = "Native library init error: ${e.cause?.message ?: e.message}"
            } catch (e: NoClassDefFoundError) {
                skipReason = "Native library class not found: ${e.message}"
            }
        }
    }

    private lateinit var scp: SCP

    private fun bridge(): CoroutineBridge =
        CoroutineBridge(
            nativeBindings = ConformanceStubBindings(),
            ioDispatcher = Dispatchers.IO,
            cpuDispatcher = Dispatchers.Default,
        )

    @BeforeEach
    fun setUp() {
        assumeTrue(nativeAvailable, skipReason)
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
            scp.aggregateTrustInput(
                contextId = "ctx-aggregate-ffi",
                subjectDid = "did:dht:zSubject",
                events = listOf(genesisMemberJoined()),
                merkleRoot = List(32) { 0.toUByte() },
            )
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
        val result = Json.parseToJsonElement(resultJson).jsonObject
        assertTrue("threshold_counts" in result, "missing threshold_counts: $resultJson")
    }

    // -----------------------------------------------------------------------
    // Challenge trust inputs (§7.3.4, ADR-058 Op D)
    // -----------------------------------------------------------------------

    /**
     * The typed attestation envelope's serialized JSON parses on the REAL
     * Rust `Attestation` deserializer: a dummy signature yields a structured
     * `valid = false` result (verification ran), never a parse error.
     */
    @Test
    fun `trustVerifyAttestation - typed envelope reaches the real verifier`() {
        val result =
            scp.trustVerifyAttestation(
                contextId = "ctx-verify-ffi",
                attestation =
                    CachedAttestationEnvelope(
                        id = "att-ffi-1",
                        attestationType = "AgentCapability",
                        issuer = "did:dht:zIssuer",
                        subject = "did:dht:zSubject",
                        claim =
                            buildJsonObject {
                                put("capability", "scp:capability:schema-validation/v1")
                            },
                        issuedAt = 1_700_000_000uL,
                        revocationStatus = Json.parseToJsonElement("\"Active\""),
                        signature = List(64) { 0.toUByte() },
                    ),
            )
        assertFalse(result.valid)
        assertTrue(result.errorMessage.isNotEmpty())
    }

    /**
     * The typed challenge pair's serialized JSON parses on the REAL Rust
     * `ChallengeRequest` / `ChallengeResponse` deserializers: dummy
     * signatures yield a structured `false`, never a parse error.
     */
    @Test
    fun `trustVerifyResponse - typed challenge pair reaches the real verifier`() {
        val valid =
            scp.trustVerifyResponse(
                challenge =
                    ChallengeRequest(
                        challengeId = "chal-ffi-1",
                        challengeType = "scp:capability:schema-validation/v1",
                        challengerDid = "did:dht:zChallenger",
                        subjectDid = "did:dht:zSubject",
                        capabilityUri = "scp:capability:schema-validation/v1",
                        parameters = buildJsonObject { },
                        timeout = CachedAttestationDuration(secs = 300uL, nanos = 0u),
                        signature = List(64) { 0.toUByte() },
                    ),
                response =
                    ChallengeResponse(
                        challengeId = "chal-ffi-1",
                        responderDid = "did:dht:zSubject",
                        result = buildJsonObject { put("passed", true) },
                        completedAt = 1_700_000_100uL,
                        signature = List(64) { 0.toUByte() },
                    ),
            )
        assertFalse(valid)
    }
}
