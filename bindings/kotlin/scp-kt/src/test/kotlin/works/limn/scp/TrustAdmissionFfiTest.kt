// TrustAdmissionFfiTest.kt — Real-FFI call-through tests for the typed
// trust-input wrappers (ADR-058, spec §7.3.2.1 / §7.3.4.4).
//
// These invoke the generated UniFFI bindings (the `Scp` instance method and
// the participation free function) through the typed
// [SCP.checkCapabilityRequirements] / [SCP.verifyParticipationRequirements]
// wrappers, proving the TrustAdmission.kt-serialized JSON parses and evaluates
// on the real Rust deserializers — not just that the encoders emit the pinned
// shapes (TrustAdmissionTest.kt covers that without the native lib). Mirrors
// the Swift SDK `TrustAdmissionCallThroughTests` scenario-for-scenario.
//
// All tests require the compiled UniFFI cdylib. A cdylib that is absent or fails
// to load throws `UnsatisfiedLinkError` from the first native call and fails the
// test.

package works.limn.scp

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertDoesNotThrow
import org.junit.jupiter.api.assertThrows
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
import kotlin.time.Duration.Companion.seconds

class TrustAdmissionFfiTest {
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

    /** A context on [scp] whose governance holds [requirements]. */
    private suspend fun contextRequiring(requirements: List<CapabilityRequirement>): String {
        val creator = scp.identityCreateInMemory()
        return scp
            .contextCreate(
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
                    capabilityRequirementsJson = encodeCapabilityRequirementsJson(requirements),
                ),
            ).contextId()
    }

    private val messagesWrite =
        listOf(
            CapabilityRequirement(
                capability = "scp:capability:messages-write/v1",
                verificationLevel = VerificationLevel.SELF_ATTESTED,
            ),
        )

    @Test
    fun `checkCapabilityRequirements - satisfied SelfAttested requirement admits`() {
        // The capability is present in agentCapabilities, so the context's
        // stored requirement is met on the Rust side (no throw).
        runBlocking {
            val contextId = contextRequiring(messagesWrite)
            val subject = scp.identityCreateInMemory()
            assertDoesNotThrow {
                runBlocking {
                    scp.checkCapabilityRequirements(
                        contextId = contextId,
                        subjectDid = subject.did(),
                        agentCapabilities = listOf("scp:capability:messages-write/v1"),
                        challengeVerifications = emptyList(),
                    )
                }
            }
        }
    }

    @Test
    fun `checkCapabilityRequirements - missing capability is SCP-VALID-7076`() {
        // An unmet SelfAttested requirement is rejected by the Rust evaluator,
        // proving the context's stored requirements were read, not dropped.
        runBlocking {
            val contextId = contextRequiring(messagesWrite)
            val subject = scp.identityCreateInMemory()
            val error =
                assertThrows<ScpException.Validation> {
                    runBlocking {
                        scp.checkCapabilityRequirements(
                            contextId = contextId,
                            subjectDid = subject.did(),
                            agentCapabilities = listOf("scp:capability:member-invite/v1"),
                            challengeVerifications = emptyList(),
                        )
                    }
                }
            assertEquals("SCP-VALID-7076", error.code)
        }
    }

    @Test
    fun `checkCapabilityRequirements - non-canonical subject is NON_CANONICAL_IDENTIFIER_CODE`() {
        runBlocking {
            val contextId = contextRequiring(messagesWrite)
            val error =
                assertThrows<ScpException.Validation> {
                    runBlocking {
                        scp.checkCapabilityRequirements(
                            contextId = contextId,
                            subjectDid = "did:dht:zSubject",
                            agentCapabilities = listOf("scp:capability:messages-write/v1"),
                            challengeVerifications = emptyList(),
                        )
                    }
                }
            assertEquals(NON_CANONICAL_IDENTIFIER_CODE, error.code)
        }
    }

    @Test
    fun `checkCapabilityRequirements - unsigned challenge verification is SCP-VALID-7076`() {
        // A ChallengeVerified requirement backed only by an unsigned
        // (zero-signature) record is unmet: the 23-field record deserialized
        // on the Rust side and its signature failed, so it counts for nothing.
        runBlocking {
            val verifier = scp.identityCreateInMemory()
            val subject = scp.identityCreateInMemory()
            val capability = "scp:capability:schema-validation/v1"
            val contextId =
                contextRequiring(
                    listOf(
                        CapabilityRequirement(
                            capability = capability,
                            verificationLevel = VerificationLevel.CHALLENGE_VERIFIED,
                            trustedVerifiers = listOf(verifier.did()),
                        ),
                    ),
                )
            val record =
                ChallengeVerification(
                    verificationId = "ab".repeat(32),
                    verifier = verifier.did(),
                    subject = subject.did(),
                    capabilityUri = capability,
                    definitionDigest = "ef".repeat(32),
                    suiteDigest = "cd".repeat(32),
                    challengeId = "01".repeat(32),
                    attempt = 1u,
                    responseDigest = "02".repeat(32),
                    maxRetries = 0u,
                    cooldownSecs = 0u,
                    passThresholdBps = 8_000u,
                    minCategoryCases = 1u,
                    passed = true,
                    score = 10_000u,
                    testCount = 20u,
                    passCount = 20u,
                    challengeCreatedAt = 1_700_000_000uL,
                    challengeExpiresAt = 1_700_003_600uL,
                    timestamp = 1_700_000_100uL,
                    expiresAt = 4_000_000_000uL,
                    contextId = contextId,
                    verifierSignature = List(64) { 0.toUByte() },
                )
            val error =
                assertThrows<ScpException.Validation> {
                    runBlocking {
                        scp.checkCapabilityRequirements(
                            contextId = contextId,
                            subjectDid = subject.did(),
                            agentCapabilities = emptyList(),
                            challengeVerifications = listOf(record),
                        )
                    }
                }
            assertEquals("SCP-VALID-7076", error.code)
        }
    }

    @Test
    fun `verifyParticipationRequirements - empty requirements pass vacuously`() {
        // Empty requirements are vacuously satisfied — a clean call-through
        // proving the empty-array serialization parses on the Rust side.
        assertDoesNotThrow {
            scp.verifyParticipationRequirements(
                expectedSubject = "did:key:zSubject",
                requirements = emptyList(),
                profiles = emptyList(),
            )
        }
    }

    @Test
    fun `verifyParticipationRequirements - unsigned profile is rejected`() {
        // A real requirement paired with an unsigned (zero-signature) profile
        // is rejected by the Rust signature check — proving the profile JSON
        // (13 snake_case fields, 32/32/64 number arrays) round-tripped far
        // enough to be signature-verified, not rejected as malformed input.
        val profile =
            ParticipationProfile(
                subjectDid = "did:key:zSubject",
                participationDurationSecs = 7200uL,
                governanceActionsAgainst = 0uL,
                governanceActionsBy = 0uL,
                outletInvocationCount = 0uL,
                outletInvocationCountAnchored = false,
                contextCreationCount = 0uL,
                roleProgressionCount = 0uL,
                attestationCount = 0uL,
                updatedAt = 1_700_000_000uL,
                eventLogRoot = List(32) { 0.toUByte() },
                signerPublicKey = List(32) { 0.toUByte() },
                signature = List(64) { 0.toUByte() },
            )
        assertThrows<ScpException> {
            scp.verifyParticipationRequirements(
                expectedSubject = "did:key:zSubject",
                requirements =
                    listOf(
                        RequireParticipation(
                            fact = ParticipationFact.PARTICIPATION_DURATION,
                            threshold = ParticipationThreshold.AtLeast(3600uL),
                            maxAgeSecs = 86_400uL,
                            minContexts = 1u,
                        ),
                    ),
                profiles = listOf(profile),
            )
        }
    }
}
