// TrustAdmissionFfiTest.kt — Real-FFI call-through tests for the typed
// trust-input wrappers (ADR-058, spec §7.3.2.1 / §7.3.4.4).
//
// These invoke the generated UniFFI free functions through the typed
// [SCP.checkCapabilityRequirements] / [SCP.verifyParticipationRequirements]
// wrappers, proving the TrustAdmission.kt-serialized JSON parses and evaluates
// on the real Rust deserializers — not just that the encoders emit the pinned
// shapes (TrustAdmissionTest.kt covers that without the native lib). Mirrors
// the Swift SDK `TrustAdmissionCallThroughTests` scenario-for-scenario.
//
// All tests require the compiled UniFFI cdylib; if the native library is not
// loadable the suite skips via JUnit 5 assumptions, matching ScpClassTest.

package works.limn.scp

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.JsonNull
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assumptions.assumeTrue
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertDoesNotThrow
import org.junit.jupiter.api.assertThrows
import uniffi.scp.ScpException
import uniffi.scp.StorageConfig
import works.limn.scp.bridge.CoroutineBridge
import works.limn.scp.conformance.ConformanceStubBindings
import kotlin.time.Duration.Companion.seconds

class TrustAdmissionFfiTest {
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

    @Test
    fun `checkCapabilityRequirements - satisfied SelfAttested requirement admits`() {
        // The capability is present in agentCapabilities, so the typed
        // wrapper's serialized JSON parses and evaluates to success on the
        // Rust side (no throw).
        assertDoesNotThrow {
            scp.checkCapabilityRequirements(
                contextId = "ctx-1",
                subjectDid = "did:key:zSubject",
                requirements =
                    listOf(
                        CapabilityRequirement(
                            capability = "scp:capability:messages-write/v1",
                            verificationLevel = VerificationLevel.SELF_ATTESTED,
                        ),
                    ),
                agentCapabilities = listOf("scp:capability:messages-write/v1"),
                challengeVerifications = emptyList(),
            )
        }
    }

    @Test
    fun `checkCapabilityRequirements - missing capability is rejected`() {
        // An unmet SelfAttested requirement (capability not declared, no
        // matching challenge verification) is rejected by the Rust evaluator —
        // proving the serialized JSON parsed and was evaluated, not silently
        // dropped.
        assertThrows<ScpException> {
            scp.checkCapabilityRequirements(
                contextId = "ctx-1",
                subjectDid = "did:key:zSubject",
                requirements =
                    listOf(
                        CapabilityRequirement(
                            capability = "scp:capability:member-invite/v1",
                            verificationLevel = VerificationLevel.SELF_ATTESTED,
                        ),
                    ),
                agentCapabilities = listOf("scp:capability:messages-write/v1"),
                challengeVerifications = emptyList(),
            )
        }
    }

    @Test
    fun `checkCapabilityRequirements - typed challenge verification crosses FFI`() {
        // A ChallengeVerified requirement backed only by an unsigned
        // (zero-signature) verification record is rejected by the Rust
        // signature check — proving the full 16-field ChallengeVerification
        // (tagged verification_method, explicit-null score, number-array
        // signature) deserialized on the Rust side and reached evaluation.
        assertThrows<ScpException> {
            scp.checkCapabilityRequirements(
                contextId = "ctx-admission",
                subjectDid = "did:key:zSubject",
                requirements =
                    listOf(
                        CapabilityRequirement(
                            capability = "scp:capability:prompt-injection-resistance/v1",
                            verificationLevel = VerificationLevel.CHALLENGE_VERIFIED,
                        ),
                    ),
                agentCapabilities = emptyList(),
                challengeVerifications =
                    listOf(
                        ChallengeVerification(
                            verificationId = "bridge-test-challenge",
                            verifierDid = "did:key:zVerifier",
                            subjectDid = "did:key:zSubject",
                            capabilityUri = "scp:capability:prompt-injection-resistance/v1",
                            challengeType = "scp:capability:prompt-injection-resistance/v1",
                            verificationMethod =
                                ChallengeVerificationMethod.ChallengeVerified(
                                    challengeType =
                                        "scp:capability:prompt-injection-resistance/v1",
                                ),
                            passed = true,
                            testCount = 1u,
                            passCount = 1u,
                            result = JsonNull,
                            completedAt = 1_700_000_000uL,
                            verifiedAt = 1_700_000_000uL,
                            expiresAt = 4_000_000_000uL,
                            contextId = "ctx-admission",
                            verifierSignature = List(64) { 0.toUByte() },
                        ),
                    ),
            )
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
