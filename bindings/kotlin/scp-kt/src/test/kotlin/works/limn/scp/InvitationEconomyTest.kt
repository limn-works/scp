// InvitationEconomyTest.kt -- Cross-layer integration tests for spending UCAN
// and consequence events (#1537, #1593, #1594)
//
// Verifies that the Kotlin SDK correctly wires spending and consequence
// parameters through the coroutine bridge to the UniFFI bridge layer.
//
// Provenance: spec section 19 (Economic Governance), ADR-033, #1537, #1593

package works.limn.scp

import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.TestDispatcher
import kotlinx.coroutines.test.runTest
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import works.limn.scp.bridge.CoroutineBridge
import works.limn.scp.bridge.ExtendedBindings
import works.limn.scp.bridge.NativeBindings
import works.limn.scp.conformance.ConformanceStubBindings
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

@OptIn(ExperimentalCoroutinesApi::class)
class InvitationEconomyTest {
    private lateinit var stubBindings: ConformanceStubBindings
    private lateinit var testDispatcher: TestDispatcher
    private lateinit var bridge: CoroutineBridge

    /** Stub [InvitationBindings] that captures the spending parameter. */
    private var capturedSpendingJson: String? = null
    private var invitationResult: String = "prompt_agent"

    private val stubInvitationBindings =
        object : InvitationBindings {
            override fun evaluateInvitation(
                paramsJson: String,
                inviterDid: String,
                identityDid: String,
                policyJson: String?,
                spendingJson: String?,
                trustedDids: List<String>,
            ): String {
                capturedSpendingJson = spendingJson
                return invitationResult
            }
        }

    /** Stub [TrustBindings] that captures the consequence rules parameter. */
    private var capturedConsequenceRulesJson: String? = null

    private val stubTrustBindings =
        object : TrustBindings {
            override fun aggregateTrustInput(
                contextId: String,
                subjectDid: String,
                eventsJson: String,
                merkleRootJson: String,
                consequenceRulesJson: String,
                thresholdRequirementsJson: String,
                attestorSetsJson: String,
                cachedAttestationsJson: String,
                challengeResultsJson: String,
            ): String {
                capturedConsequenceRulesJson = consequenceRulesJson
                return buildString {
                    append("""{"verified_attestations":[]""")
                    append(""","participation_record":{}""")
                    append(""","challenge_results":[]""")
                    append(""","consequence_structure":[]""")
                    append(""","threshold_counts":{}}""")
                }
            }
        }

    @BeforeEach
    fun setUp() {
        capturedSpendingJson = null
        capturedConsequenceRulesJson = null
        invitationResult = "prompt_agent"

        stubBindings = ConformanceStubBindings()
        testDispatcher = StandardTestDispatcher()
        bridge =
            CoroutineBridge(
                nativeBindings = stubBindings,
                ioDispatcher = testDispatcher,
                cpuDispatcher = testDispatcher,
                extendedBindings =
                    ExtendedBindings(
                        invitation = stubInvitationBindings,
                        trust = stubTrustBindings,
                    ),
            )
    }

    @Nested
    inner class SpendingUcanParameterTests {
        @Test
        fun `evaluateContextInvitation passes spending JSON to bridge`() =
            runTest(testDispatcher) {
                val spendingJson =
                    """{"has_spending_ucan":true,"configured_adapters":["x402"],"available_balance":10000}"""
                val result =
                    evaluateContextInvitation(
                        bridge = bridge,
                        paramsJson = """{"ceiling":[]}""",
                        inviterDid = "did:dht:z6MkBob",
                        identityDid = "did:dht:z6MkLocal",
                        spendingJson = spendingJson,
                    )

                assertEquals("prompt_agent", result.decision)
                assertEquals(spendingJson, capturedSpendingJson)
            }

        @Test
        fun `evaluateContextInvitation with null spending passes null`() =
            runTest(testDispatcher) {
                val result =
                    evaluateContextInvitation(
                        bridge = bridge,
                        paramsJson = """{"ceiling":[]}""",
                        inviterDid = "did:dht:z6MkBob",
                        identityDid = "did:dht:z6MkLocal",
                    )

                assertEquals("prompt_agent", result.decision)
                assertEquals(null, capturedSpendingJson)
            }

        @Test
        fun `InvitationEvaluationResult isAutoAccept reflects decision`() {
            val acceptResult = InvitationEvaluationResult("auto_accept")
            assertTrue(acceptResult.isAutoAccept)

            val promptResult = InvitationEvaluationResult("prompt_agent")
            assertTrue(!promptResult.isAutoAccept)
        }
    }

    @Nested
    inner class ConsequenceRulesParameterTests {
        @Test
        fun `aggregateTrustInput passes consequence rules JSON to bridge`() =
            runTest(testDispatcher) {
                val rulesJson =
                    """[{"trigger":"MessageVelocity","action":"SuspendAll","threshold":5}]"""
                aggregateTrustInput(
                    bridge = bridge,
                    contextId = "ctx-consequence-test",
                    subjectDid = "did:dht:z6MkBob",
                    eventsJson = "[]",
                    merkleRootJson = "[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]",
                    consequenceRulesJson = rulesJson,
                )

                assertNotNull(capturedConsequenceRulesJson)
                assertEquals(rulesJson, capturedConsequenceRulesJson)
            }

        @Test
        fun `aggregateTrustInput defaults consequence rules to empty array`() =
            runTest(testDispatcher) {
                aggregateTrustInput(
                    bridge = bridge,
                    contextId = "ctx-no-consequence",
                    subjectDid = "did:dht:z6MkBob",
                    eventsJson = "[]",
                    merkleRootJson = "[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]",
                )

                assertEquals("[]", capturedConsequenceRulesJson)
            }
    }
}
