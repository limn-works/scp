// ScpViewModelTest.kt — Tests for ScpViewModel lifecycle resource management (SCP-117)
//
// Verifies that ScpViewModel.onCleared() calls leave() on all tracked contexts
// and that track/untrack operations are thread-safe.
//
// Provenance: ADR-028 acceptance criterion 11, SCP-117

package works.limn.scp.android

import works.limn.scp.bridge.CancellationHandle
import works.limn.scp.bridge.CoroutineBridge
import works.limn.scp.bridge.MessageCallback
import works.limn.scp.bridge.NativeBindings
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.TestDispatcher
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.resetMain
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.test.setMain
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

@OptIn(ExperimentalCoroutinesApi::class)
class ScpViewModelTest {
    private lateinit var testDispatcher: TestDispatcher
    private lateinit var stubBindings: TestNativeBindings
    private lateinit var bridge: CoroutineBridge

    @BeforeEach
    fun setUp() {
        testDispatcher = StandardTestDispatcher()
        Dispatchers.setMain(testDispatcher)
        stubBindings = TestNativeBindings()
        bridge = CoroutineBridge(
            nativeBindings = stubBindings,
            ioDispatcher = testDispatcher,
            cpuDispatcher = testDispatcher,
        )
    }

    @AfterEach
    fun tearDown() {
        Dispatchers.resetMain()
    }

    @Test
    fun `onCleared calls leave on all tracked contexts`() = runTest(testDispatcher) {
        val viewModel = TestScpViewModel()
        val ctx1 = TrackedContext(handle = 1L, identityHandle = 1L, bridge = bridge)
        val ctx2 = TrackedContext(handle = 2L, identityHandle = 2L, bridge = bridge)

        viewModel.trackContext(ctx1)
        viewModel.trackContext(ctx2)
        advanceUntilIdle()

        viewModel.callOnCleared()
        advanceUntilIdle()

        assertEquals(2, stubBindings.leaveCalledHandles.size)
        assertTrue(stubBindings.leaveCalledHandles.contains(1L))
        assertTrue(stubBindings.leaveCalledHandles.contains(2L))
    }

    @Test
    fun `onCleared continues cleanup even if one leave throws`() = runTest(testDispatcher) {
        stubBindings.leaveThrowsForHandle = 1L

        val viewModel = TestScpViewModel()
        viewModel.trackContext(TrackedContext(handle = 1L, identityHandle = 1L, bridge = bridge))
        viewModel.trackContext(TrackedContext(handle = 2L, identityHandle = 2L, bridge = bridge))
        advanceUntilIdle()

        viewModel.callOnCleared()
        advanceUntilIdle()

        assertTrue(stubBindings.leaveCalledHandles.contains(1L))
        assertTrue(stubBindings.leaveCalledHandles.contains(2L))
    }

    @Test
    fun `untrackContext prevents leave on cleared`() = runTest(testDispatcher) {
        val viewModel = TestScpViewModel()
        val ctx = TrackedContext(handle = 1L, identityHandle = 1L, bridge = bridge)

        viewModel.trackContext(ctx)
        advanceUntilIdle()
        viewModel.untrackContext(ctx)
        advanceUntilIdle()

        viewModel.callOnCleared()
        advanceUntilIdle()

        assertFalse(stubBindings.leaveCalledHandles.contains(1L))
    }

    @Test
    fun `onCleared with no tracked contexts does not throw`() = runTest(testDispatcher) {
        val viewModel = TestScpViewModel()
        viewModel.callOnCleared()
        advanceUntilIdle()

        assertTrue(stubBindings.leaveCalledHandles.isEmpty())
    }

    @Test
    fun `trackContext returns the same context for chaining`() = runTest(testDispatcher) {
        val viewModel = TestScpViewModel()
        val ctx = TrackedContext(handle = 42L, identityHandle = 1L, bridge = bridge)
        val returned = viewModel.trackContext(ctx)
        assertEquals(ctx, returned)
    }

    @Test
    fun `onCleared clears the active contexts list`() = runTest(testDispatcher) {
        val viewModel = TestScpViewModel()
        viewModel.trackContext(TrackedContext(handle = 1L, identityHandle = 1L, bridge = bridge))
        advanceUntilIdle()

        viewModel.callOnCleared()
        advanceUntilIdle()

        stubBindings.leaveCalledHandles.clear()

        viewModel.callOnCleared()
        advanceUntilIdle()

        assertTrue(stubBindings.leaveCalledHandles.isEmpty(), "Second onCleared should have no contexts")
    }
}

/**
 * Concrete [ScpViewModel] subclass for testing. Exposes [onCleared] via [callOnCleared].
 */
private class TestScpViewModel : ScpViewModel() {
    fun callOnCleared() {
        onCleared()
    }
}

/**
 * Test stub for [NativeBindings] that tracks leave calls per context handle.
 */
@Suppress("TooManyFunctions")
private class TestNativeBindings : NativeBindings {
    val leaveCalledHandles = mutableListOf<Long>()
    var leaveThrowsForHandle: Long? = null

    override fun contextLeave(contextHandle: Long, identityHandle: Long) {
        leaveCalledHandles.add(contextHandle)
        if (contextHandle == leaveThrowsForHandle) {
            throw ScpLeaveException("leave failed for handle $contextHandle")
        }
    }

    override fun identityCreate(custody: String): Long = 0L
    override fun identityLoad(did: String): Long = 0L
    override fun identityResolve(did: String): String = ""
    override fun contextCreate(
        identityHandle: Long,
        paramsJson: String,
        consequenceRulesJson: String?,
        consequenceConfigJson: String?,
    ): Long = 0L
    override fun contextJoin(
        contextHandle: Long,
        identityHandle: Long,
        spendingUcanJwt: String?,
    ) { /* no-op */ }
    override fun contextClose(contextHandle: Long, identityHandle: Long) { /* no-op */ }
    override fun contextSend(
        contextHandle: Long,
        identityHandle: Long,
        payload: ByteArray,
        spendingUcanJwt: String?,
    ) { /* no-op */ }
    override fun contextSubscribe(contextHandle: Long, callback: MessageCallback): Long = 0L
    override fun contextUnsubscribe(subscriptionHandle: Long) { /* no-op */ }
    override fun contextSetEconomicPolicy(contextHandle: Long, policyJson: String) { /* no-op */ }
    override fun contextGetEconomicPolicy(contextHandle: Long): String? = null

    // MembershipBindings
    override fun contextMemberCount(contextHandle: Long): Long? = 0L
    override fun contextIsMember(contextHandle: Long, did: String): Boolean = false
    override fun contextMemberDids(contextHandle: Long): List<String> = emptyList()
    override fun contextMemberRole(contextHandle: Long, did: String): String? = null

    // GovernanceBindings
    override fun governanceExecute(contextHandle: Long, proposalIdHex: String): String = "{}"
    override fun governancePropose(contextHandle: Long, proposerDid: String, actionJson: String): String =
        """{"proposal_id":"0000","status":"Pending","execution_result":null}"""
    override fun governanceApprove(contextHandle: Long, voterDid: String, proposalIdHex: String): String =
        """{"status":"Pending"}"""
    override fun governanceReject(contextHandle: Long, voterDid: String, proposalIdHex: String): String =
        """{"status":"Pending"}"""
    override fun governanceWithdraw(contextHandle: Long, voterDid: String, proposalIdHex: String): String =
        """{"status":"Pending"}"""
    override fun governanceGetProposal(contextHandle: Long, proposalIdHex: String): String =
        """{"proposal_id":"0000","status":"Pending","action":"{}","proposer_did":"did:dht:stub","votes":{}}"""
    override fun governanceListProposals(contextHandle: Long): String = "[]"
    override fun applyPendingCeilingModification(contextHandle: Long, currentTimestamp: Long): Boolean = false
    override fun finalizeClose(contextHandle: Long) { /* no-op */ }
    @Suppress("LongParameterList")
    override fun createGovernanceCheckpoint(
        contextHandle: Long,
        checkpointSeq: Long,
        merkleRootHex: String,
        eventCount: Long,
        lastEventHashHex: String,
        stateSnapshotHashHex: String,
        creatorDid: String,
        creatorSignatureHex: String,
    ): String = "{}"
    override fun addCheckpointCosignature(
        contextHandle: Long,
        checkpointJson: String,
        signerDid: String,
        signatureHex: String,
    ): String = "{}"
    override fun restoreContext(contextId: String) { /* no-op */ }
    override fun restoreAllContexts(): String = "[]"

    // BroadcastBindings
    override fun broadcastSubscribe(contextHandle: Long, subscriberDid: String, messagesReadUcanJwt: String?) = Unit
    override fun broadcastUnsubscribe(contextHandle: Long, subscriberDid: String, rotateKeys: Boolean) = Unit
    override fun broadcastPublish(contextHandle: Long, identityHandle: Long, payload: ByteArray) = Unit
    override fun broadcastBlockSubscriber(contextHandle: Long, subscriberDid: String, blockerDid: String) = Unit
    override fun broadcastUnblockSubscriber(contextHandle: Long, subscriberDid: String, unblockerDid: String) = Unit
    override fun broadcastHandleKeyRequest(
        contextHandle: Long,
        authorDid: String,
        requesterDid: String,
        wrappingPubkey: ByteArray,
    ): String? = "{}"
    override fun broadcastSubscriberCount(contextHandle: Long): Long? = 0L
    override fun broadcastIsSubscriber(contextHandle: Long, did: String): Boolean = false
    override fun broadcastAdmission(contextHandle: Long): String? = null
    override fun broadcastPublishAsset(
        contextHandle: Long,
        identityHandle: Long,
        assetJson: String,
        deployId: String?,
    ): String = """{"blob_id":"stub","etag":"stub","deploy_id":"stub-deploy"}"""
    override fun broadcastPublishAssets(
        contextHandle: Long,
        identityHandle: Long,
        assetsJson: String,
        deployId: String?,
    ): String =
        """{"results":[{"blob_id":"stub","etag":"stub","deploy_id":"stub-deploy"}],"deploy_id":"stub-deploy"}"""

    override fun outletRegister(contextHandle: Long, definitionJson: String): String = ""
    override fun outletInvoke(
        contextHandle: Long,
        outletId: String,
        inputJson: String,
        identityHandle: Long,
        ucanToken: String?,
        proofTokens: List<String>?,
        spendingUcan: String?,
    ): String = ""
    @Suppress("LongParameterList")
    override fun outletInvokeCrossContext(
        sourceContextHandle: Long,
        targetContextHandle: Long,
        outletId: String,
        inputJson: String,
        identityHandle: Long,
        ucanToken: String,
        chainDepth: Int,
        proofTokens: List<String>?,
    ): String = ""
    @Suppress("LongParameterList")
    override fun outletInvokeCrossContextSaga(
        sourceContextHandle: Long,
        targetContextHandle: Long,
        callerDid: String,
        outletRegistrationId: String,
        inputJson: String,
        assertedNonceHex: String,
        timestampMs: Long,
        chainDepth: Int,
        ucanProofId: String?,
    ): String = ""
    override fun outletVerify(contextHandle: Long, outletId: String): String =
        """{"outlet_id":"$outletId","passed":false,"failures":[]}"""
    override fun outletInterfaceExpose(
        contextHandle: Long, outletId: String, targetContextId: String, rateLimitJson: String?,
    ): String = "{}"
    override fun outletInterfaceAccept(contextHandle: Long, interfaceJson: String): String = "{}"
    override fun outletInterfaceRevoke(contextHandle: Long, interfaceIdHex: String): String = "{}"
    override fun outletSessionCreate(
        contextHandle: Long,
        outletId: String,
        sourceContextId: String,
        ttlSeconds: Long?,
    ): String = "\"00000000-0000-0000-0000-000000000000\""
    @Suppress("LongParameterList")
    override fun outletSessionInvoke(
        contextHandle: Long,
        sessionId: String,
        inputJson: String,
        identityHandle: Long,
        ucanToken: String,
        proofTokens: List<String>?,
    ): String = "{}"
    override fun outletSessionClose(contextHandle: Long, sessionId: String) { /* no-op */ }
    override fun ucanValidate(
        contextHandle: Long,
        token: String,
        capability: String,
        presentingAgentDid: String,
        proofTokens: List<String>?,
    ) { /* no-op */ }
    override fun ucanMint(contextHandle: Long, memberDid: String, capabilitiesJson: String): String = ""
    override fun ucanRevoke(contextHandle: Long, token: String, revokerDid: String) { /* no-op */ }
    override fun ucanDelegate(
        contextHandle: Long,
        delegatorDid: String,
        delegateeDid: String,
        parentToken: String,
        capabilitiesJson: String,
    ): String = ""
    override fun eventLogQuery(contextHandle: Long, filterJson: String): String = ""
    override fun eventLogVerify(contextHandle: Long, claimJson: String): Boolean = false
    @Suppress("MaxLineLength")
    override fun eventLogCheckpoint(contextHandle: Long, identityHandle: Long, epoch: Long): String =
        """{"context_id":"","sender_did":"","event_count":0,"merkle_root":"","epoch":0,"timestamp":0,"signature":""}"""
    override fun transportConnect(configJson: String, cancellationHandle: CancellationHandle?): Long = 0L
    override fun transportStatus(transportHandle: Long): String = ""
    override fun transportDisconnect(transportHandle: Long) { /* no-op */ }
}

/**
 * Test-specific exception for simulating leave failures in [TestNativeBindings].
 */
private class ScpLeaveException(message: String) : IllegalStateException(message)
