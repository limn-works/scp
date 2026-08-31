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
import kotlinx.coroutines.CoroutineDispatcher
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
import org.junit.jupiter.api.Timeout
import java.util.concurrent.TimeUnit
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

// Every method runs on its own thread under a wall-clock limit, so a method that parks a
// thread forever — the SCP-117 `runBlocking` deadlock this suite regressed on — fails the
// build instead of hanging the CI runner until the job's own limit expires.
@Timeout(value = 30, unit = TimeUnit.SECONDS, threadMode = Timeout.ThreadMode.SEPARATE_THREAD)
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
        val viewModel = TestScpViewModel(testDispatcher)
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

        val viewModel = TestScpViewModel(testDispatcher)
        viewModel.trackContext(TrackedContext(handle = 1L, identityHandle = 1L, bridge = bridge))
        viewModel.trackContext(TrackedContext(handle = 2L, identityHandle = 2L, bridge = bridge))
        advanceUntilIdle()

        viewModel.callOnCleared()
        advanceUntilIdle()

        assertTrue(stubBindings.leaveCalledHandles.contains(1L))
        assertTrue(stubBindings.leaveCalledHandles.contains(2L))
    }

    // `.docs/standards/sdk-common.md` §Cleanup error handling requires that a cleanup error be
    // logged rather than dropped. An earlier revision swallowed every throwable except
    // CancellationException, so an app author learned nothing when a departure did not land.
    @Test
    fun `onCleanupFailure receives every leave failure`() = runTest(testDispatcher) {
        stubBindings.leaveThrowsForHandle = 1L

        val viewModel = TestScpViewModel(testDispatcher)
        val ctx1 = TrackedContext(handle = 1L, identityHandle = 1L, bridge = bridge)
        val ctx2 = TrackedContext(handle = 2L, identityHandle = 2L, bridge = bridge)
        viewModel.trackContext(ctx1)
        viewModel.trackContext(ctx2)
        advanceUntilIdle()

        viewModel.callOnCleared()
        advanceUntilIdle()

        assertEquals(
            listOf(ctx1),
            viewModel.cleanupFailures.map { it.first },
            "a failing leave must reach onCleanupFailure exactly once, naming its context",
        )
        assertTrue(
            viewModel.cleanupFailures.single().second is ScpLeaveException,
            "onCleanupFailure must receive whatever leave threw, not a wrapper",
        )
        // A reported failure does not stop remaining departures.
        assertEquals(listOf(1L, 2L), stubBindings.leaveCalledHandles)
    }

    // A CancellationException reports that this cleanup coroutine was cancelled. Reporting it
    // through onCleanupFailure would invite an override to swallow its own cancellation.
    @Test
    fun `onCleanupFailure never receives a cancellation`() = runTest(testDispatcher) {
        stubBindings.leaveCancelsForHandle = 1L

        val viewModel = TestScpViewModel(testDispatcher)
        viewModel.trackContext(TrackedContext(handle = 1L, identityHandle = 1L, bridge = bridge))
        viewModel.trackContext(TrackedContext(handle = 2L, identityHandle = 2L, bridge = bridge))
        advanceUntilIdle()

        viewModel.callOnCleared()
        advanceUntilIdle()

        assertTrue(
            viewModel.cleanupFailures.isEmpty(),
            "a cancellation must propagate, never reach onCleanupFailure",
        )
        assertEquals(
            listOf(1L),
            stubBindings.leaveCalledHandles,
            "a cancelled cleanup coroutine stops before a second leave",
        )
    }

    @Test
    fun `untrackContext prevents leave on cleared`() = runTest(testDispatcher) {
        val viewModel = TestScpViewModel(testDispatcher)
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
        val viewModel = TestScpViewModel(testDispatcher)
        viewModel.callOnCleared()
        advanceUntilIdle()

        assertTrue(stubBindings.leaveCalledHandles.isEmpty())
    }

    @Test
    fun `trackContext returns the same context for chaining`() = runTest(testDispatcher) {
        val viewModel = TestScpViewModel(testDispatcher)
        val ctx = TrackedContext(handle = 42L, identityHandle = 1L, bridge = bridge)
        val returned = viewModel.trackContext(ctx)
        assertEquals(ctx, returned)
    }

    // A cancelled cleanup scope would satisfy an "is empty" assertion whether or not
    // onCleared() cleared its tracked list, so this method asserts on recorded contents at
    // each step. Delete `activeContexts.clear()` from onCleared() and a second
    // assertEquals reports [1] against an expected empty list.
    @Test
    fun `onCleared clears the active contexts list`() = runTest(testDispatcher) {
        val viewModel = TestScpViewModel(testDispatcher)
        viewModel.trackContext(TrackedContext(handle = 1L, identityHandle = 1L, bridge = bridge))
        advanceUntilIdle()

        viewModel.callOnCleared()
        advanceUntilIdle()

        assertEquals(listOf(1L), stubBindings.leaveCalledHandles)
        stubBindings.leaveCalledHandles.clear()

        viewModel.callOnCleared()
        advanceUntilIdle()

        assertEquals(
            emptyList<Long>(),
            stubBindings.leaveCalledHandles,
            "a second onCleared finds an empty tracked list, so it leaves nothing",
        )
    }

    // Guards against reintroducing `cleanupJob.invokeOnCompletion { cleanupScope.cancel() }`.
    // A cancelled cleanup scope drops every later launch without running it, so this
    // leave would never reach TestNativeBindings.
    @Test
    fun `a context tracked after onCleared is still left by a later onCleared`() =
        runTest(testDispatcher) {
            val viewModel = TestScpViewModel(testDispatcher)
            viewModel.trackContext(TrackedContext(handle = 1L, identityHandle = 1L, bridge = bridge))
            advanceUntilIdle()

            viewModel.callOnCleared()
            advanceUntilIdle()
            assertEquals(listOf(1L), stubBindings.leaveCalledHandles)

            viewModel.trackContext(TrackedContext(handle = 2L, identityHandle = 2L, bridge = bridge))
            viewModel.callOnCleared()
            advanceUntilIdle()

            assertEquals(listOf(1L, 2L), stubBindings.leaveCalledHandles)
        }

    // A Java subclass of ScpViewModel calls `super()`, so a zero-argument JVM constructor is
    // part of this artifact's published surface. Kotlin emits one because every
    // primary-constructor parameter carries a default; adding a parameter without a default
    // removes it and fails this method.
    @Test
    fun `ScpViewModel exposes a zero-argument constructor to Java callers`() {
        val parameterCounts = ScpViewModel::class.java.declaredConstructors
            .map { it.parameterCount }
            .toSet()
        assertTrue(
            parameterCounts.contains(0),
            "expected a zero-argument constructor, found arities $parameterCounts",
        )
        assertTrue(
            parameterCounts.contains(1),
            "expected a one-argument constructor, found arities $parameterCounts",
        )
    }

    @Test
    fun `onCleared returns before the leave calls run`() = runTest(testDispatcher) {
        val viewModel = TestScpViewModel(testDispatcher)
        viewModel.trackContext(TrackedContext(handle = 7L, identityHandle = 7L, bridge = bridge))
        advanceUntilIdle()

        viewModel.callOnCleared()

        // StandardTestDispatcher queues the cleanup coroutine without running it, so an
        // onCleared that waited for leave could not have reached this line.
        assertTrue(
            stubBindings.leaveCalledHandles.isEmpty(),
            "onCleared returned, and no leave has run yet",
        )

        advanceUntilIdle()

        assertEquals(listOf(7L), stubBindings.leaveCalledHandles)
    }
}

/**
 * Concrete [ScpViewModel] subclass for testing. Exposes [onCleared] via [callOnCleared].
 *
 * @param cleanupDispatcher The dispatcher [ScpViewModel.onCleared] runs its `leave` calls on.
 *   Each test passes the same `TestDispatcher` it gave the [CoroutineBridge], so
 *   `advanceUntilIdle()` runs the cleanup coroutine and the `leave` calls it makes.
 */
private class TestScpViewModel(
    cleanupDispatcher: CoroutineDispatcher,
) : ScpViewModel(cleanupDispatcher) {
    /** Every (context, cause) pair that [onCleanupFailure] received, in call order. */
    val cleanupFailures = mutableListOf<Pair<TrackedContext, Throwable>>()

    override fun onCleanupFailure(context: TrackedContext, cause: Throwable) {
        cleanupFailures += context to cause
    }

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

    /** Handle whose leave raises a cancellation, standing in for a cancelled cleanup coroutine. */
    var leaveCancelsForHandle: Long? = null

    override fun contextLeave(contextHandle: Long, identityHandle: Long) {
        leaveCalledHandles.add(contextHandle)
        if (contextHandle == leaveCancelsForHandle) {
            throw kotlinx.coroutines.CancellationException("cleanup cancelled at handle $contextHandle")
        }
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
