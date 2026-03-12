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
        val ctx1 = TrackedContext(handle = 1L, bridge = bridge)
        val ctx2 = TrackedContext(handle = 2L, bridge = bridge)

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
        viewModel.trackContext(TrackedContext(handle = 1L, bridge = bridge))
        viewModel.trackContext(TrackedContext(handle = 2L, bridge = bridge))
        advanceUntilIdle()

        viewModel.callOnCleared()
        advanceUntilIdle()

        assertTrue(stubBindings.leaveCalledHandles.contains(1L))
        assertTrue(stubBindings.leaveCalledHandles.contains(2L))
    }

    @Test
    fun `untrackContext prevents leave on cleared`() = runTest(testDispatcher) {
        val viewModel = TestScpViewModel()
        val ctx = TrackedContext(handle = 1L, bridge = bridge)

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
        val ctx = TrackedContext(handle = 42L, bridge = bridge)
        val returned = viewModel.trackContext(ctx)
        assertEquals(ctx, returned)
    }

    @Test
    fun `onCleared clears the active contexts list`() = runTest(testDispatcher) {
        val viewModel = TestScpViewModel()
        viewModel.trackContext(TrackedContext(handle = 1L, bridge = bridge))
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

    override fun contextLeave(contextHandle: Long) {
        leaveCalledHandles.add(contextHandle)
        if (contextHandle == leaveThrowsForHandle) {
            throw ScpLeaveException("leave failed for handle $contextHandle")
        }
    }

    override fun identityCreate(custody: String): Long = 0L
    override fun identityLoad(did: String): Long = 0L
    override fun identityResolve(did: String): String = ""
    override fun contextCreate(identityHandle: Long, paramsJson: String): Long = 0L
    override fun contextJoin(identityHandle: Long, contextId: String): Long = 0L
    override fun contextClose(contextHandle: Long) { /* no-op */ }
    override fun contextSend(contextHandle: Long, payload: ByteArray) { /* no-op */ }
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
    override fun governanceExecute(contextHandle: Long, proposalJson: String): String = "{}"
    override fun governancePropose(contextHandle: Long, proposerDid: String, actionJson: String): String =
        """{"proposal_id":"0000","status":"Pending","execution_result":null}"""
    override fun governanceApprove(contextHandle: Long, voterDid: String, proposalIdHex: String): String =
        """{"status":"Pending"}"""
    override fun governanceReject(contextHandle: Long, voterDid: String, proposalIdHex: String): String =
        """{"status":"Pending"}"""
    override fun governanceWithdraw(contextHandle: Long, voterDid: String, proposalIdHex: String): String =
        """{"status":"Pending"}"""

    // BroadcastBindings
    override fun broadcastSubscribe(contextHandle: Long, subscriberDid: String) = Unit
    override fun broadcastUnsubscribe(contextHandle: Long, subscriberDid: String, rotateKeys: Boolean) = Unit
    override fun broadcastPublish(contextHandle: Long, authorDid: String, payload: ByteArray) = Unit
    override fun broadcastBlockSubscriber(contextHandle: Long, subscriberDid: String, blockerDid: String) = Unit
    override fun broadcastUnblockSubscriber(contextHandle: Long, subscriberDid: String, unblockerDid: String) = Unit
    override fun broadcastHandleKeyRequest(contextHandle: Long, authorDid: String, requesterDid: String): String = "{}"
    override fun broadcastSubscriberCount(contextHandle: Long): Long? = 0L
    override fun broadcastIsSubscriber(contextHandle: Long, did: String): Boolean = false
    override fun broadcastAdmission(contextHandle: Long): String? = null

    override fun toolRegister(contextHandle: Long, definitionJson: String): String = ""
    override fun toolInvoke(contextHandle: Long, toolId: String, inputJson: String): String = ""
    override fun toolVerify(toolId: String, inputJson: String, outputJson: String): Boolean = false
    override fun ucanValidate(token: String, capability: String, contextId: String) { /* no-op */ }
    override fun ucanMint(identityHandle: Long, memberDid: String, capabilitiesJson: String): String = ""
    override fun ucanRevoke(identityHandle: Long, token: String) { /* no-op */ }
    override fun ucanDelegate(
        contextHandle: Long,
        delegatorDid: String,
        delegateeDid: String,
        parentToken: String,
        capabilitiesJson: String,
    ): String = ""
    override fun eventLogQuery(contextId: String, filterJson: String): String = ""
    override fun eventLogVerify(contextId: String, proofJson: String): Boolean = false
    override fun transportConnect(configJson: String, cancellationHandle: CancellationHandle?): Long = 0L
    override fun transportStatus(transportHandle: Long): String = ""
    override fun transportDisconnect(transportHandle: Long) { /* no-op */ }
}

/**
 * Test-specific exception for simulating leave failures in [TestNativeBindings].
 */
private class ScpLeaveException(message: String) : IllegalStateException(message)
