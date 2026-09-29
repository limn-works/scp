// ScpViewModelTest.kt — Tests for ScpViewModel lifecycle resource management (SCP-117)
//
// Verifies that ScpViewModel.onCleared() calls leave() on all tracked contexts
// and that track/untrack operations are thread-safe.
//
// Provenance: ADR-028 acceptance criterion 11, SCP-117

package works.limn.scp.android

import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.ViewModelStore
import works.limn.scp.bridge.CancellationHandle
import works.limn.scp.bridge.CoroutineBridge
import works.limn.scp.bridge.MessageCallback
import works.limn.scp.bridge.NativeBindings
import kotlinx.coroutines.CancellationException
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
import java.util.Collections
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
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

    // The bridge's I/O dispatcher here is the test scheduler, which runs only when the
    // test advances it. A blocking onCleared would wait on that scheduler from the
    // thread that advances it and never return.
    @Test
    fun `onCleared returns before leave runs on the bridge dispatcher`() = runTest(testDispatcher) {
        val viewModel = TestScpViewModel()
        viewModel.trackContext(TrackedContext(handle = 7L, identityHandle = 1L, bridge = bridge))

        viewModel.callOnCleared()
        assertTrue(stubBindings.leaveCalledHandles.isEmpty(), "leave ran before the dispatcher advanced")

        advanceUntilIdle()
        assertEquals(listOf(7L), stubBindings.leaveCalledHandles)
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

    // `.docs/standards/sdk-common.md` §Cleanup error handling requires that a cleanup error be
    // logged rather than dropped. An earlier revision swallowed every throwable except
    // CancellationException, so an app author learned nothing when a departure did not land.
    @Test
    fun `onCleanupFailure receives every leave failure`() = runTest(testDispatcher) {
        stubBindings.leaveThrowsForHandle = 1L

        val viewModel = TestScpViewModel()
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

    // Nothing cancels ScpViewModel's cleanup scope, so a CancellationException that `leave`
    // throws comes from inside `leave` (an injected dispatcher that rejected the task, for
    // one) and never reports that the cleanup coroutine was cancelled. An earlier revision
    // rethrew it, which ended the loop: context 2 was never left and nothing was reported.
    @Test
    fun `a cancellation thrown inside leave reaches onCleanupFailure and later leaves still run`() =
        runTest(testDispatcher) {
            stubBindings.leaveCancelsForHandle = 1L

            val viewModel = TestScpViewModel()
            val ctx1 = TrackedContext(handle = 1L, identityHandle = 1L, bridge = bridge)
            viewModel.trackContext(ctx1)
            viewModel.trackContext(TrackedContext(handle = 2L, identityHandle = 2L, bridge = bridge))
            advanceUntilIdle()

            viewModel.callOnCleared()
            advanceUntilIdle()

            assertEquals(listOf(1L, 2L), stubBindings.leaveCalledHandles)
            assertEquals(listOf(ctx1), viewModel.cleanupFailures.map { it.first })
            assertTrue(
                viewModel.cleanupFailures.single().second is CancellationException,
                "onCleanupFailure must receive the cancellation leave threw",
            )
        }

    // An uncaught throw from the cleanup coroutine would reach the thread's
    // uncaught-exception handler, which on Android kills the process, and would stop every
    // later leave. onCleared catches an override's throw, logs it, and keeps going.
    @Test
    fun `an onCleanupFailure override that throws does not stop later leaves`() =
        runTest(testDispatcher) {
            stubBindings.leaveThrowsForHandle = 1L

            val viewModel = TestScpViewModel(throwFromOnCleanupFailure = true)
            viewModel.trackContext(TrackedContext(handle = 1L, identityHandle = 1L, bridge = bridge))
            viewModel.trackContext(TrackedContext(handle = 2L, identityHandle = 2L, bridge = bridge))
            viewModel.trackContext(TrackedContext(handle = 3L, identityHandle = 3L, bridge = bridge))
            advanceUntilIdle()

            viewModel.callOnCleared()
            advanceUntilIdle()

            assertEquals(listOf(1L, 2L, 3L), stubBindings.leaveCalledHandles)
            assertEquals(listOf(1L), viewModel.cleanupFailures.map { it.first.handle })
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

    // A cancelled cleanup scope would satisfy an "is empty" assertion whether or not
    // onCleared() cleared its tracked list, so this method asserts on recorded contents at
    // each step. Delete `activeContexts.clear()` from onCleared() and a second
    // assertEquals reports [1] against an expected empty list.
    @Test
    fun `onCleared clears the active contexts list`() = runTest(testDispatcher) {
        val viewModel = TestScpViewModel()
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

    // Guards against ending cleanupScope after onCleared dispatches, whether by
    // `cleanupJob.invokeOnCompletion { cleanupScope.cancel() }` or by `cleanupJob.complete()`.
    // Either one starts every later launch already cancelled. The undispatched launch still
    // runs its loop, but each `leave` throws CancellationException from the bridge's
    // `withContext` before its FFI call and goes to onCleanupFailure, whose default body logs
    // a warning, so this leave would never reach TestNativeBindings.
    @Test
    fun `a context tracked after onCleared is left without a second onCleared`() =
        runTest(testDispatcher) {
            val viewModel = TestScpViewModel()
            viewModel.trackContext(TrackedContext(handle = 1L, identityHandle = 1L, bridge = bridge))
            advanceUntilIdle()

            viewModel.callOnCleared()
            advanceUntilIdle()
            assertEquals(listOf(1L), stubBindings.leaveCalledHandles)

            // Android clears a view model once, so nothing but trackContext itself can leave
            // a context registered after that clear.
            viewModel.trackContext(TrackedContext(handle = 2L, identityHandle = 2L, bridge = bridge))
            advanceUntilIdle()

            assertEquals(listOf(1L, 2L), stubBindings.leaveCalledHandles)
        }

    // onCleared's cleanup coroutine and the one a post-clear trackContext launches run
    // `leave` in parallel on Dispatchers.IO. Without the lock around onCleanupFailure, the
    // second failure enters the override while the first is still inside it.
    @Test
    @Timeout(value = 10, unit = TimeUnit.SECONDS, threadMode = Timeout.ThreadMode.SEPARATE_THREAD)
    fun `onCleanupFailure calls from parallel cleanup coroutines never overlap`() {
        stubBindings.leaveAlwaysThrows = true
        val ioBridge = CoroutineBridge(
            nativeBindings = stubBindings,
            ioDispatcher = Dispatchers.IO,
            cpuDispatcher = Dispatchers.IO,
        )
        val viewModel = OverlapProbeViewModel()
        viewModel.trackContext(TrackedContext(handle = 1L, identityHandle = 1L, bridge = ioBridge))
        viewModel.callOnCleared()
        assertTrue(viewModel.firstEntered.await(5, TimeUnit.SECONDS), "first failure never arrived")

        // The first override call is parked inside onCleanupFailure; this leave fails on
        // another IO thread while it stays there.
        viewModel.trackContext(TrackedContext(handle = 2L, identityHandle = 2L, bridge = ioBridge))
        val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5)
        while (!stubBindings.leaveCalledHandles.contains(2L) && System.nanoTime() < deadline) {
            Thread.sleep(5)
        }
        assertTrue(stubBindings.leaveCalledHandles.contains(2L), "second leave never ran")
        Thread.sleep(OVERLAP_WINDOW_MS)
        assertEquals(1, viewModel.entered.get(), "second call entered onCleanupFailure concurrently")

        viewModel.releaseFirst.countDown()
        assertTrue(viewModel.bothDone.await(5, TimeUnit.SECONDS), "second failure never arrived")
        assertEquals(1, viewModel.maxInFlight.get())
    }

    // An inline bridge runs a post-clear leave and its onCleanupFailure call inside
    // trackContext only while no other cleanup coroutine holds the failure lock. When one
    // does, trackContext returns with the call still pending, and the call later runs on
    // the thread that released the lock. The KDoc on trackContext, onCleared, and
    // onCleanupFailure states this exception; this method keeps that statement true.
    @Test
    @Timeout(value = 10, unit = TimeUnit.SECONDS, threadMode = Timeout.ThreadMode.SEPARATE_THREAD)
    fun `an inline-bridge failure waits for a running onCleanupFailure and runs on its thread`() {
        stubBindings.leaveAlwaysThrows = true
        val ioBridge = CoroutineBridge(
            nativeBindings = stubBindings,
            ioDispatcher = Dispatchers.IO,
            cpuDispatcher = Dispatchers.IO,
        )
        val inlineBridge = CoroutineBridge(
            nativeBindings = stubBindings,
            ioDispatcher = Dispatchers.Unconfined,
            cpuDispatcher = Dispatchers.Unconfined,
        )
        val viewModel = OverlapProbeViewModel()
        viewModel.trackContext(TrackedContext(handle = 1L, identityHandle = 1L, bridge = ioBridge))
        viewModel.callOnCleared()
        assertTrue(viewModel.firstEntered.await(5, TimeUnit.SECONDS), "first failure never arrived")

        viewModel.trackContext(TrackedContext(handle = 2L, identityHandle = 2L, bridge = inlineBridge))

        assertTrue(
            stubBindings.leaveCalledHandles.contains(2L),
            "inline leave did not run inside trackContext",
        )
        assertEquals(
            1,
            viewModel.entered.get(),
            "second call ran inside trackContext although the failure lock was held",
        )

        viewModel.releaseFirst.countDown()
        assertTrue(viewModel.bothDone.await(5, TimeUnit.SECONDS), "second failure never arrived")
        val threads = viewModel.callThreads.toList()
        assertEquals(2, threads.size)
        assertEquals(threads[0], threads[1], "second call did not run on the releasing thread")
        assertNotEquals(Thread.currentThread(), threads[1], "second call ran on the trackContext caller")
    }

    // An override that retries calls trackContext from inside a cleanup coroutine on
    // Dispatchers.Unconfined. A default-start launch there is queued on the thread's unconfined
    // event loop, so the retry's inline leave would run only after the override returned.
    // Undispatched start runs it inside trackContext, as trackContext's KDoc states; the
    // retry's own failure waits for the retrying override and still runs before onCleared
    // returns, on the calling thread.
    @Test
    fun `an inline leave retried from onCleanupFailure runs before trackContext returns`() {
        stubBindings.leaveAlwaysThrows = true
        val inlineBridge = CoroutineBridge(
            nativeBindings = stubBindings,
            ioDispatcher = Dispatchers.Unconfined,
            cpuDispatcher = Dispatchers.Unconfined,
        )
        val retry = TrackedContext(handle = 2L, identityHandle = 2L, bridge = inlineBridge)
        val viewModel = RetryingViewModel(retry, stubBindings)
        viewModel.trackContext(TrackedContext(handle = 1L, identityHandle = 1L, bridge = inlineBridge))

        viewModel.callOnCleared()

        assertEquals(
            listOf(1L, 2L),
            viewModel.leftWhenRetryReturned,
            "retried leave ran after trackContext returned",
        )
        assertEquals(listOf(1L, 2L), viewModel.failedHandles)
        assertEquals(listOf(Thread.currentThread(), Thread.currentThread()), viewModel.callThreads)
    }

    // A Java subclass of ScpViewModel calls `super()`, so a zero-argument JVM constructor is
    // part of this artifact's published surface. Adding a primary-constructor parameter
    // without a default removes it and fails this method.
    @Test
    fun `ScpViewModel exposes a zero-argument constructor to Java callers`() {
        val parameterCounts = ScpViewModel::class.java.declaredConstructors
            .map { it.parameterCount }
            .toSet()
        assertTrue(
            parameterCounts.contains(0),
            "expected a zero-argument constructor, found arities $parameterCounts",
        )
    }

}

private const val OVERLAP_WINDOW_MS = 200L

/** Records how many [onCleanupFailure] calls run at once; parks the first until released. */
private class OverlapProbeViewModel : ScpViewModel() {
    val entered = AtomicInteger()
    val maxInFlight = AtomicInteger()
    val firstEntered = CountDownLatch(1)
    val releaseFirst = CountDownLatch(1)
    val bothDone = CountDownLatch(2)
    private val inFlight = AtomicInteger()

    /** The thread each [onCleanupFailure] call ran on, in call order. */
    val callThreads: MutableList<Thread> = Collections.synchronizedList(mutableListOf())

    override fun onCleanupFailure(context: TrackedContext, cause: Throwable) {
        callThreads += Thread.currentThread()
        val now = inFlight.incrementAndGet()
        maxInFlight.accumulateAndGet(now) { a, b -> maxOf(a, b) }
        if (entered.incrementAndGet() == 1) {
            firstEntered.countDown()
            releaseFirst.await(5, TimeUnit.SECONDS)
        }
        inFlight.decrementAndGet()
        bothDone.countDown()
    }

    fun callOnCleared() {
        val store = ViewModelStore()
        val self = this
        val factory =
            object : ViewModelProvider.Factory {
                @Suppress("UNCHECKED_CAST")
                override fun <T : ViewModel> create(modelClass: Class<T>): T = self as T
            }
        ViewModelProvider(store, factory)[OverlapProbeViewModel::class.java]
        store.clear()
    }
}

/** Retries the first failed departure once by tracking [retry] from inside the override. */
private class RetryingViewModel(
    private val retry: TrackedContext,
    private val bindings: TestNativeBindings,
) : ScpViewModel() {
    val failedHandles = mutableListOf<Long>()
    val callThreads = mutableListOf<Thread>()

    /** The bridge's recorded `leave` handles at the moment the retry's trackContext returned. */
    var leftWhenRetryReturned: List<Long> = emptyList()

    override fun onCleanupFailure(context: TrackedContext, cause: Throwable) {
        failedHandles += context.handle
        callThreads += Thread.currentThread()
        if (context !== retry) {
            trackContext(retry)
            leftWhenRetryReturned = bindings.leaveCalledHandles.toList()
        }
    }

    fun callOnCleared() {
        val store = ViewModelStore()
        val self = this
        val factory =
            object : ViewModelProvider.Factory {
                @Suppress("UNCHECKED_CAST")
                override fun <T : ViewModel> create(modelClass: Class<T>): T = self as T
            }
        ViewModelProvider(store, factory)[RetryingViewModel::class.java]
        store.clear()
    }
}

/**
 * Concrete [ScpViewModel] subclass for testing.
 *
 * [callOnCleared] clears the view model through a [ViewModelStore], so the call runs
 * the same `ViewModel.clear()` Android runs: `clear()` cancels `viewModelScope` and then
 * calls [onCleared]. Calling [onCleared] directly would skip the cancellation.
 */
private class TestScpViewModel(
    private val throwFromOnCleanupFailure: Boolean = false,
) : ScpViewModel() {
    /** Every (context, cause) pair that [onCleanupFailure] received, in call order. */
    val cleanupFailures = mutableListOf<Pair<TrackedContext, Throwable>>()

    override fun onCleanupFailure(context: TrackedContext, cause: Throwable) {
        cleanupFailures += context to cause
        if (throwFromOnCleanupFailure) {
            throw IllegalStateException("override failed closed for handle ${context.handle}", cause)
        }
    }

    fun callOnCleared() {
        val store = ViewModelStore()
        val self = this
        val factory =
            object : ViewModelProvider.Factory {
                @Suppress("UNCHECKED_CAST")
                override fun <T : ViewModel> create(modelClass: Class<T>): T = self as T
            }
        ViewModelProvider(store, factory)[TestScpViewModel::class.java]
        store.clear()
    }
}

/**
 * Test stub for [NativeBindings] that tracks leave calls per context handle.
 */
@Suppress("TooManyFunctions")
internal class TestNativeBindings : NativeBindings {
    /** Synchronized because a test with a dispatching bridge calls `leave` from two threads. */
    val leaveCalledHandles: MutableList<Long> = Collections.synchronizedList(mutableListOf())
    var leaveThrowsForHandle: Long? = null

    /** When true, every leave throws, whatever its handle. */
    @Volatile var leaveAlwaysThrows = false

    /**
     * Handle whose leave raises a cancellation the cleanup coroutine did not cause, as an
     * injected dispatcher that rejects the task does.
     */
    var leaveCancelsForHandle: Long? = null

    override fun contextLeave(contextHandle: Long, identityHandle: Long) {
        leaveCalledHandles.add(contextHandle)
        if (contextHandle == leaveCancelsForHandle) {
            throw CancellationException("cleanup cancelled at handle $contextHandle")
        }
        if (leaveAlwaysThrows || contextHandle == leaveThrowsForHandle) {
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
internal class ScpLeaveException(message: String) : IllegalStateException(message)
