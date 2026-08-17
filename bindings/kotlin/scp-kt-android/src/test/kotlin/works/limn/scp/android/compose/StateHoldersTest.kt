// StateHoldersTest.kt — Tests for Compose state holders (SCP-118)
// Provenance: ADR-028 (Kotlin SDK) Compose integration, SCP-118

package works.limn.scp.android.compose

import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.ui.test.junit4.createComposeRule
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong

@OptIn(ExperimentalCoroutinesApi::class)
@RunWith(RobolectricTestRunner::class)
@Config(manifest = Config.NONE, sdk = [33])
class StateHoldersTest {

    @get:Rule
    val composeRule = createComposeRule()

    @Test
    fun `rememberScpContext creates holder with correct handle`() {
        var capturedHandle = -1L
        var capturedIdentityHandle = -1L

        composeRule.setContent {
            val holder = rememberScpContext(contextHandle = 42L, identityHandle = 99L) { _, _ -> }
            capturedHandle = holder.contextHandle
            capturedIdentityHandle = holder.identityHandle
        }

        composeRule.waitForIdle()
        assertEquals(42L, capturedHandle)
        assertEquals(99L, capturedIdentityHandle)
    }

    @Test
    fun `rememberScpContext calls onDispose when leaving composition`() {
        val disposed = AtomicBoolean(false)
        val disposedHandle = AtomicLong(-1L)
        val disposedIdentityHandle = AtomicLong(-1L)
        val showComposable = MutableStateFlow(true)

        composeRule.setContent {
            val show by showComposable.collectAsStateCompat()
            if (show) {
                rememberScpContext(contextHandle = 7L, identityHandle = 13L) { handle, identityHandle ->
                    disposedHandle.set(handle)
                    disposedIdentityHandle.set(identityHandle)
                    disposed.set(true)
                }
            }
        }

        composeRule.waitForIdle()
        assertEquals(false, disposed.get())

        showComposable.value = false
        composeRule.waitForIdle()

        assertEquals(true, disposed.get())
        assertEquals(7L, disposedHandle.get())
        assertEquals(13L, disposedIdentityHandle.get())
    }

    @Test
    fun `rememberScpFlow collects initial value`() {
        val flow = MutableStateFlow("initial")
        var observed = ""

        composeRule.setContent {
            val state by rememberScpFlow(flow, "default")
            observed = state
        }

        composeRule.waitForIdle()
        assertEquals("initial", observed)
    }

    @Test
    fun `rememberScpFlow updates on new emissions`() {
        val flow = MutableStateFlow("first")
        var observed = ""

        composeRule.setContent {
            val state by rememberScpFlow(flow, "default")
            observed = state
        }

        composeRule.waitForIdle()
        assertEquals("first", observed)

        flow.value = "second"
        composeRule.waitForIdle()
        assertEquals("second", observed)
    }

    @Test
    fun `rememberScpFlow uses initial value before first emission`() {
        val flow = MutableSharedFlow<String>()
        var observed = ""

        composeRule.setContent {
            val state by rememberScpFlow(flow, "placeholder")
            observed = state
        }

        composeRule.waitForIdle()
        assertEquals("placeholder", observed)
    }

    @Test
    fun `rememberScpContextState exposes initial state`() {
        var observed = ""

        composeRule.setContent {
            val contextState = rememberScpContextState(1L) { "active" }
            observed = contextState.value
        }

        composeRule.waitForIdle()
        assertEquals("active", observed)
    }

    @Test
    fun `rememberScpContextState refresh triggers recomposition`() {
        var queryCount = 0
        val states = listOf("active", "closing", "closed")
        var observed = ""
        var capturedState: ScpContextState? = null

        composeRule.setContent {
            val contextState = rememberScpContextState(1L) {
                val state = states[queryCount.coerceAtMost(states.size - 1)]
                queryCount++
                state
            }
            capturedState = contextState
            observed = contextState.value
        }

        composeRule.waitForIdle()
        assertEquals("active", observed)

        capturedState?.refresh()
        composeRule.waitForIdle()
        assertEquals("closing", observed)
    }

    @Test
    fun `rememberScpHotStream invokes onStop when leaving composition`() {
        val stopped = CountDownLatch(1)
        val eventFlow = MutableSharedFlow<String>()
        val showComposable = MutableStateFlow(true)
        val coordinator = ScpHotStreamCoordinator(newCoordinatorScope())

        composeRule.setContent {
            val show by showComposable.collectAsStateCompat()
            if (show) {
                rememberScpHotStream(
                    key = "test-key",
                    coordinator = coordinator,
                    start = { eventFlow },
                    onStop = { stopped.countDown() },
                )
            }
        }

        composeRule.waitForIdle()
        assertEquals(1L, stopped.count)

        showComposable.value = false
        composeRule.waitForIdle()

        assertTrue(
            "onStop did not run within $AWAIT_TIMEOUT_SECONDS seconds of disposal",
            stopped.await(AWAIT_TIMEOUT_SECONDS, TimeUnit.SECONDS),
        )
    }

    // Guards a shape rememberScpHotStream's onDispose must keep: it launches onStop and
    // returns. A `runBlocking { onStop() }` parks a composition thread until onStop returns,
    // so `waitForIdle` below would never return and this method would hit its own timeout
    // rather than reach an assertion.
    @Test(timeout = DISPOSAL_TIMEOUT_MS)
    fun `rememberScpHotStream disposal returns while onStop is still suspended`() {
        val onStopEntered = CountDownLatch(1)
        val releaseOnStop = CountDownLatch(1)
        val onStopReturned = CountDownLatch(1)
        val eventFlow = MutableSharedFlow<String>()
        val showComposable = MutableStateFlow(true)
        val coordinator = ScpHotStreamCoordinator(newCoordinatorScope())

        composeRule.setContent {
            val show by showComposable.collectAsStateCompat()
            if (show) {
                rememberScpHotStream(
                    key = "blocking-key",
                    coordinator = coordinator,
                    start = { eventFlow },
                    onStop = {
                        onStopEntered.countDown()
                        releaseOnStop.await()
                        onStopReturned.countDown()
                    },
                )
            }
        }

        composeRule.waitForIdle()

        showComposable.value = false
        composeRule.waitForIdle()

        assertTrue(
            "onStop did not start within $AWAIT_TIMEOUT_SECONDS seconds of disposal",
            onStopEntered.await(AWAIT_TIMEOUT_SECONDS, TimeUnit.SECONDS),
        )
        assertEquals(
            "disposal returned before onStop returned",
            1L,
            onStopReturned.count,
        )

        releaseOnStop.countDown()
        assertTrue(
            "onStop did not return after its latch opened",
            onStopReturned.await(AWAIT_TIMEOUT_SECONDS, TimeUnit.SECONDS),
        )
    }

    @Test
    fun `rememberScpHotStream returns the started flow`() {
        val eventFlow = MutableSharedFlow<String>()
        var capturedFlow: kotlinx.coroutines.flow.SharedFlow<String>? = null
        val coordinator = ScpHotStreamCoordinator(newCoordinatorScope())

        composeRule.setContent {
            val flowState by rememberScpHotStream(
                key = "key",
                coordinator = coordinator,
                start = { eventFlow },
                onStop = {},
            )
            capturedFlow = flowState
        }

        composeRule.waitForIdle()
        Thread.sleep(SETTLE_DELAY_MS)
        composeRule.waitForIdle()
        assertTrue(capturedFlow === eventFlow)
    }

    @Test
    fun `rememberScpEventList starts with empty list`() {
        val eventFlow = MutableSharedFlow<String>()
        var observed: List<String> = listOf("non-empty")

        composeRule.setContent {
            val state by rememberScpEventList(eventFlow)
            observed = state
        }

        composeRule.waitForIdle()
        assertEquals(emptyList<String>(), observed)
    }

    @Test
    fun `rememberScpEventList accumulates events`() = runTest {
        val eventFlow = MutableSharedFlow<String>(replay = 0)
        var observed: List<String> = emptyList()

        composeRule.setContent {
            val state by rememberScpEventList(eventFlow)
            observed = state
        }

        composeRule.waitForIdle()

        eventFlow.emit("event-1")
        composeRule.waitForIdle()
        Thread.sleep(SETTLE_DELAY_MS)
        composeRule.waitForIdle()
        assertEquals(listOf("event-1"), observed)

        eventFlow.emit("event-2")
        composeRule.waitForIdle()
        Thread.sleep(SETTLE_DELAY_MS)
        composeRule.waitForIdle()
        assertEquals(listOf("event-1", "event-2"), observed)
    }

    @Test
    fun `rememberScpEventList caps at maxItems`() = runTest {
        val eventFlow = MutableSharedFlow<String>(replay = 0)
        var observed: List<String> = emptyList()

        composeRule.setContent {
            val state by rememberScpEventList(eventFlow, maxItems = 2)
            observed = state
        }

        composeRule.waitForIdle()

        eventFlow.emit("a")
        composeRule.waitForIdle()
        Thread.sleep(SETTLE_DELAY_MS)
        composeRule.waitForIdle()

        eventFlow.emit("b")
        composeRule.waitForIdle()
        Thread.sleep(SETTLE_DELAY_MS)
        composeRule.waitForIdle()

        eventFlow.emit("c")
        composeRule.waitForIdle()
        Thread.sleep(SETTLE_DELAY_MS)
        composeRule.waitForIdle()

        assertEquals(2, observed.size)
        assertEquals("b", observed[0])
        assertEquals("c", observed[1])
    }

    @Test
    fun `rememberScpContext disposes scope on cleanup`() {
        val showComposable = MutableStateFlow(true)
        var capturedHolder: ScpContextHolder? = null

        composeRule.setContent {
            val show by showComposable.collectAsStateCompat()
            if (show) {
                capturedHolder = rememberScpContext(contextHandle = 1L, identityHandle = 2L) { _, _ -> }
            }
        }

        composeRule.waitForIdle()
        val holder = capturedHolder
        assertTrue(holder != null)

        showComposable.value = false
        composeRule.waitForIdle()

        assertTrue(!holder!!.scope.isActive)
    }
}

/**
 * Drives one composable out of composition and back in under one same key, and checks which
 * subscription survives.
 *
 * A stale `onStop` that lands after a second mount started removes whatever subscription a
 * registry holds at that moment. When nothing orders that stop against that start, a collector
 * holds a [kotlinx.coroutines.flow.SharedFlow] that receives nothing further and reports no
 * error, which is what navigating away from a screen and back produced before
 * [ScpHotStreamCoordinator] existed.
 */
@OptIn(ExperimentalCoroutinesApi::class)
@RunWith(RobolectricTestRunner::class)
@Config(manifest = Config.NONE, sdk = [33])
class ScpHotStreamRemountTest {

    @get:Rule
    val composeRule = createComposeRule()

    @Test(timeout = DISPOSAL_TIMEOUT_MS)
    fun `a re-mount under one same key keeps whichever subscription that re-mount opened`() {
        val subscriptions = FakeSubscriptionRegistry()
        val showComposable = MutableStateFlow(true)
        val coordinator = ScpHotStreamCoordinator(newCoordinatorScope())
        val eventFlow = MutableSharedFlow<String>()
        val releaseStop = CountDownLatch(1)

        composeRule.setContent {
            val show by showComposable.collectAsStateCompat()
            if (show) {
                rememberScpHotStream(
                    key = "shared-key",
                    coordinator = coordinator,
                    start = {
                        subscriptions.subscribe()
                        eventFlow
                    },
                    onStop = {
                        releaseStop.await()
                        subscriptions.unsubscribeLive()
                    },
                )
            }
        }

        composeRule.waitForIdle()
        awaitCondition("first mount opened no subscription") {
            subscriptions.subscribeIds() == listOf(1)
        }

        showComposable.value = false
        composeRule.waitForIdle()

        showComposable.value = true
        composeRule.waitForIdle()

        // A second mount has entered composition, and its start lambda has had this long to
        // run. An unsequenced start reuses subscription 1 within that window, which is what
        // makes a stop below remove a subscription that this second mount depends on.
        Thread.sleep(SETTLE_DELAY_MS)
        releaseStop.countDown()

        awaitCondition("a first mount's onStop unsubscribed nothing") {
            subscriptions.unsubscribeIds().size == 1
        }
        awaitCondition("a second mount opened no subscription") {
            subscriptions.subscribeIds().size == 2
        }

        assertEquals(listOf(1, 2), subscriptions.subscribeIds())
        assertEquals(listOf(1), subscriptions.unsubscribeIds())
        assertEquals(listOf(2), subscriptions.liveIds())
    }

    /**
     * A caller who swaps the coordinator while the key stays the same must get a live
     * subscription from the new coordinator.
     *
     * `rememberScpHotStream` remembered its `CoroutineScope` on `key` alone while its
     * `DisposableEffect` keyed on `key` AND `coordinator`. A coordinator swap therefore ran
     * `onDispose` — which cancels that scope — and then relaunched `start` into the SAME
     * cancelled scope, because `key` had not changed. The launch returned an
     * already-cancelled Job, `start` never ran, and the returned `State` kept the previous
     * coordinator's flow: a subscription nobody was serving, reported as a live one.
     */
    @Test(timeout = DISPOSAL_TIMEOUT_MS)
    fun `a coordinator swap under one same key opens a subscription on the new coordinator`() {
        val subscriptions = FakeSubscriptionRegistry()
        val firstCoordinator = ScpHotStreamCoordinator(newCoordinatorScope())
        val secondCoordinator = ScpHotStreamCoordinator(newCoordinatorScope())
        val activeCoordinator = MutableStateFlow(firstCoordinator)
        val eventFlow = MutableSharedFlow<String>()

        composeRule.setContent {
            val coordinator by activeCoordinator.collectAsStateCompat()
            rememberScpHotStream(
                key = "shared-key",
                coordinator = coordinator,
                start = {
                    subscriptions.subscribe()
                    eventFlow
                },
                onStop = { subscriptions.unsubscribeLive() },
            )
        }

        composeRule.waitForIdle()
        awaitCondition("the first coordinator opened no subscription") {
            subscriptions.subscribeIds() == listOf(1)
        }

        activeCoordinator.value = secondCoordinator
        composeRule.waitForIdle()

        awaitCondition("the swapped-in coordinator opened no subscription") {
            subscriptions.subscribeIds().size == 2
        }
        awaitCondition("the swapped-out coordinator's stop released nothing") {
            subscriptions.unsubscribeIds() == listOf(1)
        }
        assertEquals(listOf(2), subscriptions.liveIds())
    }
}

/**
 * Records subscribe and unsubscribe calls for one key, as
 * [works.limn.scp.stream.HotStreamFactory] records them for one context handle.
 *
 * [subscribe] hands back a live subscription when one exists, and [unsubscribeLive] releases
 * whichever subscription is live, so this double reproduces what a stale `onStop` does to a
 * subscription that a later mount is using.
 */
private class FakeSubscriptionRegistry {
    private val lock = Any()
    private var nextId = 0
    private var live: Int? = null
    private val subscribed = mutableListOf<Int>()
    private val unsubscribed = mutableListOf<Int>()

    fun subscribe(): Int =
        synchronized(lock) {
            val existing = live
            if (existing != null) return existing
            nextId++
            live = nextId
            subscribed += nextId
            nextId
        }

    fun unsubscribeLive() {
        synchronized(lock) {
            val current = live ?: return
            unsubscribed += current
            live = null
        }
    }

    fun subscribeIds(): List<Int> = synchronized(lock) { subscribed.toList() }

    fun unsubscribeIds(): List<Int> = synchronized(lock) { unsubscribed.toList() }

    fun liveIds(): List<Int> = synchronized(lock) { listOfNotNull(live) }
}

/**
 * Poll [condition] until it holds, and throw an [AssertionError] carrying [message] when
 * [AWAIT_TIMEOUT_SECONDS] pass without it holding.
 */
private fun awaitCondition(
    message: String,
    condition: () -> Boolean,
) {
    val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(AWAIT_TIMEOUT_SECONDS)
    while (System.nanoTime() < deadline) {
        if (condition()) return
        Thread.sleep(POLL_INTERVAL_MS)
    }
    throw AssertionError(message)
}

/**
 * Build a scope for one [ScpHotStreamCoordinator]. A production caller owns this scope — a
 * ViewModel, an Application, or a dependency graph holds it — and composable disposal never
 * cancels it.
 */
private fun newCoordinatorScope(): CoroutineScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

/**
 * Convenience extension mirroring collectAsState for MutableStateFlow
 * within test composables. Uses the Compose runtime's collectAsState.
 */
@Composable
private fun <T> MutableStateFlow<T>.collectAsStateCompat() =
    collectAsState()

/**
 * Extension property to check if a CoroutineScope is still active.
 */
private val kotlinx.coroutines.CoroutineScope.isActive: Boolean
    get() = coroutineContext[kotlinx.coroutines.Job]?.isActive == true

private const val SETTLE_DELAY_MS = 100L

/** Upper bound on how long a test waits for a latch that another thread opens. */
private const val AWAIT_TIMEOUT_SECONDS = 10L

/** Gap between two reads of a condition that another thread makes true. */
private const val POLL_INTERVAL_MS = 10L

/**
 * Wall-clock limit for a method that would hang, rather than fail, if disposal blocked on
 * onStop again.
 */
private const val DISPOSAL_TIMEOUT_MS = 60_000L
