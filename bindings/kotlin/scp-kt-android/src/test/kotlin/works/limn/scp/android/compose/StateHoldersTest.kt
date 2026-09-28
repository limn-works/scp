// StateHoldersTest.kt — Tests for Compose state holders (SCP-118)
// Provenance: ADR-028 (Kotlin SDK) Compose integration, SCP-118

package works.limn.scp.android.compose

import android.util.Log
import androidx.compose.runtime.Composable
import androidx.compose.runtime.State
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.key
import androidx.compose.ui.test.junit4.createComposeRule
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.asCoroutineDispatcher
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharedFlow
import kotlinx.coroutines.isActive
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import org.robolectric.shadows.ShadowLog
import java.util.Collections
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.LinkedBlockingDeque
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong
import kotlin.concurrent.thread
import kotlin.coroutines.CoroutineContext

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
        // Reaching this line is the check: onStop is parked on releaseOnStop, which opens only
        // below, so a disposal that waited for onStop would have hung waitForIdle above.
        releaseOnStop.countDown()
        assertTrue(
            "onStop did not return after its latch opened",
            onStopReturned.await(AWAIT_TIMEOUT_SECONDS, TimeUnit.SECONDS),
        )
    }

    @Test
    fun `rememberScpHotStream returns the started flow`() {
        val eventFlow = MutableSharedFlow<String>()
        var flowState: State<SharedFlow<String>?>? = null
        var capturedFlow: SharedFlow<String>? = null
        val coordinator = ScpHotStreamCoordinator(newCoordinatorScope())

        composeRule.setContent {
            val state = rememberScpHotStream(
                key = "key",
                coordinator = coordinator,
                start = { eventFlow },
                onStop = {},
            )
            flowState = state
            capturedFlow = state.value
        }

        // rememberScpHotStream writes the state from Dispatchers.IO. The
        // Compose test clock that waitUntil advances does not deliver that
        // write's apply notification, so wait for the write itself, then let
        // waitForIdle deliver the notification and run the recomposition.
        composeRule.waitUntil(WAIT_TIMEOUT_MS) { flowState?.value === eventFlow }
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
    fun `rememberScpEventList accumulates events`() {
        val eventFlow = hotEventFlow()
        var observed: List<String> = emptyList()

        composeRule.setContent {
            val state by rememberScpEventList(eventFlow)
            observed = state
        }
        composeRule.waitUntil(WAIT_TIMEOUT_MS) { eventFlow.subscriptionCount.value >= 1 }

        assertTrue(eventFlow.tryEmit("event-1"))
        composeRule.waitUntil(WAIT_TIMEOUT_MS) { observed == listOf("event-1") }

        assertTrue(eventFlow.tryEmit("event-2"))
        composeRule.waitUntil(WAIT_TIMEOUT_MS) { observed == listOf("event-1", "event-2") }
    }

    @Test
    fun `rememberScpEventList caps at maxItems`() {
        val eventFlow = hotEventFlow()
        var observed: List<String> = emptyList()

        composeRule.setContent {
            val state by rememberScpEventList(eventFlow, maxItems = 2)
            observed = state
        }
        composeRule.waitUntil(WAIT_TIMEOUT_MS) { eventFlow.subscriptionCount.value >= 1 }

        assertTrue(eventFlow.tryEmit("a"))
        composeRule.waitUntil(WAIT_TIMEOUT_MS) { observed == listOf("a") }

        assertTrue(eventFlow.tryEmit("b"))
        composeRule.waitUntil(WAIT_TIMEOUT_MS) { observed == listOf("a", "b") }

        assertTrue(eventFlow.tryEmit("c"))
        composeRule.waitUntil(WAIT_TIMEOUT_MS) { observed == listOf("b", "c") }
    }

    @Test
    fun `rememberScpEventList subscribes during composition and keeps an event emitted right after`() {
        val eventFlow = hotEventFlow()
        var observed: List<String> = emptyList()

        composeRule.setContent {
            val state by rememberScpEventList(eventFlow)
            observed = state
        }

        // No wait of any kind between composition and the emission: a hot
        // flow with replay = 0 drops an event that no subscriber holds, so
        // the event survives only if composition itself subscribed.
        assertTrue(eventFlow.subscriptionCount.value >= 1)
        assertTrue(eventFlow.tryEmit("immediate"))
        composeRule.waitForIdle()
        assertEquals(listOf("immediate"), observed)
    }

    @Test
    fun `rememberScpEventList stops collecting when leaving composition`() {
        val eventFlow = hotEventFlow()
        val showComposable = MutableStateFlow(true)

        composeRule.setContent {
            val show by showComposable.collectAsStateCompat()
            if (show) {
                rememberScpEventList(eventFlow)
            }
        }
        composeRule.waitUntil(WAIT_TIMEOUT_MS) { eventFlow.subscriptionCount.value >= 1 }

        showComposable.value = false
        composeRule.waitUntil(WAIT_TIMEOUT_MS) { eventFlow.subscriptionCount.value == 0 }
    }

    @Test
    fun `rememberScpStateIn subscribes during composition and keeps an event emitted right after`() {
        val eventFlow = hotEventFlow()
        var observed = ""

        composeRule.setContent {
            val holder = rememberScpContext(contextHandle = 3L, identityHandle = 4L) { _, _ -> }
            val state by rememberScpStateIn(holder, eventFlow, "initial")
            observed = state
        }

        assertTrue(eventFlow.subscriptionCount.value >= 1)
        assertTrue(eventFlow.tryEmit("immediate"))
        composeRule.waitForIdle()
        assertEquals("immediate", observed)
    }

    @Test
    fun `rememberScpStateIn stops collecting when leaving composition`() {
        val eventFlow = hotEventFlow()
        val showComposable = MutableStateFlow(true)

        composeRule.setContent {
            val show by showComposable.collectAsStateCompat()
            if (show) {
                val holder = rememberScpContext(contextHandle = 5L, identityHandle = 6L) { _, _ -> }
                rememberScpStateIn(holder, eventFlow, "initial")
            }
        }
        composeRule.waitUntil(WAIT_TIMEOUT_MS) { eventFlow.subscriptionCount.value >= 1 }

        showComposable.value = false
        composeRule.waitUntil(WAIT_TIMEOUT_MS) { eventFlow.subscriptionCount.value == 0 }
    }

    @Test
    fun `rememberScpStateIn stops collecting when the holder is disposed`() {
        val eventFlow = hotEventFlow()
        val holder = ScpContextHolder(
            contextHandle = 8L,
            identityHandle = 9L,
            scope = CoroutineScope(SupervisorJob()),
            onDispose = { _, _ -> },
        )

        composeRule.setContent {
            rememberScpStateIn(holder, eventFlow, "initial")
        }
        composeRule.waitUntil(WAIT_TIMEOUT_MS) { eventFlow.subscriptionCount.value >= 1 }

        holder.dispose()
        composeRule.waitUntil(WAIT_TIMEOUT_MS) { eventFlow.subscriptionCount.value == 0 }
    }

    @Test
    fun `rememberScpFlow subscribes during composition and keeps an event emitted right after`() {
        val eventFlow = hotEventFlow()
        var observed = ""

        composeRule.setContent {
            val state by rememberScpFlow(eventFlow, "initial")
            observed = state
        }

        assertTrue(eventFlow.subscriptionCount.value >= 1)
        assertTrue(eventFlow.tryEmit("immediate"))
        composeRule.waitForIdle()
        assertEquals("immediate", observed)
    }

    @Test
    fun `rememberScpContext disposes scope on cleanup`() {
        val showComposable = MutableStateFlow(true)
        var capturedHolder: ScpContextHolder? = null
        var scopeActiveAtOnDispose: Boolean? = null

        composeRule.setContent {
            val show by showComposable.collectAsStateCompat()
            if (show) {
                capturedHolder =
                    rememberScpContext(contextHandle = 1L, identityHandle = 2L) { _, _ ->
                        scopeActiveAtOnDispose = capturedHolder?.scope?.isActive
                    }
            }
        }

        composeRule.waitForIdle()
        val holder = capturedHolder
        assertTrue(holder != null)

        showComposable.value = false
        composeRule.waitForIdle()

        assertTrue(!holder!!.scope.isActive)
        assertEquals("onDispose ran before the holder's scope was cancelled", false, scopeActiveAtOnDispose)
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
     *
     * The swapped-out coordinator's `onStop` and the swapped-in coordinator's `start` go
     * through two coordinators, so neither coordinator orders them. This method holds that
     * `onStop` open on a latch. A `start` that does not wait for it runs while subscription 1
     * is still live, reuses it, and the released stop then leaves no live subscription, so
     * the `startCalls` assertion below fails.
     */
    @Test(timeout = DISPOSAL_TIMEOUT_MS)
    fun `a coordinator swap under one same key opens a subscription on the new coordinator`() {
        val subscriptions = FakeSubscriptionRegistry()
        val startCalls = AtomicInteger(0)
        val releaseStop = CountDownLatch(1)
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
                    startCalls.incrementAndGet()
                    subscriptions.subscribe()
                    eventFlow
                },
                onStop = {
                    releaseStop.await(AWAIT_TIMEOUT_SECONDS, TimeUnit.SECONDS)
                    subscriptions.unsubscribeLive()
                },
            )
        }

        composeRule.waitForIdle()
        awaitCondition("the first coordinator opened no subscription") {
            subscriptions.subscribeIds() == listOf(1)
        }

        activeCoordinator.value = secondCoordinator
        composeRule.waitForIdle()

        // Give an unordered start time to run on its IO thread before the stop is released.
        Thread.sleep(SWAP_START_GRACE_MS)
        assertEquals(
            "the swapped-in start ran before the swapped-out stop finished",
            1,
            startCalls.get(),
        )
        releaseStop.countDown()

        awaitCondition("the swapped-in coordinator opened no subscription") {
            subscriptions.subscribeIds().size == 2
        }
        awaitCondition("the swapped-out coordinator's stop released nothing") {
            subscriptions.unsubscribeIds() == listOf(1)
        }
        assertEquals(listOf(2), subscriptions.liveIds())
    }

    /**
     * Two mounts under one key, composed at the same time, share one subscription, because a
     * registry such as `HotStreamFactory` hands a second subscriber the subscription it already
     * holds. A navigation transition keeps an outgoing screen composed while an incoming screen
     * starts, which produces exactly this overlap.
     *
     * The first mount to leave must stop nothing yet: its `onStop` would release the subscription
     * the second mount is still collecting, and that collector would then observe a SharedFlow
     * that receives nothing further and reports no error. The last mount to leave runs both
     * mounts' `onStop`, and the second call finds nothing left to release.
     */
    @Test(timeout = DISPOSAL_TIMEOUT_MS)
    fun `an overlapping mount under one same key keeps its subscription when the other mount leaves`() {
        val subscriptions = FakeSubscriptionRegistry()
        val startCalls = AtomicInteger(0)
        val stopCalls = AtomicInteger(0)
        val showFirst = MutableStateFlow(true)
        val showSecond = MutableStateFlow(false)
        val coordinator = ScpHotStreamCoordinator(newCoordinatorScope())
        val eventFlow = MutableSharedFlow<String>()

        composeRule.setContent {
            val first by showFirst.collectAsStateCompat()
            val second by showSecond.collectAsStateCompat()
            listOf(first, second).forEachIndexed { index, shown ->
                if (shown) {
                    key(index) {
                        rememberScpHotStream(
                            key = "shared-key",
                            coordinator = coordinator,
                            start = {
                                startCalls.incrementAndGet()
                                subscriptions.subscribe()
                                eventFlow
                            },
                            onStop = {
                                stopCalls.incrementAndGet()
                                subscriptions.unsubscribeLive()
                            },
                        )
                    }
                }
            }
        }

        composeRule.waitForIdle()
        awaitCondition("the first mount opened no subscription") { startCalls.get() == 1 }

        showSecond.value = true
        composeRule.waitForIdle()
        awaitCondition("the second mount ran no start") { startCalls.get() == 2 }

        showFirst.value = false
        composeRule.waitForIdle()
        // A stop that the first mount's departure launched has this long to run.
        Thread.sleep(SWAP_START_GRACE_MS)
        assertEquals("the first mount's departure ran onStop", 0, stopCalls.get())
        assertEquals(listOf(1), subscriptions.liveIds())

        showSecond.value = false
        composeRule.waitForIdle()
        awaitCondition("the last mount's departure released nothing") {
            subscriptions.unsubscribeIds() == listOf(1)
        }
        awaitCondition("the last mount's departure did not run both onStop lambdas") { stopCalls.get() == 2 }
        assertEquals(listOf(1), subscriptions.unsubscribeIds())
        assertEquals(listOf(1), subscriptions.subscribeIds())
    }

    /**
     * [ScpHotStreamCoordinator.unmount] launches a stop only for the last live mount under a
     * key, that stop runs the `onStop` an earlier departure left held as well as its own, and a
     * later mount under that key joins that stop before its start runs.
     */
    @Test(timeout = DISPOSAL_TIMEOUT_MS)
    fun `a coordinator stops a key only when its last live mount leaves`() {
        // The coordinator's one thread is held busy, so a launched stop has not reached its
        // dispatcher, let alone the key's mutex, until dispatcherFree opens. Only
        // startMounted's join of that stop then orders a later start after it: a start that
        // skipped the join would take the free mutex and run first.
        val executor = Executors.newSingleThreadExecutor()
        val dispatcherFree = CountDownLatch(1)
        executor.execute { dispatcherFree.await() }
        try {
            val coordinator =
                ScpHotStreamCoordinator(CoroutineScope(SupervisorJob() + executor.asCoroutineDispatcher()))
            val stops = AtomicInteger(0)
            val first = coordinator.mount("k")
            val second = coordinator.mount("k")

            val held = checkNotNull(coordinator.unmount(first) { stops.incrementAndGet() })
            assertEquals("unmounting one mount twice", null, coordinator.unmount(first) { stops.incrementAndGet() })
            val stop = coordinator.unmount(second) { stops.incrementAndGet() }
            assertTrue("the last mount's unmount launched no stop", stop != null)
            assertTrue("a held departure's Job completed before any stop ran", !held.isCompleted)

            val third = coordinator.mount("k")
            assertEquals("a later mount did not capture the pending stop", stop, third.pendingStop)

            val stopsSeenByStart = AtomicInteger(-1)
            val starting =
                thread {
                    runBlocking { coordinator.startMounted(third) { stopsSeenByStart.set(stops.get()) } }
                }
            // A start that skipped the join finishes inside this window, seeing no stop.
            starting.join(START_WINDOW_MS)
            dispatcherFree.countDown()
            starting.join()

            assertEquals("a later mount's start ran before the pending stop", 2, stopsSeenByStart.get())
            runBlocking { held.join() }
            assertEquals("a held departure's Job completed before its onStop ran", 2, stops.get())
        } finally {
            dispatcherFree.countDown()
            executor.shutdown()
        }
    }

    /**
     * Two mounts under one key that hold different subscriptions, such as a `contextEvents`
     * stream and an `incomingMessages` stream keyed by one context handle, each have their own
     * `onStop` run. Discarding the first departure's `onStop` would leave its subscription open
     * with no stop to release it.
     */
    @Test(timeout = DISPOSAL_TIMEOUT_MS)
    fun `two different streams under one key each have their onStop run`() {
        val coordinator = ScpHotStreamCoordinator(CoroutineScope(SupervisorJob() + Dispatchers.IO))
        val events = coordinator.mount("k")
        val messages = coordinator.mount("k")
        val stopped = Collections.synchronizedList(mutableListOf<String>())

        val held = checkNotNull(coordinator.unmount(events) { stopped += "events" })
        assertTrue("a held departure's Job completed while a mount stayed live", !held.isCompleted)
        assertEquals("the first departure released a subscription still mounted", emptyList<String>(), stopped)
        val stop = coordinator.unmount(messages) { stopped += "messages" }
        runBlocking { checkNotNull(stop).join() }

        assertEquals(listOf("events", "messages"), stopped.toList())
        runBlocking { held.join() }
    }

    /**
     * A stop launched under a key runs after every stop launched before it under that key, even
     * when the earlier stop reaches its dispatcher last. Otherwise a mount that captured only the
     * later stop could start, reuse a subscription, and then lose it to the earlier stop.
     *
     * [QueuedDispatcher] holds every dispatched task until this method runs it, and this method
     * runs the newest task first, so the second stop reaches the free mutex before the first stop
     * has left its dispatcher queue.
     */
    @Test(timeout = DISPOSAL_TIMEOUT_MS)
    fun `a stop runs after every stop launched before it under that key`() {
        val dispatcher = QueuedDispatcher()
        val coordinator = ScpHotStreamCoordinator(CoroutineScope(SupervisorJob() + dispatcher))
        val stopped = Collections.synchronizedList(mutableListOf<String>())

        val first = checkNotNull(coordinator.unmount(coordinator.mount("k")) { stopped += "first" })
        val secondMount = coordinator.mount("k")
        assertEquals("a later mount did not capture the pending stop", first, secondMount.pendingStop)
        val second = checkNotNull(coordinator.unmount(secondMount) { stopped += "second" })
        val third = coordinator.mount("k")
        assertEquals("a later mount did not capture the newest stop", second, third.pendingStop)

        dispatcher.runNewestFirst()

        assertEquals(listOf("first", "second"), stopped.toList())
        assertTrue("the earlier stop did not finish", first.isCompleted)
        assertTrue("the later stop did not finish", second.isCompleted)
    }

    /**
     * A mount that moves to another coordinator while a second mount under that key stays live
     * on the first coordinator has its `onStop` held there, and that held `onStop` runs when the
     * second mount leaves. A start through the new coordinator that ran before then would reuse
     * the shared subscription, which that held `onStop` and the second mount's `onStop` then
     * release, and the moved mount would collect a SharedFlow that receives nothing further.
     */
    @Test(timeout = DISPOSAL_TIMEOUT_MS)
    fun `a coordinator swap next to a live mount starts only after the old coordinator stops the key`() {
        val subscriptions = FakeSubscriptionRegistry()
        val startCalls = AtomicInteger(0)
        val firstCoordinator = ScpHotStreamCoordinator(newCoordinatorScope())
        val secondCoordinator = ScpHotStreamCoordinator(newCoordinatorScope())
        val movingCoordinator = MutableStateFlow(firstCoordinator)
        val showStaying = MutableStateFlow(true)
        val eventFlow = MutableSharedFlow<String>()

        composeRule.setContent {
            val moving by movingCoordinator.collectAsStateCompat()
            val staying by showStaying.collectAsStateCompat()
            listOf(moving to true, firstCoordinator to staying).forEachIndexed { index, (coordinator, shown) ->
                if (shown) {
                    key(index) {
                        rememberScpHotStream(
                            key = "shared-key",
                            coordinator = coordinator,
                            start = {
                                startCalls.incrementAndGet()
                                subscriptions.subscribe()
                                eventFlow
                            },
                            onStop = { subscriptions.unsubscribeLive() },
                        )
                    }
                }
            }
        }

        composeRule.waitForIdle()
        awaitCondition("both mounts did not start") { startCalls.get() == 2 }
        assertEquals(listOf(1), subscriptions.subscribeIds())

        movingCoordinator.value = secondCoordinator
        composeRule.waitForIdle()
        // A start through the new coordinator that does not wait for the held stop runs here.
        Thread.sleep(SWAP_START_GRACE_MS)
        assertEquals("the moved mount started while the old coordinator held its onStop", 2, startCalls.get())
        assertEquals(listOf(1), subscriptions.liveIds())

        showStaying.value = false
        composeRule.waitForIdle()
        awaitCondition("the old coordinator's stop released nothing") {
            subscriptions.unsubscribeIds() == listOf(1)
        }
        awaitCondition("the moved mount opened no subscription after that stop") {
            subscriptions.subscribeIds() == listOf(1, 2)
        }
        assertEquals(3, startCalls.get())
        assertEquals(listOf(2), subscriptions.liveIds())
    }

    /**
     * Two coordinator changes under one key, the second made while the first swapped-out stop
     * is still suspended, start the third coordinator only after that first stop finishes.
     *
     * A holder that kept only the latest swapped-out stop dropped the first one here: the
     * second coordinator's stop, for a mount that never started, ran `onStop` at once and
     * released subscription 1, the third coordinator's start opened subscription 2, and the
     * first stop then released subscription 2, leaving the third coordinator collecting a
     * SharedFlow that receives nothing further.
     */
    @Test(timeout = DISPOSAL_TIMEOUT_MS)
    fun `two coordinator changes under one key start only after the first swapped-out stop`() {
        val subscriptions = FakeSubscriptionRegistry()
        val startCalls = AtomicInteger(0)
        val stopCalls = AtomicInteger(0)
        val releaseFirstStop = CountDownLatch(1)
        val coordinators = List(3) { ScpHotStreamCoordinator(newCoordinatorScope()) }
        val activeCoordinator = MutableStateFlow(coordinators[0])
        val eventFlow = MutableSharedFlow<String>()

        composeRule.setContent {
            val coordinator by activeCoordinator.collectAsStateCompat()
            rememberScpHotStream(
                key = "shared-key",
                coordinator = coordinator,
                start = {
                    startCalls.incrementAndGet()
                    subscriptions.subscribe()
                    eventFlow
                },
                onStop = {
                    if (stopCalls.incrementAndGet() == 1) {
                        releaseFirstStop.await(AWAIT_TIMEOUT_SECONDS, TimeUnit.SECONDS)
                    }
                    subscriptions.unsubscribeLive()
                },
            )
        }

        composeRule.waitForIdle()
        awaitCondition("the first coordinator opened no subscription") { startCalls.get() == 1 }

        activeCoordinator.value = coordinators[1]
        composeRule.waitForIdle()
        awaitCondition("the first coordinator did not begin its stop") { stopCalls.get() == 1 }
        activeCoordinator.value = coordinators[2]
        composeRule.waitForIdle()

        Thread.sleep(SWAP_START_GRACE_MS)
        assertEquals("a start ran before the first swapped-out stop finished", 1, startCalls.get())
        assertEquals("a mount that never started ran onStop", 1, stopCalls.get())
        releaseFirstStop.countDown()

        awaitCondition("the third coordinator opened no subscription") {
            subscriptions.subscribeIds() == listOf(1, 2)
        }
        assertEquals(listOf(1), subscriptions.unsubscribeIds())
        assertEquals(listOf(2), subscriptions.liveIds())
        assertEquals("a mount that never started ran onStop", 1, stopCalls.get())
    }

    /**
     * A mount that moves to another coordinator while a second mount under that key stays live
     * on the first one, and then leaves before the first coordinator releases the key, releases
     * nothing: it never started on the new coordinator, so its `onStop` there would release
     * the subscription the staying mount still collects.
     */
    @Test(timeout = DISPOSAL_TIMEOUT_MS)
    fun `a moved mount that leaves before it starts releases nothing a live mount collects`() {
        val subscriptions = FakeSubscriptionRegistry()
        val startCalls = AtomicInteger(0)
        val firstCoordinator = ScpHotStreamCoordinator(newCoordinatorScope())
        val secondCoordinator = ScpHotStreamCoordinator(newCoordinatorScope())
        val movingCoordinator = MutableStateFlow(firstCoordinator)
        val showMoving = MutableStateFlow(true)
        val showStaying = MutableStateFlow(true)
        val eventFlow = MutableSharedFlow<String>()

        composeRule.setContent {
            val moving by movingCoordinator.collectAsStateCompat()
            val movingShown by showMoving.collectAsStateCompat()
            val staying by showStaying.collectAsStateCompat()
            listOf(moving to movingShown, firstCoordinator to staying).forEachIndexed { index, (coordinator, shown) ->
                if (shown) {
                    key(index) {
                        rememberScpHotStream(
                            key = "shared-key",
                            coordinator = coordinator,
                            start = {
                                startCalls.incrementAndGet()
                                subscriptions.subscribe()
                                eventFlow
                            },
                            onStop = { subscriptions.unsubscribeLive() },
                        )
                    }
                }
            }
        }

        composeRule.waitForIdle()
        awaitCondition("both mounts did not start") { startCalls.get() == 2 }

        movingCoordinator.value = secondCoordinator
        composeRule.waitForIdle()
        showMoving.value = false
        composeRule.waitForIdle()
        // A stop that runs the moved mount's onStop on the new coordinator runs here.
        Thread.sleep(SWAP_START_GRACE_MS)
        assertEquals(
            "the moved mount's departure released the staying mount's subscription",
            listOf(1),
            subscriptions.liveIds(),
        )
        assertEquals(emptyList<Int>(), subscriptions.unsubscribeIds())

        showStaying.value = false
        composeRule.waitForIdle()
        awaitCondition("the staying mount's departure released nothing") {
            subscriptions.unsubscribeIds() == listOf(1)
        }
        assertEquals(2, startCalls.get())
    }

    /**
     * A mount that moves to another coordinator and back while a second mount under that key
     * stays live on the first one starts again on the first coordinator at once, and the move
     * releases nothing. The first coordinator still holds the moved mount's first `onStop`
     * behind the staying mount, so a start that waited for it would wait on its own departure,
     * and a stop that ran the unstarted mount's `onStop` on the second coordinator would
     * release the subscription the staying mount collects.
     */
    @Test(timeout = DISPOSAL_TIMEOUT_MS)
    fun `a mount that moves away and back next to a live mount starts again and releases nothing`() {
        val subscriptions = FakeSubscriptionRegistry()
        val startCalls = AtomicInteger(0)
        val firstCoordinator = ScpHotStreamCoordinator(newCoordinatorScope())
        val secondCoordinator = ScpHotStreamCoordinator(newCoordinatorScope())
        val movingCoordinator = MutableStateFlow(firstCoordinator)
        val showStaying = MutableStateFlow(true)
        val eventFlow = MutableSharedFlow<String>()

        composeRule.setContent {
            val moving by movingCoordinator.collectAsStateCompat()
            val staying by showStaying.collectAsStateCompat()
            listOf(moving to true, firstCoordinator to staying).forEachIndexed { index, (coordinator, shown) ->
                if (shown) {
                    key(index) {
                        rememberScpHotStream(
                            key = "shared-key",
                            coordinator = coordinator,
                            start = {
                                startCalls.incrementAndGet()
                                subscriptions.subscribe()
                                eventFlow
                            },
                            onStop = { subscriptions.unsubscribeLive() },
                        )
                    }
                }
            }
        }

        composeRule.waitForIdle()
        awaitCondition("both mounts did not start") { startCalls.get() == 2 }

        movingCoordinator.value = secondCoordinator
        composeRule.waitForIdle()
        movingCoordinator.value = firstCoordinator
        composeRule.waitForIdle()

        awaitCondition("the mount that moved back did not start again") { startCalls.get() == 3 }
        Thread.sleep(SWAP_START_GRACE_MS)
        assertEquals(
            "the moves released the staying mount's subscription",
            emptyList<Int>(),
            subscriptions.unsubscribeIds(),
        )
        assertEquals(listOf(1), subscriptions.liveIds())
        assertEquals(listOf(1), subscriptions.subscribeIds())
    }

    /**
     * A start that takes the key's mutex after its own mount's stop ran never runs: that stop
     * found nothing to release, so anything the start opened would stay open with no stop.
     */
    @Test(timeout = DISPOSAL_TIMEOUT_MS)
    fun `a start that reaches the mutex after its own mount's stop does not run`() {
        val coordinator = ScpHotStreamCoordinator(CoroutineScope(SupervisorJob() + Dispatchers.IO))
        val mount = coordinator.mount("k")
        val stop = coordinator.unmount(mount) { }
        runBlocking { checkNotNull(stop).join() }

        val started = AtomicBoolean(false)
        val outcome = runCatching { runBlocking { coordinator.startMounted(mount) { started.set(true) } } }

        assertTrue(
            "a start after its own mount's stop did not fail",
            outcome.exceptionOrNull() is CancellationException,
        )
        assertEquals("a start after its own mount's stop ran", false, started.get())
    }

    /**
     * A throwing `onStop` is logged, and neither escapes its coroutine nor cancels the
     * coordinator's scope, so the next stop under that scope still runs. A plain [Job] scope
     * shows the second half: an escaping throw would cancel it.
     */
    @Test(timeout = DISPOSAL_TIMEOUT_MS)
    fun `a throwing onStop is logged and later stops still run`() {
        ShadowLog.clear()
        val scope = CoroutineScope(Job() + Dispatchers.IO)
        val coordinator = ScpHotStreamCoordinator(scope)
        val failure = IllegalStateException("engine already dropped the context")

        val failed = coordinator.unmount(coordinator.mount("k")) { throw failure }
        runBlocking { checkNotNull(failed).join() }

        val stops = AtomicInteger(0)
        val next = coordinator.unmount(coordinator.mount("k")) { stops.incrementAndGet() }
        runBlocking { checkNotNull(next).join() }

        assertTrue("a throwing onStop cancelled the coordinator's scope", scope.isActive)
        assertEquals("a stop after a throwing onStop did not run", 1, stops.get())
        val warning = ShadowLog.getLogsForTag("ScpHotStreamCoordinator").single()
        assertEquals(Log.WARN, warning.type)
        assertEquals(failure, warning.throwable)
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
 * Holds every task dispatched to it until [runNewestFirst] runs it, so a test decides which of
 * two launched coroutines runs first.
 */
private class QueuedDispatcher : CoroutineDispatcher() {
    private val tasks = LinkedBlockingDeque<Runnable>()

    override fun dispatch(
        context: CoroutineContext,
        block: Runnable,
    ) {
        tasks.addLast(block)
    }

    /** Run queued tasks on this thread, newest first, until none is left. */
    fun runNewestFirst() {
        while (true) {
            val task = tasks.pollLast() ?: return
            task.run()
        }
    }
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
 * Build a scope for one [ScpHotStreamCoordinator]. A production caller owns this scope with the
 * same lifetime as the registry that coordinator orders — an Application, a dependency-graph
 * singleton, or a ViewModel every navigation destination shares holds it — and composable
 * disposal never cancels it.
 */
private fun newCoordinatorScope(): CoroutineScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

/** Real-time window in which a start that skips its pending stop's join finishes. */
private const val START_WINDOW_MS = 500L

/**
 * Convenience extension mirroring collectAsState for MutableStateFlow
 * within test composables. Uses the Compose runtime's collectAsState.
 */
@Composable
private fun <T> MutableStateFlow<T>.collectAsStateCompat() =
    collectAsState()

/**
 * A hot event flow shaped like the SDK's streams: it replays nothing, so an
 * event emitted while no subscriber holds the flow is dropped.
 *
 * The extra buffer lets the test thread hand an event to a subscriber with
 * [MutableSharedFlow.tryEmit]. Without a buffer, `tryEmit` fails whenever a
 * subscriber exists, and a suspending `emit` from the test thread would wait
 * on a collector that runs on that same thread. The buffer holds events only
 * for subscribers that already exist, so it does not change what is dropped.
 */
private fun hotEventFlow() =
    MutableSharedFlow<String>(replay = 0, extraBufferCapacity = HOT_FLOW_BUFFER)

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

/** How long a coordinator-swap test lets an unordered start run before releasing a stop. */
private const val SWAP_START_GRACE_MS = 300L

private const val WAIT_TIMEOUT_MS = 5_000L

private const val HOT_FLOW_BUFFER = 16
