// StateHoldersTest.kt — Tests for Compose state holders (SCP-118)
// Provenance: ADR-028 (Kotlin SDK) Compose integration, SCP-118

package works.limn.scp.android.compose

import android.util.Log
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.State
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.key
import androidx.compose.ui.test.junit4.createComposeRule
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.Job
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.asCoroutineDispatcher
import kotlinx.coroutines.cancel
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharedFlow
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.withContext
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotSame
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import org.robolectric.shadows.ShadowLog
import works.limn.scp.stream.EventContextBindings
import java.lang.reflect.Proxy
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
        val started = CountDownLatch(1)
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
                    start = { eventFlow.also { started.countDown() } },
                    onStop = { stopped.countDown() },
                )
            }
        }

        composeRule.waitForIdle()
        // start runs on Dispatchers.IO, which waitForIdle does not wait for. A mount that leaves
        // before its start runs opened nothing, so the coordinator drops its onStop.
        assertTrue(
            "start did not run within $AWAIT_TIMEOUT_SECONDS seconds of composition",
            started.await(AWAIT_TIMEOUT_SECONDS, TimeUnit.SECONDS),
        )
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
        val started = CountDownLatch(1)
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
                    start = { eventFlow.also { started.countDown() } },
                    onStop = {
                        onStopEntered.countDown()
                        releaseOnStop.await()
                        onStopReturned.countDown()
                    },
                )
            }
        }

        composeRule.waitForIdle()
        // A mount that leaves before its start runs on Dispatchers.IO has its onStop dropped.
        assertTrue(
            "start did not run within $AWAIT_TIMEOUT_SECONDS seconds of composition",
            started.await(AWAIT_TIMEOUT_SECONDS, TimeUnit.SECONDS),
        )

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
     * A caller who changes the coordinator while the key stays the same, together with the
     * registry that coordinator orders, gets a live subscription from the new registry, and the
     * old coordinator's `onStop` releases the old registry's subscription.
     *
     * `rememberScpHotStream` remembered its `CoroutineScope` on `key` alone while its
     * `DisposableEffect` keyed on `key` AND `coordinator`. A coordinator change therefore ran
     * `onDispose`, which cancels that scope, and then relaunched `start` into the SAME
     * cancelled scope, because `key` had not changed. The launch returned an
     * already-cancelled Job, `start` never ran, and the returned `State` kept the previous
     * coordinator's flow: a subscription nobody was serving, reported as a live one.
     *
     * Each coordinator orders its own registry, so the new `start` has nothing to wait for:
     * this method holds the old `onStop` open on a latch and asserts that the new registry's
     * subscription and the returned `State` arrive while that stop is still suspended.
     */
    @Test(timeout = DISPOSAL_TIMEOUT_MS)
    fun `a coordinator change with its registry under one same key opens a subscription on the new registry`() {
        val firstRegistry = FakeSubscriptionRegistry()
        val secondRegistry = FakeSubscriptionRegistry()
        val releaseStop = CountDownLatch(1)
        val firstCoordinator = ScpHotStreamCoordinator(newCoordinatorScope())
        val secondCoordinator = ScpHotStreamCoordinator(newCoordinatorScope())
        val registries = mapOf(firstCoordinator to firstRegistry, secondCoordinator to secondRegistry)
        val flows = mapOf(firstCoordinator to hotEventFlow(), secondCoordinator to hotEventFlow())
        val activeCoordinator = MutableStateFlow(firstCoordinator)
        var flowState: State<SharedFlow<String>?>? = null

        composeRule.setContent {
            val coordinator by activeCoordinator.collectAsStateCompat()
            // Read once per composition, so each effect's lambdas keep the registry that was
            // active when that effect began.
            val active = coordinator
            val registry = registries.getValue(active)
            val flow = flows.getValue(active)
            flowState =
                rememberScpHotStream(
                    key = "shared-key",
                    coordinator = active,
                    start = {
                        registry.subscribe()
                        flow
                    },
                    onStop = {
                        releaseStop.await(AWAIT_TIMEOUT_SECONDS, TimeUnit.SECONDS)
                        registry.unsubscribeLive()
                    },
                )
        }

        composeRule.waitForIdle()
        awaitCondition("the first registry opened no subscription") {
            firstRegistry.subscribeIds() == listOf(1)
        }

        activeCoordinator.value = secondCoordinator
        composeRule.waitForIdle()

        awaitCondition("the new coordinator's start waited on the old coordinator's stop") {
            secondRegistry.subscribeIds() == listOf(1)
        }
        composeRule.waitForIdle()
        awaitCondition("the returned State does not hold the new registry's flow") {
            checkNotNull(flowState).value === flows.getValue(secondCoordinator)
        }
        assertEquals("the old stop ran before its latch opened", listOf(1), firstRegistry.liveIds())
        releaseStop.countDown()

        awaitCondition("the old coordinator's stop released nothing") {
            firstRegistry.unsubscribeIds() == listOf(1)
        }
        assertEquals(emptyList<Int>(), firstRegistry.liveIds())
        assertEquals(listOf(1), secondRegistry.liveIds())
        assertEquals(emptyList<Int>(), secondRegistry.unsubscribeIds())
    }

    /**
     * Two mounts under one key, composed at the same time, share one subscription, because a
     * registry such as `HotStreamFactory` hands a second subscriber the subscription it already
     * holds. A navigation transition keeps an outgoing screen composed while an incoming screen
     * starts, which produces exactly this overlap.
     *
     * The first mount to leave must stop nothing yet: its `onStop` would release the subscription
     * the second mount is still collecting, and that collector would then observe a SharedFlow
     * that receives nothing further and reports no error. Both mounts' `start` returned one
     * SharedFlow, so the last mount to leave runs one `onStop` for that one subscription.
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
        Thread.sleep(UNORDERED_STOP_GRACE_MS)
        assertEquals("the first mount's departure ran onStop", 0, stopCalls.get())
        assertEquals(listOf(1), subscriptions.liveIds())

        showSecond.value = false
        composeRule.waitForIdle()
        awaitCondition("the last mount's departure released nothing") {
            subscriptions.unsubscribeIds() == listOf(1)
        }
        Thread.sleep(UNORDERED_STOP_GRACE_MS)
        assertEquals("the last mount's departure ran one onStop per mount, not per subscription", 1, stopCalls.get())
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
            val first = coordinator.startedMount("k")
            val second = coordinator.startedMount("k")

            val held = checkNotNull(coordinator.unmount(first) { stops.incrementAndGet() })
            assertEquals("unmounting one mount twice", null, coordinator.unmount(first) { stops.incrementAndGet() })
            val stop = coordinator.unmount(second) { stops.incrementAndGet() }
            assertTrue("the last mount's unmount launched no stop", stop != null)
            assertTrue("a held departure's Job completed before any stop ran", !held.isCompleted)

            assertSame("the last departure did not get the held departure's Job", held, stop)

            val third = coordinator.mount("k")
            // The captured stop is the launched coroutine, a different object from the Job
            // unmount returned, which completes only once that coroutine has finished.
            val pending = checkNotNull(third.pendingStop) { "a later mount did not capture the pending stop" }
            val pendingDoneAtStop = AtomicBoolean(false)
            held.invokeOnCompletion { pendingDoneAtStop.set(pending.isCompleted) }

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
            assertTrue("unmount's Job completed before the stop a later mount captured", pendingDoneAtStop.get())
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
        val events = coordinator.startedMount("k")
        val messages = coordinator.startedMount("k")
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
     * A stop launched under a key completes only after every stop launched before it under that
     * key, even when the earlier stop reaches its dispatcher last. Otherwise a mount that
     * captured only the later stop could start, reuse a subscription, and then lose it to the
     * earlier stop.
     *
     * [QueuedDispatcher] holds every dispatched task until this method runs it, and this method
     * runs the newest task first, so the second stop reaches the free mutex before the first stop
     * has left its dispatcher queue. The second mount leaves before its start, which waits on
     * the first stop, can run, so the second stop runs no `onStop` of its own.
     */
    @Test(timeout = DISPOSAL_TIMEOUT_MS)
    fun `a stop runs after every stop launched before it under that key`() {
        val dispatcher = QueuedDispatcher()
        val coordinator = ScpHotStreamCoordinator(CoroutineScope(SupervisorJob() + dispatcher))
        val stopped = Collections.synchronizedList(mutableListOf<String>())

        val first = checkNotNull(coordinator.unmount(coordinator.startedMount("k")) { stopped += "first" })
        val secondMount = coordinator.mount("k")
        val firstStop = checkNotNull(secondMount.pendingStop) { "a later mount did not capture the pending stop" }
        val second = checkNotNull(coordinator.unmount(secondMount) { stopped += "second" })
        val third = coordinator.mount("k")
        val secondStop = checkNotNull(third.pendingStop) { "a later mount did not capture the newest stop" }
        assertNotSame("a later mount captured the older stop", firstStop, secondStop)
        val firstDoneAtSecond = AtomicBoolean(false)
        secondStop.invokeOnCompletion { firstDoneAtSecond.set(firstStop.isCompleted) }
        val stopDoneAtFirst = AtomicBoolean(false)
        first.invokeOnCompletion { stopDoneAtFirst.set(firstStop.isCompleted) }
        val stopDoneAtSecond = AtomicBoolean(false)
        second.invokeOnCompletion { stopDoneAtSecond.set(secondStop.isCompleted) }

        dispatcher.runNewestFirst()

        assertEquals("a mount that never started ran onStop", listOf("first"), stopped.toList())
        assertTrue("the later stop finished before the earlier one", firstDoneAtSecond.get())
        assertTrue("the earlier stop did not finish", firstStop.isCompleted)
        assertTrue("the later stop did not finish", secondStop.isCompleted)
        assertTrue("the first departure's Job completed before its stop", first.isCompleted && stopDoneAtFirst.get())
        assertTrue("the second departure's Job completed before its stop", second.isCompleted && stopDoneAtSecond.get())
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

        val failed = coordinator.unmount(coordinator.startedMount("k")) { throw failure }
        runBlocking { checkNotNull(failed).join() }

        val stops = AtomicInteger(0)
        val next = coordinator.unmount(coordinator.startedMount("k")) { stops.incrementAndGet() }
        runBlocking { checkNotNull(next).join() }

        assertTrue("a throwing onStop cancelled the coordinator's scope", scope.isActive)
        assertEquals("a stop after a throwing onStop did not run", 1, stops.get())
        val warning = ShadowLog.getLogsForTag("ScpHotStreamCoordinator").single()
        assertEquals(Log.WARN, warning.type)
        assertEquals(failure, warning.throwable)
    }

    /**
     * A key held by one long-lived mount keeps one held `onStop` per subscription, however many
     * other mounts of that subscription enter and leave beside it, and holds none for a mount
     * that left before its start ran. A held list that grew with every departure would keep
     * every departed mount's lambda, and everything it captured, until the long-lived mount left.
     */
    @Test(timeout = DISPOSAL_TIMEOUT_MS)
    fun `departures beside a live mount hold one onStop per subscription`() {
        val coordinator = ScpHotStreamCoordinator(newCoordinatorScope())
        val shared = Any()
        val header = coordinator.startedMount("k", shared)
        val stops = AtomicInteger(0)
        repeat(ROW_CHURN) {
            coordinator.unmount(coordinator.startedMount("k", shared)) { stops.incrementAndGet() }
            coordinator.unmount(coordinator.mount("k")) { stops.incrementAndGet() }
        }
        coordinator.unmount(coordinator.startedMount("k", Any())) { stops.incrementAndGet() }

        assertEquals("held onStop lambdas grew with departures", 2, header.state.heldStops.size)
        assertEquals("a held onStop ran while a mount stayed live", 0, stops.get())
        runBlocking { checkNotNull(coordinator.unmount(header) { stops.incrementAndGet() }).join() }
        assertEquals("the key's stop did not run one onStop per subscription", 2, stops.get())
    }

    /**
     * A mount that leaves beside a live mount while its `start` is suspended, and whose start
     * coroutine is then cancelled as `rememberScpHotStream`'s disposal cancels it, still records
     * what that `start` returned, so its held `onStop` collapses with the others of that
     * subscription. A start that cancellation interrupted would leave its mount's `onStop` with
     * nothing to compare, and the held list would grow by one per such departure.
     */
    @Test(timeout = DISPOSAL_TIMEOUT_MS)
    fun `departures while their start is suspended hold one onStop per subscription`() {
        val coordinator = ScpHotStreamCoordinator(newCoordinatorScope())
        val shared = Any()
        val header = coordinator.startedMount("k", shared)
        val rowScope = newCoordinatorScope()
        val stops = AtomicInteger(0)
        repeat(ROW_CHURN) {
            val row = coordinator.mount("k")
            val entered = CountDownLatch(1)
            val gate = CompletableDeferred<Unit>()
            val starting =
                rowScope.launch {
                    // Typed, so `shared` is not coerced to the Unit that `launch` expects.
                    coordinator.startMounted<Any>(row) {
                        entered.countDown()
                        gate.await()
                        shared
                    }
                }
            assertTrue("a row's start never ran", entered.await(AWAIT_TIMEOUT_SECONDS, TimeUnit.SECONDS))
            coordinator.unmount(row) { stops.incrementAndGet() }
            starting.cancel()
            gate.complete(Unit)
            runBlocking { starting.join() }
            assertEquals(
                "a start cancelled after its mount left did not record what it returned",
                ScpHotStreamCoordinator.Started(shared),
                row.phase.get(),
            )
        }

        // One entry per distinct object, plus the newest row's, which was running when it left.
        assertEquals("held onStop lambdas grew with departures", 2, header.state.heldStops.size)
        assertEquals("a held onStop ran while a mount stayed live", 0, stops.get())
        runBlocking { checkNotNull(coordinator.unmount(header) { stops.incrementAndGet() }).join() }
        assertEquals("the key's stop did not run one onStop per subscription", 1, stops.get())
    }

    /**
     * Cancelling a coordinator's scope skips every `onStop` it still holds. That is logged, the
     * held departure's Job completes exceptionally instead of reporting that its `onStop` ran,
     * and a later start is refused, because no stop could release what it opened.
     */
    @Test(timeout = DISPOSAL_TIMEOUT_MS)
    fun `a cancelled coordinator scope logs its skipped onStop and refuses later starts`() {
        ShadowLog.clear()
        val scope = newCoordinatorScope()
        val coordinator = ScpHotStreamCoordinator(scope)
        val stops = AtomicInteger(0)
        val staying = coordinator.startedMount("k")
        val held = checkNotNull(coordinator.unmount(coordinator.startedMount("k")) { stops.incrementAndGet() })
        scope.cancel()

        val stop = checkNotNull(coordinator.unmount(staying) { stops.incrementAndGet() })
        runBlocking {
            held.join()
            stop.join()
        }

        assertEquals("an onStop ran on a cancelled scope", 0, stops.get())
        assertTrue("a held departure's Job reported that its onStop ran", held.isCancelled)
        assertTrue("a skipped stop reported that it ran", stop.isCancelled)
        assertEquals(Log.WARN, ShadowLog.getLogsForTag("ScpHotStreamCoordinator").single().type)

        val started = AtomicBoolean(false)
        val later = coordinator.mount("k")
        val outcome = runCatching { runBlocking { coordinator.startMounted(later) { started.set(true) } } }
        assertTrue(
            "a start on a cancelled coordinator was not refused",
            outcome.exceptionOrNull() is ScpHotStreamCoordinatorClosedException,
        )
        assertEquals("a start on a cancelled coordinator ran", false, started.get())
    }

    /** A mount on a coordinator whose scope is cancelled logs the refusal and keeps a null State. */
    @Test(timeout = DISPOSAL_TIMEOUT_MS)
    fun `a mount on a cancelled coordinator logs and never starts`() {
        ShadowLog.clear()
        val coordinator = ScpHotStreamCoordinator(newCoordinatorScope().also { it.cancel() })
        val startCalls = AtomicInteger(0)
        var flowState: State<SharedFlow<String>?>? = null

        composeRule.setContent {
            flowState =
                rememberScpHotStream(
                    key = "k",
                    coordinator = coordinator,
                    start = {
                        startCalls.incrementAndGet()
                        MutableSharedFlow<String>()
                    },
                    onStop = {},
                )
        }

        composeRule.waitForIdle()
        awaitCondition("the refused start was not logged") {
            ShadowLog.getLogsForTag("ScpHotStreamCoordinator").isNotEmpty()
        }
        assertEquals("a start on a cancelled coordinator ran", 0, startCalls.get())
        assertEquals(null, checkNotNull(flowState).value)
    }

    /**
     * A coordinator scope cancelled while a stop's first `onStop` runs under [NonCancellable]
     * skips nothing when every `onStop` still returns, as `HotStreamFactory`'s stop functions
     * do. The stop then logs no warning, and the Job that [ScpHotStreamCoordinator.unmount]
     * returned for each departure completes normally. A stop that judged a skip from its own
     * Job's completion cause alone would log a leak and fail both Jobs, because cancelling a
     * running coroutine completes its Job as cancelled even when its body returns.
     */
    @Test(timeout = DISPOSAL_TIMEOUT_MS)
    fun `a scope cancelled while a non-cancellable onStop runs reports every onStop as run`() {
        ShadowLog.clear()
        val scope = newCoordinatorScope()
        val coordinator = ScpHotStreamCoordinator(scope)
        val stops = AtomicInteger(0)
        val entered = CountDownLatch(1)
        val gate = CompletableDeferred<Unit>()
        val staying = coordinator.startedMount("k")
        val held =
            checkNotNull(
                coordinator.unmount(coordinator.startedMount("k")) {
                    withContext(NonCancellable) {
                        entered.countDown()
                        gate.await()
                        stops.incrementAndGet()
                    }
                },
            )
        val stop = checkNotNull(coordinator.unmount(staying) { stops.incrementAndGet() })
        assertTrue("the held onStop never ran", entered.await(AWAIT_TIMEOUT_SECONDS, TimeUnit.SECONDS))

        scope.cancel()
        gate.complete(Unit)
        runBlocking {
            held.join()
            stop.join()
        }

        assertEquals("an onStop was skipped", 2, stops.get())
        assertEquals("a held departure's Job reported a skipped onStop", false, held.isCancelled)
        assertEquals("the last departure's Job reported a skipped onStop", false, stop.isCancelled)
        assertEquals(
            "a stop that ran every onStop logged a leak",
            0,
            ShadowLog.getLogsForTag("ScpHotStreamCoordinator").size,
        )
    }

    /**
     * [rememberContextEvents] and [rememberIncomingMessages] key each stream by its kind and its
     * context handle. Two mounts of one context's events share one Rust subscription, and the
     * first to leave releases nothing. That context's message stream is released as soon as its
     * own mount leaves, while its event stream stays open. A key that named the handle alone
     * would hold the message stream open, and a key per mount would release the event stream
     * the other mount still collects.
     */
    @Test(timeout = DISPOSAL_TIMEOUT_MS)
    fun `ScpHotStreams releases each stream when the last mount of that stream leaves`() {
        val bindings = CountingEventBindings()
        val hotStreams = ScpHotStreams(bindings.proxy, newCoordinatorScope())
        val shown = MutableStateFlow(listOf(StreamMount.EVENTS, StreamMount.EVENTS, StreamMount.MESSAGES))
        val opened = AtomicInteger(0)

        composeRule.setContent {
            val mounts by shown.collectAsStateCompat()
            mounts.forEachIndexed { index, mount ->
                key(index) {
                    val state =
                        when (mount) {
                            StreamMount.EVENTS -> rememberContextEvents(hotStreams, CONTEXT_HANDLE)
                            StreamMount.MESSAGES -> rememberIncomingMessages(hotStreams, CONTEXT_HANDLE)
                        }
                    if (state.value != null) {
                        DisposableEffect(Unit) {
                            opened.incrementAndGet()
                            onDispose {}
                        }
                    }
                }
            }
        }

        awaitCondition("a mount's stream never opened") {
            composeRule.waitForIdle()
            opened.get() == 3
        }
        assertEquals("two event mounts opened two Rust subscriptions", 1, bindings.eventSubscribes.get())
        assertEquals(1, bindings.messageSubscribes.get())

        shown.value = listOf(StreamMount.EVENTS, StreamMount.EVENTS)
        composeRule.waitForIdle()
        awaitCondition("the message mount's departure released nothing") { bindings.messageUnsubscribes.get() == 1 }

        shown.value = listOf(StreamMount.EVENTS)
        composeRule.waitForIdle()
        Thread.sleep(UNORDERED_STOP_GRACE_MS)
        assertEquals(
            "an event mount's departure released a stream another mount collects",
            0,
            bindings.eventUnsubscribes.get(),
        )

        shown.value = emptyList()
        composeRule.waitForIdle()
        awaitCondition("the last event mount's departure released nothing") { bindings.eventUnsubscribes.get() == 1 }
        assertEquals(1, bindings.eventSubscribes.get())
        assertEquals(1, bindings.messageUnsubscribes.get())
    }

    /**
     * [ScpHotStreams] hands the dispatcher it takes to the [works.limn.scp.stream.HotStreamFactory]
     * it constructs, so the Rust subscribe and unsubscribe calls run only when that dispatcher
     * runs them, on the thread that advances its scheduler. A factory built on its default
     * `Dispatchers.IO` would run both calls on an IO worker thread.
     */
    @Test(timeout = DISPOSAL_TIMEOUT_MS)
    fun `ScpHotStreams subscribes and releases on its injected dispatcher`() {
        val bindings = CountingEventBindings()
        val ioDispatcher = StandardTestDispatcher()
        val hotStreams = ScpHotStreams(bindings.proxy, newCoordinatorScope(), ioDispatcher)
        val caller = CoroutineScope(Dispatchers.Unconfined)

        val subscribed = caller.launch { hotStreams.factory.contextEvents(CONTEXT_HANDLE) }
        assertEquals("subscribe ran before the injected dispatcher ran it", 0, bindings.eventSubscribes.get())
        ioDispatcher.scheduler.advanceUntilIdle()
        assertTrue("subscribe never finished on the injected dispatcher", subscribed.isCompleted)
        assertEquals(1, bindings.eventSubscribes.get())

        val released = caller.launch { hotStreams.factory.stopContextEvents(CONTEXT_HANDLE) }
        assertEquals("unsubscribe ran before the injected dispatcher ran it", 0, bindings.eventUnsubscribes.get())
        ioDispatcher.scheduler.advanceUntilIdle()
        assertTrue("unsubscribe never finished on the injected dispatcher", released.isCompleted)
        assertEquals(1, bindings.eventUnsubscribes.get())
        assertEquals(
            "a Rust call ran off the injected dispatcher's thread",
            listOf(Thread.currentThread(), Thread.currentThread()),
            bindings.callThreads.toList(),
        )
    }

    /**
     * An owner that cancels its scope before the last stop runs leaves that stop's `onStop`
     * unrun, so the Rust subscription stays open. [ScpHotStreams.close] releases it through the
     * factory's `stopAll`, and refuses every later start.
     */
    @Test(timeout = DISPOSAL_TIMEOUT_MS)
    fun `closing ScpHotStreams releases a subscription whose stop a cancelled scope skipped`() {
        val bindings = CountingEventBindings()
        val scope = newCoordinatorScope()
        val hotStreams = ScpHotStreams(bindings.proxy, scope)
        val coordinator = hotStreams.coordinator
        val mount = coordinator.mount("k")
        runBlocking { coordinator.startMounted(mount) { hotStreams.factory.contextEvents(CONTEXT_HANDLE) } }

        scope.cancel()
        val stop = checkNotNull(coordinator.unmount(mount) { hotStreams.factory.stopContextEvents(CONTEXT_HANDLE) })
        runBlocking { stop.join() }
        assertEquals("a stop ran on a cancelled scope", 0, bindings.eventUnsubscribes.get())

        runBlocking { hotStreams.close() }
        assertEquals("close left the skipped subscription open", 1, bindings.eventUnsubscribes.get())

        val later = coordinator.mount("k")
        val outcome = runCatching { runBlocking { coordinator.startMounted(later) { Any() } } }
        assertTrue(
            "a start after close was not refused",
            outcome.exceptionOrNull() is ScpHotStreamCoordinatorClosedException,
        )
    }

    /**
     * [ScpHotStreams.close] returns only after the stop the last departure launched has run its
     * `onStop`, so an owner that cancels its scope once `close` returns skips no stop.
     */
    @Test(timeout = DISPOSAL_TIMEOUT_MS)
    fun `closing ScpHotStreams waits for a launched stop`() {
        val bindings = CountingEventBindings()
        val hotStreams = ScpHotStreams(bindings.proxy, newCoordinatorScope())
        val coordinator = hotStreams.coordinator
        val mount = coordinator.startedMount("k")
        val entered = CountDownLatch(1)
        val gate = CompletableDeferred<Unit>()
        val onStopDone = AtomicBoolean(false)
        checkNotNull(
            coordinator.unmount(mount) {
                entered.countDown()
                gate.await()
                onStopDone.set(true)
            },
        )
        assertTrue("the launched stop never ran", entered.await(AWAIT_TIMEOUT_SECONDS, TimeUnit.SECONDS))

        val closed = CoroutineScope(Dispatchers.IO).launch { hotStreams.close() }
        Thread.sleep(UNORDERED_STOP_GRACE_MS)
        assertEquals("close returned before the launched stop finished", false, closed.isCompleted)

        gate.complete(Unit)
        runBlocking { closed.join() }
        assertTrue("close returned before the onStop returned", onStopDone.get())
    }

    /**
     * A stop that holds no `onStop` — its only mount left before its `start` ran — skips
     * nothing when the coordinator's scope is cancelled, so its departure's Job completes
     * normally and nothing is logged.
     */
    @Test(timeout = DISPOSAL_TIMEOUT_MS)
    fun `a stop that held no onStop reports no skip on a cancelled scope`() {
        ShadowLog.clear()
        val coordinator = ScpHotStreamCoordinator(newCoordinatorScope().also { it.cancel() })

        val stop = checkNotNull(coordinator.unmount(coordinator.mount("k")) {})
        runBlocking { stop.join() }

        assertEquals("a stop that held no onStop reported a skip", false, stop.isCancelled)
        assertEquals(0, ShadowLog.getLogsForTag("ScpHotStreamCoordinator").size)
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

/** Which [ScpHotStreams] stream one mount in the stream-keying test shows. */
private enum class StreamMount {
    EVENTS,
    MESSAGES,
}

/**
 * Event bindings that count subscribe and unsubscribe calls for each stream kind and reject
 * every other call, so a [works.limn.scp.stream.HotStreamFactory] built over them reports
 * which Rust subscriptions it opened and released.
 */
private class CountingEventBindings {
    val eventSubscribes = AtomicInteger(0)
    val eventUnsubscribes = AtomicInteger(0)
    val messageSubscribes = AtomicInteger(0)
    val messageUnsubscribes = AtomicInteger(0)

    /** Thread each subscribe and unsubscribe call ran on, in call order. */
    val callThreads: MutableList<Thread> = Collections.synchronizedList(mutableListOf())

    val proxy: EventContextBindings =
        Proxy.newProxyInstance(
            EventContextBindings::class.java.classLoader,
            arrayOf(EventContextBindings::class.java),
        ) { _, method, _ ->
            callThreads += Thread.currentThread()
            when (method.name) {
                "contextSubscribeEvents" -> eventSubscribes.incrementAndGet().toLong()
                "contextSubscribe" -> messageSubscribes.incrementAndGet().toLong()
                "contextUnsubscribeEvents" -> {
                    eventUnsubscribes.incrementAndGet()
                    null
                }
                "contextUnsubscribe" -> {
                    messageUnsubscribes.incrementAndGet()
                    null
                }
                else -> throw UnsupportedOperationException(method.name)
            }
        } as EventContextBindings
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

/**
 * Count a mount under [key] and run its start, which returns [started], so that mount's `onStop`
 * runs when the key's stop runs.
 */
private fun ScpHotStreamCoordinator.startedMount(
    key: Any,
    started: Any = Any(),
): ScpHotStreamCoordinator.Mount = mount(key).also { mount -> runBlocking { startMounted<Any>(mount) { started } } }

/** Mounts that enter and leave beside a live mount in the held-list bound test. */
private const val ROW_CHURN = 100

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

/** How long a test lets a stop that should not run yet run before it asserts that none ran. */
private const val UNORDERED_STOP_GRACE_MS = 300L

private const val WAIT_TIMEOUT_MS = 5_000L

private const val HOT_FLOW_BUFFER = 16

/** Context handle the stream-keying test mounts its streams under. */
private const val CONTEXT_HANDLE = 7L
