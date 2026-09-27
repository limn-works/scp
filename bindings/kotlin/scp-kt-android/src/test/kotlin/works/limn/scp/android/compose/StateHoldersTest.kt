// StateHoldersTest.kt — Tests for Compose state holders (SCP-118)
// Provenance: ADR-028 (Kotlin SDK) Compose integration, SCP-118

package works.limn.scp.android.compose

import androidx.compose.runtime.Composable
import androidx.compose.runtime.State
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.ui.test.junit4.createComposeRule
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharedFlow
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong

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
        val stopped = AtomicBoolean(false)
        val eventFlow = MutableSharedFlow<String>()
        val showComposable = MutableStateFlow(true)

        composeRule.setContent {
            val show by showComposable.collectAsStateCompat()
            if (show) {
                rememberScpHotStream(
                    key = "test-key",
                    start = { eventFlow },
                    onStop = { stopped.set(true) },
                )
            }
        }

        composeRule.waitForIdle()
        assertEquals(false, stopped.get())

        showComposable.value = false
        composeRule.waitUntil(WAIT_TIMEOUT_MS) { stopped.get() }
    }

    @Test
    fun `rememberScpHotStream returns the started flow`() {
        val eventFlow = MutableSharedFlow<String>()
        var flowState: State<SharedFlow<String>?>? = null
        var capturedFlow: SharedFlow<String>? = null

        composeRule.setContent {
            val state = rememberScpHotStream(
                key = "key",
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

/**
 * Extension property to check if a CoroutineScope is still active.
 */
private val kotlinx.coroutines.CoroutineScope.isActive: Boolean
    get() = coroutineContext[kotlinx.coroutines.Job]?.isActive == true

private const val WAIT_TIMEOUT_MS = 5_000L

private const val HOT_FLOW_BUFFER = 16
