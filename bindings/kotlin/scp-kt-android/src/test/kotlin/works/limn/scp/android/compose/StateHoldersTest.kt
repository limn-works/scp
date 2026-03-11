// StateHoldersTest.kt — Tests for Compose state holders (SCP-118)
// Provenance: ADR-028 (Kotlin SDK) Compose integration, SCP-118

package works.limn.scp.android.compose

import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.ui.test.junit4.createComposeRule
import kotlinx.coroutines.ExperimentalCoroutinesApi
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

        composeRule.setContent {
            val holder = rememberScpContext(contextHandle = 42L) { _ -> }
            capturedHandle = holder.contextHandle
        }

        composeRule.waitForIdle()
        assertEquals(42L, capturedHandle)
    }

    @Test
    fun `rememberScpContext calls onDispose when leaving composition`() {
        val disposed = AtomicBoolean(false)
        val disposedHandle = AtomicLong(-1L)
        val showComposable = MutableStateFlow(true)

        composeRule.setContent {
            val show by showComposable.collectAsStateCompat()
            if (show) {
                rememberScpContext(contextHandle = 7L) { handle ->
                    disposedHandle.set(handle)
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
        composeRule.waitForIdle()
        Thread.sleep(SETTLE_DELAY_MS)

        assertEquals(true, stopped.get())
    }

    @Test
    fun `rememberScpHotStream returns the started flow`() {
        val eventFlow = MutableSharedFlow<String>()
        var capturedFlow: kotlinx.coroutines.flow.SharedFlow<String>? = null

        composeRule.setContent {
            val flowState by rememberScpHotStream(
                key = "key",
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
                capturedHolder = rememberScpContext(contextHandle = 1L) { _ -> }
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
 * Extension property to check if a CoroutineScope is still active.
 */
private val kotlinx.coroutines.CoroutineScope.isActive: Boolean
    get() = coroutineContext[kotlinx.coroutines.Job]?.isActive == true

private const val SETTLE_DELAY_MS = 100L
