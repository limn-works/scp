// ContextLifecycleTest.kt — Tests for lifecycle-aware SCP flow extension (SCP-117)
//
// Verifies that asLifecycleFlow() correctly scopes flow collection to a LifecycleOwner,
// cancelling on DESTROYED and pausing below minActiveState.
//
// Provenance: ADR-028 acceptance criterion 11, SCP-117

package com.limn.scp.android

import androidx.lifecycle.Lifecycle
import androidx.lifecycle.testing.TestLifecycleOwner
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.toList
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.UnconfinedTestDispatcher
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.runTest
import org.junit.jupiter.api.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

@OptIn(ExperimentalCoroutinesApi::class)
class ContextLifecycleTest {

    @Test
    fun `asLifecycleFlow completes when owner reaches DESTROYED`() = runTest {
        val testDispatcher = UnconfinedTestDispatcher(testScheduler)
        val owner = TestLifecycleOwner(
            initialState = Lifecycle.State.STARTED,
            coroutineDispatcher = testDispatcher,
        )

        val sourceFlow = MutableSharedFlow<String>()
        val lifecycleFlow: Flow<String> = sourceFlow.asLifecycleFlow(owner)
        val collected = mutableListOf<String>()

        val job = launch(testDispatcher) {
            lifecycleFlow.toList(collected)
        }

        advanceUntilIdle()

        sourceFlow.emit("message-1")
        advanceUntilIdle()
        assertEquals(1, collected.size)
        assertEquals("message-1", collected[0])

        owner.handleLifecycleEvent(Lifecycle.Event.ON_DESTROY)
        advanceUntilIdle()

        job.join()
        assertTrue(job.isCompleted)
    }

    @Test
    fun `asLifecycleFlow collects messages while in STARTED state`() = runTest {
        val testDispatcher = UnconfinedTestDispatcher(testScheduler)
        val owner = TestLifecycleOwner(
            initialState = Lifecycle.State.STARTED,
            coroutineDispatcher = testDispatcher,
        )

        val sourceFlow = MutableSharedFlow<String>()
        val lifecycleFlow = sourceFlow.asLifecycleFlow(owner)
        val collected = mutableListOf<String>()

        val job = launch(testDispatcher) {
            lifecycleFlow.toList(collected)
        }

        advanceUntilIdle()

        sourceFlow.emit("msg-1")
        sourceFlow.emit("msg-2")
        sourceFlow.emit("msg-3")
        advanceUntilIdle()

        assertEquals(3, collected.size)
        assertEquals("msg-1", collected[0])
        assertEquals("msg-2", collected[1])
        assertEquals("msg-3", collected[2])

        owner.handleLifecycleEvent(Lifecycle.Event.ON_DESTROY)
        advanceUntilIdle()
        job.join()
    }

    @Test
    fun `asLifecycleFlow pauses collection when lifecycle drops below STARTED`() = runTest {
        val testDispatcher = UnconfinedTestDispatcher(testScheduler)
        val owner = TestLifecycleOwner(
            initialState = Lifecycle.State.RESUMED,
            coroutineDispatcher = testDispatcher,
        )

        val sourceFlow = MutableSharedFlow<String>()
        val lifecycleFlow = sourceFlow.asLifecycleFlow(owner)
        val collected = mutableListOf<String>()

        val job = launch(testDispatcher) {
            lifecycleFlow.toList(collected)
        }

        advanceUntilIdle()

        sourceFlow.emit("before-stop")
        advanceUntilIdle()
        assertEquals(1, collected.size)

        owner.handleLifecycleEvent(Lifecycle.Event.ON_STOP)
        advanceUntilIdle()

        sourceFlow.emit("during-stop")
        advanceUntilIdle()
        assertEquals(1, collected.size, "Should not collect messages while stopped")

        owner.handleLifecycleEvent(Lifecycle.Event.ON_START)
        advanceUntilIdle()

        sourceFlow.emit("after-restart")
        advanceUntilIdle()
        assertEquals(2, collected.size)
        assertEquals("after-restart", collected[1])

        owner.handleLifecycleEvent(Lifecycle.Event.ON_DESTROY)
        advanceUntilIdle()
        job.join()
    }

    @Test
    fun `asLifecycleFlow with CREATED minActiveState collects during ON_STOP`() = runTest {
        val testDispatcher = UnconfinedTestDispatcher(testScheduler)
        val owner = TestLifecycleOwner(
            initialState = Lifecycle.State.RESUMED,
            coroutineDispatcher = testDispatcher,
        )

        val sourceFlow = MutableSharedFlow<String>()
        val lifecycleFlow = sourceFlow.asLifecycleFlow(
            owner,
            minActiveState = Lifecycle.State.CREATED,
        )
        val collected = mutableListOf<String>()

        val job = launch(testDispatcher) {
            lifecycleFlow.toList(collected)
        }

        advanceUntilIdle()

        sourceFlow.emit("before-stop")
        advanceUntilIdle()

        owner.handleLifecycleEvent(Lifecycle.Event.ON_STOP)
        advanceUntilIdle()

        sourceFlow.emit("during-stop")
        advanceUntilIdle()

        assertEquals(2, collected.size, "Should collect while stopped with CREATED minActiveState")
        assertEquals("before-stop", collected[0])
        assertEquals("during-stop", collected[1])

        owner.handleLifecycleEvent(Lifecycle.Event.ON_DESTROY)
        advanceUntilIdle()
        job.join()
    }

    @Test
    fun `asLifecycleFlow works with generic Flow types`() = runTest {
        val testDispatcher = UnconfinedTestDispatcher(testScheduler)
        val owner = TestLifecycleOwner(
            initialState = Lifecycle.State.STARTED,
            coroutineDispatcher = testDispatcher,
        )

        val sourceFlow = MutableSharedFlow<Int>()
        val lifecycleFlow: Flow<Int> = sourceFlow.asLifecycleFlow(owner)
        val collected = mutableListOf<Int>()

        val job = launch(testDispatcher) {
            lifecycleFlow.toList(collected)
        }

        advanceUntilIdle()

        sourceFlow.emit(42)
        sourceFlow.emit(99)
        advanceUntilIdle()

        assertEquals(listOf(42, 99), collected)

        owner.handleLifecycleEvent(Lifecycle.Event.ON_DESTROY)
        advanceUntilIdle()
        job.join()
    }
}
