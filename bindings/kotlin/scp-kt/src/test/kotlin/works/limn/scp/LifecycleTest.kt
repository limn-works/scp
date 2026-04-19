// LifecycleTest.kt — Unit tests for bridge lifecycle controls (suspend / resume).
//
// Uses injectable LifecycleBindings to exercise the wrapper logic without
// requiring a compiled Rust cdylib or a live BridgeInstance. Each test
// captures whether scpSuspend / scpResume was invoked on the stub.

package works.limn.scp

import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.TestDispatcher
import kotlinx.coroutines.test.runTest
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import works.limn.scp.bridge.CoroutineBridge
import works.limn.scp.conformance.ConformanceStubBindings
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

@OptIn(ExperimentalCoroutinesApi::class)
class LifecycleTest {
    private class RecordingBindings : LifecycleBindings {
        var suspendCalls = 0
        var resumeCalls = 0
        var throwFromSuspend: Throwable? = null
        var throwFromResume: Throwable? = null

        override fun scpSuspend() {
            suspendCalls += 1
            throwFromSuspend?.let { throw it }
        }

        // `suspend` to match LifecycleBindings after #1549 PR 3B made
        // UniFFI `scpResume()` async.
        override suspend fun scpResume() {
            resumeCalls += 1
            throwFromResume?.let { throw it }
        }
    }

    // `runTest { }` creates its own `TestCoroutineScheduler` internally,
    // and `withContext(ioDispatcher)` inside CoroutineBridge.ffiCall /
    // ffiCallSuspend posts work onto the injected `ioDispatcher`.
    // `kotlinx-coroutines-test` detects a scheduler mismatch between
    // the two and throws
    //   IllegalStateException: Detected use of different schedulers.
    // The fix documented in the test-coroutines docs is to pass the
    // bridge's dispatcher to `runTest(dispatcher)` so both sides share
    // the same `TestCoroutineScheduler`. Other tests in this module
    // (e.g. IdentityConformanceTest) follow the same pattern.
    private lateinit var testDispatcher: TestDispatcher
    private lateinit var bridge: CoroutineBridge

    @BeforeEach
    fun setUp() {
        testDispatcher = StandardTestDispatcher()
        bridge =
            CoroutineBridge(
                nativeBindings = ConformanceStubBindings(),
                ioDispatcher = testDispatcher,
                cpuDispatcher = testDispatcher,
            )
    }

    @Test
    fun `suspend delegates to bindings_scpSuspend`() =
        runTest(testDispatcher) {
            val bindings = RecordingBindings()
            suspend(bridge, bindings)
            assertEquals(1, bindings.suspendCalls)
            assertEquals(0, bindings.resumeCalls)
        }

    @Test
    fun `resume delegates to bindings_scpResume`() =
        runTest(testDispatcher) {
            val bindings = RecordingBindings()
            resume(bridge, bindings)
            assertEquals(1, bindings.resumeCalls)
            assertEquals(0, bindings.suspendCalls)
        }

    @Test
    fun `suspend-then-resume calls both bindings in order`() =
        runTest(testDispatcher) {
            val bindings = RecordingBindings()
            suspend(bridge, bindings)
            resume(bridge, bindings)
            assertEquals(1, bindings.suspendCalls)
            assertEquals(1, bindings.resumeCalls)
        }

    @Test
    fun `suspend propagates binding errors`() =
        runTest(testDispatcher) {
            val bindings = RecordingBindings()
            bindings.throwFromSuspend = IllegalStateException("boom")
            assertFailsWith<IllegalStateException> { suspend(bridge, bindings) }
        }

    @Test
    fun `resume propagates binding errors`() =
        runTest(testDispatcher) {
            val bindings = RecordingBindings()
            bindings.throwFromResume = IllegalStateException("boom")
            assertFailsWith<IllegalStateException> { resume(bridge, bindings) }
        }
}
