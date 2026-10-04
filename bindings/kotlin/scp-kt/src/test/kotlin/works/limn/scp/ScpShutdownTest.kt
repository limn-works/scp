// ScpShutdownTest.kt -- SCP.shutdown records a shutdown exactly when the engine teardown has run.
//
// The SCP twin of ServerTest's Relay and Node shutdown tests. `SCP.shutdown` sets its flag inside
// the bridge block, so a failed teardown leaves the instance live, while an SCP-STORAGE-8005 raised
// after the teardown ran and a caller cancelled after a finished teardown still record it shut down
// (sdk-common.md §"Kotlin: why no `Closeable`").
// The engine is a `uniffi.scp.Scp` built with UniFFI's `NoPointer` constructor, whose `shutdown`
// override runs a test hook instead of reaching Rust, so no native library is needed.

package works.limn.scp

import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.Job
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.TestDispatcher
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.runTest
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import uniffi.scp.NoPointer
import uniffi.scp.ScpException
import works.limn.scp.bridge.CoroutineBridge
import works.limn.scp.conformance.ConformanceStubBindings
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.milliseconds
import uniffi.scp.Scp as NativeScp

/**
 * An engine whose `shutdown` records its deadline and runs [onShutdown] instead of calling Rust.
 * `instanceId` is overridden too, because `SCP`'s finalizer reads it when it warns about an
 * instance that never shut down, and the `NoPointer` base would throw there.
 */
private class HookedNativeScp : NativeScp(NoPointer) {
    val shutdownDeadlines = mutableListOf<ULong>()
    var onShutdown: () -> Unit = {}

    override fun instanceId(): ULong = 0UL

    override suspend fun shutdown(timeoutMillis: ULong) {
        shutdownDeadlines += timeoutMillis
        onShutdown()
    }
}

class ScpShutdownTest {
    private lateinit var testDispatcher: TestDispatcher
    private lateinit var bridge: CoroutineBridge
    private lateinit var engine: HookedNativeScp
    private lateinit var scp: SCP

    @BeforeEach
    fun setUp() {
        testDispatcher = StandardTestDispatcher()
        bridge =
            CoroutineBridge(
                nativeBindings = ConformanceStubBindings(),
                ioDispatcher = testDispatcher,
                cpuDispatcher = testDispatcher,
            )
        engine = HookedNativeScp()
        scp = SCP(engine)
    }

    @Test
    fun `shutdown tears down the engine and marks the instance shut down`() {
        runTest(testDispatcher) {
            assertFalse(scp.isShutdown)
            scp.shutdown(bridge, 250.milliseconds)
            assertEquals(listOf(250UL), engine.shutdownDeadlines)
            assertTrue(scp.isShutdown)
        }
    }

    // A failed engine teardown propagates, and the instance stays recorded as live, so its
    // finalizer still warns about an instance that never shut down.
    @Test
    fun `a failed shutdown propagates and leaves the instance live`() {
        runTest(testDispatcher) {
            engine.onShutdown = { throw IllegalStateException("engine refused stop") }
            assertFailsWith<IllegalStateException> { scp.shutdown(bridge) }
            assertEquals(1, engine.shutdownDeadlines.size)
            assertFalse(scp.isShutdown)
        }
    }

    // SCP-STORAGE-8005 arrives after a teardown that ran, with only the durable store still
    // holding its lock, so the error propagates and the instance is recorded as shut down.
    @Test
    fun `a shutdown that leaves the store locked propagates and marks the instance shut down`() {
        runTest(testDispatcher) {
            engine.onShutdown = { throw ScpException.Validation(msg = "store open", code = "SCP-STORAGE-8005") }
            val err = assertFailsWith<ScpException.Validation> { scp.shutdown(bridge) }
            assertEquals("SCP-STORAGE-8005", err.code)
            assertTrue(scp.isShutdown)
        }
    }

    // Any other validation failure is an engine failure, so the instance stays recorded as live.
    @Test
    fun `a shutdown failing with another validation code leaves the instance live`() {
        runTest(testDispatcher) {
            engine.onShutdown = { throw ScpException.Validation(msg = "bad deadline", code = "SCP-VALID-7001") }
            assertFailsWith<ScpException.Validation> { scp.shutdown(bridge) }
            assertFalse(scp.isShutdown)
        }
    }

    // A caller cancelled while the engine tears down gets a CancellationException from the
    // bridge's trailing ensureActive, although the teardown finished. The flag must still record
    // the shutdown, or the finalizer warns about a torn-down instance.
    @OptIn(ExperimentalCoroutinesApi::class)
    @Test
    fun `a shutdown whose caller is cancelled after the teardown still marks it shut down`() {
        runTest(testDispatcher) {
            lateinit var caller: Job
            engine.onShutdown = { caller.cancel() }
            caller = launch { scp.shutdown(bridge) }
            advanceUntilIdle()
            assertTrue(caller.isCancelled)
            assertEquals(1, engine.shutdownDeadlines.size)
            assertTrue(scp.isShutdown)
        }
    }
}
