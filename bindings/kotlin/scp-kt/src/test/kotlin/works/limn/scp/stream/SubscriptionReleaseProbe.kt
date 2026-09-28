package works.limn.scp.stream

import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.asCoroutineDispatcher
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import java.util.concurrent.Callable
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.TimeoutException
import kotlin.test.assertTrue
import kotlin.test.fail

/**
 * Asserts that cancelling a subscription flow's collector releases the Rust subscription
 * without parking the collector's thread while the release runs.
 *
 * The collector runs on its own single thread and [openFlow] receives a second single
 * thread as the flow's FFI dispatcher. The stub's unsubscribe, installed through
 * [installHooks], holds until this probe lets it go. While it holds, a task submitted to the
 * collector's thread must run: a release that blocks that thread (`runBlocking` inside
 * `awaitClose`) leaves the task queued, and the probe fails.
 *
 * @param openFlow Builds the flow under test on the given FFI dispatcher.
 * @param installHooks Installs a hook the stub runs inside its subscribe and one it runs
 *   inside its unsubscribe.
 */
internal fun assertReleaseLeavesCollectorFree(
    openFlow: (CoroutineDispatcher) -> Flow<String>,
    installHooks: (onSubscribe: () -> Unit, onUnsubscribe: () -> Unit) -> Unit,
) {
    val collectorExecutor = Executors.newSingleThreadExecutor()
    val ffiExecutor = Executors.newSingleThreadExecutor()
    val subscribed = CountDownLatch(1)
    val releasing = CountDownLatch(1)
    val letGo = CountDownLatch(1)
    installHooks(
        { subscribed.countDown() },
        {
            releasing.countDown()
            letGo.await(RELEASE_HOLD_SECONDS, TimeUnit.SECONDS)
        },
    )
    try {
        runBlocking {
            val flow = openFlow(ffiExecutor.asCoroutineDispatcher())
            val job = launch(collectorExecutor.asCoroutineDispatcher()) { flow.collect {} }
            assertTrue(subscribed.await(WAIT_SECONDS, TimeUnit.SECONDS), "the flow never subscribed")
            // Each executor is FIFO on one thread. The first submit runs after the subscribe
            // task, which has queued the producer's resumption on the collector's thread by
            // then; the second runs after that resumption, which suspends in awaitClose.
            ffiExecutor.submit(Callable { true }).get(WAIT_SECONDS, TimeUnit.SECONDS)
            collectorExecutor.submit(Callable { true }).get(WAIT_SECONDS, TimeUnit.SECONDS)
            job.cancel()
            assertTrue(releasing.await(WAIT_SECONDS, TimeUnit.SECONDS), "cancellation never released")
            try {
                collectorExecutor.submit(Callable { true }).get(WAIT_SECONDS, TimeUnit.SECONDS)
            } catch (e: TimeoutException) {
                fail("the collector's thread stayed parked while the subscription was released", e)
            } finally {
                letGo.countDown()
            }
            job.join()
        }
    } finally {
        collectorExecutor.shutdownNow()
        ffiExecutor.shutdownNow()
    }
}

private const val WAIT_SECONDS = 5L

// Longer than WAIT_SECONDS, so a release that parks the collector's thread outlasts the probe.
private const val RELEASE_HOLD_SECONDS = 10L
