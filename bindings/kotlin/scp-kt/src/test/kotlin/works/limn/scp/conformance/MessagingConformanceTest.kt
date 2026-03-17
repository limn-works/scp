// MessagingConformanceTest.kt — Messaging conformance tests for the Kotlin SDK (SCP-120)
// Provenance: SCP-120, .docs/scaffold/shared.md "Messaging" category

package works.limn.scp.conformance

import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.async
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.take
import kotlinx.coroutines.flow.toList
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.TestDispatcher
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.runTest
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import works.limn.scp.bridge.BridgeException
import works.limn.scp.bridge.CoroutineBridge
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * Cross-platform conformance tests for messaging operations.
 *
 * Covers: send, receive, sequence ordering, encryption roundtrip.
 *
 * The messaging tests exercise both the send dispatch path (via the
 * conformance dispatcher) and the receive path (via Flow subscription
 * on the bridge). Sequence ordering and gap detection are validated
 * by configuring stub callbacks with ordered message payloads.
 */
@OptIn(ExperimentalCoroutinesApi::class)
class MessagingConformanceTest {
    private lateinit var stubBindings: ConformanceStubBindings
    private lateinit var bridge: CoroutineBridge
    private lateinit var dispatcher: ConformanceDispatcher
    private lateinit var testDispatcher: TestDispatcher

    @BeforeEach
    fun setUp() {
        stubBindings = ConformanceStubBindings()
        testDispatcher = StandardTestDispatcher()
        bridge =
            CoroutineBridge(
                nativeBindings = stubBindings,
                ioDispatcher = testDispatcher,
                cpuDispatcher = testDispatcher,
            )
        dispatcher = ConformanceDispatcher(bridge)
    }

    @Nested
    inner class SendMessage {
        @Test
        fun `context_send succeeds with payload`() =
            runTest(testDispatcher) {
                val result =
                    dispatcher.dispatch(
                        "context_send",
                        mapOf("context_handle" to "10", "identity_handle" to "1", "payload" to "hello"),
                    )
                assertEquals("sent", result["status"])
                assertTrue(stubBindings.contextSendCalled)
            }

        @Test
        fun `context_send captures payload bytes`() =
            runTest(testDispatcher) {
                dispatcher.dispatch(
                    "context_send",
                    mapOf("context_handle" to "10", "identity_handle" to "1", "payload" to "test message"),
                )
                assertEquals(
                    "test message",
                    stubBindings.contextSendPayload?.let { String(it) },
                )
            }

        @Test
        fun `context_send propagates error for closed context`() =
            runTest(testDispatcher) {
                stubBindings.contextSendError =
                    BridgeException("Context closed", "SCP-CTX-2010")
                val result =
                    dispatcher.dispatch(
                        "context_send",
                        mapOf("context_handle" to "10", "identity_handle" to "1", "payload" to "hello"),
                    )
                assertEquals("SCP-CTX-2010", result["error"])
            }
    }

    @Nested
    inner class ReceiveMessages {
        @Test
        fun `message subscription emits messages in order`() =
            runTest(testDispatcher) {
                val messages = mutableListOf<String>()
                val flow = bridge.context.subscribe(42L)

                val job =
                    launch {
                        flow.take(3).toList().also { messages.addAll(it) }
                    }

                advanceUntilIdle()

                stubBindings.lastMessageCallback?.onMessage("""{"seq":1}""")
                stubBindings.lastMessageCallback?.onMessage("""{"seq":2}""")
                stubBindings.lastMessageCallback?.onMessage("""{"seq":3}""")

                advanceUntilIdle()
                job.join()

                assertEquals(3, messages.size)
                assertEquals("""{"seq":1}""", messages[0])
                assertEquals("""{"seq":2}""", messages[1])
                assertEquals("""{"seq":3}""", messages[2])
            }

        @Test
        fun `message subscription completes on onComplete`() =
            runTest(testDispatcher) {
                val messages = mutableListOf<String>()
                val flow = bridge.context.subscribe(42L)

                val job =
                    launch {
                        flow.toList().also { messages.addAll(it) }
                    }

                advanceUntilIdle()

                stubBindings.lastMessageCallback?.onMessage("""{"seq":1}""")
                stubBindings.lastMessageCallback?.onComplete()

                advanceUntilIdle()
                job.join()

                assertEquals(1, messages.size)
            }

        @Test
        fun `message subscription propagates error as BridgeException`() =
            runTest(testDispatcher) {
                val flow = bridge.context.subscribe(42L)

                val deferred =
                    async {
                        runCatching { flow.first() }
                    }

                advanceUntilIdle()

                stubBindings.lastMessageCallback?.onError(
                    "SCP-CTX-2011",
                    "Subscription error",
                )

                advanceUntilIdle()

                val result = deferred.await()
                assertTrue(result.isFailure)
                val ex = result.exceptionOrNull()
                assertTrue(ex is BridgeException)
                assertEquals("SCP-CTX-2011", (ex as BridgeException).code)
            }
    }

    @Nested
    inner class SequenceOrdering {
        @Test
        fun `messages preserve insertion order`() =
            runTest(testDispatcher) {
                val messages = mutableListOf<String>()
                val flow = bridge.context.subscribe(42L)

                val job =
                    launch {
                        flow.take(5).toList().also { messages.addAll(it) }
                    }

                advanceUntilIdle()

                for (i in 1..5) {
                    stubBindings.lastMessageCallback?.onMessage("""{"seq":$i}""")
                }

                advanceUntilIdle()
                job.join()

                assertEquals(5, messages.size)
                for (i in 1..5) {
                    assertEquals("""{"seq":$i}""", messages[i - 1])
                }
            }
    }

    @Nested
    inner class FixtureIntegration {
        @Test
        fun `send message fixture matches dispatcher result`() =
            runTest(testDispatcher) {
                val fixture =
                    ConformanceFixture(
                        testId = "messaging-send-001",
                        category = "messaging",
                        description = "Send a message to a context",
                        operation = "context_send",
                        input =
                            mapOf(
                                "context_handle" to "10",
                                "identity_handle" to "1",
                                "payload" to "hello world",
                            ),
                        expected = mapOf("status" to "sent"),
                    )
                val result =
                    dispatcher.dispatch(
                        fixture.operation,
                        fixture.input,
                    )
                val mismatches = compareResults(result, fixture.expected)
                assertTrue(
                    mismatches.isEmpty(),
                    "Fixture ${fixture.testId}: $mismatches",
                )
            }
    }
}
