// StreamsTest.kt — JUnit 5 tests for the Flow/Channel streaming layer (SCP-116)
// Provenance: SCP-116, ADR-028 (Kotlin SDK)

package com.limn.scp.stream

import com.limn.scp.bridge.BridgeException
import com.limn.scp.bridge.CancellationHandle
import com.limn.scp.bridge.MessageCallback
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.take
import kotlinx.coroutines.flow.toList
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.TestDispatcher
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.runTest
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

@OptIn(ExperimentalCoroutinesApi::class)
class StreamsTest {
    private lateinit var stubBindings: StubEventContextBindings
    private lateinit var stubInfra: StubInfraBindings
    private lateinit var testDispatcher: TestDispatcher

    @BeforeEach
    fun setUp() {
        stubBindings = StubEventContextBindings()
        stubInfra = StubInfraBindings()
        testDispatcher = StandardTestDispatcher()
    }

    @Nested
    inner class ColdStreamFactoryTests {
        @Test
        fun `eventLogPages emits pages until empty result`() = runTest(testDispatcher) {
            stubInfra.eventLogQueryResults = mutableListOf(
                """[{"event":"joined"},{"event":"left"}]""",
                """[{"event":"message"}]""",
                "[]",
            )

            val factory = ColdStreamFactory(stubInfra, testDispatcher)
            val pages = factory.eventLogPages("ctx-1", "{}").toList()

            assertEquals(2, pages.size)
            assertEquals("""[{"event":"joined"},{"event":"left"}]""", pages[0])
            assertEquals("""[{"event":"message"}]""", pages[1])
        }

        @Test
        fun `eventLogPages emits nothing for empty query`() = runTest(testDispatcher) {
            stubInfra.eventLogQueryResults = mutableListOf("[]")

            val factory = ColdStreamFactory(stubInfra, testDispatcher)
            val pages = factory.eventLogPages("ctx-1", "{}").toList()

            assertTrue(pages.isEmpty())
        }

        @Test
        fun `eventLogPages passes pagination parameters`() = runTest(testDispatcher) {
            stubInfra.eventLogQueryResults = mutableListOf(
                """[{"event":"joined"}]""",
                "[]",
            )

            val factory = ColdStreamFactory(stubInfra, testDispatcher)
            factory.eventLogPages("ctx-1", """{"type":"joined"}""", pageSize = 25).toList()

            assertEquals(2, stubInfra.capturedFilters.size)
            assertTrue(stubInfra.capturedFilters[0].contains("\"_offset\":0"))
            assertTrue(stubInfra.capturedFilters[0].contains("\"_limit\":25"))
            assertTrue(stubInfra.capturedFilters[1].contains("\"_offset\":25"))
        }

        @Test
        fun `messageHistoryPages emits pages until empty result`() = runTest(testDispatcher) {
            stubInfra.eventLogQueryResults = mutableListOf(
                """[{"msg":"hello"},{"msg":"world"}]""",
                "[]",
            )

            val factory = ColdStreamFactory(stubInfra, testDispatcher)
            val pages = factory.messageHistoryPages("ctx-1", "{}").toList()

            assertEquals(1, pages.size)
            assertEquals("""[{"msg":"hello"},{"msg":"world"}]""", pages[0])
        }

        @Test
        fun `cold flow is lazy and does not query until collected`() = runTest(testDispatcher) {
            stubInfra.eventLogQueryResults = mutableListOf("[]")

            val factory = ColdStreamFactory(stubInfra, testDispatcher)
            val flow = factory.eventLogPages("ctx-1", "{}")

            assertEquals(0, stubInfra.queryCount)

            flow.toList()

            assertEquals(1, stubInfra.queryCount)
        }

        @Test
        fun `cold flow cancellation stops pagination`() = runTest(testDispatcher) {
            stubInfra.eventLogQueryResults = mutableListOf(
                """[{"event":"1"}]""",
                """[{"event":"2"}]""",
                """[{"event":"3"}]""",
                "[]",
            )

            val factory = ColdStreamFactory(stubInfra, testDispatcher)
            val firstPage = factory.eventLogPages("ctx-1", "{}").first()

            assertEquals("""[{"event":"1"}]""", firstPage)
            assertEquals(1, stubInfra.queryCount)
        }
    }

    @Nested
    inner class HotStreamFactoryTests {
        private lateinit var factory: HotStreamFactory

        @BeforeEach
        fun setUpFactory() {
            stubBindings.contextSubscribeEventsResult = 200L
            stubBindings.contextSubscribeResult = 300L
            factory = HotStreamFactory(stubBindings)
        }

        @AfterEach
        fun tearDown() {
            factory.stopAll()
        }

        @Test
        fun `contextEvents returns SharedFlow that emits events`() = runTest {
            val flow = factory.contextEvents(42L)
            val events = mutableListOf<String>()

            val job = launch {
                flow.take(2).toList().also { events.addAll(it) }
            }

            advanceUntilIdle()

            val callback = stubBindings.lastEventCallback
            assertNotNull(callback)
            callback.onEvent("""{"type":"member_joined","did":"did:dht:alice"}""")
            callback.onEvent("""{"type":"member_left","did":"did:dht:bob"}""")

            advanceUntilIdle()
            job.join()

            assertEquals(2, events.size)
            assertTrue(events[0].contains("member_joined"))
            assertTrue(events[1].contains("member_left"))
        }

        @Test
        fun `contextEvents returns same SharedFlow for same context handle`() {
            val flow1 = factory.contextEvents(42L)
            val flow2 = factory.contextEvents(42L)

            assertEquals(flow1, flow2)
            assertEquals(1, stubBindings.eventSubscribeCount)
        }

        @Test
        fun `contextEvents with different handles creates separate streams`() {
            factory.contextEvents(42L)
            factory.contextEvents(43L)

            assertEquals(2, stubBindings.eventSubscribeCount)
        }

        @Test
        fun `stopContextEvents unsubscribes from Rust engine`() {
            factory.contextEvents(42L)
            factory.stopContextEvents(42L)

            assertTrue(stubBindings.eventUnsubscribeCalled)
            assertEquals(200L, stubBindings.lastEventUnsubscribeHandle)
        }

        @Test
        fun `stopContextEvents is safe to call when no subscription exists`() {
            factory.stopContextEvents(999L)
            assertFalse(stubBindings.eventUnsubscribeCalled)
        }

        @Test
        fun `incomingMessages returns SharedFlow that emits messages`() = runTest {
            val flow = factory.incomingMessages(42L)
            val messages = mutableListOf<String>()

            val job = launch {
                flow.take(2).toList().also { messages.addAll(it) }
            }

            advanceUntilIdle()

            val callback = stubBindings.lastMessageCallback
            assertNotNull(callback)
            callback.onMessage("""{"seq":1,"text":"hello"}""")
            callback.onMessage("""{"seq":2,"text":"world"}""")

            advanceUntilIdle()
            job.join()

            assertEquals(2, messages.size)
            assertEquals("""{"seq":1,"text":"hello"}""", messages[0])
            assertEquals("""{"seq":2,"text":"world"}""", messages[1])
        }

        @Test
        fun `incomingMessages returns same SharedFlow for same context handle`() {
            val flow1 = factory.incomingMessages(42L)
            val flow2 = factory.incomingMessages(42L)

            assertEquals(flow1, flow2)
            assertEquals(1, stubBindings.messageSubscribeCount)
        }

        @Test
        fun `stopMessageStream unsubscribes from Rust engine`() {
            factory.incomingMessages(42L)
            factory.stopMessageStream(42L)

            assertTrue(stubBindings.contextUnsubscribeCalled)
            assertEquals(300L, stubBindings.lastUnsubscribeHandle)
        }

        @Test
        fun `stopAll cleans up all subscriptions`() {
            factory.contextEvents(42L)
            factory.contextEvents(43L)
            factory.incomingMessages(42L)

            factory.stopAll()

            assertEquals(2, stubBindings.eventUnsubscribeCount)
            assertEquals(1, stubBindings.messageUnsubscribeCount)
        }

        @Test
        fun `hot stream error callback emits error event`() = runTest {
            val flow = factory.contextEvents(42L)
            val events = mutableListOf<String>()

            val job = launch {
                flow.take(1).toList().also { events.addAll(it) }
            }

            advanceUntilIdle()

            stubBindings.lastEventCallback?.onError("SCP-CTX-500", "Internal error")

            advanceUntilIdle()
            job.join()

            assertEquals(1, events.size)
            assertTrue(events[0].contains("SCP-CTX-500"))
        }

        @Test
        fun `hot stream with replay caches events for late subscribers`() = runTest {
            val flow = factory.contextEvents(42L, replay = 2)

            stubBindings.lastEventCallback?.onEvent("""{"seq":1}""")
            stubBindings.lastEventCallback?.onEvent("""{"seq":2}""")
            stubBindings.lastEventCallback?.onEvent("""{"seq":3}""")

            val events = mutableListOf<String>()
            val job = launch {
                flow.take(2).toList().also { events.addAll(it) }
            }

            advanceUntilIdle()
            job.join()

            assertEquals(2, events.size)
            assertEquals("""{"seq":2}""", events[0])
            assertEquals("""{"seq":3}""", events[1])
        }
    }

    @Nested
    inner class ColdMessageFlowTests {
        @Test
        fun `ColdMessageFlow emits messages from callback`() = runTest(testDispatcher) {
            stubBindings.contextSubscribeResult = 100L

            val flow = ColdMessageFlow(stubBindings, 42L, testDispatcher)
            val messages = mutableListOf<String>()

            val job = launch {
                flow.take(2).toList().also { messages.addAll(it) }
            }

            advanceUntilIdle()

            stubBindings.lastMessageCallback?.onMessage("""{"seq":1}""")
            stubBindings.lastMessageCallback?.onMessage("""{"seq":2}""")

            advanceUntilIdle()
            job.join()

            assertEquals(2, messages.size)
            assertEquals("""{"seq":1}""", messages[0])
            assertEquals("""{"seq":2}""", messages[1])
        }

        @Test
        fun `ColdMessageFlow completes on onComplete callback`() = runTest(testDispatcher) {
            stubBindings.contextSubscribeResult = 100L

            val flow = ColdMessageFlow(stubBindings, 42L, testDispatcher)
            val messages = mutableListOf<String>()

            val job = launch {
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
        fun `ColdMessageFlow closes with BridgeException on error`() = runTest(testDispatcher) {
            stubBindings.contextSubscribeResult = 100L

            val flow = ColdMessageFlow(stubBindings, 42L, testDispatcher)

            val result = kotlin.runCatching {
                val job = launch {
                    flow.first()
                }

                advanceUntilIdle()

                stubBindings.lastMessageCallback?.onError("SCP-CTX-001", "Context closed")

                advanceUntilIdle()
                job.join()
            }

            assertTrue(result.isFailure)
            val exception = result.exceptionOrNull()
            assertTrue(exception is BridgeException)
            assertEquals("SCP-CTX-001", (exception as BridgeException).code)
        }

        @Test
        fun `ColdMessageFlow calls unsubscribe on cancellation`() = runTest(testDispatcher) {
            stubBindings.contextSubscribeResult = 100L

            val flow = ColdMessageFlow(stubBindings, 42L, testDispatcher)

            val job = launch {
                flow.collect {}
            }

            advanceUntilIdle()
            job.cancelAndJoin()

            assertTrue(stubBindings.contextUnsubscribeCalled)
            assertEquals(100L, stubBindings.lastUnsubscribeHandle)
        }

        @Test
        fun `ColdMessageFlow has no double buffering`() = runTest(testDispatcher) {
            stubBindings.contextSubscribeResult = 100L

            val flow = ColdMessageFlow(stubBindings, 42L, testDispatcher)

            val messages = mutableListOf<String>()
            val job = launch {
                flow.take(1).toList().also { messages.addAll(it) }
            }

            advanceUntilIdle()

            stubBindings.lastMessageCallback?.onMessage("""{"seq":1}""")

            advanceUntilIdle()
            job.join()

            assertEquals(1, messages.size)
        }
    }

    @Nested
    inner class BuildPaginatedFilterTests {
        @Test
        fun `empty filter produces pagination-only JSON`() {
            val result = buildPaginatedFilter("{}", 0, 50)
            assertEquals("""{"_offset":0,"_limit":50}""", result)
        }

        @Test
        fun `blank filter produces pagination-only JSON`() {
            val result = buildPaginatedFilter("", 0, 50)
            assertEquals("""{"_offset":0,"_limit":50}""", result)
        }

        @Test
        fun `existing filter gets pagination appended`() {
            val result = buildPaginatedFilter("""{"type":"joined"}""", 0, 25)
            assertEquals("""{"type":"joined","_offset":0,"_limit":25}""", result)
        }

        @Test
        fun `pagination offset increments correctly`() {
            val result = buildPaginatedFilter("{}", 50, 50)
            assertEquals("""{"_offset":50,"_limit":50}""", result)
        }
    }
}

@Suppress("TooManyFunctions")
class StubEventContextBindings : EventContextBindings {
    var contextSubscribeResult = 0L
    var contextSubscribeEventsResult = 0L
    var contextCreateResult = 0L
    var contextJoinResult = 0L
    var contextUnsubscribeCalled = false
    var eventUnsubscribeCalled = false
    var contextLeaveCalled = false
    var contextCloseCalled = false
    var contextSendCalled = false
    var lastMessageCallback: MessageCallback? = null
    var lastEventCallback: EventCallback? = null
    var lastUnsubscribeHandle: Long? = null
    var lastEventUnsubscribeHandle: Long? = null
    var eventSubscribeCount = 0
    var messageSubscribeCount = 0
    var eventUnsubscribeCount = 0
    var messageUnsubscribeCount = 0

    override fun contextCreate(identityHandle: Long, paramsJson: String): Long = contextCreateResult

    override fun contextJoin(identityHandle: Long, contextId: String): Long = contextJoinResult

    override fun contextLeave(contextHandle: Long) {
        contextLeaveCalled = true
    }

    override fun contextClose(contextHandle: Long) {
        contextCloseCalled = true
    }

    override fun contextSend(contextHandle: Long, payload: ByteArray) {
        contextSendCalled = true
    }

    override fun contextSubscribe(contextHandle: Long, callback: MessageCallback): Long {
        lastMessageCallback = callback
        messageSubscribeCount++
        return contextSubscribeResult
    }

    override fun contextUnsubscribe(subscriptionHandle: Long) {
        contextUnsubscribeCalled = true
        lastUnsubscribeHandle = subscriptionHandle
        messageUnsubscribeCount++
    }

    override fun contextSubscribeEvents(contextHandle: Long, callback: EventCallback): Long {
        lastEventCallback = callback
        eventSubscribeCount++
        return contextSubscribeEventsResult
    }

    override fun contextUnsubscribeEvents(subscriptionHandle: Long) {
        eventUnsubscribeCalled = true
        lastEventUnsubscribeHandle = subscriptionHandle
        eventUnsubscribeCount++
    }
}

class StubInfraBindings : com.limn.scp.bridge.InfraBindings {
    var eventLogQueryResults = mutableListOf<String>()
    var eventLogVerifyResult = false
    var transportConnectResult = 0L
    var transportStatusResult = ""
    var queryCount = 0
    var capturedFilters = mutableListOf<String>()

    override fun eventLogQuery(contextId: String, filterJson: String): String {
        queryCount++
        capturedFilters.add(filterJson)
        return if (eventLogQueryResults.isNotEmpty()) eventLogQueryResults.removeAt(0) else "[]"
    }

    override fun eventLogVerify(contextId: String, proofJson: String): Boolean = eventLogVerifyResult

    override fun transportConnect(
        configJson: String,
        cancellationHandle: CancellationHandle?,
    ): Long = transportConnectResult

    override fun transportStatus(transportHandle: Long): String = transportStatusResult
}
