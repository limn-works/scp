// CoroutineBridgeTest.kt — Unit tests for the coroutine bridge (SCP-115)
//
// Verifies dispatcher assignment, cancellation propagation, callbackFlow streaming,
// and error handling for the CoroutineBridge layer.
//
// Uses kotlinx-coroutines-test for deterministic coroutine testing with
// TestDispatcher injection.
//
// Provenance: SCP-115, ADR-028 (Kotlin SDK)

package works.limn.scp.bridge

import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.Job
import kotlinx.coroutines.async
import kotlinx.coroutines.cancelAndJoin
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
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

@OptIn(ExperimentalCoroutinesApi::class)
class CoroutineBridgeTest {
    private lateinit var bridge: CoroutineBridge
    private lateinit var stubBindings: StubNativeBindings
    private lateinit var ioDispatcher: TestDispatcher
    private lateinit var cpuDispatcher: TestDispatcher

    @BeforeEach
    fun setUp() {
        stubBindings = StubNativeBindings()
        ioDispatcher = StandardTestDispatcher()
        cpuDispatcher = StandardTestDispatcher()
        bridge =
            CoroutineBridge(
                nativeBindings = stubBindings,
                ioDispatcher = ioDispatcher,
                cpuDispatcher = cpuDispatcher,
            )
    }

    // -------------------------------------------------------------------
    // Dispatcher assignment tests — identity operations
    // -------------------------------------------------------------------

    @Nested
    inner class IdentityDispatcherTests {
        @Test
        fun `identityCreate dispatches on IO and returns handle`() =
            runTest(ioDispatcher) {
                stubBindings.identityCreateResult = 42L
                val result = bridge.identity.create("in_memory")
                assertEquals(42L, result)
                assertTrue(stubBindings.identityCreateCalled)
                assertEquals("in_memory", stubBindings.lastCustody)
            }

        @Test
        fun `identityLoad dispatches on IO`() =
            runTest(ioDispatcher) {
                stubBindings.identityLoadResult = 2L
                val result = bridge.identity.load("did:dht:test123")
                assertEquals(2L, result)
                assertEquals("did:dht:test123", stubBindings.lastDid)
            }

        @Test
        fun `identityResolve dispatches on IO`() =
            runTest(ioDispatcher) {
                stubBindings.identityResolveResult = """{"did":"did:dht:test"}"""
                val result = bridge.identity.resolve("did:dht:test")
                assertEquals("""{"did":"did:dht:test"}""", result)
            }
    }

    // -------------------------------------------------------------------
    // Dispatcher assignment tests — context operations
    // -------------------------------------------------------------------

    @Nested
    inner class ContextDispatcherTests {
        @Test
        fun `contextCreate dispatches on IO`() =
            runTest(ioDispatcher) {
                stubBindings.contextCreateResult = 10L
                val result = bridge.context.create(1L, """{"ceiling":["read"]}""")
                assertEquals(10L, result)
            }

        @Test
        fun `contextJoin dispatches on IO`() =
            runTest(ioDispatcher) {
                stubBindings.contextJoinResult = 11L
                val result = bridge.context.join(1L, "ctx-123")
                assertEquals(11L, result)
            }

        @Test
        fun `contextSend dispatches on IO`() =
            runTest(ioDispatcher) {
                val payload = "hello".toByteArray()
                bridge.context.send(10L, payload)
                assertTrue(stubBindings.contextSendCalled)
            }

        @Test
        fun `contextLeave dispatches on IO`() =
            runTest(ioDispatcher) {
                bridge.context.leave(10L)
                assertTrue(stubBindings.contextLeaveCalled)
            }

        @Test
        fun `contextClose dispatches on IO`() =
            runTest(ioDispatcher) {
                bridge.context.close(10L)
                assertTrue(stubBindings.contextCloseCalled)
            }
    }

    // -------------------------------------------------------------------
    // Dispatcher assignment tests — tool, UCAN, infra operations
    // -------------------------------------------------------------------

    @Nested
    inner class ToolUcanInfraDispatcherTests {
        @Test
        fun `toolRegister dispatches on IO`() =
            runTest(ioDispatcher) {
                stubBindings.toolRegisterResult = "tool-001"
                val result = bridge.tools.register(10L, """{"name":"test"}""")
                assertEquals("tool-001", result)
            }

        @Test
        fun `toolInvoke dispatches on IO`() =
            runTest(ioDispatcher) {
                stubBindings.toolInvokeResult = """{"output":"ok"}"""
                val result = bridge.tools.invoke(10L, "tool-001", """{"input":"data"}""")
                assertEquals("""{"output":"ok"}""", result)
            }

        @Test
        fun `toolVerify dispatches on IO`() =
            runTest(ioDispatcher) {
                stubBindings.toolVerifyResult = true
                val result = bridge.tools.verify("tool-001", """{"in":"x"}""", """{"out":"y"}""")
                assertTrue(result)
            }

        @Test
        fun `ucanValidate dispatches on IO`() =
            runTest(ioDispatcher) {
                bridge.ucan.validate("token", "read", "ctx-1")
                assertTrue(stubBindings.ucanValidateCalled)
            }

        @Test
        fun `ucanMint dispatches on IO`() =
            runTest(ioDispatcher) {
                stubBindings.ucanMintResult = "minted-token"
                val result = bridge.ucan.mint(1L, "did:dht:member", """["read","write"]""")
                assertEquals("minted-token", result)
            }

        @Test
        fun `ucanRevoke dispatches on IO`() =
            runTest(ioDispatcher) {
                bridge.ucan.revoke(1L, "header.payload.signature")
                assertTrue(stubBindings.ucanRevokeCalled)
            }

        @Test
        fun `ucanDelegate dispatches on IO`() =
            runTest(ioDispatcher) {
                stubBindings.ucanDelegateResult = "delegated-token"
                val result = bridge.ucan.delegate(
                    10L,
                    "did:dht:delegator",
                    "did:dht:delegatee",
                    "parent.token.sig",
                    """["read"]""",
                )
                assertEquals("delegated-token", result)
                assertTrue(stubBindings.ucanDelegateCalled)
            }

        @Test
        fun `eventLogQuery dispatches on IO`() =
            runTest(ioDispatcher) {
                stubBindings.eventLogQueryResult = """[{"event":"joined"}]"""
                val result = bridge.infra.eventLogQuery("ctx-1", """{"type":"joined"}""")
                assertEquals("""[{"event":"joined"}]""", result)
            }

        @Test
        fun `eventLogVerify dispatches on IO`() =
            runTest(ioDispatcher) {
                stubBindings.eventLogVerifyResult = true
                val result = bridge.infra.eventLogVerify("ctx-1", """{"proof":"abc"}""")
                assertTrue(result)
            }

        @Test
        fun `transportConnect dispatches on IO`() =
            runTest(ioDispatcher) {
                stubBindings.transportConnectResult = 99L
                val result = bridge.infra.transportConnect("""{"url":"wss://relay.example.com"}""")
                assertEquals(99L, result)
            }

        @Test
        fun `transportStatus dispatches on IO`() =
            runTest(ioDispatcher) {
                stubBindings.transportStatusResult = """{"connected":true}"""
                val result = bridge.infra.transportStatus(99L)
                assertEquals("""{"connected":true}""", result)
            }
    }

    // -------------------------------------------------------------------
    // CPU-bound dispatcher test
    // -------------------------------------------------------------------

    @Nested
    inner class CpuBoundTests {
        @Test
        fun `cpuBound dispatches on Default dispatcher`() =
            runTest(cpuDispatcher) {
                var executed = false
                bridge.cpuBound { executed = true }
                assertTrue(executed)
            }
    }

    // -------------------------------------------------------------------
    // Cancellation propagation tests
    // -------------------------------------------------------------------

    @Nested
    inner class CancellationPropagation {
        @Test
        fun `CancellationHandle starts uncancelled`() {
            val handle = CancellationHandle()
            assertFalse(handle.isCancelled)
        }

        @Test
        fun `CancellationHandle cancel sets flag`() {
            val handle = CancellationHandle()
            handle.cancel()
            assertTrue(handle.isCancelled)
        }

        @Test
        fun `CancellationHandle cancel is idempotent`() {
            val handle = CancellationHandle()
            handle.cancel()
            handle.cancel()
            assertTrue(handle.isCancelled)
        }

        @Test
        fun `cancelled coroutine throws CancellationException on FFI call`() =
            runTest(ioDispatcher) {
                val job = Job()
                job.cancel()

                assertFailsWith<CancellationException> {
                    kotlinx.coroutines.withContext(job) {
                        bridge.identity.create("in_memory")
                    }
                }
            }

        @Test
        fun `transportConnect propagates cancellation to handle`() =
            runTest(ioDispatcher) {
                stubBindings.transportConnectBlocking = true

                val job =
                    launch {
                        bridge.infra.transportConnect("""{"url":"wss://relay.example.com"}""")
                    }

                advanceUntilIdle()

                val capturedHandle = stubBindings.lastCancellationHandle
                assertFalse(capturedHandle?.isCancelled ?: true)

                job.cancelAndJoin()
            }

        @Test
        fun `contextSubscribe flow cancellation calls awaitClose`() =
            runTest(ioDispatcher) {
                stubBindings.contextSubscribeResult = 100L

                val flow = bridge.context.subscribe(42L)

                val job =
                    launch {
                        flow.take(1).toList()
                    }

                advanceUntilIdle()

                stubBindings.lastMessageCallback?.onMessage("""{"text":"hello"}""")

                advanceUntilIdle()
                job.join()
            }
    }

    // -------------------------------------------------------------------
    // callbackFlow streaming tests
    // -------------------------------------------------------------------

    @Nested
    inner class CallbackFlowStreaming {
        @Test
        fun `contextSubscribe returns Flow that emits messages`() =
            runTest(ioDispatcher) {
                stubBindings.contextSubscribeResult = 100L

                val messages = mutableListOf<String>()
                val job =
                    launch {
                        bridge.context.subscribe(42L).take(2).toList().also { messages.addAll(it) }
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
        fun `contextSubscribe flow closes on error`() =
            runTest(ioDispatcher) {
                stubBindings.contextSubscribeResult = 100L

                val deferred =
                    async {
                        runCatching {
                            bridge.context.subscribe(42L).first()
                        }
                    }

                advanceUntilIdle()

                stubBindings.lastMessageCallback?.onError("SCP-CTX-2001", "Context not active")

                advanceUntilIdle()

                val result = deferred.await()
                assertTrue(result.isFailure)
                val exception = result.exceptionOrNull()
                assertTrue(exception is BridgeException)
                assertEquals("SCP-CTX-2001", (exception as BridgeException).code)
            }

        @Test
        fun `contextSubscribe flow completes on onComplete`() =
            runTest(ioDispatcher) {
                stubBindings.contextSubscribeResult = 100L

                val messages = mutableListOf<String>()
                val job =
                    launch {
                        bridge.context.subscribe(42L).toList().also { messages.addAll(it) }
                    }

                advanceUntilIdle()

                stubBindings.lastMessageCallback?.onMessage("""{"seq":1}""")
                stubBindings.lastMessageCallback?.onComplete()

                advanceUntilIdle()
                job.join()

                assertEquals(1, messages.size)
                assertEquals("""{"seq":1}""", messages[0])
            }
    }

    // -------------------------------------------------------------------
    // Error handling tests
    // -------------------------------------------------------------------

    @Nested
    inner class ErrorHandling {
        @Test
        fun `FFI exception propagates as BridgeException`() =
            runTest(ioDispatcher) {
                stubBindings.identityCreateThrows =
                    BridgeException("Identity not found", "SCP-IDENT-1001")

                val exception =
                    assertFailsWith<BridgeException> {
                        bridge.identity.create("in_memory")
                    }

                assertEquals("SCP-IDENT-1001", exception.code)
                assertEquals("Identity not found", exception.message)
            }

        @Test
        fun `BridgeException carries structured error code`() {
            val exception = BridgeException("test error", "SCP-CTX-2999")
            assertEquals("SCP-CTX-2999", exception.code)
            assertEquals("test error", exception.message)
        }
    }
}

// ---------------------------------------------------------------------------
// Stub NativeBindings for testing
// ---------------------------------------------------------------------------

/**
 * Test stub for [NativeBindings] that records calls and returns configured results.
 *
 * Allows tests to verify which methods were called, with what arguments,
 * and to control return values and error conditions.
 */
@Suppress("TooManyFunctions")
class StubNativeBindings : NativeBindings {
    // Call tracking flags
    var identityCreateCalled = false
    var contextSendCalled = false
    var contextLeaveCalled = false
    var contextCloseCalled = false
    var contextUnsubscribeCalled = false
    var lastUnsubscribeHandle: Long? = null
    var ucanValidateCalled = false
    var ucanRevokeCalled = false
    var ucanDelegateCalled = false

    // Argument captures
    var lastCustody: String? = null
    var lastDid: String? = null
    var lastMessageCallback: MessageCallback? = null
    var lastCancellationHandle: CancellationHandle? = null

    // Configurable results
    var identityCreateResult = 0L
    var identityCreateThrows: Exception? = null
    var identityLoadResult = 0L
    var identityResolveResult = ""
    var contextCreateResult = 0L
    var contextJoinResult = 0L
    var contextSubscribeResult = 0L
    var toolRegisterResult = ""
    var toolInvokeResult = ""
    var toolVerifyResult = false
    var ucanMintResult = ""
    var ucanDelegateResult = ""
    var eventLogQueryResult = ""
    var eventLogVerifyResult = false
    var transportConnectResult = 0L
    var transportConnectBlocking = false
    var transportStatusResult = ""

    override fun identityCreate(custody: String): Long {
        identityCreateCalled = true
        lastCustody = custody
        identityCreateThrows?.let { throw it }
        return identityCreateResult
    }

    override fun identityLoad(did: String): Long {
        lastDid = did
        return identityLoadResult
    }

    override fun identityResolve(did: String): String {
        lastDid = did
        return identityResolveResult
    }

    override fun contextCreate(
        identityHandle: Long,
        paramsJson: String,
    ): Long = contextCreateResult

    override fun contextJoin(
        identityHandle: Long,
        contextId: String,
    ): Long = contextJoinResult

    override fun contextLeave(contextHandle: Long) {
        contextLeaveCalled = true
    }

    override fun contextClose(contextHandle: Long) {
        contextCloseCalled = true
    }

    override fun contextSend(
        contextHandle: Long,
        payload: ByteArray,
    ) {
        contextSendCalled = true
    }

    override fun contextSubscribe(
        contextHandle: Long,
        callback: MessageCallback,
    ): Long {
        lastMessageCallback = callback
        return contextSubscribeResult
    }

    override fun contextUnsubscribe(subscriptionHandle: Long) {
        contextUnsubscribeCalled = true
        lastUnsubscribeHandle = subscriptionHandle
    }

    // MembershipBindings
    override fun contextMemberCount(contextHandle: Long): Long? = 1L
    override fun contextIsMember(contextHandle: Long, did: String): Boolean = true
    override fun contextMemberDids(contextHandle: Long): List<String> = listOf("did:dht:stub")
    override fun contextMemberRole(contextHandle: Long, did: String): String? = "admin"

    // GovernanceBindings
    override fun governanceExecute(contextHandle: Long, proposalJson: String): String =
        """{"status":"executed"}"""

    // BroadcastBindings
    override fun broadcastSubscribe(contextHandle: Long, subscriberDid: String) = Unit
    override fun broadcastUnsubscribe(contextHandle: Long, subscriberDid: String, rotateKeys: Boolean) = Unit
    override fun broadcastPublish(contextHandle: Long, authorDid: String, payload: ByteArray) = Unit
    override fun broadcastBlockSubscriber(contextHandle: Long, subscriberDid: String, blockerDid: String) = Unit
    override fun broadcastHandleKeyRequest(contextHandle: Long, authorDid: String, requesterDid: String): String =
        """{"key":"stub"}"""
    override fun broadcastSubscriberCount(contextHandle: Long): Long? = 0L
    override fun broadcastIsSubscriber(contextHandle: Long, did: String): Boolean = false
    override fun broadcastAdmission(contextHandle: Long): String? = "Open"

    override fun toolRegister(
        contextHandle: Long,
        definitionJson: String,
    ): String = toolRegisterResult

    override fun toolInvoke(
        contextHandle: Long,
        toolId: String,
        inputJson: String,
    ): String = toolInvokeResult

    override fun toolVerify(
        toolId: String,
        inputJson: String,
        outputJson: String,
    ): Boolean = toolVerifyResult

    override fun ucanValidate(
        token: String,
        capability: String,
        contextId: String,
    ) {
        ucanValidateCalled = true
    }

    override fun ucanMint(
        identityHandle: Long,
        memberDid: String,
        capabilitiesJson: String,
    ): String = ucanMintResult

    override fun ucanRevoke(
        identityHandle: Long,
        token: String,
    ) {
        ucanRevokeCalled = true
    }

    override fun ucanDelegate(
        contextHandle: Long,
        delegatorDid: String,
        delegateeDid: String,
        parentToken: String,
        capabilitiesJson: String,
    ): String {
        ucanDelegateCalled = true
        return ucanDelegateResult
    }

    override fun eventLogQuery(
        contextId: String,
        filterJson: String,
    ): String = eventLogQueryResult

    override fun eventLogVerify(
        contextId: String,
        proofJson: String,
    ): Boolean = eventLogVerifyResult

    override fun transportConnect(
        configJson: String,
        cancellationHandle: CancellationHandle?,
    ): Long {
        lastCancellationHandle = cancellationHandle
        return transportConnectResult
    }

    override fun transportStatus(transportHandle: Long): String = transportStatusResult
}
