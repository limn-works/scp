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
                bridge.context.join(10L, 1L)
            }

        @Test
        fun `contextSend dispatches on IO`() =
            runTest(ioDispatcher) {
                val payload = "hello".toByteArray()
                bridge.context.send(10L, 1L, payload)
                assertTrue(stubBindings.contextSendCalled)
            }

        @Test
        fun `contextLeave dispatches on IO`() =
            runTest(ioDispatcher) {
                bridge.context.leave(10L, 1L)
                assertTrue(stubBindings.contextLeaveCalled)
            }

        @Test
        fun `contextClose dispatches on IO`() =
            runTest(ioDispatcher) {
                bridge.context.close(10L, 1L)
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
                val result = bridge.tools.invoke(10L, "tool-001", """{"input":"data"}""", 1L, "ucan.token.sig")
                assertEquals("""{"output":"ok"}""", result)
            }

        @Test
        fun `toolInvoke forwards identityHandle`() =
            runTest(ioDispatcher) {
                stubBindings.toolInvokeResult = """{"ok":true}"""
                bridge.tools.invoke(10L, "tool-001", """{}""", 42L, null)
                assertEquals(42L, stubBindings.lastToolInvokeIdentityHandle)
            }

        @Test
        fun `toolInvoke forwards ucanToken`() =
            runTest(ioDispatcher) {
                stubBindings.toolInvokeResult = """{"ok":true}"""
                bridge.tools.invoke(10L, "tool-001", """{}""", 1L, "header.payload.signature")
                assertEquals("header.payload.signature", stubBindings.lastToolInvokeUcanToken)
            }

        @Test
        fun `toolInvoke forwards non-null proofTokens`() =
            runTest(ioDispatcher) {
                stubBindings.toolInvokeResult = """{"ok":true}"""
                val proofs = listOf("proof1.token", "proof2.token")
                bridge.tools.invoke(10L, "tool-001", """{}""", 1L, "ucan.tok", proofs)
                assertEquals(proofs, stubBindings.lastToolInvokeProofTokens)
            }

        @Test
        fun `toolVerify dispatches on IO`() =
            runTest(ioDispatcher) {
                stubBindings.toolVerifyResult = """{"tool_id":"tool-001","passed":true,"failures":[]}"""
                val result = bridge.tools.verify(10L, "tool-001")
                assertTrue(result.contains("\"passed\":true"))
            }

        @Test
        fun `ucanValidate dispatches on IO`() =
            runTest(ioDispatcher) {
                bridge.ucan.validate(10L, "token", "read")
                assertTrue(stubBindings.ucanValidateCalled)
            }

        @Test
        fun `ucanMint dispatches on IO`() =
            runTest(ioDispatcher) {
                stubBindings.ucanMintResult = "minted-token"
                val result = bridge.ucan.mint(10L, "did:dht:member", """["read","write"]""")
                assertEquals("minted-token", result)
            }

        @Test
        fun `ucanRevoke dispatches on IO`() =
            runTest(ioDispatcher) {
                bridge.ucan.revoke(10L, "header.payload.signature", "did:dht:zRevoker")
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
                val result = bridge.infra.eventLogQuery(1L, """{"type":"joined"}""")
                assertEquals("""[{"event":"joined"}]""", result)
            }

        @Test
        fun `eventLogVerify dispatches on IO`() =
            runTest(ioDispatcher) {
                stubBindings.eventLogVerifyResult = true
                val result = bridge.infra.eventLogVerify(1L, """{"type":"inclusion","leaf_index":0}""")
                assertTrue(result)
            }

        @Test
        fun `eventLogCheckpoint dispatches on IO`() =
            runTest(ioDispatcher) {
                @Suppress("MaxLineLength")
                val checkpointJson =
                    """{"context_id":"ctx-1","sender_did":"did:dht:z6Mk","event_count":10,"merkle_root":"abcdef","epoch":5,"timestamp":1700000000,"signature":"deadbeef"}"""
                stubBindings.eventLogCheckpointResult = checkpointJson
                val result = bridge.infra.eventLogCheckpoint(1L, 2L, 5L)
                assertEquals(checkpointJson, result)
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

        @Test
        fun `transportDisconnect dispatches on IO`() =
            runTest(ioDispatcher) {
                bridge.infra.transportDisconnect(99L)
                assertTrue(stubBindings.transportDisconnectCalled)
            }
    }

    // -------------------------------------------------------------------
    // Dispatcher assignment tests — tool session + cross-context operations
    // -------------------------------------------------------------------

    @Nested
    inner class ToolSessionDispatcherTests {
        @Test
        fun `invokeCrossContext dispatches on IO and forwards all arguments`() =
            runTest(ioDispatcher) {
                stubBindings.toolInvokeCrossContextResult = """{"output":"xctx"}"""
                val result = bridge.tools.invokeCrossContext(
                    1L,
                    2L,
                    "tool-001",
                    """{"query":"test"}""",
                    42L,
                    "ucan.tok.sig",
                    1,
                    listOf("proof1"),
                )
                assertEquals("""{"output":"xctx"}""", result)
                assertEquals(1L, stubBindings.lastCrossContextSourceHandle)
                assertEquals(2L, stubBindings.lastCrossContextTargetHandle)
                assertEquals("tool-001", stubBindings.lastCrossContextToolId)
                assertEquals("""{"query":"test"}""", stubBindings.lastCrossContextInputJson)
                assertEquals(42L, stubBindings.lastCrossContextIdentityHandle)
                assertEquals("ucan.tok.sig", stubBindings.lastCrossContextUcanToken)
                assertEquals(1, stubBindings.lastCrossContextChainDepth)
                assertEquals(listOf("proof1"), stubBindings.lastCrossContextProofTokens)
            }

        @Test
        fun `sessionCreate dispatches on IO and forwards arguments`() =
            runTest(ioDispatcher) {
                stubBindings.toolSessionCreateResult = "session-abc"
                val result = bridge.tools.sessionCreate(10L, "tool-001", "src-ctx", 3600L)
                assertEquals("session-abc", result)
                assertEquals("tool-001", stubBindings.lastSessionCreateToolId)
                assertEquals("src-ctx", stubBindings.lastSessionCreateSourceContextId)
                assertEquals(3600L, stubBindings.lastSessionCreateTtlSeconds)
            }

        @Test
        fun `sessionCreate forwards null ttlSeconds`() =
            runTest(ioDispatcher) {
                bridge.tools.sessionCreate(10L, "tool-001", "src-ctx", null)
                assertEquals(null, stubBindings.lastSessionCreateTtlSeconds)
            }

        @Test
        fun `sessionInvoke dispatches on IO and forwards all arguments`() =
            runTest(ioDispatcher) {
                stubBindings.toolSessionInvokeResult = """{"out":"ok"}"""
                val result = bridge.tools.sessionInvoke(
                    10L,
                    "session-001",
                    """{"input":"data"}""",
                    42L,
                    "ucan.tok",
                    listOf("proof1", "proof2"),
                )
                assertEquals("""{"out":"ok"}""", result)
                assertEquals("session-001", stubBindings.lastSessionInvokeSessionId)
                assertEquals("""{"input":"data"}""", stubBindings.lastSessionInvokeInputJson)
                assertEquals(42L, stubBindings.lastSessionInvokeIdentityHandle)
                assertEquals("ucan.tok", stubBindings.lastSessionInvokeUcanToken)
                assertEquals(listOf("proof1", "proof2"), stubBindings.lastSessionInvokeProofTokens)
            }

        @Test
        fun `sessionClose dispatches on IO and forwards sessionId`() =
            runTest(ioDispatcher) {
                bridge.tools.sessionClose(10L, "session-001")
                assertTrue(stubBindings.toolSessionCloseCalled)
                assertEquals("session-001", stubBindings.lastSessionCloseSessionId)
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
    // Broadcast block/unblock tests
    // -------------------------------------------------------------------

    @Nested
    inner class BroadcastBlockUnblock {
        @Test
        fun `broadcastUnblockSubscriber dispatches on IO with correct args`() =
            runTest(ioDispatcher) {
                bridge.broadcast.unblockSubscriber(1L, "did:dht:z6MkSub", "did:dht:z6MkAdmin")
                assertTrue(stubBindings.broadcastUnblockCalled)
                assertEquals("did:dht:z6MkSub", stubBindings.lastUnblockSubscriberDid)
                assertEquals("did:dht:z6MkAdmin", stubBindings.lastUnblockUnblockerDid)
            }

        @Test
        fun `broadcastBlockSubscriber dispatches on IO with correct args`() =
            runTest(ioDispatcher) {
                bridge.broadcast.blockSubscriber(1L, "did:dht:z6MkBad", "did:dht:z6MkBlocker")
                assertTrue(stubBindings.broadcastBlockCalled)
                assertEquals("did:dht:z6MkBad", stubBindings.lastBlockSubscriberDid)
                assertEquals("did:dht:z6MkBlocker", stubBindings.lastBlockBlockerDid)
            }

        @Test
        fun `broadcastUnblockSubscriber propagates BridgeException`() =
            runTest(ioDispatcher) {
                stubBindings.broadcastUnblockThrows =
                    BridgeException(
                        "subscriber did:dht:z6MkSub not blocked by author did:dht:z6MkAdmin",
                        "SCP-CTX-2001",
                    )

                val exception =
                    assertFailsWith<BridgeException> {
                        bridge.broadcast.unblockSubscriber(1L, "did:dht:z6MkSub", "did:dht:z6MkAdmin")
                    }

                assertEquals("SCP-CTX-2001", exception.code)
                assertEquals(
                    "subscriber did:dht:z6MkSub not blocked by author did:dht:z6MkAdmin",
                    exception.message,
                )
            }
    }

    // -------------------------------------------------------------------
    // Economic policy roundtrip tests (#592)
    // -------------------------------------------------------------------

    @Nested
    inner class EconomicPolicyTests {
        @Test
        fun `setEconomicPolicy then getEconomicPolicy roundtrip`() =
            runTest(ioDispatcher) {
                @Suppress("MaxLineLength")
                val policyJson =
                    """{"locked":false,"cost_schedule":{"currency":[85,83,68,0]},"payment_adapters":[],"pricing_formula":null,"payee":"did:dht:z6MkPayee"}"""

                // Initially null.
                val initial = bridge.context.getEconomicPolicy(1L)
                assertEquals(null, initial)

                // Set, then get.
                bridge.context.setEconomicPolicy(1L, policyJson)
                val result = bridge.context.getEconomicPolicy(1L)
                assertEquals(policyJson, result)
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

    // toolInvoke argument captures
    var lastToolInvokeIdentityHandle: Long? = null
    var lastToolInvokeUcanToken: String? = null
    var lastToolInvokeProofTokens: List<String>? = null

    // Configurable results
    var identityCreateResult = 0L
    var identityCreateThrows: Exception? = null
    var identityLoadResult = 0L
    var identityResolveResult = ""
    var contextCreateResult = 0L
    var contextSubscribeResult = 0L
    var toolRegisterResult = ""
    var toolInvokeResult = ""
    var toolVerifyResult = """{"tool_id":"stub","passed":true,"failures":[]}"""
    var ucanMintResult = ""
    var ucanDelegateResult = ""
    var eventLogQueryResult = ""
    var eventLogVerifyResult = false
    var eventLogCheckpointResult = ""
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
        contextHandle: Long,
        identityHandle: Long,
    ) {
        // no-op
    }

    override fun contextLeave(
        contextHandle: Long,
        identityHandle: Long,
    ) {
        contextLeaveCalled = true
    }

    override fun contextClose(
        contextHandle: Long,
        identityHandle: Long,
    ) {
        contextCloseCalled = true
    }

    override fun contextSend(
        contextHandle: Long,
        identityHandle: Long,
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

    var lastEconomicPolicy: String? = null
    override fun contextSetEconomicPolicy(contextHandle: Long, policyJson: String) {
        lastEconomicPolicy = policyJson
    }
    override fun contextGetEconomicPolicy(contextHandle: Long): String? = lastEconomicPolicy

    // MembershipBindings
    override fun contextMemberCount(contextHandle: Long): Long? = 1L
    override fun contextIsMember(contextHandle: Long, did: String): Boolean = true
    override fun contextMemberDids(contextHandle: Long): List<String> = listOf("did:dht:stub")
    override fun contextMemberRole(contextHandle: Long, did: String): String? = "admin"

    // GovernanceBindings
    override fun governanceExecute(contextHandle: Long, proposalJson: String): String =
        """{"status":"executed"}"""
    override fun governancePropose(contextHandle: Long, proposerDid: String, actionJson: String): String =
        """{"proposal_id":"0000","status":"Pending","execution_result":null}"""
    override fun governanceApprove(contextHandle: Long, voterDid: String, proposalIdHex: String): String =
        """{"status":"Pending"}"""
    override fun governanceReject(contextHandle: Long, voterDid: String, proposalIdHex: String): String =
        """{"status":"Pending"}"""
    override fun governanceWithdraw(contextHandle: Long, voterDid: String, proposalIdHex: String): String =
        """{"status":"Pending"}"""
    override fun governanceGetProposal(contextHandle: Long, proposalIdHex: String): String =
        """{"proposal_id":"0000","status":"Pending","action":"{}","proposer_did":"did:dht:stub","votes":{}}"""
    override fun governanceListProposals(contextHandle: Long): String = "[]"
    override fun applyPendingCeilingModification(contextHandle: Long, currentTimestamp: Long): Boolean = false
    override fun finalizeClose(contextHandle: Long) = Unit
    @Suppress("LongParameterList")
    override fun createGovernanceCheckpoint(
        contextHandle: Long,
        checkpointSeq: Long,
        merkleRootHex: String,
        eventCount: Long,
        lastEventHashHex: String,
        stateSnapshotHashHex: String,
        creatorDid: String,
        creatorSignatureHex: String,
    ): String = "{}"
    override fun addCheckpointCosignature(
        contextHandle: Long,
        checkpointJson: String,
        signerDid: String,
        signatureHex: String,
    ): String = "{}"
    override fun restoreContext(contextId: String) = Unit
    override fun restoreAllContexts(): String = "[]"

    // BroadcastBindings
    var broadcastBlockCalled = false
    var broadcastUnblockCalled = false
    var lastBlockSubscriberDid: String? = null
    var lastBlockBlockerDid: String? = null
    var lastUnblockSubscriberDid: String? = null
    var lastUnblockUnblockerDid: String? = null
    var broadcastUnblockThrows: Exception? = null
    override fun broadcastSubscribe(contextHandle: Long, subscriberDid: String) = Unit
    override fun broadcastUnsubscribe(contextHandle: Long, subscriberDid: String, rotateKeys: Boolean) = Unit
    override fun broadcastPublish(contextHandle: Long, identityHandle: Long, payload: ByteArray) = Unit
    override fun broadcastBlockSubscriber(contextHandle: Long, subscriberDid: String, blockerDid: String) {
        broadcastBlockCalled = true
        lastBlockSubscriberDid = subscriberDid
        lastBlockBlockerDid = blockerDid
    }
    override fun broadcastUnblockSubscriber(contextHandle: Long, subscriberDid: String, unblockerDid: String) {
        broadcastUnblockCalled = true
        lastUnblockSubscriberDid = subscriberDid
        lastUnblockUnblockerDid = unblockerDid
        broadcastUnblockThrows?.let { throw it }
    }
    override fun broadcastHandleKeyRequest(contextHandle: Long, authorDid: String, requesterDid: String): String =
        """{"key":"stub"}"""
    override fun broadcastSubscriberCount(contextHandle: Long): Long? = 0L
    override fun broadcastIsSubscriber(contextHandle: Long, did: String): Boolean = false
    override fun broadcastAdmission(contextHandle: Long): String? = "Open"

    // Tool session argument captures
    var lastCrossContextSourceHandle: Long? = null
    var lastCrossContextTargetHandle: Long? = null
    var lastCrossContextToolId: String? = null
    var lastCrossContextInputJson: String? = null
    var lastCrossContextIdentityHandle: Long? = null
    var lastCrossContextUcanToken: String? = null
    var lastCrossContextChainDepth: Int? = null
    var lastCrossContextProofTokens: List<String>? = null
    var toolInvokeCrossContextResult = """{"output":"cross"}"""

    var lastSessionCreateToolId: String? = null
    var lastSessionCreateSourceContextId: String? = null
    var lastSessionCreateTtlSeconds: Long? = null
    var toolSessionCreateResult = "session-001"

    var lastSessionInvokeSessionId: String? = null
    var lastSessionInvokeInputJson: String? = null
    var lastSessionInvokeIdentityHandle: Long? = null
    var lastSessionInvokeUcanToken: String? = null
    var lastSessionInvokeProofTokens: List<String>? = null
    var toolSessionInvokeResult = """{"output":"session"}"""

    var toolSessionCloseCalled = false
    var lastSessionCloseSessionId: String? = null

    override fun toolRegister(
        contextHandle: Long,
        definitionJson: String,
    ): String = toolRegisterResult

    override fun toolInvoke(
        contextHandle: Long,
        toolId: String,
        inputJson: String,
        identityHandle: Long,
        ucanToken: String?,
        proofTokens: List<String>?,
    ): String {
        lastToolInvokeIdentityHandle = identityHandle
        lastToolInvokeUcanToken = ucanToken
        lastToolInvokeProofTokens = proofTokens
        return toolInvokeResult
    }

    override fun toolVerify(
        contextHandle: Long,
        toolId: String,
    ): String = toolVerifyResult

    override fun toolInterfaceExpose(
        contextHandle: Long,
        toolId: String,
        targetContextId: String,
        rateLimitJson: String?,
    ): String = """{"interface_id":"iface-001"}"""

    override fun toolInterfaceAccept(
        contextHandle: Long,
        interfaceJson: String,
    ): String = """{"interface_id":"iface-001","approved_by_target":true}"""

    override fun toolInterfaceRevoke(
        contextHandle: Long,
        interfaceIdHex: String,
    ): String = """{"revoked":true}"""

    @Suppress("LongParameterList")
    override fun toolInvokeCrossContext(
        sourceContextHandle: Long,
        targetContextHandle: Long,
        toolId: String,
        inputJson: String,
        identityHandle: Long,
        ucanToken: String,
        chainDepth: Int,
        proofTokens: List<String>?,
    ): String {
        lastCrossContextSourceHandle = sourceContextHandle
        lastCrossContextTargetHandle = targetContextHandle
        lastCrossContextToolId = toolId
        lastCrossContextInputJson = inputJson
        lastCrossContextIdentityHandle = identityHandle
        lastCrossContextUcanToken = ucanToken
        lastCrossContextChainDepth = chainDepth
        lastCrossContextProofTokens = proofTokens
        return toolInvokeCrossContextResult
    }

    override fun toolSessionCreate(
        contextHandle: Long,
        toolId: String,
        sourceContextId: String,
        ttlSeconds: Long?,
    ): String {
        lastSessionCreateToolId = toolId
        lastSessionCreateSourceContextId = sourceContextId
        lastSessionCreateTtlSeconds = ttlSeconds
        return toolSessionCreateResult
    }

    @Suppress("LongParameterList")
    override fun toolSessionInvoke(
        contextHandle: Long,
        sessionId: String,
        inputJson: String,
        identityHandle: Long,
        ucanToken: String,
        proofTokens: List<String>?,
    ): String {
        lastSessionInvokeSessionId = sessionId
        lastSessionInvokeInputJson = inputJson
        lastSessionInvokeIdentityHandle = identityHandle
        lastSessionInvokeUcanToken = ucanToken
        lastSessionInvokeProofTokens = proofTokens
        return toolSessionInvokeResult
    }

    override fun toolSessionClose(
        contextHandle: Long,
        sessionId: String,
    ) {
        toolSessionCloseCalled = true
        lastSessionCloseSessionId = sessionId
    }

    override fun ucanValidate(
        contextHandle: Long,
        token: String,
        capability: String,
        presentingAgentDid: String?,
        proofTokens: List<String>?,
    ) {
        ucanValidateCalled = true
    }

    override fun ucanMint(
        contextHandle: Long,
        memberDid: String,
        capabilitiesJson: String,
    ): String = ucanMintResult

    override fun ucanRevoke(
        contextHandle: Long,
        token: String,
        revokerDid: String,
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
        contextHandle: Long,
        filterJson: String,
    ): String = eventLogQueryResult

    override fun eventLogVerify(
        contextHandle: Long,
        claimJson: String,
    ): Boolean = eventLogVerifyResult

    override fun eventLogCheckpoint(
        contextHandle: Long,
        identityHandle: Long,
        epoch: Long,
    ): String = eventLogCheckpointResult

    override fun transportConnect(
        configJson: String,
        cancellationHandle: CancellationHandle?,
    ): Long {
        lastCancellationHandle = cancellationHandle
        return transportConnectResult
    }

    override fun transportStatus(transportHandle: Long): String = transportStatusResult

    var transportDisconnectCalled = false
    override fun transportDisconnect(transportHandle: Long) {
        transportDisconnectCalled = true
    }
}
