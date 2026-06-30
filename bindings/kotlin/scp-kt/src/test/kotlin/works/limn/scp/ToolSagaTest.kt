// ToolSagaTest.kt — SDK-wrapper tests for the §6.2.4 cross-context
// tool-invocation saga (ADR-049 §3a, PR-6c slice 4/4).
//
// The Kotlin SDK surfaces the generated UniFFI types directly: the saga
// terminal is the generated `SagaResult` (faithful nullable), and the
// non-committed terminals are the generated `ScpException.Saga*` cases.
// Unlike the Python/TS SDKs (which wrap untyped bridge errors into dedicated
// SDK classes), there is no re-mapping layer here — the `Scp` shim forwards
// 1:1 and the typed error propagates. Mirroring the Kotlin sibling
// `toolInvokeCrossContext`, the wrapper carries NO client-side guards: input
// is already a `String`, and the u64/u8 numeric bounds are enforced by
// `ULong`/`UByte`, so all validation lives in the Rust core.
//
// This suite exercises:
//   - the public type surface (SagaResult faithful pass-through incl. null;
//     the three typed ScpException.Saga* cases carrying their fields),
//   - the flat `ToolBridge.invokeCrossContextSaga` conformance symbol
//     (argument forwarding + BridgeException propagation), and
//   - end-to-end argument forwarding through the real UniFFI bridge.
//
// Provenance: PR-6c slice 4/4. §6.2.4 / ADR-049 §3a. ADR-026/ADR-028.

package works.limn.scp

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.TestDispatcher
import kotlinx.coroutines.test.runTest
import org.junit.jupiter.api.Assumptions.assumeTrue
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import uniffi.scp.CeilingPolicy
import uniffi.scp.ContextMode
import uniffi.scp.ContextParams
import uniffi.scp.GovernanceModel
import uniffi.scp.MemoryScope
import uniffi.scp.SagaResult
import uniffi.scp.ScpException
import uniffi.scp.StorageConfig
import uniffi.scp.ToolDefinition
import works.limn.scp.bridge.BridgeException
import works.limn.scp.bridge.CoroutineBridge
import works.limn.scp.conformance.ConformanceStubBindings
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.test.fail
import kotlin.time.Duration.Companion.seconds

@OptIn(ExperimentalCoroutinesApi::class)
class ToolSagaTest {
    companion object {
        private var nativeAvailable = false
        private var skipReason = ""

        @JvmStatic
        @BeforeAll
        fun probeNativeLibrary() {
            try {
                Class.forName("uniffi.scp.ScpKt")
                Class.forName("uniffi.scp.Scp\$Companion")
                nativeAvailable = true
            } catch (e: ClassNotFoundException) {
                skipReason = "UniFFI bindings not available: ${e.message}"
            } catch (e: UnsatisfiedLinkError) {
                skipReason = "Native library link error: ${e.message}"
            } catch (e: ExceptionInInitializerError) {
                skipReason = "Native library init error: ${e.cause?.message ?: e.message}"
            } catch (e: NoClassDefFoundError) {
                skipReason = "Native library class not found: ${e.message}"
            }
        }

        /** 32 hex chars = 16 bytes — a well-formed §6.2.4 asserted-nonce input. */
        private const val NONCE_HEX = "abababababababababababababababab"
    }

    private lateinit var stubBindings: ConformanceStubBindings
    private lateinit var bridge: CoroutineBridge
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
    }

    // ── SagaResult: faithful nullable pass-through ────────────────────────

    /**
     * A committed terminal carries the supervisor-minted `sagaId` plus the
     * signed receipt and captured output bytes verbatim.
     */
    @Test
    fun `SagaResult carries receipt and output`() {
        val receipt = byteArrayOf(0x01, 0x02, 0x03)
        val output = byteArrayOf(0x04, 0x05)
        val result = SagaResult(sagaId = "saga-1", receipt = receipt, output = output)

        assertEquals("saga-1", result.sagaId)
        assertContentEquals(receipt, result.receipt)
        assertContentEquals(output, result.output)
    }

    /**
     * `receipt` and `output` are surfaced exactly as the bridge returns them —
     * `null` when absent, never synthesized.
     */
    @Test
    fun `SagaResult passes through null receipt and output`() {
        val result = SagaResult(sagaId = "saga-2", receipt = null, output = null)

        assertEquals("saga-2", result.sagaId)
        assertNull(result.receipt)
        assertNull(result.output)
    }

    // ── Typed terminals: ScpException.Saga* surfaced directly ─────────────

    /**
     * `SagaAborted` carries `msg`, `code`, and the rate-limit back-off hint
     * `retryAfterMs` — a concrete cooldown when one exists.
     */
    @Test
    fun `SagaAborted carries retryAfter`() {
        val error =
            ScpException.SagaAborted(
                msg = "[SCP-SAGA-13001] prepare rejected",
                code = "SCP-SAGA-13001",
                retryAfterMs = 1500uL,
            )

        assertEquals("[SCP-SAGA-13001] prepare rejected", error.msg)
        assertEquals("SCP-SAGA-13001", error.code)
        assertEquals(1500uL, error.retryAfterMs)
    }

    /**
     * `retryAfterMs` is `null` (never `0`) when no precise back-off instant
     * exists — `0` would read as "retry immediately" and re-trip the limit.
     */
    @Test
    fun `SagaAborted preserves null retryAfter`() {
        val error =
            ScpException.SagaAborted(
                msg = "[SCP-SAGA-13002] hard limit",
                code = "SCP-SAGA-13002",
                retryAfterMs = null,
            )

        assertNull(error.retryAfterMs)
    }

    /** `SagaNeedsRepair` carries the durable `sagaId` operator-repair handle. */
    @Test
    fun `SagaNeedsRepair carries sagaId`() {
        val error =
            ScpException.SagaNeedsRepair(
                msg = "[SCP-SAGA-13065] commit retries exhausted",
                code = "SCP-SAGA-13065",
                sagaId = "saga-repair-7",
            )

        assertEquals("[SCP-SAGA-13065] commit retries exhausted", error.msg)
        assertEquals("SCP-SAGA-13065", error.code)
        assertEquals("saga-repair-7", error.sagaId)
    }

    /** `SagaBusy` carries the contended context id that forced serialization. */
    @Test
    fun `SagaBusy carries contendedContext`() {
        val error =
            ScpException.SagaBusy(
                msg = "[SCP-SAGA-13066] participant set overlap",
                code = "SCP-SAGA-13066",
                contendedContext = "ctx-shared-42",
            )

        assertEquals("[SCP-SAGA-13066] participant set overlap", error.msg)
        assertEquals("SCP-SAGA-13066", error.code)
        assertEquals("ctx-shared-42", error.contendedContext)
    }

    // ── Flat ToolBridge.invokeCrossContextSaga conformance ────────────────

    /**
     * The coverage symbol `ToolBridge.invokeCrossContextSaga` dispatches on IO
     * and forwards all nine arguments to the bridge verbatim, returning the
     * JSON result unchanged.
     */
    @Test
    fun `invokeCrossContextSaga forwards all arguments and returns result`() =
        runTest(testDispatcher) {
            stubBindings.toolInvokeCrossContextSagaResult = """{"saga_id":"saga-xyz"}"""
            val result =
                bridge.tools.invokeCrossContextSaga(
                    sourceContextHandle = 1L,
                    targetContextHandle = 2L,
                    callerDid = "did:key:zCaller",
                    toolRegistrationId = "reg-001",
                    inputJson = """{"city":"Berlin"}""",
                    assertedNonceHex = NONCE_HEX,
                    timestampMs = 1_700_000_000_000L,
                    chainDepth = 0,
                    ucanProofId = "proof-1",
                )

            assertEquals("""{"saga_id":"saga-xyz"}""", result)
            assertEquals(
                listOf(
                    "1",
                    "2",
                    "did:key:zCaller",
                    "reg-001",
                    """{"city":"Berlin"}""",
                    NONCE_HEX,
                    "1700000000000",
                    "0",
                    "proof-1",
                ),
                stubBindings.lastSagaArgs,
            )
        }

    /**
     * A configured bridge error propagates out of the coverage symbol as a
     * [BridgeException] carrying the typed `SCP-SAGA-13xxx` code.
     */
    @Test
    fun `invokeCrossContextSaga propagates configured BridgeException`() =
        runTest(testDispatcher) {
            stubBindings.toolInvokeCrossContextSagaError =
                BridgeException("participant set overlap", "SCP-SAGA-13066")
            try {
                bridge.tools.invokeCrossContextSaga(
                    sourceContextHandle = 1L,
                    targetContextHandle = 2L,
                    callerDid = "did:key:zCaller",
                    toolRegistrationId = "reg-001",
                    inputJson = "{}",
                    assertedNonceHex = NONCE_HEX,
                    timestampMs = 1_700_000_000_000L,
                    chainDepth = 0,
                )
                fail("expected BridgeException for a configured saga error")
            } catch (e: BridgeException) {
                assertEquals("SCP-SAGA-13066", e.code)
            }
        }

    // ── End-to-end argument forwarding through the real bridge ────────────

    /**
     * With an active source and target, the `Scp` shim forwards all arguments
     * into the real saga. Without bidirectional consent the supervisor reaches
     * a non-committed terminal, so the call surfaces a typed [ScpException] —
     * proving the nine arguments (both handles, `callerDid`,
     * `toolRegistrationId`, `inputJson`, nonce, timestamp, depth, optional
     * proof) reach the real bridge.
     *
     * This is a bridge-linkage smoke test: it confirms the call reaches the
     * real bridge, but does not assert per-argument positional fidelity (a
     * same-typed swap would not be caught here — that assurance lives in the
     * Rust/integration tests, since asserting it at this wrapper unit layer
     * would require committed-saga bidirectional-consent setup).
     */
    @Test
    fun `toolInvokeCrossContextSaga reaches the real saga and surfaces a typed ScpException`() {
        assumeTrue(nativeAvailable, skipReason)
        runBlocking {
            val scp = SCP(StorageConfig.InMemory)
            try {
                scp.configureLocalTransport(localDid = "did:key:z6MkKotlinSagaForwardTest")
                val identity = scp.identityCreate(custody = "in_memory")
                val source = scp.contextCreate(identity = identity, params = makeParams())
                val target = scp.contextCreate(identity = identity, params = makeParams())
                val toolId =
                    scp.toolRegister(
                        handle = target,
                        definition = weatherTool(operatorDid = identity.did()),
                    )

                try {
                    val result =
                        scp.toolInvokeCrossContextSaga(
                            sourceHandle = source,
                            targetHandle = target,
                            callerDid = identity.did(),
                            toolRegistrationId = toolId,
                            inputJson = """{"city":"Berlin","unit":"C"}""",
                            assertedNonceHex = NONCE_HEX,
                            timestampMs = System.currentTimeMillis().toULong(),
                            chainDepth = 0.toUByte(),
                            ucanProofId = null,
                        )
                    // A committed terminal (unlikely without consent setup) is
                    // still a valid forwarding outcome: the bridge produced a
                    // SagaResult carrying a non-empty supervisor-minted sagaId.
                    assertTrue(
                        result.sagaId.isNotEmpty(),
                        "committed saga must carry a sagaId",
                    )
                } catch (e: ScpException) {
                    // Any typed ScpException (a Saga* terminal or a
                    // supervisor-side rejection) means the call reached the
                    // real bridge — the wrapper forwarded successfully.
                    assertTrue(
                        e.message!!.contains("code="),
                        "expected a typed ScpException carrying a code= detail",
                    )
                }
            } finally {
                val shutdownBridge =
                    CoroutineBridge(
                        nativeBindings = ConformanceStubBindings(),
                        ioDispatcher = Dispatchers.IO,
                        cpuDispatcher = Dispatchers.Default,
                    )
                scp.shutdown(shutdownBridge, 1.seconds)
            }
        }
    }

    // ── Fixtures ──────────────────────────────────────────────────────────

    private fun makeParams(): ContextParams =
        ContextParams(
            mode = ContextMode.ENCRYPTED,
            ceiling =
                listOf(
                    "messages:read",
                    "messages:write",
                    "tool:invoke:*",
                    "tool:register",
                    "context:close",
                ),
            ceilingPolicy = CeilingPolicy.IMMUTABLE,
            governance = GovernanceModel.SINGLE_ADMIN,
            memoryScope = MemoryScope.EPHEMERAL,
            ttlSeconds = 3600uL,
            promotable = false,
            minProtocolVersion = 0.toUShort(),
            maxChainDepth = null,
            maxNestingDepth = null,
            sessionCap = null,
            economicPolicy = null,
            consequenceRulesJson = null,
            consequenceConfigJson = null,
        )

    private fun weatherTool(operatorDid: String): ToolDefinition =
        ToolDefinition(
            name = "weather",
            description = "Get current weather for a city",
            inputSchemaJson =
                """{"type":"object","properties":{"city":{"type":"string"},""" +
                    """"unit":{"type":"string"}},"required":["city"]}""",
            outputSchemaJson =
                """{"type":"object","properties":{"tempC":{"type":"number"},""" +
                    """"condition":{"type":"string"}}}""",
            operatorDid = operatorDid,
            testVectorsJson = "[]",
            implementationHash = null,
            cost = null,
        )
}
