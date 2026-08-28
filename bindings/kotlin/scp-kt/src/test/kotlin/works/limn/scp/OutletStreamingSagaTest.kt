// OutletStreamingSagaTest.kt — contract tests for the §6.2.4 cross-context
// STREAMING saga SDK wrapper (SCP-OUT-047): the [StreamingSagaHandle]
// (aggregate() + asFlow(), no control plane) and the SCP entry points
// [SCP.outletInvokeCrossContextStreamingSaga] / [SCP.recoverStreamingSagaTruncatedClose].
//
// The handle-behavior tests exercise ALL of the SDK-layer contract — lazy open
// at first pull, the asFlow() shared-drain iteration, the single-consumer guard,
// sequence-gap detection (no cross-context cancel plane), and open-rejection
// propagation — against a scripted mock [StreamingSagaNative] that plays back a
// JSON chunk sequence in the exact §5.4.5 OutletStreamChunk wire shape. No built
// Rust cdylib is required: the seam is a pure-Kotlin interface. The recover test
// is a bridge-linkage smoke test over the real bridge (guarded by native
// availability), mirroring OutletSagaTest.
//
// Runtime-level guarantees (billed-count / execute-exactly-once) are proven
// Rust-side and are NOT re-asserted here. Mirrors the Python reference
// tests/test_outlets_streaming_saga.py.

package works.limn.scp

import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.toList
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.long
import kotlinx.serialization.json.put
import org.junit.jupiter.api.Assumptions.assumeTrue
import org.junit.jupiter.api.BeforeAll
import uniffi.scp.ScpException
import uniffi.scp.StorageConfig
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds

// ---------------------------------------------------------------------------
// Wire-shape chunk builders (match §5.4.5 OutletStreamChunk serialization).
// ---------------------------------------------------------------------------

private val SAGA_REQUEST_ID: List<Int> = List(16) { 0x01 }
private val SAGA_SIG: List<Int> = List(64) { 0x22 }

private fun sagaChunk(
    sequence: Long,
    payload: JsonObject,
): ByteArray {
    val obj =
        buildJsonObject {
            put("request_id", JsonArray(SAGA_REQUEST_ID.map { JsonPrimitive(it) }))
            put("sequence", sequence)
            put("payload", payload)
            put("sig", JsonArray(SAGA_SIG.map { JsonPrimitive(it) }))
        }
    return obj.toString().encodeToByteArray()
}

private fun sagaDataChunk(
    sequence: Long,
    value: JsonElement,
): ByteArray =
    sagaChunk(
        sequence,
        buildJsonObject {
            put("@type", "data")
            put("value", value)
        },
    )

private fun sagaEndChunk(
    sequence: Long,
    aggregate: JsonElement,
    executionTimeMs: Int = 42,
): ByteArray =
    sagaChunk(
        sequence,
        buildJsonObject {
            put("@type", "end")
            put("aggregate", aggregate)
            put(
                "provenance",
                buildJsonObject {
                    put("source", "outlet")
                    put("quality", "verified")
                },
            )
            put("execution_time_ms", executionTimeMs)
        },
    )

private fun sagaErrorChunk(
    sequence: Long,
    code: String,
    message: String,
    terminal: Boolean = true,
): ByteArray =
    sagaChunk(
        sequence,
        buildJsonObject {
            put("@type", "error")
            put("code", code)
            put("message", message)
            put("terminal", terminal)
        },
    )

private fun sagaObj(
    key: String,
    value: Int,
): JsonObject = buildJsonObject { put(key, value) }

// ---------------------------------------------------------------------------
// Scripted mock seam.
// ---------------------------------------------------------------------------

private open class FakeSagaNative(
    chunks: List<ByteArray>,
    private val sagaId: String = "saga-1",
    private val openError: ScpException? = null,
) : StreamingSagaNative {
    private val chunks = chunks.toList()
    private var index = 0
    var openCalls = 0
        private set

    @Suppress("LongParameterList")
    override suspend fun outletStreamingSagaOpen(
        callerDid: String,
        outletRegistrationId: String,
        inputJson: String,
        assertedNonceHex: String,
        timestampMs: ULong,
        chainDepth: UByte,
        ucanToken: String,
        proofTokens: List<String>?,
        ucanProofId: String?,
        timeoutMs: UInt?,
        estimatedChunkCount: UInt?,
    ): String {
        openCalls += 1
        openError?.let { throw it }
        return sagaId
    }

    override suspend fun outletStreamingSagaPollNext(sagaId: String): ByteArray? {
        if (index >= chunks.size) return null
        return chunks[index++]
    }
}

/** A mock whose FIRST poll parks on [gate] after signalling [firstPollStarted]. */
private class GatedFakeSagaNative(
    chunks: List<ByteArray>,
    private val gate: CompletableDeferred<Unit>,
) : FakeSagaNative(chunks) {
    val firstPollStarted = CompletableDeferred<Unit>()
    private var polls = 0

    override suspend fun outletStreamingSagaPollNext(sagaId: String): ByteArray? {
        polls++
        if (polls == 1) {
            firstPollStarted.complete(Unit)
            gate.await()
        }
        return super.outletStreamingSagaPollNext(sagaId)
    }
}

private fun sagaHandle(native: FakeSagaNative): StreamingSagaHandle =
    StreamingSagaHandle(
        native = native,
        params =
            StreamingSagaOpenParams(
                callerDid = "did:dht:caller",
                outletRegistrationId = "outlet-reg-1",
                inputJson = """{"a":1}""",
                assertedNonceHex = "00".repeat(16),
                timestampMs = 1_700_000_000_000uL,
                chainDepth = 0u,
                ucanToken = "ucan-abc",
                proofTokens = null,
                ucanProofId = null,
                timeoutMs = null,
                estimatedChunkCount = 8u,
            ),
    )

// ---------------------------------------------------------------------------
// Handle behavior (mock seam — no native required).
// ---------------------------------------------------------------------------

class StreamingSagaHandleTest {
    @Test
    fun `open is lazy - constructing the handle opens nothing`() =
        runTest {
            val native = FakeSagaNative(listOf(sagaEndChunk(0, sagaObj("n", 1))))
            val handle = sagaHandle(native)
            assertEquals(0, native.openCalls)
            assertNull(handle.sagaId)
        }

    @Test
    fun `progressive drain yields data chunks then the terminal End`() =
        runTest {
            val native =
                FakeSagaNative(
                    listOf(
                        sagaDataChunk(0, sagaObj("n", 0)),
                        sagaDataChunk(1, sagaObj("n", 1)),
                        sagaEndChunk(2, sagaObj("total", 2)),
                    ),
                )
            val handle = sagaHandle(native)
            val kinds = handle.asFlow().toList().map { it.kind }
            assertEquals(listOf("data", "data", "end"), kinds)
            assertEquals(1, native.openCalls) // opened once for the whole drain
            assertEquals("saga-1", handle.sagaId)
        }

    @Test
    fun `aggregate returns the End payload`() =
        runTest {
            val native =
                FakeSagaNative(
                    listOf(
                        sagaDataChunk(0, sagaObj("n", 1)),
                        sagaEndChunk(1, sagaObj("total", 99), executionTimeMs = 55),
                    ),
                )
            val handle = sagaHandle(native)
            val aggregate = handle.aggregate()
            assertEquals(55L, aggregate.executionTimeMs)
            assertEquals(99, (aggregate.value as JsonObject)["total"]?.let { (it as JsonPrimitive).long.toInt() })
        }

    @Test
    fun `terminal Error chunk raises the typed ScpException Outlet`() =
        runTest {
            val native =
                FakeSagaNative(listOf(sagaDataChunk(0, sagaObj("n", 0)), sagaErrorChunk(1, "SCP-OUTLET-6010", "boom")))
            val handle = sagaHandle(native)
            val ex = assertFailsWith<ScpException.Outlet> { handle.aggregate() }
            assertEquals("SCP-OUTLET-6010", ex.code)
        }

    @Test
    fun `sequence gap raises StreamGap without a cancel plane`() =
        runTest {
            // Sequence jumps 0 -> 2 (missing 1). There is no cross-context cancel
            // op on the StreamingSagaNative surface, so the gap is a local terminal.
            val native = FakeSagaNative(listOf(sagaDataChunk(0, sagaObj("n", 0)), sagaDataChunk(2, sagaObj("n", 2))))
            val handle = sagaHandle(native)
            assertFailsWith<StreamGap> { handle.aggregate() }
        }

    @Test
    fun `stream without End raises OutletProtocolException`() =
        runTest {
            val native = FakeSagaNative(listOf(sagaDataChunk(0, sagaObj("n", 0))))
            val handle = sagaHandle(native)
            assertFailsWith<OutletProtocolException> { handle.aggregate() }
        }

    @Test
    fun `open rejection surfaces on first drain and the receiver is never handed out`() =
        runTest {
            val native =
                FakeSagaNative(
                    emptyList(),
                    openError =
                        ScpException.SagaAborted(
                            msg = "[SCP-SAGA-13050] caller_did is not a member of the source context",
                            code = "SCP-SAGA-13050",
                            retryAfterMs = null,
                        ),
                )
            val handle = sagaHandle(native)
            val ex = assertFailsWith<ScpException.SagaAborted> { handle.aggregate() }
            assertEquals("SCP-SAGA-13050", ex.code)
            assertNull(handle.sagaId)
        }

    @Test
    fun `second concurrent collector on the shared drain fails loud`() =
        runTest {
            val gate = CompletableDeferred<Unit>()
            val native =
                GatedFakeSagaNative(
                    listOf(sagaDataChunk(0, sagaObj("n", 0)), sagaEndChunk(1, sagaObj("n", 1))),
                    gate,
                )
            val handle = sagaHandle(native)

            // First driver: parks inside its first poll (holding the drain).
            val job = launch { handle.asFlow().toList() }
            native.firstPollStarted.await()

            // Second CONCURRENT driver: the shared drain is single-consumer.
            assertFailsWith<OutletProtocolException> { handle.asFlow().first() }

            gate.complete(Unit)
            job.join()
        }
}

// ---------------------------------------------------------------------------
// Recover truncated-close — bridge-linkage smoke test over the real bridge.
// ---------------------------------------------------------------------------

@OptIn(ExperimentalCoroutinesApi::class)
class StreamingSagaRecoverTest {
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
    }

    /**
     * The `recoverStreamingSagaTruncatedClose` wrapper forwards `sagaId` +
     * `callerDid` to the real bridge. Without a live truncated saga, an unknown
     * `sagaId` surfaces a typed [ScpException] — proving the wrapper reaches the
     * bridge (mirrors the Kotlin end-to-end saga forwarding smoke test).
     * Per-argument positional fidelity is asserted in the Rust/integration tests.
     */
    @Test
    fun `recoverStreamingSagaTruncatedClose reaches the real bridge and surfaces a typed ScpException`() {
        assumeTrue(nativeAvailable, skipReason)
        runBlocking {
            val scp = SCP(StorageConfig.InMemory)
            try {
                scp.configureLocalTransport(localDid = "did:key:z6MkKotlinStreamingSagaRecoverTest")
                val identity = scp.identityCreate(custody = CustodyType.IN_MEMORY)
                assertFailsWith<ScpException> {
                    scp.recoverStreamingSagaTruncatedClose(
                        sagaId = "nonexistent-saga-id",
                        callerDid = identity.did(),
                    )
                }
            } finally {
                val shutdownBridge =
                    works.limn.scp.bridge.CoroutineBridge(
                        nativeBindings = works.limn.scp.conformance.ConformanceStubBindings(),
                        ioDispatcher = Dispatchers.IO,
                        cpuDispatcher = Dispatchers.Default,
                    )
                scp.shutdown(shutdownBridge, 1.seconds)
            }
        }
    }
}
