// OutletsStreamingTest.kt — contract tests for the single-verb outlet streaming
// surface (SCP-OUT-038), the Kotlin mirror of the Python reference suite
// (bindings/python/tests/test_outlets_streaming.py).
//
// These exercise ALL of the SDK-layer InvocationHandle contract — the
// aggregate() drain verb, the asFlow() shared-drain iteration, the Credit
// value class, grantCredit / cancel control-plane methods, and the lifecycle
// guard — against a scripted mock OutletStreamNative that plays back a JSON
// chunk sequence in the exact §5.4.5 OutletStreamChunk wire shape (serde_bytes
// fields as integer arrays). No built Rust cdylib is required: the seam is a
// pure-Kotlin interface. The LIVE wire path is covered by the Rust bridge's own
// live-poll test.
//
// Provenance: SCP-OUT-038 / §5.4.5. Mirrors the CANONICAL Python reference.

package works.limn.scp

import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.take
import kotlinx.coroutines.flow.toList
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.long
import kotlinx.serialization.json.put
import uniffi.scp.ScpException
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertIs
import kotlin.test.assertTrue

// ---------------------------------------------------------------------------
// Wire-shape chunk builders (match §5.4.5 OutletStreamChunk serialization).
// ---------------------------------------------------------------------------

private val REQUEST_ID: List<Int> = List(16) { 0x01 }
private val SIG: List<Int> = List(64) { 0x22 }
private val REQUEST_ID_HEX: String = "01".repeat(16)
private val SIG_HEX: String = "22".repeat(64)

private const val CALLER = "did:dht:caller"
private const val UCAN = "ucan-abc"

private fun chunk(
    sequence: Long,
    payload: JsonObject,
): ByteArray {
    val obj =
        buildJsonObject {
            put("request_id", JsonArray(REQUEST_ID.map { JsonPrimitive(it) }))
            put("sequence", sequence)
            put("payload", payload)
            put("sig", JsonArray(SIG.map { JsonPrimitive(it) }))
        }
    return obj.toString().encodeToByteArray()
}

private fun dataChunk(
    sequence: Long,
    value: JsonElement,
): ByteArray =
    chunk(
        sequence,
        buildJsonObject {
            put("@type", "data")
            put("value", value)
        },
    )

private fun progressChunk(
    sequence: Long,
    pct: Int,
    note: String? = null,
): ByteArray =
    chunk(
        sequence,
        buildJsonObject {
            put("@type", "progress")
            put("pct", pct)
            if (note != null) put("note", note)
        },
    )

private fun endChunk(
    sequence: Long,
    aggregate: JsonElement,
    executionTimeMs: Int = 42,
): ByteArray =
    chunk(
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

private fun errorChunk(
    sequence: Long,
    code: String,
    message: String,
    terminal: Boolean = true,
): ByteArray =
    chunk(
        sequence,
        buildJsonObject {
            put("@type", "error")
            put("code", code)
            put("message", message)
            put("terminal", terminal)
        },
    )

private fun obj(
    key: String,
    value: Int,
): JsonObject = buildJsonObject { put(key, value) }

// ---------------------------------------------------------------------------
// Scripted mock seam.
// ---------------------------------------------------------------------------

private data class OpenCall(
    val outletId: String,
    val inputJson: String,
    val callerDid: String,
    val ucanToken: String,
    val estimatedChunkCount: UInt?,
)

private open class FakeNative(
    chunks: List<ByteArray>,
    private val handleId: String = "stream-1",
) : OutletStreamNative {
    private val chunks = chunks.toList()
    private var index = 0
    val openCalls = mutableListOf<OpenCall>()
    val grantCalls = mutableListOf<Triple<String, String, UInt>>()
    val cancelCalls = mutableListOf<Pair<String, String>>()

    @Suppress("LongParameterList")
    override suspend fun outletStreamOpen(
        outletId: String,
        inputJson: String,
        callerDid: String,
        ucanToken: String,
        proofTokens: List<String>?,
        spendingUcan: String?,
        timeoutMs: UInt?,
        estimatedChunkCount: UInt?,
    ): String {
        openCalls.add(OpenCall(outletId, inputJson, callerDid, ucanToken, estimatedChunkCount))
        return handleId
    }

    override suspend fun outletStreamPollNext(handleId: String): ByteArray? {
        if (index >= chunks.size) return null
        return chunks[index++]
    }

    override suspend fun outletStreamGrantCredit(
        handleId: String,
        callerDid: String,
        grant: UInt,
    ) {
        grantCalls.add(Triple(handleId, callerDid, grant))
    }

    override suspend fun outletStreamCancel(
        handleId: String,
        callerDid: String,
    ) {
        cancelCalls.add(handleId to callerDid)
    }
}

private class RaisingOpenNative(
    private val exc: ScpException,
) : FakeNative(emptyList()) {
    @Suppress("LongParameterList")
    override suspend fun outletStreamOpen(
        outletId: String,
        inputJson: String,
        callerDid: String,
        ucanToken: String,
        proofTokens: List<String>?,
        spendingUcan: String?,
        timeoutMs: UInt?,
        estimatedChunkCount: UInt?,
    ): String = throw exc
}

private class RaisingPollNative(
    chunks: List<ByteArray>,
    private val exc: ScpException,
    private val failAfter: Int,
) : FakeNative(chunks) {
    private var polls = 0

    override suspend fun outletStreamPollNext(handleId: String): ByteArray? {
        polls++
        if (polls > failAfter) throw exc
        return super.outletStreamPollNext(handleId)
    }
}

/** A mock whose FIRST poll parks on [gate] after signalling [firstPollStarted]. */
private class GatedFakeNative(
    chunks: List<ByteArray>,
    private val gate: CompletableDeferred<Unit>,
) : FakeNative(chunks) {
    val firstPollStarted = CompletableDeferred<Unit>()
    private var polls = 0

    override suspend fun outletStreamPollNext(handleId: String): ByteArray? {
        polls++
        if (polls == 1) {
            firstPollStarted.complete(Unit)
            gate.await()
        }
        return super.outletStreamPollNext(handleId)
    }
}

private fun invoke(
    native: FakeNative,
    callerDid: String? = null,
): InvocationHandle =
    Outlets(native, CALLER).invoke(
        outletId = "outlet-1",
        inputJson = """{"q":"x"}""",
        ucanToken = UCAN,
        callerDid = callerDid,
    )

// ---------------------------------------------------------------------------
// AC6 conformance-vector loading (single source of truth:
// tests/conformance/vectors/outlet_stream_vectors.json).
// ---------------------------------------------------------------------------

/** Walk up from the test JVM's working dir until the repo-root vectors file is found. */
private fun locateVectorsFile(): File {
    var dir: File? = File(System.getProperty("user.dir"))
    while (dir != null) {
        val candidate = File(dir, "tests/conformance/vectors/outlet_stream_vectors.json")
        if (candidate.isFile) return candidate
        dir = dir.parentFile
    }
    error("could not locate outlet_stream_vectors.json from ${System.getProperty("user.dir")}")
}

private val VECTORS: Map<String, JsonObject> =
    run {
        val text = locateVectorsFile().readText()
        val root = Json.parseToJsonElement(text).jsonObject
        root["vectors"]!!.jsonArray.associate { el ->
            val obj = el.jsonObject
            obj["name"]!!.jsonPrimitive.content to obj
        }
    }

/** Serialize a vector's chunk list into the mock's wire-byte playback. */
private fun vectorChunks(vector: JsonObject): List<ByteArray> =
    vector["chunks"]!!.jsonArray.map { el ->
        val entry = el.jsonObject
        chunk(entry["sequence"]!!.jsonPrimitive.long, entry["payload"]!!.jsonObject)
    }

private fun endAggregate(vector: JsonObject): JsonElement? =
    vector["chunks"]!!
        .jsonArray
        .map { it.jsonObject }
        .firstOrNull { it["payload"]!!.jsonObject["@type"]?.jsonPrimitive?.contentOrNull == "end" }
        ?.get("payload")
        ?.jsonObject
        ?.get("aggregate")

private fun expectedErrorCode(vector: JsonObject): String? =
    (vector["expected_error_code"] as? JsonPrimitive)?.contentOrNull

// ---------------------------------------------------------------------------
// Credit value class.
// ---------------------------------------------------------------------------

class CreditTest {
    @Test
    fun `valid credit exposes value`() {
        assertEquals(1u, Credit(1u).value)
        assertEquals(10u, Credit(10u).value)
        assertEquals(UInt.MAX_VALUE, Credit(UInt.MAX_VALUE).value)
    }

    @Test
    fun `zero raises InvalidGrant`() {
        assertFailsWith<InvalidGrant> { Credit(0u) }
    }

    @Test
    fun `InvalidGrant and StreamAlreadyClosed are protocol-class`() {
        assertTrue(InvalidGrant("x") is OutletProtocolException)
        assertTrue(StreamAlreadyClosed("x") is OutletProtocolException)
    }
}

// ---------------------------------------------------------------------------
// invoke() surface + lazy open.
// ---------------------------------------------------------------------------

class OutletsInvokeTest {
    @Test
    fun `invoke returns handle without opening the stream`() {
        val native = FakeNative(listOf(dataChunk(0, obj("n", 1)), endChunk(1, obj("n", 1))))
        val handle = invoke(native)
        assertIs<InvocationHandle>(handle)
        // Lazy open: invoke() must not have opened the stream yet.
        assertTrue(native.openCalls.isEmpty())
    }
}

// ---------------------------------------------------------------------------
// Iteration + aggregation.
// ---------------------------------------------------------------------------

class StreamingTest {
    @Test
    fun `asFlow yields all chunks including progress`() =
        runTest {
            val native =
                FakeNative(
                    listOf(
                        dataChunk(0, obj("n", 0)),
                        progressChunk(1, 5000, note = "halfway"),
                        dataChunk(2, obj("n", 1)),
                        endChunk(3, obj("total", 2)),
                    ),
                )
            val handle = invoke(native)

            val collected = handle.asFlow().toList()

            assertEquals(listOf("data", "progress", "data", "end"), collected.map { it.kind })
            val progress = collected[1]
            assertEquals(5000, progress.payload["pct"]?.let { (it as JsonPrimitive).content.toInt() })
            assertEquals("halfway", (progress.payload["note"] as JsonPrimitive).content)
            assertEquals(0L, collected[0].sequence)
            assertEquals(REQUEST_ID_HEX, collected[0].requestId)
            assertEquals(SIG_HEX, collected[0].signature)
            assertTrue(collected.last().isTerminal)
        }

    @Test
    fun `aggregate returns the End aggregate`() =
        runTest {
            val native =
                FakeNative(listOf(dataChunk(0, obj("n", 1)), endChunk(1, obj("total", 1), executionTimeMs = 77)))
            val handle = invoke(native)

            val result = handle.aggregate()

            assertEquals(buildJsonObject { put("total", 1) }, result.value)
            assertEquals(77L, result.executionTimeMs)
            assertEquals(
                buildJsonObject {
                    put("source", "outlet")
                    put("quality", "verified")
                },
                result.provenance,
            )
        }

    @Test
    fun `stream opens exactly once and forwards caller and ucan`() =
        runTest {
            val native = FakeNative(listOf(dataChunk(0, obj("n", 1)), endChunk(1, obj("n", 1))))
            val handle = invoke(native)

            handle.asFlow().toList()

            assertEquals(1, native.openCalls.size)
            val open = native.openCalls[0]
            assertEquals("outlet-1", open.outletId)
            assertEquals(CALLER, open.callerDid)
            assertEquals(UCAN, open.ucanToken)
        }

    @Test
    fun `terminal error chunk raises typed ScpException on aggregate`() =
        runTest {
            val native =
                FakeNative(
                    listOf(dataChunk(0, obj("n", 1)), errorChunk(1, "SCP-OUTLET-6130", "handler panic")),
                )
            val handle = invoke(native)

            val ex = assertFailsWith<ScpException.Outlet> { handle.aggregate() }
            assertEquals("SCP-OUTLET-6130", ex.code)
            assertTrue(ex.msg.contains("handler panic"))
        }

    @Test
    fun `stream without End raises OutletProtocolException`() =
        runTest {
            val native = FakeNative(listOf(dataChunk(0, obj("n", 1))))
            val handle = invoke(native)
            assertFailsWith<OutletProtocolException> { handle.aggregate() }
        }

    @Test
    fun `caller did override is forwarded`() =
        runTest {
            val native = FakeNative(listOf(endChunk(0, obj("ok", 1))))
            val handle = invoke(native, callerDid = "did:dht:other")
            handle.aggregate()
            assertEquals("did:dht:other", native.openCalls[0].callerDid)
        }
}

// ---------------------------------------------------------------------------
// Shared-drain: the three directions + concurrent guard (the critical mirror).
// ---------------------------------------------------------------------------

class SharedDrainTest {
    @Test
    fun `collect then aggregate returns the cached aggregate without re-draining`() =
        runTest {
            val chunks = (0 until 10).map { dataChunk(it.toLong(), obj("n", it)) } + endChunk(10, obj("total", 10))
            val native = FakeNative(chunks)
            val handle = invoke(native)

            val collected = handle.asFlow().toList()
            assertEquals(11, collected.size)
            assertEquals(10, collected.count { it.kind == "data" })

            // Direction 1: aggregate() returns the CACHED End (stream opened once).
            val result = handle.aggregate()
            assertEquals(buildJsonObject { put("total", 10) }, result.value)
            assertEquals(1, native.openCalls.size)
        }

    @Test
    fun `aggregate then collect emits nothing`() =
        runTest {
            val native = FakeNative(listOf(dataChunk(0, obj("n", 0)), endChunk(1, obj("total", 1))))
            val handle = invoke(native)

            handle.aggregate()

            // Direction 2: the shared drain is already at its terminal.
            val second = handle.asFlow().toList()
            assertTrue(second.isEmpty())
        }

    @Test
    fun `partial collect then aggregate drains the remainder`() =
        runTest {
            val chunks =
                listOf(
                    dataChunk(0, obj("n", 0)),
                    dataChunk(1, obj("n", 1)),
                    dataChunk(2, obj("n", 2)),
                    endChunk(3, obj("total", 3)),
                )
            val native = FakeNative(chunks)
            val handle = invoke(native)

            // Take only the first two chunks off the shared drain.
            val prefix = handle.asFlow().take(2).toList()
            assertEquals(listOf(0L, 1L), prefix.map { it.sequence })

            // Direction 3: aggregate() drains the REMAINING chunks to the terminal.
            val result = handle.aggregate()
            assertEquals(buildJsonObject { put("total", 3) }, result.value)
            assertEquals(1, native.openCalls.size)
        }

    @Test
    fun `second concurrent collector on the shared drain fails loud`() =
        runTest {
            val gate = CompletableDeferred<Unit>()
            val native =
                GatedFakeNative(
                    listOf(dataChunk(0, obj("n", 0)), dataChunk(1, obj("n", 1)), endChunk(2, obj("n", 1))),
                    gate,
                )
            val handle = invoke(native)

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
// Control plane: grantCredit / cancel.
// ---------------------------------------------------------------------------

class ControlPlaneTest {
    @Test
    fun `grantCredit forwards the credit magnitude to the bridge`() =
        runTest {
            val native =
                FakeNative(listOf(dataChunk(0, obj("n", 0)), dataChunk(1, obj("n", 1)), endChunk(2, obj("n", 1))))
            val handle = invoke(native)

            handle.grantCredit(Credit(4u))

            assertEquals(listOf(Triple("stream-1", CALLER, 4u)), native.grantCalls)
        }

    @Test
    fun `grantCredit mid-stream reaches the bridge and the stream continues`() =
        runTest {
            val chunks = (0 until 4).map { dataChunk(it.toLong(), obj("n", it)) } + endChunk(4, obj("total", 4))
            val native = FakeNative(chunks)
            val handle = invoke(native)

            var seen = 0
            handle.asFlow().collect { _ ->
                seen++
                if (seen == 2) handle.grantCredit(Credit(8u))
            }
            assertEquals(listOf(Triple("stream-1", CALLER, 8u)), native.grantCalls)
            assertEquals(5, seen)
        }

    @Test
    fun `cancel forwards to the bridge once opened`() =
        runTest {
            val native = FakeNative(listOf(dataChunk(0, obj("n", 0)), endChunk(1, obj("n", 0))))
            val handle = invoke(native)

            // Open the stream first (pull one chunk); cancel then signs at the bridge.
            handle.asFlow().take(1).toList()
            handle.cancel()

            assertEquals(listOf("stream-1" to CALLER), native.cancelCalls)
        }

    @Test
    fun `cancel mid-stream then a terminal still arrives`() =
        runTest {
            val chunks =
                listOf(dataChunk(0, obj("n", 0)), dataChunk(1, obj("n", 1)), endChunk(2, obj("cancelled", 1)))
            val native = FakeNative(chunks)
            val handle = invoke(native)

            var seen = 0
            handle.asFlow().collect { _ ->
                seen++
                if (seen == 1) handle.cancel()
            }
            assertEquals(listOf("stream-1" to CALLER), native.cancelCalls)
            assertEquals(3, seen)
        }

    @Test
    fun `grantCredit before open opens the stream`() =
        runTest {
            val native = FakeNative(listOf(endChunk(0, obj("n", 0))))
            val handle = invoke(native)
            handle.grantCredit(Credit(2u))
            assertEquals(1, native.openCalls.size)
            assertEquals(listOf(Triple("stream-1", CALLER, 2u)), native.grantCalls)
        }
}

// ---------------------------------------------------------------------------
// cancel() before first poll is a local no-op close (no stream open).
// ---------------------------------------------------------------------------

class CancelBeforeOpenTest {
    @Test
    fun `cancel before open does not open the stream and is a local close`() =
        runTest {
            val native = FakeNative(listOf(dataChunk(0, obj("n", 0)), endChunk(1, obj("n", 0))))
            val handle = invoke(native)

            handle.cancel()

            // No stream opened and no bridge cancel signed.
            assertTrue(native.openCalls.isEmpty())
            assertTrue(native.cancelCalls.isEmpty())
            // The handle is now closed: further control-plane calls are guarded.
            assertFailsWith<StreamAlreadyClosed> { handle.cancel() }
            assertFailsWith<StreamAlreadyClosed> { handle.grantCredit(Credit(1u)) }
        }
}

// ---------------------------------------------------------------------------
// Lifecycle guard: control plane after terminal raises StreamAlreadyClosed.
// ---------------------------------------------------------------------------

class LifecycleGuardTest {
    @Test
    fun `grantCredit after End raises StreamAlreadyClosed`() =
        runTest {
            val native = FakeNative(listOf(dataChunk(0, obj("n", 1)), endChunk(1, obj("n", 1))))
            val handle = invoke(native)
            handle.aggregate()
            assertFailsWith<StreamAlreadyClosed> { handle.grantCredit(Credit(10u)) }
            assertTrue(native.grantCalls.isEmpty())
        }

    @Test
    fun `cancel after End raises StreamAlreadyClosed`() =
        runTest {
            val native = FakeNative(listOf(endChunk(0, obj("n", 1))))
            val handle = invoke(native)
            handle.aggregate()
            assertFailsWith<StreamAlreadyClosed> { handle.cancel() }
            assertTrue(native.cancelCalls.isEmpty())
        }

    @Test
    fun `grantCredit after a terminal error chunk raises StreamAlreadyClosed`() =
        runTest {
            val native = FakeNative(listOf(errorChunk(0, "SCP-OUTLET-6130", "boom", terminal = true)))
            val handle = invoke(native)
            // Consume the terminal error chunk via iteration (observable, no throw).
            val collected = handle.asFlow().toList()
            assertEquals("error", collected.last().kind)
            assertFailsWith<StreamAlreadyClosed> { handle.grantCredit(Credit(10u)) }
        }
}

// ---------------------------------------------------------------------------
// Data-plane bridge rejections surface as their generated ScpException type.
// ---------------------------------------------------------------------------

class BridgeErrorTranslationTest {
    @Test
    fun `open UCAN denial surfaces as ScpException Permission on aggregate`() =
        runTest {
            val native =
                RaisingOpenNative(ScpException.Permission(msg = "authorization denied", code = "SCP-PERM-3001"))
            val handle = invoke(native)
            assertFailsWith<ScpException.Permission> { handle.aggregate() }
        }

    @Test
    fun `open schema violation surfaces as ScpException Validation on collect`() =
        runTest {
            val native = RaisingOpenNative(ScpException.Validation(msg = "input schema", code = "SCP-VALID-7001"))
            val handle = invoke(native)
            assertFailsWith<ScpException.Validation> { handle.asFlow().toList() }
        }

    @Test
    fun `open rejection also surfaces on grantCredit`() =
        runTest {
            val native = RaisingOpenNative(ScpException.Permission(msg = "denied", code = "SCP-PERM-3001"))
            val handle = invoke(native)
            assertFailsWith<ScpException.Permission> { handle.grantCredit(Credit(1u)) }
        }

    @Test
    fun `mid-drain poll rejection surfaces as its ScpException type`() =
        runTest {
            val native =
                RaisingPollNative(
                    listOf(dataChunk(0, obj("n", 0))),
                    ScpException.Context(msg = "no active stream", code = "SCP-CTX-2001"),
                    failAfter = 1,
                )
            val handle = invoke(native)
            assertFailsWith<ScpException.Context> { handle.asFlow().toList() }
        }
}

// ---------------------------------------------------------------------------
// Chunk parsing edge cases.
// ---------------------------------------------------------------------------

class ChunkParsingTest {
    @Test
    fun `malformed chunk raises ScpException Outlet`() {
        assertFailsWith<ScpException.Outlet> {
            OutletStreamChunk.fromBridgeBytes("not json".encodeToByteArray())
        }
    }

    @Test
    fun `hex-string request_id and sig are accepted`() {
        val raw =
            buildJsonObject {
                put("request_id", "aabb")
                put("sequence", 0)
                put(
                    "payload",
                    buildJsonObject {
                        put("@type", "data")
                        put("value", 1)
                    },
                )
                put("sig", "ccdd")
            }.toString().encodeToByteArray()
        val parsed = OutletStreamChunk.fromBridgeBytes(raw)
        assertEquals("aabb", parsed.requestId)
        assertEquals("ccdd", parsed.signature)
        assertEquals("data", parsed.kind)
    }
}

// ---------------------------------------------------------------------------
// AC6 conformance-vector smoke: each of the 7 cross-layer streaming vectors ->
// the SDK's expected terminal.
//
// IMPORTANT boundary — where the terminal comes from:
//
// - credit_stall and cancellation surface a terminal the BRIDGE delivers.
//   The mock plays a framework terminal (a terminal:true Error for the credit
//   stall; a cancel-ack End after the consumer cancels) and the SDK
//   faithfully surfaces outletStreamPollNext's terminal — the SDK cannot itself
//   stall an executor, so it does not synthesize these terminals.
// - ONLY sequence_gap requires ACTIVE SDK-side detection: the drain tracks the
//   expected sequence, detects the hole ITSELF, signs the cancel through the
//   bridge, and throws [StreamGap]. The mock feeds NO pre-baked cancel-ack for
//   that vector (that would be test-gaming) — the recorded cancel call proves
//   the SDK generated it.
// ---------------------------------------------------------------------------

class ConformanceVectorSmokeTest {
    @Test
    fun `vectors cover exactly the seven names`() {
        assertEquals(
            setOf(
                "non_streaming", "multi_chunk", "cancellation", "error_terminal",
                "error_recoverable", "sequence_gap", "credit_stall",
            ),
            VECTORS.keys,
        )
    }

    @Test
    fun `non_streaming reaches Ok with sum aggregate`() =
        runTest {
            val v = VECTORS.getValue("non_streaming")
            val result = invoke(FakeNative(vectorChunks(v))).aggregate()
            assertEquals(buildJsonObject { put("sum", 3) }, result.value)
            assertEquals(endAggregate(v), result.value)
        }

    @Test
    fun `multi_chunk reaches Ok with total aggregate and forwards the Progress chunk`() =
        runTest {
            // multi_chunk interleaves a non-billable Progress chunk (§5.4.5): the
            // SDK drain FORWARDS it (surfaced, not filtered), the monotonicity
            // cursor advances across it, and the stream still closes Ok.
            val v = VECTORS.getValue("multi_chunk")
            val handle = invoke(FakeNative(vectorChunks(v)))
            val collected = handle.asFlow().toList()
            assertTrue(collected.any { it.kind == "progress" }, "the Progress chunk is yielded")
            assertEquals("end", collected.last().kind)
            val result = handle.aggregate()
            assertEquals(buildJsonObject { put("total", 10) }, result.value)
            assertEquals(endAggregate(v), result.value)
        }

    @Test
    fun `error_recoverable yields non-terminal error then reaches Ok`() =
        runTest {
            val v = VECTORS.getValue("error_recoverable")
            val handle = invoke(FakeNative(vectorChunks(v)))
            val collected = handle.asFlow().toList()
            assertEquals(listOf("data", "error", "data", "data", "end"), collected.map { it.kind })
            val result = handle.aggregate()
            assertEquals(endAggregate(v), result.value)
        }

    @Test
    fun `error_terminal raises typed ScpException 6130`() =
        runTest {
            val v = VECTORS.getValue("error_terminal")
            assertEquals("SCP-OUTLET-6130", expectedErrorCode(v))
            val ex = assertFailsWith<ScpException.Outlet> { invoke(FakeNative(vectorChunks(v))).aggregate() }
            assertEquals("SCP-OUTLET-6130", ex.code)
        }

    @Test
    fun `credit_stall raises typed ScpException 6133 (bridge terminal)`() =
        runTest {
            val v = VECTORS.getValue("credit_stall")
            assertEquals("SCP-OUTLET-6133", expectedErrorCode(v))
            val ex = assertFailsWith<ScpException.Outlet> { invoke(FakeNative(vectorChunks(v))).aggregate() }
            assertEquals("SCP-OUTLET-6133", ex.code)
        }

    @Test
    fun `cancellation records cancel and reaches terminal`() =
        runTest {
            val v = VECTORS.getValue("cancellation")
            val native = FakeNative(vectorChunks(v))
            val handle = invoke(native)
            var idx = 0
            handle.asFlow().collect { _ ->
                if (idx == 1) handle.cancel()
                idx++
            }
            assertEquals(listOf("stream-1" to CALLER), native.cancelCalls)
            assertEquals(v["chunks"]!!.jsonArray.size, idx)
            val result = handle.aggregate()
            assertEquals(endAggregate(v), result.value)
        }

    @Test
    fun `sequence_gap detected signs cancel and raises StreamGap 6131`() =
        runTest {
            // ACTIVE SDK detection: mock plays data seq0, seq1, seq3 (seq2
            // MISSING). The drain detects the gap at seq3, itself signs a cancel
            // through the bridge, and throws StreamGap(6131). NO pre-baked
            // cancel-ack is fed.
            val v = VECTORS.getValue("sequence_gap")
            assertEquals("SCP-OUTLET-6131", expectedErrorCode(v))
            val native = FakeNative(vectorChunks(v))
            val handle = invoke(native)
            val ex = assertFailsWith<StreamGap> { handle.aggregate() }
            assertEquals("SCP-OUTLET-6131", ex.code)
            // The SDK ITSELF signed the receiver cancel (not fed by the mock).
            assertEquals(listOf("stream-1" to CALLER), native.cancelCalls)
            // Terminal cache: the gap is sticky and control-plane is now guarded.
            assertFailsWith<StreamGap> { handle.aggregate() }
            assertFailsWith<StreamAlreadyClosed> { handle.grantCredit(Credit(1u)) }
        }
}
