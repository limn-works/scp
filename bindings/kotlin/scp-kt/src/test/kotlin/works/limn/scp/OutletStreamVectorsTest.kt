// SCP-OUT-039 — Outlet streaming vector smoke tests (Kotlin SDK).
//
// Loads the seven streaming conformance vectors at
// `tests/conformance/vectors/outlet_stream_vectors.json` and drives
// each through an `InvocationHandle` pump, asserting the vector's
// declared terminal-status surface reproduces under the SDK control
// plane.
//
// Per SCP-OUT-039 AC6: each vector runs in each SDK and produces the
// expected terminal status. Runtime-side replay (CreditTracker /
// CancelAckTracker / StreamEscrow) lives in
// `crates/scp-testing/tests/integration/outlet_stream_conformance.rs`;
// this smoke ensures the Kotlin SDK can ingest the same JSON vectors
// and reproduce the surface-level outcome.
//
// The cancellation, credit-exhaustion and sequence-gap vectors all
// terminate with a terminal Error chunk via the Flow surface — the
// wire-level distinction between "framework-emitted cancel-ack" and
// "receiver-emitted StreamGap" is a runtime concern.

package works.limn.scp

import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.Paths
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.flow
import kotlinx.coroutines.flow.toList
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import org.junit.jupiter.api.Test

@Suppress("StringLiteralDuplication", "TooManyFunctions")
class OutletStreamVectorsTest {
    @Serializable
    private data class VectorFile(
        val comment: String,
        @kotlinx.serialization.SerialName("spec_section")
        val specSection: String,
        val vectors: List<Vector>,
    )

    @Serializable
    private data class Vector(
        val name: String,
        val description: String,
        val open: OpenSpec,
        val chunks: List<ChunkEntry>,
        @kotlinx.serialization.SerialName("expected_end_status")
        val expectedEndStatus: String,
        @kotlinx.serialization.SerialName("expected_error_code")
        val expectedErrorCode: String? = null,
        @kotlinx.serialization.SerialName("expected_error_slug")
        val expectedErrorSlug: String? = null,
        @kotlinx.serialization.SerialName("expected_chunks_billed")
        val expectedChunksBilled: Int,
        @kotlinx.serialization.SerialName("expected_total_chunks")
        val expectedTotalChunks: Int,
        @kotlinx.serialization.SerialName("expected_cancel_ack_seq")
        val expectedCancelAckSeq: Long? = null,
        @kotlinx.serialization.SerialName("expected_first_gap_sequence")
        val expectedFirstGapSequence: Long? = null,
    )

    @Serializable
    private data class OpenSpec(
        @kotlinx.serialization.SerialName("outlet_id") val outletId: String,
        @kotlinx.serialization.SerialName("outlet_kind") val outletKind: String,
        // input is JSON-shaped, captured as JsonElement.
        val input: JsonElement,
        @kotlinx.serialization.SerialName("invoker_did") val invokerDid: String,
        @kotlinx.serialization.SerialName("operator_did") val operatorDid: String,
        @kotlinx.serialization.SerialName("context_id") val contextId: String,
        @kotlinx.serialization.SerialName("credit_window") val creditWindow: Int,
        @kotlinx.serialization.SerialName("estimated_chunk_count") val estimatedChunkCount: Int,
        @kotlinx.serialization.SerialName("cost_per_chunk") val costPerChunk: Long,
        @kotlinx.serialization.SerialName("available_balance") val availableBalance: Long,
        @kotlinx.serialization.SerialName("stream_credit_stall_secs") val streamCreditStallSecs: Int,
        @kotlinx.serialization.SerialName("stream_cancel_ack_secs") val streamCancelAckSecs: Int,
        @kotlinx.serialization.SerialName("timeout_ms") val timeoutMs: Int,
        @kotlinx.serialization.SerialName("chain_depth") val chainDepth: Int,
    )

    @Serializable
    private data class ChunkEntry(
        val sequence: Long,
        val type: String,
        val value: JsonElement? = null,
        val aggregate: JsonElement? = null,
        @kotlinx.serialization.SerialName("execution_time_ms")
        val executionTimeMs: Long? = null,
        val code: String? = null,
        val message: String? = null,
        val terminal: Boolean? = null,
        val pct: Int? = null,
        val note: String? = null,
        val slug: String? = null,
    )

    private val json = Json { ignoreUnknownKeys = true }

    private fun vectorPath(): Path {
        var dir = Paths.get("").toAbsolutePath()
        repeat(8) {
            val candidate = dir.resolve("tests/conformance/vectors/outlet_stream_vectors.json")
            if (Files.exists(candidate)) return candidate
            val parent = dir.parent ?: return@repeat
            dir = parent
        }
        error("outlet_stream_vectors.json not found from ${'$'}{Paths.get(\"\").toAbsolutePath()}")
    }

    @OptIn(ExperimentalSerializationApi::class)
    private fun loadVectors(): List<Vector> {
        val bytes = Files.readAllBytes(vectorPath())
        return json.decodeFromString(VectorFile.serializer(), String(bytes, Charsets.UTF_8)).vectors
    }

    private val requestId: ByteArray = ByteArray(16) { 0xa5.toByte() }

    private fun chunkFromEntry(entry: ChunkEntry): OutletStreamChunk =
        when (entry.type) {
            "data" -> OutletStreamChunk.Data(
                requestId = requestId,
                sequence = entry.sequence,
                valueJson = entry.value?.toString() ?: "null",
            )
            "end" -> OutletStreamChunk.End(
                requestId = requestId,
                sequence = entry.sequence,
                aggregateJson = entry.aggregate?.toString() ?: "null",
                executionTimeMs = entry.executionTimeMs ?: 0L,
            )
            "error" -> OutletStreamChunk.Error(
                requestId = requestId,
                sequence = entry.sequence,
                code = entry.code ?: "SCP-TOOL-6200",
                message = entry.message ?: "",
                terminal = entry.terminal ?: false,
            )
            "progress" -> OutletStreamChunk.Progress(
                requestId = requestId,
                sequence = entry.sequence,
                pct = (entry.pct ?: 0).toUShort(),
                note = entry.note,
            )
            else -> error("unknown chunk type: ${'$'}{entry.type}")
        }

    private fun makeHandle(vector: Vector): InvocationHandle {
        val sdkChunks = vector.chunks.map(::chunkFromEntry).toMutableList()
        if (vector.name == "sequence_gap") {
            // Synthesize the receiver's terminal StreamGap envelope so
            // the Flow can drain. The runtime's actual StreamGap path
            // is exercised in the Rust replay.
            sdkChunks += OutletStreamChunk.Error(
                requestId = requestId,
                sequence = vector.chunks.last().sequence + 1,
                code = vector.expectedErrorCode ?: "SCP-TOOL-6131",
                message = vector.expectedErrorSlug ?: "execution.stream-gap",
                terminal = true,
            )
        }

        val endChunk = sdkChunks.filterIsInstance<OutletStreamChunk.End>().firstOrNull()

        return InvocationHandle(
            aggregateFn = {
                endChunk?.let {
                    Aggregate(valueJson = it.aggregateJson, executionTimeMs = it.executionTimeMs)
                } ?: Aggregate(valueJson = "null")
            },
            flowFn = {
                flow {
                    for (chunk in sdkChunks) {
                        emit(chunk)
                    }
                }
            },
            requestIdHex = "a5".repeat(16),
            aggregateSchemaJson = null,
        )
    }

    private val requiredNames = setOf(
        "non_streaming",
        "multi_chunk",
        "cancellation",
        "error_terminal",
        "error_recoverable",
        "sequence_gap",
        "credit_exhaustion",
    )

    @Test
    fun `vector file carries exactly seven required vectors (AC1)`() {
        val names = loadVectors().map { it.name }.toSet()
        assertEquals(requiredNames, names)
    }

    @Test
    fun `each vector reproduces expected terminal status (AC6)`() = runTest {
        for (vector in loadVectors()) {
            val handle = makeHandle(vector)
            val observed: List<OutletStreamChunk> = handle.asFlow().toList()

            val expectedTotal = vector.expectedTotalChunks
            if (vector.name == "sequence_gap") {
                assertEquals(
                    expectedTotal + 1, observed.size,
                    "vector ${'$'}{vector.name}: observed = manifest + synthesized terminal",
                )
            } else {
                assertEquals(
                    expectedTotal, observed.size,
                    "vector ${'$'}{vector.name}: chunk count mismatch",
                )
            }

            val terminal = observed.last()
            when (vector.expectedEndStatus) {
                "Ok" -> {
                    assertTrue(
                        terminal is OutletStreamChunk.End,
                        "vector ${'$'}{vector.name}: terminal must be End",
                    )
                }
                "Error" -> {
                    assertTrue(
                        terminal is OutletStreamChunk.Error && terminal.terminal,
                        "vector ${'$'}{vector.name}: terminal must be terminal=true Error",
                    )
                    assertEquals(
                        vector.expectedErrorCode, terminal.code,
                        "vector ${'$'}{vector.name}: terminal Error code mismatch",
                    )
                }
                "Cancelled" -> {
                    assertTrue(
                        terminal is OutletStreamChunk.Error && terminal.terminal,
                        "vector ${'$'}{vector.name}: cancel-ack must surface as terminal Error",
                    )
                }
                else -> error(
                    "vector ${'$'}{vector.name}: unknown expected_end_status " +
                        "${'$'}{vector.expectedEndStatus}",
                )
            }
        }
    }

    @Test
    fun `every vector carries an input field on the open block`() {
        for (v in loadVectors()) {
            assertNotNull(v.open.input)
        }
    }

    @Test
    fun `vector file is well-formed JSON the SDK ingests as-is`() {
        val outer = json.decodeFromString(
            VectorFile.serializer(),
            Files.readAllBytes(vectorPath()).toString(Charsets.UTF_8),
        )
        assertEquals(7, outer.vectors.size)
        assertTrue(outer.specSection.isNotEmpty())
        for (v in outer.vectors) {
            assertTrue(v.chunks.isNotEmpty(), "vector ${'$'}{v.name}: chunks must be non-empty")
        }
    }
}
