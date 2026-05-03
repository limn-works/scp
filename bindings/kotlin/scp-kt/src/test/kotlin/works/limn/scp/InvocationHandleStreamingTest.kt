// SCP-OUT-038 — Kotlin SDK InvocationHandle integration tests.
//
// Covers AC9-AC18 of the SDK control-plane story:
//
// - AC9: handle exposes suspend fun aggregate() AND fun asFlow();
//   suspend grantCredit(grant: Credit) and cancel() control-plane
//   methods.
// - AC10: Credit constructor rejects 0u with InvalidGrant; Kotlin
//   compiler rejects raw UInt where Credit is expected (compile-time
//   only — documented but not asserted at runtime).
// - AC13: StreamAlreadyClosed sits at OutletProtocolError depth.
// - AC14: 10 Data + End -> Flow yields 11 chunks.
// - AC17: post-End grantCredit / cancel raise StreamAlreadyClosed.
// - AC18: post-Error{terminal:true} grantCredit raises StreamAlreadyClosed.
//
// The tests drive an `InvocationHandle` directly via the constructor
// so the SDK-level lifecycle is exercised without depending on the
// UniFFI-generated bindings (regenerated in CI).

package works.limn.scp

import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.flow
import kotlinx.coroutines.flow.toList
import kotlinx.coroutines.test.runTest
import org.junit.jupiter.api.Test

@Suppress("StringLiteralDuplication")
class InvocationHandleStreamingTest {

    // --------------------------------------------------------------------
    // Helpers — synthetic chunk pumps
    // --------------------------------------------------------------------

    private fun dataChunk(seq: Long, value: String = "{\"x\":1}"): OutletStreamChunk =
        OutletStreamChunk.Data(
            requestId = ByteArray(16),
            sequence = seq,
            valueJson = value,
        )

    private fun endChunk(
        seq: Long,
        aggregate: String = "{\"sum\":45}",
        executionTimeMs: Long = 42L,
    ): OutletStreamChunk = OutletStreamChunk.End(
        requestId = ByteArray(16),
        sequence = seq,
        aggregateJson = aggregate,
        executionTimeMs = executionTimeMs,
    )

    private fun errorChunk(
        seq: Long,
        terminal: Boolean,
        code: String = "SCP-TOOL-6131",
        message: String = "synthetic error",
    ): OutletStreamChunk = OutletStreamChunk.Error(
        requestId = ByteArray(16),
        sequence = seq,
        code = code,
        message = message,
        terminal = terminal,
    )

    private fun makeHandle(
        chunks: List<OutletStreamChunk>,
        requestIdHex: String? = "aa".repeat(16),
        aggregateSchemaJson: String? = null,
    ): InvocationHandle {
        val agg = chunks.filterIsInstance<OutletStreamChunk.End>().firstOrNull()
        return InvocationHandle(
            aggregateFn = {
                agg?.let { Aggregate(valueJson = it.aggregateJson, executionTimeMs = it.executionTimeMs) }
                    ?: Aggregate(valueJson = "null")
            },
            flowFn = {
                flow {
                    for (chunk in chunks) {
                        emit(chunk)
                    }
                }
            },
            requestIdHex = requestIdHex,
            aggregateSchemaJson = aggregateSchemaJson,
        )
    }

    // --------------------------------------------------------------------
    // AC10 — Credit construction
    // --------------------------------------------------------------------

    @Test
    fun `Credit(0u) throws InvalidGrant`() {
        assertFailsWith<InvalidGrant> {
            Credit(0u)
        }
    }

    @Test
    fun `Credit(1u) succeeds (min)`() {
        val credit = Credit(1u)
        assertEquals(1u, credit.raw)
    }

    @Test
    fun `Credit(UInt MAX_VALUE) succeeds (max)`() {
        val credit = Credit(UInt.MAX_VALUE)
        assertEquals(UInt.MAX_VALUE, credit.raw)
    }

    @Test
    fun `creditOf back-compat factory delegates to Credit constructor`() {
        assertFailsWith<InvalidGrant> {
            creditOf(0u)
        }
        assertEquals(7u, creditOf(7u).raw)
    }

    // --------------------------------------------------------------------
    // AC13 — StreamAlreadyClosed depth
    // --------------------------------------------------------------------

    @Test
    fun `StreamAlreadyClosed isInstance of OutletProtocolError`() {
        val err = StreamAlreadyClosed()
        assertTrue(err is OutletProtocolError)
        assertTrue(err is OutletError)
        assertEquals(OutletErrorClass.PROTOCOL, err.classWire)
        assertEquals("SCP-TOOL-6102", err.code)
        assertEquals("protocol.stream-already-closed", err.slug)
    }

    @Test
    fun `StreamAlreadyClosed default message is set`() {
        val err = StreamAlreadyClosed()
        assertTrue(err.message?.contains("already terminated") == true)
    }

    @Test
    fun `StreamAlreadyClosed custom message overrides default`() {
        val err = StreamAlreadyClosed("custom-reason")
        assertEquals("custom-reason", err.message)
    }

    // --------------------------------------------------------------------
    // AC14 — 10 Data + End => 11 chunks observed
    // --------------------------------------------------------------------

    @Test
    fun `flow yields 11 chunks for 10 Data + End`() = runTest {
        val chunks = (0L until 10L).map { dataChunk(it) } + endChunk(10L)
        val handle = makeHandle(chunks)
        val observed = handle.asFlow().toList()
        assertEquals(11, observed.size)
        for (i in 0 until 10) {
            assertTrue(observed[i] is OutletStreamChunk.Data, "chunk $i should be Data")
        }
        assertTrue(observed[10] is OutletStreamChunk.End)
    }

    @Test
    fun `aggregate returns End aggregate`() = runTest {
        val chunks = listOf(
            dataChunk(0),
            endChunk(1, aggregate = "{\"v\":99}", executionTimeMs = 10L),
        )
        val handle = makeHandle(chunks)
        val agg = handle.aggregate()
        assertEquals("{\"v\":99}", agg.valueJson)
        assertEquals(10L, agg.executionTimeMs)
        assertTrue(handle.isTerminated)
    }

    // --------------------------------------------------------------------
    // AC17 / AC18 — post-terminal lifecycle guard
    // --------------------------------------------------------------------

    @Test
    fun `grantCredit after End raises StreamAlreadyClosed`() = runTest {
        val handle = makeHandle(listOf(endChunk(0L)))
        // Drain flow so End is observed.
        handle.asFlow().toList()
        assertTrue(handle.isTerminated)
        assertFailsWith<StreamAlreadyClosed> {
            handle.grantCredit(Credit(10u))
        }
    }

    @Test
    fun `cancel after End raises StreamAlreadyClosed`() = runTest {
        val handle = makeHandle(listOf(endChunk(0L)))
        handle.asFlow().toList()
        assertFailsWith<StreamAlreadyClosed> {
            handle.cancel()
        }
    }

    @Test
    fun `grantCredit after terminal Error raises StreamAlreadyClosed`() = runTest {
        // AC18 — Error{terminal:true} closes the stream; subsequent
        // grantCredit raises StreamAlreadyClosed.
        val handle = makeHandle(listOf(errorChunk(0L, terminal = true)))
        handle.asFlow().toList()
        assertTrue(handle.isTerminated)
        assertFailsWith<StreamAlreadyClosed> {
            handle.grantCredit(Credit(10u))
        }
    }

    @Test
    fun `aggregate await marks handle terminated`() = runTest {
        val handle = makeHandle(listOf(endChunk(0L, aggregate = "{\"ok\":true}")))
        assertFalse(handle.isTerminated)
        handle.aggregate()
        assertTrue(handle.isTerminated)
        assertFailsWith<StreamAlreadyClosed> {
            handle.grantCredit(Credit(10u))
        }
    }

    // --------------------------------------------------------------------
    // Non-streaming handle: requestIdHex == null is pre-terminated.
    // --------------------------------------------------------------------

    @Test
    fun `grantCredit on non-streaming handle raises StreamAlreadyClosed`() = runTest {
        val handle = makeHandle(
            chunks = listOf(endChunk(0L)),
            requestIdHex = null,
        )
        assertFailsWith<StreamAlreadyClosed> {
            handle.grantCredit(Credit(10u))
        }
    }

    @Test
    fun `cancel on non-streaming handle raises StreamAlreadyClosed`() = runTest {
        val handle = makeHandle(
            chunks = listOf(endChunk(0L)),
            requestIdHex = null,
        )
        assertFailsWith<StreamAlreadyClosed> {
            handle.cancel()
        }
    }

    // --------------------------------------------------------------------
    // AC12 — aggregate_schema validation
    // --------------------------------------------------------------------

    @Test
    fun `aggregate validates against schema (matching)`() = runTest {
        val schema = "{\"type\":\"object\",\"required\":[\"sum\"]}"
        val handle = makeHandle(
            chunks = listOf(endChunk(0L, aggregate = "{\"sum\":42}")),
            aggregateSchemaJson = schema,
        )
        val agg = handle.aggregate()
        assertEquals("{\"sum\":42}", agg.valueJson)
    }

    @Test
    fun `aggregate validates against schema (missing required field)`() = runTest {
        val schema = "{\"type\":\"object\",\"required\":[\"sum\"]}"
        val handle = makeHandle(
            chunks = listOf(endChunk(0L, aggregate = "{\"wrong\":1}")),
            aggregateSchemaJson = schema,
        )
        val err = assertFailsWith<OutletProtocolError> {
            handle.aggregate()
        }
        assertEquals("SCP-TOOL-6140", err.code)
        assertTrue(err.message?.contains("required field") == true)
    }

    @Test
    fun `aggregate validates against schema (type mismatch)`() = runTest {
        val schema = "{\"type\":\"object\"}"
        val handle = makeHandle(
            chunks = listOf(endChunk(0L, aggregate = "42")),
            aggregateSchemaJson = schema,
        )
        val err = assertFailsWith<OutletProtocolError> {
            handle.aggregate()
        }
        assertEquals("SCP-TOOL-6140", err.code)
    }

    // --------------------------------------------------------------------
    // Compile-time documentation — Credit is REQUIRED for grantCredit.
    // --------------------------------------------------------------------
    //
    // The Kotlin compiler rejects `handle.grantCredit(10u)` because
    // `UInt` is not assignable to `Credit`. The block below is never
    // executed; it documents the AC10 compile-time invariant.

    @Suppress("unused", "UnusedPrivateMember")
    private suspend fun _kotlinCompilerRejectsRawUIntForGrantCredit(handle: InvocationHandle) {
        // Valid call: typed Credit is accepted.
        handle.grantCredit(Credit(10u))
        // Invalid call: raw UInt is NOT a Credit. Uncommenting the line
        // below would fail to compile with:
        //   "Type mismatch: inferred type is UInt but Credit was expected"
        // handle.grantCredit(10u)
    }

    /** Drain a flow into a list — local helper kept as @Suppress dummy so
     * the imported [Flow] reference stays meaningful. */
    @Suppress("unused", "UnusedPrivateMember")
    private suspend fun <T> drainFlow(flow: Flow<T>): List<T> = flow.toList()
}
