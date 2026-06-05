// SCP-OUT-038 — production OutletNamespace control-plane tests.
//
// These tests exercise the PRODUCTION streaming-handle assembly path
// (`buildStreamingInvocationHandle`, the helper the production
// `BridgeBackedOutletNamespace.makeStreamingHandle` delegates to) — NOT
// a directly-constructed `InvocationHandle`. They drive the seam with a
// fake stream cursor and fake control-plane functions so the full
// production control plane is validated without the compiled UniFFI
// `ContextHandle` / `Identity`:
//
//   * `grantCredit` / `cancel` await the deferred `request_id` resolved
//     by the open, then reach the injected control-plane functions with
//     the runtime `request_id` + pinned invoker DID — closing the OUT-038
//     production bug where the handle never received the `request_id` and
//     the control plane was unreachable in production.
//   * an open FAILURE resolves the deferred to `null`, so the control
//     plane surfaces `StreamAlreadyClosed` rather than hanging.
//   * the receiver-side revocation re-check teardown (`stopRecheck`) runs
//     once the stream is consumed.

package works.limn.scp

import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.flow.toList
import kotlinx.coroutines.test.runTest
import org.junit.jupiter.api.Test
import java.util.concurrent.atomic.AtomicBoolean
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

@Suppress("StringLiteralDuplication")
class BridgeBackedOutletNamespaceStreamingTest {
    private val invokerDid = "did:dht:invoker"

    private fun endSource(
        seq: ULong = 0UL,
        aggregate: String = "{\"sum\":45}",
    ): StreamChunkSource =
        StreamChunkSource(
            requestId = ByteArray(16),
            sequence = seq,
            sig = ByteArray(64),
            payloadType = "end",
            valueJson = null,
            pct = null,
            note = null,
            aggregateJson = aggregate,
            provenanceJson = null,
            executionTimeMs = 7UL,
            code = null,
            message = null,
            terminal = null,
        )

    /** Fake cursor yielding a fixed chunk sequence then `null`. */
    private class FakeCursor(
        private val requestIdHex: String,
        chunks: List<StreamChunkSource>,
    ) : OutletStreamCursor {
        private val iterator = chunks.iterator()

        override fun requestId(): String = requestIdHex

        override suspend fun next(): StreamChunkSource? = if (iterator.hasNext()) iterator.next() else null
    }

    /** Records the control-plane args the handle reaches the bridge with. */
    private class ControlPlaneRecorder {
        var grantRid: String? = null
        var grantDid: String? = null
        var grantAmount: UInt? = null
        var cancelRid: String? = null
        var cancelDid: String? = null

        val grant: suspend (String, String, UInt) -> UInt = { rid, did, amt ->
            grantRid = rid
            grantDid = did
            grantAmount = amt
            amt
        }
        val cancel: suspend (String, String) -> ULong? = { rid, did ->
            cancelRid = rid
            cancelDid = did
            0UL
        }
    }

    @Test
    fun `grantCredit reaches the bridge with resolved request_id and pinned DID`() =
        runTest {
            val rid = "a5".repeat(16)
            val recorder = ControlPlaneRecorder()
            // The streaming open resolves the deferred to the runtime
            // request_id (mirrors StreamOpener.open() calling
            // `requestIdDeferred.complete(cursor.requestId())`). The control
            // plane awaits this deferred before routing to the bridge.
            val requestIdDeferred = CompletableDeferred<String?>().apply { complete(rid) }

            val handle =
                buildStreamingInvocationHandle(
                    open = { FakeCursor(rid, listOf(endSource())) },
                    stopRecheck = {},
                    requestIdDeferred = requestIdDeferred,
                    invokerDid = invokerDid,
                    aggregateSchemaJson = null,
                    grantCreditFn = recorder.grant,
                    cancelFn = recorder.cancel,
                )

            val granted = handle.grantCredit(Credit(12u))
            assertEquals(12u, granted)
            assertEquals(rid, recorder.grantRid)
            assertEquals(invokerDid, recorder.grantDid)
            assertEquals(12u, recorder.grantAmount)
        }

    @Test
    fun `cancel reaches the bridge with resolved request_id and pinned DID`() =
        runTest {
            val rid = "b6".repeat(16)
            val recorder = ControlPlaneRecorder()
            val requestIdDeferred = CompletableDeferred<String?>().apply { complete(rid) }

            val handle =
                buildStreamingInvocationHandle(
                    open = { FakeCursor(rid, listOf(endSource())) },
                    stopRecheck = {},
                    requestIdDeferred = requestIdDeferred,
                    invokerDid = invokerDid,
                    aggregateSchemaJson = null,
                    grantCreditFn = recorder.grant,
                    cancelFn = recorder.cancel,
                )

            val seq = handle.cancel()
            assertEquals(0UL, seq)
            assertEquals(rid, recorder.cancelRid)
            assertEquals(invokerDid, recorder.cancelDid)
        }

    @Test
    fun `open failure resolves request_id to null and control plane surfaces StreamAlreadyClosed`() =
        runTest {
            val recorder = ControlPlaneRecorder()
            // Mirror StreamOpener's catch arm: open failed before a
            // request_id was known, so the deferred resolves to `null`.
            val requestIdDeferred = CompletableDeferred<String?>().apply { complete(null) }

            val handle =
                buildStreamingInvocationHandle(
                    open = { error("open failed") },
                    stopRecheck = {},
                    requestIdDeferred = requestIdDeferred,
                    invokerDid = invokerDid,
                    aggregateSchemaJson = null,
                    grantCreditFn = recorder.grant,
                    cancelFn = recorder.cancel,
                )

            assertFailsWith<StreamAlreadyClosed> { handle.grantCredit(Credit(5u)) }
            assertFailsWith<StreamAlreadyClosed> { handle.cancel() }
            // The control-plane bridge functions were never reached.
            assertEquals(null, recorder.grantRid)
            assertEquals(null, recorder.cancelRid)
        }

    @Test
    fun `consuming the stream tears down the recheck loop and yields the End aggregate`() =
        runTest {
            val rid = "c7".repeat(16)
            val recorder = ControlPlaneRecorder()
            val requestIdDeferred = CompletableDeferred<String?>()
            val recheckStopped = AtomicBoolean(false)

            val handle =
                buildStreamingInvocationHandle(
                    open = {
                        requestIdDeferred.complete(rid)
                        FakeCursor(rid, listOf(endSource(aggregate = "{\"v\":1}")))
                    },
                    stopRecheck = { recheckStopped.set(true) },
                    requestIdDeferred = requestIdDeferred,
                    invokerDid = invokerDid,
                    aggregateSchemaJson = null,
                    grantCreditFn = recorder.grant,
                    cancelFn = recorder.cancel,
                )

            val agg = handle.aggregate()
            assertEquals("{\"v\":1}", agg.valueJson)
            assertTrue(recheckStopped.get(), "stopRecheck must run when the stream is consumed")

            // After terminal consumption the control plane fail-closes.
            assertFailsWith<StreamAlreadyClosed> { handle.grantCredit(Credit(1u)) }
        }

    @Test
    fun `flow consumption yields End chunk and tears down recheck`() =
        runTest {
            val rid = "d8".repeat(16)
            val recorder = ControlPlaneRecorder()
            val requestIdDeferred = CompletableDeferred<String?>()
            val recheckStopped = AtomicBoolean(false)

            val handle =
                buildStreamingInvocationHandle(
                    open = {
                        requestIdDeferred.complete(rid)
                        FakeCursor(rid, listOf(endSource()))
                    },
                    stopRecheck = { recheckStopped.set(true) },
                    requestIdDeferred = requestIdDeferred,
                    invokerDid = invokerDid,
                    aggregateSchemaJson = null,
                    grantCreditFn = recorder.grant,
                    cancelFn = recorder.cancel,
                )

            val chunks = handle.asFlow().toList()
            assertEquals(1, chunks.size)
            assertTrue(chunks[0] is OutletStreamChunk.End)
            assertTrue(recheckStopped.get(), "stopRecheck must run after flow collection")
        }
}
