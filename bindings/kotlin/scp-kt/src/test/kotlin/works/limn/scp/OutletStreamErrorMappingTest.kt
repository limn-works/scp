// Cross-SDK error-mapping consistency guards for the outlet streaming
// control plane and terminal-error fallback.
//
//   * A terminal Error chunk that carries NO code surfaces as the
//     `SCP-TOOL-6200` fallback via BOTH the aggregate path
//     (`drainToAggregate`) and the cold-flow path (`toSdkChunk`). The
//     two paths must agree — and agree with the Python / TypeScript /
//     Swift SDKs, which all use `SCP-TOOL-6200` for this fallback.
//   * A post-race control-plane call (`grantCredit` / `cancel`) that the
//     runtime rejects with `SCP-TOOL-6101` (slug
//     `protocol.stream-already-closed`) surfaces as the typed
//     `StreamAlreadyClosed`, matching the SDK's own local-terminal
//     `StreamAlreadyClosed` and the Python `_translate_bridge_error`.
//
// Both are driven through the production `buildStreamingInvocationHandle`
// seam with an injectable fake cursor + injectable control-plane
// functions, so the real mapping runs without the compiled UniFFI cdylib.

package works.limn.scp

import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.flow.toList
import kotlinx.coroutines.test.runTest
import org.junit.jupiter.api.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

@Suppress("StringLiteralDuplication")
class OutletStreamErrorMappingTest {
    private val invokerDid = "did:dht:invoker"

    /** A terminal Error chunk with NO `code` — exercises the fallback. */
    private fun terminalErrorNoCode(seq: ULong = 0UL): StreamChunkSource =
        StreamChunkSource(
            requestId = ByteArray(16),
            sequence = seq,
            sig = ByteArray(64),
            payloadType = "error",
            valueJson = null,
            pct = null,
            note = null,
            aggregateJson = null,
            provenanceJson = null,
            executionTimeMs = null,
            code = null,
            message = "executor failed without a code",
            terminal = true,
        )

    private class FakeCursor(
        private val requestIdHex: String,
        chunks: List<StreamChunkSource>,
    ) : OutletStreamCursor {
        private val iterator = chunks.iterator()

        override fun requestId(): String = requestIdHex

        override suspend fun next(): StreamChunkSource? =
            if (iterator.hasNext()) iterator.next() else null
    }

    /** Inert control-plane recorder used when the test only drains chunks. */
    private val inertGrant: suspend (String, String, UInt) -> UInt = { _, _, amt -> amt }
    private val inertCancel: suspend (String, String) -> ULong? = { _, _ -> 0UL }

    private fun handleFor(
        rid: String,
        chunks: List<StreamChunkSource>,
        grantCreditFn: suspend (String, String, UInt) -> UInt = inertGrant,
        cancelFn: suspend (String, String) -> ULong? = inertCancel,
    ): InvocationHandle {
        val requestIdDeferred = CompletableDeferred<String?>().apply { complete(rid) }
        return buildStreamingInvocationHandle(
            open = { FakeCursor(rid, chunks) },
            stopRecheck = {},
            requestIdDeferred = requestIdDeferred,
            invokerDid = invokerDid,
            aggregateSchemaJson = null,
            grantCreditFn = grantCreditFn,
            cancelFn = cancelFn,
        )
    }

    // --------------------------------------------------------------------
    // Finding 1 — no-code terminal Error falls back to SCP-TOOL-6200 on
    // BOTH the aggregate path and the flow path.
    // --------------------------------------------------------------------

    @Test
    fun `aggregate path maps a no-code terminal Error to SCP-TOOL-6200`() =
        runTest {
            val handle = handleFor("a5".repeat(16), listOf(terminalErrorNoCode()))
            val err = assertFailsWith<ExecutionError> { handle.aggregate() }
            assertEquals(
                "SCP-TOOL-6200",
                err.code,
                "aggregate-path fallback must match the flow path and the other SDKs",
            )
        }

    @Test
    fun `flow path maps a no-code terminal Error to SCP-TOOL-6200`() =
        runTest {
            val handle = handleFor("b6".repeat(16), listOf(terminalErrorNoCode()))
            val chunks = handle.asFlow().toList()
            assertEquals(1, chunks.size)
            val errorChunk = chunks[0]
            assertTrue(errorChunk is OutletStreamChunk.Error)
            assertEquals(
                "SCP-TOOL-6200",
                errorChunk.code,
                "flow-path fallback must match the aggregate path and the other SDKs",
            )
        }

    // --------------------------------------------------------------------
    // Finding 2 — a runtime SCP-TOOL-6101 rejection from the control-plane
    // bridge call surfaces as the typed StreamAlreadyClosed.
    // --------------------------------------------------------------------

    @Test
    fun `grantCredit maps a bridge SCP-TOOL-6101 rejection to StreamAlreadyClosed`() =
        runTest {
            // The runtime lost the race: the SDK's local terminal flag is
            // still false (the handle never observed a terminal chunk), so
            // preflight passes and the bridge is reached — then the runtime
            // rejects with the authoritative 6101 `ScpException.Context`.
            val rejecting6101: suspend (String, String, UInt) -> UInt = { _, _, _ ->
                throw uniffi.scp.ScpException.Context(
                    msg = "credit grant rejected (protocol.stream-already-closed)",
                    code = "SCP-TOOL-6101",
                )
            }
            // No terminal chunk in the cursor, so preflight does not
            // short-circuit on the local terminal flag.
            val handle = handleFor("c7".repeat(16), emptyList(), grantCreditFn = rejecting6101)
            assertFailsWith<StreamAlreadyClosed> { handle.grantCredit(Credit(10u)) }
        }

    @Test
    fun `cancel maps a bridge SCP-TOOL-6101 rejection to StreamAlreadyClosed`() =
        runTest {
            val rejecting6101: suspend (String, String) -> ULong? = { _, _ ->
                throw uniffi.scp.ScpException.Context(
                    msg = "cancel rejected (protocol.stream-already-closed)",
                    code = "SCP-TOOL-6101",
                )
            }
            val handle = handleFor("d8".repeat(16), emptyList(), cancelFn = rejecting6101)
            assertFailsWith<StreamAlreadyClosed> { handle.cancel() }
        }

    @Test
    fun `control-plane maps a 6101 by slug in the message to StreamAlreadyClosed`() =
        runTest {
            // Robust to a bridge variant whose typed `code` is absent but
            // whose message carries the slug.
            val rejectingSlug: suspend (String, String, UInt) -> UInt = { _, _, _ ->
                throw uniffi.scp.ScpException.Context(
                    msg = "credit grant rejected: protocol.stream-already-closed",
                    code = "SCP-CTX-2001",
                )
            }
            val handle = handleFor("e9".repeat(16), emptyList(), grantCreditFn = rejectingSlug)
            assertFailsWith<StreamAlreadyClosed> { handle.grantCredit(Credit(10u)) }
        }

    @Test
    fun `control-plane passes through a non-6101 bridge error unchanged`() =
        runTest {
            // A genuinely different rejection must NOT be masked as a
            // lifecycle violation.
            val rejectingOther: suspend (String, String, UInt) -> UInt = { _, _, _ ->
                throw uniffi.scp.ScpException.Permission(
                    msg = "caller is not authorized",
                    code = "SCP-PERM-3020",
                )
            }
            val handle = handleFor("fa".repeat(16), emptyList(), grantCreditFn = rejectingOther)
            val err = assertFailsWith<uniffi.scp.ScpException> { handle.grantCredit(Credit(10u)) }
            assertTrue(err !is StreamAlreadyClosed)
        }
}
