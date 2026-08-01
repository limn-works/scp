// OutletsStreaming.kt — the single-verb outlet streaming surface (§5.4.5,
// SCP-OUT-006 / SCP-OUT-038) for the Kotlin SDK.
//
// This is the faithful Kotlin mirror of the Python reference SDK
// (`bindings/python/scp_sdk/outlets.py`, C11a). The SDK exposes EXACTLY ONE
// public invocation verb — `ctx.outlets.invoke(...)` (see [Outlets] in
// Outlets.kt) — returning an [InvocationHandle] that drains the §5.4.5
// streaming FFI ops (`outletStreamOpen` / `outletStreamPollNext` /
// `outletStreamGrantCredit` / `outletStreamCancel`) BEHIND the handle. There is
// no public `invokeStream` / `pollNext` / `grantCredit` free function.
//
// Kotlin idioms (SCP-OUT-038 canonical contract): the handle exposes the
// explicit PRIMARY drain verb `suspend fun aggregate(): Aggregate` and
// `fun asFlow(): Flow<OutletStreamChunk>`. Unlike Python/TS, Kotlin is NOT
// awaitable-for-aggregate — `aggregate()` is the sole aggregate path.
//
// CRITICAL: `asFlow()` is backed by the SINGLE SHARED DRAIN — it emits from the
// one underlying stream cursor. It is NOT a cold producer that re-opens or
// re-drives the stream on each `collect`. Once the shared drain has reached its
// terminal, a subsequent `collect` emits nothing (the stream is already
// drained), and a second CONCURRENT driver fails loud with an
// [OutletProtocolException] rather than silently splitting the chunk sequence.
//
// Provenance: spec §5.4.5 (progressive output / streaming), SCP-OUT-006 (single
// public verb), SCP-OUT-038 (InvocationHandle control plane + per-language
// iteration idioms), ADR-014, ADR-028 (Kotlin SDK). Mirrors the CANONICAL
// Python reference outlets.py.

package works.limn.scp

import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.flow
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.int
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.longOrNull
import uniffi.scp.ContextHandle
import uniffi.scp.ScpException
import java.util.concurrent.atomic.AtomicBoolean
import uniffi.scp.Scp as NativeScp

// ---------------------------------------------------------------------------
// Protocol-class exception hierarchy (mirrors the Python OutletError ->
// ProtocolError -> InvalidGrant / StreamAlreadyClosed chain).
// ---------------------------------------------------------------------------

/**
 * A protocol-class outlet failure (`OutletErrorClass::Protocol`, §5.4.4) raised
 * by the SDK's own stream-lifecycle logic — NOT propagated from the bridge.
 *
 * This is the common parent for every SDK-synthesized protocol-class condition
 * (a concurrent-drain violation, a stream that closed without an `End` chunk,
 * an invalid credit grant, a control-plane call after terminal) so a single
 * `catch` branch can handle them all. It is a hand-written sibling of the
 * generated [uniffi.scp.ScpException] hierarchy (which is a `sealed` type this
 * SDK cannot extend); data-plane bridge rejections still surface as their
 * generated [ScpException] variant, exactly like the rest of the Kotlin SDK.
 *
 * Mirrors Python's `ProtocolError` (a subclass of `OutletError`); its default
 * code is the §5.4.4 Protocol sub-range anchor `SCP-OUTLET-6100`.
 */
public open class OutletProtocolException(
    message: String,
    public val code: String = "SCP-OUTLET-6100",
) : Exception(message)

/**
 * A stream-credit grant value outside the valid non-zero `u32` range (§5.4.5).
 *
 * Raised at [Credit] construction. The FFI boundary is a Kotlin [UInt], which
 * already excludes negatives and values `>= 2^32` by construction — so only `0`
 * can reach the constructor as an invalid value, and only `0` is rejected here.
 * (Python / TypeScript additionally reject negatives, `>= 2**32`, and non-ints
 * because their surface accepts a wider numeric type; Kotlin's [UInt] makes
 * those cases unrepresentable.) Matches the SCP-OUT-031 round-6 uniform
 * `InvalidGrant` rule: never a bare `IllegalArgumentException`.
 */
public class InvalidGrant(
    message: String,
    code: String = "SCP-OUTLET-6100",
) : OutletProtocolException(message, code)

/**
 * A control-plane call ([InvocationHandle.grantCredit] / [InvocationHandle.cancel])
 * on a handle whose stream already reached a terminal chunk — the §5.4.5
 * InvocationHandle lifecycle guard (SCP-OUT-038). Mirrors Python's
 * `StreamAlreadyClosed`.
 */
public class StreamAlreadyClosed(
    message: String,
    code: String = "SCP-OUTLET-6100",
) : OutletProtocolException(message, code)

/**
 * A gap (missing sequence) in an outlet stream's chunk sequence (§5.4.5).
 *
 * Sequence values are strictly monotonic per `request_id`; a receiver that
 * observes a gap (a missing or regressed sequence) MUST cancel the stream and
 * surface this error (spec §5.4.5 "Ordering and gaps",
 * `OutletErrorClass::Execution::StreamGap`). The SDK [InvocationHandle] drain is
 * that receiver: it tracks the expected next sequence and, on any non-contiguous
 * chunk, signs an `OutletCancel` through the bridge and throws this. A
 * same-context stream flows over a lossless ordered channel so a gap never
 * occurs in production — this is a defense-in-depth monotonicity check mirroring
 * the §5.4.5 receiver-side recheck posture.
 *
 * A protocol-class sibling of [InvalidGrant] / [StreamAlreadyClosed] under
 * [OutletProtocolException], carrying the execution-class code `SCP-OUTLET-6131`
 * (`execution.stream-gap`).
 */
public class StreamGap(
    message: String,
    code: String = "SCP-OUTLET-6131",
) : OutletProtocolException(message, code)

// ---------------------------------------------------------------------------
// Credit — a validated, non-zero u32 stream-credit grant (§5.4.5).
// ---------------------------------------------------------------------------

/**
 * A validated, non-zero `u32` stream-credit grant (§5.4.5).
 *
 * Construct with `Credit(n)` where `n` is a [UInt] in `[1, 2^32)`. `Credit(0u)`
 * raises [InvalidGrant] at construction (the SCP-OUT-031 round-6 uniform rule).
 * The validated magnitude is read through [value].
 *
 * [InvocationHandle.grantCredit] consumes a `Credit`, never a raw [UInt] — the
 * type forces every caller through the validating constructor.
 *
 * Example:
 * ```
 * handle.grantCredit(Credit(4u))
 * ```
 */
@JvmInline
public value class Credit(
    /** The validated grant magnitude (a non-zero `u32`). */
    public val value: UInt,
) {
    init {
        if (value == 0u) {
            throw InvalidGrant("Credit must be a non-zero u32 in [1, 2^32), got 0")
        }
    }
}

// ---------------------------------------------------------------------------
// OutletStreamChunk — one decoded stream chunk (§5.4.5).
// ---------------------------------------------------------------------------

/**
 * One chunk in an outlet stream (§5.4.5).
 *
 * Emitted by collecting an [InvocationHandle.asFlow]. `Progress` chunks are
 * surfaced (not filtered), so a consumer observes the full
 * `Data` / `Progress` / `End` / `Error` sequence in order.
 */
public data class OutletStreamChunk(
    /** Strictly monotonic per-stream sequence number, starting at `0`. */
    public val sequence: Long,
    /** Payload variant tag: `"data"`, `"progress"`, `"end"`, or `"error"`. */
    public val kind: String,
    /** The variant's fields, minus the `@type` tag (an opaque JSON object). */
    public val payload: JsonObject,
    /** Stream identifier as a lowercase hex string (opaque to the SDK). */
    public val requestId: String,
    /** Operator's per-chunk Ed25519 signature as a lowercase hex string. */
    public val signature: String,
) {
    /**
     * `true` for the chunk that closes the stream (an `End`, or an `Error` whose
     * `terminal` flag is set).
     */
    public val isTerminal: Boolean
        get() = when (kind) {
            "end" -> true
            "error" -> payload["terminal"]?.jsonPrimitive?.booleanOrNull == true
            else -> false
        }

    internal companion object {
        private val JSON = Json { ignoreUnknownKeys = true }

        /**
         * Parses the JSON-serialized `OutletStreamChunk` bytes returned by
         * `outletStreamPollNext`. A malformed frame is a bridge/transport
         * invariant violation, surfaced as [ScpException.Outlet] (mirroring
         * Python's `OutletError`, code `SCP-OUTLET-6100`).
         */
        fun fromBridgeBytes(raw: ByteArray): OutletStreamChunk = parseChunk(raw) ?: throw malformed()

        /**
         * Attempts to decode one chunk. Returns `null` for any malformed frame
         * (unparseable JSON, non-object root, or a payload missing its `@type`
         * tag) so the single throw lives in [fromBridgeBytes].
         */
        private fun parseChunk(raw: ByteArray): OutletStreamChunk? {
            val root =
                runCatching { JSON.parseToJsonElement(raw.decodeToString()) }.getOrNull() as? JsonObject
                    ?: return null
            val payload = root["payload"] as? JsonObject ?: return null
            val type = payload["@type"]?.jsonPrimitive?.contentOrNull ?: return null
            val variant = JsonObject(payload.filterKeys { it != "@type" })
            return OutletStreamChunk(
                sequence = root["sequence"]?.jsonPrimitive?.longOrNull ?: 0L,
                kind = type,
                payload = variant,
                requestId = jsonBytesToHex(root["request_id"]),
                signature = jsonBytesToHex(root["sig"]),
            )
        }

        private fun malformed(): ScpException.Outlet =
            ScpException.Outlet(
                msg = "malformed outlet stream chunk from bridge: invalid frame",
                code = "SCP-OUTLET-6100",
            )

        /**
         * Renders a `serde_bytes` field — a JSON array of `u8` under
         * `serde_json`, or a hex string from a hardened bridge / fixture — as a
         * lowercase hex string, so the SDK surface is stable across encodings.
         */
        private fun jsonBytesToHex(el: JsonElement?): String =
            when (el) {
                is JsonPrimitive -> if (el.isString) el.content else ""
                is JsonArray ->
                    buildString {
                        for (item in el) {
                            append(HEX[(item.jsonPrimitive.int ushr 4) and 0xF])
                            append(HEX[item.jsonPrimitive.int and 0xF])
                        }
                    }
                else -> ""
            }

        private const val HEX = "0123456789abcdef"
    }
}

// ---------------------------------------------------------------------------
// Aggregate — the aggregated terminal result (§5.4.5 End).
// ---------------------------------------------------------------------------

/**
 * The aggregated terminal result of an outlet invocation (§5.4.5 `End`).
 *
 * Returned by [InvocationHandle.aggregate]. Carries the full `End` payload: the
 * aggregate output value (matching the outlet's `aggregate_schema`, validated
 * executor-side per §5.4.5), the provenance record for the stream output, and
 * the summed wall-clock execution time.
 */
public data class Aggregate(
    /** Aggregate output value — the `End.aggregate` field (may be any JSON). */
    public val value: JsonElement?,
    /** Provenance metadata for the full stream output (`End.provenance`). */
    public val provenance: JsonObject,
    /** Total wall-clock execution time in milliseconds. */
    public val executionTimeMs: Long,
) {
    internal companion object {
        fun fromEndPayload(payload: JsonObject): Aggregate =
            Aggregate(
                value = payload["aggregate"],
                provenance = payload["provenance"] as? JsonObject ?: JsonObject(emptyMap()),
                executionTimeMs = payload["execution_time_ms"]?.jsonPrimitive?.longOrNull ?: 0L,
            )
    }
}

// ---------------------------------------------------------------------------
// OutletStreamNative — the minimal streaming FFI seam the handle drives.
// ---------------------------------------------------------------------------

/**
 * The minimal §5.4.5 streaming FFI surface an [InvocationHandle] drives, bound
 * to one context.
 *
 * The production implementation ([works.limn.scp.ScpOutletStreamNative] in
 * Outlets.kt) forwards to the UniFFI-generated `Scp.outletStream*` suspend
 * methods on the owned opaque native object, pinning the context handle at
 * construction. Abstracting the seam here mirrors Python's duck-typed `_native`
 * bridge: it lets the InvocationHandle's iteration / aggregation / control-plane
 * / lifecycle logic be exercised against a scripted playback of §5.4.5 wire
 * chunks without a built Rust cdylib (the LIVE wire path is covered by the Rust
 * bridge's own live-poll test).
 */
public interface OutletStreamNative {
    /** Opens a stream, returning the bridge `StreamHandleId`. Rejections throw a typed [ScpException]. */
    @Suppress("LongParameterList") // Flat §5.4.5 open envelope — agent-first named params.
    public suspend fun outletStreamOpen(
        outletId: String,
        inputJson: String,
        callerDid: String,
        ucanToken: String,
        proofTokens: List<String>?,
        spendingUcan: String?,
        timeoutMs: UInt?,
        estimatedChunkCount: UInt?,
    ): String

    /** Drains one chunk (JSON `OutletStreamChunk` bytes), or `null` at the terminal sentinel. */
    public suspend fun outletStreamPollNext(handleId: String): ByteArray?

    /** Applies an invoker credit grant (the bridge signs it internally under the pinned invoker key). */
    public suspend fun outletStreamGrantCredit(
        handleId: String,
        callerDid: String,
        grant: UInt,
    )

    /** Signs and applies a stream cancel at the runtime-derived cursor. */
    public suspend fun outletStreamCancel(
        handleId: String,
        callerDid: String,
    )
}

/**
 * The immutable `outletStreamOpen` argument set, captured at [Outlets.invoke]
 * and replayed on the (lazy) first open. Mirrors Python's `_StreamOpenParams`.
 */
internal data class StreamOpenParams(
    val outletId: String,
    val inputJson: String,
    val callerDid: String,
    val ucanToken: String,
    val proofTokens: List<String>?,
    val spendingUcan: String?,
    val timeoutMs: UInt?,
    val estimatedChunkCount: UInt?,
)

// ---------------------------------------------------------------------------
// InvocationHandle — the single object ctx.outlets.invoke(...) returns.
// ---------------------------------------------------------------------------

/**
 * The single object returned by `ctx.outlets.invoke(...)` (SCP-OUT-038).
 *
 * Two drain surfaces, ONE shared single-consumer drain:
 *
 * - **[aggregate]** — the explicit PRIMARY drain verb. Drains the stream to its
 *   terminal and returns the [Aggregate] built from the `End` chunk. A terminal
 *   `Error` chunk raises the typed [ScpException.Outlet] it carried; a stream
 *   that ends without an `End` chunk raises [OutletProtocolException].
 * - **[asFlow]** — a [Flow] backed by the SAME shared drain. Collecting it emits
 *   each [OutletStreamChunk] (`Data` and `Progress` included) up to and
 *   including the terminal chunk. It does NOT re-open or re-drive the stream on
 *   each `collect`; once the shared drain has reached its terminal, a subsequent
 *   `collect` emits nothing.
 *
 * The two surfaces share one terminal-capture, so the executor's chunk sequence
 * is drained exactly once (three directions):
 *
 * 1. **collect then aggregate** — after [asFlow] runs to the terminal,
 *    [aggregate] returns the CACHED [Aggregate] (no re-drain).
 * 2. **aggregate then collect** — after [aggregate], a subsequent [asFlow]
 *    collect emits NOTHING (already fully drained).
 * 3. **partial-collect then aggregate** — [aggregate] drains the REMAINING
 *    chunks to the terminal and returns the executor's `End.aggregate`.
 *
 * Draining from two coroutines concurrently raises [OutletProtocolException] on
 * the second driver rather than silently splitting the chunk sequence.
 *
 * Two control-plane methods extend the handle: [grantCredit] and [cancel]. Both
 * raise [StreamAlreadyClosed] once the stream has reached a terminal chunk.
 *
 * The stream opens LAZILY — [Outlets.invoke] returns immediately without
 * blocking, and `outletStreamOpen` runs on the first [aggregate] / [asFlow]
 * collection / [grantCredit]. [cancel] on a never-opened handle is a local
 * no-op close: it does NOT open the stream (no escrow reservation / admission
 * slot) just to cancel it.
 */
public class InvocationHandle internal constructor(
    private val native: OutletStreamNative,
    private val params: StreamOpenParams,
) {
    private val openMutex = Mutex()

    @Volatile
    private var handleId: String? = null

    /**
     * `true` while a chunk drain is outstanding, so a second concurrent driver
     * fails loud instead of stealing chunks from the shared single-consumer
     * drain. A CAS makes the guard robust under true parallelism.
     */
    private val draining = AtomicBoolean(false)

    /** Set once a terminal chunk is observed (or the sender drops without one). */
    @Volatile
    private var closed = false

    /** Captured `End` terminal, read back by [aggregate]. */
    @Volatile
    private var aggregateResult: Aggregate? = null

    /** Captured terminal `Error`, re-thrown by [aggregate]. */
    @Volatile
    private var terminalError: ScpException? = null

    /** Captured [StreamGap] terminal, re-thrown by a re-[aggregate] after a gap. */
    @Volatile
    private var streamGapError: StreamGap? = null

    /**
     * §5.4.5 receiver-side monotonicity cursor: the sequence the NEXT chunk must
     * carry. Strictly monotonic per `request_id`, starting at 0; a chunk whose
     * sequence differs is a [StreamGap] (defense-in-depth — same-context streams
     * never gap over their lossless ordered channel).
     */
    @Volatile
    private var expectedSequence: Long = 0

    /** Opens the stream exactly once (idempotent), returning the bridge handle id. */
    private suspend fun ensureOpen(): String {
        handleId?.let { return it }
        openMutex.withLock {
            handleId?.let { return it }
            val id =
                native.outletStreamOpen(
                    outletId = params.outletId,
                    inputJson = params.inputJson,
                    callerDid = params.callerDid,
                    ucanToken = params.ucanToken,
                    proofTokens = params.proofTokens,
                    spendingUcan = params.spendingUcan,
                    timeoutMs = params.timeoutMs,
                    estimatedChunkCount = params.estimatedChunkCount,
                )
            handleId = id
            return id
        }
    }

    /**
     * The single shared drain step: returns the next chunk, or `null` at the
     * terminal (channel-closed sentinel). Both [aggregate] and [asFlow] pull
     * from HERE, so the executor's chunk sequence is drained exactly once.
     */
    private suspend fun nextChunk(): OutletStreamChunk? {
        if (closed) {
            return null
        }
        if (!draining.compareAndSet(false, true)) {
            throw OutletProtocolException(
                "InvocationHandle is already being drained by another consumer; an outlet stream has a " +
                    "single shared drain — do not collect or aggregate it from two coroutines concurrently",
            )
        }
        try {
            val id = ensureOpen()
            val raw = native.outletStreamPollNext(id)
            if (raw == null) {
                // Abnormal terminal: the sender dropped without a terminal chunk.
                closed = true
                return null
            }
            val chunk = OutletStreamChunk.fromBridgeBytes(raw)
            if (chunk.sequence != expectedSequence) {
                // §5.4.5 "Ordering and gaps": a non-contiguous sequence (a hole,
                // or a regression) is a receiver-detected StreamGap. Mark the
                // drain terminal, cancel the stream through the SAME bridge path
                // public cancel() uses, and throw — WITHOUT returning the
                // offending chunk. The check spans all chunk kinds
                // (Data/Progress/End/Error) since sequences are strictly
                // monotonic across them.
                closed = true
                val gap =
                    StreamGap(
                        "outlet stream sequence gap: expected $expectedSequence, got ${chunk.sequence} (§5.4.5)",
                    )
                streamGapError = gap
                // Best-effort receiver cancel: the StreamGap is the reported
                // terminal, so a cancel-path failure must not mask it.
                runCatching { sendCancel(id) }
                throw gap
            }
            expectedSequence += 1
            if (chunk.isTerminal) {
                // Capture the terminal state for aggregate(), mark closed, then
                // still return the terminal chunk so a collector observes it.
                closed = true
                when (chunk.kind) {
                    "end" -> aggregateResult = Aggregate.fromEndPayload(chunk.payload)
                    "error" ->
                        terminalError =
                            ScpException.Outlet(
                                msg = chunk.payload["message"]?.jsonPrimitive?.contentOrNull ?: "outlet stream error",
                                code = chunk.payload["code"]?.jsonPrimitive?.contentOrNull ?: "SCP-OUTLET-6000",
                            )
                }
            }
            return chunk
        } finally {
            draining.set(false)
        }
    }

    /**
     * Drains the stream to its terminal and returns the [Aggregate] (§5.4.5
     * `End`). This is the PRIMARY drain verb (Kotlin is not awaitable — there is
     * no `await handle` sugar).
     *
     * Idempotent: if the stream has already been drained (by [asFlow] or a prior
     * [aggregate]), the captured [Aggregate] is returned without re-draining. A
     * terminal `Error` chunk raises the typed [ScpException.Outlet] it carried;
     * a stream that ends without an `End` chunk raises [OutletProtocolException].
     */
    public suspend fun aggregate(): Aggregate {
        while (!closed) {
            if (nextChunk() == null) {
                break
            }
        }
        // A gap terminal takes priority over a bridge Error terminal; either is
        // re-thrown here on a re-aggregate (a single throw keeps ThrowsCount≤2).
        (streamGapError ?: terminalError)?.let { throw it }
        return aggregateResult
            ?: throw OutletProtocolException("outlet stream closed without an End chunk")
    }

    /**
     * A [Flow] over the stream's chunks, backed by the SINGLE SHARED DRAIN.
     *
     * Collecting pulls from the one shared drain cursor via [nextChunk]: it does
     * NOT re-open or re-drive the stream. `Progress` chunks are surfaced. Once
     * the shared drain reaches its terminal, a subsequent `collect` emits
     * nothing (the stream is already drained), and a second CONCURRENT collector
     * raises [OutletProtocolException] on its first pull.
     */
    public fun asFlow(): Flow<OutletStreamChunk> =
        flow {
            while (true) {
                val chunk = nextChunk() ?: break
                emit(chunk)
            }
        }

    /**
     * Grants additional billable chunks of credit to the live stream (§5.4.5
     * credit-based backpressure). Opens the stream if it is not yet open (a
     * grant needs a live stream). The FFI bridge signs the `OutletStreamCredit`
     * internally under the pinned invoker's custody key and auto-assigns the
     * monotonic sequence (ADR-006) — the SDK passes only the [Credit] magnitude.
     *
     * @throws StreamAlreadyClosed if the stream has already reached a terminal
     *   chunk; otherwise propagates any bridge rejection as its [ScpException].
     */
    public suspend fun grantCredit(credit: Credit) {
        if (closed) {
            throw StreamAlreadyClosed("cannot grant credit: the outlet stream has already closed")
        }
        val id = ensureOpen()
        native.outletStreamGrantCredit(id, params.callerDid, credit.value)
    }

    /**
     * Requests cancellation of the live stream (§5.4.5 cancellation). The FFI
     * bridge signs the `OutletCancel` internally under the pinned invoker's
     * custody key at the runtime-derived cursor.
     *
     * Cancelling a handle whose stream was never opened is a LOCAL no-op close:
     * it marks the handle closed WITHOUT opening the stream, so a cancel never
     * reserves escrow / an admission slot just to tear the stream down.
     *
     * @throws StreamAlreadyClosed if the stream has already reached a terminal
     *   chunk; otherwise propagates any bridge rejection as its [ScpException].
     */
    public suspend fun cancel() {
        if (closed) {
            throw StreamAlreadyClosed("cannot cancel: the outlet stream has already closed")
        }
        val id = handleId
        if (id == null) {
            // Never opened — cancel is a local close, not a bridge round-trip.
            closed = true
            return
        }
        sendCancel(id)
    }

    /**
     * Signs and sends an `OutletCancel` through the bridge (§5.4.5). The single
     * bridge cancel round-trip shared by the public [cancel] and the drain's
     * [StreamGap] teardown, so both cancel through the identical signed path.
     */
    private suspend fun sendCancel(id: String) {
        native.outletStreamCancel(id, params.callerDid)
    }
}

// ---------------------------------------------------------------------------
// Cross-context STREAMING saga (§5.4.5 / §6.2.4, SCP-OUT-047).
// ---------------------------------------------------------------------------
//
// The STREAMING sibling of the unary block-until-terminal
// [SCP.outletInvokeCrossContextSaga]. Per the ADR-049 §3a streaming wait-model
// amendment, the streaming saga returns its chunk receiver PROMPTLY at the
// Commit-transition (the caller consumes chunks as produced) and reaches
// `Committed` ASYNCHRONOUSLY at seal-close — it MUST NOT block until the stream
// terminates (an LLM stream can exceed the unary saga's ~95s bound; the credit
// ceiling bounds chunk COUNT, not wall-clock). The UniFFI open
// (`outletStreamingSagaOpen`) returns a durable `sagaId` promptly, and the SDK
// drives the stream by polling `outletStreamingSagaPollNext(sagaId)` behind
// [StreamingSagaHandle] — modelled on the same-context [InvocationHandle], MINUS
// the live control plane (there is no cross-context grantCredit / cancel —
// §6.2.5 / SCP-OUT-046, cancel_ack_ceiling = u64::MAX).
//
// This mirrors the CANONICAL Python reference `StreamingSagaHandle`
// (bindings/python/scp_sdk/outlets.py). Runtime-level guarantees (billed-count /
// execute-exactly-once) are proven Rust-side and are NOT re-asserted here.

/**
 * The minimal §6.2.4 cross-context streaming-saga FFI surface a
 * [StreamingSagaHandle] drives.
 *
 * The production implementation ([ScpStreamingSagaNative]) forwards to the
 * UniFFI-generated `Scp.outletStreamingSaga*` suspend methods on the owned
 * opaque native object, capturing the source + target context handles at
 * construction. Abstracting the seam here mirrors Python's duck-typed `_native`
 * bridge: it lets the handle's iteration / aggregation / lifecycle logic be
 * exercised against a scripted playback of §5.4.5 wire chunks without a built
 * Rust cdylib (the LIVE wire path is covered by the Rust bridge's own test).
 */
public interface StreamingSagaNative {
    /** Opens the saga, returning the durable `sagaId`. Rejections throw a typed [ScpException]. */
    @Suppress("LongParameterList") // Flat §6.2.4 open envelope — agent-first named params.
    public suspend fun outletStreamingSagaOpen(
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
    ): String

    /** Drains one chunk (JSON `OutletStreamChunk` bytes), or `null` at the terminal sentinel. */
    public suspend fun outletStreamingSagaPollNext(sagaId: String): ByteArray?
}

/**
 * The production [StreamingSagaNative] — forwards to the UniFFI-generated
 * `Scp.outletStreamingSaga*` suspend methods on the owned opaque native object,
 * capturing the co-resident source + target [ContextHandle] at construction.
 */
internal class ScpStreamingSagaNative(
    private val inner: NativeScp,
    private val sourceHandle: ContextHandle,
    private val targetHandle: ContextHandle,
) : StreamingSagaNative {
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
    ): String =
        inner.outletStreamingSagaOpen(
            sourceHandle = sourceHandle,
            targetHandle = targetHandle,
            callerDid = callerDid,
            outletRegistrationId = outletRegistrationId,
            inputJson = inputJson,
            assertedNonceHex = assertedNonceHex,
            timestampMs = timestampMs,
            chainDepth = chainDepth,
            ucanToken = ucanToken,
            proofTokens = proofTokens,
            ucanProofId = ucanProofId,
            timeoutMs = timeoutMs,
            estimatedChunkCount = estimatedChunkCount,
        )

    override suspend fun outletStreamingSagaPollNext(sagaId: String): ByteArray? =
        inner.outletStreamingSagaPollNext(sagaId = sagaId)
}

/**
 * The immutable `outletStreamingSagaOpen` argument set, captured at
 * [SCP.outletInvokeCrossContextStreamingSaga] and replayed on the (lazy) first
 * open. Mirrors the FFI open param order.
 */
internal data class StreamingSagaOpenParams(
    val callerDid: String,
    val outletRegistrationId: String,
    val inputJson: String,
    val assertedNonceHex: String,
    val timestampMs: ULong,
    val chainDepth: UByte,
    val ucanToken: String,
    val proofTokens: List<String>?,
    val ucanProofId: String?,
    val timeoutMs: UInt?,
    val estimatedChunkCount: UInt?,
)

/**
 * The handle for a §6.2.4 cross-context STREAMING saga (SCP-OUT-047), returned by
 * [SCP.outletInvokeCrossContextStreamingSaga].
 *
 * Modelled on the same-context [InvocationHandle], minus the live control plane
 * (there is no cross-context grantCredit / cancel — §6.2.5 / SCP-OUT-046). Two
 * drain surfaces, ONE shared single-consumer drain:
 *
 * - **[aggregate]** — the explicit PRIMARY drain verb. Opens the saga on first
 *   touch (`outletStreamingSagaOpen` returns the durable `sagaId` PROMPTLY at the
 *   Commit-transition, NOT block-until-terminal), drains to the terminal, and
 *   returns the [Aggregate] from the `End` chunk. A terminal `Error` chunk raises
 *   the typed [ScpException.Outlet] it carried; a stream that ends without an
 *   `End` chunk raises [OutletProtocolException].
 * - **[asFlow]** — a [Flow] backed by the SAME shared drain. Collecting emits
 *   each [OutletStreamChunk] up to and including the terminal. It does NOT re-open
 *   or re-drive the saga on each `collect`.
 *
 * The saga is opened LAZILY — [SCP.outletInvokeCrossContextStreamingSaga] returns
 * immediately without starting the saga; the open happens on the first
 * [aggregate] / [asFlow] collection. An open rejection — the §6.2.4
 * caller-principal binding, a Prepare/Commit saga terminal (a typed
 * [ScpException] `Saga*` case), or an input/UCAN rejection — surfaces there, and
 * the receiver is never handed out (the `sagaId` stays `null`).
 *
 * Draining from two coroutines concurrently raises [OutletProtocolException] on
 * the second driver rather than silently splitting the chunk sequence.
 */
public class StreamingSagaHandle internal constructor(
    private val native: StreamingSagaNative,
    private val params: StreamingSagaOpenParams,
) {
    private val openMutex = Mutex()

    /** The durable supervisor-minted saga id (doubles as the poll key); `null` until the lazy first open. */
    @Volatile
    public var currentSagaId: String? = null
        private set

    /**
     * `true` while a chunk drain is outstanding, so a second concurrent driver
     * fails loud instead of stealing chunks from the shared single-consumer drain.
     */
    private val draining = AtomicBoolean(false)

    /** Set once a terminal chunk is observed (or the sender drops without one). */
    @Volatile
    private var closed = false

    /** Captured `End` terminal, read back by [aggregate]. */
    @Volatile
    private var aggregateResult: Aggregate? = null

    /** Captured terminal `Error`, re-thrown by [aggregate]. */
    @Volatile
    private var terminalError: ScpException? = null

    /** Captured [StreamGap] terminal, re-thrown by a re-[aggregate] after a gap. */
    @Volatile
    private var streamGapError: StreamGap? = null

    /**
     * §5.4.5 receiver-side monotonicity cursor: the sequence the NEXT chunk must
     * carry. The bridge forwards A's operator-signed chunks VERBATIM over a
     * lossless ordered channel (no re-sequencing), so a non-contiguous sequence is
     * a [StreamGap] (defense-in-depth). There is NO live cancel plane, so the gap
     * is a purely local terminal — the SDK does NOT sign a receiver cancel.
     */
    @Volatile
    private var expectedSequence: Long = 0

    /** Opens the saga exactly once (idempotent), returning the durable saga id. */
    private suspend fun ensureOpen(): String {
        currentSagaId?.let { return it }
        openMutex.withLock {
            currentSagaId?.let { return it }
            val id =
                native.outletStreamingSagaOpen(
                    callerDid = params.callerDid,
                    outletRegistrationId = params.outletRegistrationId,
                    inputJson = params.inputJson,
                    assertedNonceHex = params.assertedNonceHex,
                    timestampMs = params.timestampMs,
                    chainDepth = params.chainDepth,
                    ucanToken = params.ucanToken,
                    proofTokens = params.proofTokens,
                    ucanProofId = params.ucanProofId,
                    timeoutMs = params.timeoutMs,
                    estimatedChunkCount = params.estimatedChunkCount,
                )
            currentSagaId = id
            return id
        }
    }

    /**
     * The single shared drain step: returns the next chunk, or `null` at the
     * terminal (channel-closed sentinel). Both [aggregate] and [asFlow] pull from
     * HERE, so the executor's chunk sequence is drained exactly once.
     */
    private suspend fun nextChunk(): OutletStreamChunk? {
        if (closed) {
            return null
        }
        if (!draining.compareAndSet(false, true)) {
            throw OutletProtocolException(
                "StreamingSagaHandle is already being drained by another consumer; a cross-context " +
                    "streaming saga has a single shared drain — do not collect or aggregate it from two " +
                    "coroutines concurrently",
            )
        }
        try {
            val id = ensureOpen()
            val raw = native.outletStreamingSagaPollNext(id)
            if (raw == null) {
                // Abnormal terminal: the sender dropped without a terminal chunk.
                closed = true
                return null
            }
            val chunk = OutletStreamChunk.fromBridgeBytes(raw)
            if (chunk.sequence != expectedSequence) {
                // §5.4.5 "Ordering and gaps": a non-contiguous sequence is a
                // receiver-detected StreamGap. There is NO live cross-context
                // cancel plane (§6.2.5 / SCP-OUT-046), so the gap is a purely
                // local terminal — mark closed and throw WITHOUT returning the
                // offending chunk and WITHOUT a bridge cancel round-trip.
                closed = true
                val gap =
                    StreamGap(
                        "cross-context streaming-saga sequence gap: expected $expectedSequence, " +
                            "got ${chunk.sequence} (§5.4.5)",
                    )
                streamGapError = gap
                throw gap
            }
            expectedSequence += 1
            if (chunk.isTerminal) {
                // Capture the terminal state for aggregate(), mark closed, then
                // still return the terminal chunk so a collector observes it.
                closed = true
                when (chunk.kind) {
                    "end" -> aggregateResult = Aggregate.fromEndPayload(chunk.payload)
                    "error" ->
                        terminalError =
                            ScpException.Outlet(
                                msg = chunk.payload["message"]?.jsonPrimitive?.contentOrNull ?: "outlet stream error",
                                code = chunk.payload["code"]?.jsonPrimitive?.contentOrNull ?: "SCP-OUTLET-6000",
                            )
                }
            }
            return chunk
        } finally {
            draining.set(false)
        }
    }

    /**
     * Drains the saga stream to its terminal and returns the [Aggregate] (§5.4.5
     * `End`). This is the PRIMARY drain verb (Kotlin is not awaitable).
     *
     * Idempotent: if the stream has already been drained (by [asFlow] or a prior
     * [aggregate]), the captured [Aggregate] is returned without re-draining. A
     * terminal `Error` chunk raises the typed [ScpException.Outlet] it carried; a
     * stream that ends without an `End` chunk raises [OutletProtocolException].
     */
    public suspend fun aggregate(): Aggregate {
        while (!closed) {
            if (nextChunk() == null) {
                break
            }
        }
        // A gap terminal takes priority over a bridge Error terminal; either is
        // re-thrown here on a re-aggregate (a single throw keeps ThrowsCount≤2).
        (streamGapError ?: terminalError)?.let { throw it }
        return aggregateResult
            ?: throw OutletProtocolException("cross-context streaming saga closed without an End chunk")
    }

    /**
     * A [Flow] over the saga stream's chunks, backed by the SINGLE SHARED DRAIN.
     *
     * Collecting pulls from the one shared drain cursor via [nextChunk]: it does
     * NOT re-open or re-drive the saga. Once the shared drain reaches its terminal,
     * a subsequent `collect` emits nothing, and a second CONCURRENT collector
     * raises [OutletProtocolException] on its first pull.
     */
    public fun asFlow(): Flow<OutletStreamChunk> =
        flow {
            while (true) {
                val chunk = nextChunk() ?: break
                emit(chunk)
            }
        }
}
