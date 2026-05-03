// OutletsStreaming.kt — SCP-OUT-037 Kotlin streaming surface.
//
// Wraps the UniFFI-generated streaming bridge (see
// `crates/scp-ffi/uniffi/src/outlet_stream.rs`) as idiomatic Kotlin:
//
// - `OutletStreamFlow` — a `Flow<OutletStreamChunk>` over an opened
//   stream session, driven by polling `OutletStreamHandle.next()`.
// - `Context.openOutletStream(...)` — opens a stream and returns the
//   flow.
// - `OutletStreaming.grantCredit(...)` / `OutletStreaming.cancel(...)` /
//   `OutletStreaming.verifyChunkSignature(...)` /
//   `OutletStreaming.computeCaveatsBinding(...)` — top-level
//   helpers for the FFI streaming functions.
//
// Pure ergonomics layer (ADR-021 — protocol logic stays in Rust). The
// Rust bridge enforces the §5.4.5 invariants; this file translates the
// FFI symbols to Kotlin idioms.
//
// UniFFI-generated symbols this file uses (regenerated from
// `crates/scp-ffi/uniffi/src/outlet_stream.rs`):
// - `OutletStreamHandle` — opaque async-iterator class with `next()`
//   and `cancel(nextSeq:)`.
// - `OutletStreamChunkRecord` — chunk payload record.
// - `OutletStreamSubscriber` — push-style callback interface.
// - `outletInvokeStream(...)` — open returns `OutletStreamHandle`.
// - `outletInvokeStreamWithSubscriber(...)` — open + push.
// - `outletStreamGrantCredit(requestIdHex, grant)`
// - `outletStreamCancel(requestIdHex, nextSeq)`
// - `verifyChunkSignature(chunkJson, operatorPk, contextId, outletId, caveatsBinding)`
// - `computeCaveatsBinding(ucanCid, requestId, invokerDid, estimatedChunkCount, effectiveCaveatsJson)`

@file:Suppress("TooManyFunctions")

package works.limn.scp

import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.flow

// ---------------------------------------------------------------------------
// FFI-shaped chunk record — separate from the SDK-shaped sealed class
// `OutletStreamChunk` already in Outlets.kt so we can return the raw
// shape unchanged from FFI for callers who need every field.
// ---------------------------------------------------------------------------

/**
 * One chunk yielded by [OutletStreamFlow] or pushed to a
 * `OutletStreamSubscriber`. Mirrors the §5.4.5 wire form variant-by-
 * variant — callers branch on [payloadType] and read the variant
 * fields directly.
 *
 * Distinct from the SDK-shaped sealed class [OutletStreamChunk] in
 * `Outlets.kt`; this record carries every wire field including `sig`
 * for callers that need to verify the per-chunk signature locally.
 */
data class OutletStreamChunkData(
    /** 16-byte §5.4.5 `request_id` of the stream this chunk belongs to. */
    val requestId: ByteArray,
    /** Strictly-monotonic per-stream chunk sequence number. */
    val sequence: ULong,
    /** 64-byte `SCP-OUTLET-CHUNK-SIG-V1:` Ed25519 signature. */
    val sig: ByteArray,
    /** One of `"data"` / `"progress"` / `"end"` / `"error"`. */
    val payloadType: String,
    /** `data` payload — JSON-encoded payload value. */
    val valueJson: String?,
    /** `progress` payload — completion in basis points `[0, 10000]`. */
    val pct: UShort?,
    /** `progress` payload — optional human-readable note. */
    val note: String?,
    /** `end` payload — JSON-encoded aggregate output value. */
    val aggregateJson: String?,
    /** `end` payload — JSON-encoded provenance block. */
    val provenanceJson: String?,
    /** `end` payload — total wall-clock execution time in milliseconds. */
    val executionTimeMs: ULong?,
    /** `error` payload — stable error code (e.g. `SCP-TOOL-6110`). */
    val code: String?,
    /** `error` payload — human-readable error message. */
    val message: String?,
    /**
     * `error` payload — `true` for terminal errors that close the
     * stream, `false` for non-terminal warnings.
     */
    val terminal: Boolean?,
) {
    @Suppress("CyclomaticComplexMethod", "ComplexCondition")
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is OutletStreamChunkData) return false
        return requestId.contentEquals(other.requestId) &&
            sequence == other.sequence &&
            sig.contentEquals(other.sig) &&
            payloadType == other.payloadType &&
            valueJson == other.valueJson &&
            pct == other.pct &&
            note == other.note &&
            aggregateJson == other.aggregateJson &&
            provenanceJson == other.provenanceJson &&
            executionTimeMs == other.executionTimeMs &&
            code == other.code &&
            message == other.message &&
            terminal == other.terminal
    }

    override fun hashCode(): Int {
        var result = requestId.contentHashCode()
        result = 31 * result + sequence.hashCode()
        result = 31 * result + sig.contentHashCode()
        result = 31 * result + payloadType.hashCode()
        result = 31 * result + (valueJson?.hashCode() ?: 0)
        result = 31 * result + (pct?.hashCode() ?: 0)
        result = 31 * result + (note?.hashCode() ?: 0)
        result = 31 * result + (aggregateJson?.hashCode() ?: 0)
        result = 31 * result + (provenanceJson?.hashCode() ?: 0)
        result = 31 * result + (executionTimeMs?.hashCode() ?: 0)
        result = 31 * result + (code?.hashCode() ?: 0)
        result = 31 * result + (message?.hashCode() ?: 0)
        result = 31 * result + (terminal?.hashCode() ?: 0)
        return result
    }

    /**
     * Adapter constructor for converting a raw `OutletStreamChunkRecord`
     * (UniFFI-generated record) into this SDK-side shape. Lives at the
     * companion so `OutletStreamFlow` can forward without exposing the
     * generated class to callers (the generated `OutletStreamChunkRecord`
     * shape may change as UniFFI bindings regenerate).
     */
    companion object {
        @JvmStatic
        @Suppress("LongParameterList")
        fun fromFfi(
            requestId: ByteArray,
            sequence: ULong,
            sig: ByteArray,
            payloadType: String,
            valueJson: String?,
            pct: UShort?,
            note: String?,
            aggregateJson: String?,
            provenanceJson: String?,
            executionTimeMs: ULong?,
            code: String?,
            message: String?,
            terminal: Boolean?,
        ): OutletStreamChunkData = OutletStreamChunkData(
            requestId = requestId,
            sequence = sequence,
            sig = sig,
            payloadType = payloadType,
            valueJson = valueJson,
            pct = pct,
            note = note,
            aggregateJson = aggregateJson,
            provenanceJson = provenanceJson,
            executionTimeMs = executionTimeMs,
            code = code,
            message = message,
            terminal = terminal,
        )
    }
}

// ---------------------------------------------------------------------------
// OutletStreamFlow — Flow<OutletStreamChunkData> wrapper around
// `OutletStreamHandle.next()` polling.
// ---------------------------------------------------------------------------

/**
 * Cold [Flow] over the chunks of an open outlet stream session.
 *
 * Construction wraps the UniFFI-generated `OutletStreamHandle` and
 * exposes:
 * - [asFlow] — `Flow<OutletStreamChunkData>` driven by `next()`
 *   polling. Emission ends when the handle reports `done` or the
 *   receiver closes.
 * - [requestIdHex] — 32-char lowercase hex `request_id` for control-
 *   plane lookups.
 * - [grantCredit] — sign + apply an `OutletStreamCredit` grant.
 * - [cancel] — apply an `OutletCancel`.
 *
 * Callers obtain instances from [Context.openOutletStream]. The
 * underlying handle is owned by the Rust bridge and freed on JVM
 * garbage-collection of this wrapper (UniFFI emits a `Disposable`
 * lifecycle; the Kotlin SDK relies on default GC semantics).
 */
class OutletStreamFlow internal constructor(
    private val handle: OutletStreamHandle,
) {
    /** 32-char lowercase hex `request_id`. */
    val requestIdHex: String
        get() = handle.requestId()

    /** `true` once a terminal chunk has been observed (or close). */
    val isDone: Boolean
        get() = handle.done()

    /**
     * Returns a cold [Flow] that emits one chunk per
     * `OutletStreamHandle.next()` call. Emission ends on receiver close
     * or after a terminal chunk (`End` / `Error{terminal:true}`).
     */
    fun asFlow(): Flow<OutletStreamChunkData> = flow {
        while (true) {
            val raw = handle.next() ?: break
            emit(
                OutletStreamChunkData.fromFfi(
                    requestId = raw.requestId,
                    sequence = raw.sequence,
                    sig = raw.sig,
                    payloadType = raw.payloadType,
                    valueJson = raw.valueJson,
                    pct = raw.pct,
                    note = raw.note,
                    aggregateJson = raw.aggregateJson,
                    provenanceJson = raw.provenanceJson,
                    executionTimeMs = raw.executionTimeMs,
                    code = raw.code,
                    message = raw.message,
                    terminal = raw.terminal,
                ),
            )
        }
    }

    /**
     * Signs and applies an `OutletStreamCredit` grant for this stream.
     *
     * @throws ScpException.Validation when [grant] == 0u (round-6
     *   uniform `InvalidGrant` rule).
     * @throws ScpException.Context when the runtime tracker rejects
     *   the grant or the stream has already terminated.
     */
    suspend fun grantCredit(grant: UInt): UInt =
        outletStreamGrantCredit(requestIdHex = requestIdHex, grant = grant)

    /**
     * Applies an `OutletCancel` to this stream.
     *
     * @return Recorded cancel-ack sequence number, or `null` when the
     *   stream had already reached a terminal chunk (idempotent per
     *   §5.4.5).
     */
    suspend fun cancel(nextSeq: ULong? = null): ULong? =
        handle.cancel(nextSeq = nextSeq)
}

// ---------------------------------------------------------------------------
// Top-level open-stream helpers — work directly against the UniFFI
// `ContextHandle` and `Identity` opaque classes (no Kotlin-side
// `Context` wrapper exists yet in this SDK; SDKs evolve toward one).
// ---------------------------------------------------------------------------

/**
 * Opens a §5.4.5 streaming outlet invocation and returns a
 * [OutletStreamFlow].
 *
 * Mirrors the PyO3 / NAPI / Swift contracts: re-validates the UCAN
 * under the full 11-step ADR-016 pipeline, reserves a per-stream
 * `request_id`, and registers the session for later
 * `grantCredit` / `cancel` lookups.
 *
 * @param contextHandle Hosting [ContextHandle].
 * @param outletId Outlet to invoke.
 * @param inputJson JSON-encoded input matching the outlet's input schema.
 * @param identity Invoker [Identity].
 * @param ucanToken UCAN authorising the invocation.
 * @param caveatsBindingHex 32-byte `caveats_binding` rendered as 64-char
 *   lowercase hex. Compute via [OutletStreaming.computeCaveatsBinding].
 * @param streamEpoch Hosting context's MLS epoch counter at open
 *   acceptance.
 * @param proofTokens Optional encoded parent UCANs for delegation-chain
 *   traversal.
 * @param creditWindow Initial credit-window size; defaults to §5.4.5
 *   `DEFAULT_CREDIT_WINDOW` when `null`.
 * @param estimatedChunkCount Optional upper bound on billable chunks.
 * @return An [OutletStreamFlow] ready for `.asFlow().collect { }`.
 *   Use [OutletStreamFlow.grantCredit] / [OutletStreamFlow.cancel] to
 *   manage flow.
 */
@Suppress("LongParameterList")
suspend fun openOutletStreamSession(
    contextHandle: ContextHandle,
    outletId: String,
    inputJson: String,
    identity: Identity,
    ucanToken: String,
    caveatsBindingHex: String,
    streamEpoch: ULong,
    proofTokens: List<String>? = null,
    creditWindow: UInt? = null,
    estimatedChunkCount: UInt? = null,
): OutletStreamFlow {
    val raw = outletInvokeStream(
        handle = contextHandle,
        outletId = outletId,
        inputJson = inputJson,
        identity = identity,
        ucanToken = ucanToken,
        caveatsBindingHex = caveatsBindingHex,
        streamEpoch = streamEpoch,
        proofTokens = proofTokens,
        creditWindow = creditWindow,
        estimatedChunkCount = estimatedChunkCount,
    )
    return OutletStreamFlow(raw)
}

/**
 * Push-style variant of [openOutletStreamSession] that drives every
 * chunk into a caller-supplied [OutletStreamSubscriber]. Returns the
 * 32-char hex `request_id` so the caller can address the active stream
 * from [OutletStreaming.grantCredit] / [OutletStreaming.cancel] before
 * the pump exits.
 */
@Suppress("LongParameterList")
suspend fun openOutletStreamSessionWithSubscriber(
    contextHandle: ContextHandle,
    outletId: String,
    inputJson: String,
    identity: Identity,
    ucanToken: String,
    caveatsBindingHex: String,
    streamEpoch: ULong,
    proofTokens: List<String>? = null,
    creditWindow: UInt? = null,
    estimatedChunkCount: UInt? = null,
    subscriber: OutletStreamSubscriber,
): String = outletInvokeStreamWithSubscriber(
    handle = contextHandle,
    outletId = outletId,
    inputJson = inputJson,
    identity = identity,
    ucanToken = ucanToken,
    caveatsBindingHex = caveatsBindingHex,
    streamEpoch = streamEpoch,
    proofTokens = proofTokens,
    creditWindow = creditWindow,
    estimatedChunkCount = estimatedChunkCount,
    subscriber = subscriber,
)

// ---------------------------------------------------------------------------
// Top-level helpers — verify_chunk_signature, compute_caveats_binding,
// grant_credit, cancel.
// ---------------------------------------------------------------------------

/**
 * Top-level convenience namespace for the streaming-helper free
 * functions that do not require a [Context].
 */
object OutletStreaming {
    /**
     * Verifies a chunk's `SCP-OUTLET-CHUNK-SIG-V1:` Ed25519 signature.
     *
     * @param chunkJson Canonical-JSON-encoded chunk including `sig`.
     * @param operatorPk 32-byte Ed25519 public key.
     * @param contextId Hosting context id.
     * @param outletId Outlet id.
     * @param caveatsBinding 32-byte `caveats_binding` for the stream.
     * @return `true` when the signature verifies; `false` otherwise.
     *   Throws on malformed inputs (non-32-byte pubkey or
     *   `caveats_binding`, malformed JSON).
     */
    @JvmStatic
    fun verifyChunkSignature(
        chunkJson: String,
        operatorPk: ByteArray,
        contextId: String,
        outletId: String,
        caveatsBinding: ByteArray,
    ): Boolean = works.limn.scp.verifyChunkSignature(
        chunkJson = chunkJson,
        operatorPk = operatorPk,
        contextId = contextId,
        outletId = outletId,
        caveatsBinding = caveatsBinding,
    )

    /**
     * Recomputes the §5.4.5 `caveats_binding` 32-byte SHA-256 over the
     * `SCP-OUTLET-CAVEAT-BIND-V1:` preimage.
     *
     * @param ucanCid CID of the opening UCAN (raw bytes).
     * @param requestId 16-byte stream `request_id`.
     * @param invokerDid Invoker DID string (UTF-8).
     * @param estimatedChunkCount Invoker-declared upper bound on
     *   billable chunks.
     * @param effectiveCaveatsJson SDK-canonicalised JSON object of the
     *   narrowed `InvocationCaveats`. The bridge re-runs JCS over this.
     * @return The 32-byte binding.
     */
    @JvmStatic
    fun computeCaveatsBinding(
        ucanCid: ByteArray,
        requestId: ByteArray,
        invokerDid: String,
        estimatedChunkCount: UInt,
        effectiveCaveatsJson: String,
    ): ByteArray = works.limn.scp.computeCaveatsBinding(
        ucanCid = ucanCid,
        requestId = requestId,
        invokerDid = invokerDid,
        estimatedChunkCount = estimatedChunkCount,
        effectiveCaveatsJson = effectiveCaveatsJson,
    )

    /**
     * Signs and applies an `OutletStreamCredit` grant against an active
     * stream identified by [requestIdHex].
     *
     * @throws ScpException.Validation when [grant] == 0u.
     * @throws ScpException.Context when the runtime rejects the grant.
     */
    @JvmStatic
    suspend fun grantCredit(requestIdHex: String, grant: UInt): UInt =
        outletStreamGrantCredit(requestIdHex = requestIdHex, grant = grant)

    /**
     * Applies an `OutletCancel` to an active stream by [requestIdHex].
     *
     * @return Recorded cancel-ack sequence, or `null` when the stream
     *   had already reached a terminal chunk.
     */
    @JvmStatic
    suspend fun cancel(requestIdHex: String, nextSeq: ULong? = null): ULong? =
        outletStreamCancel(requestIdHex = requestIdHex, nextSeq = nextSeq)
}
