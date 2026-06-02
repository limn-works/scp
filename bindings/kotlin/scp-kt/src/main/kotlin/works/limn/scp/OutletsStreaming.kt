// OutletsStreaming.kt — SCP-OUT-037 Kotlin streaming surface.
//
// Wraps the UniFFI-generated streaming bridge (see
// `crates/scp-ffi/uniffi/src/outlet_stream.rs`) as idiomatic Kotlin:
//
// - `OutletStreaming.grantCredit(...)` / `OutletStreaming.cancel(...)` /
//   `OutletStreaming.terminate(...)` / `OutletStreaming.verifyChunkSignature(...)` /
//   `OutletStreaming.computeCaveatsBinding(...)` — top-level
//   helpers for the FFI streaming functions.
//
// All stream invocation flows through `ctx.outlets.invoke(...)` →
// `InvocationHandle` (SCP-OUT-038 AC1 — the SOLE public verb). The
// reusable abnormal-closure flow logic lives in `outletStreamFlowFromNext`.
//
// Pure ergonomics layer (ADR-021 — protocol logic stays in Rust). The
// Rust bridge enforces the §5.4.5 invariants; this file translates the
// FFI symbols to Kotlin idioms.
//
// UniFFI-generated symbols this file uses (regenerated from
// `crates/scp-ffi/uniffi/src/outlet_stream.rs`):
// - `OutletStreamChunkRecord` — chunk payload record.
// - `outletStreamGrantCredit(requestIdHex, grant)`
// - `outletStreamCancel(requestIdHex, nextSeq)`
// - `outletStreamTerminate(requestIdHex, callerDid, reason, messageOverride)`
// - `verifyChunkSignature(chunkJson, operatorPk, contextId, outletId, caveatsBinding)`
// - `computeCaveatsBinding(ucanCid, requestId, invokerDid, estimatedChunkCount, effectiveCaveatsJson)`

@file:Suppress("TooManyFunctions")

package works.limn.scp

import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.flow
import uniffi.scp.TerminateReason
import uniffi.scp.computeCaveatsBinding as ffiComputeCaveatsBinding
import uniffi.scp.outletStreamCancel as ffiOutletStreamCancel
import uniffi.scp.outletStreamTerminate as ffiOutletStreamTerminate
import uniffi.scp.outletStreamGrantCredit as ffiOutletStreamGrantCredit
import uniffi.scp.verifyChunkSignature as ffiVerifyChunkSignature

// ---------------------------------------------------------------------------
// FFI-shaped chunk record — separate from the SDK-shaped sealed class
// `OutletStreamChunk` already in Outlets.kt so we can return the raw
// shape unchanged from FFI for callers who need every field.
// ---------------------------------------------------------------------------

/**
 * One chunk yielded by the [outletStreamFlowFromNext] flow. Mirrors the
 * §5.4.5 wire form variant-by-variant — callers branch on [payloadType]
 * and read the variant fields directly.
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
     * companion so the flow seam can forward without exposing the
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
// outletStreamFlowFromNext — reusable abnormal-closure flow logic over a
// `next()` cursor. The §5.4.5 streaming control plane is `InvocationHandle`
// (SCP-OUT-038 AC1); this seam carries the converged §5.4.4 abnormal-
// closure contract (6131, NO slug) independent of any opaque bridge handle.
// ---------------------------------------------------------------------------

/**
 * Builds a cold [Flow] over outlet-stream chunks pulled from a `next`
 * suspend lambda. Accepting `next` rather than an opaque
 * `OutletStreamHandle` keeps the abnormal-closure contract testable
 * without the regenerated `uniffi.scp` bindings or the compiled cdylib.
 *
 * Abnormal-closure handling: if `next()` returns `null` BEFORE a terminal
 * chunk (`End` / `Error{terminal:true}`) has been emitted, the flow throws
 * [ExecutionError] with code `SCP-TOOL-6131` and NO slug per §5.4.4
 * (converged with Python / TypeScript / Swift). Synthesising a silent
 * end-of-flow on receiver close would let callers mistake a transport
 * drop, executor crash, or bridge fault for a clean stream completion.
 *
 * Surfaced via an internal helper so unit tests in the same package can
 * reach it without exposing it on the public API.
 */
internal fun outletStreamFlowFromNext(
    next: suspend () -> StreamChunkSource?,
): Flow<OutletStreamChunkData> = flow {
    var terminalObserved = false
    while (true) {
        val raw = next()
        if (raw == null) {
            if (terminalObserved) {
                return@flow
            }
            // Abnormal closure — `next()` returned null before any
            // terminal chunk. Code `SCP-TOOL-6131`, NO slug — converged
            // with Python / TypeScript / Swift. §5.4.5 does list
            // `execution.stream-gap` sharing the 6131 band, but that slug
            // names a distinct condition (an explicit gap signal in the
            // stream). The SDK intentionally omits the slug for THIS
            // condition — the receiver closed before any terminal chunk —
            // so it is not conflated with the spec's StreamGap.
            throw ExecutionError(
                message = "stream closed without terminal chunk",
                code = "SCP-TOOL-6131",
            )
        }
        if (raw.payloadType == "end" || (raw.payloadType == "error" && raw.terminal == true)) {
            terminalObserved = true
        }
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
 * Minimal shape that [outletStreamFlowFromNext] needs from each chunk —
 * mirrors the field set of the UniFFI-generated `OutletStreamChunkRecord`
 * so the production adapter (`{ handle.next()?.toSource() }`) can pass
 * straight through. Tests construct synthetic instances of this type.
 *
 * Internal: this shape is an implementation detail of the abnormal-
 * closure test seam, not part of the public API.
 */
internal data class StreamChunkSource(
    val requestId: ByteArray,
    val sequence: ULong,
    val sig: ByteArray,
    val payloadType: String,
    val valueJson: String?,
    val pct: UShort?,
    val note: String?,
    val aggregateJson: String?,
    val provenanceJson: String?,
    val executionTimeMs: ULong?,
    val code: String?,
    val message: String?,
    val terminal: Boolean?,
) {
    @Suppress("CyclomaticComplexMethod", "ComplexCondition")
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is StreamChunkSource) return false
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
}

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
    ): Boolean = ffiVerifyChunkSignature(
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
    ): ByteArray = ffiComputeCaveatsBinding(
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
     * Takes a typed [Credit] to keep parity with the per-handle form
     * and the §5.4.4 round-6 zero-rejection rule. The compiler rejects
     * passing a raw [UInt]; [Credit]'s constructor itself raises
     * [InvalidGrant] for `raw == 0u`.
     *
     * @throws ScpException.Context when the runtime rejects the grant.
     */
    @JvmStatic
    suspend fun grantCredit(requestIdHex: String, callerDid: String, grant: Credit): UInt =
        ffiOutletStreamGrantCredit(
            requestIdHex = requestIdHex,
            callerDid = callerDid,
            grant = grant.raw,
        )

    /**
     * Applies an `OutletCancel` to an active stream by [requestIdHex].
     *
     * `callerDid` MUST match the pinned invoker DID at stream open.
     * CRITICAL #3 — `next_seq` is no longer caller-supplied; the
     * bridge derives the canonical next-emission cursor from runtime
     * state.
     *
     * @return Recorded cancel-ack sequence, or `null` when the stream
     *   had already reached a terminal chunk.
     */
    @JvmStatic
    suspend fun cancel(requestIdHex: String, callerDid: String): ULong? =
        ffiOutletStreamCancel(requestIdHex = requestIdHex, callerDid = callerDid)

    /**
     * Forces a terminal `Error{terminal:true}` chunk into an active
     * stream (§5.4.5 receiver-side revocation re-check,
     * `RevokedMidStream` / `SCP-TOOL-6110`).
     *
     * `callerDid` MUST match the pinned invoker DID at stream open.
     * Called by the SDK framework's periodic UCAN re-check loop when
     * it observes the opening UCAN has been revoked since stream
     * open. The runtime emits a synthetic terminal Error chunk under
     * the pinned operator key and runs settlement (admission release,
     * escrow refund, OutletInvokedEvent emission) identically to
     * other framework-emitted closes.
     */
    @JvmStatic
    suspend fun terminate(
        requestIdHex: String,
        callerDid: String,
        reason: TerminateReason,
        messageOverride: String?,
    ) {
        ffiOutletStreamTerminate(
            requestIdHex = requestIdHex,
            callerDid = callerDid,
            reason = reason,
            messageOverride = messageOverride,
        )
    }
}

/**
 * Module-internal alias for the UniFFI-generated `outletStreamGrantCredit`
 * — exposed at the `works.limn.scp` package scope so SDK code in
 * `Outlets.kt` (the `InvocationHandle.grantCredit` method) can call it
 * without importing from the generated `uniffi.scp` package.
 */
internal suspend fun outletStreamGrantCredit(
    requestIdHex: String,
    callerDid: String,
    grant: UInt,
): UInt =
    ffiOutletStreamGrantCredit(
        requestIdHex = requestIdHex,
        callerDid = callerDid,
        grant = grant,
    )

/**
 * Module-internal alias for the UniFFI-generated `outletStreamCancel`.
 *
 * CRITICAL #3 — `next_seq` is no longer caller-supplied; the bridge
 * derives the canonical next-emission cursor from runtime state.
 */
internal suspend fun outletStreamCancel(
    requestIdHex: String,
    callerDid: String,
): ULong? =
    ffiOutletStreamCancel(requestIdHex = requestIdHex, callerDid = callerDid)

/**
 * Module-internal alias for the UniFFI-generated `outletStreamTerminate`
 * — exposed at the `works.limn.scp` package scope so SDK code can call
 * the §5.4.5 receiver-side revocation re-check terminate without
 * importing from the generated `uniffi.scp` package.
 *
 * CRITICAL #1 — `callerDid` MUST match the pinned invoker DID at
 * stream open. The bridge rejects mismatched callers as
 * `authorization.denied`.
 */
internal suspend fun outletStreamTerminate(
    requestIdHex: String,
    callerDid: String,
    reason: TerminateReason,
    messageOverride: String?,
) {
    ffiOutletStreamTerminate(
        requestIdHex = requestIdHex,
        callerDid = callerDid,
        reason = reason,
        messageOverride = messageOverride,
    )
}
