// Outlets.kt — the `ctx.outlets` accessor holding the SINGLE public streaming
// invocation verb `invoke(...)` (§5.4.5, SCP-OUT-006 / SCP-OUT-038).
//
// The Kotlin SDK has no dedicated `Context` type — a context is represented by
// its opaque UniFFI `ContextHandle`. So the `ctx.outlets` accessor is obtained
// from an [SCP] instance plus the [uniffi.scp.ContextHandle] it operates on:
// `scp.outlets(handle, callerDid).invoke(...)`. The returned [Outlets] is bound
// to that one context (it pins the handle and the default caller DID), exactly
// like the Python reference's context-bound `Outlets` accessor.
//
// `invoke(...)` NEVER blocks or throws — it returns an [InvocationHandle]
// synchronously; the §5.4.5 stream opens LAZILY on the first
// `aggregate()` / `asFlow()` collection / `grantCredit()`. Open-time rejections
// (UCAN denial, input-schema violation, escrow InsufficientFunds/overflow)
// surface THERE as the matching [uniffi.scp.ScpException] variant. The streaming
// FFI ops are wrapped BEHIND the handle — there is no public `invokeStream` /
// `pollNext` / `grantCredit` free function.
//
// Provenance: spec §5.4.5, SCP-OUT-006 (single public verb), SCP-OUT-038,
// ADR-028 (Kotlin SDK). Mirrors the CANONICAL Python reference outlets.py.

package works.limn.scp

import uniffi.scp.ContextHandle
import uniffi.scp.Scp as NativeScp

/**
 * The `ctx.outlets` accessor — the home of the single public [invoke] verb.
 *
 * Bound to one context: it pins the [ContextHandle] (via its [OutletStreamNative]
 * seam) and the default caller DID that context is scoped to. Obtain it from
 * [SCP.outlets]; do not construct directly.
 */
public class Outlets internal constructor(
    private val native: OutletStreamNative,
    private val defaultCallerDid: String,
) {
    /**
     * Invokes [outletId] and returns its [InvocationHandle].
     *
     * This is the ONLY public invocation verb (SCP-OUT-006). The returned handle
     * exposes `suspend fun aggregate(): Aggregate` (the primary drain) and
     * `fun asFlow(): Flow<OutletStreamChunk>` (backed by the same shared drain),
     * plus the `grantCredit` / `cancel` control-plane methods; the streaming FFI
     * ops are wrapped behind it. `invoke` itself performs no I/O and does not
     * block — the stream opens lazily on the first drain / control-plane call.
     *
     * @param outletId Registration id of the target outlet.
     * @param inputJson JSON-encoded input value (validated against the outlet's
     *   `input_schema` at open).
     * @param ucanToken The invoker's authorizing UCAN (required).
     * @param callerDid The invoking DID. Defaults to the context's caller DID
     *   when omitted; must equal the DID pinned as the stream invoker for the
     *   control-plane methods to authorize.
     * @param proofTokens Optional UCAN delegation-chain proof tokens.
     * @param spendingUcan Optional spending-authorization UCAN for a paid
     *   (Action) outlet.
     * @param timeoutMs Optional per-stream timeout in milliseconds.
     * @param estimatedChunkCount Optional invoker-declared upper bound on
     *   billable chunks (feeds the §5.4.5 `caveats_binding`).
     */
    @Suppress("LongParameterList") // Flat §5.4.5 invoke envelope — agent-first named params.
    public fun invoke(
        outletId: String,
        inputJson: String,
        ucanToken: String,
        callerDid: String? = null,
        proofTokens: List<String>? = null,
        spendingUcan: String? = null,
        timeoutMs: UInt? = null,
        estimatedChunkCount: UInt? = null,
    ): InvocationHandle {
        val params =
            StreamOpenParams(
                outletId = outletId,
                inputJson = inputJson,
                callerDid = callerDid ?: defaultCallerDid,
                ucanToken = ucanToken,
                proofTokens = proofTokens,
                spendingUcan = spendingUcan,
                timeoutMs = timeoutMs,
                estimatedChunkCount = estimatedChunkCount,
            )
        return InvocationHandle(native, params)
    }
}

/**
 * The production [OutletStreamNative] — forwards to the UniFFI-generated
 * `Scp.outletStream*` suspend methods on the owned opaque native object, pinning
 * the [ContextHandle] at construction (the handle the whole stream is scoped
 * to). One instance per (native, context) pair.
 */
internal class ScpOutletStreamNative(
    private val inner: NativeScp,
    private val handle: ContextHandle,
) : OutletStreamNative {
    override suspend fun outletStreamOpen(
        outletId: String,
        inputJson: String,
        callerDid: String,
        ucanToken: String,
        proofTokens: List<String>?,
        spendingUcan: String?,
        timeoutMs: UInt?,
        estimatedChunkCount: UInt?,
    ): String =
        inner.outletStreamOpen(
            handle = handle,
            outletId = outletId,
            inputJson = inputJson,
            callerDid = callerDid,
            ucanToken = ucanToken,
            proofTokens = proofTokens,
            spendingUcan = spendingUcan,
            timeoutMs = timeoutMs,
            estimatedChunkCount = estimatedChunkCount,
        )

    override suspend fun outletStreamPollNext(handleId: String): ByteArray? =
        inner.outletStreamPollNext(handleId = handleId)

    override suspend fun outletStreamGrantCredit(
        handleId: String,
        callerDid: String,
        grant: UInt,
    ) = inner.outletStreamGrantCredit(handleId = handleId, callerDid = callerDid, grant = grant)

    override suspend fun outletStreamCancel(
        handleId: String,
        callerDid: String,
    ) = inner.outletStreamCancel(handleId = handleId, callerDid = callerDid)
}

/**
 * Returns the [Outlets] accessor for the context identified by [handle], scoped
 * to the invoking [callerDid] (the default stream invoker, overridable per
 * [Outlets.invoke] call). Faithful analogue of the Python reference's
 * `ctx.outlets` — the Kotlin SDK has no `Context` type, so the context handle
 * and caller DID are supplied here.
 *
 * Usage: `scp.outlets(handle, callerDid).invoke(outletId, inputJson, ucanToken)`.
 */
public fun SCP.outlets(
    handle: ContextHandle,
    callerDid: String,
): Outlets = Outlets(ScpOutletStreamNative(inner, handle), callerDid)
