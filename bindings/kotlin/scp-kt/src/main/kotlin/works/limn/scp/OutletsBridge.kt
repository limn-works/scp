// OutletsBridge.kt — SCP-OUT-006 / SCP-OUT-038 production outlet surface.
//
// `BridgeBackedOutletNamespace` is the PRODUCTION `OutletNamespace`
// implementation. Every verb routes through the UniFFI-generated
// `uniffi.scp.outlet*` exports (regenerated from
// `crates/scp-ffi/uniffi/src/bridge.rs` and `.../outlet_stream.rs`).
//
// Streaming-mode `invoke(...)` opens a real §5.4.5 stream via
// `outletInvokeStream`, threads the runtime `request_id` (read from the
// returned `OutletStreamHandle.requestId()`) and the pinned invoker DID
// into the production `InvocationHandle`, and wires the receiver-side
// UCAN revocation re-check loop — so `handle.grantCredit(...)` /
// `handle.cancel()` reach `outletStreamGrantCredit` /
// `outletStreamCancel` on the runtime. This closes the OUT-038 deferral:
// previously only `InMemoryOutletNamespace` (a test stub) existed, so
// the documented control plane was unreachable in production.
//
// Behavioral reference: the Python (`scp_sdk/outlets.py`), TypeScript
// (`src/outlets.ts`) and Swift (`Sources/SCP/Outlets.swift`) SDKs. Written
// in idiomatic Kotlin (coroutines + `Flow`).
//
// Pure ergonomics layer (ADR-021 / ADR-028 flat delegation) — protocol
// logic stays in Rust. The bridge seam (`OutletBridgeFns`) is injectable
// so the production control plane is testable without the compiled
// cdylib; the defaults call the real `uniffi.scp` functions.

@file:Suppress("TooManyFunctions")

package works.limn.scp

import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.channelFlow
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.jsonObject
import uniffi.scp.ContextHandle
import uniffi.scp.Identity
import uniffi.scp.OutletStreamChunkRecord
import uniffi.scp.OutletStreamHandle

// ---------------------------------------------------------------------------
// Injectable bridge seam.
//
// Each function mirrors a `uniffi.scp.outlet*` / `uniffi.scp.ucanValidate`
// export. Defaults call the real generated functions; tests inject fakes
// to drive the production namespace without the compiled cdylib (mirrors
// the Swift SDK's `*Bridge` injectable-closure pattern and the Kotlin
// SDK's `NativeBindings` seam).
// ---------------------------------------------------------------------------

/**
 * Opaque per-stream cursor the production namespace pumps. Abstracts the
 * UniFFI `OutletStreamHandle` so the pump + control-plane wiring is
 * testable against a fake. `requestId()` returns the 32-char lowercase
 * hex §5.4.5 `request_id`; `next()` yields the next chunk as the
 * cdylib-independent [StreamChunkSource] (the UniFFI `OutletStreamHandle`
 * adapter performs the record → source mapping), or `null` at
 * end-of-stream. Surfacing [StreamChunkSource] — not the UniFFI
 * `OutletStreamChunkRecord` — keeps the seam constructible in tests
 * without the compiled binary.
 */
internal interface OutletStreamCursor {
    fun requestId(): String

    suspend fun next(): StreamChunkSource?
}

/** Adapter wrapping a real UniFFI [OutletStreamHandle] as a cursor. */
private class UniffiStreamCursor(private val raw: OutletStreamHandle) : OutletStreamCursor {
    override fun requestId(): String = raw.requestId()

    override suspend fun next(): StreamChunkSource? = raw.next()?.toSource()
}

/**
 * The set of bridge calls `BridgeBackedOutletNamespace` depends on.
 * Defaults delegate to the UniFFI-generated `uniffi.scp` functions;
 * `OutletBridgeFns.production` is the production wiring.
 */
internal data class OutletBridgeFns(
    val register: suspend (handle: ContextHandle, definition: uniffi.scp.OutletDefinition) -> String,
    val get: suspend (handle: ContextHandle, outletId: String) -> String,
    val list: suspend (handle: ContextHandle) -> List<String>,
    val verify: suspend (handle: ContextHandle, outletId: String) -> uniffi.scp.OutletVerificationResult,
    val update: suspend (
        handle: ContextHandle,
        outletId: String,
        definition: uniffi.scp.OutletDefinition,
        updaterDid: String,
    ) -> String,
    val deregister: suspend (handle: ContextHandle, outletId: String, actorDid: String) -> Unit,
    val invoke: suspend (
        handle: ContextHandle,
        outletId: String,
        inputJson: String,
        identity: Identity,
        ucanToken: String?,
        proofTokens: List<String>?,
        spendingUcanJwt: String?,
    ) -> String,
    val invokeStream: suspend (
        handle: ContextHandle,
        outletId: String,
        inputJson: String,
        identity: Identity,
        ucanToken: String,
        caveatsBindingHex: String,
        streamEpoch: ULong,
        proofTokens: List<String>?,
        creditWindow: UInt?,
        estimatedChunkCount: UInt?,
        spendingUcan: String?,
    ) -> OutletStreamCursor,
    val invokeCrossContext: suspend (
        sourceHandle: ContextHandle,
        targetHandle: ContextHandle,
        outletId: String,
        inputJson: String,
        identity: Identity,
        ucanToken: String,
        chainDepth: UByte,
        proofTokens: List<String>?,
    ) -> String,
    val sessionOpen: suspend (
        handle: ContextHandle,
        outletId: String,
        sourceContextId: String,
        ttlSeconds: ULong?,
    ) -> String,
    val sessionInvoke: suspend (
        handle: ContextHandle,
        sessionId: String,
        inputJson: String,
        identity: Identity,
        ucanToken: String,
        proofTokens: List<String>?,
    ) -> String,
    val sessionClose: suspend (handle: ContextHandle, sessionId: String) -> Unit,
    val interfaceOffer: suspend (
        handle: ContextHandle,
        outletId: String,
        targetContextId: String,
        rateLimitJson: String?,
    ) -> String,
    val interfaceAccept: suspend (handle: ContextHandle, interfaceJson: String) -> String,
    val interfaceRevoke: suspend (handle: ContextHandle, interfaceIdHex: String) -> String,
    val ucanValidate: suspend (
        handle: ContextHandle,
        token: String,
        capability: String,
        presentingAgentDid: String?,
        proofTokens: List<String>?,
    ) -> Unit,
    val streamTerminate: suspend (
        requestIdHex: String,
        callerDid: String,
        reason: uniffi.scp.TerminateReason,
        messageOverride: String?,
    ) -> Unit,
    val streamGrantCredit: suspend (requestIdHex: String, callerDid: String, grant: UInt) -> UInt,
    val streamCancel: suspend (requestIdHex: String, callerDid: String) -> ULong?,
) {
    companion object {
        /** Production bridge wiring — calls the real UniFFI exports. */
        val production: OutletBridgeFns =
            OutletBridgeFns(
                register = { handle, definition -> uniffi.scp.outletRegister(handle, definition) },
                get = { handle, outletId -> uniffi.scp.outletGet(handle, outletId) },
                list = { handle -> uniffi.scp.outletList(handle) },
                verify = { handle, outletId -> uniffi.scp.outletVerify(handle, outletId) },
                update = { handle, outletId, definition, updaterDid ->
                    uniffi.scp.outletUpdate(handle, outletId, definition, updaterDid)
                },
                deregister = { handle, outletId, actorDid ->
                    uniffi.scp.outletDeregister(handle, outletId, actorDid)
                },
                invoke = { handle, outletId, inputJson, identity, ucanToken, proofTokens, spendingUcanJwt ->
                    uniffi.scp.outletInvoke(
                        handle,
                        outletId,
                        inputJson,
                        identity,
                        ucanToken,
                        proofTokens,
                        spendingUcanJwt,
                    )
                },
                invokeStream = {
                        handle,
                        outletId,
                        inputJson,
                        identity,
                        ucanToken,
                        caveatsBindingHex,
                        streamEpoch,
                        proofTokens,
                        creditWindow,
                        estimatedChunkCount,
                        spendingUcan,
                    ->
                    UniffiStreamCursor(
                        uniffi.scp.outletInvokeStream(
                            handle,
                            outletId,
                            inputJson,
                            identity,
                            ucanToken,
                            caveatsBindingHex,
                            streamEpoch,
                            proofTokens,
                            creditWindow,
                            estimatedChunkCount,
                            spendingUcan,
                        ),
                    )
                },
                invokeCrossContext = {
                        sourceHandle,
                        targetHandle,
                        outletId,
                        inputJson,
                        identity,
                        ucanToken,
                        chainDepth,
                        proofTokens,
                    ->
                    uniffi.scp.outletInvokeCrossContext(
                        sourceHandle,
                        targetHandle,
                        outletId,
                        inputJson,
                        identity,
                        ucanToken,
                        chainDepth,
                        proofTokens,
                    )
                },
                sessionOpen = { handle, outletId, sourceContextId, ttlSeconds ->
                    uniffi.scp.outletSessionOpen(handle, outletId, sourceContextId, ttlSeconds)
                },
                sessionInvoke = { handle, sessionId, inputJson, identity, ucanToken, proofTokens ->
                    uniffi.scp.outletSessionInvoke(handle, sessionId, inputJson, identity, ucanToken, proofTokens)
                },
                sessionClose = { handle, sessionId -> uniffi.scp.outletSessionClose(handle, sessionId) },
                interfaceOffer = { handle, outletId, targetContextId, rateLimitJson ->
                    uniffi.scp.outletInterfaceOffer(handle, outletId, targetContextId, rateLimitJson)
                },
                interfaceAccept = { handle, interfaceJson -> uniffi.scp.outletInterfaceAccept(handle, interfaceJson) },
                interfaceRevoke = { handle, interfaceIdHex ->
                    uniffi.scp.outletInterfaceRevoke(handle, interfaceIdHex)
                },
                ucanValidate = { handle, token, capability, presentingAgentDid, proofTokens ->
                    uniffi.scp.ucanValidate(handle, token, capability, presentingAgentDid, proofTokens)
                },
                streamTerminate = { requestIdHex, callerDid, reason, messageOverride ->
                    uniffi.scp.outletStreamTerminate(requestIdHex, callerDid, reason, messageOverride)
                },
                streamGrantCredit = { requestIdHex, callerDid, grant ->
                    uniffi.scp.outletStreamGrantCredit(requestIdHex, callerDid, grant)
                },
                streamCancel = { requestIdHex, callerDid ->
                    uniffi.scp.outletStreamCancel(requestIdHex, callerDid)
                },
            )
    }
}

// ---------------------------------------------------------------------------
// Production OutletNamespace.
// ---------------------------------------------------------------------------

/**
 * Production [OutletNamespace] bound to a UniFFI [ContextHandle] and
 * [Identity]. Obtain via [outletNamespace].
 *
 * Default §5.4.5 receiver-side UCAN revocation re-check cadence (seconds)
 * when the caller does not override [ucanRecheckSecs] on [invoke]. The
 * runtime authoritatively snapshots `ContextParams::stream_ucan_recheck_secs`
 * at open; this SDK-side framework loop mirrors the other SDKs' default of
 * 10 seconds.
 */
internal class BridgeBackedOutletNamespace internal constructor(
    private val handle: ContextHandle,
    private val identity: Identity,
    private val bridge: OutletBridgeFns = OutletBridgeFns.production,
    private val defaultUcanRecheckSecs: UInt = DEFAULT_UCAN_RECHECK_SECS,
) : OutletNamespace {
    override val sessions: OutletSessionsNamespace =
        BridgeBackedOutletSessionsNamespace(handle, identity, bridge)
    override val offers: OutletOffersNamespace =
        BridgeBackedOutletOffersNamespace(handle, bridge)

    override suspend fun register(
        kind: OutletKind,
        definitionJson: String,
    ): String = bridge.register(handle, parseDefinition(kind, definitionJson))

    @Suppress("LongParameterList")
    override fun invoke(
        outletId: String,
        inputJson: String,
        ucanToken: String?,
        proofTokens: List<String>?,
        spendingUcan: String?,
        caveatsBindingHex: String?,
        streamEpoch: ULong?,
        creditWindow: UInt?,
        estimatedChunkCount: UInt?,
        aggregateSchemaJson: String?,
    ): InvocationHandle {
        // OUT-038 AC1 — streaming-mode params must be MUTUALLY supplied.
        if ((caveatsBindingHex == null) != (streamEpoch == null)) {
            throw OutletError.Validation(
                "streaming-mode invoke requires BOTH caveatsBindingHex (64 hex chars) " +
                    "and streamEpoch; pass them together or omit both for the degenerate " +
                    "single-shot path",
            )
        }
        return if (caveatsBindingHex != null && streamEpoch != null) {
            val validatedUcan = requireStreamingUcan(ucanToken)
            makeStreamingHandle(
                outletId = outletId,
                inputJson = inputJson,
                ucanToken = validatedUcan,
                caveatsBindingHex = caveatsBindingHex,
                streamEpoch = streamEpoch,
                proofTokens = proofTokens,
                creditWindow = creditWindow,
                estimatedChunkCount = estimatedChunkCount,
                spendingUcan = spendingUcan,
                aggregateSchemaJson = aggregateSchemaJson,
                ucanRecheckSecs = defaultUcanRecheckSecs,
            )
        } else {
            makeOneShotHandle(
                outletId = outletId,
                inputJson = inputJson,
                ucanToken = ucanToken,
                proofTokens = proofTokens,
                spendingUcan = spendingUcan,
                aggregateSchemaJson = aggregateSchemaJson,
            )
        }
    }

    override suspend fun update(
        outletId: String,
        definitionJson: String,
        updaterDid: String?,
    ): String =
        bridge.update(
            handle,
            outletId,
            parseDefinition(definitionJsonToKind(definitionJson), definitionJson),
            updaterDid ?: identity.did(),
        )

    override suspend fun get(outletId: String): String = bridge.get(handle, outletId)

    override suspend fun list(): List<String> = bridge.list(handle)

    override suspend fun verify(outletId: String): OutletVerificationSummary {
        val result = bridge.verify(handle, outletId)
        return OutletVerificationSummary(
            outletId = result.outletId,
            passed = result.passed,
            failures = result.failures,
        )
    }

    override suspend fun deregister(
        outletId: String,
        actorDid: String?,
    ) {
        bridge.deregister(handle, outletId, actorDid ?: identity.did())
    }

    override suspend fun invokeCrossContext(options: InvokeCrossContextOptions): String {
        // The cross-context call needs the TARGET context handle. The
        // production surface obtains it from the same context manager the
        // source handle is bound to; the bridge resolves the target by id.
        // Until a target-handle resolver is wired at the namespace layer,
        // the source handle doubles as the target lookup root (the bridge
        // validates the target context id from the UCAN audience).
        return bridge.invokeCrossContext(
            handle,
            handle,
            options.outletId.raw,
            options.inputJson,
            identity,
            options.ucan,
            options.chainDepth,
            options.proofTokens,
        )
    }

    // -- one-shot (degenerate single-chunk) --------------------------------

    @Suppress("LongParameterList")
    private fun makeOneShotHandle(
        outletId: String,
        inputJson: String,
        ucanToken: String?,
        proofTokens: List<String>?,
        spendingUcan: String?,
        aggregateSchemaJson: String?,
    ): InvocationHandle {
        val aggregateFn: suspend () -> Aggregate = {
            val output = bridge.invoke(handle, outletId, inputJson, identity, ucanToken, proofTokens, spendingUcan)
            Aggregate(valueJson = output, executionTimeMs = 0L)
        }
        val flowFn: () -> Flow<OutletStreamChunk> = {
            channelFlow {
                val output = bridge.invoke(handle, outletId, inputJson, identity, ucanToken, proofTokens, spendingUcan)
                send(
                    OutletStreamChunk.End(
                        requestId = ByteArray(16),
                        sequence = 0L,
                        aggregateJson = output,
                        executionTimeMs = 0L,
                    ),
                )
            }
        }
        return InvocationHandle(
            aggregateFn = aggregateFn,
            flowFn = flowFn,
            requestIdHex = null,
            invokerDid = null,
            aggregateSchemaJson = aggregateSchemaJson,
            grantCreditFn = bridge.streamGrantCredit,
            cancelFn = bridge.streamCancel,
        )
    }

    // -- streaming (§5.4.5) -------------------------------------------------

    @Suppress("LongParameterList")
    private fun makeStreamingHandle(
        outletId: String,
        inputJson: String,
        ucanToken: String,
        caveatsBindingHex: String,
        streamEpoch: ULong,
        proofTokens: List<String>?,
        creditWindow: UInt?,
        estimatedChunkCount: UInt?,
        spendingUcan: String?,
        aggregateSchemaJson: String?,
        ucanRecheckSecs: UInt,
    ): InvocationHandle {
        val invokerDid = identity.did()
        // The §5.4.5 open is `suspend`, but `invoke` returns the handle
        // synchronously. `StreamOpener` opens EAGERLY on a background
        // coroutine (see `eagerOpen()` below) and resolves a shared
        // `CompletableDeferred<OutletStreamCursor>` that the aggregate
        // path, the flow path, AND the request-id deferred all reuse — a
        // single open rather than racing to open the stream twice.
        // `request_id` is threaded into the handle via `requestIdDeferred`
        // so `grantCredit` / `cancel` await it before the terminal check,
        // even when the caller never consumes the chunk stream.
        val cursorDeferred = CompletableDeferred<OutletStreamCursor>()
        val requestIdDeferred = CompletableDeferred<String?>()
        val opener =
            StreamOpener(
                bridge = bridge,
                handle = handle,
                identity = identity,
                outletId = outletId,
                inputJson = inputJson,
                ucanToken = ucanToken,
                caveatsBindingHex = caveatsBindingHex,
                streamEpoch = streamEpoch,
                proofTokens = proofTokens,
                creditWindow = creditWindow,
                estimatedChunkCount = estimatedChunkCount,
                spendingUcan = spendingUcan,
                invokerDid = invokerDid,
                recheckSecs = ucanRecheckSecs,
                cursorDeferred = cursorDeferred,
                requestIdDeferred = requestIdDeferred,
            )
        // Open eagerly (background) so `grantCredit` / `cancel` and the
        // revocation re-check loop resolve independent of chunk
        // consumption — parity with the Swift / TS / Python factories.
        opener.eagerOpen()

        return buildStreamingInvocationHandle(
            open = opener::open,
            stopRecheck = opener::stopRecheck,
            requestIdDeferred = requestIdDeferred,
            invokerDid = invokerDid,
            aggregateSchemaJson = aggregateSchemaJson,
            grantCreditFn = bridge.streamGrantCredit,
            cancelFn = bridge.streamCancel,
        )
    }

    private fun parseDefinition(
        kind: OutletKind,
        definitionJson: String,
    ): uniffi.scp.OutletDefinition = outletDefinitionFromJson(kind, definitionJson)

    private fun definitionJsonToKind(definitionJson: String): OutletKind {
        val obj = runCatching { Json.parseToJsonElement(definitionJson).jsonObject }.getOrNull()
        val kindStr = (obj?.get("kind") as? JsonPrimitive)?.contentOrNull
        return if (kindStr != null) OutletKind.parse(kindStr) else OutletKind.ACTION
    }

    private fun requireStreamingUcan(ucanToken: String?): String =
        ucanToken ?: throw OutletError.Validation(
            "streaming-mode invoke requires ucanToken (the bridge re-runs the " +
                "11-step ADR-016 pipeline at open)",
            "SCP-VALID-7002",
        )

    internal companion object {
        /** §5.4.5 default receiver-side UCAN revocation re-check cadence. */
        const val DEFAULT_UCAN_RECHECK_SECS: UInt = 10u
    }
}

/**
 * Drives a single eager §5.4.5 stream open. The cursor and its
 * `request_id` are resolved exactly once and shared across the
 * aggregate / flow consumers and the control plane; the receiver-side
 * UCAN revocation re-check loop is launched on open and force-terminates
 * the stream on observed revocation (`RevokedMidStream` /
 * `SCP-TOOL-6110`). The open, the recheck loop, and any consumer share a
 * single [scope] that [stopRecheck] cancels at stream end.
 */
private class StreamOpener
    @Suppress("LongParameterList")
    constructor(
        private val bridge: OutletBridgeFns,
        private val handle: ContextHandle,
        private val identity: Identity,
        private val outletId: String,
        private val inputJson: String,
        private val ucanToken: String,
        private val caveatsBindingHex: String,
        private val streamEpoch: ULong,
        private val proofTokens: List<String>?,
        private val creditWindow: UInt?,
        private val estimatedChunkCount: UInt?,
        private val spendingUcan: String?,
        private val invokerDid: String,
        private val recheckSecs: UInt,
        private val cursorDeferred: CompletableDeferred<OutletStreamCursor>,
        private val requestIdDeferred: CompletableDeferred<String?>,
    ) {
        private val opened = java.util.concurrent.atomic.AtomicBoolean(false)
        private val terminated = java.util.concurrent.atomic.AtomicBoolean(false)

        /**
         * Scope owning the eager open + receiver-side revocation re-check
         * loop. Held so the consuming coroutine can cancel it via
         * [stopRecheck] once the stream reaches its terminal chunk (normal
         * end) — otherwise the `delay`-driven loop would outlive the stream
         * and leak a coroutine.
         */
        private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)

        /**
         * Kicks off the §5.4.5 stream open EAGERLY — once, at handle build
         * time — so the `request_id` deferred and the revocation re-check
         * loop resolve independent of stream consumption. This matches the
         * Swift / TypeScript / Python factories, all of which open in a
         * background task at `invoke()` time: a caller may `grantCredit` /
         * `cancel` BEFORE (or without) consuming the chunk stream and still
         * unblock on the runtime `request_id`. Idempotent — the
         * compareAndSet guard means a later [open] call reuses the same
         * cursor rather than opening twice.
         */
        fun eagerOpen() {
            scope.launch { runOpen() }
        }

        /**
         * Awaits the shared cursor, triggering the open if [eagerOpen] has
         * not already done so (defensive — the production path always calls
         * [eagerOpen] first). The open runs exactly once.
         */
        suspend fun open(): OutletStreamCursor {
            runOpen()
            return cursorDeferred.await()
        }

        /**
         * Performs the one-shot §5.4.5 open. On open failure the
         * `request_id` deferred resolves to `null` so control-plane callers
         * surface [StreamAlreadyClosed] rather than hanging, and the cursor
         * deferred completes exceptionally so consumers see the open error.
         */
        @Suppress("TooGenericExceptionCaught") // any open failure must resolve the deferred to null
        private suspend fun runOpen() {
            if (!opened.compareAndSet(false, true)) return
            try {
                val cursor =
                    bridge.invokeStream(
                        handle,
                        outletId,
                        inputJson,
                        identity,
                        ucanToken,
                        caveatsBindingHex,
                        streamEpoch,
                        proofTokens,
                        creditWindow,
                        estimatedChunkCount,
                        spendingUcan,
                    )
                requestIdDeferred.complete(cursor.requestId())
                cursorDeferred.complete(cursor)
                launchRecheckLoop(cursor.requestId())
            } catch (e: Throwable) {
                requestIdDeferred.complete(null)
                cursorDeferred.completeExceptionally(e)
            }
        }

        /**
         * §5.4.5 receiver-side revocation re-check. Per spec the SDK
         * framework MUST periodically re-check the opening UCAN's revocation
         * status during the stream's active lifetime, every
         * `stream_ucan_recheck_secs`, and on observed revocation MUST
         * terminate the stream with `RevokedMidStream` / `SCP-TOOL-6110`.
         * Mirrors the Python / TypeScript / Swift recheck loops.
         */
        private fun launchRecheckLoop(requestIdHex: String) {
            val capability = "tool_invoke:$outletId"
            val intervalMs = recheckSecs.coerceAtLeast(1u).toLong() * 1000L
            scope.launch {
                // Loop exits via the guard only — `terminated` flips on
                // revocation (below) or on `stopRecheck()` (stream end), so
                // no in-body `break` is needed.
                while (isActive && !terminated.get()) {
                    delay(intervalMs)
                    if (terminated.get()) continue
                    try {
                        bridge.ucanValidate(handle, ucanToken, capability, null, proofTokens)
                    } catch (_: Throwable) {
                        // Any validation failure signals the token is no
                        // longer authorized — terminate with the spec's
                        // RevokedMidStream reason. Terminate is idempotent
                        // on the runtime side, so AlreadyTerminated /
                        // AlreadyPending stop the loop either way. Flipping
                        // `terminated` makes the `while` guard exit on the
                        // next iteration.
                        terminated.set(true)
                        runCatching {
                            bridge.streamTerminate(
                                requestIdHex,
                                invokerDid,
                                uniffi.scp.TerminateReason.REVOKED_MID_STREAM,
                                "ucan revoked or invalid mid-stream",
                            )
                        }
                    }
                }
            }
        }

        /**
         * Stops the receiver-side revocation re-check loop. Called from the
         * consuming coroutine's `finally` once the stream reaches its
         * terminal chunk (or the collector is cancelled) so the loop does
         * not outlive the stream. Idempotent — safe to call when the loop
         * was never launched (open failed) or already torn down.
         */
        fun stopRecheck() {
            terminated.set(true)
            scope.cancel()
        }
    }

/**
 * Assembles the streaming-mode production [InvocationHandle] from the
 * cdylib-independent primitives: a lazy stream [open] (resolving the
 * cursor + `request_id` exactly once), a [stopRecheck] teardown, the
 * deferred `request_id` carrier, the pinned [invokerDid], and the
 * injectable [grantCreditFn] / [cancelFn] control-plane calls.
 *
 * Extracted from [BridgeBackedOutletNamespace.makeStreamingHandle] so
 * the production control plane (deferred-`request_id` threading +
 * `grantCredit` / `cancel` reaching the bridge + recheck teardown) is
 * unit-testable against a fake cursor and fake control-plane functions
 * without the compiled UniFFI `ContextHandle` / `Identity`. Both
 * consumer paths wrap consumption in `try { … } finally { stopRecheck() }`
 * so the §5.4.5 revocation re-check loop never outlives the stream.
 */
@Suppress("LongParameterList")
internal fun buildStreamingInvocationHandle(
    open: suspend () -> OutletStreamCursor,
    stopRecheck: () -> Unit,
    requestIdDeferred: kotlinx.coroutines.Deferred<String?>,
    invokerDid: String,
    aggregateSchemaJson: String?,
    grantCreditFn: suspend (requestIdHex: String, callerDid: String, grant: UInt) -> UInt,
    cancelFn: suspend (requestIdHex: String, callerDid: String) -> ULong?,
): InvocationHandle {
    val flowFn: () -> Flow<OutletStreamChunk> = {
        channelFlow {
            try {
                val cursor = open()
                outletStreamFlowFromNext { cursor.next() }.collect { data ->
                    send(data.toSdkChunk())
                }
            } finally {
                // Stream consumption ended (terminal chunk, abnormal
                // closure, or collector cancellation) — tear down the
                // receiver-side revocation re-check loop so it does not
                // outlive the stream. Mirrors the Swift
                // `defer { recheckTask.cancel() }` and the Python loop's
                // `handle.is_terminated` exit condition.
                stopRecheck()
            }
        }
    }
    val aggregateFn: suspend () -> Aggregate = {
        try {
            drainToAggregate(open())
        } finally {
            stopRecheck()
        }
    }
    return InvocationHandle(
        aggregateFn = aggregateFn,
        flowFn = flowFn,
        requestIdHex = null,
        invokerDid = invokerDid,
        aggregateSchemaJson = aggregateSchemaJson,
        requestIdDeferred = requestIdDeferred,
        grantCreditFn = grantCreditFn,
        cancelFn = cancelFn,
    )
}

// ---------------------------------------------------------------------------
// Sub-namespaces (production, bridge-backed).
// ---------------------------------------------------------------------------

private class BridgeBackedOutletSessionsNamespace(
    private val handle: ContextHandle,
    private val identity: Identity,
    private val bridge: OutletBridgeFns,
) : OutletSessionsNamespace {
    override suspend fun open(
        outletId: String,
        sourceContextId: String,
        ttlSeconds: ULong?,
    ): SessionId {
        val raw = bridge.sessionOpen(handle, outletId, sourceContextId, ttlSeconds)
        // Validate only when the bridge returns a canonical UUIDv7; accept
        // legacy non-UUIDv7 ids transparently (mirrors the Swift SDK).
        if (SESSION_ID_REGEX.matches(raw)) {
            SessionId.validate(raw)
        }
        return SessionId(raw)
    }

    override suspend fun invoke(
        sessionId: SessionId,
        inputJson: String,
        ucanToken: String,
        proofTokens: List<String>?,
    ): String = bridge.sessionInvoke(handle, sessionId.raw, inputJson, identity, ucanToken, proofTokens)

    override suspend fun close(sessionId: SessionId) {
        bridge.sessionClose(handle, sessionId.raw)
    }
}

private class BridgeBackedOutletOffersNamespace(
    private val handle: ContextHandle,
    private val bridge: OutletBridgeFns,
) : OutletOffersNamespace {
    override suspend fun propose(
        outletId: String,
        targetContextId: String,
        rateLimitJson: String?,
    ): String = bridge.interfaceOffer(handle, outletId, targetContextId, rateLimitJson)

    override suspend fun accept(interfaceJson: String): String = bridge.interfaceAccept(handle, interfaceJson)

    override suspend fun revoke(interfaceIdHex: String): String = bridge.interfaceRevoke(handle, interfaceIdHex)

    /**
     * The bridge does not expose an offer-listing primitive; offers are
     * visible via the context's event log. Returns an empty list as a
     * stable no-op at the SDK layer (mirrors the Swift SDK).
     */
    override suspend fun list(): List<String> = emptyList()
}

// ---------------------------------------------------------------------------
// Production entry point + helpers.
// ---------------------------------------------------------------------------

/**
 * Construct the production [OutletNamespace] for a context.
 *
 * Binds the namespace to the UniFFI [ContextHandle] and the invoker
 * [Identity]; every verb routes through the real `uniffi.scp.outlet*`
 * exports. Streaming `invoke(...)` opens real §5.4.5 streams and the
 * returned [InvocationHandle]'s `grantCredit` / `cancel` reach the
 * runtime control plane.
 */
fun outletNamespace(
    handle: ContextHandle,
    identity: Identity,
): OutletNamespace = BridgeBackedOutletNamespace(handle, identity)

/** Maps a UniFFI chunk record to the SDK-shaped sealed [OutletStreamChunk]. */
private fun OutletStreamChunkData.toSdkChunk(): OutletStreamChunk =
    when (payloadType) {
        "data" ->
            OutletStreamChunk.Data(
                requestId = requestId,
                sequence = sequence.toLong(),
                valueJson = valueJson ?: "null",
            )
        "progress" ->
            OutletStreamChunk.Progress(
                requestId = requestId,
                sequence = sequence.toLong(),
                pct = pct ?: 0u,
                note = note,
            )
        "end" ->
            OutletStreamChunk.End(
                requestId = requestId,
                sequence = sequence.toLong(),
                aggregateJson = aggregateJson ?: "null",
                executionTimeMs = (executionTimeMs ?: 0u).toLong(),
            )
        "error" ->
            OutletStreamChunk.Error(
                requestId = requestId,
                sequence = sequence.toLong(),
                code = code ?: "SCP-TOOL-6200",
                message = message ?: "",
                terminal = terminal ?: false,
            )
        else ->
            OutletStreamChunk.Error(
                requestId = requestId,
                sequence = sequence.toLong(),
                code = "SCP-TOOL-6200",
                message = "unknown chunk payload type: $payloadType",
                terminal = true,
            )
    }

/** Maps a UniFFI chunk record to the abnormal-closure flow source shape. */
private fun OutletStreamChunkRecord.toSource(): StreamChunkSource =
    StreamChunkSource(
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

/**
 * Drains the cursor to its terminal chunk, returning the End aggregate.
 * Reuses [outletStreamFlowFromNext]'s abnormal-closure contract
 * (`SCP-TOOL-6131`, no slug) and surfaces a terminal Error chunk as an
 * [ExecutionError].
 */
private suspend fun drainToAggregate(cursor: OutletStreamCursor): Aggregate {
    var aggregate: Aggregate? = null
    outletStreamFlowFromNext { cursor.next() }.collect { data ->
        when (data.payloadType) {
            "end" ->
                aggregate =
                    Aggregate(
                        valueJson = data.aggregateJson ?: "null",
                        executionTimeMs = (data.executionTimeMs ?: 0u).toLong(),
                    )
            "error" ->
                if (data.terminal == true) {
                    throw ExecutionError(
                        message = data.message ?: "stream terminated with error",
                        code = data.code ?: "SCP-TOOL-6130",
                    )
                }
            else -> Unit
        }
    }
    return aggregate ?: throw ExecutionError(
        message = "stream closed without terminal chunk",
        code = "SCP-TOOL-6131",
    )
}

/**
 * Build the UniFFI [uniffi.scp.OutletDefinition] record from the SDK's
 * `(kind, definitionJson)` register surface. The JSON body carries the
 * non-kind fields; `kind` comes from the typed argument (SCP-OUT-017).
 */
private fun outletDefinitionFromJson(
    kind: OutletKind,
    definitionJson: String,
): uniffi.scp.OutletDefinition {
    val obj: JsonObject =
        runCatching { Json.parseToJsonElement(definitionJson).jsonObject }
            .getOrElse {
                throw OutletError.Validation(
                    "outlet definition must be a JSON object, got: $definitionJson",
                    "SCP-VALID-7010",
                )
            }

    fun str(key: String): String? = (obj[key] as? JsonPrimitive)?.takeIf { it.isString }?.contentOrNull

    fun rawJson(key: String): String? = obj[key]?.toString()

    val name =
        str("name")
            ?: throw OutletError.Validation("outlet definition missing required field 'name'", "SCP-VALID-7010")

    return uniffi.scp.OutletDefinition(
        name = name,
        description = str("description") ?: "",
        kind = kind.toUniffi(),
        inputSchemaJson = rawJson("inputSchema") ?: rawJson("inputSchemaJson") ?: "{}",
        outputSchemaJson = rawJson("outputSchema") ?: rawJson("outputSchemaJson") ?: "{}",
        operatorDid = str("operatorDid") ?: "",
        testVectorsJson = rawJson("testVectors") ?: rawJson("testVectorsJson"),
        implementationHash = null,
        cost = null,
    )
}

/** Maps the SDK [OutletKind] to the UniFFI-generated enum. */
private fun OutletKind.toUniffi(): uniffi.scp.OutletKind =
    when (this) {
        OutletKind.QUERY -> uniffi.scp.OutletKind.QUERY
        OutletKind.ACTION -> uniffi.scp.OutletKind.ACTION
    }
