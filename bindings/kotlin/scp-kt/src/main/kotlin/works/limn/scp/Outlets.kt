// Outlets.kt — SCP-OUT-006 Kotlin outlet surface.
//
// Exposes the OutletNamespace interface and its sub-interfaces
// (OutletSessionsNamespace, OutletOffersNamespace), the SessionId
// value-class newtype, the Caveats builder namespace, and the
// InvocationHandle dual-mode handle (aggregate() + asFlow()).
//
// Error-code prefix remains SCP-TOOL-* (§9.18 — registered namespace);
// only the vocabulary at the class/method level is outlet-renamed.

@file:Suppress("TooManyFunctions")

package works.limn.scp

import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.channelFlow
import kotlinx.coroutines.flow.flow
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.doubleOrNull
import kotlinx.serialization.json.longOrNull
import java.security.SecureRandom

// ---------------------------------------------------------------------------
// SessionId — @JvmInline value-class newtype (API MAJOR 28).
// ---------------------------------------------------------------------------

internal val SESSION_ID_REGEX =
    Regex("^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")

private const val UUID7_SKEW_TOLERANCE_MS: Long = 10L * 60L * 1000L

/**
 * A UUIDv7-format session identifier, distinct at the type level from
 * [OutletId] / [DID] / raw [String]. Enforced by the Kotlin `@JvmInline`
 * value-class — the compiler rejects passing a `String` where a
 * `SessionId` is required at compile time (API MAJOR 28).
 *
 * Use [SessionId.of] to validate an incoming string or [newSessionId] to
 * mint a fresh one.
 */
@JvmInline
value class SessionId(val raw: String) {
    companion object {
        /**
         * Parse [raw] after UUIDv7 + timestamp-window validation.
         *
         * @throws IllegalArgumentException if [raw] is not a canonical
         *   UUIDv7 or the embedded 48-bit unix-ms timestamp is outside
         *   the ±10-minute clock-skew window (§9.14).
         */
        @JvmStatic
        fun of(
            raw: String,
            nowMs: Long = System.currentTimeMillis(),
        ): SessionId {
            validate(raw, nowMs)
            return SessionId(raw)
        }

        /** Validate `raw` without constructing a [SessionId]. */
        @JvmStatic
        fun validate(
            raw: String,
            nowMs: Long = System.currentTimeMillis(),
        ) {
            require(SESSION_ID_REGEX.matches(raw)) {
                "SessionId must be a canonical UUIDv7 (got $raw)"
            }
            val tsHex = raw.substring(0, 8) + raw.substring(9, 13)
            val tsMs = tsHex.toLong(16)
            require(tsMs >= nowMs - UUID7_SKEW_TOLERANCE_MS) {
                "SessionId timestamp $tsMs is more than 10 minutes in the past (now $nowMs)"
            }
            require(tsMs <= nowMs + UUID7_SKEW_TOLERANCE_MS) {
                "SessionId timestamp $tsMs is more than 10 minutes in the future (now $nowMs)"
            }
        }
    }
}

/**
 * Mint a fresh UUIDv7 [SessionId] using [SecureRandom] for the 74
 * random bits (rand_b). Pure CSPRNG — no DID-derived material, no
 * monotonic counter.
 */
fun newSessionId(now: Long = System.currentTimeMillis()): SessionId {
    val tsMs = now and ((1L shl 48) - 1L)
    val rand = ByteArray(10)
    SecureRandom().nextBytes(rand)
    val bytes = ByteArray(16)
    bytes[0] = ((tsMs shr 40) and 0xFFL).toByte()
    bytes[1] = ((tsMs shr 32) and 0xFFL).toByte()
    bytes[2] = ((tsMs shr 24) and 0xFFL).toByte()
    bytes[3] = ((tsMs shr 16) and 0xFFL).toByte()
    bytes[4] = ((tsMs shr 8) and 0xFFL).toByte()
    bytes[5] = (tsMs and 0xFFL).toByte()
    bytes[6] = (0x70.toByte().toInt() or (rand[0].toInt() and 0x0F)).toByte()
    bytes[7] = rand[1]
    bytes[8] = (0x80.toByte().toInt() or (rand[2].toInt() and 0x3F)).toByte()
    bytes[9] = rand[3]
    for (i in 0 until 6) {
        bytes[10 + i] = rand[4 + i]
    }
    val hex = bytes.joinToString("") { "%02x".format(it) }
    val raw =
        "${hex.substring(0, 8)}-${hex.substring(8, 12)}-" +
            "${hex.substring(12, 16)}-${hex.substring(16, 20)}-${hex.substring(20, 32)}"
    return SessionId(raw)
}

/** Distinct `DID` value class — prevents DID / OutletId swap at compile time. */
@JvmInline
value class DID(val raw: String)

// `OutletId` (a branded newtype) is defined in `Errors.kt` so the
// §5.4.4 sealed error hierarchy and the OUT-031 round-6 swap-risk fix
// can share a single canonical declaration. Re-importing it here is
// not necessary because both definitions live in the same package.

/**
 * Outlet semantic class (§5.4.2).
 *
 * `QUERY` outlets are read-only and idempotent (UCAN stem
 * `outlet_query:{id}`); `ACTION` outlets may mutate state (UCAN stem
 * `outlet_call:{id}`).
 *
 * SCP-OUT-017 makes this REQUIRED at the SDK surface across all 4
 * bindings. Crosses the wire as the lowercase string `"query"` /
 * `"action"` matching the §5.4.2 wire vocabulary.
 */
enum class OutletKind(val wire: String) {
    QUERY("query"),
    ACTION("action"),
    ;

    companion object {
        /** Parse the lowercase wire form ("query" / "action") into an [OutletKind]. */
        @JvmStatic
        fun parse(value: String): OutletKind =
            when (value) {
                "query" -> QUERY
                "action" -> ACTION
                else -> throw IllegalArgumentException(
                    "OutletKind must be 'query' or 'action' (§5.4.2 wire vocabulary), got $value",
                )
            }
    }
}

// ---------------------------------------------------------------------------
// Streaming + caveats (§5.4.5, §7.3.8)
// ---------------------------------------------------------------------------

/** One chunk of a streamed outlet invocation (§5.4.5). */
sealed class OutletStreamChunk {
    abstract val requestId: ByteArray
    abstract val sequence: Long

    data class Data(
        override val requestId: ByteArray,
        override val sequence: Long,
        val valueJson: String,
    ) : OutletStreamChunk()

    data class Progress(
        override val requestId: ByteArray,
        override val sequence: Long,
        val pct: UShort,
        val note: String?,
    ) : OutletStreamChunk()

    data class End(
        override val requestId: ByteArray,
        override val sequence: Long,
        val aggregateJson: String,
        val executionTimeMs: Long,
    ) : OutletStreamChunk()

    data class Error(
        override val requestId: ByteArray,
        override val sequence: Long,
        val code: String,
        val message: String,
        val terminal: Boolean,
    ) : OutletStreamChunk()
}

/** The collected aggregate returned by [InvocationHandle.aggregate]. */
data class Aggregate(
    val valueJson: String,
    val executionTimeMs: Long? = null,
)

/** Narrowed UCAN invocation caveats (§7.3.8, 11 fields + originKind). */
data class InvocationCaveats(
    val amountMaxPerCall: Long? = null,
    val amountMaxCumulative: Long? = null,
    val validFrom: Long? = null,
    val validUntil: Long? = null,
    val hoursOfDay: UInt? = null,
    val daysOfWeek: UByte? = null,
    val maxCalls: UInt? = null,
    val rateWindow: UInt? = null,
    val inputSchemaJson: String? = null,
    val allowedAdapters: List<String>? = null,
    val allowedTargetDids: List<String>? = null,
    val originKind: String? = null,
) {
    /**
     * Serializes this record to its canonical wire JSON form (§7.3.8
     * vocabulary). Field naming matches the wire layer verbatim
     * (camelCase). Absent fields are omitted. `inputSchemaJson` is
     * embedded as a parsed JSON object. `rateWindow` is wrapped into the
     * full `{max:1, windowSecs:N}` form because the SDK uses a
     * single-int convenience while the Rust `RateWindow` deserializer
     * requires both keys.
     *
     * Used by [UcanNamespace.mint] and [UcanNamespace.narrow]
     * (SCP-OUT-023).
     */
    @Suppress("CyclomaticComplexMethod", "LongMethod")
    fun toWireJson(): String {
        val parts = mutableListOf<String>()
        amountMaxPerCall?.let { parts += """"amountMaxPerCall":$it""" }
        amountMaxCumulative?.let { parts += """"amountMaxCumulative":$it""" }
        validFrom?.let { parts += """"validFrom":$it""" }
        validUntil?.let { parts += """"validUntil":$it""" }
        hoursOfDay?.let { parts += """"hoursOfDay":${it.toLong()}""" }
        daysOfWeek?.let { parts += """"daysOfWeek":${it.toShort()}""" }
        maxCalls?.let { parts += """"maxCalls":${it.toLong()}""" }
        rateWindow?.let { parts += """"rateWindow":{"max":1,"windowSecs":${it.toLong()}}""" }
        inputSchemaJson?.let { parts += """"inputSchema":$it""" }
        allowedAdapters?.let {
            val esc = it.joinToString(",") { s -> "\"${s.replace("\"", "\\\"")}\"" }
            parts += """"allowedAdapters":[$esc]"""
        }
        allowedTargetDids?.let {
            val esc = it.joinToString(",") { s -> "\"${s.replace("\"", "\\\"")}\"" }
            parts += """"allowedTargetDids":[$esc]"""
        }
        originKind?.let { parts += """"originKind":"$it"""" }
        return "{${parts.joinToString(",")}}"
    }
}

// ---------------------------------------------------------------------------
// Caveat builder helpers (review item 33).
// ---------------------------------------------------------------------------

class CaveatBuilder {
    private var fields = InvocationCaveats()

    fun spendingCap(
        perCall: Long? = null,
        cumulative: Long? = null,
    ): CaveatBuilder {
        fields =
            fields.copy(
                amountMaxPerCall = perCall ?: fields.amountMaxPerCall,
                amountMaxCumulative = cumulative ?: fields.amountMaxCumulative,
            )
        return this
    }

    fun timeBounded(
        validFrom: Long? = null,
        validUntil: Long? = null,
        hoursOfDay: UInt? = null,
        daysOfWeek: UByte? = null,
    ): CaveatBuilder {
        hoursOfDay?.let {
            require(it.toLong() < (1L shl 24)) {
                "hoursOfDay must be a 24-bit bitmask, got $it"
            }
        }
        daysOfWeek?.let {
            require(it.toInt() < (1 shl 7)) {
                "daysOfWeek must be a 7-bit bitmask, got $it"
            }
        }
        fields =
            fields.copy(
                validFrom = validFrom ?: fields.validFrom,
                validUntil = validUntil ?: fields.validUntil,
                hoursOfDay = hoursOfDay ?: fields.hoursOfDay,
                daysOfWeek = daysOfWeek ?: fields.daysOfWeek,
            )
        return this
    }

    fun rateLimited(
        maxCalls: UInt? = null,
        rateWindow: UInt? = null,
    ): CaveatBuilder {
        fields =
            fields.copy(
                maxCalls = maxCalls ?: fields.maxCalls,
                rateWindow = rateWindow ?: fields.rateWindow,
            )
        return this
    }

    fun forTarget(
        allowedTargetDids: List<String>? = null,
        allowedAdapters: List<String>? = null,
    ): CaveatBuilder {
        fields =
            fields.copy(
                allowedTargetDids = allowedTargetDids ?: fields.allowedTargetDids,
                allowedAdapters = allowedAdapters ?: fields.allowedAdapters,
            )
        return this
    }

    fun inputSchema(jsonString: String): CaveatBuilder {
        fields = fields.copy(inputSchemaJson = jsonString)
        return this
    }

    fun originKind(kind: String): CaveatBuilder {
        require(kind == "Query" || kind == "Action") {
            "originKind must be 'Query' or 'Action', got $kind"
        }
        fields = fields.copy(originKind = kind)
        return this
    }

    fun build(): InvocationCaveats = fields
}

/**
 * Caveat helper namespace — reduces 11-field [InvocationCaveats] friction
 * at call sites (review item 33).
 */
object Caveats {
    fun spendingCap(
        perCall: Long? = null,
        cumulative: Long? = null,
    ): CaveatBuilder = CaveatBuilder().spendingCap(perCall, cumulative)

    fun timeBounded(
        validFrom: Long? = null,
        validUntil: Long? = null,
        hoursOfDay: UInt? = null,
        daysOfWeek: UByte? = null,
    ): CaveatBuilder = CaveatBuilder().timeBounded(validFrom, validUntil, hoursOfDay, daysOfWeek)

    fun rateLimited(
        maxCalls: UInt? = null,
        rateWindow: UInt? = null,
    ): CaveatBuilder = CaveatBuilder().rateLimited(maxCalls, rateWindow)

    fun forTarget(
        allowedTargetDids: List<String>? = null,
        allowedAdapters: List<String>? = null,
    ): CaveatBuilder = CaveatBuilder().forTarget(allowedTargetDids, allowedAdapters)

    fun builder(): CaveatBuilder = CaveatBuilder()
}

// ---------------------------------------------------------------------------
// OutletError — sealed class with structured subclasses.
// ---------------------------------------------------------------------------

/**
 * Outlet registration, invocation, or verification errors.
 *
 * Error-code prefix remains `SCP-TOOL-*` (§9.18).
 */
sealed class OutletError(message: String, val code: String) : RuntimeException(message) {
    class NotFound(message: String, code: String = "SCP-TOOL-6100") : OutletError(message, code)

    class ExecutionFailed(message: String, code: String = "SCP-TOOL-6200") : OutletError(message, code)

    class Validation(message: String, code: String = "SCP-VALID-7010") : OutletError(message, code)

    class Unauthorized(message: String, code: String = "SCP-PERM-3020") : OutletError(message, code)

    class Bridge(message: String, code: String = "SCP-TOOL-6000") : OutletError(message, code)

    /** Companion object exposes the §5.4.4 [`new`] keyword-only factory
     *  (defined as a Kotlin extension in `Errors.kt`). */
    companion object
}

// ---------------------------------------------------------------------------
// InvocationHandle — dual consumption (aggregate() + asFlow()).
// ---------------------------------------------------------------------------

/**
 * Handle returned by [OutletNamespace.invoke].
 *
 * Supports BOTH consumption patterns (API MAJOR 21, review item 32):
 *
 * * `val agg = handle.aggregate()` — suspends until the terminal `End`
 *   chunk is emitted; returns the aggregate value (validated against
 *   the registered `aggregateSchemaJson` per OUT-038 AC12).
 * * `handle.asFlow().collect { chunk -> ... }` — iterate chunks via
 *   [Flow]<[OutletStreamChunk]>. Per OUT-038 AC14 the flow yields the
 *   terminal `End` chunk too — 10 Data + End ⇒ 11 chunks observed.
 *
 * SCP-OUT-038 control plane (AC9-10): every handle exposes
 * `grantCredit(grant: Credit)` and `cancel()` suspend functions. When
 * the handle wraps a real §5.4.5 streaming session the methods route
 * to the UniFFI `outletStreamGrantCredit` / `outletStreamCancel`
 * exports. When the handle wraps a degenerate single-shot invocation
 * the End chunk arrives synchronously and the control-plane methods
 * raise [StreamAlreadyClosed] per AC13.
 *
 * Lifecycle guard (AC13): once a terminal chunk is observed via the
 * flow OR the aggregate await path, subsequent control-plane calls
 * raise [StreamAlreadyClosed].
 *
 * Implementations MUST buffer chunks so both APIs see the same stream;
 * a handle is expected to be consumed by only one API per invocation.
 *
 * Lifecycle / resource ownership ([AutoCloseable]): a streaming handle
 * owns a background coroutine scope running the §5.4.5 receiver-side
 * UCAN revocation re-check loop. Consuming the handle (via [aggregate]
 * or [asFlow]) tears that scope down on terminal observation. A caller
 * that opens a streaming handle for its CONTROL PLANE ONLY — e.g.
 * `invoke(...)` → `grantCredit(...)` → abandon, without ever consuming
 * the chunk stream — MUST [close] the handle (idiomatically via
 * `handle.use { ... }`) so the re-check scope and its `delay`-driven
 * polling do not leak for the process lifetime. [close] is idempotent
 * and safe to call alongside normal consumption.
 */
class InvocationHandle
    @Suppress("LongParameterList")
    internal constructor(
        private val aggregateFn: suspend () -> Aggregate,
        private val flowFn: () -> Flow<OutletStreamChunk>,
        private val requestIdHex: String? = null,
        /**
         * Pinned invoker DID. Threaded through to every control-plane
         * bridge call as `callerDid` so the bridge can verify against
         * its registry's pinned identity. CRITICAL #1 fix.
         */
        private val invokerDid: String? = null,
        private val aggregateSchemaJson: String? = null,
        /**
         * Deferred §5.4.5 `request_id` (32-char lowercase hex), resolved
         * once the streaming bridge open completes. `null` for handles that
         * already know their `request_id` at construction time (the literal
         * [requestIdHex] path) or for the non-streaming degenerate
         * single-shot path.
         *
         * The production streaming namespace returns the [InvocationHandle]
         * synchronously, before the `suspend outletInvokeStream` open
         * resolves, so the real `request_id` is not known at construction
         * time. The namespace passes an unresolved [CompletableDeferred] and
         * completes it from inside the eager OPEN coroutine as soon as
         * `outletInvokeStream` returns — not from a chunk pump (the Kotlin
         * chunk path is a cold `Flow`, pulled only on consumption).
         * [grantCredit] / [cancel] await it before the terminal-state check.
         * This closes the race deterministically — a caller may invoke
         * `grantCredit` / `cancel` immediately after `invoke()` returns
         * without losing to the bridge's first chunk. Mirrors the TypeScript
         * `requestIdPromise` and the Swift `RequestIdBox`.
         */
        private val requestIdDeferred: kotlinx.coroutines.Deferred<String?>? = null,
        /**
         * §5.4.5 credit-grant control-plane call. Defaults to the
         * UniFFI-backed [outletStreamGrantCredit] free function; the
         * production namespace wires this from its injectable
         * `OutletBridgeFns` seam so the control plane is testable without
         * the compiled cdylib. Mirrors the Swift `*Bridge` closure pattern.
         */
        private val grantCreditFn: suspend (requestIdHex: String, callerDid: String, grant: UInt) -> UInt =
            ::outletStreamGrantCredit,
        /**
         * §5.4.5 cancel control-plane call. Defaults to the UniFFI-backed
         * [outletStreamCancel] free function; injectable for the same
         * reason as [grantCreditFn].
         */
        private val cancelFn: suspend (requestIdHex: String, callerDid: String) -> ULong? =
            ::outletStreamCancel,
        /**
         * Teardown callback invoked exactly once by [close] (idempotent).
         * For streaming handles the production namespace wires this to the
         * [StreamOpener.stopRecheck] teardown so a caller that never
         * consumes the chunk stream can still release the receiver-side
         * revocation re-check scope. Defaults to a no-op for handles with
         * no background resource (the degenerate single-shot path and the
         * in-memory test namespace).
         */
        private val onClose: () -> Unit = {},
        /**
         * Invoked the first time the handle observes a terminal state —
         * via [aggregate], [asFlow] terminal-chunk observation, or
         * [close]. The production streaming namespace wires this to a
         * shared flag the receiver-side revocation re-check loop polls, so
         * the loop's lifetime binds to the HANDLE terminal state rather
         * than to a consumer's `finally`. Runs at most once.
         *
         * Because the Kotlin chunk path is a cold `Flow` (chunks are
         * pulled only when a consumer collects), an unconsumed streaming
         * handle has no background pump to drive it to a terminal chunk —
         * so its re-check loop is torn down by [close] / `use { }`, not by
         * a self-terminating eager pump. The exit-flag polling mirrors the
         * TypeScript `while (!sdkHandle.isTerminated)` loop only in the
         * exit CONDITION; what flips the flag for an unconsumed handle is
         * [close], not a pump.
         */
        private val onTerminalObserved: () -> Unit = {},
    ) : AutoCloseable {
        private val terminatedFlag = java.util.concurrent.atomic.AtomicBoolean(false)
        private val closedFlag = java.util.concurrent.atomic.AtomicBoolean(false)

        /**
         * Flips the terminal flag and, on the first transition, fires
         * [onTerminalObserved]. Idempotent — the callback runs at most
         * once regardless of how many paths observe the terminal state.
         */
        private fun markTerminated() {
            if (terminatedFlag.compareAndSet(false, true)) {
                onTerminalObserved()
            }
        }

        /**
         * Tracks the consumption mode chosen by the caller — one of
         * `"aggregate"` (the `aggregate()` await path) or `"stream"` (the
         * `asFlow()` iterator path). Per Python / TypeScript parity the two
         * styles are mutually exclusive: a handle backed by a single
         * underlying source cannot be drained twice. Calling the second
         * style raises [OutletProtocolError] with slug
         * `protocol.handle-double-consumed` and code `SCP-TOOL-6020`.
         *
         * `null` until the first `aggregate()` / `asFlow()` call wins the
         * compareAndSet race.
         */
        private val consumedMode = java.util.concurrent.atomic.AtomicReference<String?>(null)

        /** OUT-038 dual-consumption guard. Mirrors Python `_consumed` and
         *  TypeScript `consumed`. If the caller has already started consuming
         *  the handle in another mode, raise [OutletProtocolError]. */
        private fun guard(mode: String) {
            if (!consumedMode.compareAndSet(null, mode)) {
                val current = consumedMode.get()
                if (current != mode) {
                    throw OutletProtocolError(
                        message = "InvocationHandle already consumed as $current; cannot switch to $mode",
                        code = "SCP-TOOL-6020",
                        slug = "protocol.handle-double-consumed",
                    )
                }
            }
        }

        /** `true` once a terminal chunk has been observed (AC13). */
        val isTerminated: Boolean
            get() = terminatedFlag.get()

        /**
         * Releases the handle's background resources — for a streaming
         * handle, the §5.4.5 receiver-side revocation re-check scope.
         * Idempotent: the first call runs [onClose]; subsequent calls are
         * no-ops. Also flips the terminal flag so any later control-plane
         * call fail-closes with [StreamAlreadyClosed].
         *
         * A control-plane-only caller (open → `grantCredit` → abandon)
         * MUST call this — idiomatically `handle.use { ... }` — so the
         * re-check loop does not poll `ucanValidate` for the process
         * lifetime. Normal consumption (`aggregate()` / `asFlow()`) tears
         * the scope down on terminal observation, so calling [close]
         * afterward is harmless.
         */
        override fun close() {
            if (closedFlag.compareAndSet(false, true)) {
                markTerminated()
                onClose()
            }
        }

        /** Suspends until the terminal `End` chunk and returns the aggregate.
         *  Throws [OutletProtocolError] (slug `protocol.handle-double-consumed`)
         *  when the handle has already been iterated via [asFlow]. */
        suspend fun aggregate(): Aggregate {
            guard("aggregate")
            // Fail-closed if the handle was closed before consumption: an
            // UNBOUNDED control-plane-only stream that is close()d has no
            // terminal chunk, so draining it here would hang on cursor.next()
            // forever. Surface StreamAlreadyClosed instead — parity with the
            // TS / Swift / Python close() settlement (await after close
            // ERRORS, never hangs).
            if (closedFlag.get()) {
                throw StreamAlreadyClosed(
                    "handle closed before the stream produced a terminal chunk",
                )
            }
            val agg = aggregateFn()
            markTerminated()
            validateAggregate(agg)
            return agg
        }

        /** Returns a cold [Flow] over the outlet's chunks (§5.4.5). Per
         *  OUT-038 AC14 the flow yields the terminal End chunk; the flow
         *  is augmented with a side effect that flips the lifecycle flag
         *  on terminal observation so subsequent control-plane calls
         *  fail-fast with [StreamAlreadyClosed].
         *
         *  Throws [OutletProtocolError] (slug
         *  `protocol.handle-double-consumed`) when the handle has already
         *  been awaited via [aggregate]. The guard fires when the flow's
         *  cold builder is *collected* — not when [asFlow] itself returns —
         *  so callers may obtain the cold `Flow<...>` reference and only
         *  trip the guard at `.collect { }` time. */
        fun asFlow(): Flow<OutletStreamChunk> =
            flow {
                guard("stream")
                // Fail-closed if the handle was closed before collection —
                // an unbounded stream would otherwise block on cursor.next()
                // forever. Parity with the aggregate() close-guard above.
                if (closedFlag.get()) {
                    throw StreamAlreadyClosed(
                        "handle closed before the stream produced a terminal chunk",
                    )
                }
                flowFn().collect { chunk ->
                    if (chunk is OutletStreamChunk.End ||
                        (chunk is OutletStreamChunk.Error && chunk.terminal)
                    ) {
                        markTerminated()
                    }
                    emit(chunk)
                }
            }

        /**
         * SCP-OUT-038 AC9/AC11 — issues an additional credit grant for
         * the underlying §5.4.5 stream session.
         *
         * `grant` MUST be a typed [Credit] value; the Kotlin compiler
         * rejects passing a raw [UInt] where [Credit] is expected (AC10).
         * The [Credit] constructor itself raises [InvalidGrant] for
         * `raw == 0u` so the zero-rejection rule is uniform across SDKs.
         *
         * @throws StreamAlreadyClosed (AC13) when the stream has already
         *   emitted a terminal chunk.
         */
        suspend fun grantCredit(grant: Credit): UInt {
            val (rid, did) = preflightControlPlane("grantCredit")
            return grantCreditFn(rid, did, grant.raw)
        }

        /**
         * SCP-OUT-038 AC9 — cancels the active stream (§5.4.5 cancel-ack).
         *
         * CRITICAL #3 — `next_seq` is no longer accepted; the bridge
         * derives the canonical next-emission cursor from runtime state.
         *
         * @return Recorded cancel-ack sequence, or `null` when the stream
         *   had already reached a terminal chunk at the moment the cancel
         *   reached the runtime (idempotent per §5.4.5).
         * @throws StreamAlreadyClosed (AC13) when the stream has already
         *   emitted a terminal chunk.
         */
        suspend fun cancel(): ULong? {
            val (rid, did) = preflightControlPlane("cancel")
            return cancelFn(rid, did)
        }

        /**
         * Shared preflight for [grantCredit] and [cancel]. Verifies the
         * stream is still active, the registry holds a `request_id` for
         * this handle, and the pinned `invoker_did` is set; throws
         * [StreamAlreadyClosed] otherwise. Returning a `(rid, did)` pair
         * keeps each call site below the detekt `ThrowsCount` ceiling
         * without sacrificing the three discrete guards.
         *
         * Resolves the `request_id` BEFORE the terminal check — on the
         * streaming path the deferred completes once `outletInvokeStream`
         * returns, so awaiting here lets a caller invoke `grantCredit` /
         * `cancel` immediately after `invoke()` returns without racing the
         * bridge's first chunk. Mirrors the TypeScript `resolveRequestId()`
         * and the Swift `RequestIdBox.value()` await ordering.
         */
        @Suppress("ThrowsCount") // three discrete guards: terminated, request id present, invoker did present
        private suspend fun preflightControlPlane(verb: String): Pair<String, String> {
            // Prefer a literal request id; otherwise await the streaming-mode
            // deferred. `null` from either means the non-streaming path.
            val rid = requestIdHex ?: requestIdDeferred?.await()
            // Race-check terminated AFTER the await — a terminal chunk may
            // have arrived while we were waiting on the bridge open.
            if (terminatedFlag.get()) {
                throw StreamAlreadyClosed(
                    "$verb rejected: stream has already emitted a terminal chunk",
                )
            }
            val did = invokerDid
            if (rid == null) {
                throw StreamAlreadyClosed(
                    "$verb rejected: handle was opened without a streaming session " +
                        "(degenerate single-shot invoke; the End chunk arrived synchronously)",
                )
            }
            if (did == null) {
                throw StreamAlreadyClosed(
                    "$verb rejected: handle has no pinned invoker DID — bridge " +
                        "caller authentication unavailable",
                )
            }
            return rid to did
        }

        /**
         * SCP-OUT-038 AC12 — validate the End.aggregate payload against
         * the registered `aggregateSchemaJson`. No-op when no schema is
         * bound. The validator performs a structural pass-through (type
         * match + required fields) using `kotlinx.serialization.json`
         * (already a project dep) — the bridge has already validated at
         * registration time per §5.4.5; this SDK-side hook is defense in
         * depth.
         */
        @Suppress("CyclomaticComplexMethod", "ReturnCount", "ThrowsCount")
        private fun validateAggregate(agg: Aggregate) {
            val schemaJson = aggregateSchemaJson ?: return
            val schema =
                runCatching {
                    Json.parseToJsonElement(schemaJson)
                }.getOrNull() as? JsonObject ?: return
            val aggValue =
                runCatching {
                    Json.parseToJsonElement(agg.valueJson)
                }.getOrNull() ?: throw OutletProtocolError(
                    message = "End.aggregate is not valid JSON",
                    code = "SCP-TOOL-6140",
                    slug = "output.invalid-json",
                )
            val declaredType = (schema["type"] as? JsonPrimitive)?.contentOrNull
            if (!declaredType.isNullOrEmpty()) {
                val actual = jsonValueTypeName(aggValue)
                val matches =
                    declaredType == actual ||
                        (declaredType == "number" && actual == "integer") ||
                        (declaredType == "object" && actual == "object")
                if (!matches) {
                    throw OutletProtocolError(
                        message = "End.aggregate type '$actual' does not match aggregate_schema type '$declaredType'",
                        code = "SCP-TOOL-6140",
                        slug = "output.type-mismatch",
                    )
                }
            }
            val required = schema["required"] as? JsonArray
            val aggObj = aggValue as? JsonObject
            if (required != null && aggObj != null) {
                for (entry in required) {
                    val field =
                        (entry as? JsonPrimitive)?.contentOrNull
                            ?: continue
                    if (!aggObj.containsKey(field)) {
                        throw OutletProtocolError(
                            message = "End.aggregate missing required field '$field' per aggregate_schema",
                            code = "SCP-TOOL-6140",
                            slug = "output.missing-required-field",
                        )
                    }
                }
            }
        }

        private fun jsonValueTypeName(value: JsonElement): String {
            return when (value) {
                is JsonArray -> "array"
                is JsonObject -> "object"
                is JsonNull -> "null"
                is JsonPrimitive ->
                    when {
                        value.isString -> "string"
                        value.booleanOrNull != null -> "boolean"
                        value.longOrNull != null -> "integer"
                        value.doubleOrNull != null -> "number"
                        else -> "unknown"
                    }
            }
        }
    }

// ---------------------------------------------------------------------------
// OutletNamespace + sub-interfaces (public surface per AC22).
// ---------------------------------------------------------------------------

/**
 * `ctx.outlets` — the outlet surface for a Kotlin `Context`.
 *
 * Renamed from `OutletsApi` for cross-SDK parity (simplifier MAJOR 25).
 */
interface OutletNamespace {
    val sessions: OutletSessionsNamespace
    val offers: OutletOffersNamespace

    /**
     * Register an outlet in the context.
     *
     * SCP-OUT-017 makes `kind` a REQUIRED parameter (no default). The
     * caller MUST pass `kind = OutletKind.QUERY` or
     * `OutletKind.ACTION`; omitting it is a Kotlin compile error.
     *
     * @param kind Outlet semantic class (§5.4.2). REQUIRED.
     * @param definitionJson JSON definition body (without `kind`).
     */
    suspend fun register(
        kind: OutletKind,
        definitionJson: String,
    ): String

    /** Convenience: register an outlet with `kind = OutletKind.QUERY`. */
    suspend fun registerQuery(definitionJson: String): String = register(OutletKind.QUERY, definitionJson)

    /** Convenience: register an outlet with `kind = OutletKind.ACTION`. */
    suspend fun registerAction(definitionJson: String): String = register(OutletKind.ACTION, definitionJson)

    /**
     * Invoke an outlet — the SOLE public verb (SCP-OUT-038 AC1).
     *
     * Returns an [InvocationHandle] that exposes both
     * `handle.aggregate()` and `handle.asFlow()`, plus the SCP-OUT-038
     * control-plane methods `handle.grantCredit(...)` and
     * `handle.cancel()`.
     *
     * When [caveatsBindingHex] AND [streamEpoch] are both supplied,
     * the handle routes to the §5.4.5 streaming bridge
     * (`outletInvokeStream`); the resulting handle carries a real
     * `request_id` and `grantCredit` / `cancel` route to the runtime.
     * When either is absent, the handle uses the non-streaming bridge
     * (degenerate single-chunk per §5.4.5) and the lifecycle ends
     * synchronously — control-plane methods then raise
     * [StreamAlreadyClosed] per AC13.
     *
     * Parity with PyO3 / NAPI / Swift: the streaming-mode parameters
     * are MUTUALLY DEPENDENT — supplying one without the other is a
     * runtime [ScpException.Validation] at the bridge boundary.
     *
     * @param outletId Outlet to invoke.
     * @param inputJson JSON-encoded input matching the outlet's input
     *   schema.
     * @param ucanToken UCAN authorising the invocation. REQUIRED when
     *   [caveatsBindingHex] is supplied (the bridge re-runs the
     *   11-step ADR-016 pipeline at open).
     * @param proofTokens Optional encoded parent UCANs for delegation
     *   chain traversal (ADR-016 step 3).
     * @param spendingUcan Optional JWT-encoded spending-cap UCAN for
     *   paid outlets. Threaded through on BOTH paths: the single-shot
     *   bridge passes it to `outletInvoke`, and the streaming bridge
     *   passes it to `outletInvokeStream` (§5.4.5), where it bounds the
     *   per-action spend the credit-grant path may consume.
     * @param caveatsBindingHex 32-byte SHA-256 binding rendered as
     *   64-char lowercase hex. When supplied with [streamEpoch], opens
     *   a real streaming session.
     * @param streamEpoch Hosting context's MLS epoch counter at open
     *   acceptance. REQUIRED when [caveatsBindingHex] is supplied.
     * @param creditWindow Optional initial credit-window override;
     *   defaults to §5.4.5 `DEFAULT_CREDIT_WINDOW` when `null`.
     *   Streaming-mode only.
     * @param estimatedChunkCount Optional invoker-declared upper bound
     *   on billable Data chunks. Streaming-mode only.
     * @param aggregateSchemaJson Optional JSON Schema for the End
     *   chunk's `aggregate` value (§5.4.5). When supplied, the handle
     *   validates the End chunk's aggregate against this schema before
     *   resolving (AC12).
     */
    @Suppress("LongParameterList")
    fun invoke(
        outletId: String,
        inputJson: String,
        ucanToken: String? = null,
        proofTokens: List<String>? = null,
        spendingUcan: String? = null,
        caveatsBindingHex: String? = null,
        streamEpoch: ULong? = null,
        creditWindow: UInt? = null,
        estimatedChunkCount: UInt? = null,
        aggregateSchemaJson: String? = null,
    ): InvocationHandle

    suspend fun update(
        outletId: String,
        definitionJson: String,
        updaterDid: String? = null,
    ): String

    suspend fun get(outletId: String): String

    suspend fun list(): List<String>

    suspend fun verify(outletId: String): OutletVerificationSummary

    suspend fun deregister(
        outletId: String,
        actorDid: String? = null,
    )

    /**
     * Invoke an outlet in a target context (API MAJOR 22).
     *
     * Uses an options-builder form — the named parameters (target:
     * [DID], outletId: [OutletId], input: String, ucan: String) are
     * typed so the compiler rejects positional target/outletId swap.
     */
    suspend fun invokeCrossContext(options: InvokeCrossContextOptions): String
}

/** Options for [OutletNamespace.invokeCrossContext] (API MAJOR 22). */
data class InvokeCrossContextOptions(
    val target: DID,
    val outletId: OutletId,
    val inputJson: String,
    val ucan: String,
    val chainDepth: UByte = 0u,
    val proofTokens: List<String>? = null,
)

/** Summary result of [OutletNamespace.verify]. */
data class OutletVerificationSummary(
    val outletId: String,
    val passed: Boolean,
    val failures: List<String>,
)

/** `ctx.outlets.sessions` — stateful outlet sessions (§6.2.1.1). */
interface OutletSessionsNamespace {
    suspend fun open(
        outletId: String,
        sourceContextId: String,
        ttlSeconds: ULong? = null,
    ): SessionId

    suspend fun invoke(
        sessionId: SessionId,
        inputJson: String,
        ucanToken: String,
        proofTokens: List<String>? = null,
    ): String

    suspend fun close(sessionId: SessionId)
}

/** `ctx.outlets.offers` — cross-context outlet interface offers (§6.2.0.1). */
interface OutletOffersNamespace {
    suspend fun propose(
        outletId: String,
        targetContextId: String,
        rateLimitJson: String? = null,
    ): String

    suspend fun accept(interfaceJson: String): String

    suspend fun revoke(interfaceIdHex: String): String

    suspend fun list(): List<String>
}

// ---------------------------------------------------------------------------
// OutletNamespace implementations.
//
// - `BridgeBackedOutletNamespace` (in `OutletsBridge.kt`) is the
//   PRODUCTION implementation: it routes every verb through the UniFFI
//   `uniffi.scp.outlet*` exports, opens real §5.4.5 streams via
//   `outletInvokeStream`, and threads the runtime `request_id` + pinned
//   invoker DID into the production `InvocationHandle` so `grantCredit` /
//   `cancel` reach `outletStreamGrantCredit` / `outletStreamCancel`.
//   Obtain it via `outletNamespace(handle, identity)`.
// - `InMemoryOutletNamespace` (below) is a test/example stub: it returns
//   a synthesized End chunk and never opens a real stream.
// ---------------------------------------------------------------------------

/**
 * A minimal in-memory [OutletNamespace] used by tests and examples.
 * Production callers obtain an `OutletNamespace` from
 * [outletNamespace] (a bridge-backed [BridgeBackedOutletNamespace]).
 */
internal class InMemoryOutletNamespace(
    override val sessions: OutletSessionsNamespace = InMemoryOutletSessionsNamespace(),
    override val offers: OutletOffersNamespace = InMemoryOutletOffersNamespace(),
) : OutletNamespace {
    private val registry = mutableMapOf<String, String>()

    override suspend fun register(
        kind: OutletKind,
        definitionJson: String,
    ): String {
        // SCP-OUT-017: kind is required — embed the registered kind in the
        // stored JSON so callers see it round-tripped on the read paths.
        val id = "outlet-${registry.size + 1}"
        // Augment the JSON definition with a kind field, preserving the
        // body untouched. The in-memory impl is a stub for tests; a
        // production impl forwards (kind, definition) to UniFFI.
        registry[id] = "{\"kind\":\"${kind.wire}\",\"definition\":$definitionJson}"
        return id
    }

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
        // UCAN pre-check parity with the production namespace + the other
        // SDKs: streaming requires ucanToken (SCP-VALID-7002); the degenerate
        // one-shot path requires it too (SCP-VALID-7003 — the bridge's
        // context_outlet_invoke takes a REQUIRED non-null UCAN).
        if (caveatsBindingHex != null && streamEpoch != null) {
            ucanToken ?: throw OutletError.Validation(
                "streaming-mode invoke requires ucanToken (the bridge re-runs the " +
                    "11-step ADR-016 pipeline at open)",
                "SCP-VALID-7002",
            )
        } else {
            ucanToken ?: throw OutletError.Validation(
                "ucanToken is required for ctx.outlets.invoke()",
                "SCP-VALID-7003",
            )
        }
        // The in-memory namespace does not run the §5.4.5 streaming
        // bridge; it always returns a synthesized End chunk so tests
        // can drive aggregate / flow without a Rust backend. The real
        // production OutletNamespace impl (in `bridge/`) consumes the
        // streaming params and routes through `ffiOutletInvokeStream`.
        val registered = registry.containsKey(outletId)
        return InvocationHandle(
            aggregateFn = {
                if (!registered) throw OutletError.NotFound("outlet $outletId not found")
                Aggregate(valueJson = "{\"echo\":$inputJson}", executionTimeMs = 0L)
            },
            flowFn = {
                channelFlow {
                    if (!registered) {
                        throw OutletError.NotFound("outlet $outletId not found")
                    }
                    send(
                        OutletStreamChunk.End(
                            requestId = ByteArray(16),
                            sequence = 0L,
                            aggregateJson = "{\"echo\":$inputJson}",
                            executionTimeMs = 0L,
                        ),
                    )
                }
            },
            aggregateSchemaJson = aggregateSchemaJson,
        )
    }

    override suspend fun update(
        outletId: String,
        definitionJson: String,
        updaterDid: String?,
    ): String {
        require(registry.containsKey(outletId)) { "outlet $outletId not found" }
        registry[outletId] = definitionJson
        return outletId
    }

    override suspend fun get(outletId: String): String {
        return registry[outletId] ?: throw OutletError.NotFound("outlet $outletId not found")
    }

    override suspend fun list(): List<String> = registry.keys.toList()

    override suspend fun verify(outletId: String): OutletVerificationSummary =
        if (registry.containsKey(outletId)) {
            OutletVerificationSummary(outletId = outletId, passed = true, failures = emptyList())
        } else {
            throw OutletError.NotFound("outlet $outletId not found")
        }

    override suspend fun deregister(
        outletId: String,
        actorDid: String?,
    ) {
        registry.remove(outletId) ?: throw OutletError.NotFound("outlet $outletId not found")
    }

    override suspend fun invokeCrossContext(options: InvokeCrossContextOptions): String {
        return "{\"echo\":${options.inputJson}}"
    }
}

internal class InMemoryOutletSessionsNamespace : OutletSessionsNamespace {
    override suspend fun open(
        outletId: String,
        sourceContextId: String,
        ttlSeconds: ULong?,
    ): SessionId = newSessionId()

    override suspend fun invoke(
        sessionId: SessionId,
        inputJson: String,
        ucanToken: String,
        proofTokens: List<String>?,
    ): String = "{\"echo\":$inputJson}"

    override suspend fun close(sessionId: SessionId) = Unit
}

internal class InMemoryOutletOffersNamespace : OutletOffersNamespace {
    override suspend fun propose(
        outletId: String,
        targetContextId: String,
        rateLimitJson: String?,
    ): String = "{\"outlet_id\":\"$outletId\",\"target\":\"$targetContextId\"}"

    override suspend fun accept(interfaceJson: String): String = interfaceJson

    override suspend fun revoke(interfaceIdHex: String): String = "{\"revoked\":\"$interfaceIdHex\"}"

    override suspend fun list(): List<String> = emptyList()
}
