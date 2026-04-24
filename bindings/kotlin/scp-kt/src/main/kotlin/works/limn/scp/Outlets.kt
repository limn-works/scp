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

import java.security.SecureRandom
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.channelFlow

// ---------------------------------------------------------------------------
// SessionId — @JvmInline value-class newtype (API MAJOR 28).
// ---------------------------------------------------------------------------

private val SESSION_ID_REGEX =
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
        fun of(raw: String, nowMs: Long = System.currentTimeMillis()): SessionId {
            validate(raw, nowMs)
            return SessionId(raw)
        }

        /** Validate `raw` without constructing a [SessionId]. */
        @JvmStatic
        fun validate(raw: String, nowMs: Long = System.currentTimeMillis()) {
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
    val raw = "${hex.substring(0, 8)}-${hex.substring(8, 12)}-" +
        "${hex.substring(12, 16)}-${hex.substring(16, 20)}-${hex.substring(20, 32)}"
    return SessionId(raw)
}

/** Distinct `DID` value class — prevents DID / OutletId swap at compile time. */
@JvmInline
value class DID(val raw: String)

/** Distinct `OutletId` value class. */
@JvmInline
value class OutletId(val raw: String)

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

/** Narrowed UCAN invocation caveats (§7.3.8, 11 fields). */
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
)

// ---------------------------------------------------------------------------
// Caveat builder helpers (review item 33).
// ---------------------------------------------------------------------------

class CaveatBuilder {
    private var fields = InvocationCaveats()

    fun spendingCap(perCall: Long? = null, cumulative: Long? = null): CaveatBuilder {
        fields = fields.copy(
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
        fields = fields.copy(
            validFrom = validFrom ?: fields.validFrom,
            validUntil = validUntil ?: fields.validUntil,
            hoursOfDay = hoursOfDay ?: fields.hoursOfDay,
            daysOfWeek = daysOfWeek ?: fields.daysOfWeek,
        )
        return this
    }

    fun rateLimited(maxCalls: UInt? = null, rateWindow: UInt? = null): CaveatBuilder {
        fields = fields.copy(
            maxCalls = maxCalls ?: fields.maxCalls,
            rateWindow = rateWindow ?: fields.rateWindow,
        )
        return this
    }

    fun forTarget(
        allowedTargetDids: List<String>? = null,
        allowedAdapters: List<String>? = null,
    ): CaveatBuilder {
        fields = fields.copy(
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
    fun spendingCap(perCall: Long? = null, cumulative: Long? = null): CaveatBuilder =
        CaveatBuilder().spendingCap(perCall, cumulative)
    fun timeBounded(
        validFrom: Long? = null,
        validUntil: Long? = null,
        hoursOfDay: UInt? = null,
        daysOfWeek: UByte? = null,
    ): CaveatBuilder = CaveatBuilder().timeBounded(validFrom, validUntil, hoursOfDay, daysOfWeek)
    fun rateLimited(maxCalls: UInt? = null, rateWindow: UInt? = null): CaveatBuilder =
        CaveatBuilder().rateLimited(maxCalls, rateWindow)
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
 *   chunk is emitted; returns the aggregate value.
 * * `handle.asFlow().collect { chunk -> ... }` — iterate chunks via
 *   [Flow]<[OutletStreamChunk]>.
 *
 * Implementations MUST buffer chunks so both APIs see the same stream;
 * a handle is expected to be consumed by only one API per invocation.
 */
class InvocationHandle internal constructor(
    private val aggregateFn: suspend () -> Aggregate,
    private val flowFn: () -> Flow<OutletStreamChunk>,
) {
    /** Suspends until the terminal `End` chunk and returns the aggregate. */
    suspend fun aggregate(): Aggregate = aggregateFn()

    /** Returns a cold [Flow] over the outlet's chunks (§5.4.5). */
    fun asFlow(): Flow<OutletStreamChunk> = flowFn()
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

    suspend fun register(definitionJson: String): String
    fun invoke(
        outletId: String,
        inputJson: String,
        ucanToken: String? = null,
        proofTokens: List<String>? = null,
        spendingUcanJwt: String? = null,
    ): InvocationHandle
    suspend fun update(
        outletId: String,
        definitionJson: String,
        updaterDid: String? = null,
    ): String
    suspend fun get(outletId: String): String
    suspend fun list(): List<String>
    suspend fun verify(outletId: String): OutletVerificationSummary
    suspend fun deregister(outletId: String, actorDid: String? = null)

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
// SDK-level facade — wraps a plain UniFFI caller (in-memory tests or a
// host-supplied bridge) around the OutletNamespace interfaces.
//
// The real UniFFI-backed impl lives in works.limn.scp.bridge.ToolBridge —
// this facade gives a synchronous-looking entry point that honors the AC
// shape (namespace + sub-namespaces + verbs).
// ---------------------------------------------------------------------------

/**
 * A minimal in-memory [OutletNamespace] used by tests and examples.
 * Production callers obtain an `OutletNamespace` from their `Context`
 * instance.
 */
internal class InMemoryOutletNamespace(
    override val sessions: OutletSessionsNamespace = InMemoryOutletSessionsNamespace(),
    override val offers: OutletOffersNamespace = InMemoryOutletOffersNamespace(),
) : OutletNamespace {
    private val registry = mutableMapOf<String, String>()

    override suspend fun register(definitionJson: String): String {
        val id = "outlet-${registry.size + 1}"
        registry[id] = definitionJson
        return id
    }

    override fun invoke(
        outletId: String,
        inputJson: String,
        ucanToken: String?,
        proofTokens: List<String>?,
        spendingUcanJwt: String?,
    ): InvocationHandle {
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
                        )
                    )
                }
            },
        )
    }

    override suspend fun update(outletId: String, definitionJson: String, updaterDid: String?): String {
        require(registry.containsKey(outletId)) { "outlet $outletId not found" }
        registry[outletId] = definitionJson
        return outletId
    }

    override suspend fun get(outletId: String): String =
        registry[outletId] ?: throw OutletError.NotFound("outlet $outletId not found")

    override suspend fun list(): List<String> = registry.keys.toList()

    override suspend fun verify(outletId: String): OutletVerificationSummary =
        if (registry.containsKey(outletId)) {
            OutletVerificationSummary(outletId = outletId, passed = true, failures = emptyList())
        } else {
            throw OutletError.NotFound("outlet $outletId not found")
        }

    override suspend fun deregister(outletId: String, actorDid: String?) {
        registry.remove(outletId) ?: throw OutletError.NotFound("outlet $outletId not found")
    }

    override suspend fun invokeCrossContext(options: InvokeCrossContextOptions): String =
        "{\"echo\":${options.inputJson}}"
}

internal class InMemoryOutletSessionsNamespace : OutletSessionsNamespace {
    override suspend fun open(outletId: String, sourceContextId: String, ttlSeconds: ULong?): SessionId =
        newSessionId()

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
    override suspend fun revoke(interfaceIdHex: String): String =
        "{\"revoked\":\"$interfaceIdHex\"}"
    override suspend fun list(): List<String> = emptyList()
}
