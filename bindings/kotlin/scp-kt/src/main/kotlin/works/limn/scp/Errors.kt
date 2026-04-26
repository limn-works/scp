package works.limn.scp

/**
 * §5.4.4 Outlet error taxonomy — sealed Kotlin types.
 *
 * The pre-OUT-031 [OutletError] sealed class (in `Outlets.kt`) keeps its
 * legacy subclasses ([OutletError.NotFound], [OutletError.ExecutionFailed],
 * [OutletError.Validation], [OutletError.Unauthorized], [OutletError.Bridge])
 * for back-compat. SCP-OUT-031 adds the eight new sealed children for the
 * §5.4.4 sealed-hierarchy taxonomy ([OutletProtocolError],
 * [AuthorizationError], [InputError], [ExecutionError], [OutputError],
 * [EconomicError], [OutletTransportError], [OutletGovernanceError]) plus
 * branded newtypes ([Credit], [CatalogKey], [OutletId]) and supporting
 * value types.
 *
 * The new types live alongside the legacy ones in this file (rather than in
 * `Outlets.kt`) to keep the §5.4.4 taxonomy coherent in one place.
 */

// ---------------------------------------------------------------------------
// OutletErrorClass — eight wire-form variants per §5.4.4.
// ---------------------------------------------------------------------------

/**
 * Wire-form §5.4.4 [OutletErrorClass] discriminant — one of eight root
 * classes. Each [OutletError] subclass added by OUT-031 carries a
 * `classWire` field whose value matches one of these.
 */
enum class OutletErrorClass(val wire: String) {
    PROTOCOL("protocol"),
    AUTHORIZATION("authorization"),
    INPUT("input"),
    EXECUTION("execution"),
    OUTPUT("output"),
    ECONOMIC("economic"),
    TRANSPORT("transport"),
    GOVERNANCE("governance");

    companion object {
        fun fromWire(value: String): OutletErrorClass? =
            values().firstOrNull { it.wire == value }
    }
}

// ---------------------------------------------------------------------------
// RetryPolicy — sealed §5.4.4 tag-5 retry guidance.
// ---------------------------------------------------------------------------

sealed class RetryPolicy {
    object Never : RetryPolicy()
    object Immediate : RetryPolicy()
    data class After(val delayMs: ULong) : RetryPolicy()
    data class WithBackoff(val minMs: ULong, val maxMs: ULong) : RetryPolicy() {
        init {
            require(minMs > 0u && minMs <= maxMs) {
                "with-backoff requires 0 < min <= max"
            }
        }
    }
}

// ---------------------------------------------------------------------------
// ContextHop — §5.4.4 tag-8 source-chain entry.
// ---------------------------------------------------------------------------

data class ContextHop(
    val contextId: String,
    val hopIndex: UShort,
    val wrappedCode: String,
)

// ---------------------------------------------------------------------------
// Per-class detail — closed sealed type (free-form `detail` is forbidden).
// ---------------------------------------------------------------------------

sealed class OutletErrorDetail {
    data class ProtocolRule(val rule: String) : OutletErrorDetail()
    data class AuthorizationCapability(val capability: String) : OutletErrorDetail()
    data class FieldViolation(val fieldPath: String, val violation: String) : OutletErrorDetail()
    data class ExecutionTimeout(val elapsedMs: ULong) : OutletErrorDetail()
    data class ExecutionPanic(val panicLocationHash: String) : OutletErrorDetail()
    object ExecutionEmpty : OutletErrorDetail()
    data class EconomicInsufficient(val needed: ULong, val currency: String) : OutletErrorDetail()
    data class EconomicAdapter(val adapterId: String) : OutletErrorDetail()
    data class TransportRateLimit(val retryAfterSecs: UInt) : OutletErrorDetail()
    data class TransportRelay(val relayUrlKind: RelayUrlKind) : OutletErrorDetail() {
        enum class RelayUrlKind(val wire: String) {
            WSS("wss"), WS_LOOPBACK("ws-loopback"), UNKNOWN("unknown");
        }
    }
    data class GovernanceAction(val action: String) : OutletErrorDetail()

    /** Returns true if this detail variant is legal for [errorClass]. */
    fun matches(errorClass: OutletErrorClass): Boolean = when (errorClass) {
        OutletErrorClass.PROTOCOL -> this is ProtocolRule
        OutletErrorClass.AUTHORIZATION -> this is AuthorizationCapability
        OutletErrorClass.INPUT, OutletErrorClass.OUTPUT -> this is FieldViolation
        OutletErrorClass.EXECUTION ->
            this is ExecutionTimeout || this is ExecutionPanic || this is ExecutionEmpty
        OutletErrorClass.ECONOMIC ->
            this is EconomicInsufficient || this is EconomicAdapter
        OutletErrorClass.TRANSPORT ->
            this is TransportRateLimit || this is TransportRelay
        OutletErrorClass.GOVERNANCE -> this is GovernanceAction
    }
}

// ---------------------------------------------------------------------------
// Branded newtypes (Credit, CatalogKey, OutletId) — round-6 newtype pass.
// ---------------------------------------------------------------------------

/**
 * Branded newtype for an Outlet credit grant. Constructor rejects zero
 * with [InvalidGrant] under the [OutletError] hierarchy (round-6 unified
 * error type — replaces the round-5 `IllegalArgumentException`).
 */
@JvmInline
value class Credit(val raw: UInt) {
    init {
        require(raw > 0u) { "Credit must be > 0; use OutletError.InvalidGrant for the typed reject" }
    }
}

/**
 * Construct a [Credit] from a raw [UInt]. Throws [InvalidGrant] (under the
 * [OutletError] hierarchy) on `raw == 0u` so all four SDKs surface the same
 * exception class for the same condition.
 */
fun creditOf(raw: UInt): Credit {
    if (raw == 0u) throw InvalidGrant(raw)
    return Credit(raw)
}

/**
 * Branded newtype for §5.4.4 catalog keys.
 *
 * Companion factory regex-validates against
 * `^[a-z][a-z0-9-]{0,63}(\.[a-z][a-z0-9-]{0,63})*$` and the
 * `≤ 256` byte cap — failures throw [OutletProtocolError] under the
 * [OutletError] hierarchy.
 */
@JvmInline
value class CatalogKey(val raw: String) {
    companion object {
        private val PATTERN = Regex("""^[a-z][a-z0-9-]{0,63}(\.[a-z][a-z0-9-]{0,63})*$""")
        private const val MAX_BYTES = 256

        @JvmStatic
        fun of(raw: String): CatalogKey {
            if (raw.isEmpty() || raw.toByteArray(Charsets.UTF_8).size > MAX_BYTES) {
                throw OutletProtocolError(
                    message = "catalog key length out of range: ${'$'}{raw.length}",
                    code = "SCP-TOOL-6100",
                    slug = "protocol.malformed-catalog-key",
                )
            }
            if (!PATTERN.matches(raw)) {
                throw OutletProtocolError(
                    message = "malformed catalog key: ${'$'}raw",
                    code = "SCP-TOOL-6100",
                    slug = "protocol.malformed-catalog-key",
                )
            }
            return CatalogKey(raw)
        }
    }
}

/** Branded newtype for outlet ids. */
@JvmInline
value class OutletId(val raw: String) {
    companion object {
        @JvmStatic
        fun of(raw: String): OutletId {
            require(raw.isNotEmpty()) { "outletId must be non-empty" }
            return OutletId(raw)
        }
    }
}

// ---------------------------------------------------------------------------
// New §5.4.4 OutletError subclasses (sealed children of OutletError).
// ---------------------------------------------------------------------------
//
// `OutletError` (in Outlets.kt) is already a sealed class. Its old children
// (NotFound, ExecutionFailed, Validation, Unauthorized, Bridge) are kept
// verbatim for back-compat. The eight new children below extend it directly
// — Kotlin's `sealed class` permits subclasses defined in the same Gradle
// module (works.limn.scp), so adding these here is legal.

/**
 * Optional §5.4.4 envelope attributes carried by every typed
 * [OutletError] subclass. Bundled into one data class so the per-class
 * constructors stay short (detekt LongParameterList threshold = 7).
 */
data class OutletErrorAttributes(
    val slug: String? = null,
    val retry: RetryPolicy = RetryPolicy.Never,
    val detail: OutletErrorDetail? = null,
    val sourceChain: List<ContextHop> = emptyList(),
    val padNonce: ByteArray? = null,
    val registrationEventId: ByteArray? = null,
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false
        other as OutletErrorAttributes
        if (slug != other.slug) return false
        if (retry != other.retry) return false
        if (detail != other.detail) return false
        if (sourceChain != other.sourceChain) return false
        if (padNonce != null) {
            if (other.padNonce == null) return false
            if (!padNonce.contentEquals(other.padNonce)) return false
        } else if (other.padNonce != null) return false
        if (registrationEventId != null) {
            if (other.registrationEventId == null) return false
            if (!registrationEventId.contentEquals(other.registrationEventId)) return false
        } else if (other.registrationEventId != null) return false
        return true
    }

    override fun hashCode(): Int {
        var result = slug?.hashCode() ?: 0
        result = 31 * result + retry.hashCode()
        result = 31 * result + (detail?.hashCode() ?: 0)
        result = 31 * result + sourceChain.hashCode()
        result = 31 * result + (padNonce?.contentHashCode() ?: 0)
        result = 31 * result + (registrationEventId?.contentHashCode() ?: 0)
        return result
    }
}

/**
 * §5.4.4 `Protocol` class — registration / validation / classification.
 *
 * Named [OutletProtocolError] (not `ProtocolError`) to avoid collision with
 * the MLS protocol error symbol elsewhere in the SDK (round-6 collision-fix).
 */
open class OutletProtocolError(
    message: String,
    code: String = "SCP-TOOL-6100",
    val slug: String? = null,
    val retry: RetryPolicy = RetryPolicy.Never,
    val detail: OutletErrorDetail? = null,
    val sourceChain: List<ContextHop> = emptyList(),
) : OutletError(redactPii(message), code) {
    val classWire: OutletErrorClass = OutletErrorClass.PROTOCOL
}

class AuthorizationError(
    message: String,
    code: String = "SCP-TOOL-6110",
    val slug: String? = null,
    val retry: RetryPolicy = RetryPolicy.Never,
    val detail: OutletErrorDetail? = null,
    val sourceChain: List<ContextHop> = emptyList(),
) : OutletError(redactPii(message), code) {
    val classWire: OutletErrorClass = OutletErrorClass.AUTHORIZATION
}

class InputError(
    message: String,
    code: String = "SCP-TOOL-6120",
    val slug: String? = null,
    val retry: RetryPolicy = RetryPolicy.Never,
    val detail: OutletErrorDetail? = null,
    val sourceChain: List<ContextHop> = emptyList(),
) : OutletError(redactPii(message), code) {
    val classWire: OutletErrorClass = OutletErrorClass.INPUT
}

class ExecutionError(
    message: String,
    code: String = "SCP-TOOL-6130",
    val slug: String? = null,
    val retry: RetryPolicy = RetryPolicy.Never,
    val detail: OutletErrorDetail? = null,
    val sourceChain: List<ContextHop> = emptyList(),
) : OutletError(redactPii(message), code) {
    val classWire: OutletErrorClass = OutletErrorClass.EXECUTION
}

class OutputError(
    message: String,
    code: String = "SCP-TOOL-6140",
    val slug: String? = null,
    val retry: RetryPolicy = RetryPolicy.Never,
    val detail: OutletErrorDetail? = null,
    val sourceChain: List<ContextHop> = emptyList(),
) : OutletError(redactPii(message), code) {
    val classWire: OutletErrorClass = OutletErrorClass.OUTPUT
}

class EconomicError(
    message: String,
    code: String = "SCP-TOOL-6150",
    val slug: String? = null,
    val retry: RetryPolicy = RetryPolicy.Never,
    val detail: OutletErrorDetail? = null,
    val sourceChain: List<ContextHop> = emptyList(),
) : OutletError(redactPii(message), code) {
    val classWire: OutletErrorClass = OutletErrorClass.ECONOMIC
}

/**
 * §5.4.4 `Transport` class. Suffixed `Outlet` to disambiguate from any
 * top-level `TransportError`.
 */
class OutletTransportError(
    message: String,
    code: String = "SCP-TOOL-6160",
    val slug: String? = null,
    val retry: RetryPolicy = RetryPolicy.Never,
    val detail: OutletErrorDetail? = null,
    val sourceChain: List<ContextHop> = emptyList(),
) : OutletError(redactPii(message), code) {
    val classWire: OutletErrorClass = OutletErrorClass.TRANSPORT
}

/**
 * §5.4.4 `Governance` class. Suffixed `Outlet` to disambiguate from any
 * top-level `GovernanceError`.
 */
class OutletGovernanceError(
    message: String,
    code: String = "SCP-TOOL-6170",
    val slug: String? = null,
    val retry: RetryPolicy = RetryPolicy.Never,
    val detail: OutletErrorDetail? = null,
    val sourceChain: List<ContextHop> = emptyList(),
) : OutletError(redactPii(message), code) {
    val classWire: OutletErrorClass = OutletErrorClass.GOVERNANCE
}

/**
 * Round-6 unified zero-credit-grant rejection — surfaces under
 * [OutletProtocolError] so all four SDKs share an [OutletError]-rooted
 * exception class for the [Credit] zero-rejection rule (replaces the
 * round-5 [IllegalArgumentException]).
 */
class InvalidGrant(val grant: UInt) : OutletProtocolError(
    message = "invalid grant ${'$'}grant: must be in (0, 2^32 - 1]",
    code = "SCP-TOOL-6101",
    slug = "protocol.invalid-grant",
)

// ---------------------------------------------------------------------------
// Options-object input for OutletError.new — round-6 swap-risk fix.
// ---------------------------------------------------------------------------

data class OutletErrorNewOptions(
    val outletId: OutletId,
    val catalogKey: CatalogKey,
    val errorClass: OutletErrorClass,
    val code: String? = null,
    val slug: String? = null,
    val retry: RetryPolicy = RetryPolicy.Never,
    val detail: OutletErrorDetail? = null,
)

/**
 * Companion-style factory `OutletError.new(opts)` — keyword-only via the
 * data-class options. The pre-redesign `OutletError(message, code)` ctor
 * remains for back-compat callers; round-6 mandates options-object for new
 * code so adjacent string fields cannot be swapped at the call site.
 */
@Suppress("LongMethod")
fun OutletError.Companion.new(opts: OutletErrorNewOptions): OutletError {
    val errorClass = opts.errorClass
    if (opts.detail != null && !opts.detail.matches(errorClass)) {
        throw OutletError.Validation(
            message = "OutletError.detail shape mismatch for class ${'$'}{errorClass.wire}",
            code = "SCP-VALID-7000",
        )
    }
    val code = opts.code ?: defaultCodeForClass(errorClass)
    val slug = opts.slug ?: opts.catalogKey.raw
    val message = opts.catalogKey.raw
    return when (errorClass) {
        OutletErrorClass.PROTOCOL -> OutletProtocolError(
            message = message, code = code, slug = slug, retry = opts.retry,
            detail = opts.detail, sourceChain = emptyList(),
        )
        OutletErrorClass.AUTHORIZATION -> AuthorizationError(
            message = message, code = code, slug = slug, retry = opts.retry,
            detail = opts.detail, sourceChain = emptyList(),
        )
        OutletErrorClass.INPUT -> InputError(
            message = message, code = code, slug = slug, retry = opts.retry,
            detail = opts.detail, sourceChain = emptyList(),
        )
        OutletErrorClass.EXECUTION -> ExecutionError(
            message = message, code = code, slug = slug, retry = opts.retry,
            detail = opts.detail, sourceChain = emptyList(),
        )
        OutletErrorClass.OUTPUT -> OutputError(
            message = message, code = code, slug = slug, retry = opts.retry,
            detail = opts.detail, sourceChain = emptyList(),
        )
        OutletErrorClass.ECONOMIC -> EconomicError(
            message = message, code = code, slug = slug, retry = opts.retry,
            detail = opts.detail, sourceChain = emptyList(),
        )
        OutletErrorClass.TRANSPORT -> OutletTransportError(
            message = message, code = code, slug = slug, retry = opts.retry,
            detail = opts.detail, sourceChain = emptyList(),
        )
        OutletErrorClass.GOVERNANCE -> OutletGovernanceError(
            message = message, code = code, slug = slug, retry = opts.retry,
            detail = opts.detail, sourceChain = emptyList(),
        )
    }
}

private fun defaultCodeForClass(errorClass: OutletErrorClass): String = when (errorClass) {
    OutletErrorClass.PROTOCOL -> "SCP-TOOL-6100"
    OutletErrorClass.AUTHORIZATION -> "SCP-TOOL-6110"
    OutletErrorClass.INPUT -> "SCP-TOOL-6120"
    OutletErrorClass.EXECUTION -> "SCP-TOOL-6130"
    OutletErrorClass.OUTPUT -> "SCP-TOOL-6140"
    OutletErrorClass.ECONOMIC -> "SCP-TOOL-6150"
    OutletErrorClass.TRANSPORT -> "SCP-TOOL-6160"
    OutletErrorClass.GOVERNANCE -> "SCP-TOOL-6170"
}

// ---------------------------------------------------------------------------
// PII redaction
// ---------------------------------------------------------------------------

private val EMAIL_REGEX =
    Regex("""[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}""")
private val DID_REGEX =
    Regex("""did:(dht|web|key):[A-Za-z0-9._-]+""")

/**
 * Redacts emails and DIDs from a §5.4.4 message before surfacing to logs.
 * Stable across SDKs (matches the same regex set in Python / TS / Swift).
 */
fun redactPii(message: String): String {
    var out = EMAIL_REGEX.replace(message, "[redacted]")
    out = DID_REGEX.replace(out, "[redacted]")
    return out
}

// ---------------------------------------------------------------------------
// (Companion is declared in Outlets.kt; the new() extension above attaches
// to OutletError.Companion.)
// ---------------------------------------------------------------------------
