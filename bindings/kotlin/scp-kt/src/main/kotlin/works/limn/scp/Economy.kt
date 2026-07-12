// Economy.kt — Kotlin SDK economic governance wrappers (#613)
//
// Wraps economy-related UniFFI bridge functions as suspend functions with
// proper dispatcher assignment per ADR-028. All monetary values are in the
// smallest currency unit (e.g., cents for USD, satoshis for BTC).
//
// Provenance: spec §19 (Economic Governance), ADR-033

package works.limn.scp

import works.limn.scp.bridge.CoroutineBridge

// ---------------------------------------------------------------------------
// Amount display formatting (ADR-060 SDK display surface)
// ---------------------------------------------------------------------------

/**
 * Number of decimal places for well-known currencies, keyed by uppercase
 * currency code. The SCP protocol does NOT store per-currency decimals -- the
 * wire form is always a smallest-unit integer -- so this table lives entirely
 * in the SDK for display. The same values are used across every SDK
 * (TypeScript, Python, Swift) for cross-binding consistency.
 */
private val KNOWN_CURRENCY_DECIMALS: Map<String, Int> =
    mapOf(
        "USD" to 2,
        "EUR" to 2,
        "GBP" to 2,
        "BTC" to 8,
        "SAT" to 0,
        "SOL" to 9,
        "USDC" to 6,
        "ETH" to 18,
    )

private fun formatWithDecimals(
    amount: ULong,
    decimals: Int,
): String {
    // Operate on the decimal digit string directly (no divisor arithmetic), so
    // any [decimals] -- even beyond a ULong's digit count -- formats exactly
    // with no overflow. A full-width ULong formats exactly.
    val digits = amount.toString()
    if (decimals == 0) {
        // The amount is already in whole display units -- no fraction.
        return digits
    }
    if (digits.length <= decimals) {
        return "0." + "0".repeat(decimals - digits.length) + digits
    }
    val split = digits.length - decimals
    return digits.substring(0, split) + "." + digits.substring(split)
}

/**
 * Formats a smallest-unit monetary amount as a human-readable decimal string,
 * applying the currency's decimal scale.
 *
 * Pure integer/string arithmetic (no floating point), so a full-width [ULong]
 * formats exactly.
 *
 * ```kotlin
 * formatAmount(150uL, "USD")        // "1.50"
 * formatAmount(100_000_000uL, "BTC") // "1.00000000"
 * ```
 *
 * @param amount Smallest-unit amount (e.g. cents, satoshis).
 * @param currency A known currency code (case-insensitive).
 * @return The human-decimal representation.
 * @throws IllegalArgumentException (SCP-ECON-12070) if the currency is unknown;
 *     use the [formatAmount] overload taking `decimals` for unknown/custom
 *     currencies. This is a pure SDK-side display helper that never touches the
 *     FFI bridge, so it raises an idiomatic argument exception rather than a
 *     [works.limn.scp.bridge.BridgeException] (which carries FFI error codes);
 *     the `SCP-ECON-12070` code is kept in the message for cross-SDK parity.
 */
fun formatAmount(
    amount: ULong,
    currency: String,
): String {
    val decimals =
        KNOWN_CURRENCY_DECIMALS[currency.uppercase()]
            ?: throw IllegalArgumentException(
                "[SCP-ECON-12070] unknown currency \"$currency\" has no known decimals; " +
                    "use formatAmount(amount, decimals) with an explicit scale",
            )
    return formatWithDecimals(amount, decimals)
}

/**
 * Formats a smallest-unit monetary amount using an explicit decimal scale, for
 * unknown or custom currencies.
 *
 * @param amount Smallest-unit amount (e.g. cents, satoshis).
 * @param decimals The number of fractional decimal places (0..100).
 * @return The human-decimal representation.
 * @throws IllegalArgumentException (SCP-ECON-12070) if [decimals] is out of
 *     range. Pure SDK-side display helper — no FFI bridge, so an idiomatic
 *     argument exception rather than a
 *     [works.limn.scp.bridge.BridgeException]; the `SCP-ECON-12070` code is
 *     kept in the message for cross-SDK parity.
 */
fun formatAmount(
    amount: ULong,
    decimals: Int,
): String {
    // `require` raises IllegalArgumentException — the idiomatic non-bridge
    // exception; the SCP-ECON-12070 code stays in the message for cross-SDK
    // parity.
    require(decimals in 0..100) { "[SCP-ECON-12070] decimals must be in 0..100, got $decimals" }
    return formatWithDecimals(amount, decimals)
}

/**
 * Native binding functions for economic governance operations.
 *
 * All methods are blocking JNA calls into Rust and must be dispatched
 * on [kotlinx.coroutines.Dispatchers.IO].
 */
@Suppress("TooManyFunctions")
interface EconomyBindings {
    /** Estimates the cost for an action given a policy and metrics. */
    fun economyEstimateCost(
        policyJson: String,
        actionType: String,
        metricsJson: String,
    ): ULong?

    /** Checks whether an economic policy requires payment. */
    fun economyPolicyRequiresPayment(policyJson: String): Boolean

    /** Checks whether auto-accept is blocked by the economic policy. */
    fun economyAutoAcceptBlocked(policyJson: String): Boolean

    /** Checks whether an economic policy is locked (immutable). */
    fun economyCheckPolicyLock(policyJson: String): Boolean

    /** Validates a proposed economic policy change. */
    fun economyValidatePolicyChange(
        currentJson: String,
        proposedJson: String,
    ): Boolean

    /** Evaluates a pricing formula against observable metrics. */
    fun economyEvaluateFormula(
        formulaJson: String,
        metricsJson: String,
    ): ULong?

    /** Queries the remaining budget for a member. */
    fun economyBudgetRemaining(
        contextId: String,
        did: String,
    ): ULong

    /** Grants spending budget to a member. */
    fun economyBudgetGrant(
        contextId: String,
        did: String,
        amount: ULong,
    )

    /** Records a spend against a member's budget. */
    fun economyBudgetRecordSpend(
        contextId: String,
        did: String,
        amount: ULong,
    )

    /** Records a message for antispam velocity tracking. */
    fun economyAntispamRecord(
        contextId: String,
        senderDid: String,
        timestamp: ULong,
    )

    /** Queries the sender's message velocity. */
    fun economyAntispamVelocity(
        contextId: String,
        senderDid: String,
        now: ULong,
    ): ULong

    /** Computes the escalated cost for a sender. */
    @Suppress("LongParameterList")
    fun economyAntispamEscalatedCost(
        contextId: String,
        senderDid: String,
        now: ULong,
        baseCost: ULong,
        thresholdsJson: String,
        floor: ULong?,
        cap: ULong?,
    ): ULong
}

/**
 * Kotlin SDK wrapper for economic governance operations.
 *
 * All operations delegate through the coroutine bridge to UniFFI-generated
 * Rust functions. See spec §19 (Economic Governance) and ADR-033.
 */
@Suppress("TooManyFunctions")
class EconomyBridge internal constructor(
    private val bindings: EconomyBindings,
    private val bridge: CoroutineBridge,
) {
    // -----------------------------------------------------------------------
    // Cost estimation
    // -----------------------------------------------------------------------

    /**
     * Estimates the cost for an action in a context.
     *
     * @param policyJson Economic policy JSON string (empty or "null" for free).
     * @param actionType One of: "MessageSend", "OutletCall", "ContextJoin",
     *     "SubscriptionPeriod", "ByteStored".
     * @param metricsJson Observable metrics as JSON string.
     * @return Estimated cost, or null on overflow.
     */
    suspend fun estimateCost(
        policyJson: String,
        actionType: String,
        metricsJson: String = "{}",
    ): ULong? =
        bridge.ffiCall {
            bindings.economyEstimateCost(policyJson, actionType, metricsJson)
        }

    /**
     * Checks whether an economic policy requires payment.
     *
     * @param policyJson Economic policy JSON string.
     * @return `true` if payment is required.
     */
    suspend fun policyRequiresPayment(policyJson: String): Boolean =
        bridge.ffiCall {
            bindings.economyPolicyRequiresPayment(policyJson)
        }

    /**
     * Checks whether auto-accept is blocked by the economic policy.
     *
     * @param policyJson Economic policy JSON string.
     * @return `true` if auto-accept is blocked.
     */
    suspend fun autoAcceptBlocked(policyJson: String): Boolean =
        bridge.ffiCall {
            bindings.economyAutoAcceptBlocked(policyJson)
        }

    /**
     * Checks whether an economic policy is locked (immutable).
     *
     * @param policyJson Economic policy JSON string.
     * @return `true` if the policy is locked.
     */
    suspend fun checkPolicyLock(policyJson: String): Boolean =
        bridge.ffiCall {
            bindings.economyCheckPolicyLock(policyJson)
        }

    /**
     * Validates a proposed economic policy change.
     *
     * @param currentJson Current economic policy JSON.
     * @param proposedJson Proposed new policy JSON.
     * @return `true` if the change is valid.
     */
    suspend fun validatePolicyChange(
        currentJson: String,
        proposedJson: String,
    ): Boolean =
        bridge.ffiCall {
            bindings.economyValidatePolicyChange(currentJson, proposedJson)
        }

    /**
     * Evaluates a pricing formula against observable metrics.
     *
     * @param formulaJson Pricing formula JSON string.
     * @param metricsJson Observable metrics JSON string.
     * @return Computed cost, or null on overflow.
     */
    suspend fun evaluateFormula(
        formulaJson: String,
        metricsJson: String = "{}",
    ): ULong? =
        bridge.ffiCall {
            bindings.economyEvaluateFormula(formulaJson, metricsJson)
        }

    // -----------------------------------------------------------------------
    // Budget tracking
    // -----------------------------------------------------------------------

    /**
     * Queries the remaining budget for a member.
     *
     * @param contextId The context ID.
     * @param did The member's DID.
     * @return Remaining budget (smallest currency unit).
     */
    suspend fun budgetRemaining(
        contextId: String,
        did: String,
    ): ULong =
        bridge.ffiCall {
            bindings.economyBudgetRemaining(contextId, did)
        }

    /**
     * Grants spending budget to a member.
     *
     * @param contextId The context ID.
     * @param did The member's DID.
     * @param amount Budget to grant.
     */
    suspend fun budgetGrant(
        contextId: String,
        did: String,
        amount: ULong,
    ) = bridge.ffiCall {
        bindings.economyBudgetGrant(contextId, did, amount)
    }

    /**
     * Records a spend against a member's budget.
     *
     * @param contextId The context ID.
     * @param did The member's DID.
     * @param amount Amount spent.
     */
    suspend fun budgetRecordSpend(
        contextId: String,
        did: String,
        amount: ULong,
    ) = bridge.ffiCall {
        bindings.economyBudgetRecordSpend(contextId, did, amount)
    }

    // -----------------------------------------------------------------------
    // Antispam
    // -----------------------------------------------------------------------

    /**
     * Records a message for antispam velocity tracking.
     *
     * @param contextId The context ID.
     * @param senderDid The sender's DID.
     * @param timestamp Unix timestamp in seconds.
     */
    suspend fun antispamRecord(
        contextId: String,
        senderDid: String,
        timestamp: ULong,
    ) = bridge.ffiCall {
        bindings.economyAntispamRecord(contextId, senderDid, timestamp)
    }

    /**
     * Queries the sender's message velocity.
     *
     * @param contextId The context ID.
     * @param senderDid The sender's DID.
     * @param now Current Unix timestamp in seconds.
     * @return Number of messages within the sliding window.
     */
    suspend fun antispamVelocity(
        contextId: String,
        senderDid: String,
        now: ULong,
    ): ULong =
        bridge.ffiCall {
            bindings.economyAntispamVelocity(contextId, senderDid, now)
        }

    /**
     * Computes the escalated cost for a sender.
     *
     * @param contextId The context ID.
     * @param senderDid The sender's DID.
     * @param now Current Unix timestamp in seconds.
     * @param baseCost Base cost.
     * @param thresholdsJson JSON array of [velocity_threshold, additional_cost] pairs.
     * @param floor Optional minimum cost.
     * @param cap Optional maximum cost.
     * @return Escalated cost.
     */
    @Suppress("LongParameterList")
    suspend fun antispamEscalatedCost(
        contextId: String,
        senderDid: String,
        now: ULong,
        baseCost: ULong,
        thresholdsJson: String,
        floor: ULong? = null,
        cap: ULong? = null,
    ): ULong =
        bridge.ffiCall {
            bindings.economyAntispamEscalatedCost(
                contextId,
                senderDid,
                now,
                baseCost,
                thresholdsJson,
                floor,
                cap,
            )
        }
}
