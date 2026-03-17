// Economy.kt — Kotlin SDK economic governance wrappers (#613)
//
// Wraps economy-related UniFFI bridge functions as suspend functions with
// proper dispatcher assignment per ADR-028. All monetary values are in the
// smallest currency unit (e.g., cents for USD, satoshis for BTC).
//
// Provenance: spec §19 (Economic Governance), ADR-033

package works.limn.scp

import works.limn.scp.bridge.CoroutineBridge

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

    /** Computes an EIP-1559-style relay price adjustment. */
    fun economyAdjustRelayPrice(
        configJson: String,
        utilizationPct: ULong,
    ): String

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
     * @param actionType One of: "MessageSend", "ToolInvoke", "ContextJoin",
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

    /**
     * Computes an EIP-1559-style relay price adjustment.
     *
     * @param configJson Relay pricing config JSON string.
     * @param utilizationPct Current utilization percentage (0-100).
     * @return JSON string with new_base_price, previous_base_price, direction.
     */
    suspend fun adjustRelayPrice(
        configJson: String,
        utilizationPct: ULong,
    ): String =
        bridge.ffiCall {
            bindings.economyAdjustRelayPrice(configJson, utilizationPct)
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
