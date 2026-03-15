package works.limn.scp

/**
 * Economic governance operations for SCP contexts.
 *
 * Provides cost estimation, budget tracking, antispam velocity checking,
 * and pricing policy evaluation. All monetary values are in the smallest
 * currency unit (e.g., cents for USD, satoshis for BTC).
 *
 * See spec section 19 (Economic Governance) and ADR-033.
 */
@Suppress("TooManyFunctions")
object Economy {
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
    ): ULong? = economyEstimateCost(policyJson, actionType, metricsJson)

    /**
     * Checks whether an economic policy requires payment.
     *
     * @param policyJson Economic policy JSON string.
     * @return `true` if payment is required.
     */
    suspend fun policyRequiresPayment(policyJson: String): Boolean =
        economyPolicyRequiresPayment(policyJson)

    /**
     * Checks whether auto-accept is blocked by the economic policy.
     *
     * @param policyJson Economic policy JSON string.
     * @return `true` if auto-accept is blocked.
     */
    suspend fun autoAcceptBlocked(policyJson: String): Boolean =
        economyAutoAcceptBlocked(policyJson)

    /**
     * Checks whether an economic policy is locked (immutable).
     *
     * @param policyJson Economic policy JSON string.
     * @return `true` if the policy is locked.
     */
    suspend fun checkPolicyLock(policyJson: String): Boolean =
        economyCheckPolicyLock(policyJson)

    /**
     * Validates a proposed economic policy change.
     *
     * @param currentJson Current economic policy JSON.
     * @param proposedJson Proposed new policy JSON.
     * @return `true` if the change is valid.
     */
    suspend fun validatePolicyChange(currentJson: String, proposedJson: String): Boolean =
        economyValidatePolicyChange(currentJson, proposedJson)

    /**
     * Evaluates a pricing formula against observable metrics.
     *
     * @param formulaJson Pricing formula JSON string.
     * @param metricsJson Observable metrics JSON string.
     * @return Computed cost, or null on overflow.
     */
    suspend fun evaluateFormula(formulaJson: String, metricsJson: String = "{}"): ULong? =
        economyEvaluateFormula(formulaJson, metricsJson)

    /**
     * Computes an EIP-1559-style relay price adjustment.
     *
     * @param configJson Relay pricing config JSON string.
     * @param utilizationPct Current utilization percentage (0-100).
     * @return JSON string with new_base_price, previous_base_price, direction.
     */
    suspend fun adjustRelayPrice(configJson: String, utilizationPct: ULong): String =
        economyAdjustRelayPrice(configJson, utilizationPct)

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
    suspend fun budgetRemaining(contextId: String, did: String): ULong =
        economyBudgetRemaining(contextId, did)

    /**
     * Grants spending budget to a member.
     *
     * @param contextId The context ID.
     * @param did The member's DID.
     * @param amount Budget to grant.
     */
    suspend fun budgetGrant(contextId: String, did: String, amount: ULong) =
        economyBudgetGrant(contextId, did, amount)

    /**
     * Records a spend against a member's budget.
     *
     * @param contextId The context ID.
     * @param did The member's DID.
     * @param amount Amount spent.
     */
    suspend fun budgetRecordSpend(contextId: String, did: String, amount: ULong) =
        economyBudgetRecordSpend(contextId, did, amount)

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
    suspend fun antispamRecord(contextId: String, senderDid: String, timestamp: ULong) =
        economyAntispamRecord(contextId, senderDid, timestamp)

    /**
     * Queries the sender's message velocity.
     *
     * @param contextId The context ID.
     * @param senderDid The sender's DID.
     * @param now Current Unix timestamp in seconds.
     * @return Number of messages within the sliding window.
     */
    suspend fun antispamVelocity(contextId: String, senderDid: String, now: ULong): ULong =
        economyAntispamVelocity(contextId, senderDid, now)

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
        economyAntispamEscalatedCost(
            contextId,
            senderDid,
            now,
            baseCost,
            thresholdsJson,
            floor,
            cap,
        )
}
