import Foundation

// MARK: - Economy

/// Economic governance operations for SCP contexts.
///
/// Provides cost estimation, budget tracking, antispam velocity checking,
/// and pricing policy evaluation. All monetary values are in the smallest
/// currency unit (e.g., cents for USD, satoshis for BTC).
///
/// ## Provenance
///
/// - Spec section 19 (Economic Governance)
/// - ADR-033 in `.docs/adrs/phase-3.md`
/// - Story SCP-613
public enum Economy {
    // MARK: - Cost Estimation

    /// Estimates the cost for an action in a context.
    ///
    /// - Parameters:
    ///   - policyJson: Economic policy JSON string (empty or "null" for free contexts).
    ///   - actionType: One of: "MessageSend", "ToolInvoke", "ContextJoin",
    ///     "SubscriptionPeriod", "ByteStored".
    ///   - metricsJson: Observable metrics as JSON string.
    /// - Returns: Estimated cost, or `nil` on overflow.
    public static func estimateCost(
        policyJson: String,
        actionType: String,
        metricsJson: String = "{}"
    ) async throws -> UInt64? {
        try await Scp.defaultInstance().economyEstimateCost(
            policyJson: policyJson,
            actionType: actionType,
            metricsJson: metricsJson
        )
    }

    /// Checks whether an economic policy requires payment.
    ///
    /// - Parameter policyJson: Economic policy JSON string.
    /// - Returns: `true` if payment is required for at least one action type.
    public static func policyRequiresPayment(policyJson: String) async throws -> Bool {
        try await Scp.defaultInstance().economyPolicyRequiresPayment(policyJson: policyJson)
    }

    /// Checks whether auto-accept is blocked by the economic policy.
    ///
    /// - Parameter policyJson: Economic policy JSON string.
    /// - Returns: `true` if auto-accept is blocked.
    public static func autoAcceptBlocked(policyJson: String) async throws -> Bool {
        try await Scp.defaultInstance().economyAutoAcceptBlocked(policyJson: policyJson)
    }

    /// Checks whether an economic policy is locked (immutable).
    ///
    /// - Parameter policyJson: Economic policy JSON string.
    /// - Returns: `true` if the policy is locked.
    public static func checkPolicyLock(policyJson: String) async throws -> Bool {
        try await Scp.defaultInstance().economyCheckPolicyLock(policyJson: policyJson)
    }

    /// Validates a proposed economic policy change.
    ///
    /// - Parameters:
    ///   - currentJson: Current economic policy JSON.
    ///   - proposedJson: Proposed new policy JSON.
    /// - Returns: `true` if the change is valid.
    public static func validatePolicyChange(
        currentJson: String,
        proposedJson: String
    ) async throws -> Bool {
        try await Scp.defaultInstance().economyValidatePolicyChange(
            currentPolicyJson: currentJson,
            proposedPolicyJson: proposedJson
        )
    }

    /// Evaluates a pricing formula against observable metrics.
    ///
    /// - Parameters:
    ///   - formulaJson: Pricing formula JSON string.
    ///   - metricsJson: Observable metrics JSON string.
    /// - Returns: Computed cost, or `nil` on overflow.
    public static func evaluateFormula(
        formulaJson: String,
        metricsJson: String = "{}"
    ) async throws -> UInt64? {
        try await Scp.defaultInstance().economyEvaluateFormula(
            formulaJson: formulaJson,
            metricsJson: metricsJson
        )
    }

    // MARK: - Budget Tracking

    // The budget and antispam free functions below route through the
    // process-wide default bridge instance via the UniFFI free-function
    // façade. They are deprecated in favour of explicit `SCP()`
    // construction (ADR-048). The pure helpers above (estimateCost,
    // policyRequiresPayment, autoAcceptBlocked, checkPolicyLock,
    // validatePolicyChange, evaluateFormula) are stateless — they stay
    // unannotated because they can be evaluated from any caller without
    // touching the default bridge.

    /// Queries the remaining budget for a member.
    ///
    /// - Parameters:
    ///   - contextId: The context ID.
    ///   - did: The member's DID.
    /// - Returns: Remaining budget (smallest currency unit).
    @available(
        *,
        deprecated,
        message: "Use SCP() instance explicitly. Removal: two release cycles after Phase 4 merge (ADR-048)."
    )
    public static func budgetRemaining(contextId: String, did: String) async throws -> UInt64 {
        try await Scp.defaultInstance().economyBudgetRemaining(contextId: contextId, did: did)
    }

    /// Grants spending budget to a member.
    ///
    /// - Parameters:
    ///   - contextId: The context ID.
    ///   - did: The member's DID.
    ///   - amount: Budget to grant.
    @available(
        *,
        deprecated,
        message: "Use SCP() instance explicitly. Removal: two release cycles after Phase 4 merge (ADR-048)."
    )
    public static func budgetGrant(
        contextId: String,
        did: String,
        amount: UInt64
    ) async throws {
        try await Scp.defaultInstance().economyBudgetGrant(contextId: contextId, did: did, amount: amount)
    }

    /// Records a spend against a member's budget.
    ///
    /// - Parameters:
    ///   - contextId: The context ID.
    ///   - did: The member's DID.
    ///   - amount: Amount spent.
    @available(
        *,
        deprecated,
        message: "Use SCP() instance explicitly. Removal: two release cycles after Phase 4 merge (ADR-048)."
    )
    public static func budgetRecordSpend(
        contextId: String,
        did: String,
        amount: UInt64
    ) async throws {
        try await Scp.defaultInstance()
            .economyBudgetRecordSpend(contextId: contextId, did: did, amount: amount)
    }

    // MARK: - Antispam

    /// Records a message for antispam velocity tracking.
    ///
    /// - Parameters:
    ///   - contextId: The context ID.
    ///   - senderDid: The sender's DID.
    ///   - timestamp: Unix timestamp in seconds.
    @available(
        *,
        deprecated,
        message: "Use SCP() instance explicitly. Removal: two release cycles after Phase 4 merge (ADR-048)."
    )
    public static func antispamRecord(
        contextId: String,
        senderDid: String,
        timestamp: UInt64
    ) async throws {
        try await Scp.defaultInstance().economyAntispamRecord(
            contextId: contextId,
            senderDid: senderDid,
            timestamp: timestamp
        )
    }

    /// Queries the sender's message velocity.
    ///
    /// - Parameters:
    ///   - contextId: The context ID.
    ///   - senderDid: The sender's DID.
    ///   - now: Current Unix timestamp in seconds.
    /// - Returns: Number of messages within the sliding window.
    @available(
        *,
        deprecated,
        message: "Use SCP() instance explicitly. Removal: two release cycles after Phase 4 merge (ADR-048)."
    )
    public static func antispamVelocity(
        contextId: String,
        senderDid: String,
        now: UInt64
    ) async throws -> UInt64 {
        try await Scp.defaultInstance().economyAntispamVelocity(
            contextId: contextId,
            senderDid: senderDid,
            now: now
        )
    }

    /// Computes the escalated cost for a sender.
    ///
    /// - Parameters:
    ///   - contextId: The context ID.
    ///   - senderDid: The sender's DID.
    ///   - now: Current Unix timestamp in seconds.
    ///   - baseCost: Base cost.
    ///   - thresholdsJson: JSON array of [velocity_threshold, additional_cost] pairs.
    ///   - floor: Optional minimum cost.
    ///   - cap: Optional maximum cost.
    /// - Returns: Escalated cost.
    @available(
        *,
        deprecated,
        message: "Use SCP() instance explicitly. Removal: two release cycles after Phase 4 merge (ADR-048)."
    )
    public static func antispamEscalatedCost(
        contextId: String,
        senderDid: String,
        now: UInt64,
        baseCost: UInt64,
        thresholdsJson: String,
        floor: UInt64? = nil,
        cap: UInt64? = nil
    ) async throws -> UInt64 {
        try await Scp.defaultInstance().economyAntispamEscalatedCost(
            contextId: contextId,
            senderDid: senderDid,
            now: now,
            baseCost: baseCost,
            thresholdsJson: thresholdsJson,
            floor: floor,
            cap: cap
        )
    }
}
