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
        try await economyEstimateCost(
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
        try await economyPolicyRequiresPayment(policyJson: policyJson)
    }

    /// Checks whether auto-accept is blocked by the economic policy.
    ///
    /// - Parameter policyJson: Economic policy JSON string.
    /// - Returns: `true` if auto-accept is blocked.
    public static func autoAcceptBlocked(policyJson: String) async throws -> Bool {
        try await economyAutoAcceptBlocked(policyJson: policyJson)
    }

    /// Checks whether an economic policy is locked (immutable).
    ///
    /// - Parameter policyJson: Economic policy JSON string.
    /// - Returns: `true` if the policy is locked.
    public static func checkPolicyLock(policyJson: String) async throws -> Bool {
        try await economyCheckPolicyLock(policyJson: policyJson)
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
        try await economyValidatePolicyChange(
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
        try await economyEvaluateFormula(
            formulaJson: formulaJson,
            metricsJson: metricsJson
        )
    }

    // MARK: - Budget Tracking

    /// Queries the remaining budget for a member.
    ///
    /// - Parameters:
    ///   - contextId: The context ID.
    ///   - did: The member's DID.
    /// - Returns: Remaining budget (smallest currency unit).
    public static func budgetRemaining(contextId: String, did: String) async throws -> UInt64 {
        try await economyBudgetRemaining(contextId: contextId, did: did)
    }

    /// Grants spending budget to a member.
    ///
    /// - Parameters:
    ///   - contextId: The context ID.
    ///   - did: The member's DID.
    ///   - amount: Budget to grant.
    public static func budgetGrant(
        contextId: String,
        did: String,
        amount: UInt64
    ) async throws {
        try await economyBudgetGrant(contextId: contextId, did: did, amount: amount)
    }

    /// Records a spend against a member's budget.
    ///
    /// - Parameters:
    ///   - contextId: The context ID.
    ///   - did: The member's DID.
    ///   - amount: Amount spent.
    public static func budgetRecordSpend(
        contextId: String,
        did: String,
        amount: UInt64
    ) async throws {
        try await economyBudgetRecordSpend(contextId: contextId, did: did, amount: amount)
    }

    // MARK: - Antispam

    /// Records a message for antispam velocity tracking.
    ///
    /// - Parameters:
    ///   - contextId: The context ID.
    ///   - senderDid: The sender's DID.
    ///   - timestamp: Unix timestamp in seconds.
    public static func antispamRecord(
        contextId: String,
        senderDid: String,
        timestamp: UInt64
    ) async throws {
        try await economyAntispamRecord(
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
    public static func antispamVelocity(
        contextId: String,
        senderDid: String,
        now: UInt64
    ) async throws -> UInt64 {
        try await economyAntispamVelocity(
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
    public static func antispamEscalatedCost(
        contextId: String,
        senderDid: String,
        now: UInt64,
        baseCost: UInt64,
        thresholdsJson: String,
        floor: UInt64? = nil,
        cap: UInt64? = nil
    ) async throws -> UInt64 {
        try await economyAntispamEscalatedCost(
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
