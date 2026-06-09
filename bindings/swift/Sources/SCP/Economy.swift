import Foundation

// MARK: - Economy

/// Economic governance pure helpers for SCP contexts.
///
/// These are the pure/stateless cost-estimation and policy-validation
/// helpers. Stateful budget and antispam operations have migrated to the
/// ``SCP`` instance (ADR-048) — use ``SCP/economyBudgetRemaining``,
/// ``SCP/economyBudgetGrant``, ``SCP/economyBudgetRecordSpend``,
/// ``SCP/economyAntispamRecord``, ``SCP/economyAntispamVelocity``,
/// ``SCP/economyAntispamEscalatedCost``,
/// ``SCP/economyVerifyPaymentReceipts``.
///
/// ## Provenance
///
/// - Spec section 19 (Economic Governance)
/// - ADR-033 in `.docs/adrs/phase-3.md`
/// - Story SCP-613
public enum Economy {
    // MARK: - Cost Estimation (pure helpers)

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
    ) throws -> UInt64? {
        try economyEstimateCost(
            policyJson: policyJson,
            actionType: actionType,
            metricsJson: metricsJson
        )
    }

    /// Checks whether an economic policy requires payment.
    ///
    /// - Parameter policyJson: Economic policy JSON string.
    /// - Returns: `true` if payment is required for at least one action type.
    public static func policyRequiresPayment(policyJson: String) throws -> Bool {
        try economyPolicyRequiresPayment(policyJson: policyJson)
    }

    /// Checks whether auto-accept is blocked by the economic policy.
    ///
    /// - Parameter policyJson: Economic policy JSON string.
    /// - Returns: `true` if auto-accept is blocked.
    public static func autoAcceptBlocked(policyJson: String) throws -> Bool {
        try economyAutoAcceptBlocked(policyJson: policyJson)
    }

    /// Checks whether an economic policy is locked (immutable).
    ///
    /// - Parameter policyJson: Economic policy JSON string.
    /// - Returns: `true` if the policy is locked.
    public static func checkPolicyLock(policyJson: String) throws -> Bool {
        try economyCheckPolicyLock(policyJson: policyJson)
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
    ) throws -> Bool {
        try economyValidatePolicyChange(
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
    ) throws -> UInt64? {
        try economyEvaluateFormula(
            formulaJson: formulaJson,
            metricsJson: metricsJson
        )
    }
}
