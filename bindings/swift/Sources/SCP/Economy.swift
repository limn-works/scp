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
    ///   - actionType: One of: "MessageSend", "OutletCall", "ContextJoin",
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

    // MARK: - Amount display formatting (ADR-060 SDK display surface)

    /// Number of decimal places for well-known currencies, keyed by uppercase
    /// currency code. The SCP protocol does NOT store per-currency decimals —
    /// the wire form is always a smallest-unit integer — so this table lives
    /// entirely in the SDK for display. The same values are used across every
    /// SDK (TypeScript, Python, Kotlin) for cross-binding consistency.
    private static let knownCurrencyDecimals: [String: Int] = [
        "USD": 2,
        "EUR": 2,
        "GBP": 2,
        "BTC": 8,
        "SAT": 0,
        "SOL": 9,
        "USDC": 6,
        "ETH": 18
    ]

    private static func format(amount: UInt64, validatedDecimals decimals: Int) -> String {
        // Operate on the decimal digit string directly (no divisor arithmetic),
        // so any `decimals` — even beyond a UInt64's digit count — formats
        // exactly with no overflow. A full-width `UInt64` formats exactly.
        let digits = String(amount)
        if decimals == 0 {
            // The amount is already in whole display units — no fraction.
            return digits
        }
        if digits.count <= decimals {
            let fraction = String(repeating: "0", count: decimals - digits.count) + digits
            return "0.\(fraction)"
        }
        let splitIndex = digits.index(digits.endIndex, offsetBy: -decimals)
        let whole = digits[digits.startIndex ..< splitIndex]
        let fraction = digits[splitIndex ..< digits.endIndex]
        return "\(whole).\(fraction)"
    }

    /// Formats a smallest-unit monetary amount as a human-readable decimal
    /// string, applying the currency's decimal scale.
    ///
    /// Pure integer/string arithmetic (no floating point), so a full-width
    /// `UInt64` formats exactly.
    ///
    /// ```swift
    /// try Economy.format(amount: 150, currency: "USD")        // "1.50"
    /// try Economy.format(amount: 100_000_000, currency: "BTC") // "1.00000000"
    /// ```
    ///
    /// - Parameters:
    ///   - amount: Smallest-unit amount (e.g. cents, satoshis).
    ///   - currency: A known currency code (case-insensitive).
    /// - Returns: The human-decimal representation.
    /// - Throws: `ScpError.Validation` if the currency is unknown; pass the
    ///   `decimals:` overload for unknown/custom currencies.
    public static func format(amount: UInt64, currency: String) throws -> String {
        guard let decimals = knownCurrencyDecimals[currency.uppercased()] else {
            throw ScpError.Validation(
                msg: "unknown currency \"\(currency)\" has no known decimals; "
                    + "use format(amount:decimals:) with an explicit scale",
                code: "SCP-ECON-12070"
            )
        }
        return format(amount: amount, validatedDecimals: decimals)
    }

    /// Formats a smallest-unit monetary amount using an explicit decimal scale,
    /// for unknown or custom currencies.
    ///
    /// - Parameters:
    ///   - amount: Smallest-unit amount (e.g. cents, satoshis).
    ///   - decimals: The number of fractional decimal places (0...100).
    /// - Returns: The human-decimal representation.
    /// - Throws: `ScpError.Validation` if `decimals` is out of range.
    public static func format(amount: UInt64, decimals: Int) throws -> String {
        guard decimals >= 0, decimals <= 100 else {
            throw ScpError.Validation(
                msg: "decimals must be in 0...100, got \(decimals)",
                code: "SCP-ECON-12070"
            )
        }
        return format(amount: amount, validatedDecimals: decimals)
    }
}
