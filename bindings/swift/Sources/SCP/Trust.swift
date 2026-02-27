import Foundation

// MARK: - TrustEvaluation

/// The result of evaluating trust for a subject within a context.
///
/// Aggregates verifiable facts from the SCP four-layer trust model:
///
/// - **Layer 1 (Protocol Enforcement):** Mechanical pass/fail checks on UCAN
///   tokens, signatures, ceiling, and revocation status.
/// - **Layer 2 (Behavioral Validation):** Verified facts computed from the
///   context event log (participation history, governance actions, role changes).
/// - **Layer 3 (Attestation & Challenge-Response):** Third-party attestations
///   and challenge-response verification results.
/// - **Layer 4 (Consequence):** Declared consequence rules for enforcement.
///
/// The trust engine provides *inputs* for agent-level evaluation -- it does
/// not produce trust "scores." Each agent applies its own criteria to a
/// ``TrustEvaluation``.
///
/// ## Provenance
///
/// - ADR-017 (Trust Model) in `.docs/adrs/phase-4.md`
/// - `.docs/sketch.md` section 5 "Trust & Capabilities"
/// - Story SCP-101
public nonisolated struct TrustEvaluation: Sendable {

    // MARK: - Layer 1: Protocol Enforcement

    /// Whether all UCAN tokens in the subject's presentation are valid.
    public let tokensValid: Bool

    /// Whether all Ed25519 signatures verified successfully.
    public let signaturesValid: Bool

    /// Whether the subject's capabilities are within the context's ceiling.
    public let withinCeiling: Bool

    /// Whether none of the presented tokens have been revoked.
    public let notRevoked: Bool

    // MARK: - Layer 2: Behavioral Validation

    /// The behavioral record for the subject, if event log data is available.
    public let behavioralRecord: BehavioralRecord?

    // MARK: - Layer 3: Attestation

    /// The number of verified attestations for the subject.
    public let verifiedAttestationCount: Int

    /// The number of verified challenge-response results.
    public let challengeResultCount: Int

    // MARK: - Layer 4: Consequence

    /// The number of consequence rules declared for the context.
    public let consequenceRuleCount: Int

    /// Memberwise initializer.
    public init(
        tokensValid: Bool,
        signaturesValid: Bool,
        withinCeiling: Bool,
        notRevoked: Bool,
        behavioralRecord: BehavioralRecord?,
        verifiedAttestationCount: Int,
        challengeResultCount: Int,
        consequenceRuleCount: Int
    ) {
        self.tokensValid = tokensValid
        self.signaturesValid = signaturesValid
        self.withinCeiling = withinCeiling
        self.notRevoked = notRevoked
        self.behavioralRecord = behavioralRecord
        self.verifiedAttestationCount = verifiedAttestationCount
        self.challengeResultCount = challengeResultCount
        self.consequenceRuleCount = consequenceRuleCount
    }
}

// MARK: - BehavioralRecord

/// Verified behavioral facts for a subject DID, computed from a context's
/// event log.
///
/// Two agents may compute different records from different event log views --
/// this is correct behavior (trust is contextual per protocol tenets).
///
/// See ADR-017 Layer 2 in `.docs/adrs/phase-4.md`.
public nonisolated struct BehavioralRecord: Sendable {
    /// Number of contexts the subject has participated in.
    public let contextsParticipated: Int

    /// Total duration of participation across all contexts (seconds).
    public let totalDurationSecs: UInt64

    /// Number of governance actions taken against the subject.
    public let governanceActionsAgainst: Int

    /// Number of tool invocations by the subject.
    public let toolInvocations: Int

    /// Number of role transitions for the subject.
    public let roleTransitions: Int

    /// Memberwise initializer.
    public init(
        contextsParticipated: Int,
        totalDurationSecs: UInt64,
        governanceActionsAgainst: Int,
        toolInvocations: Int,
        roleTransitions: Int
    ) {
        self.contextsParticipated = contextsParticipated
        self.totalDurationSecs = totalDurationSecs
        self.governanceActionsAgainst = governanceActionsAgainst
        self.toolInvocations = toolInvocations
        self.roleTransitions = roleTransitions
    }
}

// MARK: - UniFFI Bridge Stubs

/// Evaluate trust for a subject within a context.
///
/// Placeholder stub for the UniFFI-generated `trust_evaluate` function.
/// When the XCFramework ships (SCP-103), this free function is replaced by
/// the auto-generated binding.
///
/// - Parameters:
///   - subjectDid: The DID of the subject to evaluate.
///   - contextId: The context ID in which to evaluate trust.
///   - completion: Callback delivering the evaluation or an error.
internal func scpTrustEvaluate(
    subjectDid: String,
    contextId: String,
    completion: @Sendable @escaping (Result<TrustEvaluation, ScpError>) -> Void
) {
    // Placeholder: replaced by UniFFI-generated binding (SCP-103).
    completion(.failure(.validation(
        message: "UniFFI bridge not yet available — build ScpFFI.xcframework (SCP-103)",
        code: "SCP-TRUST-001"
    )))
}

// MARK: - Public API

/// Evaluates trust for a subject DID within a specific context.
///
/// Aggregates verifiable facts from the four-layer trust model and returns
/// a ``TrustEvaluation``. The trust engine provides inputs for agent-level
/// evaluation -- it does not produce trust "scores." Each agent applies its
/// own criteria to the returned evaluation.
///
/// This function bridges the asynchronous UniFFI `trust_evaluate` call to
/// Swift concurrency via `CheckedContinuation`.
///
/// - Parameters:
///   - subjectDid: The DID of the subject to evaluate (e.g., `"did:dht:z6Mk..."`).
///   - contextId: The context ID in which to evaluate trust.
/// - Returns: A ``TrustEvaluation`` containing verifiable facts from all four
///   trust layers.
/// - Throws: ``ScpError/validation(message:code:)`` if the evaluation fails
///   or inputs are invalid.
///
/// ## Provenance
///
/// - ADR-017 (Trust Model) in `.docs/adrs/phase-4.md`
/// - `.docs/sketch.md` section 5 "Trust & Capabilities"
/// - Story SCP-101
public func evaluateTrust(
    subjectDid: String,
    contextId: String
) async throws -> TrustEvaluation {
    try await withCheckedThrowingContinuation {
        (continuation: CheckedContinuation<TrustEvaluation, Error>) in
        scpTrustEvaluate(subjectDid: subjectDid, contextId: contextId) { result in
            switch result {
            case .success(let evaluation):
                continuation.resume(returning: evaluation)
            case .failure(let error):
                continuation.resume(throwing: error)
            }
        }
    }
}
