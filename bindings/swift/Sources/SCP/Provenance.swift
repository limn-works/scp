import Foundation

// MARK: - Provenance pure helpers

/// Evaluates the provenance quality tier for a given data source.
///
/// Pure function — does not touch any SCP instance state. Returns an
/// integer (0-3) representing the quality tier.
///
/// - Parameters:
///   - sourceContext: Optional source context ID.
///   - sourceType: Source type: "persistent", "ephemeral", or "summary".
///   - contextState: Context state: "active", "closed_with_summary_verified",
///     "closed_with_summary_unverified", "closed_ephemeral", or "unknown".
///   - counterparties: Optional list of counterparty DIDs.
/// - Returns: Quality tier integer (0-3).
/// - Throws: ``ScpError/Validation(msg:code:)`` if source type or
///   context state is not recognized.
///
/// ## Provenance
///
/// - Spec section 24 (Provenance System)
/// - ADR-019 (Provenance)
public func evaluateProvenanceQualityTier(
    sourceContext: String? = nil,
    sourceType: String,
    contextState: String,
    counterparties: [String] = []
) throws -> UInt32 {
    try evaluateProvenanceQuality(
        sourceContext: sourceContext,
        sourceType: sourceType,
        contextState: contextState,
        counterparties: counterparties
    )
}

/// Checks whether a provenance chain depth is within the allowed limit.
///
/// Pure function — does not touch any SCP instance state. The default
/// maximum chain depth is 8 (ADR-043).
///
/// - Parameters:
///   - chainDepth: The current chain depth to check.
///   - maxDepth: Optional custom maximum depth (default: 8).
/// - Returns: `true` if within limit, `false` otherwise.
///
/// ## Provenance
///
/// - Spec section 24 (Provenance System)
/// - ADR-019 (Provenance)
public func checkProvenanceChainDepth(
    chainDepth: UInt8,
    maxDepth: UInt8? = nil
) -> Bool {
    provenanceCheckChainDepth(chainDepth: chainDepth, maxDepth: maxDepth)
}
