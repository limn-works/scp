import Foundation

// MARK: - ProvenanceBridge

/// Namespace for UniFFI bridge function references used by provenance
/// operations. Each typealias maps 1:1 to a UniFFI-generated function.
/// Closures are injected for testability; defaults call through to
/// ScpBindings.
///
/// See spec section 24 (Provenance System) and ADR-019.
internal enum ProvenanceBridge {
    /// Evaluate provenance quality tier.
    internal typealias EvaluateQualityFn = @Sendable (
        _ sourceContext: String?,
        _ sourceType: String,
        _ contextState: String,
        _ counterparties: [String]?
    ) throws -> UInt32

    /// Attach provenance metadata at cross-context boundaries.
    internal typealias AttachFn = @Sendable (
        _ sourceContextId: String,
        _ sourceType: String,
        _ memoryScope: String,
        _ members: [String],
        _ targetContextId: String,
        _ existingChainDepth: UInt8?
    ) throws -> String

    /// Check whether chain depth is within the allowed limit.
    internal typealias CheckChainDepthFn = @Sendable (
        _ chainDepth: UInt8,
        _ maxDepth: UInt8?
    ) -> Bool

    /// Default evaluate quality function — delegates to UniFFI
    /// ``evaluateProvenanceQuality``.
    internal static let defaultEvaluateQuality: EvaluateQualityFn = {
        sourceContext, sourceType, contextState, counterparties in
        try evaluateProvenanceQuality(
            sourceContext: sourceContext,
            sourceType: sourceType,
            contextState: contextState,
            counterparties: counterparties
        )
    }

    /// Default attach function — delegates to UniFFI
    /// ``provenanceAttach``.
    internal static let defaultAttach: AttachFn = {
        sourceContextId, sourceType, memoryScope, members, targetContextId, existingChainDepth in
        try provenanceAttach(
            sourceContextId: sourceContextId,
            sourceType: sourceType,
            memoryScope: memoryScope,
            members: members,
            targetContextId: targetContextId,
            existingChainDepth: existingChainDepth
        )
    }

    /// Default check chain depth function — delegates to UniFFI
    /// ``provenanceCheckChainDepth``.
    internal static let defaultCheckChainDepth: CheckChainDepthFn = {
        chainDepth, maxDepth in
        provenanceCheckChainDepth(chainDepth: chainDepth, maxDepth: maxDepth)
    }
}

// MARK: - Public API

/// Evaluates the provenance quality tier for a given data source.
///
/// Returns an integer (0-3) representing the quality tier.
///
/// - Parameters:
///   - sourceContext: Optional source context ID.
///   - sourceType: Source type: "persistent", "ephemeral", or "summary".
///   - contextState: Context state: "active", "closed_with_summary_verified",
///     "closed_with_summary_unverified", "closed_ephemeral", or "unknown".
///   - counterparties: Optional list of counterparty DIDs.
///   - evaluateQualityFn: Bridge function override for testing.
/// - Returns: Quality tier integer (0-3).
/// - Throws: ``ScpError/Validation(message:code:)`` if source type or
///   context state is not recognized.
///
/// ## Provenance
///
/// - Spec section 24 (Provenance System)
/// - ADR-019 (Provenance)
public func evaluateProvenanceQuality(
    sourceContext: String? = nil,
    sourceType: String,
    contextState: String,
    counterparties: [String]? = nil,
    evaluateQualityFn: ProvenanceBridge.EvaluateQualityFn = ProvenanceBridge.defaultEvaluateQuality
) throws -> UInt32 {
    try evaluateQualityFn(sourceContext, sourceType, contextState, counterparties)
}

/// Attaches provenance metadata when data crosses a context boundary.
///
/// Returns a JSON string with the attached provenance record.
///
/// - Parameters:
///   - sourceContextId: The source context ID.
///   - sourceType: Source type: "persistent", "ephemeral", or "summary".
///   - memoryScope: Memory scope: "full", "summary", or "ephemeral".
///   - members: List of member DIDs in the source context.
///   - targetContextId: The target context ID.
///   - existingChainDepth: Optional existing chain depth to extend.
///   - attachFn: Bridge function override for testing.
/// - Returns: A JSON string with the attached provenance record.
/// - Throws: ``ScpError/Validation(message:code:)`` if source type or
///   memory scope is not recognized.
///
/// ## Provenance
///
/// - Spec section 24 (Provenance System)
/// - ADR-019 (Provenance)
public func attachProvenance(
    sourceContextId: String,
    sourceType: String,
    memoryScope: String,
    members: [String],
    targetContextId: String,
    existingChainDepth: UInt8? = nil,
    attachFn: ProvenanceBridge.AttachFn = ProvenanceBridge.defaultAttach
) throws -> String {
    try attachFn(
        sourceContextId, sourceType, memoryScope, members,
        targetContextId, existingChainDepth
    )
}

/// Checks whether a provenance chain depth is within the allowed limit.
///
/// The default maximum chain depth is 3 (per spec).
///
/// - Parameters:
///   - chainDepth: The current chain depth to check.
///   - maxDepth: Optional custom maximum depth (default: 3).
///   - checkChainDepthFn: Bridge function override for testing.
/// - Returns: `true` if within limit, `false` otherwise.
///
/// ## Provenance
///
/// - Spec section 24 (Provenance System)
/// - ADR-019 (Provenance)
public func checkProvenanceChainDepth(
    chainDepth: UInt8,
    maxDepth: UInt8? = nil,
    checkChainDepthFn: ProvenanceBridge.CheckChainDepthFn = ProvenanceBridge.defaultCheckChainDepth
) -> Bool {
    checkChainDepthFn(chainDepth, maxDepth)
}
