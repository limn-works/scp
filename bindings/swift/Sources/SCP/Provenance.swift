import Foundation

// MARK: - ProvenanceBridge

/// Namespace for UniFFI bridge function references used by provenance
/// operations. Each typealias maps 1:1 to a UniFFI-generated function.
/// Closures are injected for testability; defaults call through to
/// ScpBindings.
///
/// See spec section 24 (Provenance System) and ADR-019.
public enum ProvenanceBridge {
    /// Evaluate provenance quality tier.
    public typealias EvaluateQualityFn = @Sendable (
        _ sourceContext: String?,
        _ sourceType: String,
        _ contextState: String,
        _ counterparties: [String]?
    ) throws -> UInt32

    /// Attach provenance metadata at cross-context boundaries.
    public typealias AttachFn = @Sendable (
        _ sourceContextId: String,
        _ sourceType: String,
        _ memoryScope: String,
        _ members: [String],
        _ targetContextId: String,
        _ actorDid: String,
        _ existingChainDepth: UInt8?
    ) throws -> String

    /// Check whether chain depth is within the allowed limit.
    public typealias CheckChainDepthFn = @Sendable (
        _ chainDepth: UInt8,
        _ maxDepth: UInt8?
    ) -> Bool

    /// Default evaluate quality function — delegates to the process-wide
    /// default ``Scp`` instance's ``Scp/evaluateProvenanceQuality`` method.
    public static let defaultEvaluateQuality: EvaluateQualityFn = { sourceContext, sourceType, contextState, counterparties in
        try Scp.defaultInstance().evaluateProvenanceQuality(
            sourceContext: sourceContext,
            sourceType: sourceType,
            contextState: contextState,
            counterparties: counterparties
        )
    }

    /// Default attach function — delegates to the process-wide default
    /// ``Scp`` instance's ``Scp/provenanceAttach`` method.
    public static let defaultAttach: AttachFn = { sourceContextId, sourceType, memoryScope, members, targetContextId, actorDid, existingChainDepth in
        try Scp.defaultInstance().provenanceAttach(
            sourceContextId: sourceContextId,
            sourceType: sourceType,
            memoryScopeStr: memoryScope,
            members: members,
            targetContextId: targetContextId,
            actorDid: actorDid,
            existingChainDepth: existingChainDepth
        )
    }

    /// Default check chain depth function — delegates to the process-wide
    /// default ``Scp`` instance's ``Scp/provenanceCheckChainDepth`` method.
    ///
    /// Non-throwing: conservatively returns `false` (outside the allowed
    /// limit) if the default instance cannot be resolved.
    public static let defaultCheckChainDepth: CheckChainDepthFn = { chainDepth, maxDepth in
        guard let scp = try? Scp.defaultInstance() else { return false }
        return scp.provenanceCheckChainDepth(chainDepth: chainDepth, maxDepth: maxDepth)
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
/// - Throws: ``ScpError/Validation(msg:code:)`` if source type or
///   context state is not recognized.
///
/// ## Provenance
///
/// - Spec section 24 (Provenance System)
/// - ADR-019 (Provenance)
@available(
    *,
    deprecated,
    message: "Operates on the default SCP instance. Construct an explicit `SCP` and call its methods instead. Removal target: two release cycles after Phase 4 merge (ADR-048)."
)
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
/// - Throws: ``ScpError/Validation(msg:code:)`` if source type or
///   memory scope is not recognized.
///
/// ## Provenance
///
/// - Spec section 24 (Provenance System)
/// - ADR-019 (Provenance)
@available(
    *,
    deprecated,
    message: "Operates on the default SCP instance. Construct an explicit `SCP` and call its methods instead. Removal target: two release cycles after Phase 4 merge (ADR-048)."
)
public func attachProvenance(
    sourceContextId: String,
    sourceType: String,
    memoryScope: String,
    members: [String],
    targetContextId: String,
    actorDid: String,
    existingChainDepth: UInt8? = nil,
    attachFn: ProvenanceBridge.AttachFn = ProvenanceBridge.defaultAttach
) throws -> String {
    try attachFn(
        sourceContextId, sourceType, memoryScope, members,
        targetContextId, actorDid, existingChainDepth
    )
}

/// Checks whether a provenance chain depth is within the allowed limit.
///
/// The default maximum chain depth is 8 (ADR-043).
///
/// - Parameters:
///   - chainDepth: The current chain depth to check.
///   - maxDepth: Optional custom maximum depth (default: 8).
///   - checkChainDepthFn: Bridge function override for testing.
/// - Returns: `true` if within limit, `false` otherwise.
///
/// ## Provenance
///
/// - Spec section 24 (Provenance System)
/// - ADR-019 (Provenance)
@available(
    *,
    deprecated,
    message: "Operates on the default SCP instance. Construct an explicit `SCP` and call its methods instead. Removal target: two release cycles after Phase 4 merge (ADR-048)."
)
public func checkProvenanceChainDepth(
    chainDepth: UInt8,
    maxDepth: UInt8? = nil,
    checkChainDepthFn: ProvenanceBridge.CheckChainDepthFn = ProvenanceBridge.defaultCheckChainDepth
) -> Bool {
    checkChainDepthFn(chainDepth, maxDepth)
}
