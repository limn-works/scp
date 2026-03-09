import Foundation

// MARK: - BridgeRegistration

/// The result of registering a bridge connector with a context.
///
/// Contains the bridge's ID, operator DID, platform, mode, and status.
///
/// ## Provenance
///
/// - Spec section 12 (Bridge System)
/// - ADR-023 (Bridge Connector)
public nonisolated struct BridgeRegistrationResult: Sendable {
    /// Unique identifier for the registered bridge.
    public let bridgeId: String

    /// DID of the bridge operator.
    public let operatorDid: String

    /// External platform name (e.g., "discord", "slack").
    public let platform: String

    /// Bridge operating mode: "relay", "puppet", "api", or "cooperative".
    public let mode: String

    /// Bridge status after registration (e.g., "active").
    public let status: String

    /// Context the bridge is registered in.
    public let contextId: String

    /// Memberwise initializer.
    public init(
        bridgeId: String,
        operatorDid: String,
        platform: String,
        mode: String,
        status: String,
        contextId: String
    ) {
        self.bridgeId = bridgeId
        self.operatorDid = operatorDid
        self.platform = platform
        self.mode = mode
        self.status = status
        self.contextId = contextId
    }
}

// MARK: - ShadowIdentityResult

/// A shadow identity representing an external platform participant.
///
/// Shadow identities represent non-SCP participants in a bridged context.
/// They carry provenance metadata indicating they are not native SCP
/// identities.
///
/// ## Provenance
///
/// - Spec section 12 (Bridge System)
/// - ADR-023 (Bridge Connector)
public nonisolated struct ShadowIdentityResult: Sendable {
    /// Unique identifier for this shadow identity.
    public let shadowId: String

    /// External platform handle (e.g., "@user").
    public let platformHandle: String

    /// Bridge connector that created this shadow.
    public let bridgeId: String

    /// Role attributed to this shadow.
    public let attributedRole: String

    /// Provenance status: "Shadow" or "Claimed".
    public let provenanceStatus: String

    /// Memberwise initializer.
    public init(
        shadowId: String,
        platformHandle: String,
        bridgeId: String,
        attributedRole: String,
        provenanceStatus: String
    ) {
        self.shadowId = shadowId
        self.platformHandle = platformHandle
        self.bridgeId = bridgeId
        self.attributedRole = attributedRole
        self.provenanceStatus = provenanceStatus
    }
}

// MARK: - BridgeConnectorBridge

/// Namespace for UniFFI bridge function references used by bridge connector
/// operations. Each typealias maps 1:1 to a UniFFI-generated function.
/// Closures are injected for testability; defaults call through to
/// ScpBindings.
///
/// See spec section 12 (Bridge System) and ADR-023.
internal enum BridgeConnectorBridge {
    /// Evaluate trust level for a bridge action.
    internal typealias EvaluateTrustFn = @Sendable (
        _ isBridged: Bool,
        _ isNativeTransport: Bool,
        _ shadowStatus: String
    ) throws -> UInt8

    /// Default evaluate trust function — delegates to UniFFI
    /// ``bridgeEvaluateTrust``.
    internal static let defaultEvaluateTrust: EvaluateTrustFn = {
        isBridged, isNativeTransport, shadowStatus in
        try bridgeEvaluateTrust(
            isBridged: isBridged,
            isNativeTransport: isNativeTransport,
            shadowStatus: shadowStatus
        )
    }
}

// MARK: - Public API

/// Evaluates the trust level for an action based on bridge provenance.
///
/// Returns an integer (0-3) representing the trust tier:
/// - 0: Native-native (highest trust)
/// - 1: Native-bridged
/// - 2: Claimed-bridged
/// - 3: Shadow-bridged (lowest trust)
///
/// - Parameters:
///   - isBridged: Whether the action originates from a bridge.
///   - isNativeTransport: Whether native SCP transport is used.
///   - shadowStatus: Shadow provenance status: "shadow" or "claimed".
///   - evaluateTrustFn: Bridge function override for testing.
/// - Returns: Trust tier integer (0-3).
/// - Throws: ``ScpError/Validation(message:code:)`` if the shadow status
///   is not recognized.
///
/// ## Provenance
///
/// - Spec section 12 (Bridge System)
/// - ADR-023 (Bridge Connector)
public func evaluateBridgeTrust(
    isBridged: Bool,
    isNativeTransport: Bool,
    shadowStatus: String,
    evaluateTrustFn: BridgeConnectorBridge.EvaluateTrustFn = BridgeConnectorBridge.defaultEvaluateTrust
) throws -> UInt8 {
    try evaluateTrustFn(isBridged, isNativeTransport, shadowStatus)
}
