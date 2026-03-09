import Foundation

// MARK: - BridgeRegistration

/// Result of bridge registration. Forward-declared — UniFFI exports pending.
/// Construct manually or await UniFFI bridge coverage.
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

    /// Bridge operating mode.
    public let mode: String

    /// Typed bridge mode, or `nil` if the raw string is unrecognized.
    public var bridgeMode: BridgeMode? {
        BridgeMode(rawValue: mode)
    }

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
/// Forward-declared — UniFFI exports pending. Construct manually or await
/// UniFFI bridge coverage.
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

    /// Typed shadow status, or `nil` if the raw string is unrecognized.
    public var typedShadowStatus: ShadowStatus? {
        ShadowStatus(rawValue: provenanceStatus.lowercased())
    }

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
enum BridgeConnectorBridge {
    /// Evaluate trust level for a bridge action.
    typealias EvaluateTrustFn = @Sendable (
        _ isBridged: Bool,
        _ isNativeTransport: Bool,
        _ shadowStatus: String
    ) throws -> UInt8

    /// Register a bridge connector with a context.
    typealias RegisterFn = @Sendable (
        _ contextId: String,
        _ operatorDid: String,
        _ platform: String,
        _ mode: String
    ) throws -> BridgeRegistrationResult

    /// Create a shadow identity for an external platform participant.
    typealias CreateShadowFn = @Sendable (
        _ bridgeId: String,
        _ platformHandle: String,
        _ bridgeMode: String,
        _ contextId: String
    ) throws -> ShadowIdentityResult

    /// Default evaluate trust function — delegates to UniFFI
    /// ``bridgeEvaluateTrust``.
    static let defaultEvaluateTrust: EvaluateTrustFn = { isBridged, isNativeTransport, shadowStatus in
        try bridgeEvaluateTrust(
            isBridged: isBridged,
            isNativeTransport: isNativeTransport,
            shadowStatus: shadowStatus
        )
    }

    /// Default register function — delegates to UniFFI ``bridgeRegister``.
    ///
    /// UniFFI does not yet export ``bridgeRegister``; the default throws a
    /// descriptive error. Inject a real closure in production once the
    /// UniFFI bridge is extended, or in tests via the injectable parameter.
    static let defaultRegister: RegisterFn = { _, _, _, _ in
        throw ScpError.Context(
            message: "bridgeRegister is not yet available in the UniFFI bridge. "
                + "Inject a bridge function or wait for the UniFFI export.",
            code: "SCP-CTX-2040"
        )
    }

    /// Default create shadow function — delegates to UniFFI
    /// ``bridgeCreateShadow``.
    ///
    /// UniFFI does not yet export ``bridgeCreateShadow``; the default
    /// throws a descriptive error. Inject a real closure in production
    /// once the UniFFI bridge is extended, or in tests via the injectable
    /// parameter.
    static let defaultCreateShadow: CreateShadowFn = { _, _, _, _ in
        throw ScpError.Context(
            message: "bridgeCreateShadow is not yet available in the UniFFI bridge. "
                + "Inject a bridge function or wait for the UniFFI export.",
            code: "SCP-CTX-2041"
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

/// Registers a bridge connector with a context.
///
/// Creates a registration for a bridge that connects an external platform
/// (e.g., Discord, Slack) to an SCP context. The bridge operator is
/// accountable for all messages relayed through the bridge.
///
/// - Parameters:
///   - contextId: The context to register the bridge in.
///   - operatorDid: DID of the human operator accountable for the bridge.
///   - platform: External platform name (e.g., `"discord"`, `"slack"`).
///   - mode: Bridge mode: `"relay"`, `"puppet"`, `"api"`, or
///     `"cooperative"`.
///   - registerFn: Bridge function override for testing.
/// - Returns: A ``BridgeRegistrationResult`` with the registration details.
/// - Throws: ``ScpError`` if registration fails.
///
/// ## Provenance
///
/// - Spec section 12 (Bridge System)
/// - ADR-023 (Bridge Connector)
public func bridgeRegister(
    contextId: String,
    operatorDid: String,
    platform: String,
    mode: String,
    registerFn: BridgeConnectorBridge.RegisterFn = BridgeConnectorBridge.defaultRegister
) throws -> BridgeRegistrationResult {
    try registerFn(contextId, operatorDid, platform, mode)
}

/// Creates a shadow identity for an external platform participant.
///
/// Shadow identities represent non-SCP participants in a bridged context.
/// They carry provenance metadata indicating they are not native SCP
/// identities.
///
/// - Parameters:
///   - bridgeId: The bridge connector ID that owns this shadow.
///   - platformHandle: External platform handle (e.g., `"@user#1234"`).
///   - bridgeMode: Bridge mode: `"relay"`, `"puppet"`, `"api"`, or
///     `"cooperative"`.
///   - contextId: Context the shadow is being created in.
///   - createShadowFn: Bridge function override for testing.
/// - Returns: A ``ShadowIdentityResult`` with the shadow identity details.
/// - Throws: ``ScpError`` if shadow creation fails.
///
/// ## Provenance
///
/// - Spec section 12 (Bridge System)
/// - ADR-023 (Bridge Connector)
public func bridgeCreateShadow(
    bridgeId: String,
    platformHandle: String,
    bridgeMode: String,
    contextId: String,
    createShadowFn: BridgeConnectorBridge.CreateShadowFn = BridgeConnectorBridge.defaultCreateShadow
) throws -> ShadowIdentityResult {
    try createShadowFn(bridgeId, platformHandle, bridgeMode, contextId)
}

// MARK: - Typed overloads

/// Evaluates bridge trust using typed ``ShadowStatus``.
///
/// Convenience overload that accepts a ``ShadowStatus`` enum value
/// instead of a raw string.
///
/// - Parameters:
///   - isBridged: Whether the action originates from a bridge.
///   - isNativeTransport: Whether native SCP transport is used.
///   - shadowStatus: Shadow provenance status.
///   - evaluateTrustFn: Bridge function override for testing.
/// - Returns: Trust tier integer (0-3).
/// - Throws: ``ScpError/Validation(message:code:)`` if evaluation fails.
public func evaluateBridgeTrust(
    isBridged: Bool,
    isNativeTransport: Bool,
    shadowStatus: ShadowStatus,
    evaluateTrustFn: BridgeConnectorBridge.EvaluateTrustFn = BridgeConnectorBridge.defaultEvaluateTrust
) throws -> UInt8 {
    try evaluateTrustFn(isBridged, isNativeTransport, shadowStatus.rawValue)
}

/// Registers a bridge connector using typed ``BridgeMode``.
///
/// Convenience overload that accepts a ``BridgeMode`` enum value
/// instead of a raw string.
///
/// - Parameters:
///   - contextId: The context to register the bridge in.
///   - operatorDid: DID of the human operator accountable for the bridge.
///   - platform: External platform name (e.g., `"discord"`, `"slack"`).
///   - mode: Bridge mode.
///   - registerFn: Bridge function override for testing.
/// - Returns: A ``BridgeRegistrationResult`` with the registration details.
/// - Throws: ``ScpError`` if registration fails.
public func bridgeRegister(
    contextId: String,
    operatorDid: String,
    platform: String,
    mode: BridgeMode,
    registerFn: BridgeConnectorBridge.RegisterFn = BridgeConnectorBridge.defaultRegister
) throws -> BridgeRegistrationResult {
    try registerFn(contextId, operatorDid, platform, mode.rawValue)
}

/// Creates a shadow identity using typed ``BridgeMode``.
///
/// Convenience overload that accepts a ``BridgeMode`` enum value
/// instead of a raw string.
///
/// - Parameters:
///   - bridgeId: The bridge connector ID that owns this shadow.
///   - platformHandle: External platform handle (e.g., `"@user#1234"`).
///   - bridgeMode: Bridge mode.
///   - contextId: Context the shadow is being created in.
///   - createShadowFn: Bridge function override for testing.
/// - Returns: A ``ShadowIdentityResult`` with the shadow identity details.
/// - Throws: ``ScpError`` if shadow creation fails.
public func bridgeCreateShadow(
    bridgeId: String,
    platformHandle: String,
    bridgeMode: BridgeMode,
    contextId: String,
    createShadowFn: BridgeConnectorBridge.CreateShadowFn = BridgeConnectorBridge.defaultCreateShadow
) throws -> ShadowIdentityResult {
    try createShadowFn(bridgeId, platformHandle, bridgeMode.rawValue, contextId)
}
