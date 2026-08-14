import Foundation

// ConsequenceRule.swift — Typed Swift SDK shapes for ADR-017 consequence rules.
//
// Mirrors `scp_protocol::trust::consequence::{ConsequenceRule, ConsequenceTrigger,
// ConsequenceAction, EnforcementSeverity}` and `scp_protocol::context::params::
// ConsequenceConfig`. Provides Codable conformance so SDK call sites can pass
// `[ConsequenceRule]` and the SDK serializes to the Rust serde wire format
// before passing the JSON string into `UniFFIContextParams.consequenceRulesJson`.
//
// These are pure Swift convenience types — they do not conflict with any
// UniFFI-generated type.
//
// Provenance: ADR-017 (Trust Engine), §9.3 (Consequence Rules), #1531

// MARK: - AccessScope

/// Read/Write/Both scope for ``EnforcementSeverity/revokeAccess(did:access:)``.
///
/// Mirrors `scp_protocol::context::governance::AccessScope`.
public nonisolated enum AccessScope: String, Sendable, Codable, CaseIterable {
    case read = "Read"
    case write = "Write"
    case both = "Both"
}

// MARK: - ConsequenceCapability

/// A capability that may be referenced inside
/// ``EnforcementSeverity/suspendCapability(capabilities:)``.
///
/// Mirrors `scp_protocol::context::roles::Capability`. The unit variants are
/// represented by ``unit(name:)`` carrying the variant name; payload-bearing
/// variants ([outletCall], [custom]) carry their string field directly.
public nonisolated enum ConsequenceCapability: Sendable, Codable, Equatable {
    /// A unit-variant capability. The `name` must match a Rust `Capability`
    /// enum variant name exactly, e.g. `MessagesRead`, `MessagesWrite`,
    /// `GovernanceVote`.
    case unit(name: String)

    /// Action-outlet invocation capability for a specific registered outlet.
    /// Mirrors `Capability::OutletCall(OutletId)`. Encodes as
    /// `{"OutletCall": "<id>"}`.
    case outletCall(outletId: String)

    /// Context-specific custom capability.
    /// Encodes as `{"Custom": "<name>"}`.
    case custom(name: String)

    public func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        switch self {
        case let .unit(name):
            try container.encode(name)
        case let .outletCall(outletId):
            try container.encode(["OutletCall": outletId])
        case let .custom(name):
            try container.encode(["Custom": name])
        }
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        if let unitName = try? container.decode(String.self) {
            self = .unit(name: unitName)
            return
        }
        let dict = try container.decode([String: String].self)
        if let outletId = dict["OutletCall"] {
            self = .outletCall(outletId: outletId)
            return
        }
        if let name = dict["Custom"] {
            self = .custom(name: name)
            return
        }
        throw DecodingError.dataCorruptedError(
            in: container,
            debugDescription: "Unknown ConsequenceCapability variant: \(dict.keys)"
        )
    }
}

// MARK: - EnforcementSeverity

/// Unified enforcement severity for consequence rules and governance actions.
///
/// Mirrors `scp_protocol::trust::consequence::EnforcementSeverity`. Four tiers
/// ordered from least to most severe:
///
/// 1. ``suspendCapability(capabilities:)`` — application-level block on a
///    specific capability set.
/// 2. ``suspendAccess`` — application-level block on the member's full
///    capability set.
/// 3. ``revokeAccess(did:access:)`` — cryptographic revocation. Only allowed
///    in consequence rules when ``ConsequenceConfig/allowAutomaticAccessRevocation``
///    is `true`.
/// 4. ``removeMember(did:reason:)`` — MLS group ejection. Never allowed in
///    consequence rules (governance-only).
///
/// The variant names are pinned in ``ENFORCEMENT_SEVERITY_VARIANT_NAMES``.
public nonisolated enum EnforcementSeverity: Sendable, Codable, Equatable {
    case suspendCapability(capabilities: [ConsequenceCapability])
    case suspendAccess
    case revokeAccess(did: String, access: AccessScope)
    case removeMember(did: String, reason: String?)

    /// Mirror of `scp_protocol::trust::consequence::MAX_CAPABILITY_SUSPENSION_COUNT`.
    public static let maxSuspendCount: Int = 32

    public func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        switch self {
        case .suspendAccess:
            try container.encode("SuspendAccess")
        case let .suspendCapability(capabilities):
            let payload = SuspendCapabilityPayload(capabilities: capabilities)
            try container.encode(["SuspendCapability": payload])
        case let .revokeAccess(did, access):
            let payload = RevokeAccessPayload(did: did, access: access)
            try container.encode(["RevokeAccess": payload])
        case let .removeMember(did, reason):
            let payload = RemoveMemberPayload(did: did, reason: reason)
            try container.encode(["RemoveMember": payload])
        }
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        if let unit = try? container.decode(String.self) {
            switch unit {
            case "SuspendAccess":
                self = .suspendAccess
                return
            default:
                throw DecodingError.dataCorruptedError(
                    in: container,
                    debugDescription: "Unknown unit EnforcementSeverity: \(unit)"
                )
            }
        }
        let raw = try container.decode([String: AnyCodable].self)
        if let payload = raw["SuspendCapability"] {
            let decoded = try payload.decode(as: SuspendCapabilityPayload.self)
            self = .suspendCapability(capabilities: decoded.capabilities)
            return
        }
        if let payload = raw["RevokeAccess"] {
            let decoded = try payload.decode(as: RevokeAccessPayload.self)
            self = .revokeAccess(did: decoded.did, access: decoded.access)
            return
        }
        if let payload = raw["RemoveMember"] {
            let decoded = try payload.decode(as: RemoveMemberPayload.self)
            self = .removeMember(did: decoded.did, reason: decoded.reason)
            return
        }
        throw DecodingError.dataCorruptedError(
            in: container,
            debugDescription: "Unknown EnforcementSeverity variant: \(raw.keys)"
        )
    }
}

private struct SuspendCapabilityPayload: Codable {
    let capabilities: [ConsequenceCapability]
}

private struct RevokeAccessPayload: Codable {
    let did: String
    let access: AccessScope
}

private struct RemoveMemberPayload: Codable {
    let did: String
    let reason: String?
}

/// Frozen list of ``EnforcementSeverity`` variant short names. Pinned by the
/// SDK round-trip tests so renaming a variant trips a compile or test error.
public let enforcementSeverityVariantNames: [String] = [
    "SuspendCapability",
    "SuspendAccess",
    "RevokeAccess",
    "RemoveMember"
]

// MARK: - ConsequenceTrigger

/// The condition that triggers a consequence rule.
///
/// Mirrors `scp_protocol::trust::consequence::ConsequenceTrigger`.
///
/// The variant names are pinned in ``CONSEQUENCE_TRIGGER_VARIANT_NAMES``.
public nonisolated enum ConsequenceTrigger: Sendable, Codable, Equatable {
    case messageVelocity
    case outletRateExceeded
    case warningCount
    case custom(key: String)

    public func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        switch self {
        case .messageVelocity:
            try container.encode("MessageVelocity")
        case .outletRateExceeded:
            try container.encode("OutletRateExceeded")
        case .warningCount:
            try container.encode("WarningCount")
        case let .custom(key):
            try container.encode(["Custom": key])
        }
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        if let unit = try? container.decode(String.self) {
            switch unit {
            case "MessageVelocity":
                self = .messageVelocity
                return
            case "OutletRateExceeded":
                self = .outletRateExceeded
                return
            case "WarningCount":
                self = .warningCount
                return
            default:
                throw DecodingError.dataCorruptedError(
                    in: container,
                    debugDescription: "Unknown unit ConsequenceTrigger: \(unit)"
                )
            }
        }
        let dict = try container.decode([String: String].self)
        if let key = dict["Custom"] {
            self = .custom(key: key)
            return
        }
        throw DecodingError.dataCorruptedError(
            in: container,
            debugDescription: "Unknown ConsequenceTrigger variant: \(dict.keys)"
        )
    }
}

/// Frozen list of ``ConsequenceTrigger`` variant short names.
public let consequenceTriggerVariantNames: [String] = [
    "MessageVelocity",
    "OutletRateExceeded",
    "WarningCount",
    "Custom"
]

// MARK: - ConsequenceAction

/// The action taken when a ``ConsequenceRule`` fires.
///
/// Mirrors `scp_protocol::trust::consequence::ConsequenceAction`.
public nonisolated enum ConsequenceAction: Sendable, Codable, Equatable {
    case enforcement(EnforcementSeverity)
    case assignRole(toRole: String)

    public func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        switch self {
        case let .enforcement(severity):
            try container.encode(["Enforcement": severity])
        case let .assignRole(toRole):
            try container.encode(["AssignRole": AssignRolePayload(toRole: toRole)])
        }
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        let raw = try container.decode([String: AnyCodable].self)
        if let payload = raw["Enforcement"] {
            let severity = try payload.decode(as: EnforcementSeverity.self)
            self = .enforcement(severity)
            return
        }
        if let payload = raw["AssignRole"] {
            let decoded = try payload.decode(as: AssignRolePayload.self)
            self = .assignRole(toRole: decoded.toRole)
            return
        }
        throw DecodingError.dataCorruptedError(
            in: container,
            debugDescription: "Unknown ConsequenceAction variant: \(raw.keys)"
        )
    }
}

private struct AssignRolePayload: Codable {
    let toRole: String

    enum CodingKeys: String, CodingKey {
        case toRole = "to_role"
    }
}

/// Frozen list of ``ConsequenceAction`` variant short names.
public let consequenceActionVariantNames: [String] = ["Enforcement", "AssignRole"]

// MARK: - ConsequenceRule

/// A declared consequence rule (ADR-017 §1).
///
/// Mirrors `scp_protocol::trust::consequence::ConsequenceRule`. Each rule
/// specifies a trigger condition, an enforcement action, a numeric threshold,
/// and a time window for counting events.
///
/// Rules are visible to all participants before they join — the opt-in
/// contract for consequences. The SDK serializes the array to the wire JSON
/// shape via ``encodeConsequenceRulesJson(_:)`` before populating
/// `UniFFIContextParams.consequenceRulesJson`.
public nonisolated struct ConsequenceRule: Sendable, Codable, Equatable {
    /// Trigger condition.
    public let trigger: ConsequenceTrigger
    /// Enforcement action taken when the trigger fires.
    public let action: ConsequenceAction
    /// Threshold count: when matching events within the time window meet or
    /// exceed this value, the consequence fires. Must be > 0.
    public let threshold: UInt64
    /// Time window in seconds. Only events in `[now - windowSecs, now]` count.
    public let windowSecs: UInt64

    public init(
        trigger: ConsequenceTrigger,
        action: ConsequenceAction,
        threshold: UInt64,
        windowSecs: UInt64
    ) {
        self.trigger = trigger
        self.action = action
        self.threshold = threshold
        self.windowSecs = windowSecs
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(trigger, forKey: .trigger)
        try container.encode(action, forKey: .action)
        try container.encode(threshold, forKey: .threshold)
        try container.encode(WindowDuration(secs: windowSecs, nanos: 0), forKey: .window)
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        trigger = try container.decode(ConsequenceTrigger.self, forKey: .trigger)
        action = try container.decode(ConsequenceAction.self, forKey: .action)
        threshold = try container.decode(UInt64.self, forKey: .threshold)
        let window = try container.decode(WindowDuration.self, forKey: .window)
        windowSecs = window.secs
    }

    private enum CodingKeys: String, CodingKey {
        case trigger
        case action
        case threshold
        case window
    }
}

private struct WindowDuration: Codable, Equatable {
    let secs: UInt64
    let nanos: UInt32
}

// MARK: - ConsequenceConfig

/// Per-context configuration governing which enforcement severities
/// consequence rules may reference (ADR-017, #1531).
///
/// Mirrors `scp_protocol::context::params::ConsequenceConfig`. Defaults to
/// `allowAutomaticAccessRevocation = false`.
public nonisolated struct ConsequenceConfig: Sendable, Codable, Equatable {
    /// If `true`, consequence rules may reference
    /// ``EnforcementSeverity/revokeAccess(did:access:)`` — automatic
    /// cryptographic revocation of a member's access keys.
    public let allowAutomaticAccessRevocation: Bool

    public init(allowAutomaticAccessRevocation: Bool = false) {
        self.allowAutomaticAccessRevocation = allowAutomaticAccessRevocation
    }

    private enum CodingKeys: String, CodingKey {
        case allowAutomaticAccessRevocation = "allow_automatic_access_revocation"
    }
}

// MARK: - JSON encoders

/// Encodes a typed `[ConsequenceRule]` array to the JSON wire shape expected
/// by the Rust bridge. Public for SDK call sites that build
/// `UniFFIContextParams.consequenceRulesJson` from typed values.
///
/// - Throws: `EncodingError` if a variant cannot be serialized.
public func encodeConsequenceRulesJson(_ rules: [ConsequenceRule]) throws -> String {
    let encoder = JSONEncoder()
    encoder.outputFormatting = [.sortedKeys]
    let data = try encoder.encode(rules)
    guard let string = String(data: data, encoding: .utf8) else {
        throw EncodingError.invalidValue(
            rules,
            EncodingError.Context(
                codingPath: [],
                debugDescription: "ConsequenceRule JSON is not valid UTF-8"
            )
        )
    }
    return string
}

/// Encodes a typed ``ConsequenceConfig`` to the JSON wire shape expected by
/// the Rust bridge. Field names are snake_cased to match
/// `serde_json::to_string(&ConsequenceConfig)`.
public func encodeConsequenceConfigJson(_ config: ConsequenceConfig) throws -> String {
    let encoder = JSONEncoder()
    encoder.outputFormatting = [.sortedKeys]
    let data = try encoder.encode(config)
    guard let string = String(data: data, encoding: .utf8) else {
        throw EncodingError.invalidValue(
            config,
            EncodingError.Context(
                codingPath: [],
                debugDescription: "ConsequenceConfig JSON is not valid UTF-8"
            )
        )
    }
    return string
}

// MARK: - ContextParams typed convenience extension

public extension ContextParams {
    /// Convenience initializer that accepts typed ``ConsequenceRule`` /
    /// ``ConsequenceConfig`` values and serializes them to the JSON wire shape
    /// that the underlying UniFFI ``ContextParams`` expects.
    ///
    /// Use this in preference to constructing `ContextParams` with raw JSON
    /// strings — it removes the round-trip through hand-rolled JSON and gives
    /// callers compile-time checks against the discriminated unions.
    ///
    /// - Throws: `EncodingError` if a typed value cannot be serialized.
    init(
        mode: ContextMode,
        ceiling: [String],
        ceilingPolicy: CeilingPolicy,
        governance: GovernanceModel,
        memoryScope: MemoryScope,
        ttlSeconds: UInt64,
        promotable: Bool,
        minProtocolVersion: UInt16 = 0,
        maxChainDepth: UInt8? = nil,
        maxNestingDepth: UInt32? = nil,
        sessionCap: UInt32? = nil,
        economicPolicy: String? = nil,
        consequenceRules: [ConsequenceRule]?,
        consequenceConfig: ConsequenceConfig?
    ) throws {
        let rulesJson = try consequenceRules.map { try encodeConsequenceRulesJson($0) }
        let configJson = try consequenceConfig.map { try encodeConsequenceConfigJson($0) }
        self.init(
            mode: mode,
            ceiling: ceiling,
            ceilingPolicy: ceilingPolicy,
            governance: governance,
            memoryScope: memoryScope,
            ttlSeconds: ttlSeconds,
            promotable: promotable,
            minProtocolVersion: minProtocolVersion,
            maxChainDepth: maxChainDepth,
            maxNestingDepth: maxNestingDepth,
            sessionCap: sessionCap,
            economicPolicy: economicPolicy,
            consequenceRulesJson: rulesJson,
            consequenceConfigJson: configJson
        )
    }
}

// MARK: - AnyCodable helper

/// Minimal type-erased codable wrapper used by the discriminated-union
/// decoders to defer payload decoding until the variant is known.
private struct AnyCodable: Codable {
    let value: Any

    init(_ value: Any) {
        self.value = value
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        if container.decodeNil() {
            value = NSNull()
        } else if let bool = try? container.decode(Bool.self) {
            value = bool
        } else if let int = try? container.decode(Int64.self) {
            value = int
        } else if let uint = try? container.decode(UInt64.self) {
            value = uint
        } else if let double = try? container.decode(Double.self) {
            value = double
        } else if let string = try? container.decode(String.self) {
            value = string
        } else if let array = try? container.decode([AnyCodable].self) {
            value = array
        } else if let dict = try? container.decode([String: AnyCodable].self) {
            value = dict
        } else {
            throw DecodingError.dataCorruptedError(
                in: container,
                debugDescription: "Unsupported AnyCodable value"
            )
        }
    }

    func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        switch value {
        case is NSNull:
            try container.encodeNil()
        case let bool as Bool:
            try container.encode(bool)
        case let int as Int:
            try container.encode(int)
        case let int as Int64:
            try container.encode(int)
        case let uint as UInt64:
            try container.encode(uint)
        case let double as Double:
            try container.encode(double)
        case let string as String:
            try container.encode(string)
        case let array as [AnyCodable]:
            try container.encode(array)
        case let dict as [String: AnyCodable]:
            try container.encode(dict)
        default:
            throw EncodingError.invalidValue(
                value,
                EncodingError.Context(
                    codingPath: encoder.codingPath,
                    debugDescription: "Unsupported AnyCodable value"
                )
            )
        }
    }

    /// Re-encodes this wrapper as JSON and decodes it as `T`. Used by the
    /// discriminated-union decoders to recover typed payloads after the
    /// variant key is known.
    func decode<T: Decodable>(as _: T.Type) throws -> T {
        let data = try JSONEncoder().encode(self)
        return try JSONDecoder().decode(T.self, from: data)
    }
}
