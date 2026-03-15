import Foundation

// Message, ToolDefinition, and other core types are now defined by UniFFI in
// ScpBindings.swift. This file provides additional Swift-idiomatic convenience
// types that do NOT conflict with UniFFI-generated types.

// MARK: - CustodyType

/// Key custody method for identity key management (spec section 3.2).
///
/// Determines where cryptographic keys are stored and managed.
/// The `rawValue` matches the wire-format string expected by the FFI bridge.
///
/// This type is a pure Swift convenience type. It does not conflict with any
/// UniFFI-generated type.
///
/// ## Provenance
///
/// - Spec section 3.2 (Key Custody)
public nonisolated enum CustodyType: String, Sendable, CaseIterable {
    /// Platform-native secure storage (Keychain on macOS/iOS, Keystore
    /// on Android, credential manager on Windows/Linux). Default.
    case platform
    /// Ephemeral in-memory key store, suitable for testing or short-lived
    /// agents. Keys are lost on process exit.
    case inMemory = "in_memory"
    /// Software-backed file-based key store with passphrase protection.
    case software
}

// MARK: - BridgeMode

/// Bridge operating mode (spec section 12.2).
///
/// Determines how a bridge connector relays messages between an external
/// platform and an SCP context.
///
/// This type is a pure Swift convenience type. It does not conflict with any
/// UniFFI-generated type.
///
/// ## Provenance
///
/// - Spec section 12.2 (Bridge Connectors)
/// - ADR-023 (Bridge Connector)
public nonisolated enum BridgeMode: String, Sendable, CaseIterable {
    /// Messages forwarded verbatim. Bridge is a transparent pipe.
    case relay
    /// Bridge controls external-side identity and can act on behalf
    /// of participants.
    case puppet
    /// Bridge exposes a programmatic API rather than a chat interface.
    case api
    /// Both SCP and external participants have equal agency.
    case cooperative
}

// MARK: - ShadowStatus

/// Shadow identity provenance status (spec section 12.2).
///
/// Indicates how a bridged participant's identity was established.
/// Used for trust evaluation.
///
/// This type is a pure Swift convenience type. It does not conflict with any
/// UniFFI-generated type.
///
/// ## Provenance
///
/// - Spec section 12.2 (Bridge Connectors)
public nonisolated enum ShadowStatus: String, Sendable, CaseIterable {
    /// Identity is a shadow -- no verified link to external identity.
    case shadow
    /// External participant has completed identity claim verification.
    case claimed
}

// MARK: - Capability

/// A named capability with a declared ceiling, used for UCAN-based authorization.
///
/// This type is a pure Swift convenience type. It does not conflict with any
/// UniFFI-generated type.
public nonisolated struct Capability: Sendable {
    /// The capability name (e.g., `"messages:write"`, `"context:close"`).
    public let name: String
    /// The ceiling value constraining this capability (e.g., `"*"`, `"read-only"`).
    public let ceiling: String

    /// Memberwise initializer.
    public init(name: String, ceiling: String) {
        self.name = name
        self.ceiling = ceiling
    }
}

// MARK: - TestVector

/// An input/output pair used for tool conformance testing.
///
/// Mirrors `scp_core::context::tools::TestVector`. Each vector carries a
/// human-readable description of what it validates, plus the input and
/// expected output as JSON strings.
///
/// This type is a pure Swift convenience type. It does not conflict with any
/// UniFFI-generated type.
///
/// Provenance: spec §7.3.3, ADR-010 (phase-2)
public nonisolated struct TestVector: Sendable {
    /// Human-readable description of what this test vector validates.
    public let description: String
    /// The serialized input value (JSON).
    public let input: String
    /// The expected serialized output value (JSON).
    public let expectedOutput: String

    /// Memberwise initializer.
    public init(description: String, input: String, expectedOutput: String) {
        self.description = description
        self.input = input
        self.expectedOutput = expectedOutput
    }
}
