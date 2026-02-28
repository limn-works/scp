import Foundation

// Message, ToolDefinition, and other core types are now defined by UniFFI in
// ScpBindings.swift. This file provides additional Swift-idiomatic convenience
// types that do NOT conflict with UniFFI-generated types.

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
/// This type is a pure Swift convenience type. It does not conflict with any
/// UniFFI-generated type.
public nonisolated struct TestVector: Sendable {
    /// The serialized input value (JSON).
    public let input: String
    /// The expected serialized output value (JSON).
    public let expectedOutput: String

    /// Memberwise initializer.
    public init(input: String, expectedOutput: String) {
        self.input = input
        self.expectedOutput = expectedOutput
    }
}
