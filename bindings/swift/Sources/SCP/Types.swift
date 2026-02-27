import Foundation

// MARK: - Message

/// A message received within an SCP context. Carries sender identity, content,
/// ordering metadata, and optional cross-context provenance.
public nonisolated struct Message: Sendable {
    /// The DID of the participant who sent this message.
    public let senderDid: String
    /// The raw message payload.
    public let content: Data
    /// Unix timestamp (milliseconds since epoch) at which the message was sent.
    public let timestamp: UInt64
    /// Monotonically increasing sequence number within the context.
    public let sequence: UInt64
    /// The context ID in which this message was sent.
    public let contextId: String
    /// Cross-context provenance metadata, present when this message originated
    /// outside the current context.
    public let provenance: Provenance?

    /// Memberwise initializer.
    public init(
        senderDid: String,
        content: Data,
        timestamp: UInt64,
        sequence: UInt64,
        contextId: String,
        provenance: Provenance?
    ) {
        self.senderDid = senderDid
        self.content = content
        self.timestamp = timestamp
        self.sequence = sequence
        self.contextId = contextId
        self.provenance = provenance
    }
}

// MARK: - Provenance

/// Cross-context provenance metadata. Present on messages that originated outside
/// the receiving context (e.g., promoted from a child context or relayed via a bridge).
public nonisolated struct Provenance: Sendable {
    /// The context ID from which this message originated.
    public let sourceContext: String
    /// Describes the provenance chain type (e.g., `"promotion"`, `"bridge"`, `"tool"`).
    public let sourceType: String

    /// Memberwise initializer.
    public init(sourceContext: String, sourceType: String) {
        self.sourceContext = sourceContext
        self.sourceType = sourceType
    }
}

// MARK: - Capability

/// A named capability with a declared ceiling, used for UCAN-based authorization.
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

// MARK: - ToolDefinition

/// Describes a tool registered within an SCP context.
public nonisolated struct ToolDefinition: Sendable {
    /// The tool name.
    public let name: String
    /// A human-readable description of what the tool does.
    public let description: String
    /// JSON Schema string describing the tool's input shape.
    public let inputSchema: String
    /// JSON Schema string describing the tool's output shape.
    public let outputSchema: String
    /// The DID of the participant operating this tool.
    public let operatorDid: String
    /// Optional test vectors for conformance verification.
    public let testVectors: [TestVector]?
    /// Optional SHA-256 hash of the tool implementation for integrity verification.
    public let implementationHash: Data?

    /// Memberwise initializer.
    public init(
        name: String,
        description: String,
        inputSchema: String,
        outputSchema: String,
        operatorDid: String,
        testVectors: [TestVector]?,
        implementationHash: Data?
    ) {
        self.name = name
        self.description = description
        self.inputSchema = inputSchema
        self.outputSchema = outputSchema
        self.operatorDid = operatorDid
        self.testVectors = testVectors
        self.implementationHash = implementationHash
    }
}

// MARK: - TestVector

/// An input/output pair used for tool conformance testing.
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
