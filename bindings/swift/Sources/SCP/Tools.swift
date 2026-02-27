import Foundation

// MARK: - ToolInvocationResult

/// The result of invoking a tool within an SCP context.
///
/// Contains the tool's output payload and provenance metadata recording which
/// agent invoked the tool, in which context, and when.
///
/// See `.docs/sketch.md` section 4 "Tools (within a context)".
public nonisolated struct ToolInvocationResult: Sendable {
    /// The serialized output from the tool invocation (JSON).
    public let output: Data

    /// The DID of the agent that invoked the tool.
    public let invokerDid: String

    /// The context ID in which the tool was invoked.
    public let contextId: String

    /// Unix timestamp (milliseconds since epoch) of the invocation.
    public let timestamp: UInt64

    /// Memberwise initializer.
    public init(
        output: Data,
        invokerDid: String,
        contextId: String,
        timestamp: UInt64
    ) {
        self.output = output
        self.invokerDid = invokerDid
        self.contextId = contextId
        self.timestamp = timestamp
    }
}

// MARK: - ToolVerificationResult

/// The result of verifying a tool against its registered test vectors.
///
/// Any agent can test a tool against its registered test vectors at any time.
/// This struct captures the outcome of that verification.
///
/// See `.docs/sketch.md` section 4 "Verify Tool Integrity".
public nonisolated struct ToolVerificationResult: Sendable {
    /// Whether all test vectors passed.
    public let allTestsPassed: Bool

    /// The total number of test vectors run.
    public let testsRun: Int

    /// The number of test vectors that passed.
    public let testsPassed: Int

    /// Whether the implementation hash matches the registered hash.
    public let implementationHashMatches: Bool

    /// Unix timestamp (milliseconds since epoch) when verification was performed.
    public let verifiedAt: UInt64

    /// The DID of the agent that performed the verification.
    public let verifiedBy: String

    /// Memberwise initializer.
    public init(
        allTestsPassed: Bool,
        testsRun: Int,
        testsPassed: Int,
        implementationHashMatches: Bool,
        verifiedAt: UInt64,
        verifiedBy: String
    ) {
        self.allTestsPassed = allTestsPassed
        self.testsRun = testsRun
        self.testsPassed = testsPassed
        self.implementationHashMatches = implementationHashMatches
        self.verifiedAt = verifiedAt
        self.verifiedBy = verifiedBy
    }
}

// MARK: - UniFFI Bridge Stubs

/// Invoke a tool via the UniFFI bridge.
///
/// Placeholder stub for the UniFFI-generated `tool_invoke` function.
/// When the XCFramework ships (SCP-103), this free function is replaced by
/// the auto-generated binding.
///
/// - Parameters:
///   - contextId: The context in which to invoke the tool.
///   - toolName: The name of the tool to invoke.
///   - inputJson: The tool input as serialized JSON.
///   - completion: Callback delivering the result or an error.
internal func scpToolInvoke(
    contextId: String,
    toolName: String,
    inputJson: Data,
    completion: @Sendable @escaping (Result<ToolInvocationResult, ScpError>) -> Void
) {
    // Placeholder: replaced by UniFFI-generated binding (SCP-103).
    completion(.failure(.tool(
        message: "UniFFI bridge not yet available — build ScpFFI.xcframework (SCP-103)",
        code: "SCP-TOOL-001"
    )))
}

/// Register a tool via the UniFFI bridge.
///
/// Placeholder stub for the UniFFI-generated `tool_register` function.
/// When the XCFramework ships (SCP-103), this free function is replaced by
/// the auto-generated binding.
///
/// - Parameters:
///   - contextId: The context in which to register the tool.
///   - definition: The tool definition to register.
///   - completion: Callback delivering the assigned tool ID or an error.
internal func scpToolRegister(
    contextId: String,
    definition: ToolDefinition,
    completion: @Sendable @escaping (Result<String, ScpError>) -> Void
) {
    // Placeholder: replaced by UniFFI-generated binding (SCP-103).
    completion(.failure(.tool(
        message: "UniFFI bridge not yet available — build ScpFFI.xcframework (SCP-103)",
        code: "SCP-TOOL-002"
    )))
}

/// Verify a tool via the UniFFI bridge.
///
/// Placeholder stub for the UniFFI-generated `tool_verify` function.
/// When the XCFramework ships (SCP-103), this free function is replaced by
/// the auto-generated binding.
///
/// - Parameters:
///   - contextId: The context containing the tool.
///   - toolName: The name of the tool to verify.
///   - completion: Callback delivering the verification result or an error.
internal func scpToolVerify(
    contextId: String,
    toolName: String,
    completion: @Sendable @escaping (Result<ToolVerificationResult, ScpError>) -> Void
) {
    // Placeholder: replaced by UniFFI-generated binding (SCP-103).
    completion(.failure(.tool(
        message: "UniFFI bridge not yet available — build ScpFFI.xcframework (SCP-103)",
        code: "SCP-TOOL-003"
    )))
}

// MARK: - Context Tool Extensions

/// Tool invocation and management extensions for ``Context``.
///
/// These methods follow the cross-language naming convention defined in
/// `.docs/scaffold/shared.md`: Swift uses `ctx.invokeTool()` matching the
/// camelCase convention for Swift methods.
///
/// ## Provenance
///
/// - ADR-026 (Swift SDK) in `.docs/adrs/phase-5.md`
/// - `.docs/scaffold/shared.md` cross-language naming table
/// - Story SCP-101
extension Context {

    /// Invokes a registered tool in this context.
    ///
    /// The input is validated against the tool's input schema, the invocation
    /// is authorized via UCAN capability checks, and the result carries full
    /// provenance metadata.
    ///
    /// - Parameters:
    ///   - tool: The name of the tool to invoke.
    ///   - input: The tool input as serialized JSON.
    /// - Returns: A ``ToolInvocationResult`` containing the tool's output and
    ///   provenance metadata.
    /// - Throws: ``ScpError/tool(message:code:)`` if the tool is not found,
    ///   the input fails schema validation, or the invocation is unauthorized.
    ///   ``ScpError/context(message:code:)`` if the context is not active.
    public func invokeTool(_ tool: String, input: Data) async throws -> ToolInvocationResult {
        guard state == .active else {
            throw ScpError.context(
                message: "Context is not active",
                code: "SCP-CTX-001"
            )
        }
        return try await withCheckedThrowingContinuation {
            (continuation: CheckedContinuation<ToolInvocationResult, Error>) in
            scpToolInvoke(contextId: contextId, toolName: tool, inputJson: input) { result in
                switch result {
                case .success(let invocationResult):
                    continuation.resume(returning: invocationResult)
                case .failure(let error):
                    continuation.resume(throwing: error)
                }
            }
        }
    }

    /// Registers a tool in this context.
    ///
    /// The tool definition includes its name, description, input/output schemas,
    /// test vectors, and the operator DID. Only the context creator or admin
    /// can register tools.
    ///
    /// - Parameter definition: The ``ToolDefinition`` describing the tool.
    /// - Returns: The assigned tool identifier.
    /// - Throws: ``ScpError/tool(message:code:)`` if registration fails.
    ///   ``ScpError/context(message:code:)`` if the context is not active.
    public func registerTool(_ definition: ToolDefinition) async throws -> String {
        guard state == .active else {
            throw ScpError.context(
                message: "Context is not active",
                code: "SCP-CTX-001"
            )
        }
        return try await withCheckedThrowingContinuation {
            (continuation: CheckedContinuation<String, Error>) in
            scpToolRegister(contextId: contextId, definition: definition) { result in
                switch result {
                case .success(let toolId):
                    continuation.resume(returning: toolId)
                case .failure(let error):
                    continuation.resume(throwing: error)
                }
            }
        }
    }

    /// Verifies a tool against its registered test vectors.
    ///
    /// Any agent can test a tool at any time. The verification runs each test
    /// vector through the tool and compares actual output against expected output.
    ///
    /// - Parameter tool: The name of the tool to verify.
    /// - Returns: A ``ToolVerificationResult`` describing the outcome.
    /// - Throws: ``ScpError/tool(message:code:)`` if the tool is not found
    ///   or verification fails. ``ScpError/context(message:code:)`` if the
    ///   context is not active.
    public func verifyTool(_ tool: String) async throws -> ToolVerificationResult {
        guard state == .active else {
            throw ScpError.context(
                message: "Context is not active",
                code: "SCP-CTX-001"
            )
        }
        return try await withCheckedThrowingContinuation {
            (continuation: CheckedContinuation<ToolVerificationResult, Error>) in
            scpToolVerify(contextId: contextId, toolName: tool) { result in
                switch result {
                case .success(let verificationResult):
                    continuation.resume(returning: verificationResult)
                case .failure(let error):
                    continuation.resume(throwing: error)
                }
            }
        }
    }
}
