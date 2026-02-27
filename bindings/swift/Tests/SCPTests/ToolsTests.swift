import Foundation
import Testing

@testable import SCP

// MARK: - Tools Tests

/// Tests for tool definition, invocation, registration, and test vector
/// verification via the ``Context`` actor's tool extensions.
///
/// These tests validate the Swift ergonomics layer and type shapes. The
/// UniFFI bridge stubs return placeholder errors until SCP-103 ships.
///
/// See ADR-026 (Swift SDK), `.docs/scaffold/shared.md` conformance testing,
/// and story SCP-102.
@Suite("Tools Tests")
struct ToolsTests {

    // MARK: - Helpers

    /// Creates a mock ``Context`` with injectable bridge functions for testing.
    private func makeTestContext(
        contextId: String = "tool-test-ctx",
        state: String = "active"
    ) -> Context {
        let handle = MockToolContextHandle(id: contextId, state: state)

        let sendFn: ContextBridge.SendFn = { _, _ in }
        let subscribeFn: ContextBridge.SubscribeFn = { _, _ in }
        let leaveFn: ContextBridge.LeaveFn = { _ in }
        let closeFn: ContextBridge.CloseFn = { _ in }

        return Context(
            handle: handle,
            sendFn: sendFn,
            subscribeFn: subscribeFn,
            leaveFn: leaveFn,
            closeFn: closeFn
        )
    }

    // MARK: - ToolDefinition type shape

    @Test("ToolDefinition stores all fields correctly")
    func toolDefinitionFields() {
        let testVectors = [
            TestVector(input: #"{"x": 1}"#, expectedOutput: #"{"result": 2}"#),
        ]
        let definition = ToolDefinition(
            name: "calculator",
            description: "Performs arithmetic",
            inputSchema: #"{"type": "object"}"#,
            outputSchema: #"{"type": "object"}"#,
            operatorDid: "did:dht:z6MkOperator",
            testVectors: testVectors,
            implementationHash: Data([0x01, 0x02, 0x03])
        )

        #expect(definition.name == "calculator")
        #expect(definition.description == "Performs arithmetic")
        #expect(definition.inputSchema == #"{"type": "object"}"#)
        #expect(definition.outputSchema == #"{"type": "object"}"#)
        #expect(definition.operatorDid == "did:dht:z6MkOperator")
        #expect(definition.testVectors?.count == 1)
        #expect(definition.implementationHash == Data([0x01, 0x02, 0x03]))
    }

    @Test("ToolDefinition with nil optional fields")
    func toolDefinitionNilOptionals() {
        let definition = ToolDefinition(
            name: "simple-tool",
            description: "No test vectors",
            inputSchema: "{}",
            outputSchema: "{}",
            operatorDid: "did:dht:z6MkOp",
            testVectors: nil,
            implementationHash: nil
        )

        #expect(definition.testVectors == nil)
        #expect(definition.implementationHash == nil)
    }

    @Test("ToolDefinition is Sendable")
    func toolDefinitionIsSendable() async {
        let definition: any Sendable = ToolDefinition(
            name: "sendable-tool",
            description: "Test",
            inputSchema: "{}",
            outputSchema: "{}",
            operatorDid: "did:dht:z6MkOp",
            testVectors: nil,
            implementationHash: nil
        )
        #expect(definition is ToolDefinition)
    }

    // MARK: - TestVector type shape

    @Test("TestVector stores input and expected output")
    func testVectorFields() {
        let vector = TestVector(
            input: #"{"operands": [2, 3]}"#,
            expectedOutput: #"{"sum": 5}"#
        )
        #expect(vector.input == #"{"operands": [2, 3]}"#)
        #expect(vector.expectedOutput == #"{"sum": 5}"#)
    }

    @Test("TestVector is Sendable")
    func testVectorIsSendable() async {
        let vector: any Sendable = TestVector(input: "{}", expectedOutput: "{}")
        #expect(vector is TestVector)
    }

    // MARK: - ToolInvocationResult type shape

    @Test("ToolInvocationResult stores all fields")
    func toolInvocationResultFields() {
        let result = ToolInvocationResult(
            output: Data("result".utf8),
            invokerDid: "did:dht:z6MkInvoker",
            contextId: "ctx-001",
            timestamp: 1_700_000_000
        )
        #expect(result.output == Data("result".utf8))
        #expect(result.invokerDid == "did:dht:z6MkInvoker")
        #expect(result.contextId == "ctx-001")
        #expect(result.timestamp == 1_700_000_000)
    }

    // MARK: - ToolVerificationResult type shape

    @Test("ToolVerificationResult stores all fields")
    func toolVerificationResultFields() {
        let result = ToolVerificationResult(
            allTestsPassed: true,
            testsRun: 5,
            testsPassed: 5,
            implementationHashMatches: true,
            verifiedAt: 1_700_000_000,
            verifiedBy: "did:dht:z6MkVerifier"
        )
        #expect(result.allTestsPassed)
        #expect(result.testsRun == 5)
        #expect(result.testsPassed == 5)
        #expect(result.implementationHashMatches)
        #expect(result.verifiedAt == 1_700_000_000)
        #expect(result.verifiedBy == "did:dht:z6MkVerifier")
    }

    @Test("ToolVerificationResult reports failing tests")
    func toolVerificationResultFailing() {
        let result = ToolVerificationResult(
            allTestsPassed: false,
            testsRun: 3,
            testsPassed: 1,
            implementationHashMatches: false,
            verifiedAt: 1_700_000_000,
            verifiedBy: "did:dht:z6MkVerifier"
        )
        #expect(!result.allTestsPassed)
        #expect(result.testsPassed < result.testsRun)
        #expect(!result.implementationHashMatches)
    }

    // MARK: - Tool invocation via Context

    @Test("invokeTool throws bridge error with SCP-TOOL-001")
    func invokeToolThrowsBridgeError() async {
        let context = makeTestContext()
        do {
            _ = try await context.invokeTool("calculator", input: Data("{}".utf8))
            Issue.record("Expected invokeTool to throw")
        } catch let error as ScpError {
            if case .tool(_, let code) = error {
                #expect(code == "SCP-TOOL-001")
            } else {
                Issue.record("Expected ScpError.tool, got \(error)")
            }
        } catch {
            Issue.record("Expected ScpError, got \(type(of: error))")
        }
    }

    @Test("invokeTool throws when context is closed")
    func invokeToolThrowsWhenClosed() async throws {
        let context = makeTestContext()
        try await context.close()

        do {
            _ = try await context.invokeTool("calculator", input: Data("{}".utf8))
            Issue.record("Expected invokeTool to throw on closed context")
        } catch let error as ScpError {
            if case .context(_, let code) = error {
                #expect(code == "SCP-CTX-001")
            } else {
                Issue.record("Expected ScpError.context, got \(error)")
            }
        } catch {
            Issue.record("Expected ScpError, got \(type(of: error))")
        }
    }

    // MARK: - Tool registration via Context

    @Test("registerTool throws bridge error with SCP-TOOL-002")
    func registerToolThrowsBridgeError() async {
        let context = makeTestContext()
        let definition = ToolDefinition(
            name: "test-tool",
            description: "A test tool",
            inputSchema: "{}",
            outputSchema: "{}",
            operatorDid: "did:dht:z6MkOp",
            testVectors: nil,
            implementationHash: nil
        )
        do {
            _ = try await context.registerTool(definition)
            Issue.record("Expected registerTool to throw")
        } catch let error as ScpError {
            if case .tool(_, let code) = error {
                #expect(code == "SCP-TOOL-002")
            } else {
                Issue.record("Expected ScpError.tool, got \(error)")
            }
        } catch {
            Issue.record("Expected ScpError, got \(type(of: error))")
        }
    }

    @Test("registerTool throws when context is closed")
    func registerToolThrowsWhenClosed() async throws {
        let context = makeTestContext()
        try await context.close()

        let definition = ToolDefinition(
            name: "test-tool",
            description: "A test tool",
            inputSchema: "{}",
            outputSchema: "{}",
            operatorDid: "did:dht:z6MkOp",
            testVectors: nil,
            implementationHash: nil
        )
        do {
            _ = try await context.registerTool(definition)
            Issue.record("Expected registerTool to throw on closed context")
        } catch let error as ScpError {
            if case .context(_, let code) = error {
                #expect(code == "SCP-CTX-001")
            } else {
                Issue.record("Expected ScpError.context, got \(error)")
            }
        } catch {
            Issue.record("Expected ScpError, got \(type(of: error))")
        }
    }

    // MARK: - Tool verification via Context

    @Test("verifyTool throws bridge error with SCP-TOOL-003")
    func verifyToolThrowsBridgeError() async {
        let context = makeTestContext()
        do {
            _ = try await context.verifyTool("calculator")
            Issue.record("Expected verifyTool to throw")
        } catch let error as ScpError {
            if case .tool(_, let code) = error {
                #expect(code == "SCP-TOOL-003")
            } else {
                Issue.record("Expected ScpError.tool, got \(error)")
            }
        } catch {
            Issue.record("Expected ScpError, got \(type(of: error))")
        }
    }

    @Test("verifyTool throws when context is closed")
    func verifyToolThrowsWhenClosed() async throws {
        let context = makeTestContext()
        try await context.close()

        do {
            _ = try await context.verifyTool("calculator")
            Issue.record("Expected verifyTool to throw on closed context")
        } catch let error as ScpError {
            if case .context(_, let code) = error {
                #expect(code == "SCP-CTX-001")
            } else {
                Issue.record("Expected ScpError.context, got \(error)")
            }
        } catch {
            Issue.record("Expected ScpError, got \(type(of: error))")
        }
    }

    // MARK: - Test vector verification

    @Test("ToolDefinition with test vectors preserves vector data")
    func toolDefinitionPreservesTestVectors() {
        let vectors = [
            TestVector(input: #"{"a": 1, "b": 2}"#, expectedOutput: #"{"sum": 3}"#),
            TestVector(input: #"{"a": 10, "b": 20}"#, expectedOutput: #"{"sum": 30}"#),
            TestVector(input: #"{"a": -1, "b": 1}"#, expectedOutput: #"{"sum": 0}"#),
        ]
        let definition = ToolDefinition(
            name: "add",
            description: "Adds two numbers",
            inputSchema: #"{"type": "object", "properties": {"a": {"type": "number"}, "b": {"type": "number"}}}"#,
            outputSchema: #"{"type": "object", "properties": {"sum": {"type": "number"}}}"#,
            operatorDid: "did:dht:z6MkMath",
            testVectors: vectors,
            implementationHash: Data([0xAA, 0xBB, 0xCC])
        )

        #expect(definition.testVectors?.count == 3)
        #expect(definition.testVectors?[0].input == #"{"a": 1, "b": 2}"#)
        #expect(definition.testVectors?[0].expectedOutput == #"{"sum": 3}"#)
        #expect(definition.testVectors?[2].expectedOutput == #"{"sum": 0}"#)
    }

} // end ToolsTests

// MARK: - Mock ContextHandle for Tool Tests

/// Mock implementation of ``ContextHandleProtocol`` for tool testing.
private final class MockToolContextHandle: ContextHandleProtocol, @unchecked Sendable {
    let id: String
    let initialState: String

    init(id: String = "tool-test-ctx", state: String = "active") {
        self.id = id
        self.initialState = state
    }

    func contextId() -> String { id }
    func state() -> String { initialState }
}
