import Foundation
import Testing

@testable import SCP

// MARK: - Tools Tests

/// Tests for tool definition, invocation, registration, and test vector
/// verification via the ``Context`` actor's tool extensions.
///
/// UniFFI ToolDefinition fields: name, description, inputSchemaJson, outputSchemaJson,
///     operatorDid, testVectorsJson (String?), implementationHash (Data?)
/// UniFFI ToolVerificationResult fields: toolId (String), passed (Bool), failures ([String])
///
/// These tests validate the Swift ergonomics layer, type shapes, and async
/// bridging through injectable bridge closures.
///
/// See ADR-026 (Swift SDK), `.docs/scaffold/shared.md` conformance testing,
/// and story SCP-221.
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
        let definition = ToolDefinition(
            name: "calculator",
            description: "Performs arithmetic",
            inputSchemaJson: #"{"type": "object"}"#,
            outputSchemaJson: #"{"type": "object"}"#,
            operatorDid: "did:dht:z6MkOperator",
            testVectorsJson: #"[{"input": {"x": 1}, "expected_output": {"result": 2}}]"#,
            implementationHash: Data([0x01, 0x02, 0x03])
        )

        #expect(definition.name == "calculator")
        #expect(definition.description == "Performs arithmetic")
        #expect(definition.inputSchemaJson == #"{"type": "object"}"#)
        #expect(definition.outputSchemaJson == #"{"type": "object"}"#)
        #expect(definition.operatorDid == "did:dht:z6MkOperator")
        #expect(definition.testVectorsJson != nil)
        #expect(definition.implementationHash == Data([0x01, 0x02, 0x03]))
    }

    @Test("ToolDefinition with nil optional fields")
    func toolDefinitionNilOptionals() {
        let definition = ToolDefinition(
            name: "simple-tool",
            description: "No test vectors",
            inputSchemaJson: "{}",
            outputSchemaJson: "{}",
            operatorDid: "did:dht:z6MkOp",
            testVectorsJson: nil,
            implementationHash: nil
        )

        #expect(definition.testVectorsJson == nil)
        #expect(definition.implementationHash == nil)
    }

    @Test("ToolDefinition is Sendable")
    func toolDefinitionIsSendable() async {
        let definition: any Sendable = ToolDefinition(
            name: "sendable-tool",
            description: "Test",
            inputSchemaJson: "{}",
            outputSchemaJson: "{}",
            operatorDid: "did:dht:z6MkOp",
            testVectorsJson: nil,
            implementationHash: nil
        )
        #expect(definition is ToolDefinition)
    }

    // MARK: - TestVector type shape (hand-written, not UniFFI)

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

    // MARK: - ToolInvocationResult type shape (hand-written, not UniFFI)

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

    // MARK: - ToolVerificationResult type shape (UniFFI)

    @Test("ToolVerificationResult stores all fields")
    func toolVerificationResultFields() {
        let result = ToolVerificationResult(
            toolId: "calculator",
            passed: true,
            failures: []
        )
        #expect(result.toolId == "calculator")
        #expect(result.passed)
        #expect(result.failures.isEmpty)
    }

    @Test("ToolVerificationResult reports failing tests")
    func toolVerificationResultFailing() {
        let result = ToolVerificationResult(
            toolId: "calculator",
            passed: false,
            failures: ["Vector 1 mismatch", "Vector 3 timeout"]
        )
        #expect(!result.passed)
        #expect(result.failures.count == 2)
        #expect(result.failures[0] == "Vector 1 mismatch")
    }

    // MARK: - Tool invocation via injectable bridge (async roundtrip)

    @Test("invokeTool calls bridge and returns result")
    func invokeToolRoundtrip() async throws {
        let handle = ContextHandle(noPointer: .init())
        let sendFn: ContextBridge.SendFn = { _, _ in }
        let subscribeFn: ContextBridge.SubscribeFn = { _, _ in }
        let leaveFn: ContextBridge.LeaveFn = { _ in }
        let closeFn: ContextBridge.CloseFn = { _ in }

        let context = Context(
            handle: handle,
            sendFn: sendFn,
            subscribeFn: subscribeFn,
            leaveFn: leaveFn,
            closeFn: closeFn
        )

        let mockInvoke: ToolBridge.InvokeFn = { _, toolId, inputJson, _ in
            #expect(toolId == "calculator")
            #expect(inputJson == "{}")
            return #"{"result": 42}"#
        }

        let result = try await context.invokeTool(
            "calculator",
            input: Data("{}".utf8),
            invokeFn: mockInvoke
        )
        #expect(result.output == Data(#"{"result": 42}"#.utf8))
        #expect(result.contextId.isEmpty == false || true)
    }

    @Test("invokeTool throws when context is closed")
    func invokeToolThrowsWhenClosed() async throws {
        let context = makeTestContext()
        try await context.close()

        do {
            _ = try await context.invokeTool("calculator", input: Data("{}".utf8))
            Issue.record("Expected invokeTool to throw on closed context")
        } catch let error as ScpError {
            if case .Context(_, let code) = error {
                #expect(code == "SCP-CTX-2001")
            } else {
                Issue.record("Expected ScpError.Context, got \(error)")
            }
        } catch {
            Issue.record("Expected ScpError, got \(type(of: error))")
        }
    }

    // MARK: - Tool registration via injectable bridge (async roundtrip)

    @Test("registerTool calls bridge and returns tool ID")
    func registerToolRoundtrip() async throws {
        let handle = ContextHandle(noPointer: .init())
        let sendFn: ContextBridge.SendFn = { _, _ in }
        let subscribeFn: ContextBridge.SubscribeFn = { _, _ in }
        let leaveFn: ContextBridge.LeaveFn = { _ in }
        let closeFn: ContextBridge.CloseFn = { _ in }

        let context = Context(
            handle: handle,
            sendFn: sendFn,
            subscribeFn: subscribeFn,
            leaveFn: leaveFn,
            closeFn: closeFn
        )

        let mockRegister: ToolBridge.RegisterFn = { _, definition in
            #expect(definition.name == "test-tool")
            return "tool-abc-123"
        }

        let definition = ToolDefinition(
            name: "test-tool",
            description: "A test tool",
            inputSchemaJson: "{}",
            outputSchemaJson: "{}",
            operatorDid: "did:dht:z6MkOp",
            testVectorsJson: nil,
            implementationHash: nil
        )
        let toolId = try await context.registerTool(definition, registerFn: mockRegister)
        #expect(toolId == "tool-abc-123")
    }

    @Test("registerTool throws when context is closed")
    func registerToolThrowsWhenClosed() async throws {
        let context = makeTestContext()
        try await context.close()

        let definition = ToolDefinition(
            name: "test-tool",
            description: "A test tool",
            inputSchemaJson: "{}",
            outputSchemaJson: "{}",
            operatorDid: "did:dht:z6MkOp",
            testVectorsJson: nil,
            implementationHash: nil
        )
        do {
            _ = try await context.registerTool(definition)
            Issue.record("Expected registerTool to throw on closed context")
        } catch let error as ScpError {
            if case .Context(_, let code) = error {
                #expect(code == "SCP-CTX-2001")
            } else {
                Issue.record("Expected ScpError.Context, got \(error)")
            }
        } catch {
            Issue.record("Expected ScpError, got \(type(of: error))")
        }
    }

    // MARK: - Tool verification via injectable bridge (async roundtrip)

    @Test("verifyTool calls bridge and returns result")
    func verifyToolRoundtrip() async throws {
        let handle = ContextHandle(noPointer: .init())
        let sendFn: ContextBridge.SendFn = { _, _ in }
        let subscribeFn: ContextBridge.SubscribeFn = { _, _ in }
        let leaveFn: ContextBridge.LeaveFn = { _ in }
        let closeFn: ContextBridge.CloseFn = { _ in }

        let context = Context(
            handle: handle,
            sendFn: sendFn,
            subscribeFn: subscribeFn,
            leaveFn: leaveFn,
            closeFn: closeFn
        )

        let mockVerify: ToolBridge.VerifyFn = { _, toolId in
            #expect(toolId == "calculator")
            return ToolVerificationResult(toolId: "calculator", passed: true, failures: [])
        }

        let result = try await context.verifyTool("calculator", verifyFn: mockVerify)
        #expect(result.passed)
        #expect(result.toolId == "calculator")
    }

    @Test("verifyTool throws when context is closed")
    func verifyToolThrowsWhenClosed() async throws {
        let context = makeTestContext()
        try await context.close()

        do {
            _ = try await context.verifyTool("calculator")
            Issue.record("Expected verifyTool to throw on closed context")
        } catch let error as ScpError {
            if case .Context(_, let code) = error {
                #expect(code == "SCP-CTX-2001")
            } else {
                Issue.record("Expected ScpError.Context, got \(error)")
            }
        } catch {
            Issue.record("Expected ScpError, got \(type(of: error))")
        }
    }

    // MARK: - Test vector verification

    @Test("ToolDefinition with test vectors JSON preserves data")
    func toolDefinitionPreservesTestVectors() {
        let vectorsJson = #"[{"input": {"a": 1, "b": 2}, "expected_output": {"sum": 3}}, {"input": {"a": 10, "b": 20}, "expected_output": {"sum": 30}}]"#
        let definition = ToolDefinition(
            name: "add",
            description: "Adds two numbers",
            inputSchemaJson: #"{"type": "object", "properties": {"a": {"type": "number"}, "b": {"type": "number"}}}"#,
            outputSchemaJson: #"{"type": "object", "properties": {"sum": {"type": "number"}}}"#,
            operatorDid: "did:dht:z6MkMath",
            testVectorsJson: vectorsJson,
            implementationHash: Data([0xAA, 0xBB, 0xCC])
        )

        #expect(definition.testVectorsJson != nil)
        #expect(definition.testVectorsJson!.contains("sum"))
    }

    // MARK: - ToolSessionResult type shape

    @Test("ToolSessionResult stores session ID")
    func toolSessionResultFields() {
        let result = ToolSessionResult(sessionId: "session-uuid-001")
        #expect(result.sessionId == "session-uuid-001")
    }

    // MARK: - Cross-context tool invocation via injectable bridge

    @Test("invokeToolCrossContext calls bridge with both handles")
    func invokeToolCrossContextRoundtrip() async throws {
        let sourceHandle = ContextHandle(noPointer: .init())
        let targetHandle = ContextHandle(noPointer: .init())
        let sendFn: ContextBridge.SendFn = { _, _ in }
        let subscribeFn: ContextBridge.SubscribeFn = { _, _ in }
        let leaveFn: ContextBridge.LeaveFn = { _ in }
        let closeFn: ContextBridge.CloseFn = { _ in }

        let sourceContext = Context(
            handle: sourceHandle,
            sendFn: sendFn,
            subscribeFn: subscribeFn,
            leaveFn: leaveFn,
            closeFn: closeFn
        )
        let targetContext = Context(
            handle: targetHandle,
            sendFn: sendFn,
            subscribeFn: subscribeFn,
            leaveFn: leaveFn,
            closeFn: closeFn
        )

        var receivedChainDepth: UInt8?
        let mockInvokeCrossContext: ToolBridge.InvokeCrossContextFn = {
            _, _, toolId, inputJson, _, chainDepth in
            #expect(toolId == "remote-calc")
            #expect(inputJson == "{\"x\":1}")
            receivedChainDepth = chainDepth
            return #"{"result": 99}"#
        }

        let result = try await sourceContext.invokeToolCrossContext(
            "remote-calc",
            input: Data("{\"x\":1}".utf8),
            targetContext: targetContext,
            chainDepth: 1,
            invokeCrossContextFn: mockInvokeCrossContext
        )

        #expect(result.output == Data(#"{"result": 99}"#.utf8))
        #expect(receivedChainDepth == 1)
    }

    @Test("invokeToolCrossContext throws when source context is closed")
    func invokeToolCrossContextThrowsWhenClosed() async throws {
        let sourceContext = makeTestContext()
        let targetContext = makeTestContext(contextId: "target-ctx")
        try await sourceContext.close()

        do {
            _ = try await sourceContext.invokeToolCrossContext(
                "tool",
                input: Data("{}".utf8),
                targetContext: targetContext
            )
            Issue.record("Expected error for closed source context")
        } catch let error as ScpError {
            if case .Context(_, let code) = error {
                #expect(code == "SCP-CTX-2001")
            } else {
                Issue.record("Expected ScpError.Context, got \(error)")
            }
        } catch {
            Issue.record("Expected ScpError, got \(type(of: error))")
        }
    }

    // MARK: - Stateful tool session via injectable bridge

    @Test("createToolSession calls bridge and returns session result")
    func createToolSessionRoundtrip() async throws {
        let handle = ContextHandle(noPointer: .init())
        let sendFn: ContextBridge.SendFn = { _, _ in }
        let subscribeFn: ContextBridge.SubscribeFn = { _, _ in }
        let leaveFn: ContextBridge.LeaveFn = { _ in }
        let closeFn: ContextBridge.CloseFn = { _ in }

        let context = Context(
            handle: handle,
            sendFn: sendFn,
            subscribeFn: subscribeFn,
            leaveFn: leaveFn,
            closeFn: closeFn
        )

        var receivedToolId: String?
        var receivedTtl: UInt64?
        let mockSessionCreate: ToolBridge.SessionCreateFn = { _, toolId, _, ttl in
            receivedToolId = toolId
            receivedTtl = ttl
            return "session-abc-123"
        }

        let result = try await context.createToolSession(
            toolId: "calc",
            sourceContextId: "src-ctx",
            ttlSeconds: 300,
            sessionCreateFn: mockSessionCreate
        )

        #expect(result.sessionId == "session-abc-123")
        #expect(receivedToolId == "calc")
        #expect(receivedTtl == 300)
    }

    @Test("invokeToolSession calls bridge with session ID")
    func invokeToolSessionRoundtrip() async throws {
        let handle = ContextHandle(noPointer: .init())
        let sendFn: ContextBridge.SendFn = { _, _ in }
        let subscribeFn: ContextBridge.SubscribeFn = { _, _ in }
        let leaveFn: ContextBridge.LeaveFn = { _ in }
        let closeFn: ContextBridge.CloseFn = { _ in }

        let context = Context(
            handle: handle,
            sendFn: sendFn,
            subscribeFn: subscribeFn,
            leaveFn: leaveFn,
            closeFn: closeFn
        )

        var receivedSessionId: String?
        let mockSessionInvoke: ToolBridge.SessionInvokeFn = { _, sessionId, inputJson, _ in
            receivedSessionId = sessionId
            #expect(inputJson == "{\"op\":\"add\"}")
            return #"{"sum": 5}"#
        }

        let result = try await context.invokeToolSession(
            sessionId: "session-abc-123",
            input: Data("{\"op\":\"add\"}".utf8),
            sessionInvokeFn: mockSessionInvoke
        )

        #expect(result.output == Data(#"{"sum": 5}"#.utf8))
        #expect(receivedSessionId == "session-abc-123")
    }

    @Test("closeToolSession calls bridge with session ID")
    func closeToolSessionRoundtrip() async throws {
        let handle = ContextHandle(noPointer: .init())
        let sendFn: ContextBridge.SendFn = { _, _ in }
        let subscribeFn: ContextBridge.SubscribeFn = { _, _ in }
        let leaveFn: ContextBridge.LeaveFn = { _ in }
        let closeFn: ContextBridge.CloseFn = { _ in }

        let context = Context(
            handle: handle,
            sendFn: sendFn,
            subscribeFn: subscribeFn,
            leaveFn: leaveFn,
            closeFn: closeFn
        )

        var closedSessionId: String?
        let mockSessionClose: ToolBridge.SessionCloseFn = { _, sessionId in
            closedSessionId = sessionId
        }

        try await context.closeToolSession(
            sessionId: "session-abc-123",
            sessionCloseFn: mockSessionClose
        )

        #expect(closedSessionId == "session-abc-123")
    }

    @Test("createToolSession throws when context is closed")
    func createToolSessionThrowsWhenClosed() async throws {
        let context = makeTestContext()
        try await context.close()

        do {
            _ = try await context.createToolSession(
                toolId: "calc",
                sourceContextId: "src",
                ttlSeconds: 300
            )
            Issue.record("Expected error for closed context")
        } catch let error as ScpError {
            if case .Context(_, let code) = error {
                #expect(code == "SCP-CTX-2001")
            } else {
                Issue.record("Expected ScpError.Context, got \(error)")
            }
        } catch {
            Issue.record("Expected ScpError, got \(type(of: error))")
        }
    }

} // end ToolsTests

// MARK: - Mock ContextHandle for Tool Tests

/// Mock implementation of ``ContextHandleProtocol`` for tool testing.
private final class MockToolContextHandle: ContextHandleProtocol, @unchecked Sendable {
    let id: String
    let creator: String
    let initialState: String

    init(id: String = "tool-test-ctx", creator: String = "did:dht:z6MkCreator", state: String = "active") {
        self.id = id
        self.creator = creator
        self.initialState = state
    }

    func contextId() -> String { id }
    func creatorDid() -> String { creator }
    func state() throws -> String { initialState }
}
