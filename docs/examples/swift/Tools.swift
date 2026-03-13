/// Tool registration and invocation within a context.
///
/// Demonstrates defining a tool with a JSON schema, registering it
/// in a context, and invoking it with UCAN authorization.
///
/// Prerequisites:
///   - Add the SCP Swift package to your project
///   - import SCP
///
/// Usage:
///   swift run Tools

import Foundation
import SCP

@main
struct ToolsExample {
    static func main() async throws {
        // 1. Create an identity for the tool operator.
        let operator_ = try await createIdentity(custody: "in_memory")
        print("Operator DID: \(operator_.did())")

        // 2. Create a context with tool capabilities.
        let ceiling = [
            "messages:read",
            "messages:write",
            "tool:register",
            "tool:invoke_all",
        ]

        let ctx = try await Context.create(
            contextId: "tool-demo",
            ceiling: ceiling,
            createFn: ContextBridge.defaultCreate,
            sendFn: ContextBridge.defaultSend,
            subscribeFn: ContextBridge.defaultSubscribe,
            leaveFn: ContextBridge.defaultLeave,
            closeFn: ContextBridge.defaultClose
        )
        print("Context: \(ctx.contextId)")

        // 3. Define a calculator tool.
        //    ToolDefinition is a UniFFI-generated type with JSON schema fields.
        let inputSchema = """
        {
            "type": "object",
            "properties": {
                "a": {"type": "number"},
                "b": {"type": "number"},
                "op": {"type": "string", "enum": ["add", "sub", "mul"]}
            },
            "required": ["a", "b", "op"]
        }
        """

        let outputSchema = """
        {
            "type": "object",
            "properties": {
                "result": {"type": "number"}
            },
            "required": ["result"]
        }
        """

        let definition = ToolDefinition(
            name: "calculator",
            description: "A simple arithmetic calculator",
            inputSchemaJson: inputSchema,
            outputSchemaJson: outputSchema,
            operatorDid: operator_.did(),
            testVectorsJson: """
            [
                {"input": {"a": 2, "b": 3, "op": "add"}, "expected_output": {"result": 5}},
                {"input": {"a": 7, "b": 3, "op": "mul"}, "expected_output": {"result": 21}}
            ]
            """,
            implementationHash: nil
        )

        print("\nTool defined: \(definition.name)")
        print("  Description: \(definition.description)")

        // 4. Register the tool in the context.
        let toolId = try await ctx.registerTool(definition)
        print("  Registered with ID: \(toolId)")

        // 5. Verify the tool against its test vectors.
        let verification = try await ctx.verifyTool(toolId)
        print("  Verification passed: \(verification.passed)")
        if !verification.failures.isEmpty {
            for failure in verification.failures {
                print("    Failure: \(failure)")
            }
        }

        // 6. Invoke the tool.
        //    Tool input is passed as serialized JSON Data.
        let input = #"{"a": 7, "b": 3, "op": "mul"}"#.data(using: .utf8)!

        let result = try await ctx.invokeTool(
            "calculator",
            input: input,
            identity: operator_
        )

        print("\nInvoked calculator: 7 * 3")
        if let outputString = String(data: result.output, encoding: .utf8) {
            print("  Result: \(outputString)")
        }
        print("  Invoker: \(result.invokerDid)")
        print("  Context: \(result.contextId)")
        print("  Timestamp: \(result.timestamp)")

        // 7. Stateful tool sessions (spec section 6.2.1).
        //    Sessions enable multi-turn workflows with state preservation.
        let session = try await ctx.createToolSession(
            toolId: toolId,
            sourceContextId: ctx.contextId,
            ttlSeconds: 300  // 5-minute session
        )
        print("\nSession created: \(session.sessionId)")

        // Invoke within the session.
        let sessionInput = #"{"a": 10, "b": 5, "op": "sub"}"#.data(using: .utf8)!
        let sessionResult = try await ctx.invokeToolSession(
            sessionId: session.sessionId,
            input: sessionInput,
            identity: operator_,
            ucanToken: "placeholder-token"
        )

        if let output = String(data: sessionResult.output, encoding: .utf8) {
            print("  Session invoke: 10 - 5 = \(output)")
        }

        // Close the session.
        try await ctx.closeToolSession(sessionId: session.sessionId)
        print("  Session closed.")

        // 8. Clean up.
        try await ctx.close()
        print("\nTool operations complete.")
    }
}
