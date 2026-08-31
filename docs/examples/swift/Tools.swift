/// Tool registration and invocation within a context.
///
/// Demonstrates defining a tool with a JSON schema, registering it
/// in a context, and invoking it with the UniFFI bridge functions.
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
        let operator_ = try await createIdentity(custody: "encrypted_file")
        print("Operator DID: \(operator_.did())")

        // 2. Create a context with tool capabilities.
        let params = ContextParams(
            ceiling: [
                "messages:read",
                "messages:write",
                "tool:register",
                "tool:invoke:*",
            ],
            governance: .singleAdmin,
            memoryScope: .full,
            ttlSeconds: 0,
            promotable: false,
            minProtocolVersion: 0
        )

        let handle = try await contextCreate(identity: operator_, params: params)
        print("Context: \(handle.contextId())")

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
            implementationHash: nil,
            cost: nil
        )

        print("\nTool defined: \(definition.name)")
        print("  Description: \(definition.description)")

        // 4. Register the tool in the context.
        let toolId = try await toolRegister(handle: handle, definition: definition)
        print("  Registered with ID: \(toolId)")

        // 5. Verify the tool against its test vectors.
        let verification = try await toolVerify(handle: handle, toolId: toolId)
        print("  Verification passed: \(verification.passed)")
        if !verification.failures.isEmpty {
            for failure in verification.failures {
                print("    Failure: \(failure)")
            }
        }

        // 6. Invoke the tool.
        //    Tool input and output are JSON strings at the bridge level.
        let inputJson = #"{"a": 7, "b": 3, "op": "mul"}"#

        let outputJson = try await toolInvoke(
            handle: handle,
            toolId: "calculator",
            inputJson: inputJson,
            identity: operator_,
            ucanToken: nil,
            proofTokens: nil
        )

        print("\nInvoked calculator: 7 * 3")
        print("  Result: \(outputJson)")

        // 7. Stateful tool sessions (spec section 6.2.1).
        //    Sessions enable multi-turn workflows with state preservation.
        let sessionId = try await toolSessionCreate(
            handle: handle,
            toolId: toolId,
            sourceContextId: handle.contextId(),
            ttlSeconds: 300  // 5-minute session
        )
        print("\nSession created: \(sessionId)")

        // Invoke within the session.
        let sessionInputJson = #"{"a": 10, "b": 5, "op": "sub"}"#
        let sessionOutputJson = try await toolSessionInvoke(
            handle: handle,
            sessionId: sessionId,
            inputJson: sessionInputJson,
            identity: operator_,
            ucanToken: "placeholder-token",
            proofTokens: nil
        )
        print("  Session invoke: 10 - 5 = \(sessionOutputJson)")

        // Close the session.
        try await toolSessionClose(handle: handle, sessionId: sessionId)
        print("  Session closed.")

        // 8. Clean up.
        try await contextClose(handle: handle, identity: operator_)
        print("\nTool operations complete.")
    }
}
