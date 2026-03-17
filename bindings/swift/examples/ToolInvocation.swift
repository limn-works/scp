// Tool invocation: register a tool and invoke it within a context.
//
// Demonstrates ToolDefinition construction with the UniFFI field names
// (inputSchemaJson, outputSchemaJson, testVectorsJson, implementationHash,
// cost) and tool invocation via the bridge functions.

import Foundation
import SCP

@main
struct ToolInvocation {
    static func main() async throws {
        let identity = try await createIdentity(custody: "in_memory")

        // ToolDefinition uses UniFFI field names: inputSchemaJson, outputSchemaJson,
        // testVectorsJson (optional JSON string), implementationHash (optional Data),
        // cost (optional ToolCostDefinition)
        let weatherTool = ToolDefinition(
            name: "weather",
            description: "Get current weather for a city",
            inputSchemaJson: #"{"type":"object","properties":{"city":{"type":"string"}},"required":["city"]}"#,
            outputSchemaJson: #"{"type":"object","properties":{"tempC":{"type":"number"},"condition":{"type":"string"}}}"#,
            operatorDid: identity.did(),
            testVectorsJson: #"[{"input":{"city":"Berlin"},"expected":{"tempC":18,"condition":"cloudy"}}]"#,
            implementationHash: nil,
            cost: nil
        )

        // Create a context and register the tool
        let params = ContextParams(
            ceiling: ["messages:read", "messages:write", "tool:invoke:*", "tool:register"],
            governance: .singleAdmin,
            memoryScope: .ephemeral,
            ttlSeconds: 3600,
            promotable: false,
            minProtocolVersion: 0
        )
        let handle = try await contextCreate(identity: identity, params: params)

        // Register the tool via the bridge function
        let toolId = try await toolRegister(handle: handle, definition: weatherTool)
        print("Registered tool: \(toolId)")

        // Invoke the tool via the bridge function. Input is a JSON string.
        let resultJson = try await toolInvoke(
            handle: handle,
            toolId: "weather",
            inputJson: #"{"city":"Berlin"}"#,
            identity: identity,
            ucanToken: nil,
            proofTokens: nil
        )
        print("Weather result: \(resultJson)")

        try await contextClose(handle: handle, identity: identity)
    }
}
