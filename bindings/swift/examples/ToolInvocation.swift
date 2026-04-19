// Tool invocation: register a tool and invoke it within a context.
//
// Demonstrates ToolDefinition construction and tool invocation through
// an explicit `SCP` instance (ADR-048).

import Foundation
import SCP

@main
struct ToolInvocation {
    static func main() async throws {
        let scp = SCP()
        defer { Task { try? await scp.shutdown(timeout: 5) } }

        let identity = try await scp.identityCreate(custody: "in_memory")

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

        let params = ContextParams(
            mode: .encrypted,
            ceiling: ["messages:read", "messages:write", "tool:invoke:*", "tool:register"],
            ceilingPolicy: .immutable,
            governance: .singleAdmin,
            memoryScope: .ephemeral,
            ttlSeconds: 3600,
            promotable: false,
            minProtocolVersion: 0,
            maxChainDepth: nil,
            maxNestingDepth: nil,
            sessionCap: nil,
            economicPolicy: nil
        )
        let handle = try await scp.contextCreate(identity: identity, params: params)

        let toolId = try await scp.toolRegister(handle: handle, definition: weatherTool)
        print("Registered tool: \(toolId)")

        let resultJson = try await scp.toolInvoke(
            handle: handle,
            toolId: "weather",
            inputJson: #"{"city":"Berlin"}"#,
            identity: identity,
            ucanToken: nil,
            proofTokens: nil,
            spendingUcanJwt: nil
        )
        print("Weather result: \(resultJson)")

        try await scp.contextClose(handle: handle, identity: identity)
    }
}
