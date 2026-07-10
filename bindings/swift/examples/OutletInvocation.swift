// Outlet invocation: register an outlet and invoke it within a context.
//
// Demonstrates OutletDefinition construction and outlet invocation through
// an explicit `SCP` instance (ADR-048).

import Foundation
import SCP

@main
struct OutletInvocation {
    static func main() async throws {
        let scp = try SCP(storage: .inMemory)
        defer { Task { try? await scp.shutdown(timeout: 5) } }

        let identity = try await scp.identityCreate(custody: "in_memory")

        let weatherOutlet = OutletDefinition(
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

        let outletId = try await scp.outletRegister(handle: handle, definition: weatherOutlet)
        print("Registered outlet: \(outletId)")

        let resultJson = try await scp.outletInvoke(
            handle: handle,
            outletId: "weather",
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
