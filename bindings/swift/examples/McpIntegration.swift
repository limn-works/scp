// MCP integration: expose SCP outlets via MCP and consume external MCP servers.
//
// Demonstrates outlet registration against an explicit `SCP` instance
// (ADR-048). MCP server/client methods are available as `SCP` instance
// methods once the bridge is wired.

import Foundation
import SCP

@main
struct McpIntegration {
    static func main() async throws {
        let scp = try SCP(storage: .inMemory)
        defer { Task { try? await scp.shutdown(timeout: 5) } }

        let identity = try await scp.identityCreate(custody: "in_memory")

        let params = ContextParams(
            mode: .encrypted,
            ceiling: ["messages:read", "messages:write", "outlet:call:*", "outlet:register"],
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

        let outlet = OutletDefinition(
            name: "summarize",
            description: "Summarize text content",
            inputSchemaJson: #"{"type":"object","properties":{"text":{"type":"string"}},"required":["text"]}"#,
            outputSchemaJson: #"{"type":"object","properties":{"summary":{"type":"string"}}}"#,
            operatorDid: identity.did(),
            testVectorsJson: nil,
            implementationHash: nil,
            cost: nil
        )
        _ = try await scp.outletRegister(handle: handle, definition: outlet)

        // MCP server/client methods on SCP:
        //
        //   let serverConfig = McpServerConfig(
        //       identityDid: identity.did(),
        //       contextIds: [handle.contextId()],
        //       transport: "stdio",
        //       ucanToken: nil,
        //       proofTokens: nil
        //   )
        //   _ = try await scp.mcpServerCreate(config: serverConfig)
        //
        //   // Or connect as an MCP client to an SCP SSE server started
        //   // separately on this machine at 127.0.0.1:8080. The server streams
        //   // events at `/sse` and takes requests at the `/message` path it
        //   // names in its first event, so the client dials `/sse`. The
        //   // context created above lives only in this process's in-memory
        //   // store, so that server cannot expose it: the example invokes a
        //   // context the server exposes, read from SCP_MCP_SSE_CONTEXT_ID,
        //   // and that context must offer an outlet named `summarize`. An SCP
        //   // server lists each outlet as `<context_id>/call.<outlet>` or
        //   // `<context_id>/query.<outlet>` and refuses a bare outlet name in
        //   // `tools/call`, so the example invokes the name `listTools()` returns;
        //   // `contextId` on `invoke` feeds only local provenance. An SCP
        //   // SSE server always runs a bearer check (ADR-015), so pass the
        //   // token that server's operator gives you, read here from
        //   // SCP_MCP_SSE_TOKEN. The transport has no TLS, so a token is sent
        //   // only to a loopback host.
        //   let env = ProcessInfo.processInfo.environment
        //   guard let sseToken = env["SCP_MCP_SSE_TOKEN"],
        //         let sseContextId = env["SCP_MCP_SSE_CONTEXT_ID"] else {
        //       fatalError("set SCP_MCP_SSE_TOKEN to the bearer token of the SCP SSE server on 127.0.0.1:8080 and SCP_MCP_SSE_CONTEXT_ID to a context it exposes")
        //   }
        //   let client = try await McpClient.connect(
        //       scp: scp,
        //       config: .sse(url: "http://127.0.0.1:8080/sse", authToken: sseToken)
        //   )
        //   let outlets = try await client.listTools()
        //   let summarizeNames = ["\(sseContextId)/call.summarize", "\(sseContextId)/query.summarize"]
        //   guard let summarize = outlets.first(where: { summarizeNames.contains($0.name) }) else {
        //       fatalError("context \(sseContextId) offers no `summarize` outlet")
        //   }
        //   let result = try await client.invoke(
        //       tool: summarize.name,
        //       input: Data(#"{"text":"SCP is a protocol for..."}"#.utf8),
        //       contextId: sseContextId,
        //       invokerDid: identity.did()
        //   )
        //   try await client.disconnect()
        //
        print("(MCP server/client available via scp.mcpServerCreate / McpClient.connect)")

        try await scp.contextClose(handle: handle, identity: identity)
    }
}
