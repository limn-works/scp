// Tool invocation: register a tool with test vectors and invoke it.

import Foundation
import SCP

@main
struct ToolInvocation {
    static func main() async throws {
        let identity = try await Identity.create(custody: "platform")

        let weatherTool = ToolDefinition(
            name: "weather",
            description: "Get current weather for a city",
            inputSchema: #"{"type":"object","properties":{"city":{"type":"string"}},"required":["city"]}"#,
            outputSchema: #"{"type":"object","properties":{"tempC":{"type":"number"},"condition":{"type":"string"}}}"#,
            operatorDid: identity.did,
            testVectors: [
                TestVector(
                    input: ["city": "Berlin"],
                    expectedOutput: ["tempC": 18, "condition": "cloudy"],
                    description: "Berlin weather lookup"
                )
            ]
        )

        let ctx = try await Context.create(
            identity: identity,
            params: ContextParams(
                ceiling: ["msg:send", "msg:receive", "tool:invoke"],
                tools: [weatherTool]
            )
        )

        // Invoke the tool
        let result = try await ctx.invokeTool("weather", input: ["city": "Berlin"])
        print("Weather result: \(result)")

        try await ctx.close()
    }
}
