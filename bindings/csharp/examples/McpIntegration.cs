/// MCP integration: expose SCP tools via MCP JSON-RPC server.

using Limn.Scp;

await using var identity = await Identity.CreateAsync(custody: "platform");

await using var ctx = await Context.CreateAsync(
    identity,
    new ContextParams
    {
        Ceiling = ["msg:send", "msg:receive", "tool:invoke", "mcp:serve"],
        Tools =
        [
            new ToolDefinition(
                Name: "summarize",
                Description: "Summarize text content",
                InputSchema: new Dictionary<string, object>
                {
                    ["type"] = "object",
                    ["properties"] = new Dictionary<string, object>
                    {
                        ["text"] = new Dictionary<string, object> { ["type"] = "string" }
                    },
                    ["required"] = new[] { "text" },
                },
                OutputSchema: new Dictionary<string, object>
                {
                    ["type"] = "object",
                    ["properties"] = new Dictionary<string, object>
                    {
                        ["summary"] = new Dictionary<string, object> { ["type"] = "string" }
                    },
                },
                Operator: identity.Did
            ),
        ],
    }
);

// Start an MCP server exposing context tools on stdio
var server = await McpServer.ServeAsync(ctx, McpTransport.Stdio);
Console.WriteLine("MCP server running, exposing tools");

// Or connect as an MCP client to a remote server
await using var client = await McpClient.ConnectAsync("ws://localhost:8080/mcp");
var tools = await client.ListToolsAsync();
Console.WriteLine($"Remote server offers {tools.Count} tool(s)");

var result = await client.CallToolAsync("summarize", new Dictionary<string, object>
{
    ["text"] = "SCP is a protocol for...",
});
Console.WriteLine($"Result: {result}");

await server.StopAsync();
