/** MCP integration: expose SCP tools via MCP JSON-RPC server. */

package com.limn.scp.examples;

import com.limn.scp.Context;
import com.limn.scp.Identity;
import com.limn.scp.Mcp;
import com.limn.scp.Mcp.McpClient;
import java.util.List;
import java.util.Map;

public class McpIntegration {
    public static void main(String[] args) throws Exception {
        var identity = Identity.create("platform").join();

        var ctx = Context.create(identity, Map.of(
            "ceiling", List.of("msg:send", "msg:receive", "tool:invoke", "mcp:serve"),
            "tools", List.of(Map.of(
                "name", "summarize",
                "description", "Summarize text content",
                "inputSchema", Map.of(
                    "type", "object",
                    "properties", Map.of("text", Map.of("type", "string")),
                    "required", List.of("text")
                ),
                "outputSchema", Map.of(
                    "type", "object",
                    "properties", Map.of("summary", Map.of("type", "string"))
                ),
                "operator", identity.did()
            ))
        )).join();

        // Start an MCP server exposing context tools on stdio
        var server = Mcp.serve(ctx, "stdio");
        System.out.println("MCP server running, exposing tools");

        // Or connect as an MCP client to a remote server
        var client = McpClient.connect("ws://localhost:8080/mcp").join();
        var tools = client.listTools().join();
        System.out.println("Remote server offers " + tools.size() + " tool(s)");

        var result = client.callTool("summarize", Map.of("text", "SCP is a protocol for...")).join();
        System.out.println("Result: " + result);

        client.close();
        server.stop();
        ctx.close();
        identity.close();
    }
}
