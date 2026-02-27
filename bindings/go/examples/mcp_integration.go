// MCP integration: expose SCP tools via MCP JSON-RPC server.
package main

import (
	"fmt"
	"log"

	scp "github.com/limn/scp-go"
)

func main() {
	if err := scp.Init(); err != nil {
		log.Fatal(err)
	}
	defer scp.Shutdown()

	identity, err := scp.NewIdentity("platform")
	if err != nil {
		log.Fatal(err)
	}

	ctx, err := scp.NewContext(identity, scp.ContextParams{
		Ceiling: []string{"msg:send", "msg:receive", "tool:invoke", "mcp:serve"},
		Tools: []scp.ToolDefinition{
			{
				Name:        "summarize",
				Description: "Summarize text content",
				InputSchema: map[string]any{
					"type":       "object",
					"properties": map[string]any{"text": map[string]any{"type": "string"}},
					"required":   []string{"text"},
				},
				OutputSchema: map[string]any{
					"type":       "object",
					"properties": map[string]any{"summary": map[string]any{"type": "string"}},
				},
				Operator: identity.DID(),
			},
		},
	})
	if err != nil {
		log.Fatal(err)
	}
	defer ctx.Close()

	// Start an MCP server exposing context tools on stdio
	server, err := scp.ServeMcp(ctx, scp.McpTransportStdio)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("MCP server running, exposing tools")

	// Or connect as an MCP client to a remote server
	client, err := scp.NewMcpClient("ws://localhost:8080/mcp")
	if err != nil {
		log.Fatal(err)
	}
	defer client.Close()

	tools, err := client.ListTools()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Remote server offers %d tool(s)\n", len(tools))

	result, err := client.CallTool("summarize", map[string]any{"text": "SCP is a protocol for..."})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("Result:", result)

	server.Stop()
}
