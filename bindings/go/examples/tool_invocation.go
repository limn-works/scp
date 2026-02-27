// Tool invocation: register a tool with test vectors and invoke it.
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
		Ceiling: []string{"msg:send", "msg:receive", "tool:invoke"},
		Tools: []scp.ToolDefinition{
			{
				Name:        "weather",
				Description: "Get current weather for a city",
				InputSchema: map[string]any{
					"type":       "object",
					"properties": map[string]any{"city": map[string]any{"type": "string"}},
					"required":   []string{"city"},
				},
				OutputSchema: map[string]any{
					"type": "object",
					"properties": map[string]any{
						"tempC":     map[string]any{"type": "number"},
						"condition": map[string]any{"type": "string"},
					},
				},
				Operator: identity.DID(),
				TestVectors: []scp.TestVector{
					{
						Input:          map[string]any{"city": "Berlin"},
						ExpectedOutput: map[string]any{"tempC": 18, "condition": "cloudy"},
						Description:    "Berlin weather lookup",
					},
				},
			},
		},
	})
	if err != nil {
		log.Fatal(err)
	}
	defer ctx.Close()

	// Invoke the tool
	result, err := ctx.InvokeTool("weather", map[string]any{"city": "Berlin"})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("Weather result:", result)
}
