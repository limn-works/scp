/// Tool invocation: register a tool with test vectors and invoke it.

using Limn.Scp;

await using var identity = await Identity.CreateAsync(custody: "platform");

await using var ctx = await Context.CreateAsync(
    identity,
    new ContextParams
    {
        Ceiling = ["msg:send", "msg:receive", "tool:invoke"],
        Tools =
        [
            new ToolDefinition(
                Name: "weather",
                Description: "Get current weather for a city",
                InputSchema: new Dictionary<string, object>
                {
                    ["type"] = "object",
                    ["properties"] = new Dictionary<string, object>
                    {
                        ["city"] = new Dictionary<string, object> { ["type"] = "string" }
                    },
                    ["required"] = new[] { "city" },
                },
                OutputSchema: new Dictionary<string, object>
                {
                    ["type"] = "object",
                    ["properties"] = new Dictionary<string, object>
                    {
                        ["tempC"] = new Dictionary<string, object> { ["type"] = "number" },
                        ["condition"] = new Dictionary<string, object> { ["type"] = "string" },
                    },
                },
                Operator: identity.Did,
                TestVectors:
                [
                    new TestVector(
                        Input: new Dictionary<string, object> { ["city"] = "Berlin" },
                        ExpectedOutput: new Dictionary<string, object>
                        {
                            ["tempC"] = 18,
                            ["condition"] = "cloudy",
                        },
                        Description: "Berlin weather lookup"
                    ),
                ]
            ),
        ],
    }
);

// Invoke the tool
var result = await ctx.InvokeToolAsync("weather", new Dictionary<string, object> { ["city"] = "Berlin" });
Console.WriteLine($"Weather result: {result}");
