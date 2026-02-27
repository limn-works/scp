/// Multi-agent coordination: multiple agents collaborating in a shared context.

using Limn.Scp;

static async Task RunAgent(string name, Identity identity, string contextId)
{
    await using var ctx = await Context.JoinAsync(identity, contextId);
    Console.WriteLine($"[{name}] Joined context {contextId}");

    await ctx.SendAsync(System.Text.Encoding.UTF8.GetBytes($"[{name}] reporting in"));

    var count = 0;
    await foreach (var msg in ctx.ReceiveAsync())
    {
        var sender = msg.SenderDid.Length > 16 ? msg.SenderDid[..16] : msg.SenderDid;
        var text = System.Text.Encoding.UTF8.GetString(msg.Content);
        Console.WriteLine($"[{name}] Received from {sender}...: {text}");
        count++;
        if (count >= 2) break;
    }

    Console.WriteLine($"[{name}] Left context");
}

// Create identities for coordinator and two agents
await using var coordinator = await Identity.CreateAsync(custody: "platform");
await using var agentA = await Identity.CreateAsync(custody: "platform");
await using var agentB = await Identity.CreateAsync(custody: "platform");

// Coordinator creates the context
await using var ctx = await Context.CreateAsync(
    coordinator,
    new ContextParams
    {
        Ceiling = ["msg:send", "msg:receive", "tool:invoke"],
        Roles = new Dictionary<string, string[]>
        {
            ["agent"] = ["msg:send", "msg:receive", "tool:invoke"],
        },
        Governance = "single_admin",
    }
);
Console.WriteLine($"Context created: {ctx.ContextId}");

// Mint UCANs for each agent
await Ucan.MintAsync(coordinator, agentA.Did, ["msg:send", "msg:receive"], ctx.ContextId);
await Ucan.MintAsync(coordinator, agentB.Did, ["msg:send", "msg:receive"], ctx.ContextId);

// Run agents concurrently
await Task.WhenAll(
    RunAgent("Agent-A", agentA, ctx.ContextId),
    RunAgent("Agent-B", agentB, ctx.ContextId)
);
