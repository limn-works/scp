/// Basic messaging: create identity, create context, send and receive messages.

using Limn.Scp;

// Create two identities
await using var alice = await Identity.CreateAsync(custody: "platform");
await using var bob = await Identity.CreateAsync(custody: "platform");
Console.WriteLine($"Alice DID: {alice.Did}");
Console.WriteLine($"Bob DID: {bob.Did}");

// Alice creates a context
await using var ctxAlice = await Context.CreateAsync(
    alice,
    new ContextParams
    {
        Ceiling = ["msg:send", "msg:receive"],
        Ttl = 3600,
        Governance = "single_admin",
    }
);
Console.WriteLine($"Context ID: {ctxAlice.ContextId}");

// Bob joins the context
await using var ctxBob = await Context.JoinAsync(bob, ctxAlice.ContextId);

// Alice sends a message
await ctxAlice.SendAsync("Hello Bob, this is Alice"u8.ToArray());

// Bob receives it
await foreach (var msg in ctxBob.ReceiveAsync())
{
    var text = System.Text.Encoding.UTF8.GetString(msg.Content);
    Console.WriteLine($"Bob received from {msg.SenderDid}: {text}");
    break;
}
