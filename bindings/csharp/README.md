# SCP C# SDK

> `Limn.Scp` -- Shareable Context Protocol for .NET

Cryptographic identity, encrypted contexts, capability-based auth, and tool invocation for AI agents. Built on Rust via cbindgen + P/Invoke.

## Install

```bash
dotnet add package Limn.Scp
```

Or in your `.csproj`:

```xml
<PackageReference Include="Limn.Scp" Version="0.1.0" />
```

## Quick Start

```csharp
using Limn.Scp;

// Create a cryptographic identity (DID)
await using var identity = await Identity.CreateAsync(custody: "platform");
Console.WriteLine($"DID: {identity.Did}");

// Create an encrypted context
await using var ctx = await Context.CreateAsync(
    identity,
    new ContextParams
    {
        Ceiling = ["msg:send", "msg:receive"],
        Ttl = 3600,
    }
);

// Send a message (MLS-encrypted, signed, provenance-tagged)
await ctx.SendAsync("Hello from SCP"u8.ToArray());

// Receive messages
await foreach (var msg in ctx.ReceiveAsync())
{
    Console.WriteLine($"{msg.SenderDid}: {msg.Content}");
    break;
}
```

## Requirements

- .NET 8.0+
- Native libraries bundled per RID (linux-x64, linux-arm64, osx-x64, osx-arm64, win-x64)

## API Reference

Generated from XML documentation comments via `xmldoc`. Build locally:

```bash
dotnet build /p:GenerateDocumentationFile=true
```

Published API docs are generated on every release by CI.

## Examples

See [`examples/`](./examples/) for runnable programs:

| File | Description |
|------|-------------|
| `BasicMessaging.cs` | Create identity, context, send/receive messages |
| `ToolInvocation.cs` | Register and invoke a tool with test vectors |
| `McpIntegration.cs` | Expose SCP tools via MCP JSON-RPC server |
| `MultiAgent.cs` | Coordinate multiple agents in a shared context |

## Error Handling

All exceptions extend `ScpException` with a machine-readable `Code` property:

```csharp
try
{
    await ctx.SendAsync(payload);
}
catch (ContextException e)
{
    Console.WriteLine($"[{e.Code}] {e.Message}");
}
```

## Source

- Scaffold: `.docs/scaffold/csharp.md`
- Standards: `.docs/standards/csharp.md`
- API sketch: `.docs/sketch.md`
