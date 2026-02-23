# C# Standards

C# conventions, toolchain, and CI for the SCP C# SDK. See `.docs/scaffold/csharp.md` for project structure, P/Invoke bridge, type definitions, and .csproj. References `sdk-common.md` for cross-language invariants and `conventions.md` for git/branch conventions.

## Toolchain

| Tool | Version | Purpose |
|------|---------|---------|
| C# | 12 | Language version |
| .NET | 8 LTS | Target framework |
| dotnet CLI | latest | Build, test, package |
| NRT | enabled | Nullable Reference Types (compiler-enforced null safety) |
| xUnit | latest | Test framework |
| FluentAssertions | latest | Assertion library |
| Coverlet | latest | Code coverage |

## Code Style

### Async Task\<T\>

All I/O operations are `async Task<T>`. Streaming uses `IAsyncEnumerable<T>`. Blocking FFI calls are offloaded via `Task.Run`. See `.docs/scaffold/csharp.md` for Identity and Context class implementations.

### Nullable Reference Types (NRT)

NRT is enabled project-wide (`<Nullable>enable</Nullable>`). All reference types are non-nullable by default. Use `?` suffix for nullable:

```csharp
public record Message(
    string SenderDid,
    byte[] Content,
    long Timestamp,
    long Sequence,
    string ContextId,
    Provenance? Provenance = null  // Nullable
);
```

### Records for value types

Use C# records for immutable value types. See `.docs/scaffold/csharp.md` for Message, ToolDefinition, and TestVector definitions.

### Resource management

`IAsyncDisposable` for all types holding native handles:

```csharp
// Usage
await using var ctx = await Context.CreateAsync(params);
await ctx.SendAsync(payload);
// ctx is disposed when scope exits
```

### Naming

- Types/classes/records: `PascalCase`
- Methods/properties: `PascalCase` (async methods: `*Async` suffix)
- Constants: `PascalCase`
- Private fields: `_camelCase`
- Parameters: `camelCase`
- Namespaces: `PascalCase` (`Limn.Scp`)
- Files: `PascalCase.cs`

## Testing

### xUnit + FluentAssertions

```csharp
public class IdentityTests
{
    [Fact]
    public async Task CreateAsync_ReturnsIdentityWithValidDid()
    {
        var identity = await Identity.CreateAsync(custody: "in_memory");
        identity.Did.Should().StartWith("did:dht:");
    }

    [Fact]
    public async Task SendAsync_ThrowsWhenContextNotActive()
    {
        // ...
    }

    [Theory]
    [InlineData("messages:write", true)]
    [InlineData("context:close", false)]
    public async Task ValidateCapability_ChecksCeiling(string capability, bool shouldPass)
    {
        // ...
    }
}
```

### Test naming

Format: `MethodName_Condition_ExpectedResult`.

### CancellationToken in tests

All async test methods should respect `CancellationToken` to prevent hangs:

```csharp
[Fact]
public async Task ReceiveAsync_YieldsMessages()
{
    using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
    await foreach (var msg in ctx.ReceiveAsync(cts.Token))
    {
        msg.Content.Should().NotBeEmpty();
        break;
    }
}
```

## CI Commands

```bash
# Build
dotnet build --configuration Release

# Test
dotnet test --configuration Release --verbosity normal

# Format check
dotnet format --verify-no-changes

# Pack NuGet
dotnet pack --configuration Release --output ./artifacts

# Publish to NuGet
dotnet nuget push ./artifacts/*.nupkg --source https://api.nuget.org/v3/index.json
```

## CI Matrix

| Job | Runs on | .NET version | Trigger |
|-----|---------|-------------|---------|
| format | ubuntu-latest | 8 | Every PR |
| dotnet-audit | ubuntu-latest | 8 | Every PR |
| build | ubuntu-latest, macos-latest, windows-latest | 8 | Every PR |
| test | ubuntu-latest, macos-latest, windows-latest | 8 | Every PR |
| conformance | ubuntu-latest | 8 | Every PR |
| pack | ubuntu-latest | 8 | Every PR |
| publish (NuGet) | ubuntu-latest | 8 | Tagged release |
