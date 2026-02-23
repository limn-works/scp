> Source of truth: .docs/specs/, .docs/sketch.md, .docs/adrs/. This file is downstream of those documents.

# C# SDK Scaffold

Build blueprint for the SCP C# SDK: project structure, P/Invoke bridge, and type definitions. See `.docs/standards/csharp.md` for coding standards (style rules, NRT, testing, CI).

## Package Layout

```
bindings/csharp/
  Limn.Scp.sln
  src/
    Limn.Scp/
      Limn.Scp.csproj
      Identity.cs                # Identity class, DIDDocument
      Context.cs                 # Context class, Membership, IAsyncDisposable
      Tools.cs                   # ToolDefinition, TestVector records
      Trust.cs                   # EvaluateTrustAsync(), TrustEvaluation
      EventLog.cs                # EventLog class, Event, Proof, Checkpoint
      Errors.cs                  # Exception hierarchy (ScpException → subtypes)
      Transport.cs               # TransportConfig, ConnectAsync()
      Types.cs                   # Shared types: Message, Provenance, Capability
      Ucan.cs                    # ValidateAsync(), MintAsync(), RevokeAsync()
      Mcp.cs                     # ServeMcpAsync(), McpClient
      Internal/
        NativeLib.cs             # P/Invoke declarations to libscp_ffi
        SafeHandles.cs           # SafeHandle subclasses for all native handles
  tests/
    Limn.Scp.Tests/
      Limn.Scp.Tests.csproj
      IdentityTests.cs
      ContextTests.cs
      ToolsTests.cs
      UcanTests.cs
      TransportTests.cs
      EventLogTests.cs
      McpTests.cs
      Conformance/
        ConformanceTests.cs
  runtimes/
    linux-x64/native/libscp_ffi.so
    linux-arm64/native/libscp_ffi.so
    osx-x64/native/libscp_ffi.dylib
    osx-arm64/native/libscp_ffi.dylib
    win-x64/native/scp_ffi.dll
```

## C ABI Bridge (cbindgen + P/Invoke)

### Bridge architecture

Rust → cbindgen → C header → P/Invoke → C#

The Rust FFI layer (`crates/scp-ffi/cbindgen/`) is shared with Go and Java. P/Invoke declarations in C# map to the same C ABI functions.

### P/Invoke declarations

```csharp
// Internal/NativeLib.cs
using System.Runtime.InteropServices;

internal static partial class NativeLib
{
    private const string LibName = "scp_ffi";

    [LibraryImport(LibName, EntryPoint = "scp_identity_create", StringMarshalling = StringMarshalling.Utf8)]
    internal static partial int IdentityCreate(
        string custody,
        out nint handle,
        out nint error);

    [LibraryImport(LibName, EntryPoint = "scp_identity_free")]
    internal static partial void IdentityFree(nint handle);

    [LibraryImport(LibName, EntryPoint = "scp_identity_did", StringMarshalling = StringMarshalling.Utf8)]
    internal static partial int IdentityDid(
        nint handle,
        out nint didString);

    [LibraryImport(LibName, EntryPoint = "scp_string_free")]
    internal static partial void StringFree(nint s);

    [LibraryImport(LibName, EntryPoint = "scp_runtime_init")]
    internal static partial int RuntimeInit();

    [LibraryImport(LibName, EntryPoint = "scp_runtime_shutdown")]
    internal static partial void RuntimeShutdown();

    [LibraryImport(LibName, EntryPoint = "scp_error_free")]
    internal static partial void ErrorFree(nint error);
}
```

### SafeHandles

Every native handle is wrapped in a `SafeHandle` subclass for deterministic cleanup:

```csharp
// Internal/SafeHandles.cs
internal sealed class IdentityHandle : SafeHandle
{
    public IdentityHandle() : base(nint.Zero, ownsHandle: true) { }

    public override bool IsInvalid => handle == nint.Zero;

    protected override bool ReleaseHandle()
    {
        NativeLib.IdentityFree(handle);
        return true;
    }
}

internal sealed class ContextHandle : SafeHandle
{
    public ContextHandle() : base(nint.Zero, ownsHandle: true) { }
    public override bool IsInvalid => handle == nint.Zero;
    protected override bool ReleaseHandle()
    {
        NativeLib.ContextFree(handle);
        return true;
    }
}
```

## Limn.Scp.csproj

```xml
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <TargetFramework>net8.0</TargetFramework>
    <LangVersion>12</LangVersion>
    <Nullable>enable</Nullable>
    <ImplicitUsings>enable</ImplicitUsings>
    <TreatWarningsAsErrors>true</TreatWarningsAsErrors>

    <PackageId>Limn.Scp</PackageId>
    <Version>0.1.0</Version>
    <Description>Social Context Protocol SDK for .NET</Description>
    <Authors>Limn</Authors>
    <!-- License TBD -->
    <RepositoryUrl>https://github.com/limn/scp</RepositoryUrl>
  </PropertyGroup>

  <ItemGroup>
    <!-- Native libraries bundled per RID -->
    <Content Include="../runtimes/**/*" PackagePath="runtimes/" />
  </ItemGroup>

  <ItemGroup>
    <PackageReference Include="Microsoft.CodeAnalysis.NetAnalyzers" Version="8.*" PrivateAssets="all" />
  </ItemGroup>
</Project>
```

## SDK Type Definitions

### Identity

```csharp
public sealed class Identity : IAsyncDisposable
{
    private readonly IdentityHandle _handle;

    public string Did => NativeLib.GetDid(_handle);
    public string CustodyType => NativeLib.GetCustodyType(_handle);

    public static async Task<Identity> CreateAsync(string custody = "platform")
    {
        // Task.Run offloads blocking FFI to thread pool. If FFI throughput becomes
        // a bottleneck, consider a dedicated thread or async FFI callbacks.
        return await Task.Run(() =>
        {
            var rc = NativeLib.IdentityCreate(custody, out var handle, out var error);
            if (rc != 0) throw ExtractException(error);
            return new Identity(new IdentityHandle { handle = handle });
        });
    }

    public async ValueTask DisposeAsync()
    {
        _handle.Dispose();
    }
}
```

### Context

```csharp
public sealed class Context : IAsyncDisposable
{
    public async Task SendAsync(ReadOnlyMemory<byte> payload) { ... }

    public async IAsyncEnumerable<Message> ReceiveAsync(
        [EnumeratorCancellation] CancellationToken ct = default)
    {
        while (!ct.IsCancellationRequested)
        {
            var msg = await Task.Run(() => NativeLib.ContextReceive(_handle), ct);
            if (msg is null) yield break;
            yield return msg.ToMessage();
        }
    }

    public async Task<Dictionary<string, object>> InvokeToolAsync(
        string toolId, Dictionary<string, object> input) { ... }

    public async ValueTask DisposeAsync()
    {
        if (_handle is { IsInvalid: false })
        {
            await LeaveAsync();
            _handle.Dispose();
        }
    }
}
```

### Value types

```csharp
public record Message(
    string SenderDid,
    byte[] Content,
    long Timestamp,
    long Sequence,
    string ContextId,
    Provenance? Provenance = null
);

public record ToolDefinition(
    string Name,
    string Description,
    Dictionary<string, object> InputSchema,
    Dictionary<string, object> OutputSchema,
    string Operator,
    IReadOnlyList<TestVector>? TestVectors = null,
    byte[]? ImplementationHash = null
);

public record TestVector(
    Dictionary<string, object> Input,
    Dictionary<string, object> ExpectedOutput,
    string Description
);
```

### Exception hierarchy

```csharp
public class ScpException : Exception
{
    public string Code { get; }  // e.g., "SCP-CTX-2001"

    public ScpException(string message, string code) : base(message)
    {
        Code = code;
    }
}

public class IdentityException : ScpException
{
    public IdentityException(string message, string code) : base(message, code) { }
}

public class ContextException : ScpException { ... }
public class PermissionException : ScpException { ... }
public class CryptoException : ScpException { ... }
public class TransportException : ScpException { ... }
public class ToolException : ScpException { ... }
public class ValidationException : ScpException { ... }
```

## NuGet Publishing

Published as `Limn.Scp` on NuGet.

```xml
<!-- Consumer usage -->
<PackageReference Include="Limn.Scp" Version="0.1.0" />
```

Package includes:
- Compiled .NET assembly
- Native libraries per RID (runtime identifier): `linux-x64`, `linux-arm64`, `osx-x64`, `osx-arm64`, `win-x64`
- XML documentation for IntelliSense
