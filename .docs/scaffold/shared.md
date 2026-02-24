# Shared Scaffold

> Source of truth: .docs/specs/, .docs/sketch.md, .docs/adrs/. This file is downstream of those documents.

Build blueprint for the SCP monorepo: crate organization, FFI strategy, cross-language naming, versioning, conformance testing, and documentation requirements. See `.docs/standards/sdk-common.md` for cross-language coding standards (error hierarchy, async patterns, resource lifecycle, CI gates).

## Monorepo Topology

```
crates/
  scp-core/           # Protocol engine (MLS, DID, envelope, context, UCAN, event log)
  scp-transport/      # Transport abstraction + native relay + adapters
  scp-platform/       # Platform adapters (key custody, attestation, push, storage)
  scp-mcp/            # MCP adapter (JSON-RPC server/client)
  scp-ffi/
    pyo3/             # Python FFI bridge (PyO3 + maturin)
    uniffi/           # Swift + Kotlin FFI bridge (UniFFI UDL)
    cbindgen/         # C ABI bridge → Go (cgo), C# (P/Invoke), Java (JNA)
    wasm/             # Browser TypeScript FFI (wasm-bindgen)
    napi/             # Node/Bun TypeScript FFI (napi-rs)
bindings/
  python/             # scp-sdk (PyPI) — scp_sdk package
  typescript/         # @scp/sdk (npm) — dual target: browser WASM + Bun/Node native
  swift/              # SCP (Swift Package Manager)
  kotlin/             # com.limn:scp-sdk-kotlin (Maven Central)
  go/                 # github.com/limn/scp-go (Go module)
  csharp/             # Limn.Scp (NuGet)
  java/               # com.limn:scp-sdk-java (Maven Central)
```

## Crate Responsibilities

| Crate | Role | Key dependencies |
|-------|------|------------------|
| `scp-core` | All protocol logic: MLS wrapper, DID, envelope, context lifecycle, UCAN, event log, sender keys | openmls, ed25519-dalek, sha2, hkdf, aes-gcm, serde, thiserror |
| `scp-transport` | Transport trait + adapters. Native relay server/client. Multi-transport routing | tokio, tokio-tungstenite, futures |
| `scp-platform` | Platform abstraction traits + in-memory testing adapters | ed25519-dalek, rand |
| `scp-mcp` | MCP JSON-RPC server/client for tool exposition | serde_json, tokio, axum |
| `scp-ffi/*` | Language-specific FFI bridges. Thin translation layers only — zero protocol logic | pyo3, uniffi, cbindgen, wasm-bindgen, napi-rs |

## FFI Bridge Strategy

Three bridges serve eight languages:

| Bridge | Crate | Target languages | Mechanism |
|--------|-------|------------------|-----------|
| **PyO3** | `scp-ffi/pyo3` | Python | Direct Rust-Python interop via `#[pyfunction]`/`#[pyclass]` |
| **UniFFI** | `scp-ffi/uniffi` | Swift, Kotlin | Single UDL definition generates Swift + Kotlin bindings |
| **cbindgen** | `scp-ffi/cbindgen` | Go, C#, Java | C ABI header → cgo, P/Invoke, JNA |
| **wasm-bindgen** | `scp-ffi/wasm` | TypeScript (browser) | WASM module loaded in browser |
| **napi-rs** | `scp-ffi/napi` | TypeScript (Bun/Node) | Native addon for server-side JS runtimes |

Every FFI bridge crate:
- Depends on `scp-core`, `scp-transport`, `scp-platform`
- Contains zero protocol logic — only type translation and runtime bridging
- Exposes the same logical API surface (see sketch.md)

## Cross-Language Naming

### Naming table

All SDKs use language-idiomatic casing for the same logical identifiers.

| Concept | Rust | Python | TypeScript | Swift | Kotlin | Go | C# | Java |
|---------|------|--------|------------|-------|--------|-----|-----|------|
| Identity type | `Identity` | `Identity` | `Identity` | `Identity` | `Identity` | `Identity` | `Identity` | `Identity` |
| Context type | `ContextHandle` | `Context` | `Context` | `Context` | `Context` | `Context` | `Context` | `Context` |
| Create identity | `Identity::create` | `Identity.create()` | `Identity.create()` | `Identity.create()` | `Identity.create()` | `NewIdentity()` | `Identity.CreateAsync()` | `Identity.create()` |
| Create context | `ContextManager::create` | `Context.create()` | `Context.create()` | `Context.create()` | `Context.create()` | `NewContext()` | `Context.CreateAsync()` | `Context.create()` |
| Send message | `ctx.send_message()` | `ctx.send()` | `ctx.send()` | `ctx.send()` | `ctx.send()` | `ctx.Send()` | `ctx.SendAsync()` | `ctx.send()` |
| Invoke tool | `ctx.invoke_tool()` | `ctx.invoke_tool()` | `ctx.invokeTool()` | `ctx.invokeTool()` | `ctx.invokeTool()` | `ctx.InvokeTool()` | `ctx.InvokeToolAsync()` | `ctx.invokeTool()` |
| Receive messages | `ctx.receive()` | `ctx.receive()` | `ctx.receive()` | `ctx.messages` | `ctx.receiveFlow()` | `ctx.Receive()` | `ctx.ReceiveAsync()` | `ctx.receive()` |
| Leave context | `ctx.leave()` | `ctx.leave()` | `ctx.leave()` | `ctx.leave()` | `ctx.leave()` | `ctx.Leave()` | `ctx.LeaveAsync()` | `ctx.leave()` |
| Close context | `ctx.close()` | `ctx.close()` | `ctx.close()` | `ctx.close()` | `ctx.close()` | `ctx.Close()` | `ctx.CloseAsync()` | `ctx.close()` |
| Error base | `ScpError` | `ScpError` | `ScpError` | `ScpError` | `ScpException` | `ScpError` | `ScpException` | `ScpException` |
| Package name | `scp-core` | `scp-sdk` | `@scp/sdk` | `SCP` | `com.limn:scp-sdk-kotlin` | `scp-go` | `Limn.Scp` | `com.limn:scp-sdk-java` |

### Casing rules per language

| Language | Types | Functions/Methods | Constants | Modules/Packages | Files |
|----------|-------|-------------------|-----------|-------------------|-------|
| Rust | `PascalCase` | `snake_case` | `SCREAMING_SNAKE` | `snake_case` | `snake_case.rs` |
| Python | `PascalCase` | `snake_case` | `SCREAMING_SNAKE` | `snake_case` | `snake_case.py` |
| TypeScript | `PascalCase` | `camelCase` | `SCREAMING_SNAKE` | `camelCase` | `kebab-case.ts` |
| Swift | `PascalCase` | `camelCase` | `camelCase` | `PascalCase` | `PascalCase.swift` |
| Kotlin | `PascalCase` | `camelCase` | `SCREAMING_SNAKE` | `lowercase` | `PascalCase.kt` |
| Go | `PascalCase` (exported) | `PascalCase` (exported) / `camelCase` (unexported) | `PascalCase` (exported) | `lowercase` | `snake_case.go` |
| C# | `PascalCase` | `PascalCase` | `PascalCase` | `PascalCase` | `PascalCase.cs` |
| Java | `PascalCase` | `camelCase` | `SCREAMING_SNAKE` | `lowercase` | `PascalCase.java` |

## Streaming Types

`context_receive()` returns a language-appropriate stream:

| Language | Stream type |
|----------|-------------|
| Rust | `Pin<Box<dyn Stream<Item = Message> + Send>>` |
| Python | `AsyncIterator[Message]` |
| TypeScript | `AsyncIterable<Message>` |
| Swift | `AsyncSequence` |
| Kotlin | `Flow<Message>` |
| Go | `<-chan Message` |
| C# | `IAsyncEnumerable<Message>` |
| Java | `Flow.Publisher<Message>` (Reactive Streams) |

## Versioning

All SDKs follow [SemVer 2.0](https://semver.org/):

- **Major:** Breaking API changes (removed functions, changed signatures, incompatible types)
- **Minor:** New features, new functions, backwards-compatible additions
- **Patch:** Bug fixes, security patches, performance improvements

### Version alignment

All SDK packages share the same major.minor version. Patch versions may differ (language-specific fixes). The Rust core crate version is the source of truth.

```
scp-core 0.1.0 → scp-sdk (Python) 0.1.x, @scp/sdk 0.1.x, SCP (Swift) 0.1.x, ...
```

### Pre-1.0 stability

During 0.x development, minor version bumps may include breaking changes. The API is unstable until 1.0.

## Conformance Testing

Every SDK must pass the cross-language conformance test suite. The suite is defined in `tests/conformance/` and exercises every operation in sketch.md.

### Conformance test categories

| Category | Tests |
|----------|-------|
| **Identity** | Create, load, resolve, rotate key, verify self-certification |
| **Context** | Create, join, leave, close, TTL expiry, state machine transitions |
| **Messaging** | Send, receive, sequence ordering, MLS encryption, out-of-order delivery reordering, gap detection, suppression alerts |
| **Sender keys** | Sender key create, distribute, rotate, encrypt/decrypt roundtrip, key destruction on leave, wrapping key lifecycle (create, publish in LeafNode extension, rotation on identity key change) |
| **Tools** | Register, invoke, verify test vectors, update, cross-context interfaces |
| **UCAN** | Mint, validate (all 11 steps), delegate, revoke, nonce replay rejection, ceiling enforcement |
| **Transport** | Connect, send envelope, subscribe, query, multi-relay fanout, deduplication |
| **Event log** | Append, prove inclusion, verify proof, consistency checkpoint, absence proof |
| **Error handling** | Every error code is reachable, error messages are actionable |

### Conformance test format

Tests are defined as JSON fixtures:

```json
{
  "test_id": "identity-create-001",
  "category": "identity",
  "description": "Create identity with in-memory custody",
  "operation": "identity_create",
  "input": { "custody": "in_memory" },
  "expected": {
    "did_prefix": "did:dht:",
    "custody_type": "in_memory"
  }
}
```

Each SDK implements a conformance test runner that:
1. Loads JSON fixtures from `tests/conformance/`
2. Maps `operation` strings to SDK function calls (e.g., `"identity_create"` → `Identity.create()`)
3. Compares actual output against `expected` using deep equality (with tolerance for timestamps and nonces)
4. Reports results with fixture `test_id` for cross-language debugging

The test runner is language-specific; the fixtures are shared.

### CI gate

No SDK release proceeds without 100% conformance test pass rate. Conformance tests run on every PR that touches `crates/` or `bindings/`.

## SDK Documentation Requirements

Every SDK ships with:

1. **README.md** — Quick start (install, create identity, create context, send message) in under 30 lines
2. **API reference** — Generated from source (rustdoc, pydoc, typedoc, DocC, KDoc, godoc, xmldoc, javadoc)
3. **Type stubs / declarations** — For IDE autocompletion and static analysis (`.pyi`, `.d.ts`, etc.)
4. **Examples directory** — Runnable examples covering: basic messaging, tool invocation, MCP integration, multi-agent coordination

## Release Pipeline

Binary artifact build, sign, and distribute workflow. Conformance gate (100% pass) is a prerequisite — no release without it.

### Build matrix

| Platform | Architectures | Artifact types |
|----------|--------------|----------------|
| Linux | x86_64, aarch64 | manylinux2014 wheels (Python), .so (native) |
| macOS | universal2 (x86_64 + arm64) | wheels (Python), .dylib (native), .xcframework (Swift) |
| Windows | x86_64 | wheels (Python), .dll (native) |

### Distribution channels

| Language | Package | Registry | Artifact |
|----------|---------|----------|----------|
| Rust | `scp-core`, `scp-transport`, `scp-platform` | crates.io | Source crate |
| Python | `scp-sdk` | PyPI | maturin-built wheel (includes compiled Rust) |
| TypeScript (browser) | `@scp/sdk` | npm | WASM bundle |
| TypeScript (Node/Bun) | `@scp/sdk-node` | npm | napi-rs native addon |
| Swift | `SCP` | Swift Package Manager | XCFramework binary target |
| Kotlin | `com.limn:scp-sdk-kotlin` | Maven Central | AAR with bundled .so |
| Go | `github.com/limn/scp-go` | Go modules | Source + pre-built .so |
| C# | `Limn.Scp` | NuGet | Native runtime pack |
| Java | `com.limn:scp-sdk-java` | Maven Central | JAR with bundled natives |

### Version pinning

All SDK packages pin to the exact `scp-core` version they were built against. The `scp-core` crate version is the source of truth (see §Versioning above). SDK packages encode the core version in their metadata (e.g., Python wheel metadata, npm `engines`, Swift Package.swift).

### Signing

All release artifacts are signed. Rust crates are verified by crates.io's built-in checksums. Platform packages use the platform's native signing mechanism (Apple codesigning for .xcframework, Authenticode for .dll, GPG for Maven artifacts). PyPI wheels use Trusted Publishers (GitHub Actions OIDC).

### Release checklist

1. All conformance tests pass (100%) across all target platforms
2. Changelog updated with version bump and summary of changes
3. Version tags created: `scp-core@{version}`, per-SDK tags (`scp-sdk-python@{version}`, etc.)
4. CI builds artifacts for all platforms in the build matrix
5. Artifacts signed per platform signing requirements
6. Publish to registries (crates.io, PyPI, npm, SPM, Maven Central, NuGet, Go proxy)
7. GitHub Release created with binary attachments and changelog
