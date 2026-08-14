# Swift SDK (`bindings/swift/`)

## Architecture

The Swift SDK is a thin delegation layer over UniFFI-generated bindings. Every public method calls exactly one UniFFI bridge function -- zero protocol logic lives in Swift. See ADR-026 in `.docs/adrs/phase-5.md`.

### Key files

- `Sources/SCP/Internal/ScpBindings.swift` -- UniFFI-generated bindings (~5700 lines). Do not edit.
- `Sources/SCP/Context.swift` -- Core `Context` actor with `ContextBridge` injectable pattern.
- `Sources/SCP/Outlets.swift`, `Ucan.swift`, `Transport.swift`, `EventLog.swift`, `Trust.swift`, `Mcp.swift` -- Module wrappers using `*Bridge` enums.
- `Sources/SCP/Errors.swift`, `Types.swift`, `Identity.swift` -- Minimal; most types come from UniFFI.

### Injectable bridge pattern

Each module has an internal `*Bridge` enum with:
1. Typealias closures matching UniFFI function signatures
2. Static default implementations calling the real UniFFI functions
3. Public API methods accept optional bridge function parameter for test injection

```swift
internal enum OutletBridge {
    internal typealias InvokeFn = @Sendable (_ handle: ContextHandle, ...) async throws -> String
    internal static let defaultInvoke: InvokeFn = { ... try await outletInvoke(...) }
}

public func invokeOutlet(..., invokeFn: OutletBridge.InvokeFn = OutletBridge.defaultInvoke) async throws -> OutletInvocationResult
```

### Trust delegation

Trust is wired to the UniFFI bridge: `Trust.swift` delegates to the generated `inner` (e.g. `ucanEvaluate`, `participationRecord`) exactly like every other module — `evaluateTrust` composes those bridge calls (Layer 1 + Layer 2) and resolves the context id from `handle.contextId()`; zero protocol logic lives in Swift. Tests still use the injectable `*Bridge` closures to stand in for the bridge.

### Modules without UniFFI exports

MCP does not have Rust bridge function exports yet. Its `*Bridge` defaults throw descriptive errors. These are NOT "not yet available" placeholders -- they are injectable stubs that will be replaced when Rust exports land.

## Gotchas

- **Context.handle is `internal`** -- Extensions in other files (Outlets.swift, etc.) access `handle` directly for UniFFI bridge calls. `private` would make this impossible.
- **Context.handle is concrete `ContextHandle`** -- All bridge function typealiases (except `CreateFn`, which returns `any ContextHandleProtocol`) and the actor property use the concrete `ContextHandle` type, not `any ContextHandleProtocol`. No guard-casts needed.
- **No `withCheckedThrowingContinuation`** -- UniFFI async functions are already `async throws` in Swift. Direct `try await` is correct. The old callback-based stubs used continuations; those are gone.
- **`ContextHandle(noPointer: .init())`** -- Use this in tests to create a fake handle. Pass `contextId`, `creatorDid`, and `initialState` overrides to `Context.init` to avoid calling handle methods on a null pointer.
- **Error code namespacing** -- Outlet extensions use `SCP-CTX-2001` (not `SCP-CTX-001`) to avoid collision with Context.swift. EventLog uses `SCP-CTX-2030/2031`. Transport uses `SCP-TRANS-5001`. MCP stubs use `SCP-MCP-10001`-`10004`.
- **Concurrency** -- Use actors, not locks. Target is macOS 14 / iOS 17 (Swift Concurrency without `Synchronization.Mutex`).
- **ScpBindings.swift is large** (~5700 lines). Read in chunks or use grep to find specific sections.

## Testing

Tests use the injectable bridge pattern: inject mock closures that capture arguments and return canned responses. Every module has at least one async roundtrip test. Tests live in `Tests/SCPTests/`.

## Build

```bash
cd bindings/swift && swift build
```

Note: Without the actual XCFramework (SCP-103), the build will succeed for type checking but the binary cannot link against Rust. The injectable bridge pattern allows testing without the binary.
