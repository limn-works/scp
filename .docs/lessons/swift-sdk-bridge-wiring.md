# Swift SDK Bridge Wiring Patterns

Lessons from implementing SCP-221 (wire Swift SDK wrappers to UniFFI bridge).

## Context.handle must be internal, not private

The `Context` actor's `handle` property was originally `private`. Extensions
in other files (Tools.swift, etc.) need to cast `handle` to `ContextHandle`
for UniFFI bridge calls. Swift's `private` means file-scoped, so extensions
in different files cannot access it. Changed to `internal`.

## Injectable bridge pattern for Swift

Each module uses an internal `*Bridge` enum with typealias closures and
static default implementations that call UniFFI-generated async functions.
Public API methods accept an optional bridge function parameter (defaulting
to the real bridge) for test injection. This avoids mocking UniFFI classes
and enables async roundtrip testing without the XCFramework binary.

Pattern:
```swift
internal enum ToolBridge {
    internal typealias InvokeFn = @Sendable (
        _ handle: ContextHandle, _ toolId: String, ...
    ) async throws -> String

    internal static let defaultInvoke: InvokeFn = { handle, toolId, ... in
        try await toolInvoke(handle: handle, toolId: toolId, ...)
    }
}

// Public API accepts optional bridge fn
public func invokeTool(
    _ tool: String,
    input: Data,
    invokeFn: ToolBridge.InvokeFn = ToolBridge.defaultInvoke
) async throws -> ToolInvocationResult { ... }
```

## ContextHandle casting for bridge calls

UniFFI bridge functions require `ContextHandle` (a concrete class), but
`Context` stores `any ContextHandleProtocol` for testability. Extensions
must guard-cast: `guard let contextHandle = handle as? ContextHandle`.
Tests that use `MockContextHandle` will hit the state check first (closed)
or get `SCP-CTX-2002` if active with wrong handle type. Roundtrip tests
use `ContextHandle(noPointer: .init())` to pass the cast.

## Modules without UniFFI exports

Trust and MCP have no Rust bridge function exports. Their `*Bridge` enums
have default implementations that either:
- Construct data locally (Trust: builds `TrustInput` and maps to `TrustEvaluation`)
- Throw descriptive errors (MCP: "awaiting mcp_serve export")

These are NOT "UniFFI bridge not yet available" placeholders. They are
injectable bridge stubs that will be replaced when Rust exports land.

## Old callback pattern vs new async pattern

The old stubs used `completion: @Sendable @escaping (Result<T, ScpError>) -> Void`
wrapped in `withCheckedThrowingContinuation`. UniFFI-generated functions are
already `async throws` in Swift, so the continuation wrapper is unnecessary.
Direct `try await bridgeFn(...)` is correct.

## Error code namespacing

Tool extension error codes use `SCP-CTX-2001` (not `SCP-CTX-001`) to avoid
collision with the existing codes in Context.swift. EventLog uses
`SCP-CTX-2030`/`SCP-CTX-2031`. Transport uses `SCP-TRANS-5001`. MCP stubs
use `SCP-MCP-10001` through `SCP-MCP-10004`.
