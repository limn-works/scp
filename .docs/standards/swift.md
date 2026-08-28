# Swift Standards

Swift conventions, safety rules, framework-specific patterns, and SCP SDK standards. References `sdk-common.md` for cross-language invariants and `conventions.md` for git/branch conventions.

## Swift Conventions

- Follow Swift API Design Guidelines
- Use meaningful, descriptive names
- Prefer `let` over `var`
- Use access control intentionally (`private`, `internal`, `public`)

## Design Patterns

- Protocol-first design; inject dependencies through initializers
- No singletons — use dependency injection
- Prefer value types (`struct`, `enum`) over reference types where possible

## Safety

- **No force unwraps** (`!`) in production code
- **No force try** (`try!`) — handle errors explicitly
- **No implicitly unwrapped optionals**
- **No `@unchecked Sendable`** — use proper `Sendable` conformance or actors
- **No `nonisolated(unsafe)`** — prefer making the containing type `nonisolated` (e.g., `nonisolated enum`, `nonisolated struct`) so all its members inherit nonisolated context
- Use `guard` for early exits
- Prefer `if let` / `guard let` over force unwrapping

## Async/Await

- Use `async/await` for all asynchronous work
- Mark actors appropriately for thread safety
- Avoid completion handlers in new code

## Swift 6 Concurrency

- **Data races are compile-time errors**, not warnings — strict concurrency is enforced
- Prefer actors for mutable shared state
- Use `nonisolated` explicitly when needed for protocol conformance
- Capture values in closures to avoid isolation issues
- When wrapping callback-based APIs, prefer `@MainActor` classes over `@unchecked Sendable`
- **Sendable closures** capturing non-Sendable types across isolation boundaries is a compile error or runtime data race

## Swift 6.2 Approachable Concurrency

Two independent build settings:
- `SWIFT_APPROACHABLE_CONCURRENCY = YES` — async functions inherit caller's isolation
- `SWIFT_DEFAULT_ACTOR_ISOLATION = MainActor` — all types default to `@MainActor`

**Quick rules:**
- **MainActor is default.** All types are `@MainActor` unless explicitly opted out
- **Data carrier types** (DTOs, requests, errors): `nonisolated struct` — `Sendable` by definition
- **Stateless utility types** (configuration enums, services): `nonisolated enum`/`nonisolated struct`
- **`nonisolated async`** inherits caller's isolation (doesn't run in background)
- **Use `@concurrent`** for background async work, not `nonisolated`
- **`@Model` is not Sendable** — use DTOs to cross isolation boundaries

## SwiftUI

- Keep views small and focused
- Extract reusable components
- Use `@State` for local view state
- Use `@Query` for SwiftData fetches — only works in SwiftUI views, updates on main actor
- Prefer `@Environment` for dependency injection in views
- Include previews for all views with multiple states

## SwiftData

- Define models with `@Model` macro
- Use relationships for connected data
- Handle migrations explicitly
- Keep queries in repository abstractions
- **`ModelContext` is not Sendable** — must not cross actor boundaries
- **`@Model` objects are not Sendable** — passing them across isolation boundaries is a bug; use DTOs instead

## Multiplatform

- **Always verify both iOS and macOS build** before committing
- Use conditional compilation for platform-specific APIs:
  ```swift
  #if canImport(UIKit)
  import UIKit
  #elseif canImport(AppKit)
  import AppKit
  #endif
  ```
- Prefer pure SwiftUI and CoreGraphics where possible (works everywhere)
- UIKit-specific code (UIFont, UIColor, UIFontMetrics) requires AppKit equivalents

---

## SCP SDK Standards

The following sections apply to the SCP Swift SDK (`bindings/swift/`). The app-layer standards above also apply when building apps on top of the SDK.

### Toolchain

| Tool | Version | Purpose |
|------|---------|---------|
| Swift | 6.2+ | Language version |
| SPM | (bundled) | Swift Package Manager |
| UniFFI | latest | FFI bridge from Rust (shared UDL with Kotlin) |
| Swift Testing | (bundled) | Test framework (`@Test`, `#expect`) |
| SwiftFormat | latest | Formatter |
| SwiftLint | latest | Linter |

### Package layout, UniFFI bridge, and type definitions

See `.docs/scaffold/swift.md` for the build blueprint: package structure, UniFFI bridge patterns, XCFramework build, and SDK type definitions (Identity, ScpError, Message, ToolDefinition).

### Testing (Swift Testing)

Use the Swift Testing framework (`@Test`, `#expect`):

```swift
import Testing
@testable import SCP

@Test
func createIdentityReturnsValidDid() async throws {
    let identity = try await Identity.create(custody: "in_memory")
    #expect(identity.did.hasPrefix("did:dht:"))
}

@Test
func contextSendRequiresActiveState() async throws {
    // ...
}

@Test(arguments: [
    ("messages:write", true),
    ("context:close", false),
])
func validateCapabilityChecksCeiling(capability: String, shouldPass: Bool) async throws {
    // ...
}
```

The snippet above passes `in_memory`, which §3.2.2 of the identity spec, the custody
vocabulary, classifies as a test-harness string rather than a value a shipped caller
names. A test reaches it only in a build carrying the bridge's `testing` feature; a
shipped build rejects it with `SCP-IDENT-1008` and takes `encrypted_file` or
`os_keystore` instead.

### CI Commands

```bash
# Build (iOS + macOS)
swift build
xcodebuild build -scheme SCP -destination 'platform=iOS Simulator,name=iPhone 16'
xcodebuild build -scheme SCP -destination 'platform=macOS'

# Test
swift test
xcodebuild test -scheme SCP -destination 'platform=iOS Simulator,name=iPhone 16'

# Lint
swiftlint lint --strict

# Format
swiftformat --lint Sources/ Tests/
```

### CI Matrix

| Job | Runs on | Xcode | Trigger |
|-----|---------|-------|---------|
| swiftlint | macos-latest | latest | Every PR |
| swiftformat | macos-latest | latest | Every PR |
| dependency-audit | macos-latest | latest | Every PR |
| build (iOS) | macos-latest | latest | Every PR |
| build (macOS) | macos-latest | latest | Every PR |
| test (iOS Simulator) | macos-latest | latest | Every PR |
| test (macOS) | macos-latest | latest | Every PR |
| conformance | macos-latest | latest | Every PR |
| build-xcframework | macos-latest | latest | Tagged release |
