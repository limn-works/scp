# Test Quality Reviewer Memory

## SCP Project Conventions

### Swift Testing
- All Swift tests use Swift Testing framework (@Test, #expect, @Suite) -- never XCTest
- Standard at `.docs/standards/swift.md` lines 112-136
- `@unchecked Sendable` prohibited in production (line 23) but used in test mocks -- consider documenting exception
- Test files at `bindings/swift/Tests/SCPTests/`

### Swift SDK Architecture (affects test design)
- All bridge functions are stubs returning errors until SCP-103 (XCFramework) ships
- Bridge injection via typed closures (ContextBridge.SendFn etc.) enables behavioral testing
- Context is an actor; DTOs are nonisolated structs
- CheckedContinuation bridges async Rust FFI to Swift concurrency
- See `swift-sdk-patterns.md` for details

### Common Anti-Patterns Found
- Tautological assertions: `#expect(value >= 0)` on unsigned/empty-default values provides zero signal
- Duplicated mock types across test files instead of shared test helpers
- Polling loops with Task.sleep for synchronization instead of deterministic mechanisms
- Local `var` captured by `@Sendable` closures = data race under Swift 6 strict concurrency
- Relative file paths in test fixture loading (use #filePath for repo root)
- Tests claiming to verify access control but using @testable import (which exposes internals)

### Good Patterns Worth Replicating
- ContextTests mock injection: typed closure injection for every bridge function
- Locked<Value> wrapper with NSLock for test-side mutable state in concurrent tests
- Doc comments on test suites explaining scope and known limitations
- "Stub-era" marking so update scope is visible when real bridges ship

## Review Checklist Additions (SCP-specific)
- Conformance dispatcher must cover ALL operations from `.docs/scaffold/shared.md` categories
- Every SDK source module needs a corresponding test file (Trust.swift was missing tests)
- Cross-reference acceptance criteria operations against actual SDK API surface (e.g., "append" vs "query")
