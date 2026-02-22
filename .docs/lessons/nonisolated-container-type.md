# Prefer nonisolated on the Container Type, Not Individual Members

**Problem**: In Swift 6.2 with `default-isolation=MainActor`, annotating every member individually with `nonisolated` is verbose and error-prone. The compiler warns that `nonisolated(unsafe)` is unnecessary for `Sendable` `static let` constants, but removing the annotation causes isolation errors at use sites.

**Solution**: Make the containing type `nonisolated`:

```swift
// BAD: per-member annotations
struct KeychainService {
    nonisolated func store(_ value: String, for key: Key) throws { ... }
    nonisolated func retrieve(for key: Key) throws -> String? { ... }
    nonisolated func delete(for key: Key) throws { ... }
}

// GOOD: type-level nonisolated, members inherit
nonisolated struct KeychainService {
    func store(_ value: String, for key: Key) throws { ... }
    func retrieve(for key: Key) throws -> String? { ... }
    func delete(for key: Key) throws { ... }
}
```

**Applies to**: Stateless utility types (configuration enums, keychain wrappers, service helpers) where no member needs MainActor isolation. Does NOT apply to types that manage mutable UI state.
