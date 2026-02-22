# File-Level Logger Constants with MainActor Default

**Problem**: With `SWIFT_DEFAULT_ACTOR_ISOLATION = MainActor`, file-level `let` constants are MainActor-isolated by default, even if the type is `Sendable`. A file-level `Logger` constant used inside an `actor` fails with "main actor-isolated let 'logger' cannot be accessed from outside of the actor".

**Solution**: Move the logger inside the actor as a `nonisolated static let`:

```swift
actor MyService {
    private nonisolated static let logger = Logger(
        subsystem: "com.example",
        category: "MyService"
    )

    func work() {
        Self.logger.debug("Working...")
    }
}
```

**Note**: SE-0412 says global `let` constants of Sendable types should be safe, but with `SWIFT_DEFAULT_ACTOR_ISOLATION = MainActor`, they still get MainActor isolation. Using a nonisolated static property inside the actor avoids this.
