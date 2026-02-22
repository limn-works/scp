# Prefer @MainActor Class Over Actor When All Callers Are MainActor

**Problem**: Actor isolation requires hop through the cooperative thread pool for every property access and method call, even when the caller is already on MainActor. This adds scheduling overhead for zero safety benefit when underlying dependencies are already thread-safe.

**Solution**: Use `@MainActor final class` instead. Properties become synchronous from MainActor context. Network calls (`URLSession`) suspend the MainActor during I/O without blocking it.

**Key insight**: A synchronous `@MainActor` property satisfies a `{ get async }` protocol requirement — the compiler bridges automatically. No adapter code needed.

**Decision rule**: Use `actor` when callers are on mixed isolation domains. Use `@MainActor final class` when all callers are MainActor.
