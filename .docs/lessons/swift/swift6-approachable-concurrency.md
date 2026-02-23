# Swift 6.2 Approachable Concurrency

Two **independent** build settings change concurrency behavior:
- `SWIFT_APPROACHABLE_CONCURRENCY = YES` — changes async function behavior
- `SWIFT_DEFAULT_ACTOR_ISOLATION = MainActor` — changes default type isolation

**The mental model**: Everything runs on the main thread unless you explicitly opt into concurrency.

**`nonisolated` means different things for sync vs async**:
- **Sync** (inits, regular functions): "callable from any isolation domain without await" — unchanged in 6.2
- **Async** (with Approachable Concurrency): "inherits caller's isolation" — no longer means "background thread"

**To run async work off the main actor**: Use `@concurrent`, not `nonisolated`.

See `standards/swift.md` for the full quick-reference rules.
