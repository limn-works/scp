# MainActor Reentrancy at Suspension Points

**Problem**: MainActor is **reentrant** at `await` suspension points. Other MainActor code can execute between capture and write-back, mutating shared state in the interim. The write-back silently overwrites those changes:

```swift
// BAD: stale snapshot
func updateItem(at index: Int) async {
    var items = self.items              // capture before await
    let updated = await service.process(items[index])
    items[index] = updated             // stale — items may have changed
    self.items = items                 // overwrites concurrent mutations
}
```

**Solution**: Always re-read shared state after the `await` returns. Re-resolve indices by stable identifier (UUID), not captured integer:

```swift
// GOOD: fresh state after suspension
func updateItem(id: UUID) async {
    let updated = await service.process(...)
    // Re-read AFTER await — get current state
    guard let index = self.items.firstIndex(where: { $0.id == id }) else { return }
    self.items[index] = updated
}
```

**General rule**: Treat any `await` on MainActor as a potential interleaving point. Never assume `self` properties are unchanged after suspension. This applies to all `@MainActor` classes.
