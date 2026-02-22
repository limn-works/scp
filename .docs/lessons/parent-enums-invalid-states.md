# Making Invalid States Unrepresentable with Parent Enums

**Problem**: Optional properties with runtime validation catches errors too late:

```swift
// Bad: allows invalid states
struct MessageDTO {
    let groupID: UUID?   // One or the other, but which?
    let channelID: UUID?

    var isValid: Bool {  // Runtime check — too late!
        (groupID != nil) != (channelID != nil)
    }
}
```

**Solution**: Model the constraint as an enum. Invalid states become unrepresentable at compile time:

```swift
nonisolated enum MessageParent: Sendable, Equatable, Hashable {
    case group(UUID)
    case channel(UUID)
}

nonisolated struct MessageDTO: Sendable {
    let parent: MessageParent  // Exactly one parent, always valid
}
```

**Benefits**:
- Invalid states are **impossible to construct** (compile-time guarantee)
- No runtime validation needed
- Switch statements are exhaustive (compiler ensures all cases handled)
- Self-documenting: type signature shows the constraint

**Pattern applies when**: A type has mutually exclusive parent relationships or either/or semantics. Prefer this over factory methods — factory methods still allow invalid internal state.
