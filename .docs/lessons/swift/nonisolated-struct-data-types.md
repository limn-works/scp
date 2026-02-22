# Data Types Should Be `nonisolated struct`

**Problem**: With `SWIFT_DEFAULT_ACTOR_ISOLATION = MainActor`, all types default to `@MainActor`. DTOs, request models, and data carriers need to work across isolation boundaries. If they're `@MainActor`, they can only be created from MainActor.

**Solution**: Mark data carrier types at the type level:

```swift
nonisolated struct UserDTO: Sendable {
    let id: UUID
    let displayName: String
}
```

**This applies to**:
- DTOs (data transfer objects)
- Request/Response models
- Pure data carriers
- Enums used as values (roles, providers, error types)
- Utility structs (parsers, builders)
- Any `Sendable` struct used across actor boundaries

**Important caveats**:
- Extensions on nonisolated types must also be `nonisolated extension`
- Nested types in nonisolated structs need explicit `nonisolated`

**This is intentional design, not a workaround**. With MainActor default, the UI layer is simpler (no annotations), and the data layer explicitly opts out where needed.
