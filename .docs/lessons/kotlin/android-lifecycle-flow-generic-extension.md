# Lesson: Use generic Flow<T> for lifecycle extensions, not domain-specific types

## Context

SCP-117 implemented `asLifecycleFlow()` as a lifecycle-scoped flow extension in the `scp-sdk-kotlin-android` module. The ADR-028 spec showed `Context.asLifecycleFlow()` as an extension on the ergonomics-layer `Context` class (returning `Flow<Message>`), but that class did not exist yet at implementation time.

## Decision

Defined the extension as `Flow<T>.asLifecycleFlow(owner, minActiveState)` -- a generic extension on any Flow -- rather than coupling it to a specific SCP type.

## Why

1. **Bridge layer returns `Flow<String>`** (`ContextBridge.subscribe()`), not `Flow<Message>`. The ergonomics-layer `Context.receiveFlow()` returning `Flow<Message>` is a future story.
2. **Generic extension works at every layer**: bridge (`Flow<String>`), ergonomics (`Flow<Message>`), and any other Flow the consumer might want lifecycle-scoped.
3. **No breaking change needed** when `Context.kt` is implemented. The ADR-028 pattern `context.receiveFlow().asLifecycleFlow(owner)` works directly because `receiveFlow()` returns a `Flow<Message>` which satisfies `Flow<T>`.
4. **Matches `flowWithLifecycle()` signature** from AndroidX, which is also generic.

## Anti-pattern

Do NOT create type-specific lifecycle extensions like `Flow<Message>.asLifecycleFlow()` or `Context.asLifecycleFlow()`. These would need to be updated or duplicated as the type hierarchy evolves. The generic version handles all cases.
