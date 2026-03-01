# Lesson: HotStreamFactory cleanup is explicit, not coroutine-scope-linked

## Context

SCP-116 implemented `HotStreamFactory` for real-time event and message streams backed by
`MutableSharedFlow`. The story criterion said "Stream cleanup occurs on coroutine scope
cancellation." The implementation does not satisfy this literally — subscriptions are held
in plain `mutableMapOf` with no `CoroutineScope` linkage.

## Decision

`HotStreamFactory` requires explicit cleanup via `stopContextEvents()`, `stopMessageStream()`,
or `stopAll()`. It does not accept a `CoroutineScope` and does not perform automatic cleanup
when any scope is cancelled.

## Why

ADR-028 (phase-6.md §ADR-028) delegates lifecycle management to the ViewModel/lifecycle layer.
The intended usage is `ViewModel.onCleared()` calling `factory.stopAll()`, or an `@AfterEach`
in tests. This keeps the factory itself free of Android/lifecycle dependencies and matches the
ADR-028 `AutoCloseable` + explicit `close()` pattern.

## Implications

- Story criteria for future hot-stream features must explicitly state whether cleanup is
  scope-linked or explicit. "Cleanup on scope cancellation" is ambiguous when the component
  does not hold a scope.
- When writing tests, always add an `@AfterEach` that calls `factory.stopAll()` — the test
  will otherwise leak subscriptions across test cases.
- If automatic scope-linked cleanup is needed (e.g., for a background data sync use case),
  pass a `CoroutineScope` to the factory constructor and launch a job that calls `stopAll()`
  when the scope's `Job` completes.

## Anti-pattern

Do NOT rely on garbage collection for `HotStreamFactory` cleanup. The docstring notes GC as
a fallback, but explicit `stopAll()` is the only reliable teardown path. Rust-side subscription
handles are opaque longs — they will not be reclaimed until `contextUnsubscribeEvents()` or
`contextUnsubscribe()` is called explicitly.
