# Lesson: viewModelScope is cancelled BEFORE onCleared() — never launch cleanup there

## Context

SCP-117 implemented `ScpViewModel.onCleared()` using `viewModelScope.launch { ... }` to
dispatch cleanup of tracked SCP context handles. The implementation passed all JVM unit tests
but contains a silent production defect: cleanup never runs on real Android.

## The Bug

`ViewModel.clear()` (called by the Android framework) cancels `viewModelScope` via its
`CloseableCoroutineScope` tag **before** invoking `onCleared()`. The sequence is:

1. Framework calls `ViewModel.clear()`
2. `clear()` closes all `CloseableCoroutineScope` tags → `viewModelScope` Job is cancelled
3. `clear()` calls `onCleared()`
4. `onCleared()` calls `viewModelScope.launch { cleanup }` → launch into cancelled scope → no-op

The cleanup coroutine is silently dropped. No exception. No warning. Context handles leak.

## Why Tests Masked the Bug

`TestScpViewModel.callOnCleared()` calls `onCleared()` directly, bypassing `ViewModel.clear()`.
The `viewModelScope` is never pre-cancelled in tests, so `viewModelScope.launch` succeeds and
the tests pass. Production and test environments diverge on the one critical behavior being tested.

## Correct Pattern

Use a dedicated cleanup scope not tied to `viewModelScope`:

```kotlin
private val cleanupScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

override fun onCleared() {
    cleanupScope.launch {
        val contexts = mutex.withLock {
            val snapshot = activeContexts.toList()
            activeContexts.clear()
            snapshot
        }
        for (ctx in contexts) {
            runCatching { ctx.bridge.context.leave(ctx.handle) }
        }
        cleanupScope.cancel()
    }
    super.onCleared()
}
```

## Testing the Correct Pattern

To test that cleanup actually runs on ViewModel destruction, use one of:

1. **Robolectric with real ViewModel lifecycle** — `ViewModelProvider` + `ActivityScenario.close()`
   triggers the full `clear()` → cancel → `onCleared()` sequence on the real framework code.
2. **Dedicated scope** — if using the dedicated `cleanupScope` pattern above, tests can
   directly `advanceUntilIdle()` after `callOnCleared()` because `cleanupScope` is not
   pre-cancelled by the test helper.

## Anti-Pattern

Never dispatch ViewModel cleanup work via `viewModelScope.launch` inside `onCleared()`. The
scope is already cancelled at that point. This pattern looks correct, passes JVM unit tests,
but silently leaks every resource the ViewModel was supposed to release.

## Affected Files (SCP-117)

- `bindings/kotlin/scp-sdk-kotlin-android/src/main/kotlin/com/limn/scp/android/ScpViewModel.kt`
- `bindings/kotlin/scp-sdk-kotlin-android/src/test/kotlin/com/limn/scp/android/ScpViewModelTest.kt`
