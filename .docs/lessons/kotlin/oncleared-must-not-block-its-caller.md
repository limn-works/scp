# Lesson: `runBlocking` in `onCleared()` deadlocks whenever the work it waits on is scheduled onto the caller's thread

## Context

SCP-117 shipped `ScpViewModel.onCleared()` as `runBlocking(cleanupScope.coroutineContext) { … }`
around a loop that called `CoroutineBridge.ContextBridge.leave` for each tracked context. The
KDoc justified the block: cleanup had to "complete before the method returns."

`ScpViewModelTest` exercised that loop under a `StandardTestDispatcher`. Three of its six methods
parked a thread forever instead of failing. Nobody saw the park, because
`bindings/kotlin/scp-kt-android/build.gradle.kts` never called `useJUnitPlatform()`, so the six
JUnit 5 test classes in that module compiled and never ran.

## The deadlock

`ScpViewModelTest` gives `CoroutineBridge` a `StandardTestDispatcher` as its `ioDispatcher`, and
`ContextBridge.leave` routes through `CoroutineBridge.ffiCall`, which runs its body inside
`withContext(ioDispatcher)`. The chain:

1. The test body runs on the `TestCoroutineScheduler`, which executes tasks on the test thread.
2. `callOnCleared()` enters `runBlocking`, which parks the test thread in
   `BlockingCoroutine.joinBlocking` until its child coroutine completes.
3. The child coroutine calls `leave`, which enqueues a continuation on the `TestCoroutineScheduler`.
4. A `StandardTestDispatcher` runs a queued task only when a test advances its scheduler, and only
   the test thread advances it. That thread is parked at step 2.

A thread dump of the hung worker showed one thread, `Test worker @kotlinx.coroutines.test runner`,
in `TIMED_WAITING (parking)` at `BlockingCoroutine.joinBlocking`, called from
`ScpViewModel.onCleared`, with the coroutine's `leave` continuation still queued.

The dispatcher the `runBlocking` call names does not change the outcome. `runBlocking(Dispatchers.IO)`
parks the *calling* thread and runs the block on an IO thread, and that block still suspends on the
test scheduler, which still needs the parked thread. `withTimeoutOrNull` does not rescue it either:
the timeout runs on the test scheduler's virtual clock, which only advances when the parked thread
advances it. Every variant that blocks the caller keeps the deadlock.

## The rule

A non-suspend method must not block its calling thread waiting on a coroutine whose dispatcher the
method does not control. Dispatch the work and return.

`onCleared()` now snapshots and clears the tracked-context list under a monitor lock, launches the
`leave` calls on a dedicated scope, and returns. It states plainly that cleanup is best-effort: the
`leave` calls run to completion only if the process outlives them. Blocking the Android main thread
on FFI calls risks an ANR, so the honest guarantee is the one worth documenting, not a stronger one
bought with a deadlock.

## Injecting the cleanup dispatcher

`ScpViewModel` takes `cleanupDispatcher: CoroutineDispatcher = Dispatchers.IO` and builds its
cleanup scope from it. A test passes the same `TestDispatcher` it gave `CoroutineBridge`, so
`advanceUntilIdle()` runs the cleanup coroutine and every `leave` it makes. A cleanup scope hardwired
to `Dispatchers.IO` would leave the test racing an IO thread that may not have enqueued its
continuation yet when `advanceUntilIdle()` returns.

## Make a deadlock fail instead of hang

`ScpViewModelTest` carries a class-level
`@Timeout(value = 30, unit = TimeUnit.SECONDS, threadMode = Timeout.ThreadMode.SEPARATE_THREAD)`.
`SEPARATE_THREAD` runs each method on its own thread and aborts it at the limit, so a reintroduced
block fails the build in 31 seconds. `.github/workflows/ci.yml` sets no `timeout-minutes`, so
without that annotation one deadlocked test consumes a 360-minute runner per pull request.

## Affected files

- `bindings/kotlin/scp-kt-android/src/main/kotlin/works/limn/scp/android/ScpViewModel.kt`
- `bindings/kotlin/scp-kt-android/src/test/kotlin/works/limn/scp/android/ScpViewModelTest.kt`
