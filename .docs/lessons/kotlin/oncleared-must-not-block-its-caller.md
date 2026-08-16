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

## Do not cancel a cleanup scope after dispatching to it

`onCleared()` first shipped its non-blocking form with `cleanupJob.invokeOnCompletion { cleanupScope.cancel() }`
appended. That cancellation frees nothing: a `SupervisorJob` whose children have all completed
holds no thread, no handle, and no memory, and `cleanupDispatcher` belongs to whoever constructed
that ViewModel, so cancelling a job never shuts a dispatcher down. It does turn every later
`cleanupScope.launch` into a silent no-op, so a context that `trackContext` registers after a first
`onCleared` call never gets its `leave`. `ScpViewModelTest.a context tracked after onCleared is
still left by a later onCleared` fails if that cancellation returns.

That same reasoning applies to any scope a class creates to outlive one dispatch: cancel it when it
owns something worth releasing, not as a reflex once whatever work it carried has finished.

## That same failure, in a second spelling: Compose disposal

`rememberScpHotStream` in
`bindings/kotlin/scp-kt-android/src/main/kotlin/works/limn/scp/android/compose/StateHolders.kt`
ran `runBlocking { onStop() }` inside `DisposableEffect`'s `onDispose`. A comment there argued that
blocking was safe because `onDispose` runs on a composition thread while its subscription scope uses
`Dispatchers.IO`. That argument fails for a reason stated above: `onStop` is a caller-supplied suspend
lambda, so whichever dispatcher it reaches is not one `rememberScpHotStream` controls, and a
composition thread on Android is a main thread, where blocking risks an ANR regardless.

That comment also named a real constraint: launching `onStop` on whichever scope disposal then
cancels races cancellation against `onStop`, and `onStop` may never run. A second scope settles
both — disposal launches `onStop` on a scope it never cancels, then cancels its subscription scope
and returns. `rememberScpContext`'s KDoc example teaches callers that same shape, because that
example previously showed `runBlocking(Dispatchers.IO) { bridge.context.leave(...) }` inside a
disposal callback.

## No exception for `AutoCloseable`

`Relay.close()` and `Node.close()` in `bindings/kotlin/scp-kt/src/main/kotlin/works/limn/scp/Server.kt`
called `runBlocking(Dispatchers.Default) { shutdown() }`, and `shutdown()` routes through
`CoroutineBridge.ffiCall`, which suspends on an injected `ioDispatcher`. That structure matches
`onCleared()`'s deadlock exactly.

An earlier revision kept both and documented a caveat above them, reasoning that
`AutoCloseable.close()` is a synchronous contract a caller opts into for `use {}`. That reasoning
does not survive two facts. Nothing in this repository ever called either `close()` — no test, no
example, no SDK code — so no caller opted into anything. And a rule that a type may break whenever
an interface asks it to is not a rule; `AutoCloseable` is a choice this SDK makes, not a constraint
imposed on it.

Both types dropped `AutoCloseable`, leaving one suspending `shutdown()` as one canonical stop path,
which is also what agent-first API design asks for. A bounded wait was weighed and rejected: it
still blocks a calling thread, and blocking an Android main thread up to a timeout produces an ANR,
so it trades a deadlock for an ANR rather than removing a blocking wait.

`ServerTest.neither Relay nor Node implements AutoCloseable` fails if that interface returns.
`ServerTest.every stop method on Relay and Node suspends` matches on a trailing
`kotlin.coroutines.Continuation` parameter, so a non-suspending stop method fails it under any name
— `close`, `stop`, or `dispose`.

## Affected files

- `bindings/kotlin/scp-kt-android/src/main/kotlin/works/limn/scp/android/ScpViewModel.kt`
- `bindings/kotlin/scp-kt-android/src/test/kotlin/works/limn/scp/android/ScpViewModelTest.kt`
- `bindings/kotlin/scp-kt-android/src/main/kotlin/works/limn/scp/android/compose/StateHolders.kt`
- `bindings/kotlin/scp-kt-android/src/test/kotlin/works/limn/scp/android/compose/StateHoldersTest.kt`
- `bindings/kotlin/scp-kt/src/main/kotlin/works/limn/scp/Server.kt`
