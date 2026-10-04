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
test scheduler, which still needs the parked thread. `withTimeoutOrNull` does not rescue it either.
Inside `runBlocking(cleanupScope.coroutineContext)`, whose dispatcher was `Dispatchers.IO`, the
timeout takes its clock from `Dispatchers.IO`, which does not implement `Delay`, so it falls back to
the default wall-clock executor, and the timeout fires. Firing only cancels the pending
`withContext(ioDispatcher)` coroutine. That coroutine completes its cancellation only when its
queued task runs on the `StandardTestDispatcher`, `withTimeoutOrNull` returns only after it
completes, and only the parked thread can run that task. Every variant that blocks the caller keeps
the deadlock.

## The rule

A non-suspend method must not block its calling thread waiting on a coroutine whose dispatcher the
method does not control. Dispatch the work and return.

`onCleared()` now snapshots and clears the tracked-context list under a monitor lock, launches the
`leave` calls on a dedicated scope, and returns. It states plainly that cleanup is best-effort: the
`leave` calls run to completion only if the process outlives them. Blocking the Android main thread
on FFI calls risks an ANR, so the honest guarantee is the one worth documenting, not a stronger one
bought with a deadlock.

## Why the tests stay deterministic without a cleanup-dispatcher parameter

`ScpViewModel` has only a zero-argument constructor, because a Java subclass calls `super()`, and
it builds its cleanup scope as `CoroutineScope(SupervisorJob() + Dispatchers.Unconfined)`.
Each cleanup coroutine is launched with `CoroutineStart.UNDISPATCHED`, which starts it on the
thread that calls `onCleared()` or `trackContext`. A test gives
`CoroutineBridge` a `StandardTestDispatcher` as its `ioDispatcher`, so `advanceUntilIdle()` on the
same scheduler runs every `leave` and every resumption between them. A cleanup scope hardwired to
`Dispatchers.IO` would leave the test racing an IO thread that may not have enqueued its
continuation yet when `advanceUntilIdle()` returns.

## Make a deadlock fail instead of hang

`ScpViewModelTest` carries a class-level
`@Timeout(value = 30, unit = TimeUnit.SECONDS, threadMode = Timeout.ThreadMode.SEPARATE_THREAD)`.
`SEPARATE_THREAD` runs each method on its own thread and aborts it at the limit, so a reintroduced
block fails as one named test once that method's limit expires. The class-level limit is 30
seconds. Three methods override it with a method-level 10-second `@Timeout` of the same thread
mode: `onCleanupFailure calls from parallel cleanup coroutines never overlap`,
`an inline-bridge failure waits for a running onCleanupFailure and runs on its thread`, and
`an inline leave retried from onCleanupFailure runs before trackContext returns`. Without that annotation, a deadlocked test holds the
`kotlin-test` runner until that job's 45-minute `timeout-minutes` expires, and it surfaces as a job
timeout rather than as a named failing test.

## Do not end a cleanup scope after dispatching to it

One revision of `onCleared()` appended `cleanupJob.invokeOnCompletion { cleanupScope.cancel() }`
after dispatching, and another called `cleanupJob.complete()`. Neither frees anything: a
`SupervisorJob` whose children have all completed holds no thread, no handle, and no memory, and
`Dispatchers.Unconfined` owns no thread to shut down. Both do make every later
`cleanupScope.launch` start its child already cancelled. `launchLeave` starts that child with
`CoroutineStart.UNDISPATCHED`, which runs a coroutine's body even when its job is already
cancelled, so the child's loop still runs. Each `leave` then enters the bridge's
`withContext(ioDispatcher)`, which throws `CancellationException` on entry because the job is
cancelled, before the FFI call starts. The loop catches that exception and hands it to
`onCleanupFailure` when no other cleanup coroutine holds `cleanupFailureLock`; the default body
logs a warning. When another one holds it, `Mutex.lock` in the cancelled coroutine throws
`CancellationException` instead of waiting, because `launchLeave` calls `runCatching` inside
`withLock`, not around it, so that loop ends with no `onCleanupFailure` call, no warning, and no
`leave` for its remaining contexts. A context that `trackContext` registers after `onCleared`
therefore never gets its `leave`, and at best it produces a leave-failure warning carrying a
`CancellationException`; under a concurrent `onCleanupFailure` call it produces nothing. Android
clears a view model once, so `trackContext` itself launches that `leave` once `onCleared` has run, the way `ViewModel.addCloseable` closes a resource added after
clear. `ScpViewModelTest.a context tracked after onCleared is left without a second onCleared`
fails if either call returns.

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
both — disposal hands `onStop` to its coordinator and returns after cancelling its subscription
scope. When the departing mount is the last live mount under its key, the coordinator launches a stop
that runs `onStop` on a scope disposal never cancels; while another mount under that key stays live,
the coordinator holds `onStop` for the stop the last mount's departure launches. The coordinator's
KDoc and `.docs/lessons/kotlin/hot-stream-subscription-ownership.md` state when it drops an `onStop`.
`rememberScpContext`'s KDoc example teaches callers that same shape, because that example previously
showed `runBlocking(Dispatchers.IO) { bridge.context.leave(...) }` inside a disposal callback.

## No exception for `AutoCloseable`

`Relay.close()` and `Node.close()` in `bindings/kotlin/scp-kt/src/main/kotlin/works/limn/scp/Server.kt`
called `runBlocking(Dispatchers.Default) { shutdown() }`, and `shutdown()` routes through
`CoroutineBridge.ffiCall`, which suspends on an injected `ioDispatcher`. That structure matches
`onCleared()`'s deadlock exactly.

An earlier revision kept both and documented a caveat above them, reasoning that
`AutoCloseable.close()` is a synchronous contract a caller opts into for `use {}`. That reasoning
does not survive two facts. No test and no SDK code in this repository ever called either
`close()`; only the two types' own KDoc usage examples did, through `use { }`, and this change
rewrote them to call `shutdown()` from a coroutine under `withContext(NonCancellable)`. No caller
outside that documentation opted into anything. And a rule that a type may break whenever an
interface asks it to is not a rule; `AutoCloseable` is a choice this SDK makes, not a constraint
imposed on it.

Both types dropped `AutoCloseable`, leaving one suspending `shutdown()` as one canonical stop path,
which is also what agent-first API design asks for. A bounded wait was weighed and rejected: it
still blocks a calling thread, and blocking an Android main thread up to a timeout risks an ANR,
so it trades a deadlock for an ANR rather than removing a blocking wait.

ADR-028 in `.docs/adrs/phase-6.md` (its `AutoCloseable` rationale bullet) and
`.docs/standards/sdk-common.md` §"Kotlin: why no `Closeable`" state that rule; this lesson records
the deadlock `ScpViewModelTest` observed that drove it.

`ServerTest.no lifecycle-owning type implements AutoCloseable` fails if that interface returns to
`Relay`, `Node`, or `SCP`. `ServerTest.every stop method on a lifecycle-owning type suspends`
requires a `kotlin.coroutines.Continuation` parameter on every method `Relay`, `Node`, or `SCP`
declares under a stop name (`shutdown`, `close`, `stop`, or `dispose`, compiled overloads
included), so a non-suspending method under one of those names fails it. It reads signatures only,
so it catches no blocking call inside a method body. `ScpHotStreamsTeardownShapeTest`, in
`scp-kt-android`'s `compose/StateHoldersTest.kt`, holds `ScpHotStreams` to the same two checks.

## Affected files

- `bindings/kotlin/scp-kt-android/src/main/kotlin/works/limn/scp/android/ScpViewModel.kt`
- `bindings/kotlin/scp-kt-android/src/test/kotlin/works/limn/scp/android/ScpViewModelTest.kt`
- `bindings/kotlin/scp-kt-android/src/main/kotlin/works/limn/scp/android/compose/StateHolders.kt`
- `bindings/kotlin/scp-kt-android/src/test/kotlin/works/limn/scp/android/compose/StateHoldersTest.kt`
- `bindings/kotlin/scp-kt/src/main/kotlin/works/limn/scp/Server.kt`
- `bindings/kotlin/scp-kt/src/test/kotlin/works/limn/scp/ServerTest.kt`
