# Lesson: a hot stream subscription needs one owner, across cancellation and across a re-mount

## Context

`HotStreamFactory`
(`bindings/kotlin/scp-kt/src/main/kotlin/works/limn/scp/stream/Streams.kt`) opens a Rust
subscription and records its handle in a `ConcurrentHashMap` keyed by context handle. That map is
a caller's only route back to a live subscription: `stopContextEvents`, `stopMessageStream`, and
`stopAll` read it to decide what to unsubscribe.

`rememberScpHotStream`
(`bindings/kotlin/scp-kt-android/src/main/kotlin/works/limn/scp/android/compose/StateHolders.kt`)
starts one such subscription when a composable enters composition, and stops it when that
composable leaves.

Three defects shared one root: no code tied a subscription's lifetime to whichever caller owned
it, so a subscription could outlive every reference naming it, or a stop could release a
subscription that a different caller had just opened.

1. `contextEvents` called `contextSubscribeEvents` inside `withContext(ioDispatcher)` and wrote
   its registry entry on a following line. Cancellation arriving while that FFI call ran surfaces
   on that `withContext`'s resumption, which skipped that write. A Rust subscription and its
   callback then stayed live with no registry entry naming them, so neither `stopContextEvents`
   nor `stopAll` could release either one. `incomingMessages` carried an identical window.
2. `contextEvents` and `incomingMessages` took a `Mutex` and removal paths took none, so a stop
   that ran while a subscribe held that mutex read an empty registry, returned, and left a
   subscription that same subscribe registered a moment later. A caller who called
   `stopContextEvents` observed a return with no error and kept a live subscription.
3. A composable that left composition and re-entered it under one same `key` got fresh
   `remember(key)` values, so nothing ordered a first mount's `onStop` against a second mount's
   `start`. A stale `stopContextEvents(handle)` landing after that second start removed whatever
   entry a registry held, which was that second mount's entry, and unsubscribed it. That caller
   collected a `SharedFlow` that received nothing further and reported no error, so membership
   changes and revocations stopped arriving. Navigating away from a screen and back produced it.

## Decision

- **Pair a subscribe call with its registry write under `NonCancellable`.** Both
  `HotStreamFactory.contextEvents` and `HotStreamFactory.incomingMessages` run
  `withContext(NonCancellable + ioDispatcher) { subscribe(); slot.register(...) }`. That scope
  covers those two statements and no others, so a cancelled caller still observes cancellation
  and still leaves a releasable subscription behind. Removal paths pair their registry removal
  with their unsubscribe call in that same shape.
- **Take a registry's mutex on every path that writes that registry.** `stopContextEvents` takes
  `eventMutex` and `stopMessageStream` takes `messageMutex`. `stopAll` takes each mutex once and
  calls private helpers under it, because taking one non-reentrant `Mutex` twice on one coroutine
  deadlocks that coroutine.
- **Give a completion callback conditional removal instead of a lock.** A Rust callback thread
  runs `onComplete` outside any coroutine, so that thread cannot take a `Mutex`. `SubscriptionSlot`
  calls `ConcurrentHashMap.remove(key, value)`, which deletes an entry only when that entry is
  that callback's own `HotStreamState`. A stale completion callback therefore never deletes a
  later subscription carrying one same context handle.
- **Hold cross-mount ordering state outside composition.** `ScpHotStreamCoordinator` holds one
  `Mutex` and one most-recent stop `Job` per key. `rememberScpHotStream` takes a coordinator as a
  required parameter with no default: `launchStop` records a stop's `Job` before `onDispose`
  returns, and `startAfterPendingStop` joins that job before it runs a `start` lambda.

## Why a coordinator rather than a file-scope registry

`CLAUDE.md` states "Inject every dependency through an initializer. Never reach for a singleton",
and `scripts/check-no-kotlin-mutable-globals.sh` states that this SDK holds no implicit
per-process mutable state. An `object` singleton in `StateHolders.kt` would carry that state
across mounts and would also carry it across every unrelated caller in one process, so a caller
constructs a coordinator, owns its scope, and decides when to cancel it.

A default parameter that built a coordinator per composition would compile, read as convenient,
and restore defect 3 exactly, because each mount would then coordinate against itself alone.

## How to detect a recurrence

- `StreamsTest.SubscriptionOwnershipTests` cancels a subscribing coroutine from inside a stub's
  subscribe call, and asserts that `stopAll` unsubscribes what that call opened.
- Two tests in that same class gate a subscribe call open on a latch, launch a stop, and assert
  that stop stays suspended while that subscribe holds its mutex.
- `ScpHotStreamRemountTest` in
  `bindings/kotlin/scp-kt-android/src/test/kotlin/works/limn/scp/android/compose/StateHoldersTest.kt`
  drives one composable out of composition and back under one same key against a fake registry,
  and asserts that a subscription live at test end is one a second mount opened.

## Anti-patterns

- Writing a registry entry after a cancellable suspension point that opened whatever that entry
  names. Cancellation lands between those two statements.
- Reading a registry outside whichever mutex guards writes to it, and treating an absent entry as
  proof that nothing is live.
- Keeping cross-mount coordination state in `remember(key)`. Compose forgets it at exactly one
  moment when two mounts need it.
