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

Four defects shared one root: no code tied a subscription's lifetime to whichever caller owned
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
4. Two mounts under one `key` composed at the same time — a navigation transition keeps an
   outgoing screen composed while an incoming screen starts — share one subscription, because
   `contextEvents` hands a second caller the entry it already holds. Ordering a stop before a
   later start does nothing here: the first mount to leave ran `stopContextEvents(handle)` and
   released the subscription the second mount was still collecting, with the same silent result.

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
- **Hold cross-mount ownership state outside composition.** `ScpHotStreamCoordinator` holds a
  live-mount count, one `Mutex`, the `onStop` lambdas of mounts that left early, and one
  most-recent stop `Job` per key. `rememberScpHotStream` takes a coordinator as a required
  parameter with no default. `mount` counts a mount when its effect applies and captures the
  pending stop; `unmount` holds a departing mount's `onStop` while another mount under that key
  is live, and when it removes the last live mount it launches one stop that runs every held
  `onStop` and its own, and records that stop's `Job` before `onDispose` returns;
  `startMounted` joins the captured stop before it runs a `start` lambda. Each launched stop joins
  the stop launched before it under that key before it takes that key's mutex, because a mount
  captures only the newest stop, and an older stop that reached its dispatcher last would
  otherwise release whatever that mount's start opened. For a departure it holds, `unmount`
  returns a `Job` that the next launched stop completes, so a mount that moves to another
  coordinator while a second mount under that key stays on the first one starts only after the
  first coordinator releases the subscription both mounts shared. `rememberScpHotStream` keeps
  every such `Job` that has not completed, each paired with the coordinator that returned it,
  across any number of coordinator changes, and a start joins every one a different coordinator
  returned. A mount that waits on another coordinator's Job is counted on its new coordinator
  only once that wait ends: counted while waiting, it made its new coordinator hold the `onStop`
  of a mount moving the other way, and two crosswise moves then each waited on a Job only the
  other's departure completed.
- **Run one `onStop` per subscription a started mount opened.** `startMounted` and `unmount`
  race to claim a mount with one compare-and-set; when `unmount` wins, that mount's `start`
  never runs and its `onStop` is dropped, because it opened nothing and a mount still live on a
  replaced coordinator may collect the subscription that `onStop` would release. A held
  departure whose `start` returned the same object as an earlier held one's (compared by
  identity; `HotStreamFactory` hands every caller of one subscription one `SharedFlow`) adds
  nothing to the held list, so that list stays bounded by the number of distinct subscriptions
  under the key, not by how many list rows scrolled past a long-lived mount. A `start` that
  began runs to completion under `NonCancellable` even when its mount leaves meanwhile: a start
  that disposal cancelled returned nothing to compare, so each row that left while its start
  waited on `HotStreamFactory`'s mutex kept one more `onStop` for good. A mount whose `start`
  threw keeps its `onStop`, because that start may have opened what it did not return, so the
  bound adds one entry per start that threw and one for the start running under the key's
  mutex. Discarding an early
  mount's `onStop` whose `start` returned a different object instead leaks a subscription
  whenever two different streams share a key, such as a `contextEvents` and an
  `incomingMessages` stream both keyed by one context handle.
- **Refuse a start and report a skipped stop once the coordinator's scope is cancelled.** A stop
  launched on a cancelled scope never runs its body, so the coordinator logs every stop that
  cancellation kept from running its `onStop` lambdas, completes a held departure's Job
  exceptionally instead of reporting that its `onStop` ran, and refuses every later `start` with
  `ScpHotStreamCoordinatorClosedException`, because no stop could release what it opened.

## Why a coordinator rather than a file-scope registry

`AGENTS.md` states "inject dependencies through initializers, never use a singleton",
and `scripts/check-no-kotlin-mutable-globals.sh` states that this SDK holds no implicit
per-process mutable state. An `object` singleton in `StateHolders.kt` would carry that state
across mounts and would also carry it across every unrelated caller in one process, so a caller
constructs a coordinator, owns its scope, and cancels it only once every mount that passed
that coordinator has left composition.

A default parameter that built a coordinator per composition would compile, read as convenient,
and restore defect 3 exactly, because each mount would then coordinate against itself alone.

A coordinator must have the same lifetime and sharing as the registry whose subscriptions it
orders: one per `HotStreamFactory`, held by an application container, a dependency-graph
singleton, or a ViewModel that every navigation destination reading that factory shares. A
ViewModel scoped to one navigation destination restores defect 4, because two destinations that
show one context handle during a transition each count only their own mounts.

## How to detect a recurrence

- `StreamsTest.SubscriptionOwnershipTests` cancels a subscribing coroutine from inside a stub's
  subscribe call, and asserts that `stopAll` unsubscribes what that call opened.
- Two tests in that same class gate a subscribe call open on a latch, launch a stop, and assert
  that stop stays suspended while that subscribe holds its mutex.
- `ScpHotStreamRemountTest` in
  `bindings/kotlin/scp-kt-android/src/test/kotlin/works/limn/scp/android/compose/StateHoldersTest.kt`
  drives one composable out of composition and back under one same key against a fake registry,
  and asserts that a subscription live at test end is one a second mount opened. A second test
  there composes two mounts under one key at once, removes one, and asserts that no `onStop` ran
  and that their shared subscription is still live. `a stop runs after every stop launched before
  it under that key` launches two stops on a dispatcher that runs its queued tasks newest first,
  and asserts that the earlier stop completes before the later one and that the second mount,
  which leaves before its `start` runs, has no `onStop` run for it, and `a coordinator swap next to a
  live mount starts only after the old coordinator stops the key` asserts that a moved mount
  opens a fresh subscription only after its old coordinator released the shared one. `two
  coordinator changes under one key start only after the first swapped-out stop` holds the first
  swapped-out `onStop` on a latch across a second change, `a moved mount that leaves before it
  starts releases nothing a live mount collects` removes a moved mount while its old coordinator
  still holds its `onStop`, and `a mount that moves away and back next to a live mount starts
  again and releases nothing` returns a moved mount to its first coordinator; each asserts which
  subscription stays live. `crosswise coordinator moves under one key do not wait on each other`
  moves two mounts in opposite directions and asserts that the second one starts.
  `departures beside a live mount hold one onStop per subscription` churns a hundred mounts
  past a live one and asserts the held list's size, `departures while their start is suspended
  hold one onStop per subscription` cancels each departing row's start while it is suspended and
  asserts the same bound, and `a cancelled coordinator scope logs its
  skipped onStop and refuses later starts` asserts the log line, the exceptional Job, and the
  refused start.

## Anti-patterns

- Writing a registry entry after a cancellable suspension point that opened whatever that entry
  names. Cancellation lands between those two statements.
- Reading a registry outside whichever mutex guards writes to it, and treating an absent entry as
  proof that nothing is live.
- Keeping cross-mount coordination state in `remember(key)`. Compose forgets it at exactly one
  moment when two mounts need it.
