# Lesson: a hot stream subscription needs one owner, across cancellation and across a re-mount

## Context

`HotStreamFactory`
(`bindings/kotlin/scp-kt/src/main/kotlin/works/limn/scp/stream/Streams.kt`) opens a Rust
subscription and records its handle in a `ConcurrentHashMap` keyed by context handle. That map is
a caller's only route back to a live subscription: `stopContextEvents`, `stopMessageStream`, and
`stopAll` read it to decide what to unsubscribe.

`rememberContextEvents` and `rememberIncomingMessages`
(`bindings/kotlin/scp-kt-android/src/main/kotlin/works/limn/scp/android/compose/StateHolders.kt`)
start one such subscription when a composable enters composition, and stop it when that
composable leaves, through the module-internal `rememberScpHotStream`.

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
  most-recent stop `Job` per key. `ScpHotStreams` constructs one coordinator together with the
  `HotStreamFactory` it orders, and `rememberScpHotStream` takes that coordinator as a required
  parameter with no default. `mount` counts a mount when its effect applies and captures the
  pending stop; `unmount` holds a departing mount's `onStop` while another mount under that key
  is live, and when it removes the last live mount it launches one stop that runs every held
  `onStop` and its own, except each whose mount's start returned the object an earlier one's
  start returned, and records that stop's `Job` before `onDispose` returns;
  `startMounted` joins the captured stop before it runs a `start` lambda. Each launched stop joins
  the stop launched before it under that key before it takes that key's mutex, because a mount
  captures only the newest stop, and an older stop that reached its dispatcher last would
  otherwise release whatever that mount's start opened. For a departure it holds, `unmount`
  returns a `Job` that the next launched stop completes, and the last departure gets that same
  `Job`. That `Job` is not the launched stop a later mount captures: it completes only after that
  stop finishes, so a test compares the two by completion order, never by identity.
- **Derive the key from the stream and the handle.** The coordinator counts and orders mounts
  per key only, while `HotStreamFactory` keys a subscription by context handle alone. A mount
  under `handle` and a mount under `"events" to handle` that both reach one `contextEvents`
  subscription are two unrelated groups, so the first to leave releases the subscription the
  other still collects (defect 4). A `key` parameter that only documented this rule compiled
  every mismatched call. `rememberContextEvents` and `rememberIncomingMessages` therefore take a
  context handle and build the key themselves, one per stream kind and handle, and
  `rememberScpHotStream`, which accepts any key, is `internal`.
- **Construct each coordinator with the one registry it orders.** Two coordinators cannot order
  each other's lambdas. When two coordinators reach one `HotStreamFactory`, the first
  coordinator's stop releases the one subscription that factory keeps under a context handle
  once that coordinator's own last mount under that key leaves, and every mount collecting that
  subscription through the second coordinator loses it (defect 4). An earlier shape made a
  moving mount's start wait for the old coordinator's stop. That wait protected the moving mount
  alone: a third mount already live on the new coordinator still lost its subscription,
  silently. A public coordinator constructed apart from its factory left that pairing to
  documentation. `ScpHotStreams` now constructs its own `HotStreamFactory` over the event
  bindings it receives, on the `ioDispatcher` it receives, together with its own coordinator,
  and exposes neither, so no second
  coordinator reaches that factory. A second `ScpHotStreams` opens its own Rust subscriptions,
  which only its own stops release.
- **Run one `onStop` per subscription a started mount opened.** `startMounted` and `unmount`
  race to claim a mount with one compare-and-set; when `unmount` wins, that mount's `start`
  never runs and its `onStop` is dropped, because it opened nothing. A held
  departure whose `start` returned the same object as an earlier held one's (compared by
  identity; `HotStreamFactory` hands every caller of one subscription one `SharedFlow`) adds
  nothing to the held list, so list rows whose start returned an existing subscription can
  scroll past a long-lived mount without growing that list. A `start` that
  began runs to completion under `NonCancellable` even when its mount leaves meanwhile: a start
  that disposal cancelled returned nothing to compare, so each row that left while its start
  waited on `HotStreamFactory`'s mutex kept one more `onStop` for good. A mount whose `start`
  threw keeps its `onStop`, because that start may have opened what it did not return. The held
  list for a key therefore holds one entry per distinct subscription, one for the start running
  under the key's mutex, and one for each departed mount whose start threw: while a long-lived
  mount stays composed, it grows by one with every row whose start threw and then left, such as
  a row over a dropped context whose subscribe keeps throwing. `rememberScpHotStream` logs that throw and leaves the mount's State null: its launch
  scope has no exception handler, so a throw escaping it reaches the thread's uncaught-exception
  handler, which on Android kills the process before the held `onStop` can run. Discarding an early
  mount's `onStop` whose `start` returned a different object instead leaks a subscription
  whenever two different streams share a key, such as a `contextEvents` and an
  `incomingMessages` stream both keyed by one context handle.
- **Refuse a start and report a skipped stop once the coordinator's scope is cancelled.** A stop
  launched on a cancelled scope never runs its body, so the coordinator logs every stop that
  cancellation kept from running its `onStop` lambdas, completes each departure's Job
  exceptionally instead of reporting that its `onStop` ran, and refuses every later `start` with
  `ScpHotStreamCoordinatorClosedException`, because no stop could release what it opened.
- **Give the owner a teardown that releases what cancellation would skip.** A stop that the last
  mount's `onDispose` launched may not have taken its key's mutex when the owner cancels the
  scope, and nothing outside `ScpHotStreams` could reach its factory's `stopAll`. The owner
  therefore calls `ScpHotStreams.close()` once every mount has left, and cancels the scope after
  it returns. `close` refuses every later `start`, waits for each running `start` and each
  launched stop, and then calls `HotStreamFactory.stopAll`, which also releases a subscription
  whose stop an earlier cancellation skipped.
- **Decide a skipped stop from the `onStop` calls that returned, not from the stop's `Job`.**
  Cancelling a coroutine while its body runs completes its `Job` as cancelled even when the body
  then returns normally. `HotStreamFactory`'s stop functions run under `NonCancellable`, so a
  scope cancelled while they run still lets every `onStop` return. The stop sets a flag after its
  last `onStop` returns, and logs a skip and fails the departures' `Job` only when that flag is
  unset and the stop held at least one `onStop`; a stop that held none skipped none.

## Why a coordinator rather than a file-scope registry

`AGENTS.md` states "inject dependencies through initializers, never use a singleton",
and `scripts/check-no-kotlin-mutable-globals.sh` states that this SDK holds no implicit
per-process mutable state. An `object` singleton in `StateHolders.kt` would carry that state
across mounts and would also carry it across every unrelated caller in one process, so a caller
constructs an `ScpHotStreams`, owns its scope, and, once every mount that passed that
`ScpHotStreams` has left composition, calls its `close()` and then cancels that scope.

A default parameter that built a coordinator per composition would compile, read as convenient,
and restore defect 3 exactly, because each mount would then coordinate against itself alone.

An application container, a dependency-graph singleton, or a ViewModel that every navigation
destination shares holds one `ScpHotStreams`, so every screen showing one context's stream
shares one Rust subscription. An `ScpHotStreams` held by a ViewModel scoped to one navigation
destination stays correct, because its factory and its coordinator are its own, but it opens a
second Rust subscription per stream beside any other instance's.

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
  which leaves before its `start` runs, has no `onStop` run for it. `a coordinator change with its
  registry under one same key opens a subscription on the new registry` changes a mount's
  coordinator and registry together while the old `onStop` is held on a latch, and asserts that
  the new registry's subscription and the returned `State` arrive before that stop runs.
  `departures beside a live mount hold one onStop per subscription` churns a hundred mounts
  past a live one and asserts the held list's size, `departures while their start is suspended
  hold one onStop per subscription` cancels each departing row's start while it is suspended and
  asserts the same bound, and `a cancelled coordinator scope logs its
  skipped onStop and refuses later starts` asserts the log line, the exceptional Job, and the
  refused start. `a scope cancelled while a non-cancellable onStop runs reports every onStop as
  run` cancels the scope while a held `onStop` suspends under `NonCancellable`, and asserts that
  both `onStop` calls ran, that neither departure's `Job` is cancelled, and that nothing is
  logged. `ScpHotStreams releases each stream when the last mount of that stream leaves` mounts
  two event streams and one message stream of one context over counting bindings, and asserts
  one Rust subscription per stream, that the message stream is released when its own mount
  leaves, and that the event stream is released only when its second mount leaves.
  `ScpHotStreams subscribes and releases on its injected dispatcher` asserts that no Rust call
  runs until an injected `StandardTestDispatcher` runs it, and that each runs on that
  dispatcher's thread. `closing ScpHotStreams releases a subscription whose stop a cancelled scope
  skipped` asserts that `close` unsubscribes what a skipped stop left open and refuses a later
  start, and `closing ScpHotStreams waits for a launched stop` asserts that `close` returns only
  after a launched `onStop` returns. `a stop that held no onStop reports no skip on a cancelled
  scope` asserts that such a stop's `Job` completes normally and logs nothing.

## Anti-patterns

- Writing a registry entry after a cancellable suspension point that opened whatever that entry
  names. Cancellation lands between those two statements.
- Reading a registry outside whichever mutex guards writes to it, and treating an absent entry as
  proof that nothing is live.
- Keeping cross-mount coordination state in `remember(key)`. Compose forgets it at exactly one
  moment when two mounts need it.
- Exposing a caller-chosen key or a coordinator constructed apart from its registry on a public
  entry point. Two screens that pass `handle` and `"events" to handle` for one subscription,
  or two coordinators over one factory, then count each screen alone, and both calls compile.
