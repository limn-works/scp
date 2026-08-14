---
name: feedback-spin-yield-invalid-on-multi-thread-tests
description: A bare `for _ in 0..N { yield_now().await }` test wait is only valid on a current-thread runtime; on multi_thread it flakes under CPU load. Bound the wait by std::time::Instant instead.
metadata:
  type: feedback
---

A test helper that waits by spinning `tokio::task::yield_now().await` a fixed
number of times is only a valid wait on a **current-thread** runtime, where
yielding necessarily hands the single worker to the task being waited on.

**Why:** on `#[tokio::test(flavor = "multi_thread")]` the awaited task may be on
another worker. The loop then burns its whole iteration budget in microseconds
without that worker having been scheduled at all. In this repo
(`crates/scp-node/src/self_host.rs`, `settle_until`) a 2000-iteration budget
passed 6/6 in isolation and failed 2/2 during a full-workspace `cargo nextest run`,
because every core was saturated by other test processes. The failure looks like a
logic regression ("timed out waiting for the initial DHT arm to publish") and
costs a long detour to diagnose.

**How to apply:** bound such helpers by wall clock, not iterations:

```rust
let deadline = std::time::Instant::now() + Duration::from_secs(30);
loop {
    if cond().await { return; }
    assert!(std::time::Instant::now() < deadline, "timed out waiting for {label}");
    tokio::task::yield_now().await;
}
```

`std::time::Instant` is the REAL clock and is unaffected by
`#[tokio::test(start_paused = true)]`, so one deadline is correct for paused
current-thread tests and multi-thread ones alike. Do NOT reach for
`tokio::time::sleep` in a shared helper: under `start_paused` it auto-advances the
paused clock when all tasks are idle, which fires unrelated long timers (republish
cycles, TTLs) and perturbs the tests it is meant to serve.

A generous budget costs nothing on the happy path — it is only spent when the test
is going to fail anyway.
