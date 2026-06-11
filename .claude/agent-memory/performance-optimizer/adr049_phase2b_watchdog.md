# ADR-049 Phase 2B — Actor Watchdog/Respawn/Poison Perf Profile

File: crates/scp-runtime/src/context/supervisor/supervisor.rs (HEAD c17331886, branch agent-a80ace23c18c8ed03)

## Verdict: performance ACCEPTABLE. No hot-path regression.

## Per-actor overhead (2N tasks)
- Each context: actor task + watchdog task. Watchdog body = single `join.await` (supervisor.rs ~389). Parked future, no timer/poll/busy-wait. Idle cost ≈ one tokio task slot + one strong Arc<Supervisor> refcount. Acceptable.
- Watchdog is NOT on the supervisor `task_set` JoinSet (owns its JoinHandle directly) — by design.
- Per-message hot path (send/receive/query): UNCHANGED. lookup = DashMap::get (lock-free), dispatch_via_mailbox unchanged. Watchdog is purely out-of-band, only runs after join resolves (actor exit/crash).

## crash_windows DashMap
- Read on hot path? NO. Only touched in actor_watchdog (crash path) + lookup_miss_error (only on a lookup MISS, i.e. error path, not steady state). is_context_poisoned = single DashMap::get.
- Growth: entries created lazily on FIRST crash (entry().or_default()). Healthy contexts never get an entry. Entry is NOT removed on clean shutdown/despawn → a context that crashed >=1 time then was cleanly removed leaves a stale CrashWindow entry. Bounded per-entry (VecDeque cap = CRASH_DEQUE_CAP = 3) but the MAP itself has no eviction for non-poisoned crashed-then-gone contexts. LOW severity: entry is tiny (~few u64 + bool), only for contexts that actually crashed. Worth noting for very-long-lived process with churn of crash-prone short-lived contexts.
- Per-CrashWindow VecDeque: bounded at CRASH_DEQUE_CAP (=CRASH_POISON_THRESHOLD=3) defensively, plus sliding-window eviction. Confirmed O(1) space even under stuck/non-monotonic clock (clock_ref None => now_ms=0 always; deque cap defends).

## Respawn cost
- restore_context reloads+decrypts snapshot, rebuilds full PerContextState. Bounded by crash budget: 3 respawns/60s then poison (CRASH_POISON_THRESHOLD). Non-amplifying: a failed respawn is itself recorded as a crash (record_failure) so a snapshot that panics the loader poisons after budget instead of looping. No exponential fan-out.
- NO block_on / block_in_place in watchdog or respawn_from_snapshot — all async. (block_in_place only in shutdown_all_contexts_sync, the FFI sync boundary, pre-existing, §7 allowlisted.)
- build_actor_deps = all Arc::clone (cheap) + one key_package_store_for await. No deep copies.

## Lock/await discipline
- crash_windows entry guard: explicitly copied out into (poisoned,count) in a block, dropped before any .await (await_holding_lock denied workspace-wide). record_failure closure drops its entry guard before the `if .. { despawn.await }`.
- despawn_actor: takes write_lock.lock().await, then actors.remove (DashMap, sync) — NO await held under write_lock. Respawn calls despawn_actor (acquires write_lock) same as normal lifecycle ops (import_context) — no NEW contention class, same single global write_lock serialization for registry mutations (rare path).

## Task-leak / cleanup
- Clean shutdown (shutdown_all_contexts, lifecycle_helpers.rs:2310): ShutdownSelf then despawn_actor drops last mpsc::Sender → inbox closes → actor run() exits None arm → join.await returns Ok(()) → watchdog returns. Self-reaping. NO leak.
- Cancellation/abort (!is_panic): watchdog treats as clean, returns. No leak.
- REFERENCE CYCLE (pre-existing pattern, watchdog deepens it): actor ActorDeps holds SupervisorHandle{Arc<Supervisor>} AND watchdog holds Arc<Supervisor>. Supervisor cannot drop while any actor/watchdog parked. Broken only by explicit shutdown_all_contexts. If supervisor Arc dropped WITHOUT shutdown, actors+watchdogs keep it (and themselves) alive = leak. This is the existing actor-model teardown contract; watchdog adds 1 more strong ref per context but same contract. Acceptable given FFI BridgeInstance::shutdown calls shutdown_all_contexts_sync.

## Tests prove: deque cap, sticky poison, failed-respawn-counts-as-crash, clean-shutdown-not-crash (no crash_windows entry), payload redaction.
