---
name: sup113-supervisor-docscrub-81d36e1ab
description: Review of chore/113 supervisor.rs doc-scrub (future-tense/stub comments → present tense) vs ADR-049 actor-per-context; HEAD 81d36e1ab, diff e7cb66da8..HEAD
metadata:
  type: project
---

# sup-113 supervisor.rs doc-scrub review (2026-06-30) — ALIGNED w/ 1 LOW-MED finding

Worktree `/Users/alec/Developer/limn/scp/.claude/worktrees/sup-113`, branch `chore/113-supervisor-deadcode-docscrub`, HEAD `81d36e1ab`. Diff `e7cb66da8..HEAD` = 2 files, +23/-65: reworded stale future-tense/"commit 6/11" doc-comments to present tense + deleted dead `persist_state` (NotImplemented stub), `PendingSagaProjection` struct, `pending_sagas` DashMap field + their test/exports.

**Why ACCURATE (verified against worktree code, not main — PATH GOTCHA: bash cwd defaults to worktree, but absolute Reads of `/Users/alec/Developer/limn/scp/crates/...` hit MAIN repo which is a different HEAD; always use the worktree absolute path):**
- Saga FSM chain `start_saga → run_saga → run_saga_fsm` CONFIRMED: start_saga@5392 calls self.run_saga; run_saga@5735 calls .run_saga_fsm; run_saga_fsm@6852.
- `send_message`@10376 reword "Dispatch is mailbox-only … lookup-miss ContextError rather than mutating supervisor state" CONFIRMED for messaging path: send_message→dispatch_command@2438 does `lookup(ctx).ok_or_else(lookup_miss_error)?` then dispatch_via_mailbox. dispatch_from_shim/take-and-swap deleted.
- "No migration stubs remain" CONFIRMED: persist_state gone; remaining `NotImplemented` returns are all `*Command::Placeholder` permanent handshake/smoke-test targets (2568, 3178, …), NOT migration stubs.
- `SupervisorConfig` reword CONFIRMED: struct is literally just `reserved: ()` `#[allow(dead_code)]`; stored as `health_config` but never read for tunables.
- Deletions don't contradict ADR-049: the `persist_state`/`pending_sagas` strings in ADR-049 are unrelated `ClassSCell::persist_state_best_effort` (Class-S fail-closed persistence), NOT a promised `Supervisor::persist_state`. No downstream artifact reconcile needed.

**FINDING (LOW-MED, fix recommended) — test comment misdescribes architecture @ supervisor.rs:11821-11823** (test `spawn_actor_registers_handle_under_write_lock`): reword says "duplicate-spawn detection is a watchdog responsibility (ADR-049 §10)." WRONG on two counts: (1) ADR-049 §10 ("Actor panic recovery") covers panic/crash detection + respawn budget + poison — it never mentions duplicate-spawn detection; the watchdog detects PANICS, not dup spawns. (2) Duplicate-spawn rejection DOES exist but lives in the production owned-state path `spawn_actor_with_state`/`spawn_actor_with_watchdog` as first-writer-wins `CreationFailed` (3880-3886, 3930-3932), tested 50 lines away as `spawn_actor_with_state_rejects_duplicate_context_id`@12169 — NOT a watchdog, NOT §10. The skeleton `spawn_actor`@3803 (what the test exercises) overwrites only because it's a test/skeleton helper. Accurate rewrite: cite skeleton-vs-owned-state + first-writer-wins in `spawn_actor_with_state`, drop the §10/watchdog attribution. (Old comment had same wrong framing but future-tense "lands in commit 11"; reword promoted it to authoritative present-tense + false §10 citation.)

**MINOR:** SupervisorConfig reword says timeouts "derived from associated constants on Supervisor" — loose: only LIFECYCLE_TIMEOUT@1449 is a true `impl Supervisor` associated const; saga PHASE_TIMEOUT@7047/7256 + CRASH_WINDOW_MS@746 are fn-local/module consts. Spirit correct (values come from code consts not the config struct).

**OBSERVATIONS (pre-existing, NOT this diff):** (a) supervisor still mid-ADR-049-Phase-2A: doc-comments reference dual-write of legacy `contexts` DashMap "during the transition window" (2461, 2548) — "No migration stubs remain" is true (no NotImplemented stubs) but migration itself isn't complete; reader could over-infer. (b) Broken intradoc links: docs reference `[crate::context::lifecycle_helpers_legacy]` (2464, 2556) but that module does NOT exist in the worktree (no file, no `mod` decl) — `cargo doc` would warn.
