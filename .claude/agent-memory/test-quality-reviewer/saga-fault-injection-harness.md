# §6.2.4 xctx saga fault-injection journal harness (supervisor.rs #[cfg(test)])

Branch feat/122-fault-injection-saga-journal. Two NeedsRepair pivot arms + self-heal-on-reopen.
Reviewed 2026-06-30: SHIP-quality. Mutation-verified load-bearing.

## What makes these GOOD reference tests
- Drive the LIVE two-actor FSM (spawn_xctx_pair) over the PRODUCTION ProtocolRepositorySagaJournal,
  not internal state pokes. FailingSagaJournal WRAPS the prod journal so post-fault on-disk bytes
  are exactly production's.
- Fault injection at the two real FSM write points: fallible append(NeedsRepair seq-4) on Err arm;
  one-shot mark_resolved(Committed) fault on Ok arm. Both are the genuine NeedsRepair pivots.
- Err-arm determinism: #[test] + manually-built new_current_thread().start_paused(true) runtime so the
  500ms/1s/2s commit_with_retry back-off auto-advances in VIRTUAL time (ran 0.03s, no wall clock).
  Actor msg-passing wakes via wakers not timers; 30s phase timeouts never fire (back-off total 3.5s <<
  30s and start_paused advances to EARLIEST armed timer). Sound.
- Metrics capture: metrics::with_local_recorder + DebuggingRecorder (metrics-util 0.19, dev-dep),
  THREAD-LOCAL — works because current_thread runtime keeps all tasks on the block_on thread. Avoids
  the process-global recorder poisoning across the parallel test binary. Correct pattern to replicate.

## Mutation results (I ran these, all distinguished)
- Move Err-arm `reached_needs_repair=true` to AFTER the fallible NeedsRepair append → variant-2 fails
  (got Aborted 13067). Proves variant 2 uniquely pins flag-BEFORE-append ordering.
- Delete Ok-arm `reached_needs_repair=true` in resolve_committed_or_needs_repair → Ok-arm fails (Aborted).
- Skip mark_resolved(Committed) in recover_committing_entry Committed arm → self-heal load_unresolved
  non-empty → fails. Proves the self-heal is_empty() assertion is load-bearing.

## The ONE weak assertion (low severity)
- self-heal test post-reopen `calls == 1` CANNOT fail: supervisor #1 is dropped (executor closure
  capturing the calls Arc dropped with it); recovery path (redrive_xctx_commit_in_progress →
  AlreadyCommitted, re-emits target actor's STORED output) has NO executor to invoke. So the counter
  has no live invoker post-reopen → the "never re-invoke on reopen" claim is structurally guaranteed,
  not pinned by the assertion. The Ok-arm `calls==1` (live executor on supervisor #1) IS load-bearing.
  The self-heal test's real strength is load_unresolved().is_empty().

## Correctly-scoped omission (NOT a gap)
- Live §6.2.4 outbound leg stages NO caller-side escrow (Prepare-A presents no spending UCAN; free tool).
  Harness drives with None payment adapter and does NOT assert escrow void/hold — hold-vs-void is
  trivially unobservable (every terminal voids zero escrows). Documented in-test; separate follow-up
  tracks a test-only escrow seam. Good judgment, not mis-asserted.

## Minor notes
- Err-arm aggregate metric assert (count>=1) only satisfiable by variant 1 (variant 2 faults via `?`
  BEFORE record_saga_repair_needed). Correct but the aggregate framing is slightly muddy.
- self-heal test leans on shared helper + Ok-arm test to establish the pre-reopen Committing entry;
  an explicit pre-reopen load_unresolved==Committing assert would make it self-contained (optional).
- `always: bool` added to FailContextPersistOncePersistence is clean additive; 3rd call site updated.
- No string-gaming / `let _ = fn;` dead refs. saga.rs change is doc-comment-only.
