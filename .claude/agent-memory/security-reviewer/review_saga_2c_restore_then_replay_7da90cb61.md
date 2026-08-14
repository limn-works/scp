---
name: review-saga-2c-restore-then-replay-7da90cb61
description: Security audit of saga-2c restore-then-replay crash-recovery feature (branch feat/2c-saga-dispatch, HEAD 7da90cb61) — CLEAN, no findings, all 4 categories
metadata:
  type: project
---

Audited whole feature `git diff origin/main...7da90cb61` (merge-base 8a76b7089) on worktree saga-2c. Final commit = doc fixes + `Supervisor::restore_all_contexts` pub→pub(crate) seal. SECURITY-CLEAN, ZERO findings (Injection/Auth/Secrets/Leakage).

**Why:** §17.16.4 restore-then-replay crash recovery; exactly-once economic integrity is the security-critical surface (a wrong terminal-Aborted marker = permanent caller over-charge or stranded refund).

**How to apply:** if this branch reopens, these invariants are verified-sound at 7da90cb61 — re-check only if the named functions change.

VERIFIED LIVE (all gates/tests run green w/ DYLD_LIBRARY_PATH):
1. Witness topology: `RestoredContexts` sealed (private `ids`, no Default/Clone, module-private `new`). `for_test` gated behind `saga-witness-test-mint` (empty feature `[]`, NOT implied by `testing`, enabled ONLY by required-features of actor_saga_coordinator/actor_saga_crash_recovery targets). grep confirms zero dependency-feature activation anywhere; only fuzz enables scp-runtime/testing (standalone, testing≠mint). `cargo build -p scp-runtime` (no feature) compiles → for_test physically unreachable in prod/allow_in_memory_custody. 3 compile_fail doctests pass (no-witness / Default-forge / struct-literal-forge).
2. Exactly-once + fail-closed: reaper `caller_context_deleted_from_persistence` (supervisor.rs:6106) reaps ONLY on `Ok(None)` (confirmed absence); `Err`→false (transient≠deletion), `Ok(Some)`→false. Unit-pinned by `caller_context_deleted_predicate_reaps_only_on_confirmed_absence`. `recover_preparing_b_entry` (5779) writes terminal-Aborted only when reversal SettledOrAbsent OR caller confirmed-deleted; else leaves PreparingB non-terminal for next start (no over-charge). `restore_on_startup` (8088): restore THEN replay; restore-error short-circuits before replay (fail-closed, pinned by restore_on_startup_fails_closed_when_restore_leg_errors). Ordering type-enforced (replay needs &RestoredContexts witness only restore mints).
3. pub(crate) seal no-regression: all 3 FFI bridges (PyO3 context.rs / NAPI context.rs / UniFFI bridge.rs) + CoreFields::restore_all_persisted_contexts route through restore_on_startup. grep: zero remaining cross-crate `.restore_all_contexts()` on a Supervisor. WASM `mgr.restore_all_contexts()` is the ADR-034 re-impl ContextManager (ephemeral, no saga journal), NOT the narrowed Supervisor method — unaffected. persistence_sdk.rs test redirected to restore_on_startup (NoopSagaJournal replay = no-op, restore semantics preserved). bridge_resume_path_routes_through_restore_on_startup + restore_on_startup_runs_restore_before_replay gates pass.
4. Auth/secrets/leakage: hosting_handshake.rs (scp-protocol, §5.14.13, in scope) signing sound — verify_strict (anti-malleable), domain-sep BCAST-HOST-REQ/GRANT-V1 distinct, all fields length-prefixed-bound (nonce/timestamp incl), signer-auth requires caller-resolved key (no self-asserted key trust). Error enum BroadcastHostingError embeds only dalek/serde lib strings — no key material/paths/PII. Error codes SCP-SAGA-13100..13102 registered; check-error-codes.sh PASS. No hardcoded secrets in diff (added-line scan clean). clippy touched crates clean.
