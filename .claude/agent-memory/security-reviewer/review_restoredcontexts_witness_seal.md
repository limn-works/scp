---
name: review-restoredcontexts-witness-seal
description: Security audit of RestoredContexts §17.16.4 ordering-witness seal + saga-witness-test-mint feature gating + with_providers_and_journal pub (commit d4f7a7aea, branch feat/2c-saga-dispatch)
metadata:
  type: project
---

# RestoredContexts witness seal — CLEAN (commit d4f7a7aea)

Worktree saga-2c, branch feat/2c-saga-dispatch. Hardens the §17.16.4 restore-then-replay
ordering witness `RestoredContexts` (scp-runtime supervisor.rs). VERDICT: clean all 4 categories.

**Why:** §17.16.4 crash-recovery exactly-once economic refund depends on restore-before-replay
ordering being unforgeable. The witness is a capability token: `replay_unresolved_sagas(&RestoredContexts)`
requires a witness, and only a real `restore_all_contexts` (supervisor.rs:8025-8027) mints one via
module-private `RestoredContexts::new`. A forge = bypass restore = replay against non-resident actors.

**How to apply (verified facts, re-check if revisited):**
- Seal is sound: `#[derive(Debug)]` only (no Default/Clone), private `ids` field, module-private `const fn new`.
  Construction sites (grep `RestoredContexts::new|::for_test|{ ids`): new ONLY at supervisor.rs:8027 (prod restore)
  + 2 in-module unit tests; for_test ONLY in the two actor_saga_* test crates. No external forge.
- 3 compile_fail doctests on replay_unresolved_sagas (supervisor.rs ~5561/5575/5588) PASS: reorder (no token),
  E0599 Default::default(), E0451 private-field literal. RAN: `cargo test -p scp-runtime --doc ... replay_unresolved_sagas` = 3 ok.
- for_test re-gated `testing` → NEW dedicated `saga-witness-test-mint` cargo feature. VERIFIED feature graph:
  `cargo tree -p scp-ffi --features allow_in_memory_custody -e features` activates scp-runtime {default,
  allow_unencrypted_storage, testing} — NOT saga-witness-test-mint. So for_test is #[cfg]-compiled-OUT of the
  FFI/allow_in_memory_custody build. grep confirms feature referenced ONLY in scp-runtime/Cargo.toml (def +
  2 test-target required-features), zero [dependencies]/implication edges. `cargo build -p scp-ffi --features
  allow_in_memory_custody --lib` = clean.
- Fail-closed (#2): restore_on_startup (supervisor.rs:8074-8085) calls restore_all_contexts().await? BEFORE
  replay — restore error short-circuits, unresolved sagas carried to next start. Live test
  `restore_on_startup_fails_closed_when_restore_leg_errors` = ok.
- with_providers_and_journal pub→pub (#3): NO new risk. Supervisor::new is ALREADY pub (supervisor.rs:1220)
  and ALREADY takes arbitrary Arc<dyn SagaJournal> (:1222). Journal is the supervisor's own durable store
  supplied at construction by the instantiating bridge; no cross-context/tenant boundary crossed. Whoever can
  call this already constructs the whole supervisor.
- CI edits (#4): saga-witness-test-mint added ONLY to cargo test/clippy/doc invocations (ci.yml lint+nextest+doc,
  release.yml "Run all workspace tests" :94, build-matrix.yml "Run tests" :86, docs.yml). Artifact-producing
  steps are SEPARATE and flag-free: build-matrix.yml "Build all crates" (:80-81, `cargo build --release` no
  features) feeds the upload (:88-97); XCFramework/wheel/npm release jobs never reference the flag or
  allow_in_memory_custody. No test constructor ships in a release artifact. The pipeline_wiring.rs gate
  doc-comment downgrade MUST→best-effort is a NET STRENGTHENING (assertions preserved + new behavioral
  both-legs test bridge_restore_entry_runs_restore_and_replay_legs as real enforcement; RAN = ok).
- Broadcast signing (#5): NO logic touched. crypto/mls/provider.rs change is doc-comment only
  (ContextManager→Supervisor rename, ×6 across commands.rs/event_log.rs/state.rs/provider.rs/persistence.rs).
  New test's persist/load_broadcast are no-op Ok stubs; KeyResolver returns None (harness). No new error codes.
- Test dedup via stage_xctx_preparing_b_crash is assertion-preserving (refund-to-burst_milli + terminal-Aborted
  both retained). Both refactored tests RAN = ok.
