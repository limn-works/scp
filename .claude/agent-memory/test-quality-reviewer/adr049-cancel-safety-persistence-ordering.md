---
name: adr049-cancel-safety-persistence-ordering
description: ADR-049 D8/D9 mandated tests cancel_safety.rs + persistence_ordering.rs review — gating-visibility hazard + cancel_safety primitive-in-isolation ROI note
metadata:
  type: project
---

Review of the two ADR-049 Verification-block mandated integration tests (scp-runtime/tests).

**persistence_ordering.rs — SHIP, high ROI.** Drives REAL Supervisor: create_context → test_insert_member → propose_governance_action → actor dispatch → execute_suspend_member → `commit_class_s_keep` (class_s.rs:2803 = `f(view)?` then `persist_state_fail_closed(..).await.map(|()|value)`). RecordingPersistence is a real ContextPersistence impl (store=committed-only, fail=AtomicBool arm, persist_attempts counter). Case1 ack⟹durable, Case2 ¬durable⟹¬ack. Case2 non-vacuous via `attempts()>before` (proves ack path REACHED persist, not short-circuit) + Err(PersistenceFailed) not swallow + durable-unchanged. keep-direction: in-mem may retain, durable withheld, caller Err. Distinct from class_s.rs combinator unit tests (those hit ClassSCell directly; this is only public-mailbox→caller ordering coverage). Zero flake (sequential awaits, SeqCst).

**cancel_safety.rs — SHIP w/ note.** Case3 (saga context-set release on cancel) strongest: real `try_reserve_context_set` via test_reserve_saga_context_set (supervisor.rs:6035), mid-flight ActorBusy assert makes post-cancel is_ok() non-vacuous. Cases 1&2 (SequenceReservation before/after commit) are LOW–MED ROI: SequenceReservation has ONE Drop impl (sequence.rs:268) — path-identical for sync-scope/catch_unwind/async-future-drop. sequence.rs sync unit tests ALREADY cover rollback (reserve_then_drop_rolls_back:319), slot-reuse (:377), commit-stays (commit_consumes_guard:444, reserve_then_commit_advances:308). Novel dimension = "local held across await dropped on future-cancel" = std/tokio guarantee, not SCP behavior. Also NONE of 1/2/3 drive the real production send path (ContextActorHandle::send / MLS seal provider.rs:1081) — they hand-roll reserve/commit; verify the RAII primitive under cancel, not the prod handler holding the guard across the transport await. Doc honestly concedes this (lines 42-50). Recommend softening "closes that gap" prose.

**FLAKINESS — deliberately race-free.** `std::future::pending()` NEVER resolves ⇒ the timeout/sleep(25ms) branch is the ONLY completable branch ⇒ single possible winner regardless of CI load. In select! cases the async block's sync prefix (reserve/commit/overlap-assert) always runs on first poll before suspending at pending(), so Case3's overlap assert is guaranteed. 25ms = latency not correctness window. Zero flake.

**GATING HAZARD (item 5) — reusable finding.** scp-runtime `testing` is NOT a default feature. Two gating styles:
- cancel_safety: `[[test]] required-features=["testing"]` in Cargo.toml.
- persistence_ordering: `#![cfg(feature="testing")]`, NO [[test]] entry (auto-discovered).
Under the mandated `cargo test -p scp-runtime --test <name> --features testing`: BOTH run all cases, NO correctness difference. Divergence only when `testing` ABSENT (e.g. ADR Verification block writes the bare lines WITHOUT --features testing, and bare `cargo test --workspace`):
- required-features (cancel_safety) → target SKIPPED, cargo emits a note naming missing feature (visibly inert).
- self-cfg (persistence_ordering) → empty binary reports "running 0 tests … ok" (SILENT false-green; makes the ADR bare `--test persistence_ordering` line VACUOUS).
Self-cfg is strictly less discoverable. Recommend persistence_ordering ALSO get a `[[test]] required-features=["testing"]` entry (keep the #![cfg]) so feature-absent → note not silent green. Hazard shared by all ~15 required-features=["testing"] targets in the crate ⇒ CI must inject --features testing.
