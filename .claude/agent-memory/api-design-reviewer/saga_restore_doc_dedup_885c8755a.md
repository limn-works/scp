---
name: saga-restore-doc-dedup-885c8755a
description: APPROVED doc-only review of commit 885c8755a (saga restore-then-replay comment de-dup); verified contract accuracy
metadata:
  type: project
---

Commit 885c8755a (worktree saga-2c, branch atop a0db45b0a) — APPROVED. Comment/markdown-only: de-dup the pub(crate)/E0624 gate rationale in pipeline_wiring.rs, split ADR-049 §A into mechanism+caveat clauses, trim a redundant trailing phrase on supervisor.rs with_providers_and_journal doc. No API surface / visibility / assertion / logic changed.

**Why:** continuation of [[saga_restore_doc_sweep_a0db45b0a]] doc-alignment work for the pub(crate) restore-leg seal.

**How to apply:** verified contract facts (still true as of this commit) —
- `Supervisor::restore_on_startup` = pub public cross-crate entry (supervisor.rs:8088), returns `Result<Vec<String>>`.
- `Supervisor::restore_all_contexts` = pub(crate) (supervisor.rs:8037), SOLE minter of `RestoredContexts` witness.
- GOTCHA: a SECOND same-name `pub` free fn `restore_all_contexts` exists in lifecycle_helpers.rs:2743 but returns `Vec<String>` (no witness) — NOT a cross-crate ordering bypass. Don't false-flag the name collision.
- `replay_unresolved_sagas` (supervisor.rs:5613) is witness-gated; backed by 3 compile_fail doctests (E0451 private field / no Default / no struct-literal forge).
- `with_providers` hardcodes NoopSagaJournal (supervisor.rs:1354); `with_providers_and_journal` (1410) takes caller-supplied journal — saga crash-recovery inert in prod until bridges switch.
- Referenced tests all exist: bridge_restore_entry_runs_restore_and_replay_legs (saga_bridge_bootstrap.rs:206), bridge_resume_path_routes_through_restore_on_startup (pipeline_wiring.rs:933).
- Framing is correct: pub(crate)/E0624 seal = IN-CRATE defense-in-depth; type-system witness + behavioral bootstrap test = the REAL enforcement (consistent with ADR-052 "invariant uncompilable not gated" pattern).
