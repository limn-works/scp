---
name: ctxmig-saga-code-cut-final-review
description: Final CODE-cut review of cross-identity custody-handover saga (spec #1793 §4 withdrawal) — branch chore/cut-context-migration-saga HEAD d25e4419d — ALIGNED + 1 LOW stale test name
metadata:
  type: project
---

Final alignment review of the cross-identity custody-handover code-layer cut. Branch `chore/cut-context-migration-saga`, base `origin/main` c25c78608, HEAD d25e4419d. 4 files in `crates/scp-runtime/src/context/supervisor/` (+87/-243): mod.rs, saga_journal.rs, saga_prepared_state.rs, supervisor.rs.

VERDICT: ALIGNED + 1 LOW (stale test name).

**Why:** Downstream code-correctness completion of spec PR #1793 §4 withdrawal (Gap-4 RESOLVED-AS-WITHDRAWN). The DEFERRED ADR (`.docs/adrs/DEFERRED-commit-11-saga-use-cases.md:133`) explicitly names this PR: "`SagaInput::ContextMigration` / `ContextMigrationPrepared` are slated for deletion in a separate code-correctness PR." Artifact-flow honored — spec withdrew first, code follows.

**How to apply / what was verified:**
1. No over-cut: state.rs + governance_helpers.rs BYTE-IDENTICAL to main (0 diff lines). §5.11A ProposeContextMigration (governance_helpers.rs 2366/3227/3304/3504) + ContextEvent::ContextMigration{Proposed/Started/Cancelled} (state.rs 1360-62, membership.rs 620/636/646) + GovernanceCommand::MigrationState/TombstoneMigratedContext + ContextState::MigratingOut state machine (state_machine.rs §5.11A) ALL SURVIVE. The diff `--name-only` regex `state\.rs` only matches `saga_prepared_state.rs` — DON'T confuse it for state.rs.
2. §9.4.3 apparatus KEPT: saga_journal.rs mark_resolved(secret_bearing) + EvidenceWire + Zeroizing evidence + 2 tests (mark_resolved_secret_bearing_zeroes_evidence_bytes, _non_secret_leaves_prior_intact) intact. Classifier saga_input_is_secret_bearing DEFINED :6904 + CALLED :4382 — EXHAUSTIVE match, NO wildcard (all 3 variants listed → false) so a 4th variant = compile error.
3. Prose scrub: zero "spec-gapped" in source; zero stale "4 saga"/"fifth saga" counts (one "4 FFI bridges" at :5042 is unrelated); surviving "migration" hits are all DISTINCT senses — actor-refactor "handler migrates to actor model"/"migration shim/window", OR §5.11A governance MigrationState/MigratingOut. None is migration-as-live-saga.
4. New recovery-path doc note ACCURATE: recover_saga_entry (:4435) hardcodes `/*secret_bearing=*/ false` at :4446 + :4466 because replayed JournalEntry carries no SagaInput. Note correctly says a future secret-bearing saga must re-derive classification there.
5. Spec citations §5.15.8 (standing-pair) / §6.2.4 (xctx-tool-invoke heading) / §5.14.13 (broadcast-hosting) all EXIST and match their saga types. SagaInput now has exactly 3 variants.
6. No external consumer of deleted symbols anywhere in crates/ or bindings/. clippy -p scp-runtime -D warnings CLEAN; 16 lib saga tests PASS.

**LOW finding (the only one):** test fn name `start_saga_returns_not_implemented_for_spec_gapped_input` (supervisor.rs:7339) still embeds the abandoned "spec_gapped" framing. The diff updated this test's BODY comment to "All 3 current SagaInput variants are not yet wired" and scrubbed every doc-comment, but left the function identifier. Mechanical rename (→ `..._not_yet_wired_input` or `..._unwired_input`) finishes the scrub claim (3) asks for. Not a correctness issue; test passes.

LESSON: a "spec-gapped → unwired" terminology migration must also scrub TEST FUNCTION NAMES, not just doc-comments and body comments. grep the abandoned term across the whole module including `fn` identifiers — a passing test with a stale name is the last straggler. Builds on prior [[ctxmig_saga_code_cut_review]] (which caught the saga_journal.rs prose straggler at an earlier HEAD).
