---
name: ctxmig-saga-code-cut-review
description: Context-Migration saga CODE-cut review (branch chore/cut-context-migration-saga, HEAD fd7060536) — ALIGNED zero findings; code-layer completion of spec PR #1793 / DEFERRED Gap-4 RESOLVED-AS-WITHDRAWN
metadata:
  type: project
---

# Context-Migration Saga CODE-Cut Review — ALIGNED, ZERO findings (HEAD fd7060536)

**Why:** Downstream code-layer completion of spec PR #1793 / ADR-049 §4 tombstone. Cross-identity custody handover is a §5.11A.6 security violation (key material to a different DID), a category error vs the saga abstraction (1-context/2-identity, not 2+ context-actors), zero use case. DEFERRED-commit-11-saga-use-cases.md Gap-4 = RESOLVED-AS-WITHDRAWN, names this as the "separate code-correctness PR."

**How to apply:** Canonical "cut a saga, keep the forward-contract apparatus" pattern. Re-use the checklist for any saga/feature withdrawal.

## Branch / HEAD
chore/cut-context-migration-saga, on origin/main @ c25c78608, HEAD fd7060536. 4 files in crates/scp-runtime/src/context/supervisor/ (+67/-229): mod.rs, saga_journal.rs, saga_prepared_state.rs, supervisor.rs. (This HEAD closes the LOW saga_journal-prose straggler the EARLIER 3-file HEAD had.)

## What it deletes (matches spec exactly)
- SagaInput::ContextMigration variant + ContextMigrationPrepared struct + SagaPreparedState::ContextMigration arm
- Prepare dispatch arm + Commit match arm + saga_input_participants arm for ContextMigration
- 3 tests (context_migration_constructs, migration_prepared_envelope_zeroizes, migration_prepared_envelope_field_is_zeroizing_vec_u8) + ContextMigrationPrepared from types_are_send_sync
- `use zeroize::Zeroizing` import in saga_prepared_state.rs (now unused there — only doc-comment mentions remain; DID import correctly kept)
- "4 saga types" -> "3 saga types" everywhere

## VERIFIED (4 alignment-lens claims all hold)
1. **No over-cut.** state.rs + governance_helpers.rs BYTE-IDENTICAL to main (git diff = 0 lines). §5.11A ProposeContextMigration (4 refs in governance_helpers) + ContextEvent::ContextMigration{Proposed,Started,Cancelled} (state.rs:1360-1362, governance_helpers.rs:2454/2461/2569) + GovernanceCommand::MigrationState (supervisor.rs:6683) ALL SURVIVE. §5.11A member-transition governance flow — distinct from the cut custody-handover saga.
2. **§9.4.3 apparatus KEPT.** saga_journal.rs change is DOC-ONLY (mark_resolved(secret_bearing), EvidenceWire, Zeroizing<Vec<u8>> evidence, mark_resolved_secret_bearing_zeroes_evidence_bytes test all structurally intact). saga_input_is_secret_bearing RETAINED as exhaustive hook: def supervisor.rs:6898, CALLED at :4381 (`let secret_bearing = saga_input_is_secret_bearing(&input)`) — real call w/ arg, not let _=. NEW match has NO wildcard -> 4th variant = compile error.
3. **No stale live-saga prose.** Surviving migration/custody/handover hits all classify clean: supervisor.rs 127/371 = actor-refactor "handler migration to actor model"; "migration shim" (1423/1955/...) = actor-refactor; saga_prepared_state.rs:134 = broadcast handler's migration (actor sense); 6883/6887 + prepared_state 37-38/232 = NEW explanatory prose about the WITHDRAWN saga (correct); MigrationState:6683 = governance. No hit describes the cut saga as live/example. saga_journal.rs FULLY SCRUBBED at this HEAD (prior straggler closed).
4. **Matches spec exactly.** DEFERRED Gap-4 names deletion of SagaInput::ContextMigration / ContextMigrationPrepared as "the code task." Spec 09-security-model.md:287 + 05-contexts.md:1776 re-scope §9.4.3 to "contract any FUTURE secret-bearing saga MUST satisfy, currently with NO instance — normative for any such future saga." So keeping the apparatus dormant (not deleting it) is what the spec MANDATES.

## The one nuance worth recording
DEFERRED doc says "the §9.4.3 secret-bearing journal path are to be deleted in the code task" — sounds like delete the apparatus. But the doc's own final clause + spec §9.4.3 say "re-scoped to 'no live instance' / normative for future saga." Resolution: "delete the journal path" = delete the ContextMigration-SPECIFIC secret-bearing route; the GENERIC contract machinery (mark_resolved(bool), EvidenceWire, Zeroizing evidence) STAYS because §9.4.3 is now a live normative forward contract requiring it to exist. Diff did exactly this. Correct.

## Gates
clippy -p scp-runtime --all-targets --features scp-runtime/testing -D warnings = CLEAN. 16 saga lib tests pass (4 in saga_prepared_state). Feature is scp-runtime/testing, NOT scp-core/testing (scp-runtime doesn't re-export that).

## LESSON
Cut-a-saga / withdraw-a-feature review pattern:
- Two layers: enumeration sites (count must drop: "4 saga types"->"3", variant gone) AND historical/problem-statement prose (each withdrawn body needs a supersession marker; verify no live-saga description survives).
- Retain-the-hook is the CORRECT shape when an exhaustive classifier (no wildcard) feeds dormant apparatus that a spec keeps as a normative forward contract. Confirm the hook is CALLED (grep call site w/ arg), not just defined — a `let _ =` or unused fn would be the fraud pattern.
- A DEFERRED/historical doc's "to be deleted" can be narrower than literal (delete the specific path, not the generic contract). Trust the SPEC's re-scope wording over the doc's looser phrasing — artifact flow: spec governs.
- When "migration" appears in a refactor codebase, distinguish 3 senses: (a) the cut saga, (b) actor-refactor "handler migration / migration shim", (c) §5.11A governance ProposeContextMigration / MigrationState. Only (a) should be gone.
- When the same saga-cut appears across two diffs at different HEADs, the fuller one may close the earlier's straggler — re-grep the previously-flagged file at the NEW HEAD before re-reporting.
