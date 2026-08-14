---
name: review-classs-state-datasplit-pr2a
description: ADR-049 §9 PR2a Class-S data-split (ClassSState/GovernanceClassS sub-structs + mirror snapshot) security review — CLEAN, behavior-neutral
metadata:
  type: project
---

# ClassSState/GovernanceClassS data-split + mirror snapshot — CLEAN

Worktree classs-guard, HEAD ebb8314f2 (commit "refactor(actor): group Class-S state into ClassSState/GovernanceClassS sub-structs + mirror snapshot"). 14 files.

**Verdict: behavior-neutral, no leak, no weakening, no new panic. Zero findings.**

**Why:** ADR-049 §9 PR2a groups the 5 Class-S xctx-saga fields (PerContextState→ClassSState) + 4 Class-S governance fields (GovernanceState→GovernanceClassS) into named sub-structs, fields stay `pub(crate)`. Mirror snapshot/restore added. Privatization-behind-mutator is a LATER PR.

**How verified (mechanical, repeatable):**
- §9.4.3 bearer barrier intact: saga_prepared_state.rs UNTOUCHED by diff; `SagaPreparedState` enum (saga_prepared_state.rs:67) still derives NOTHING. Only added derive in whole diff = `#[derive(Debug,Clone)]` on `GovernanceClassSSnapshot` (mirror of public projected fields, NO live NonceTracker/no secret). `ClassSState`/`GovernanceClassS`/`ClassSStateSnapshot` get NO Clone/Serialize. saga_pending snapshots via pre-existing sanctioned `SagaPreparedStateSnapshot` (ucan_proof_id = index String not proof bytes, confirmed CrossContextToolInvocationPrepared:273-275).
- On-disk format byte-identical: `snapshot_context`/`build_snapshot_from_state` build the SAME flat `ContextSnapshot` fields; only the READ source path changed (`ctx.governance.X`→`ctx.governance.class_s.X`), same `.keys().copied().collect()`/`.clone()`/`snapshot_entries()`. ContextSnapshot struct unchanged.
- Pure repath proof: normalized diff (strip `.class_s` + whitespace) of removed vs added lines = IDENTICAL for saga.rs (the security-critical handler) AND broadcast/governance/tools/trust_recovery/ttl_close/lifecycle_logic/supervisor helpers. messaging_helpers "differs" only because `build_snapshot_from_state` exhaustive-destructure now binds the 4 gov fields through nested `class_s: GovernanceClassS{..}` pattern (same local names feed same flat snapshot fields) — a forward-lock strengthening.
- Gate green: `check-class-s-fail-closed.sh --self-test` EXIT 0; real-tree run EXIT 0. Mutation markers survive as substrings of lengthened paths. No persist call removed/reordered.
- No new panic: only unwrap is pre-existing `u32::try_from(...).unwrap_or(u32::MAX)` repathed. restore() uses struct-literal rehydration, infallible.
- Mirror methods exist: NonceDedup `entries`/`ttl_secs`(const)/`from_entries_with_ttl`(const)/`with_ttl`; NonceTracker `snapshot_entries`/`from_snapshot`/`context_id`/`new`. xctx_nonce_dedup IS Class-S persisted (not reconstructable freshness — crash would re-open §6.2.4 replay window).

**How to apply:** This is scaffolding; the privatization/compile-time-enforcement PR is the real barrier. Re-confirm next PR doesn't add Clone/Serialize to the live sub-structs and that the mutator boundary actually retires the source-text gate.
