---
name: pr2218-rotate-all-author-keys-kea
description: PR #2218 fix/rotate-all-author-keys-epoch-advance 2nd-pass white-hat review — KeyEpochAdvance leaf emission + determinism sort; 1 MEDIUM test-gap
metadata:
  type: project
---

# PR #2218 rotate_all_author_keys / KeyEpochAdvance — 2nd-pass review (2026-08-02, origin/fix/rotate-all-author-keys-epoch-advance)

Scope: rotate_all_author_keys now returns Vec<BroadcastKeyEpochAdvance> so governance RotateContentKeys path emits KEA event-log leaves (#1847, §5.14.10); new shared helper `emit_key_epoch_advance_best_effort` (governance_helpers.rs) dedups the ban-path + rotate-content-keys emit loops; determinism sort added to both producers; checkpoint counter `+= 1 + kea_success_count`.

**old_epoch = new_epoch.saturating_sub(1) is SOUND.** Both producers increment epoch by exactly 1 (broadcast/mod.rs:1632 ban path `author.epoch += 1; new_epoch = author.epoch`; :1719 rotate-all same), each guarded by a `checked_add(1)` pre-validate pass (:1608, :1712 — all-or-nothing, no partial rotation). So new_epoch >= 1 always ⇒ saturating never saturates ⇒ exact `-1`. The helper's `rotations: &[(String,u64)]` contract (each entry = a single +1 increment) is satisfied by both callers.

**author_did = trusted internal state**, not caller input (author.author_did / rotation.author_did). warn! logs only context_id/author_did/error/label — NO key material, NO epoch numbers even. Fail-CLOSED-irrelevant: KEA leaves are best-effort PROVENANCE only; enforcement (key rotation) is durable inside commit_class_s_keep BEFORE emission — a dropped leaf suppresses provenance, never defeats enforcement (matches eventtype-audit-1847-defense.md). Counter `+= 1 + kea_success_count` counts ONLY successful appends ⇒ tracks true durable-leaf count, no §9.9.3 drift either direction (primary leaf appended with `.await?` so the unconditional "1" is only reached on primary success).

**MEDIUM (test gap, NOT a code bug): the determinism sort is not regression-guarded.** Both new sorts (broadcast/mod.rs:1653 ban, :1731 rotate-all) exist to make Merkle leaf order deterministic across replicas (HashMap iter is randomized per-process). But the guarding unit test `rotate_all_author_keys_returns_one_advance_per_author` (:6241) does `advance_dids.sort_unstable()` BEFORE assert_eq — re-sorting masks the production sort. Deleting line :1731 leaves the test GREEN → silent reintroduction of divergent Merkle roots (a consensus/fork-detection integrity property). Integration tests (event_log_leaves.rs Test 3/4) use a SINGLE author (alice) so also can't catch order regressions. FIX: assert the vec is already sorted WITHOUT re-sorting — e.g. `assert!(advances.windows(2).all(|w| w[0].author_did <= w[1].author_did))`, ideally after inserting authors in reverse order. Same gap on the ban-path sort.

Everything else CLEAN. Test isolation fine (each new_manager() + distinct ctx_id, no shared mutable state). execute_reconfigure_governance `+= 2` correct (GovernanceReconfigured + GovernanceDeadlockRecovery). `timestamp_secs.saturating_mul(1_000)` feeding advance.timestamp is dead data on the governance path (documented) — append uses timestamp_secs directly.
