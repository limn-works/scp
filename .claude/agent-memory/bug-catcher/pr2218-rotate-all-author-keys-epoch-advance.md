---
name: pr2218-rotate-all-author-keys-epoch-advance
description: Review of PR #2218 fix/rotate-all-author-keys-epoch-advance (@050d0767f) — rotate_all_author_keys returns epoch advances + checkpoint counter fixes
metadata:
  type: project
---

PR #2218 `fix/rotate-all-author-keys-epoch-advance` @050d0767f (base ed80eab40). Issue #1847.

**Substantially CLEAN.** rotate_all_author_keys (scp-protocol/src/context/broadcast/mod.rs:1697) now takes `timestamp_ms: u64`, returns `Vec<BroadcastKeyEpochAdvance>` sorted by author_did (unique HashMap keys → deterministic). Pre-validate checked_add overflow all-or-nothing. new_epoch is post-increment u64 so always ≥1 → `old_epoch = new_epoch.saturating_sub(1)` sound; both KeyEpochAdvancePayload fields u64 (no truncation). Only ONE prod caller (governance_helpers.rs:3103) updated correctly; git-grep on branch ref confirms no stale no-arg caller (working-tree line 2596 was a DIFFERENT commit lineage 1620de983, not this branch — do NOT trust working-tree grep for branch review).

Counter fixes VERIFIED CORRECT (governance_logic.rs:156-158: checkpoint_events_since must == true durable-leaf count per node):
- execute_rotate_content_keys:3249 `+= 1 + kea_success_count` (1 ContentKeysRotated `?`-append + each best-effort KEA success). Counter placed after best-effort loop (no `?` between append and counter) → always reached, per-node-consistent.
- execute_revoke:1031 `+= 1 + kea_success_count`, OUTSIDE/before the needs_sender_key_rotation block. Pre-PR was bare `+= 1` (undercounted KEA leaves) — genuine fix. Counting only kea_success_count (actual appends) is correct for per-node checkpoint position; cross-node best-effort divergence is inherent/pre-existing, not a bug.
- execute_reconfigure_governance:3386 `+= 2` (GovernanceReconfigured + GovernanceDeadlockRecovery, both `?`-fail-closed). Happy path now correct (was `+= 1`, always drifted -1). DeadlockRecovery leaf pre-existed the branch base.
- execute_revoke return `Ok(rotated_authors.len())` = broadcast-author count → RevokeResult.rotated_author_count (informational usize, state.rs:409). Sender-key path emits no durable leaf. Correct, pre-existing.

**ONLY finding — LOW (not a regression, strict improvement):** execute_reconfigure_governance batches `+= 2` AFTER two sequential `?`-fail-closed appends. If the 2nd (GovernanceDeadlockRecovery) append fails, 1st leaf is already durable but Err returns before `+= 2` → counter under-counts by 1 (§9.9.3 drift). Requires I/O failure precisely between the two appends. Pre-PR had same error-path drift AND a happy-path drift; PR fixes happy path, leaves error path. FIX: increment incrementally right after each successful `?`-append (`+= 1` after each) instead of batch `+= 2` at end — matches the "increment only when a durable leaf is actually appended" invariant exactly. Other two functions don't have the two-sequential-`?`-appends shape (best-effort loop has no `?`) so they're already robust.

execute_add_member NOT touched by this PR (checklist item 8 premise false). Integration test event_log_leaves.rs::rotate_content_keys_broadcast_emits_key_epoch_advance_per_author is meaningful (asserts 1 ContentKeysRotated + N KEA, decodes payload old/new epoch + actor_did). timestamp_ms is dead-data in governance path (append uses timestamp_secs) — harmless.
