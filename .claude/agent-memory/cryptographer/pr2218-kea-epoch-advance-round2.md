---
name: pr2218-kea-epoch-advance-round2
description: PR #2218 rotate-all-author-keys KEA epoch-advance round-2 review — SOUND, checkpoint-counter drift fixes
metadata:
  type: project
---

# PR #2218 `fix/rotate-all-author-keys-epoch-advance` (issue #1847) — round-2 review

VERDICT: SOUND, no BLOCKER/HIGH/MEDIUM. Diff `ed80eab40...origin/fix/...`.

**Why:** governance-triggered broadcast-key rotation must emit one KeyEpochAdvance
event-log leaf per author, deterministically ordered, and counted into
`checkpoint_events_since` so §9.9.3 checkpoint position doesn't drift.

**How to apply / key facts (verify before trusting):**
- `emit_key_epoch_advance_best_effort` (governance_helpers.rs ~839) derives
  `old_epoch = new_epoch.saturating_sub(1)`. SOUND because BOTH rotation paths
  (`rotate_all_author_keys` + `governance_ban_subscriber`) increment epoch by
  EXACTLY 1 (pre-validated checked_add), so new_epoch is post-increment ≥1 and
  old_epoch == new_epoch-1 exactly. saturating never bites.
- Helper takes `timestamp_secs` and passes it straight to the append. The
  `BroadcastKeyEpochAdvance.timestamp` (ms) field is DEAD in the governance path
  (caller maps only (did,new_epoch)); it's a live wire field only on the
  per-author block/unsubscribe path. `execute_rotate_content_keys` computes
  `timestamp_secs.saturating_mul(1000)` to populate it then discards → LOW smell,
  not a bug.
- warn! logs carry only context_id, author_did (public), error string, label — NO
  key material. Clean.
- kea_success_count init 0, incremented ONLY in the `else` of the append-Err
  branch → correct. Err arm is warn-only, no early return/panic; loop continues.
- Determinism: both rotation Vecs `sort_unstable_by(author_did)` before emit →
  deterministic append order → deterministic Merkle root across replicas.
- Counter FIXES (both real, latent pre-existing drift closed):
  - execute_revoke: was `+= 1` while appending KEA leaves (undercounted) →
    now `+= 1 + kea_success_count`.
  - execute_reconfigure_governance: was `+= 1` but appends TWO fail-closed leaves
    (GovernanceReconfigured + GovernanceDeadlockRecovery) → now `+= 2`. Both
    appends are `.await?` (fail-closed) so counter line only reached on full
    success; `+= 2` correct. Function is deadlock-only (always emits both).

**LOW findings:**
1. Tests 5/6 named `..checkpoint_counter_increments_by..` but `checkpoint_events_since`
   is unobservable from integration tests — they pin DURABLE LEAF COUNT only. A
   regression that keeps appending leaves but reverts counter to `+= 1` is NOT
   caught. Names oversell; comments are honest. Counter formula itself untested.
2. `timestamp_secs*1000` in execute_rotate_content_keys feeds a field the caller
   discards — wasted compute (documented).

Note: fail-closed appends that succeed then a later fail-closed append fails →
counter skipped though earlier leaf durable = drift-by-1. Pre-existing, inherent
to fail-closed pattern, not introduced here.
