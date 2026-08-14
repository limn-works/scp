---
name: rotate-all-author-keys-epoch-advance-pr
description: Pass-4 black/white/security review of fix/rotate-all-author-keys-epoch-advance (KEA leaf emission + checkpoint counter). Security-clean; residual = counter-formula test guard gap.
metadata:
  type: project
---

# fix/rotate-all-author-keys-epoch-advance (tip 9b8282ec2, likely PR#2218 lineage)

`BroadcastContext::rotate_all_author_keys` now returns `Vec<BroadcastKeyEpochAdvance>` (was `()`) + takes `timestamp_ms`. Runtime emits one best-effort `KeyEpochAdvance` leaf per rotated author in execute_revoke (ban) + execute_rotate_content_keys. Shared helper `emit_key_epoch_advance_best_effort` in governance_helpers.rs. Counter fixes: `+= 1 + kea_success_count` (only counts durable-appended leaves) and execute_reconfigure_governance `+= 2`.

## Security verdict: CLEAN (black/white/security)
- **No key-material exposure**: `BroadcastKeyEpochAdvance` = {author_did, new_epoch, timestamp} — all public metadata. No SenderKey/BroadcastKey surfaced. (broadcast.rs:129)
- **No TOCTOU**: rotation happens inside `commit_class_s_keep` (fail-closed persist); leaf emission is AFTER, best-effort. Rotation durable regardless of leaf. Counter counts only successful appends → matches durable reality on replay/reconstruction.
- **Banned subscriber can't exploit ordering**: sort_unstable_by author_did deterministic; attacker can't influence author-DID set. governance_ban_subscriber sorts rotated_authors; rotate_all_author_keys sorts advances. Both deterministic Merkle ordering.
- **Overflow**: pre-validate pass all-or-nothing (checked_add), CryptoFailed before any mutation.
- Only 1 prod caller of rotate_all_author_keys (governance_helpers.rs:3147). timestamp_secs.saturating_mul(1000) safe.

## Residual finding (LOW, pass-4): counter-formula regression guard absent
Tests 5/6 in tests/event_log_leaves.rs are NAMED "Regression guard for the checkpoint-counter formula" but only assert LEAF COUNTS, not `checkpoint_events_since`. Counter increment is a statement INDEPENDENT of the leaf appends. Reverting `+= 1 + kea_success_count` → `+= 1` (or reconfigure `+= 2` → `+= 1`) PASSES all 6 tests. Docstrings HONESTLY disclose this inline ("not observable from integration tests ... counter formula itself must be guarded at unit level"). Same gap I flagged for PR#2218 round-2 (see pr2218-kea-counter-round2.md).
- Counter IS pub (state.rs:915); unit precedent lifecycle_helpers.rs:4139/4174 asserts it directly. But those execute_* fns need full ClassSCell harness — not cheaply reachable from the integration `manager` API (snapshot_context takes &PerContextState, internal). Closing requires either snapshot round-trip read or heavy unit harness.
- Recommendation: either rename tests to "leaf-count regression guard" (honest) or add unit-level counter assertion. Underlying property correctly implemented; only the guard is missing.
