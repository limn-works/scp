# Tiered Storage: Checkpoint Root Must Span All Tiers

**Date:** 2026-02-27
**Source:** SCP-127 security review of `crates/scp-core/src/event_log/tiered_storage.rs`

## The Bug

`TieredEventLog::migrate_to_cold()` captures `checkpoint_root = tree::root(&self.hot)` before rebuilding the hot log. After migration, the hot log is reconstructed from only the remaining (non-migrated) leaves. A second migration captures the root of this *partial* hot log, permanently invalidating the checkpoint root that first-batch cold entries need for proof verification.

## Why Tests Missed It

The `multiple_migrations_accumulate_cold_entries` test verified counts and tier membership after two migrations, but never attempted `fetch_cold_proof` for entries from the first migration batch. Single-migration tests passed because the checkpoint root was still the full-log root.

## The Invariant

When a tiered system captures a Merkle root for cold proof verification, the root must be valid for ALL cold entries, not just the most recently migrated batch. Options:

1. **Per-epoch roots:** Store a separate checkpoint root per migration epoch and associate each cold entry with its epoch.
2. **Cumulative root:** Maintain a ghost Merkle tree of all leaf hashes (cold + hot) so the root always spans the full log.
3. **Proof caching:** Store inclusion proofs at migration time so cold entries carry their own verified proof and do not need relay re-fetch.

## General Lesson

When testing tiered/partitioned data with cryptographic verification, always test the verification path across at least 2 partition operations. A single operation often looks correct because the captured state still matches the full state. The invariant breaks only when state is captured from a *subset* after the first partition.

## Resolution (2026-02-27)

Both issues were fixed in the same commit:

1. **Checkpoint root:** Option 2 (cumulative root) was chosen. An `all_leaf_hashes: Vec<[u8; 32]>` ghost collection maintains ALL leaf hashes in global append order. `record_hot_event()` appends each new leaf hash. At migration time, `checkpoint_root` is computed from `compute_root_from_leaves(&self.all_leaf_hashes)`, so it always spans the full log.

2. **Index translation:** A `global_index_offset: u64` field tracks total events migrated to cold. Cold entry sequences use `global_index_offset + local_index`. `is_hot()` checks against the offset range. This maintains correct global addressing without modifying the hot EventLog internals.

3. **Regression tests added:**
   - `checkpoint_root_valid_after_two_migrations` -- verifies root and cold proofs across 2 migration cycles
   - `global_index_offset_maintained_after_migration` -- verifies offset and cold entry sequences
   - `global_index_offset_correct_after_two_migrations` -- verifies offset accumulation

## Related

- The `GhostTreeProvider` test helper generates valid Merkle proofs from the full ghost tree, enabling end-to-end cold proof verification in tests.
