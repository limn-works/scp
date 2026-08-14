---
name: project-event-log-root-divergence-1535
description: ADR decision resolving #1535's event-log merkle_root divergence — canonical root is RFC 6962 tree::root over event-hash leaves; scp-runtime ContextLog is the divergent reimplementation
metadata:
  type: project
---

#1535 uncovered that `ConsistencyCheckpoint.merkle_root` means two different things in two parallel event-log substrates.

**Decision:** Canonical event-log root = `scp_event_log::tree::root(log)` — the RFC 6962 tree root over leaves `SHA-256(0x00 || rmp_serde(Event))`. This is what ADR-011 (.docs/adrs/phase-2.md:683,756,823,836), §25.8 KAT vectors, and the proof subsystem all mandate. `prev_hash` is a per-event chain field used for append-time integrity validation ONLY; it is NOT the tree leaf and NOT the root.

**Why:** Two substrates exist:
- `scp-event-log` crate (EventLog) + FFI bridges (PyO3/NAPI/WASM via `ctx_rt.event_log`/`rt.event_log`) → checkpoint `merkle_root = tree::root(log)`. CORRECT. `generate_checkpoint_at` (checkpoint.rs:965), `compare_checkpoints` (checkpoint.rs:937), pruned-proof verify all use tree::root.
- `scp-runtime` ContextManager `MerkleEventLogProvider`/`ContextLog` (providers/event_log.rs) → hash-chain with domain `"SCP-EXPORT-ENTRY:"`; `merkle_root()` returns `entries.last().hash` (CHAIN HEAD, not a tree root). `build_checkpoint`/`compare_remote_checkpoint` (queries_helpers.rs) source the chain head. DIVERGENT. Also `sync_merkle_tree` (queries_helpers.rs:870) pushes `entry.hash` (chain hashes) as RFC 6962 LEAVES — wrong leaves too. So native checkpoint root ≠ native proof-tree root ≠ WASM/FFI root.

**How to apply:** The fix is to make scp-runtime's ContextManager use the canonical `scp_event_log::EventLog` (event-hash leaves, tree::root) for checkpoints, OR build the RFC 6962 tree over event hashes (not chain hashes) and have build_checkpoint return tree::root. The runtime ContextLog chain and the scp-event-log tree must be unified into ONE substrate keyed identically across all consumers. Checkpoint canonical-hash CONSTRUCTION (`SCP-CHECKPOINT-V1:`) is unchanged — only the merkle_root VALUE fed into it changes. #1535's §23.7 catch-up gate `ct_eq(reached_tree_root, peer.merkle_root)` only passes once both sides emit tree::root. No spec edit needed — ADR-011/§23.16.1 already say "Merkle root"; this is pure impl alignment. Pre-release: no migration. See [[lock_free_read_invariant]].
