---
name: adr011-eventtype-unification
description: ADR-011/spec amendment unifying scp-runtime event log onto canonical RFC 6962 Merkle tree; export root binding correction; reviewed APPROVE at commit 63723abf7
metadata:
  type: project
---

# ADR-011 EventType Unification + Signed-Export Root Correction (commit 63723abf7)

Docs-only amendment. Reviewed APPROVE 2026-06-17 (worktree spec-adr011-eventtype-unification).

**Why:** scp-runtime event log diverged from protocol RFC 6962 tree (hash-CHAIN + SCP-EXPORT-ENTRY: + ~18 untyped names). See [[finding_runtime_eventlog_not_rfc6962]]. Unify onto scp_event_log::EventLog.

**Verified against impl at pinned commit (crates/scp-event-log/src):**
- Leaf = SHA-256(0x00 || rmp_serde::to_vec(event)) — tree.rs serialize_event_for_hashing:285-290 IS rmp_serde, leaf hash at append:83-88. Matches amendment's `SHA-256(0x00 ‖ rmp_serde(Event))`. NOTE: distinct from compute_event_canonical_hash (SCP-EVENT-V1: signature preimage, excludes signature) — leaf commits the FULL signed event. Two hashes, both correct, do not conflate.
- Interior = SHA-256(0x01 || L || R) hash_pair:575. Empty = SHA-256("") empty_tree_root:273. Odd-node = promote (not hash-with-self) recompute_tree:540-556. All RFC 6962 §2.1.
- Event struct lib.rs:244 = 7 fields (event_type, actor_did, timestamp, sequence, payload, prev_hash, signature). NO signing_key_id. Amendment's signing_key_id removal is consistent.
- checkpoint generate_checkpoint_at:975 uses tree::root(log) + tree::event_count(log) = full ordered set. Was previously chain-head. compare_checkpoints:803 uses ct_eq (constant-time).

**Export-binding correction sound:** old chain-head was prefix-truncation-tolerant (verify_merkle_chain skipped first prev_hash → oldest-drop = prefix truncation accepted). tree::root over full ordered leaf set rejects ANY alteration (prefix/suffix/interior/forge) by construction. Wording precise: oldest-drop correctly = prefix truncation. ADR-050 lines 12/14 retain "Merkle chain" only as historical/rejected-state context — fine.

**Exclusion rationale sound:** §9.9.3 (spec 09:819) crypto equivocation test = equal eventCount + different merkleRoot → requires convergent leaf sets. MessageReceived (per-recipient) + EquivocationDetected (local alert, §9.9.3 tier-a) are non-convergent → correctly excluded. RecoveryEpochAdvanced (§9.12 step 2 MLS Update in all contexts → all members process same Commit) IS convergent → correctly INCLUDED.

**Impl-not-yet-landed (correct artifact flow):** EventType enum at this commit does NOT yet have MessageReceived/EquivocationDetected/RecoveryEpochAdvanced + trailing variant groups — spec amended BEFORE code (one-way flow). 25-test-vectors.md defers typed-leaf KAT to impl landing (byte values impl-derived) — acceptable.

**No new hash/signature construction** — only merkle_root INPUT VALUE changes (chain-head → tree::root). §23.16.1 checkpoint canonical hash recipe unchanged. SOUND.
