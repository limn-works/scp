---
name: pruning-economy-credentials
description: Pruning/proof-compaction (SCP-126) missing checkpoint verification, dynamic-pricing integer arithmetic (SCP-157), and adapter credential management (SCP-162)
metadata:
  type: project
---

# Pruning & proof compaction (SCP-126)

- `CompactProof` == `PrunedInclusionProof` with renamed fields (unnecessary duplication)
- `hash_pair()` now duplicated in THREE files: tree.rs, proof.rs, pruning.rs — critical divergence risk
- `prune_before_checkpoint` does NOT verify the checkpoint `merkle_root` against log state
- `prune_before_checkpoint` does NOT verify the checkpoint signature
- `compute_prune_boundary` has a structural retention logic error: prunes structural events within retention
- `TruncatedEventLog` always prunes at `checkpoint.event_count` regardless of the `compute_prune_boundary` result
- ADR-030 invariant 3 (checkpoint events never pruned) NOT enforced
- Size-based pruning (ADR-030 §2b) NOT implemented
- Test checkpoints use fake signatures (`vec![0u8; 64]`) — masks the missing verification

# Economy / dynamic pricing (SCP-157)

- `evaluate_formula`: integer-only, `Amount(u64)` + `Coefficient(i64)`, no f64
- Linear: `(coefficient.0 * metric_value) / 1_000_000` via `Coefficient::evaluate`
- Step: cumulative thresholds; all met thresholds add via `saturating_add`
- Floor applied before cap — cap takes precedence in the degenerate (cap < floor) case
- Overflow in `Coefficient::evaluate` returns `None`, propagated up; `verify_cost_sufficiency` falls back to `Amount(u64::MAX)` (fail-closed)
- `cast_unsigned()` (Rust 1.87) used for non-negative i64→u64, guarded by a `delta >= 0` check
- EIP-1559 relay pricing: stuck price when `current_base_price * max_change_per_mille < 1000` (integer truncation to 0 change)
- Step thresholds NOT required to be sorted — doesn't affect correctness (saturating_add commutativity)

# Adapter credential management (SCP-162)

- `AdapterCredential` stores pre-encrypted credential bytes (caller encrypts before storing)
- Storage key: `identity/{did}/adapter_credentials/{adapter_id}` per spec §17.3
- No zeroization on `encrypted_data: Vec<u8>` (mitigated by the data being encrypted)
- DID key-injection risk: the `DID` type has no character validation and is used in storage-key construction
- `configure_adapter` overwrites `created_at` on rotation (loses original creation time)
- `validate_adapter` checks: non-empty id, safe chars `[a-zA-Z0-9_-]`, ≥1 currency
- 34 tests, all passing; missing proptest for serialization roundtrips
- `ProtocolRepository<S: Storage>` wraps the platform `Storage` trait for domain methods
