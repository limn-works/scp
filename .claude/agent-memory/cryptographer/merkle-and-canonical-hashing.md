---
name: merkle-and-canonical-hashing
description: RFC 6962 Merkle construction in event_log/, canonical-hash weaknesses (no domain separators / no length prefixes), signature-verification forms, pruning gaps (SCP-126)
metadata:
  type: project
---

# Merkle tree (`event_log/`)

- RFC 6962 domain separation: leaf = `SHA-256(0x00 ‖ data)`, interior = `SHA-256(0x01 ‖ left ‖ right)`.
- Consistent across `tree.rs`, `proof.rs`, `checkpoint.rs`, `metrics.rs`, `phase2_integration.rs`.
- Odd-leaf promotion: hash-with-self (not carry-unchanged).
- `hash_pair()` duplicated in `tree.rs`, `proof.rs`, `pruning.rs` — three copies, divergence risk.
- `compute_event_canonical_hash()` + `event_type_tag()` duplicated in 5 files.

# Canonical-hash weaknesses (open findings, PR #76 review)

- No domain separators across hash functions (event, claim, attestation, checkpoint).
- No length prefixes on variable-length fields in concatenated hashes.
- Attestation type uses `Debug` formatting — not stable for canonicalization.
- `serde_json::Value::to_string()` is not canonical across languages/versions.
- **CRITICAL**: `claiming.rs:267` uses `to_be_bytes` + SHA-256 prehash;
  `trust/attestation.rs:431` uses `to_le_bytes` + raw bytes — INCOMPATIBLE
  attestation verification. Two canonical forms exist; must consolidate.

# Signature verification

- `claim_shadow()` verifies the attestation sig, then the claim sig, before any state transition.
- Ed25519 via `ed25519_dalek`; signatures over SHA-256 canonical hashes (`claiming.rs`)
  vs over raw canonical bytes (`trust/attestation.rs`) — see the incompatibility above.
- DID formats: `did:dht:z<z-base-32>` (prod), `did:key:<hex>` (test, non-standard).
  The `did:key` form in `claiming.rs` does NOT conform to the W3C did:key spec
  (missing multicodec/multibase).

# Deterministic serialization

- `nesting.rs`: `BTreeSet` for `requires_approval_for` ensures sorted `serde_json`.
- `content_hash()` returns `Result` for proper error propagation.

# Pruning & proof compaction (SCP-126)

- `CompactProof` == `PrunedInclusionProof` with renamed fields (unnecessary duplication).
- `prune_before_checkpoint` does NOT verify the checkpoint `merkle_root` against log state.
- `prune_before_checkpoint` does NOT verify the checkpoint signature.
- `compute_prune_boundary` has a structural retention logic error: prunes structural
  events within retention.
- `TruncatedEventLog` always prunes at `checkpoint.event_count` regardless of the
  `compute_prune_boundary` result.
- ADR-030 invariant 3 (checkpoint events never pruned) NOT enforced.
- Size-based pruning (ADR-030 §2b) NOT implemented.
- Test checkpoints use fake signatures (`vec![0u8; 64]`) — masks the missing verification.
