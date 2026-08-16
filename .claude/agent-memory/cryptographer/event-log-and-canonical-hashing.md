---
name: event-log-and-canonical-hashing
description: Merkle tree domain separation in event_log/, open canonical-hash weaknesses, and SCP-126 pruning/proof-compaction findings
metadata:
  type: project
---

# Merkle tree (event_log/)

- RFC 6962 domain separation: leaf = SHA-256(0x00||data), interior = SHA-256(0x01||left||right)
- Consistent across tree.rs, proof.rs, checkpoint.rs, metrics.rs, phase2_integration.rs
- Odd-leaf promotion: hash-with-self, not carry-unchanged
- `hash_pair()` duplicated in tree.rs, proof.rs, pruning.rs — divergence risk
- `compute_event_canonical_hash()` + `event_type_tag()` duplicated in 5 files

# Canonical-hash weaknesses (open findings, PR #76 review)

- No domain separators across several hash functions (event, claim, attestation, checkpoint)
- No length prefixes on variable-length fields in concatenated hashes
- Attestation type uses Debug formatting, which is not stable for canonicalization
- `serde_json::Value::to_string()` is not canonical across languages or versions
- CRITICAL: claiming.rs:267 uses `to_be_bytes` + SHA-256 prehash; trust/attestation.rs:431
  uses `to_le_bytes` + raw bytes — INCOMPATIBLE attestation verification

# Pruning and proof compaction (SCP-126)

- `CompactProof` == `PrunedInclusionProof` with renamed fields (unnecessary duplication)
- `prune_before_checkpoint` verifies neither the checkpoint merkle_root against log
  state nor the checkpoint signature
- `compute_prune_boundary` prunes structural events inside its retention window
- `TruncatedEventLog` always prunes at `checkpoint.event_count` regardless of
  `compute_prune_boundary`
- ADR-030 invariant 3 (checkpoint events never pruned) NOT enforced
- Size-based pruning (ADR-030 section 2b) NOT implemented
- Test checkpoints use fake signatures (`vec![0u8; 64]`), which masks missing verification

# Signed context export (export_import.rs, commit 16a2cd42b) — APPROVE

Removed an unsigned envelope `ContextExport.merkle_root` field plus its step-6
self-check. Strictly stronger. Signed preimage =
`SHA-256(SCP-CONTEXT-EXPORT-V1: || scope.tag_byte() || JCS(snapshot))`, and
`snapshot.event_log_merkle_root` sits inside `JCS(snapshot)`. Step 5 (recompute
RFC 6962 root over `event_log_data` via `recompute_event_log_root`, renamed from
`verify_merkle_chain`, then `ct_eq` against the signed root) is the sole
authoritative binding. Step 6 compared an attacker-writable envelope copy against
a signed copy — both attacker-visible, trivially satisfiable, gating nothing.
Coverage: prefix truncation rejected in `append_unsigned_event` (seq/prev_hash);
suffix, middle, reorder, substitution, forgery all fail on root mismatch. Empty
log signs `[0u8;32]`, not an unsigned sentinel, so no all-zeros bypass.

# PseudonymAnnounced removal (commit f438acf0f) — APPROVE

Taxonomy 76 → 75. Tag 59 RETIRED as a gap (no renumber), so every other
`event_type_tag` stays stable and §25 KAT 32/33 root `39e50b87` is byte-unchanged
(verified). `EventType` serializes by NAME string via rmp_serde with no integer
repr, so removal cannot shift other leaves. Convergence restored: receive path
`deliver_plaintext_or_announcement` returns `None` for all 3 arms, so its
`Some`-append channel is dead in production. Three non-convergent classes
(MessageReceived, EquivocationDetected, PseudonymAnnounced) have no `EventType`
variant, making them un-appendable at type level.

**Gotcha:** bare `cargo test -p scp-event-log` fails 116 tests — hex `did:key` is
gated behind the scp-primitives `testing` feature (identity.rs:118). Run with
`--features testing`.
