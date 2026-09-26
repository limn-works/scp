---
name: reviews-2026-q1
description: Bridge relay auth/DID healing (PR #255), Phase 0/1 production-readiness review, white-paper crypto review, and economy/adapter-credential findings
metadata:
  type: project
---

# Bridge relay auth + DID healing (PR #255, SCP-247/SCP-245)

- Bridge auth preimage: `"SCP-BRIDGE-REGISTER-V1:" || routing_id[32] ||
  be-u64(timestamp)` = 63 bytes fixed — SOUND.
- `verify_strict()` used. Verification order: timestamp → signature → routing_id
  (fast reject).
- Routing id: `SHA-256("scp:did:" || did_string)` — domain-separated, golden
  vector verified.
- DID derivation: `did:dht:z` + zbase32(pubkey) — deterministic and invertible.
- 60s replay window with no nonce tracking, acceptable because registration is
  idempotent.
- `DualLayerResolver`: `tokio::join!`, BEP44 `verify_strict` on both layers,
  anti-rollback via cached seq.
- Healing: async best-effort republish to a stale layer, panic-monitored.
- PRE-EXISTING: migration proof hash (dht.rs:607) has variable-length concat
  ambiguity (`old_did||new_did`).

# Phase 0/1 production-readiness review (2026-03-06)

- Sender key protocol: JSON → MessagePack (`to_vec_named`) SOUND across all 4
  serialization points and 25 test sites.
- HPKE domain separator `"scp-sender-key-hpke-v1"` → `"scp-sender-key-v1"` per
  spec; prefix matches but the full info param is still incomplete.
- PRE-EXISTING HIGH: `hpke_seal`/`hpke_open` pass only a domain prefix to HKDF
  info, not `context_id||sender_did||epoch_bytes` per spec §9.16.2, and set no
  AAD on AES-GCM. Tracked in spec-audit-findings.md.
- `InnerEnvelope`: `deny_unknown_fields` added — SOUND. Its `Provenance` nested
  struct lacks it (mitigated by `provenance_hash`); sender key wire types also
  lack it.
- `ProtocolRepository`: `to_vec` → `to_vec_named` SOUND, backward-compatible on
  deserialization.
- Dedup cache TTL 1h → 24h per spec §9.8.2(b) — SOUND.
- Wire format: 10 `ref_id` → `"ref"` renames plus `event_type` → `"type"`, with
  tests — SOUND.
- Conflict detection: RemoveMember same-target and RotateContentKeys
  self-conflict added — SOUND.
- `[u8;16]` nonce fields lack `serde_bytes`, so MessagePack encodes them as an
  integer array rather than a binary blob — wire-format interop risk.
- Block-notification future-timestamp rejection added, but no dedicated test
  covers that code path.

# White paper crypto review (2026-03-09)

Reviewed `.docs/white-paper.md` against the specs. Substantially correct, no
construction flaws.

- MEDIUM: paper omits that the MLS ciphersuite uses AES-128-GCM, not 256, so
  system security is bounded at 128 bits.
- MEDIUM: sender keys do NOT provide forward secrecy (intentional, spec §9.16.5)
  and the paper omits that.
- MEDIUM: HPKE info param has variable-length concat ambiguity (pre-existing spec
  issue).
- LOW: MessagePack listed as a "Cryptographic Primitive"; it is a serialization
  format.
- LOW: X25519 and HMAC-SHA256 missing from the Appendix A primitives table.
- Composition notes: MLS epoch and sender key epoch are independent, the 3-layer
  ordering is load-bearing, and a UCAN-MLS gap window exists.
- All RFC and NIST references correct. The formal-analysis call in Section 14.1
  is appropriate.

# Economy / dynamic pricing (SCP-157)

- `evaluate_formula` is integer-only: `Amount(u64)` plus `Coefficient(i64)`, no
  f64.
- Linear: `(coefficient.0 * metric_value) / 1_000_000` via `Coefficient::evaluate`.
- Step: cumulative thresholds; every met threshold adds via `saturating_add`.
  Thresholds need not be sorted, because `saturating_add` commutes.
- Floor applied before cap, so a cap wins in a degenerate `cap < floor` case.
- Overflow in `Coefficient::evaluate` returns `None` and propagates;
  `verify_cost_sufficiency` falls back to `Amount(u64::MAX)` — fail-closed.
- `cast_unsigned()` (stabilized Rust 1.87) handles non-negative i64 → u64,
  guarded by a `delta >= 0` check.
- EIP-1559 relay pricing sticks when
  `current_base_price * max_change_per_mille < 1000`, because integer truncation
  yields a 0 change.

# Adapter credential management (SCP-162)

- `AdapterCredential` stores pre-encrypted credential bytes; a caller encrypts
  before storing.
- Storage key: `identity/{did}/adapter_credentials/{adapter_id}` per spec §17.3.
- No zeroization on `encrypted_data: Vec<u8>`, mitigated because that data is
  already encrypted.
- DID key injection risk: the `DID` type performs no character validation yet
  feeds storage-key construction.
- `configure_adapter` overwrites `created_at` on rotation, losing original
  creation time.
- `validate_adapter` checks non-empty id, safe chars `[a-zA-Z0-9_-]`, and at
  least 1 currency.
- 34 tests pass; a proptest for serialization round trips is missing.
- `ProtocolRepository<S: Storage>` wraps the platform `Storage` trait with domain
  methods.
