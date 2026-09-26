---
name: phase01-readiness-economy-whitepaper
description: Phase 0/1 production-readiness crypto review, economy/dynamic-pricing + adapter-credential findings, and the white-paper crypto review
metadata:
  type: project
---

# Phase 0/1 production-readiness review (2026-03-06)

- Sender key protocol: JSON → MessagePack (`to_vec_named`) SOUND — all 4 serialization
  points + 25 test sites.
- HPKE domain separator: `"scp-sender-key-hpke-v1"` → `"scp-sender-key-v1"` per spec.
  Prefix matches, but the full `info` param is still incomplete.
- **PRE-EXISTING HIGH**: `hpke_seal`/`hpke_open` pass only the domain prefix to the
  HKDF `info`, NOT `context_id ‖ sender_did ‖ epoch_bytes` per spec §9.16.2. No AAD on
  AES-GCM. Tracked in [[spec-audit-findings]].
- `InnerEnvelope`: `deny_unknown_fields` added, SOUND. The nested `Provenance` struct
  lacks it (mitigated by `provenance_hash`). Sender key wire types also lack it.
- `ProtocolRepository`: `to_vec` → `to_vec_named` SOUND, backward-compatible deserialization.
- Dedup cache TTL 1h → 24h per spec §9.8.2(b), SOUND.
- Wire format: 10 `ref_id` → `"ref"` renames + `event_type` → `"type"`, comprehensive
  tests, SOUND.
- Conflict detection: `RemoveMember` same-target + `RotateContentKeys` self-conflict
  added, SOUND.
- `[u8; 16]` nonce fields lack `serde_bytes` (integer array in msgpack, not a binary
  blob) — wire-format interop risk.
- Block notification future-timestamp rejection added but no dedicated test for that path.

# White paper crypto review (2026-03-09)

Reviewed `.docs/white-paper.md` against the specs. Substantially correct, no
construction flaws.

- MEDIUM: paper omits that the MLS ciphersuite uses AES-128-GCM (not 256). System
  security is bounded at 128-bit.
- MEDIUM: sender keys do NOT provide forward secrecy (intentional, spec §9.16.5) —
  the paper omits this.
- MEDIUM: HPKE `info` param has variable-length concat ambiguity (pre-existing spec issue).
- LOW: MessagePack listed as a "Cryptographic Primitive" (it is a serialization format).
- LOW: X25519 and HMAC-SHA256 missing from the Appendix A primitives table.
- Composition notes: MLS epoch vs sender key epoch independence; 3-layer ordering is
  load-bearing; UCAN–MLS gap window.
- All RFC/NIST references correct. The formal-analysis call in §14.1 is appropriate.

# Economy / dynamic pricing (SCP-157)

- `evaluate_formula`: integer-only, `Amount(u64)` + `Coefficient(i64)`, no `f64`.
- Linear: `(coefficient.0 * metric_value) / 1_000_000` via `Coefficient::evaluate`.
- Step: cumulative thresholds; all met thresholds add via `saturating_add`. Thresholds
  are NOT required to be sorted — correctness is unaffected by `saturating_add` commutativity.
- Floor applied before cap — cap takes precedence in the degenerate (`cap < floor`) case.
- Overflow in `Coefficient::evaluate` returns `None`, propagated up;
  `verify_cost_sufficiency` falls back to `Amount(u64::MAX)` (fail-closed).
- `cast_unsigned()` (Rust 1.87) used for non-negative `i64 → u64`, guarded by `delta >= 0`.
- EIP-1559 relay pricing: stuck price when
  `current_base_price * max_change_per_mille < 1000` (integer truncation to 0 change).

# Adapter credential management (SCP-162)

- `AdapterCredential` stores pre-encrypted credential bytes (the caller encrypts before storing).
- Storage key `identity/{did}/adapter_credentials/{adapter_id}` per spec §17.3.
- No zeroization on `encrypted_data: Vec<u8>` (mitigated by the data being encrypted).
- DID key-injection risk: the `DID` type has no character validation and is used in
  storage-key construction.
- `configure_adapter` overwrites `created_at` on rotation (loses original creation time).
- `validate_adapter` checks: non-empty id, safe chars `[a-zA-Z0-9_-]`, ≥ 1 currency.
- 34 tests pass; missing proptest for serialization round-trips.
- `ProtocolRepository<S: Storage>` wraps the platform `Storage` trait for domain methods.
