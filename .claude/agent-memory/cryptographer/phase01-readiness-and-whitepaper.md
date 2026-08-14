---
name: phase01-readiness-and-whitepaper
description: Phase 0/1 production-readiness crypto review (2026-03-06) — sender-key MessagePack migration, HPKE info-param gap — and the white-paper accuracy review (2026-03-09)
metadata:
  type: project
---

# Phase 0/1 production readiness (2026-03-06)

- Sender key protocol: JSON → MessagePack (`to_vec_named`) SOUND, all 4 serialization points + 25 test sites
- HPKE domain separator: `"scp-sender-key-hpke-v1"` → `"scp-sender-key-v1"` per spec. Prefix matches but the full `info` param is still incomplete (see [[spec-audit-findings]]).
- **PRE-EXISTING HIGH**: `hpke_seal`/`hpke_open` pass only the domain prefix to HKDF `info`, NOT `context_id || sender_did || epoch_bytes` per spec §9.16.2. No AAD on AES-GCM. Tracked in the spec audit.
- `InnerEnvelope`: `deny_unknown_fields` added — SOUND. The nested `Provenance` struct lacks it (mitigated by `provenance_hash`). Sender-key wire types also lack it.
- `ProtocolRepository`: `to_vec` → `to_vec_named` SOUND, backward-compatible deserialization
- Dedup cache TTL: 1h → 24h per spec §9.8.2(b) — SOUND
- Wire format: 10 `ref_id` → `"ref"` renames + `event_type` → `"type"`, comprehensive tests — SOUND
- Conflict detection: `RemoveMember` same-target + `RotateContentKeys` self-conflict added — SOUND
- `[u8;16]` nonce fields lack `serde_bytes` (integer array in msgpack, not a binary blob) — wire-format interop risk
- Block-notification future-timestamp rejection added but no dedicated test for that code path

# White paper crypto review (2026-03-09)

Reviewed `.docs/white-paper.md` against the specs. Substantially correct, no construction flaws.

- MEDIUM: the paper omits that the MLS ciphersuite uses AES-128-GCM (not 256). System security is bounded at 128-bit.
- MEDIUM: sender keys do NOT provide forward secrecy (intentional, spec §9.16.5) — the paper omits this.
- MEDIUM: the HPKE `info` param has a variable-length concat ambiguity (pre-existing spec issue).
- LOW: MessagePack listed as a "Cryptographic Primitive" (it is a serialization format).
- LOW: X25519 and HMAC-SHA256 missing from the Appendix A primitives table.
- Composition notes: MLS epoch vs sender-key epoch independence; the 3-layer ordering is load-bearing; the UCAN–MLS gap window.
- All RFC/NIST references correct. The formal-analysis call in §14.1 is appropriate.
