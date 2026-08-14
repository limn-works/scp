---
name: attestation-claim-jcs-9.5.2
description: trust::Attestation claim canonicalization switched MessagePack→RFC8785 JCS (§9.5.2 row5); soundness + JCS f64-int hazard for arbitrary claims
metadata:
  type: project
---

# canonical_attestation_bytes claim = JCS (§9.5.2 row 5), commit a6d74edbd

`crates/scp-protocol/src/trust/attestation.rs::canonical_attestation_bytes`: `claim`
now `crate::jcs::to_vec` (RFC 8785 JCS) instead of `rmp_serde::to_vec_named`.
`evidence`/`revocation_status` stay MessagePack (§9.5.2 note sanctions those two).
Matches governance siblings `compute_proposal_id`(action_bytes)/`compute_vote_hash`(vote_type)
which already use `crate::jcs::to_vec` under UNCHANGED domains SCP-PROPOSAL-V1/SCP-VOTE-V1.

**Construction SOUND:** each field independently length-prefixed via `CanonicalField::VarBytes`
(4-byte BE len) in `crypto::canonical::canonical_hash`; mixed JCS+MessagePack per-field is
unambiguous because every field is self-delimited by its length prefix. Field order per
09-security-model.md:433. Absent=SHA-256(0x00) sentinel. Keeping SCP-ATTESTATION-V1 sound
(pre-release no deployed sigs; domain=message-type binding not canonicalization-version tag;
governance JCS precedent under V1).

**IdentityLinkAttestation** (`identity/attestation.rs::canonical_signing_bytes`, domain
SCP-IDENTITY-LINK-ATTESTATION-V1) correctly UNCHANGED = MessagePack for claim/evidence/revocation,
genuinely mandated by §03:197/230 + Vector 26 (§25.13). Different field order + domain → no cross-collision.

**JCS f64 INTEGER HAZARD (serde_json_canonicalizer 0.3.2 jcs.rs:178 write_u64→write_f64):**
EVERY integer coerced to f64. For `claim` = arbitrary caller `serde_json::Value`, integers >2^53
(~9e15; e.g. Discord/Twitter snowflakes ~1.2e18) lose precision. Consequences: (a) deterministic
within Rust (sign/verify self-consistent); (b) distinct large-int claims collide to same canonical
bytes → signature valid for both → wire-claim tamper within rounding class UNDETECTED (§17 wire
carries exact u64 but signature only commits f64-rounded); (c) cross-impl divergence vs spec's stated
Python `json.dumps` (exact bignum). Governance siblings exposure NEGLIGIBLE (bounded protocol enums,
timestamps<2^53); attestation WORSE (arbitrary claim JSON). Inherent to spec's compact-JSON mandate,
not a code defect — remediation flows UP to spec (constrain claim numbers to I-JSON ±2^53 / string-encode).

**SPEC STALE:** §9.5.2 row-5 note (09-security-model.md:443) still says "compact JSON ~ json.dumps
(separators)" + "key ordering NOT deterministic across implementations" — but code uses JCS (SORTS keys,
deterministic). Governance row (line 490) already names JCS explicitly. Update attestation row to name
RFC 8785 JCS + drop misleading json.dumps/disclaimer + add I-JSON numeric bound. No §25 KAT vector for
trust::Attestation (only Vector 26 for IdentityLink) — add one.

Pinning test `canonical_attestation_claim_is_length_prefixed_compact_json` solid (catches msgpack revert
+ dropped len prefix + asserts JCS key-sort invariance) but does NOT exercise number path.
