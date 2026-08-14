---
name: adr060-monetary-value-representation
description: ADR-060 Amount/Coefficient is_human_readable serde split (JSON string / MessagePack native int) — SOUND, closes prior JCS non-injectivity + missed ToolCost.amount gap
metadata:
  type: project
---

# ADR-060 monetary wire codec — SOUND (branch @f71b78a14, worktree fu-money)

`crates/scp-protocol/src/economy/types.rs`: `Amount(u64)`/`Coefficient(i64)` hand-written
Serialize/Deserialize keyed on `serializer.is_human_readable()`:
- **Human-readable (JSON/JCS)** → canonical base-10 decimal STRING (`serialize_str`).
- **Binary (MessagePack)** → native `u64`/`i64`.

Strict decoder `parse_canonical_u64_str`/`parse_canonical_i64_str`: rejects empty, leading
zeros (except lone "0"), `+`, `-0`, whitespace, separators, `.`, `e`, hex, overflow. Injective.
Coefficient `visit_u64` narrows non-neg rmp ints (rmp dispatches non-neg to visit_u64 even under
deserialize_i64 hint). i64::MIN round-trips ("-9223372036854775808").

**Why:** closes the LIVE governance JCS non-injectivity (bare u64 smallest-units >2^53 f64-coerce
in serde_json_canonicalizer) recorded in [[amount-coefficient-jcs-string-encoding]] and finding-B of
[[canonicalization-cleanup-3part-falsify]]. This is the ADR-blessed successor to @0e855a501.

**How to apply / verification (all confirmed READ-ONLY):**
1. JCS sign==verify: governance uses `crate::jcs::to_vec(&action)` on BOTH sides (proposal_id in
   multisig/majority/unanimity :344/488/327; vote hash mod.rs compute_vote_hash). Single Serialize
   impl; serde_json_canonicalizer-0.3.2 JcsSerializer does NOT override is_human_readable → default
   true → string. NO rmp on any GovernanceAction anywhere (grep clean). No sign-string/verify-int skew.
2. Vector 35 (`DataProvenance.payment_amount: Option<Amount>` → provenance_hash = SHA-256(rmp_serde::
   to_vec)) RESTORED to native-int `12ea6cf5…` (broadcast.rs:2121). String-form `d49aed04…` FULLY
   PURGED from tree (was introduced+removed within-branch: 92a489e44/a0343ceae → af1bdc257). Only
   rmp-hashed economy field.
3. NO dual-form hazard: RegisterTool governance action (JCS, amount→string) and
   `compute_tool_registration_canonical_bytes` (raw u64 BE, registry.rs:567 `tc.amount.0.to_be_bytes()`)
   are DISTINCT commitments over ToolCost.amount, each internally self-consistent. Not sign/verify skew.
4. Coefficient i64 negatives/i64::MIN injective in JCS. Tested.
5. ToolCost.amount retyped u64→Amount; canonical bytes hash raw u64 BE (NOT wire string) → tool-reg
   KAT byte-unchanged. Guard test tool_registration_canonical_bytes_use_raw_u64_be_not_wire_string.

Also closes the MISSED gap from [[amount-coefficient-jcs-string-encoding]] ("ToolCost.amount bare u64
in signed RegisterTool"): RegisterTool JCS now string-encodes amount via the same Serialize impl.
