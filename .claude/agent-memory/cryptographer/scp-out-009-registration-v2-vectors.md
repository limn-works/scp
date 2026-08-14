---
name: scp-out-009-registration-v2-vectors
description: SCP-OUT-009 SCP-OUTLET-REGISTRATION-V2 conformance vectors re-port verification (recovery commit 4d5896528) — goldens byte-correct, not gamed
metadata:
  type: project
---

SCP-OUT-009 V2 registration vectors (tests/conformance/vectors/outlet_registration_v2.json, recovery commit 4d5896528 on fix/outlet-recover-010-027-009) VERIFIED SOUND — goldens byte-correct + not gamed.

**Why:** recovery regenerated goldens because orphaned pre-port bytes (at b5a25f142) were signed under a STALE placeholder preimage. Confirmed genuinely stale: old minimal-query canon 6aeebe1b… had input with NO `kind` field, inlined RAW UTF-8 description + RAW JSON schemas (len-prefixed) instead of description_hash/schema_hash, and NO catalog_hash term. Current canon 40152a10…. Regeneration necessary + correct.

**How to apply:** §5.4.1 preimage (crates/scp-protocol/src/context/outlets/hash.rs `outlet_registration_v2_preimage`): `"SCP-OUTLET-REGISTRATION-V2:" || BE32len(outlet_id)||outlet_id || kind_byte(0x00 Query/0x01 Action) || BE32len(name)||name || SHA256(description) || BE32len(operator_did)||operator_did || SHA256(rmp(schema)) || implementation_hash[32] || SHA256(rmp(test_vectors)) || cost_hash(SHA256(rmp(Some cost)) else SHA256(0x00)) || catalog_hash(empty=SHA256(0x90)) || BE64(registered_at)`. Amount serializes NATIVE u64 in msgpack (str only in JSON). OutletSchema/OutletTestVector/OutletCost = rmp POSITIONAL arrays (compact to_vec), aggregate_schema/cost_formula skip_serializing_if None. serde_json no preserve_order → Object maps sorted-key.

I INDEPENDENTLY reproduced all 12 vectors byte-exact in Python (own msgpack encoder matching rmp-serde, own layout, hashlib, cryptography Ed25519): preimage hex + canonical hash + Ed25519 sig verify under pk d75a9801… (RFC-8032 TV1). vector0 canon=40152a10…. Tamper test (flip 1 desc char) → canon changes + stored sig REJECTS. V1 rejection corpus (12): all v1!=v2, all SCP-TOOL-REGISTRATION-V1: domain. 4 Rust conf tests pass (043 shape/044 sign-verify/045 v1-reject/046 generator-drift).

MINOR (not a defect): harness compute_v2_preimage (outlet_registration.rs:550) reuses the pinned sub-hash primitives (description_hash/schema_hash/cost_hash/catalog_hash) from scp_protocol, so CONF-044/046's internal "manual==core" assertion is only PARTIALLY independent (layout/framing independent, hash-term computation shared — acknowledged in its own doc comment L543-548). Fully closed by: frozen on-disk goldens + stored Ed25519 signature (real crypto anchor) + my fully-external repro.
