---
name: outlet-pr2-port-crypto-faithful
description: PR-2 outlet re-port (feat/outlet-report-pr2 @f0d2d5130) — all signed/hashed constructions byte-faithful to origin/feat/outlet-redesign; Amount-over-u64 keep is crypto-inert via MessagePack native-u64 path
metadata:
  type: project
---

# Outlet PR-2 port — crypto SOUND, faithful port (@f0d2d5130)

Diff = `git diff feat/outlet-report...HEAD` (base = 5cd7110f9, PR-1 tip). Ports outlet SIGNED/HASHED types from `origin/feat/outlet-redesign`. VERDICT: faithful port, reconcile did NOT alter any signing input.

**Why:** RE-review of ADR-057-era crate split + ADR-060 Amount reconcile landing on outlet types.
**How to apply:** if PR-2 re-reviewed, this is the byte-faithfulness evidence; the ONE risk vector (Amount cost_hash) is closed.

## hash.rs (SCP-OUTLET-REGISTRATION-V2:) — BYTE-IDENTICAL to branch
`diff` of full file = IDENTICAL. Preimage layout, field order, BE32 length-prefix helper (push_length_prefixed, u32::try_from saturate), kind_byte term (kind.canonical_byte 0x00 Query/0x01 Action, verified identical), all 32-byte hash terms (description/schema/impl/test_vectors/cost/catalog), BE64 registered_at — all unchanged. Domain `b"SCP-OUTLET-REGISTRATION-V2:"` identical.

## stream.rs — ONLY delta = import repoint scp_primitives::DID → scp_did::DID (crate topology, ADR-057). Crypto-inert (DID enters preimages via .as_bytes() on string form). All domains byte-identical at identical line#: SCP-OUTLET-CHUNK-SIG-V1:, SCP-OUTLET-CREDIT-V1:, SCP-OUTLET-CHUNK-V1: (Merkle leaf 0x00/interior 0x01 RFC-6962), SCP-OUTLET-CAVEAT-BIND-V1:, SCP-OUTLET-CANCEL-V1:. compute_caveats_binding, per-chunk/credit/cancel Ed25519 preimages, chunk-manifest Merkle — all identical.

## Amount-over-u64 keep — CRYPTO-INERT (the key finding)
OutletCost.amount: branch=`u64`, HEAD=`Amount` (crate::economy::types::Amount, newtype `pub struct Amount(pub u64)`). cost_hash = SHA-256(rmp_serde::to_vec(&OutletCost)). Amount::Serialize: `if is_human_readable() { serialize_str(decimal) } else { serialize_u64(self.0) }`. rmp_serde default Serializer::is_human_readable()==FALSE → takes serialize_u64 path → MessagePack bytes IDENTICAL to bare u64 field. cost_hash term unchanged. Field doc says "canonical decimal string" (true for JSON wire) but hash path is MessagePack — hash.rs doc correctly says MessagePack(cost). NO dual-form hazard: sole hash-path cost use = rmp_serde::to_vec at hash.rs:152; the 2 serde_json::to_value cost calls (registry.rs:1569/1583) are #[test]-only, positively assert ADR-060 JSON string form, touch NO signing path.

## registration.rs deltas — all mechanical Amount-keep: DID import repoint; `cost.amount > 0` → `cost.amount.0 > 0` (validation, not preimage); test ctors `amount: N` → `amount: Amount(N)` (same value). None touch preimage.

## KATs — self-recomputing, none stale. grep for hex!/[0x..,]/from_hex in ALL outlet test modules = ZERO hardcoded hash/sig literals. hash.rs tests recompute expected via Sha256::digest(...) inline → immune to Amount type change. New tests (outlet_cost_amount_serializes_as_canonical_decimal_string) correctly pin ADR-060 JSON string form (strengthening). `cargo test -p scp-protocol --lib outlets` = 372 passed / 0 failed (all chunk/credit/cancel/caveats/Merkle verify tests green).

## SCP-XCTX-* — untouched. cross_context_saga.rs (holds SCP-XCTX-RECEIPT-V1:/SCP-XCTX-DIVERGENCE-V1:) is PRE-EXISTING base file on feat/outlet-report (NOT ported from branch — absent on origin/feat/outlet-redesign). PR-2 leaves it byte-identical vs base; NOT in PR-2 diff. mod.rs `pub mod cross_context_saga` already on base.

## mod.rs — Tool*/Outlet* name reconcile (ToolIdMismatch, Capability::ToolRegister/ToolInvoke*) keeps BASE Tool* names where branch renamed to Outlet*. Rust identifiers, NOT preimage bytes — crypto-inert.
