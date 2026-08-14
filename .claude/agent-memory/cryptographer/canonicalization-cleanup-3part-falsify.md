---
name: canonicalization-cleanup-3part-falsify
description: Adversarial falsification of a 3-part JCS/MP canonicalization cleanup (provenance hash unify, I-JSON 2^53 generalization, attestation evidence/revocation→JCS) against origin/main ee07d5bac
metadata:
  type: project
---

# 3-part canonicalization cleanup — falsification (origin/main @ ee07d5bac, PR #2024)

Reviewed READ-ONLY. Verdicts: A=AMEND, B=REJECT-as-stated/AMEND, C=AMEND(split).

**Why:** proposed cleanup conflates deterministic-serde-json with RFC8785 JCS, and would move arbitrary numeric data INTO non-injective JCS while another part frets about JCS non-injectivity — internal contradiction.

**How to apply:** if this plan resurfaces, enforce the per-site design below, not a blanket rule.

## Part A — provenance hash (AMEND, not "unify to JSON")
- 3 sites, 2 structs. FFI (pyo3/napi/uniffi, all Rust — WASM gone) hash `DataProvenance` via `serde_json::to_vec` → event-log ProvenanceAttached/Received LEAF payload. Native `broadcast::compute_provenance_hash` (DataProvenance) + `envelope::inner::compute_provenance_hash` (different struct `envelope::inner::Provenance`) via `rmp_serde` → SIGNED envelope preimage.
- FFI comments say "JSON-serialized" (accurate), NOT "canonical". The false "canonical JSON (RFC 8785)" + phantom §5.14/§25 citation lives in NATIVE doc comments (envelope/inner/mod.rs ~478, broadcast.rs ~350). serde_json is declaration-order not lexicographic → NOT JCS (DataProvenance has no maps so it's deterministic, just not RFC8785).
- No spec rule exists: §5.14.5:1526 says generic `SHA256(serialize(provenance))`; §24 says nothing. No KAT pins DataProvenance→hash (§25 V5/6 feed literal provenance_hash 0xabcdef).
- Sites never cross-compared today → no live bug. Latent footgun: future "logged-provenance == message-provenance" check fails across encodings.
- FIX: unify FFI event-log hash to rmp (matches event-log leaf which is already SHA256(0x00||rmp_serde(event)) + the 2 signed paths). Do NOT convert signed paths to JSON. Correct native doc; add real §5.14.5/§24 sentence + KAT.

## Part B — |n|≤2^53 generalization (REJECT blanket; live bug found)
- Current rule §9.5.2:443 = claim only. Line 490 governance action_bytes cites JCS but NOT the bound. `crate::jcs` (serde_json_canonicalizer) does NO range check → rule UNENFORCED today (even for claim = aspirational MUST = latent hole).
- LANDMINE is NOT timestamps (all sites use secs/ms, safe). It's economy `Amount(#[serde(transparent)] u64)` (economy/types.rs:28) = smallest currency unit → 18-dec token 1e18 >> 2^53(9.007e15); 0.01 token=1e16>2^53. Flows to JCS action_bytes via GovernanceAction::ApproveSpend.amount, EconomicPolicy/SubscriptionCost/PricingFormula/ToolCost.amount (jcs::to_vec majority.rs:488, mod.rs:1693, multisig.rs:345, unanimity.rs:328).
- => LIVE governance signature non-injectivity TODAY: ApproveSpend(1e16)≡ApproveSpend(1e16+1) same JCS bytes/sig; at 1e18 collision window = ULP(256 units). "Close is not correct."
- Arbitrary-JSON sites also >2^53: challenge params/result Value, tool schema/test-vector Value, cross_context output_jcs (jcs::to_string(tool_output) — highest risk, receipt signs output_hash). Site 5 app_sandbox = SAFE (max_message_size u64 bytes 9PB ceiling; u32 counters).
- FIX per-site: economy → string-encode Amount/Coefficient (or binary CanonicalField), NOT reject; regen governance KATs. Arbitrary sites → prefer INJECTIVE MP, or enforced-reject + tool-author string-encode obligation. Site 5 → rule fine. ENFORCE at crate::jcs, don't just document.

## Part C — attestation evidence/revocation→JCS (AMEND: split)
- IdentityLink claim/evidence/revocation→JCS = SAFE (String/enum/DID/u64-secs; proof=opaque String §3.5.2; no bytes in preimage-sigs excluded; no f64; no non-string keys).
- trust::Attestation revocation_status→JCS = SAFE (Active/Revoked{revoked_at u64 secs,reason String,revoked_by DID}).
- trust::Attestation EVIDENCE→JCS = UNSAFE. `AttestationEvidence{evidence_type:String, data: serde_json::Value}` — data arbitrary JSON, MP(injective all u64/i64/f64)→JCS(non-injective >2^53, f64→ES6 shortest) = net loss. Contradicts Part B. §9.5.2 note kept evidence=MP deliberately. KEEP evidence MP, OR only convert under enforced ≤2^53 + collision KAT matching claim.
- JCS lib = serde_json_canonicalizer via crate::jcs. canonical_attestation_bytes attestation.rs:1183 (evidence/revocation rmp_serde::to_vec_named 1186-1200); identity canonical_signing_bytes 556 (3 rmp calls 560/565/571).
- Regen (Rust-only, NO bindings/ re-derive): Vector 26 §25.13; Vector 34 §25.20 (pins hash 0x6d07c76821a2ae4dd830ca117aa9fd8e30232cca72459a4d129432f56d87a08c, 197B); §9.5.2 rows 6/9+note; §03:230; phase-6.md; tests test_vectors.rs V26/V34, phase5_integration.rs, conformance.rs CONF-004, trust.rs builder, attestation.rs+identity/attestation.rs doc/tests. forward_compatibility_conformance.rs = wire-format (MP storage) not preimage → reviewer judgment.
- Event-log KEEP: leaf=SHA256(0x00||rmp_serde::to_vec(event)) tree.rs:281/296. Spec pins only SCP-EVENT-V1 hash "field order from code" + synthetic-payload leaves V16-18. rmp positional/minimal-int/no-map contract NOT spec-stated → "make explicit" is REAL work (add positional-array/decl-order/minimal-width/no-map clauses + real-Event KAT), not a no-op.

## Concurrent-session overlap
- Spec: user WIP = 05-contexts.md only; B/C = 09/03/25/phase-6 → NO spec collision.
- Code: user WIP = runtime governance_helpers.rs/lifecycle_helpers.rs + uniffi/bridge.rs (FFI-02/InvitationBundle). C touches scp-protocol trust/identity only → LOW file collision.
- REAL hazard: FFI-02 §5.14 0xFF02 ext carries JCS-hashes of governance_policy/ceiling (per project memory, though §5.13.2 spec text still says canonical_msgpack — discrepancy). If Part B changes governance JCS encoding (string-encode Amount), it changes those 0xFF02-committed hashes → two sessions defining conflicting canonical form for governance data. SEQUENCE B after/with FFI-02.
