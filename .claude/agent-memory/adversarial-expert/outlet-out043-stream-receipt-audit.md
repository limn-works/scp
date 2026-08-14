---
name: outlet-out043-stream-receipt-audit
description: SCP-OUT-043 CrossContextOutletStreamReceipt crypto audit (commit 3b07703c6) — SHIP; sound Ed25519-over-canonical primitive, unwired by design; weakest point = root binds content not billed amount.
metadata:
  type: project
---

# SCP-OUT-043 streaming-saga receipt crypto (commit 3b07703c6)

`CrossContextOutletStreamReceipt` in crates/scp-protocol/src/context/outlets/cross_context_saga.rs.
Mirrors unary `CrossContextOutletReceipt` exactly; swaps `Fixed32(output_hash)` → `Fixed32(stream_manifest_hash)` (RFC-6962 root carried directly) under distinct separator `SCP-XCTX-STREAM-RECEIPT-V1:`.

**Verdict: SHIP.** Crypto is sound. Ed25519 `sign_prehashed_preimage` (plain sign over 32-byte SHA-256 canonical preimage) + `verify_strict` (rejects malleability/torsion). Length-prefixed VarBytes → splice-safe. Domain-separated. All 9 fields bound.

All 8 ACs genuinely met. 8 new tests all assert real REJECTION (tamper-each-of-9-fields, wrong-signer, cross-separator graft) — not vacuous. KAT hand-rolls SHA-256 byte-exact. cargo test -p scp-protocol passes (23/23 in module).

**PRD reword ReceiptError→CrossContextSagaError is HONEST** — corrects story to match established unary pattern (fallible Result, no new error type), which story prose already demanded. Not a scope-dodge.

**Weakest points (all out-of-scope wiring, not defects here):**
1. Type has ZERO consumers — unwired. Seal-phase capture (SCP-OUT-046) + caller-side compare are future slices. ADR-061 line 80: production sites hardcode `stream_manifest_hash: [0u8;32]` today.
2. verify() confirms signature-over-root but CANNOT confirm root-matches-received-content (no inline bytes by design). Caller MUST independently recompute root from received chunks + compare — that obligation is NOT in this primitive. ADR-061 acknowledges: pure-receipt auditor gets root-binding only.
3. Receipt binds CONTENT (root) but NOT billed amount. Billing integrity = separate escrow/verify_chunks_billed reconciliation (ADR-061 line 80). Receipt alone is not a billing attestation.

**Nits:** cross-separator test over-determined (preimages differ in separator AND output-slot value, doesn't isolate separator — but domain-distinctness separately asserted). String fields (caller_did, outlet_registration_id, outlet_invoked_event_id) unbounded at type level; bounded only by §9.10.3 envelope — consistent with unary sibling.
