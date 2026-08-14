---
name: scp-out-043-stream-receipt
description: SCP-XCTX-STREAM-RECEIPT-V1 cross-context streaming-saga receipt crypto (commit 3b07703c6) — VERDICT SOUND
metadata:
  type: project
---

# CrossContextOutletStreamReceipt (SCP-OUT-043, commit 3b07703c6)

VERDICT: SOUND. No crypto findings. File: crates/scp-protocol/src/context/outlets/cross_context_saga.rs (net-new sibling of unary CrossContextOutletReceipt in same file).

**Why:** Streaming-saga receipt mirrors unary receipt EXACTLY; only 2 preimage differences: (1) domain `SCP-XCTX-STREAM-RECEIPT-V1:` vs `SCP-XCTX-RECEIPT-V1:`, (2) slot-6 `Fixed32(stream_manifest_hash)` (RFC-6962 root carried DIRECTLY, no SHA recompute) vs `Fixed32(output_hash=SHA256(output_jcs))`. Verified field-by-field.

**How to apply / facts:**
- Preimage = canonical_hash (crypto/canonical.rs §9.5.1): domain(raw,no-len-prefix) ‖ 9 fields. Domain fed INTO hasher first → bound into digest. VarBytes=4B BE len prefix (caller_did/outlet_registration_id/outlet_invoked_event_id all length-prefixed → splice-free); RawBytes(nonce 16B no prefix, fixed width so unambiguous); Fixed32 no prefix; U8/U64 BE fixed. Unambiguously parseable.
- Domain separation ROBUST: separators feed into SHA-256 → distinct digests; cross-protocol forgery needs SHA collision. All SCP separators prefix-free ("SCP-XCTX-" diverges 'R'/'S'/'D' at char 10; "SCP-OUTLET-" diverges at char 4). Graft-test `stream_and_unary_receipts_reject_cross_separator_signatures` proves unary sig rejected by stream verify & vice-versa even over identical fields. No collision w/ SCP-OUTLET-CREDIT/CHUNK-SIG (different domain+different hasher).
- KAT `stream_receipt_preimage_is_byte_exact` = GENUINELY INDEPENDENT (hand-rolled fresh Sha256 literal bytes, NOT calling signing_preimage). Reproduced by hand: lens 18/11/20 correct.
- Ed25519: plain PureEdDSA (`self.sign(&preimage_32)`) — NOT Ed25519ph despite `SignPrehashedPreimage` trait name ("prehashed"=canonical construction already hashed fields to 32B msg, standard hash-then-sign, same as broadcast envelope). verify_strict (rejects non-canonical R/small-order A → malleability-resistant). Deterministic (RFC8032) → no nonce reuse. Wrong-signer test passes.
- stream_manifest_hash carried directly SOUND per ADR-061: root is binding RFC-6962 commitment to sealed chunk sequence; reproducibility from SagaId-keyed durable capture at seal, not recompute. Receipt commits to whatever 32B given; root↔real-chunks binding is manifest-layer's job (stream.rs, separately SOUND). Correct separation of concerns.
- No new error codes (reuses CrossContextSagaError SCP-SAGA-13000/1/2). Diff = 3 files (outlet.json PRD status, cross_context_saga.rs, mod.rs export). Separator registered spec §9.18.2:1648.
- 23/23 tests pass.
