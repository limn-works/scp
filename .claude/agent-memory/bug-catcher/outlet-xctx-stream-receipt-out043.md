---
name: outlet-xctx-stream-receipt-out043
description: SCP-OUT-043 CrossContextOutletStreamReceipt crypto review (3b07703c6, feat/outlet-xctx-streaming-phase1) — CLEAN
metadata:
  type: project
---

# SCP-OUT-043 streaming-saga receipt (SCP-XCTX-STREAM-RECEIPT-V1)

Commit 3b07703c6 added `CrossContextOutletStreamReceipt` + `...Fields` in
crates/scp-protocol/src/context/outlets/cross_context_saga.rs beside the unary
`CrossContextOutletReceipt`.

**CLEAN, 0 defects.** Line-by-line vs unary sibling: only intended divergences —
(1) `STREAM_XCTX_RECEIPT_DOMAIN = "SCP-XCTX-STREAM-RECEIPT-V1:"` separator (matches
§9.18.2 registry row, distinct from unary + divergence), (2) output slot binds
`Fixed32(&self.stream_manifest_hash)` DIRECTLY (carried root, no SHA-256 recompute)
in place of unary's `Fixed32(&output_hash)`. Preimage field order identical & matches
normative §6.2.4/§6.2.5: caller_ctx, target_ctx, VarBytes(caller_did), RawBytes(nonce16),
VarBytes(reg_id), Fixed32(hash-slot), VarBytes(event_id), U8(chain_depth), U64(ts_ms).

- All 9 preimage fields present on struct; no field-in-struct-not-preimage (signature excluded, correct) or vice-versa.
- Encoding: U8/U64 BE via canonical_hash, nonce RawBytes(16), hashes Fixed32; canonical_hash uses u32::try_from → error (no panic). serde try_into → error. No unwrap/expect on wire input.
- verify(): `Signature::from_bytes(&[u8;64])` INFALLIBLE in ed25519-dalek 2.2.0 (no panic); verify_strict → SignatureInvalid on mismatch; no Ok-on-bad-sig path.
- serde: stream_manifest_hash uses serde_hash_32 (symmetric, len-checked); signature serde_signature_64; nonce serde_nonce_16 — all round-trip.
- 23 tests pass (8 streaming, 0 ignored, all assert); clippy -p scp-protocol --all-features clean.

Non-defects noted: mod.rs re-exports StreamReceiptFields but unary ReceiptFields was
never re-exported (pre-existing cosmetic asymmetry). String fields (caller_did,
reg_id, event_id) deserialize unbounded (no serde_bounded_string) — matches unary
sibling exactly, pre-existing pattern, not introduced here.
