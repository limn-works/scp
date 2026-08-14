---
name: adr061-streaming-saga-manifest
description: ADR-061 outlet invocation modes + ported streaming primitives (stream.rs credit/escrow/manifest, signer.rs custody seam) crypto review
metadata:
  type: project
---

# ADR-061 streaming saga + ported streaming primitives (@69fdd7ae8, branch feat/outlet-streaming-runtime)

Reviewed: ADR-061, runtime `context/outlets/stream.rs`+`signer.rs`, protocol `context/outlets/stream.rs`+`lifecycle.rs`+`cross_context_saga.rs`, spec §6.2.4/§6.2.5.

**Verdict: the ported cryptographic PRIMITIVES are SOUND.** All 5 claims hold as constructions. Main caveat: streaming-saga is NOT wired to production (ADR marks it "planned") — several claims are design-correct but unenforced in code.

- **Manifest (`compute_chunk_manifest_root`, protocol stream.rs:1127)** = genuine RFC 6962. leaf=SHA256(SCP-OUTLET-CHUNK-V1: ‖ 0x00 ‖ jcs(chunk)), interior=…‖0x01‖L‖R. Bottom-up pairing PROMOTES odd node without duplication (verified equal to RFC6962 split-at-largest-pow2 for n=5,6,7,9,11,13) → immune to CVE-2012-2459 (Bitcoin dup). Bounded 32B. Binds order+count (leaf also commits `sequence` field AND `sig`). SOUND.
- **`compute_chunks_billed_ref` is a DIFFERENT function** from the manifest root — it's the BILLING count (Data chunks with sequence<=cancel_ack_seq), not the integrity commitment. Task prompt conflated them.
- **Chunk sig (`compute_chunk_sig_preimage`, protocol stream.rs:486)**: domain-sep + len_be32(context_id/outlet_id) + request_id(16)+seq_be(8)+caveats_binding(32)+SHA256(jcs(payload))(32). Pure Ed25519 both sides (sign_chunk `key.sign(preimage)` / verify `verify_strict(preimage,sig)`). Signer signs 32B digest verbatim (no re-hash). Binds cross-stream/cross-position. Does NOT bind stream_epoch (relies on request_id uniqueness + caveats_binding pinning) — acceptable.
- **Receipt swap output_hash→stream_manifest_hash (claim 3): NOT IMPLEMENTED.** `CrossContextOutletReceipt` (cross_context_saga.rs:128) still commits Fixed32(output_hash) recomputed from carried `output_jcs`. No stream_manifest_hash field. Swap is shape-preserving Fixed32→Fixed32 AND replay-deterministic IFF root captured durably at close keyed by SagaId (never recomputed by re-executing) — ADR/§6.2.4 state exactly this. GAP: reproducibility MECHANISM differs — output_hash = carry-bytes-recompute; manifest root must be carried DIRECTLY (can't carry unbounded chunks) + reproduced from durable capture. Spec/ADR gloss this substitution.
- **Wiring gaps (consistent w/ "planned", flag not break):** `compute_chunk_manifest_root` has ZERO prod callers; every prod site hardcodes `stream_manifest_hash:[0u8;32]` (invoke.rs:635, uniffi bridge.rs:4861, mcp.rs:1062). `verify_chunks_billed`/`EventLogError::ChunksBilledMismatch` has NO append-path caller (tests only).
- **Billing/over-bill (claim 4): SOUND.** cancel_ack_seq = receiver next-to-emit cursor (record_cancel), NOT operator-controlled; chunks>ceiling excluded. `max_billable` HARD ceiling folds max_calls AND floor(amount_max_cumulative/cost) (effective_max_billable_chunks); replenish_clamped keeps billed_emitted+remaining<=max_billable so no grant raises ceiling. Per-chunk credit invoker-signed (SCP-OUTLET-CREDIT-V1). chunks_billed verifiable vs manifest. Residual: no single primitive jointly checks chunks_billed AND manifest_root derive from same chunk slice; escrow settle billed_count not cross-checked to manifest — reconcile when wiring.
- **Custody isolation (claim 5): SOUND.** StreamSigner trait exposes only async sign(digest)->[u8;64] + verifying_key(); operator privkey never in runtime structs. InProcessStreamSigner is `#[cfg(any(test,feature=testing))]` only; Debug redacts key. Signer receives only 32B SHA-256 digest — never plaintext chunk content. Error `Custody{detail}` sanitization is a DOCUMENTED implementor contract (not mechanically enforced) — residual leak risk if a native custody adapter is careless.
- JCS injectivity for arbitrary Data payload: NOT a meaningful finding here (serde_json_canonicalizer preserves i64/u64 exactly; only f64 goes through RFC8785 float algo; round-trips via MessagePack) — unlike the attestation bare-u64 case.
