---
name: scp-out-043-stream-receipt-3b07703c6
description: SCP-OUT-043 SCP-XCTX-STREAM-RECEIPT-V1 streaming-saga receipt crypto @ 3b07703c6 (feat/outlet-xctx-streaming-phase1, scp-wt-slice3) — ALIGNED, all 8 ACs faithful, PRD reword legit, 1 LOW re-export nit
metadata:
  type: project
---

Reviewed commit 3b07703c6 (net-new `CrossContextOutletStreamReceipt` + `...Fields` in cross_context_saga.rs, mod.rs re-export, 1-line outlet.json AC reword). VERDICT ALIGNED.

**Why (faithfulness):** Mirrors the unary `CrossContextOutletReceipt` sibling EXACTLY (cross_context_saga.rs:198-334). Preimage field order identical, `Fixed32(output_hash)`→`Fixed32(stream_manifest_hash)` in the output slot only (code line ~222). Separator `STREAM_XCTX_RECEIPT_DOMAIN = "SCP-XCTX-STREAM-RECEIPT-V1:"` matches §9.18.2:1648 registration byte-for-byte and §6.2.5:366 ("distinct SCP-XCTX-STREAM-RECEIPT-V1 separator carrying the 32-byte manifest root directly, reproduced on replay from SagaId-keyed durable capture") and ADR-061 "Receipt (streaming)" (node-side, seal-close, root carried directly). sign/verify use `sign_prehashed_preimage`/`verify_strict` identical to sibling. All 8 ACs faithful: AC1 const✓ AC2 stream_manifest_hash:[u8;32] no output_hash✓ AC3 KAT byte-exact preimage test✓ AC4 sign(key,fields)->Result<Self,CrossContextSagaError> + tamper test✓ AC5 cross-separator rejection test✓ AC6 deterministic replay-repro, no Vec chunk field✓ AC7 unary unchanged (diff never touches unary struct/preimage)✓ AC8 test helpers (test_signing_key, Sha256) already in test mod, compiles.

**PRD reword LEGITIMATE (not a weakening):** original AC4 named `sign(fields, signing_key) -> Self` + `verify -> Result<(), ReceiptError>`. `ReceiptError` DOES NOT EXIST anywhere in crates/ (grep confirms zero). Reword to `sign(target_signing_key, fields) -> Result<Self, CrossContextSagaError>` matches the REAL unary sibling exactly = correct spec-fixes-story flow (story named nonexistent type + wrong arg order/return). No AC diluted; reword TIGHTENS (adds "reusing CrossContextSagaError — no new error type") and makes sign fallible (Result, more honest re preimage construction). Classic legitimate story-correction to match reality.

**LOW (re-export asymmetry, coder-flagged):** streaming re-exports `CrossContextOutletStreamReceiptFields` from outlets/mod.rs:67; unary does NOT re-export `CrossContextOutletReceiptFields`. HARMLESS: `pub mod cross_context_saga` (mod.rs:49) so both reachable; real unary callers (scp-runtime state.rs:3034, handlers/saga.rs:64, supervisor.rs:21019/25816...) import via the deep `cross_context_saga::` path. Streaming's choice (mod.rs re-export) is the BETTER pattern; unary is the laggard. Fix = add unary Fields to mod.rs re-export for symmetry (out of this story's scope). Not a defect.

**OBS:** new streaming type has ZERO external consumers yet (only mod.rs re-exports it) — seal-phase wiring is future SCP-OUT-046; consistent with ADR-061 "streaming saga planned" status. No FFI/SDK surface (correct: pure protocol crypto primitive, node-delegated per ADR-057, "no SDK verb").
