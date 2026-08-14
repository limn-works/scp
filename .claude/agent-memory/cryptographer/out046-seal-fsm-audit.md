---
name: out046-seal-fsm-audit
description: SCP-OUT-046 streaming-saga seal-phase FSM crypto audit (branch feat/outlet-xctx-046-seal-fsm, HEAD 18f6fd11c) — SOUND; deliver-before-capture prefix edge is the only substantive finding.
metadata:
  type: project
---

# SCP-OUT-046 seal-phase FSM crypto (HEAD 18f6fd11c; base bc4464566)

Verdict: cryptographically SOUND. Files: saga.rs (commit_b_stream_first_settle, build_signed_stream_receipt),
outlets/invoke.rs (run_streaming_saga_seal_task, record_streaming_saga_a_event), supervisor.rs
(recover_streaming_saga_truncated_close 6818, recover_streaming_committing_entry 7767, streaming_saga_target_hex 7753).
Primitives (pre-existing, in scp-protocol outlets/stream.rs + cross_context_saga.rs).

## Confirmed sound
- MerkleFrontier.root() == compute_chunk_manifest_root (RFC-6962 §2.1, forest-of-perfect-subtrees fold =
  recursive MTH). Prefix property holds: frontier after k pushes == batch oracle over chunks[0..k] (property
  test stream.rs ~3048). leaf 0x00 / interior 0x01 domain sep → no 2nd-preimage. Truncated close seals the
  durable prefix root soundly.
- Receipt SCP-XCTX-STREAM-RECEIPT-V1: domain-separated, length-prefixed VarBytes, verify_strict, signed by
  target(B) Active key (SigningKeyBytes.to_signing_key), verified against B's Active key (caller resolves).
  Binds caller/target ctx ids, caller_did, nonce, outlet_reg_id, stream_manifest_hash, outlet_invoked_event_id
  (="OutletInvoked:{saga_id}", saga_id=uuid v4 CSPRNG), chain_depth, timestamp_ms. Per-saga event_id ⇒ no
  cross-stream substitution. Replay re-emits STORED receipt byte-for-byte (reemit_committed_stream_settle).
- NO private key persisted: SigningKeyBytes = zeroize::Zeroizing<[u8;32]>, no derive Serialize; SagaPhaseMessage
  carries oneshot reply (unSerializable). Prepared slot + CommittedStreamingOutletInvocation witness + journal
  (empty evidence, public metadata only) hold NO key. Key only in-memory as fn param.
- Keyless startup sweep (recover_streaming_committing_entry): witness present→Committed (idempotent, no re-sign),
  witness absent→NeedsRepair + escrow HELD. CANNOT forge/skip a sig — key-bearing recover_streaming_saga_truncated_close
  takes target_signing_key explicitly (FFI reconnect). No signature fabricated without a key.
- Operator chunk sigs (SCP-OUTLET-CHUNK-SIG-V1, verify_strict) verified via verify_forwarded_chunk BEFORE
  forward AND before StreamCaptureAppend fold — unverified chunk never enters frontier/billing. request_id
  pinned at gate. billed_count = frontier Data-leaf count ≤ leaf_count ≤ delivered (manifest binds billed set).

## Findings (non-blocking)
1. MEDIUM/LOW — deliver-before-capture (§6.2.5 by design): chunk forwarded to caller BEFORE StreamCaptureAppend.
   On a capture-break (actor vanished/diverged, capture_broke=true) the delivered set exceeds the sealed
   manifest by the in-flight chunk. Effects: (a) UNDER-bills by 1 (fail-safe, B eats it); (b) breaks the
   SCP-OUT-043 caller-side "recompute root over received chunks == receipt root" equality on an HONEST
   capture-break → false-positive divergence → NeedsRepair (fail-closed, not a forgery); (c) capture_broke is
   excluded from the synthesized-terminal block, so caller truncates after a non-terminal Data (loses the
   terminal guarantee) on that path. Direction is always fail-safe; no over-commit ever (every manifest leaf
   was forwarded first).
2. LOW — receipt binds NEITHER billed_count NOR request_id DIRECTLY. request_id + billed set bound only
   TRANSITIVELY via manifest root (each leaf JCS includes request_id; billed_count recomputable from Data
   leaves). Pure-receipt auditor (no chunks) can't verify billed amount/request_id from receipt alone —
   inherited OUT-043 limitation. Billing auditable via per-ctx event-log chunks_billed leaves, not receipt.
3. LOW — billed ≤ reserved has NO defensive assertion at the seal; refund=reserved.saturating_sub(billed).
   Holds structurally (frontier only folds pump-emitted chunks; pump credit ceiling bounds count) but a cheap
   billed_count ≤ reserved_chunks assert at settle would make the seal self-defending vs an upstream pump bug.
4. LOW (doc nit) — "the REAL 32-byte root — never [0u8;32]" (saga.rs commit_b_stream_first_settle) overclaims:
   an empty/zero-chunk sealed prefix legitimately yields root=[0;32] (honest empty-stream attestation, zero
   billed, domain-separated — harmless). Comment is inaccurate.
