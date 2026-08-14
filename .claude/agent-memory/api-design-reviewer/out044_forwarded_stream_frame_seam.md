---
name: out044-forwarded-stream-frame-seam
description: API review of ForwardedStreamFrame — the pub(crate) runtime seam SCP-OUT-045/047 build on. APPROVED with two minor DX notes.
metadata:
  type: project
---

# SCP-OUT-044 `ForwardedStreamFrame` seam review (commit b9b333f69, branch feat/outlet-xctx-044-base-sequence)

Reviewed the cross-context outlet-stream return-type change: `open_outlet_stream_cross_context` / `invoke_outlet_cross_context` now return `Receiver<ForwardedStreamFrame>` instead of bare `Receiver<OutletStreamChunk>`.

Type (invoke.rs:4362): `pub struct ForwardedStreamFrame { pub base_sequence: u64, pub chunk: OutletStreamChunk }`. Debug-only, never serialized, struct-literal construction only (a `new`/`.anchor()` accessor would trip check-cross-layer). Minimal, self-evident, excellent rustdoc.

**Verdict: APPROVED.** Well-designed, misuse-resistant. Only two minor non-blocking DX notes:
1. Two sibling `u64` sequences — `frame.base_sequence` (per-sender MLS send-seq, gap-detector key) vs `frame.chunk.sequence` (operator per-request index). Rustdoc says key on `(request_id, base_sequence)` but never warns AGAINST `chunk.sequence`. One negative sentence on the base_sequence field doc would close the only silent-misuse path.
2. Rustdoc points to SCP-OUT-045 (gap-detector) but not SCP-OUT-047 (streaming-saga FFI, the other consumer of this seam).

**Why:** These are the contract 045 (authoritative reassembly gap-detector) and 047 (FFI export) build on. When reviewing 045/047, verify they key on `frame.base_sequence` not `frame.chunk.sequence`, and that 047's FFI export of the frame keeps base_sequence:u64 + wire-exportable chunk.

**How to apply:** Same-context path deliberately stays bare `Receiver<OutletStreamChunk>` (no off-mailbox bridge, no load-bearing gap-detector, actor owns send_tracker) — do NOT flag that asymmetry as inconsistency; forcing uniformity would add a field no same-context consumer reads. base_sequence is allocated-at-consumption via ADR-049 §8 SequenceReservation RAII guard (rolls back on send failure, no gap burned).
