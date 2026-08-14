---
name: outlet-streaming-merkle-frontier
description: C5+C1 incremental RFC-6962 MerkleFrontier replacing batch Vec manifest for streaming-outlet billing (commit e6fdf8b1b) — verdict SOUND
metadata:
  type: project
---

Commit e6fdf8b1b (branch feat/outlet-streaming-ffi, worktree scp-wt-ffi): replaced the
pump's retained `Vec<OutletStreamChunk>` with an incremental O(log n) RFC-6962
`MerkleFrontier` (scp-protocol/src/context/outlets/stream.rs ~L1206-1337). VERDICT: SOUND,
no BLOCKER/HIGH/MED.

**Why:** RFC-6962 correctness proven 3 ways: (1) structural proof — frontier is the
canonical binary-decomposition tree (perfect-subtree forest by set-bits of n, folded
right-to-left via `interior(bigger_left, accumulated_smaller_right)`) = RFC recursion split
at largest power of two < n; (2) independent Python RFC-6962 recursive MTH cross-checked
frontier == level-by-level oracle (`compute_chunk_manifest_root`) == recursive-split for
ALL n=0..300 incl 2^k+1 imbalanced; (3) 54/0 Rust tests incl 256-case proptest with
per-prefix root equivalence (len 0..=257). Level-by-level pair-and-promote oracle IS correct
RFC-6962 (not just test-matching frontier). Domain sep: leaf 0x00, interior 0x01, prefix
`SCP-OUTLET-CHUNK-V1:` — frontier+oracle SHARE compute_chunk_leaf_hash/interior_hash so zero
drift risk; tag-after-fixed-prefix gives leaf/interior second-preimage separation.

**How to apply:** billed_count equivalence holds because dispatch pump uses `MerkleFrontier::new()`
(unbounded u64::MAX ceiling) and the gate `StreamGateOutcome::DropAboveCancelAck`
(dispatch.rs:3122) does NOTHING — above-cancel-ack Data chunks never reach ingest_stream_chunk.
Gate view stamped with `next_seq` (outer cursor, dispatch.rs:3024), same seq the forwarded
final_chunk carries → gate drop-decision and frontier-recorded sequence agree. Both
frontier.push and compute_chunks_billed_ref filter on `chunk.sequence` (NOT slice index).
Money path: settlement receipt anchored to `manifest_reference = summary.manifest_billed`
(frontier.billed_count), NOT escrow ledger self-count; anchor_settlement_receipt_to_manifest
caps billed=min(cost×ref, reserved), refund=reserved−billed → billed+refund==reserved always.
On escrow-vs-frontier divergence, event emitted with frontier value + AuditAnomaly::ChunksBilledSelfMismatch (never dropped).

C1 append invariant (event_log.rs:710) enforces only event-LOCAL `chunks_billed <= stream_chunk_count`
(tighter manifest-equality impossible at append — no chunk Vec, ADR-061). "Only payloads that
decode as OutletInvokedEvent are checked" is NOT a bypass: a claim only exists if it decodes,
and decode→check with the same type readers use; malformed payload carries no trustable
chunks_billed. INFO-only: append accepts a forged decoding event with chunks_billed==stream_chunk_count
that over-states billing, but money flows from the pump-computed settlement receipt (independent
of audit event), log is Merkle-chained + membership-gated, pump is sole prod emitter computing
chunks_billed from manifest by construction. Acceptable/documented, not new vuln.
