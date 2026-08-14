---
name: outlet-chunks-billed-manifest-apparatus
description: Outlet streaming chunks_billed manifest wire-invariant — Frontier tautology BLOCKER now RESOLVED (db89f9f24, round-11). Frontier arm/ChunksBilledSource/StreamManifestCommitment DELETED; Sequence path retained for slice-3 SCP-OUT-045 (justified, not dead code).
metadata:
  type: project
---

Branch feat/outlet-xctx-streaming-saga (worktree scp-wt-slice3). Three review passes; BLOCKER now resolved.

## Pass 1 — f96079706: apparatus gave ZERO prod enforcement (Frontier x==x, behind `if let Some(sink)`, bridges pass None). Only load-bearing = `verify_outlet_invoked_event_local` (`<=` backstop).
## Pass 2 — 0b665ae4f: dead-code half fixed (event now persisted) but Frontier tautology only MOVED to append boundary. Still BLOCKER. Self-aware false-confidence comment claimed a separation the data flow didn't have.

## Pass 3 — db89f9f24 (round-11 fix) — BLOCKER RESOLVED ✅
**Why:** The convergent fix I prescribed in Pass 2 was applied exactly.
- `ChunksBilledSource` enum + `Frontier` arm: GONE. `verify_outlet_invoked_event_manifest(event, chunks: &[OutletStreamChunk])` and `append_outlet_invoked_verified(...chunks...)` take the slice directly (stream.rs:1624, builder.rs:294).
- `StreamManifestCommitment` struct + false "avoids tautological comparison" doc comment + `manifest` param on `OutletInvokedEventSink::record`: all GONE.
- Pump persists via plain `append_event` (supervisor.rs:2147 `append_streaming_outlet_invoked_event`; dispatch.rs sink.record(event); adapter stream_settlement_adapter.rs). Grep for ChunksBilledSource/StreamManifestCommitment across crates/ = 0 residual (comments/docs also updated).
- NO tautology relocated: the surviving inline `AuditAnomaly::ChunksBilledSelfMismatch` (dispatch.rs:3287) compares two INDEPENDENT accumulators — `summary.billed_count` (escrow-ledger running tally) vs `summary.manifest_billed` (Merkle-frontier fold). Genuinely fireable. Deletion is terminal.
- No orphaned bindings: `manifest_reference`/`manifest_root` still used by self-mismatch + settlement anchoring.

## Sequence path retained — simplicity verdict: KEEP (justified, NOT dead code)
`append_outlet_invoked_verified` (trait default method, ContextEventLogProvider) → `verify_outlet_invoked_event_manifest` → `verify_chunks_billed`/`compute_chunks_billed_ref`/`compute_chunk_manifest_root` currently have ONLY `#[cfg(test)]` callers (034 AC21 accept / AC22 reject, event_log.rs:1086/1150). Justified because:
- Complete + tested; AC22 proves it actually REJECTS bad events (fireable, not vacuous) — sharp contrast to the deleted tautological Frontier arm.
- Named imminent consumer: **SCP-OUT-045** (status pending, W4, slice 3) — authoritative cross-context reassembly gap-detector at the re-encrypting bridge hop, the retained-chunk-sequence boundary.
- Deleting to re-add in slice 3 would violate CLAUDE.md's explicit no-deferral tenet and discard tested crypto re-derivation.
- **Honest caveat:** justification RESTS on SCP-OUT-045 landing and actually retaining+re-deriving over the sequence. If that story is cancelled or the reassembly layer doesn't retain the sequence, this collapses to dead code — revisit then.

## UPDATE — caveat RESOLVED by SCP-OUT-036 (commit 9475d6d82, slice-3 xctx bridge)
`append_outlet_invoked_verified` → `verify_outlet_invoked_event_manifest` now has a GENUINE PRODUCTION caller: `record_cross_context_a_event` (invoke.rs:4326, called from `run_cross_context_bridge`). The receiving context A records its own OutletInvoked over its independently-reassembled chunk sequence, wire-rejecting a chunks_billed/root mismatch at log-insert. This closes the SCP-OUT-043 carry-forward independent of whether 045 lands — the Sequence/verified-append path is no longer #[cfg(test)]-only. Do NOT re-flag it as dead-code-pending-045.
