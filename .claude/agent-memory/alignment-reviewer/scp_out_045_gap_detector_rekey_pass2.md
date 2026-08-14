---
name: scp-out-045-gap-detector-rekey-pass2
description: SCP-OUT-045 gap-detector re-key pass-2 confirmation — code+story fixed to chunk.sequence, but residual mis-key scar tissue survives in sibling stories 044 (done) + 049 (pending)
metadata:
  type: project
---

# SCP-OUT-045 gap-detector re-key — pass-2 (2026-07-16) — NEEDS DISCUSSION

Branch feat/outlet-xctx-045-gap-detector, HEAD d7512ef21 (whole 045 = one commit).
Pass-1 (inquisitor, memory scp-out-045-gap-detector-wrong-key) BLOCKER: detector keyed on
`base_sequence` (locally-minted by bridge SendSequenceTracker, contiguous by construction) →
tautological, could never fire on real loss. §5.4.5:513/:515 keys on `sequence`.

**Code + 045 story fix = CONFIRMED spec-faithful.** `ReassemblyGapDetector` (invoke.rs:4456)
`expected:0`, `observe(chunk.sequence)` at invoke.rs:4963 runs BEFORE forward_frame reserves
base_sequence. Real drop (0,1,2,4) fires: observe(4) vs expected 3 → Gap. Bridge test
`out045_dropped_chunk_fires_stream_gap` (invoke.rs:9091) uses REAL drive_bridge path w/
operator-signed chunks seq 0,1,2,4 — no synthetic seam. `ObservedBaseSequenceProbe` DELETED
(0 matches tree-wide). "047 relay-provided" framing gone from 045 story + code. Dual-locus
honest: bridge (045 on chunk.sequence at reassembly boundary) vs 037 SDK-drain
(ReceiverSequenceTracker, also sequence, at SDK InvocationHandle) = diff layers, real
defense-in-depth. base_sequence retained ONLY for SCP-OUT-047 A-context re-seal (code doc
invoke.rs:4370-4374), NOT the gap key.

**RESIDUAL SCAR TISSUE (2 findings — re-key did not sweep siblings):**
1. SCP-OUT-044 (status=done) still asserts 045 keys on base_sequence — FALSE now.
   outlet.json:2963 desc "anchor that the ... gap-detector (SCP-OUT-045) keys on";
   AC4 (2967) "frame exposes the base_sequence anchor to the gap-detector as (request_id,
   base_sequence)"; AC5 "hop where the gap-detector is load-bearing". Code proves false: detector
   reads chunk.sequence before frame built, never reads base_sequence/ForwardedStreamFrame.
   Phantom provenance in a done story (code fine; only its justification is the disproven premise).
2. SCP-OUT-049 (status=pending) desc item5 (3222) + AC (3229): "drops a base_sequence fires
   StreamGap/6131" — the exact impossible scenario (base_sequence contiguous by construction).
   Will misdirect 049 implementer to rebuild the mis-key. Fix→ "drops a chunk (chunk.sequence)".
   Free to fix now (pending), forward-only per artifact-flow.

Verdict NEEDS DISCUSSION: code+045 story clean; scar tissue NOT fully resolved (relocated to
044/049). Per MANDATORY scar-tissue defense these are blockers not residual notes — internal
per-story consistency ≠ correctness; artifact SET incoherent (044/049 say base_sequence; 045+code
say chunk.sequence). LESSON: a re-key/rename fix must sweep EVERY sibling story that names the old
key — done stories carry false ACs (phantom provenance), pending stories propagate the bug forward.
