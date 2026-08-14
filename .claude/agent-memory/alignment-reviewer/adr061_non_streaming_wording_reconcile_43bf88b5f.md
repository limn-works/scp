---
name: adr061-non-streaming-wording-reconcile-43bf88b5f
description: §5.4.5 non-streaming wording reconcile with ADR-061 distinct-modes @ 43bf88b5f (feat/outlet-xctx-streaming-saga) — ALIGNED, 0 findings, artifact-flow-legit spec-fix
metadata:
  type: project
---

Commit 43bf88b5f (branch feat/outlet-xctx-streaming-saga, scp-wt-slice3, 2026-07-14) — docs-only, reconciles stale pre-ADR-061 §5.4.5 wording. VERDICT: ALIGNED, 0 findings.

**Why:** §5.4.5:610 old text ("A non-streaming invocation is a stream that emits exactly two chunks…") + rejected-alt (1) were pre-ADR-061 leftovers contradicting the §5.4.5:347 preamble and ADR-061's distinct-modes decision (unary→output_hash, NOT a stream; streaming→stream_manifest_hash). Legitimate spec-leads-code fix per artifact-flow (fixing stale spec sentence to match governing ADR).

**How to apply (verification results, all 5 pass):**
1. Reworded :610 "**Non-progressive executor on the streaming path.**" — correctly says a non-progressive EXECUTOR run through the streaming surface = 2-chunk degenerate stream (Data+End) committing stream_manifest_hash, explicitly DISTINCT from a unary invocation (output_hash, not a stream). Does NOT re-assert unary=stream. FAITHFUL.
2. Reworded rejected-alt (1) — unary+streaming distinct modes sharing ONE OutletInvokedEvent shape (unary carries output_hash + no-manifest sentinels; streaming carries stream_manifest_hash), no fork into two response types. FAITHFUL.
3. §5.4.5:347 preamble ↔ :610 ↔ :612 ↔ ADR-061 now COHERENT. Cross-spec sweep found NO surviving "every call is a stream" assertion — only the §347 preamble + ADR-061:7 SUPERSEDING clauses remain (both correct). §347 "one-chunk stream" describes the REJECTED framing (matches ADR-061:7 verbatim), :610 "two-chunk" describes the live non-progressive-executor case — different objects, no conflict.
4. SCP-OUT-035 AC5 rewording (outlet.json:2120 "a non-progressive (one-shot) executor run through the streaming runtime emits… stream_chunk_count = 2") FAITHFUL to test invoke.rs:5853 invoke_outlet_one_shot_emits_two_chunk_event_035_ac5 — OneShotExecutor.exec_action returns single value, default exec_action_stream adapter → Data+End = 2 chunks; test asserts stream_chunk_count==2 @ :5906. Still machine-verifiable.
5. Code spec-faithful: unary build_outlet_event (invoke.rs:725-756) sets output_hash:Some, stream_manifest_hash:[0u8;32], stream_chunk_count:0, chunks_billed:0 — comment @ :742 cites ADR-061 "NOT a degenerate one-chunk stream". §5.4.5:566 wire-rejection genuinely available on Sequence path: append_outlet_invoked_verified (event_log.rs:1078) re-derives full chunk Sequence, wire-rejects on chunks_billed mismatch (AC22 test :1086 asserts NOT appended; AC21 :1150 accepts well-formed).

OBS (pre-existing, not this commit): streaming finalize (invoke.rs:3850) sets BOTH output_hash (from End aggregate) AND stream_manifest_hash on the streaming event — the aggregate output_hash is a retained "existing field" per §570, not a contradiction with the distinct-artifact framing (unary event has NO manifest; streaming event has manifest + aggregate). Tracked in prior f96079706 entry's "aggregating path coexists" observation.
