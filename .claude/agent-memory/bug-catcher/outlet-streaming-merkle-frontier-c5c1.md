# outlet-streaming Merkle frontier + chunks_billed append-invariant (C5+C1)

Commit e6fdf8b1b, branch feat/outlet-streaming-ffi (@scp-wt-ffi). Reviewed 2026-07-13. Recovered-from-stalled-coder.

**Verdict: CLEAN. Only 2 LOW stale doc comments.** All tests pass (frontier proptest 2/2 in 181s incl per-prefix re-check to n=257; runtime C1 unit 2/2; event_log append C1 5/5). scp-runtime + scp-protocol compile clean.

Scope: (C5) pump's retained `Vec<OutletStreamChunk>` manifest → incremental O(log n) RFC-6962 `MerkleFrontier` (scp-protocol stream.rs); StreamCloseSummary drops `manifest: Vec` for `manifest_root/manifest_billed/terminal_summary`. (C1) `chunks_billed <= stream_chunk_count` event-local wire-invariant at MerkleEventLogProvider::append_event.

Verified sound:
- **Frontier == batch oracle** for all n (RFC-6962 MTH; hand-checked n=0,1,5,6,7,9,10,12,13 — level-by-level "promote-odd-unchanged" batch IS the incremental RFC-6962 form). `root()` folds stack top(smallest)→bottom(largest) as `H(left,right)`; push is binary-counter mountain-range → stack ≤ log2(n)+1 → O(log n) memory real.
- **Billing equivalence (unbounded ceiling == pinned)**: dispatch pump uses `MerkleFrontier::new()` (ceiling u64::MAX) but gate `apply_stream_chunk_gate` returns DropAboveCancelAck for Data with seq>billing_ceiling BEFORE ingest; only Forward-path Data (+synthetic terminals, never Data) are ingested → frontier.billed_count == old `reference_chunks_billed(manifest, cancel_ack_seq)`. Settlement receipt + audit event both anchor to `manifest_billed`. cancel pins ceiling=next_seq at arrival; monotonic seq → no forwarded Data exceeds final cancel_ack_seq.
- **Saturating u32 conversions** never violate invariant direction (billed<=leaf by construction; saturation monotonic). Only bites at 4e9 chunks.
- **C1 decode**: saga join-record (saga.rs:1808 shape) lacks required `request_id/outlet_id/invoker_did/status/execution_time_ms/input_hash/output_hash` (no serde default on those; NO deny_unknown_fields) → fails decode → passed through. chunks_billed/stream_chunk_count ARE `#[serde(default)]` so legacy/unary events decode 0<=0 pass. Fail-open not exploitable: check + downstream reader share same required-field contract, so anything skipping the check is also un-decodable as OutletInvokedEvent downstream. Live path: append_context_event delegates to append_event (test confirms).
- **1:1 emission→ingest**: every `emitted_chunks.push` replaced by `ingest_stream_chunk` at same site (loop-top terminal, cancel/credit timer, Forward final_chunk, inner-pump capture + late-drain + terminal). Ingest precedes send everywhere; sign-failure `else{break}` skips both (consistent old/new). terminal_summary.observe = old batch scan last-write-wins (Default = Error(CODE_EXECUTION_FAULT)).
- **Recovery angle clean**: both modified dispatch tests KEEP `assert_ne!(chunk.sig,[0u8;64])` on the outer_rx-received chunk (the folded chunk) — sig invariant NOT lost, comment claim accurate. No vacuous/filtered tests. No stale `.manifest`/`reference_chunks_billed`/`verify_summary_chunks_billed` refs anywhere in crates/bindings.

LOW findings (stale doc comments, no runtime impact):
- dispatch.rs:51-53 module doc: "verifies it via `super::stream::verify_chunks_billed` before handing the event to the event-log appender" — pump now uses `verify_outlet_invoked_event_local`.
- dispatch.rs:2233 comment: "emit the event ... over the outer `emitted_chunks` manifest" — `emitted_chunks` deleted; now the frontier.

NOTE: `verify_chunks_billed` (stream.rs:1461) NOT removed — still used by its own tests; distinct from removed `verify_summary_chunks_billed`/`reference_chunks_billed`.
