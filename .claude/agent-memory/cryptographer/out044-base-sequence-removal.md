---
name: out044-base-sequence-removal
description: SCP-OUT-044 reversal (commit 9ace80c0a) — removing the bridge base_sequence anchor is crypto-safe; the real MLS send-seq lives elsewhere and is untouched
metadata:
  type: project
---

Commit `9ace80c0a` (branch feat/outlet-xctx-045-gap-detector, #1907) removed `ForwardedStreamFrame { base_sequence: u64, chunk }` and the `base_sequence` field from the cross-context outlet-stream bridge. VERDICT: crypto-safe, no guarantee weakened.

**Why base_sequence was crypto-irrelevant:** it was minted from a fresh per-stream `SendSequenceTracker::new()` in `run_cross_context_bridge`/`run_streaming_saga_seal_task` (invoke.rs), stamped onto an in-process `mpsc::Sender<ForwardedStreamFrame>`, and delivered to A's shared-member invoker as PLAINTEXT. Never fed to AES-GCM / AAD / any MLS `(epoch,sequence)` header. The removed rustdoc itself said "never fed to any encryption here" and "NOT an MLS AEAD sequence input." `ForwardedStreamFrame` derived only `Debug`, never serialized. Post-removal `forward_frame` = `outer_tx.send(chunk.clone()).await.is_ok()` — pure passthrough.

**Real MLS send-seq is untouched:** §9.16.1 — per-sender monotonic send counter bound into AES-256-GCM AAD (`epoch(8)||sequence(8)` header + AAD `BE32(len(ctx))||ctx||BE32(len(sender_did))||sender_did||epoch||sequence`), plus receive-side `(last_epoch,last_sequence)` replay tracker. This lives in the actor's genuine `SendSequenceTracker` (actor/sequence.rs [12 refs], actor/state.rs [AAD-binding comments], handlers/messaging.rs). The removal diff touches ONLY invoke.rs, commands.rs (doc), outlets_helpers.rs (doc), supervisor.rs, prds/outlet.json — NONE of the real-tracker files. grep confirms SendSequenceTracker fully present outside invoke.rs; invoke.rs retains only a rustdoc link, no constructor. `base_sequence`/`ForwardedStreamFrame` = 0 occurrences repo-wide.

**Reserve-at-encryption is the correct locus (§5.15.7):** a send-seq becomes durable iff the encrypted payload was handed to transport. A's re-seal for A's OTHER members must reserve over A's PERSISTENT per-sender counter at the §9.16 encrypt seam (SCP-OUT-047 delivery seam), NOT a fresh bridge-local counter at the plaintext handoff. A bridge-pre-minted fresh counter would diverge from A's real persistent counter and could never be the AAD-bound value — so it was WRONG; removal correctly defers to the real seam. It also could never be a gap-detector key (locally +1-by-construction).

**Operator chunk sig (SCP-OUTLET-CHUNK-SIG-V1) preserved:** bridge forwards `chunk.clone()` byte-for-byte, never re-signs; `sig`/`request_id`/`sequence` unchanged. A's independent manifest still recomputes over the bare `OutletStreamChunk` (`compute_chunk_leaf_hash` JCS-hashes the whole chunk — which is exactly why base_sequence was a wrapper, never a chunk field). SCP-OUT-045 gap-detector still keys on `chunk.sequence` (only the "unlike base_sequence" contrast prose trimmed) — consistent with the base_sequence-tautological note in [[MEMORY]].
