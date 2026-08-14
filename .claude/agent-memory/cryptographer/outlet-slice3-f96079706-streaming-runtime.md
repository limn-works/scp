---
name: outlet-slice3-f96079706-streaming-runtime
description: Crypto review of SCP-OUT-033/034/035 same-context streaming runtime (commit f96079706) — RFC-6962 chunk-manifest KATs, cancel_ack_seq, chunks_billed wire-rejection, durable monotonic_seq. VERDICT SOUND.
metadata:
  type: project
---

# f96079706 same-context streaming runtime (slice-3 foundation) — crypto SOUND

Reviewed on branch feat/outlet-xctx-streaming-saga (worktree scp-wt-slice3). Billing-critical + hashed structures.

**1. RFC-6962 chunk-manifest KATs (scp-protocol/src/context/outlets/stream.rs:3106/3128) — TRULY INDEPENDENT.**
`indep_leaf`/`indep_node` use raw `Sha256` with byte-literal `b"SCP-OUTLET-CHUNK-V1:"` + `[0x00]`/`[0x01]` (NOT the library consts `SCP_OUTLET_CHUNK_V1`/`CHUNK_MANIFEST_*_TAG`); `indep_mth` = recursive split-at-largest-pow2 (structurally distinct from library iterative pair-and-promote); goldens hardcoded. I independently reproduced ALL THREE goldens (leaf0 4eee7606…, root2 04183441…, root4 6fcec837…) in a standalone Python canonicalizer+SHA-256 → byte-exact. Domain sep / leaf 0x00 / interior 0x01 / left‖right order / JCS all verified. leaf = SHA-256("SCP-OUTLET-CHUNK-V1:"‖0x00‖jcs(chunk)); interior = SHA-256(sep‖0x01‖L‖R). Both KATs pass.

**2. cancel_ack_seq: Option<u64> on OutletInvokedEvent (lifecycle.rs:~320) — NOT in any Ed25519 preimage.**
Event-log leaf = SHA-256(0x00‖rmp_serde(Event)); Event.payload.data = serde_json bytes of OutletInvokedEvent (opaque). NOT a signature. Only signed cancel value is OutletCancel.next_seq in SCP-OUTLET-CANCEL-V1 — distinct. `skip_serializing_if=Option::is_none` on serde_json (the real path, event_log.rs:284) → non-cancel bytes byte-identical → no event-KAT regression. Guarded by test at lifecycle.rs (!json.contains). SOUND.

**3. chunks_billed wire-rejection (providers/event_log.rs:266 append_outlet_invoked_verified + runtime stream.rs:1617 verify_outlet_invoked_event_manifest).**
Sequence path: re-derives root=compute_chunk_manifest_root(chunks), leaf_count=chunks.len(), reference=compute_chunks_billed_ref(chunks, cancel_ack_seq); rejects unless event.{stream_manifest_hash,chunks_billed,stream_chunk_count} all match. Frontier path: event triple must == pump frontier {root,billed_count,leaf_count}. A crafted event CANNOT slip a mismatched root/chunks_billed/leaf_count — all recomputed. compute_chunks_billed_ref = |{Data chunk : seq <= cancel_ack_seq}| (§5.4.5:558-566, ceiling None→u64::MAX). cancel_ack_seq ceiling is bound: runtime derives cancel next_seq from its OWN live emission cursor and apply_outlet_cancel_signed cross-checks cancel.next_seq==guard.next_emission_seq (rejects CursorAdvanced) — caller cannot forge (dispatch.rs:1132-1198). Pump gate drops Data at seq>=cancel_ack_seq BEFORE manifest fold (dispatch.rs:2720) → frontier billed_count authoritative. SOUND. Minor note: Sequence path (used by import) takes event.cancel_ack_seq at face value, not re-anchored to a signed cancel — acceptable within import trust model (import trusts exporting ledger).

**4. Durable monotonic_seq cursor (scp-ffi/common/src/outlet_stream_credit.rs) — SOUND for AC31.**
Cursor durable-ONLY (no in-memory shadow), key context/{ctx}/stream_credit_counter/{rid_hex}. next_grant_monotonic_seq: read(absent→0) → checked_add(1) → store BEFORE returning pre-increment value. Monotonic across restart; reload can only go UP; burned values OK (runtime wants strictly-increasing, not gapless). Old in-memory AtomicU64 grant_seq REMOVED from StreamEntry (all 3 bridges). PyO3 holds handle.lock().await across seq-assign+apply (serializes concurrent grants). monotonic_seq IS in signed SCP-OUTLET-CREDIT-V1 preimage.
CROSS-CUTTING LOW (pre-existing, NOT introduced here): runtime CreditTracker.seen_seq floor is in-memory per-session (stream.rs:267), reset to None on post-restart stream resume. Durable cursor guarantees legit-client monotonicity (LIVENESS) but the app-layer credit-REPLAY defense across a full process restart leans on stream_epoch binding (in credit preimage), not seen_seq — a captured signed grant could replay in the post-restart re-pin window IFF the MLS epoch did not advance between open and reopen. Flag for awareness; would need durable seen_seq (or epoch-advance-on-resume) to fully close.
