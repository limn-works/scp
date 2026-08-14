---
name: relayres003-delete-gate-cold-index
description: SCP-RELAYRES-003 Fix B DELETE gate (is_current_slot_blob) is in-memory-index-only, bypassable in the cold-index window on durable/multi-node relays
metadata:
  type: project
---

# RELAYRES-003 DELETE gate: cold-index bypass (found round 3, commit 887ebfdc4)

Fix B added a DELETE gate on all 4 transports (WS/QUIC/UDP/WT): reject DELETE whose
blob_id is a claimed DID slot, via `DidSlotRegistry::is_current_slot_blob`
(`crates/scp-transport/src/native/did_slot.rs` ~L386). That fn scans ONLY the
in-memory `slots` HashMap — it never probes storage.

**Gap:** the in-memory index is empty after a relay restart (never persisted;
`RelayServer::new/with_persistence/new_shared` all do `DidSlotRegistry::new()`) and
on a store-sharing PEER node (separate registry). Durable blob backends
(sqlite/postgres/s3) persist the genuine record across restart. Nothing warms the
index — not QUERY (`slot_blob` cold-misses → falls through to `storage.query`,
returns bytes, index stays cold), not the sweep task. Only a PUBLISH to that exact
routing_id warms it → cold window is up to the ~6-day BEP44 refresh cycle per DID.

**Chain (durable restart, or peer node B):** QUERY victim routing_id → get genuine
record R bytes (storage fallthrough) → blob_id_R = SHA256(R) → DELETE blob_id_R →
gate cold-misses → R purged from durable store → PUBLISH captured older genuine
frame R_old(seq<N) → publish_frame cold reconcile finds R gone → R_old establishes →
DID doc rolled back (revoked-key resurrection). Defeats the round-2 seq-aware
cold-index rollback defense (which assumes R is still in storage).

**Asymmetry:** publish_frame reconciles cold index vs storage (integrity kept);
DELETE gate does NOT. Fix: on DELETE, fetch blob, decode as DidRecordV1, derive
routing_id from embedded pubkey, verify binding+signature → reject if valid.
Storage-backed, immune to cold index. Severity HIGH.

Clean at 887ebfdc4: hot-index DELETE gate, generation counter (Fix A), all 4 delete
handlers gated, WT parity (not node-wired, symmetric), publish_frame write-lock
atomicity closes DELETE-vs-supersede race, seq-aware cold-index rollback for publish.
