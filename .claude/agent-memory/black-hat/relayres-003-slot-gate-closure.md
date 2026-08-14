---
name: relayres-003-slot-gate-closure
description: SCP-RELAYRES-003 round-4 closure (commit 370d123d0) — DID-slot chokepoint refactor confirmed clean; one within-model warm_slot rollback-pinning residual
metadata:
  type: project
---

# SCP-RELAYRES-003 DID-slot closure (commit 370d123d0, branch relayres-003-fixes)

The slot-gate was extracted into ONE shared chokepoint in
`crates/scp-transport/src/native/did_slot.rs`: `gate_publish` (:515),
`gate_query` (:596), `gate_delete` (:649), `warm_slot` (:450).

**CONFIRMED CLEAN across all 4 transports (WS/QUIC/UDP/WebTransport):**
- PUBLISH→gate_publish, QUERY→gate_query, backfill→gate_query, DELETE→gate_delete.
- UDP has NO SUBSCRIBE (rejected), so no backfill path — correctly N/A, not a gap.
- Transports never call slot_blob/is_claimed directly; both are internal to did_slot.rs.
- DELETE gate: rate-limit BEFORE the CPU-amplifiable classify (:659), fail-CLOSED on
  storage Err (:681). Correct.
- gate_publish rule-(a) uses O(1) index is_claimed on hot path (no O(N) storage scan
  on ordinary opaque PUBLISH — DoS-safe). O(N) scan only in publish_frame cold-establish
  (rate-limited) and gate_query (query already runs).
- storage.query is oldest-first + truncate(limit). Genuine frame is always OLDEST (establish
  evicts older strays), so a newer junk flood cannot truncate it out. Junk NEVER returned
  as genuine (classify_did_record_frame gates every read-path filter).

**Prior closes hold at 370d123d0:** QUIC/UDP flood (rate-limit before gate), seq-aware
rollback (cold-index reconcile adopts higher-seq genuine, rejects replay), DELETE-reversion
hot+cold (storage-backed gate immune to cold index), sweep race (generation-gated removal).

**RESIDUAL (LOW / within documented availability-only model) — warm_slot rollback-pinning:**
`gate_query` warms the index on ANY highest_valid_frame hit, even a limit-TRUNCATED cold
query. If two GENUINE frames coexist in storage (requires best-effort evict_others to have
FAILED) + cold index + attacker issues a small-limit query, warm_slot can PIN the OLDER
genuine frame; subsequent full queries then hit the step-1 slot_blob fast-path and return
the OLDER exclusively, hiding the newer on that one relay until the owner's next republish
supersedes (≤6-day cycle) or TTL. Rollback-to-older-GENUINE, NOT junk; defended by client
seq-monotonicity + multi-relay/DHT highest-seq-wins. Consistent with module's stated model.
Optional hardening: only `warm_slot` when result was not truncated (`blobs.len() < limit`).
The refactor slightly SHARPENS the cold rollback window (caching makes it sticky +
attacker-triggerable) but does not break integrity.
