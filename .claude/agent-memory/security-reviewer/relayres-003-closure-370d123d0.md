---
name: relayres-003-closure-370d123d0
description: SCP-RELAYRES-003 DID-slot chokepoint refactor round-4 closure — FINAL security review, NO FINDINGS
metadata:
  type: project
---

# SCP-RELAYRES-003 closure (commit 370d123d0, branch relayres-003-fixes) — 2026-08-03

FINAL security review of the DID-record slot-exclusivity chokepoint refactor. **NO FINDINGS.**
Diff base e353cbd14. Files: crates/scp-transport/src/native/did_slot.rs (chokepoint) +
native/server.rs, quic/listener.rs, udp/listener.rs, webtransport/session.rs + .docs/adrs/phase-1.md.

**Why:** Round-4 findings all confirmed closed; the ratified opaque-PUBLISH index-cache deviation is sound.
**How to apply:** If this branch is re-reviewed or the chokepoint changes, these are the load-bearing invariants.

## Round-4 findings — CLOSED
- **MED rate-limit DELETE**: old `handle_delete` called `delete_would_revert_slot` (storage.get + Ed25519
  classify) with NO rate-limit → unauthenticated CPU-amplification DoS. New `DidSlotRegistry::gate_delete`
  rate-limits (shared per-IP publish budget) BEFORE storage.get+classify, on all 4 transports (verified each
  handler passes rate_limiter + correct IP; gate runs before best-effort delete; no early delete). Test:
  `delete_gate_is_rate_limited`.
- **LOW fail-closed**: `gate_delete` `storage.get` `Err` → DidDeleteGate::Rejected(INTERNAL_ERROR), refuse.
  Test `delete_gate_fails_closed_on_storage_error` (FailingGetStorage stub).

## Ratified deviation — SOUND
- opaque-PUBLISH rule (a) stays index-cache (`is_claimed` fast path). Cold index may ACCEPT junk into storage
  but can never SUPPRESS: the SUPPRESSION invariant is closed authoritatively at QUERY. Making rule (a)
  storage-authoritative = unbounded storage.query on hot path of EVERY encrypted-context PUBLISH → worse DoS.
- `gate_query` NEW storage-authoritative step: after `storage.query`, `highest_valid_frame` filters to the
  single highest-seq binding-valid frame + `warm_slot`. Pre-refactor QUERY did NO filtering (index-only
  slot_blob then raw query) → strictly stronger now. Non-DID routing_id = all NotAFrame (1-byte decode
  reject), no sig work, pass-through. Tests: `cold_index_query_returns_only_genuine_frame`,
  `query_at_non_did_routing_id_is_pass_through`.
- Honest residual: a cold-index junk FLOOD that pushes the genuine frame past the caller's query `limit`
  leaves a bounded, availability-only, single-relay suppression window (client re-verify + DHT + multi-relay +
  next establish/sweep evicts + warm-up rejects further junk). Not a regression, not integrity. ADR says
  "largely closing" (not "fully") — honest.

## Doc fix (inquisitor) — CORRECT
- ADR phase-1.md + module header now SPLIT the two reversion causes: (1) TTL-expiry (record genuinely absent,
  not a bypass) vs (2) relay-restart/cold-index (durable blob PRESENT, cache forgot — real bounded
  availability window). Explicitly retracts the earlier false "genuine record is already absent" claim for
  the restart case. Closure matrix documents each op's authority + cold-index behavior accurately.

## No new issue / not a trust dependency
- Chokepoint consolidates 4 copies → 1 (gate_publish/gate_query/gate_delete). Whole feature gated on
  DidRecordValidation::Enabled (Disabled = FallThrough/plain query). warm_slot race-safe (inserts only if no
  existing seq>=incoming; never lowers). generation token gates revert/sweep (Fix A) against
  expiry→same-record-refresh clobber. Storage-authoritative across ALL backends, no dev/test stand-in, no
  nullifier. Client re-verifies every record (RELAYRES-002) → relay degrades availability only, never integrity.
