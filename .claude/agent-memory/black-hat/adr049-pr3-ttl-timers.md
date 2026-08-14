---
name: adr049-pr3-ttl-timers
description: ADR-049 PR-3 live TTL timers — round-2 re-review of pass-4 fixes for BLACK-P3-003/004/005 (leaf-timestamp convergence, relay starvation, retry durability)
metadata:
  type: project
---

# ADR-049 PR-3 live TTL timers (branch feat/adr049-pr3-live-timers, HEAD ae3bcc7b1)

Files: crates/scp-runtime/src/context/{ttl.rs, ttl_close_helpers.rs, actor/mod.rs, actor/handlers/ttl_close.rs, governance_helpers.rs, lifecycle_helpers.rs, export_import.rs}

## Pass-4 verdicts
- **P3-004 (M2) CLOSED.** finish_ttl_expiry_io appends ContextExpired leaf FIRST, relay delete_published AFTER under its own RELAY_DELETE_BUDGET (5s); relay delete NOT in completeness bitmask; append is LOCAL event log; HANDLER_TIMEOUT=30s >> 5s. Hostile relay cannot starve leaf or force perpetual non-despawn. Retry = bounded exp backoff (5s base, 5min cap) + stuck-threshold operator error.
- **P3-005 (L2) accepted crash residual — fair**, but cheap closure exists (see M1 fix below).
- **L1 CLOSED.** Phase-2 leaf gated on persist_result.is_ok(); no NEW permanent-absence window beyond the accepted crash residual (actor stays alive retrying while persist flaps).
- **M3 import clamp** sound/fail-closed, no panic (rmp err→Err, decode_payload .ok()), all saturating. Only defense-in-depth: defeatable by the snapshot SIGNER (who controls the event log used for derived_ub); harmless to honest exports. Not a break.
- **B8/is_terminal (N5) CLOSED.** is_terminal() exhaustive {Expired|Closed|Tombstoned}. Strictly MORE restrictive for B8 create-refuse; correct for despawn. Poisoned correctly excluded (recoverable).

## STILL-OPEN: P3-003 (M1) re-breakable via context_reset_ttl_timer
M1 retry re-derives the ContextExpired leaf timestamp from event-log TtlExtended leaves only
(convergent_expiry_leaf_deadline / max_extended_deadline_from_log, ttl_close_helpers.rs 454-496).
BUT the `reset_ttl_timer` helper (ttl_close_helpers.rs 329-373) extends the deadline
`old_dl + new_duration` and writes NO TtlExtended leaf. It is a LIVE FFI op
`context_reset_ttl_timer` in all 4 bridges (scp-ffi/src/context.rs:5056, napi context.rs:4029,
uniffi bridge.rs:12735, wasm context.rs:1953), the actor-native propose+reset extension flow
distinct from governance execute_extend_ttl (which DOES write the leaf, governance_helpers.rs 1940-65).
So after a reset-extension: recorded=extended(D2), log max TtlExtended=None/D1.
First expiry attempt stamps recorded D2; a RETRY (Phase 1 cleared the field) re-derives
base.max(log)=creation+ttl or D1 ≠ D2. Member appending first-try vs on-retry → divergent
ContextExpired leaf timestamp → Merkle root divergence across members. Retry triggers on LOCAL
persist/append failure (transient disk hiccup suffices — not attacker-gated). Secondary path:
execute_extend_ttl partial commit (timer persisted, leaf append Err, no rollback) yields same
recorded⊥log inconsistency.
**Fix:** carry the resolved expiry_deadline_secs in the resident retry state alongside
ttl_expiry_completed (actor/mod.rs ttl_expiry_completed:u8) so retry stamps byte-identical value —
eliminates re-derivation entirely, also closes the P3-005 concern cheaply. OR make reset_ttl_timer
append a TtlExtended leaf so the log is authoritative.
