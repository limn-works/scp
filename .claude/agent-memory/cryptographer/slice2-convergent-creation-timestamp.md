---
name: slice2-convergent-creation-timestamp
description: PR #1858 ContextSnapshot convergent creation_timestamp_secs review — timestamp axis SOUND, residual actor_did divergence on ContextExpired/system leaves (native sentinel vs WASM empty)
metadata:
  type: project
---

# Slice 2 — ContextSnapshot convergent creation_timestamp_secs (PR #1858)

Branch `feat/contextsnapshot-convergent-creation-time`, HEAD e935347b5. Adds `#[serde(default)] creation_timestamp_secs: u64` to ContextSnapshot, consumed VERBATIM on import/restore to arm convergent TTL deadline. WASM mirror.

## Delta reviewed (commit e935347b5): SOUND
- WASM `handle_ttl_expiry` (manager.rs:5100): dropped `creation != 0 => creation+ttl, _ => now()` guard. Now `Some(ttl) => creation.saturating_add(ttl); None => now()`.
- Native `convergent_ttl_deadline_secs` (ttl_close_helpers.rs:277): `Some(ttl) => Some(creation.saturating_add(ttl)); None => None` — NO creation==0 guard. Legacy snapshot (creation==0) → `0+ttl` on BOTH. CONFIRMED identical.
- Native leaf stamping chain: handle_start_ttl_timer sets deadline_override=convergent_ttl_deadline_secs(creation,Some(ttl)) → state.ttl.timer.deadline_unix_secs → handle_ttl_expiry reads it (unwrap_or now()) → try_ttl_expiry_cleanup(...,expiry_deadline_secs) → append_context_event(ContextExpired, "system:timer", expiry_deadline_secs). Leaf timestamp = creation+ttl. (ttl.rs:743+, 875)
- WASM import verbatim (manager.rs:5952 `creation_timestamp_secs: snap.creation_timestamp_secs`, no `.min(now)` clamp). Native import verbatim (lifecycle_helpers.rs:1818 `export.snapshot.creation_timestamp_secs`).
- WASM sig gate sound: deserialize_and_verify_envelope (5537) → bound input → JCS recanon → exporter_did==creator_did → empty-sig reject → verify_snapshot_signature (verify_strict, fail-closed) BEFORE field mapping. creation_timestamp_secs is inside signed JCS preimage = authenticated. Round-trips through JCS (export_import.rs:2748 test).
- Trust model: verbatim consume; sole consumer = TTL UPPER bound (creation+ttl); backdating only shortens (fail-safe); future-dating bounded by ttl. observed_at (notification-window LOWER bound) correctly STILL re-pinned to local now (lifecycle_helpers.rs:1850). FIX A corrected the stale "mirrors the re-pin above" comment.

## RESIDUAL FINDING (pre-existing, NOT introduced by slice, undercuts full §9.9.3 claim)
- ContextExpired leaf `actor_did` DIVERGES native vs WASM: native "system:timer" (ttl.rs:876), WASM "" (manager.rs:5105).
- Leaf hash = SHA-256(0x00 || rmp_serde(Event)); Event includes actor_did (tree.rs:296 leaf_hash; canonical hash tree.rs:388 length-prefixes actor_did). So same timestamp + different actor_did = DIFFERENT leaf hash = DIFFERENT Merkle root at equal event count in a mixed native+WASM context.
- SYSTEMIC, not isolated: native system leaves use sentinel DIDs ("system:timer", "system:close" ttl.rs:679, ...), WASM uses "" (ContextExpired) or real initiator (ContextClosing manager.rs:1781) or "system" (manager.rs:696). actor_did parity for committer-assigned/system leaves is NOT aligned across substrates.
- This slice's convergence tests (tests/eventlog_convergence.rs) are NATIVE-ONLY (MerkleEventLogProvider both sides, clock-offset) — they verify timestamp convergence, do NOT cross-check WASM substrate root vs native for the ContextExpired leaf incl actor_did. So the actor_did axis is untested.
- Predates slice (Phase 2 substrate #1850). Recommend: align system-event actor_did across native↔WASM (canonical sentinel set) + add a native↔WASM root-equality KAT for ContextExpired/ContextClosed system leaves. File or fix.
