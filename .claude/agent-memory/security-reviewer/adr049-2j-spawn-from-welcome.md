# ADR-049 Phase 2J spawn-from-Welcome — security review (branch feat/adr049-2j-spawn-from-welcome)

## Round-3 confirm @580e8d0ef (2026-07-02) — MEDIUM CLOSED, zero new findings
Round-2 MEDIUM (missing `bootstrap_spawn_lock` → concurrent/respawn clobber) is CLOSED.

Key facts (all supervisor.rs unless noted):
- `bootstrap_spawn_lock: tokio::sync::Mutex<()>` (field ~1167). Exactly 6 acquisition
  sites, all at entrypoint tops, none nested: create@2609, import@2741, restore@2813,
  respawn_from_snapshot@4290, standing@9054, spawn_actor_from_welcome@10396.
  Uniform lock order `bootstrap_spawn_lock → write_lock` (register/build_actor_deps take
  write_lock strictly inside). No inversion, no re-acquire → deadlock-free.
- spawn_actor_from_welcome holds guard WHOLE body (10396..10638).
- Precheck A (10421) live-registry `lookup`; Precheck D (10480) DURABLE first-writer-wins:
  `load_context` refuses on ANY `Ok(Some(_))` (not just Active → catches non-Active/
  failed-restore snapshots); `Err` → PersistenceFailed fail-closed. BOTH before ConfirmConsume
  (10509) so collision never burns the single-use KP.
- Crypto-durability check moved PRE-persist: welcome_snapshot_crypto_is_durable
  (messaging_helpers.rs:2435, `Ok(blob) if !blob.is_empty()`) reads LIVE export (not
  persistence read-back → works even for Noop backend), step 3b @10575, before persist @10594.
  Rollback destroys group, returns before any durable write.
- reset_crash_window (4715, `crash_windows.remove`) called under lock @10610 pre-spawn.
- Ceiling precheck @10458 (CapabilityCeiling::new(...).validate_entries()) reversible, pre-consume.

## force_export_failure test seam — CLEAN
provider.rs: field@477, init@535, arm_export_failure_once@547, branch@2036 — ALL
`#[cfg(any(test, feature="testing"))]`. Production build carries neither field nor branch.
One-shot swap(false). No DoS / production reach.

## Residual: context_id NOT bound to joined group_id — correctly deferred
install_joined_group(&context_id_to_bytes(context_id), ...) @10537 uses caller-supplied
context_id string; never compared to joined_group.group_id(). BUT zero production attack
surface: spawn_actor_from_welcome is `pub(in crate::context)`, only callers are tests
(handle.rs:436 is a COMMENT explaining the capability-gated OwnedIdentityDid FFI seam is a
follow-on slice). First-writer-wins (Precheck A+D) already stops colliding-id clobber of
other contexts. Group-binding is a protocol-consistency matter → #127 follow-on per task #128.
Boundary is correct; MUST bind context_id↔group_id when the FFI consumer lands.

## Tests (spawn_from_welcome_tests.rs, 1067 lines) — behavioral, not string-gamed
- non_durable_crypto_export_fails_closed... : arms seam, asserts PersistenceFailed + group
  rolled back (export empty) + no actor + no member_count.
- durable_snapshot_collision_is_rejected... : seeds real snapshot via supervisor A, retries
  via supervisor B sharing store (no live actor → Precheck A misses, D catches), asserts
  CreationFailed + victim NOT deleted + intact + no group installed; then clears snapshot and
  retries SAME reservation → succeeds (proves KP never burned = reject fired pre-ConfirmConsume).
