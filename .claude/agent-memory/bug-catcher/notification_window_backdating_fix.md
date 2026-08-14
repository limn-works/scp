---
name: notification-window-backdating-fix
description: Review of commit 4cad781e5 — observed_at floor on PendingCeiling/EconomicPolicy is_effective gate. Clean; serde-default-0 concern does NOT materialize.
metadata:
  type: project
---

# Notification-window backdating fix (commit 4cad781e5)

Added per-member `observed_at: u64` to `PendingCeilingModification` / `PendingEconomicPolicyChange`
(state.rs), set to `deps.clock.now_secs()` at the two construction sites (governance_helpers.rs
~1414 ceiling, ~2526 economic). `is_effective` now `current >= effective_at.max(observed_at + PERIOD)`.

**Verdict: clean.** All 6 bug-hunt items checked, no real defects found.

- **Item 1 (serde-default-0 gate-break): DOES NOT materialize.** Inner structs `#[derive(Deserialize)]`
  with NO `#[serde(default)]` on `observed_at` → a missing field ERRORS on deserialize (fail-closed),
  it does NOT silently default to 0. So `max(effective_at, 0+PERIOD)` mis-gate cannot arise at runtime.
  Pre-release = no old snapshots exist anyway. The outer `GovernanceState.pending_*` Option fields ARE
  `#[serde(default)]` (default None) — correct. Only 2 production construction sites, both set observed_at.
  No `Default` impl on either struct. No `..Default::default()` path.
- **Item 2 (constants not swapped): clean.** Ceiling uses CEILING_CHANGE_NOTIFICATION_PERIOD_SECS
  (259_200=72h), economic uses ECONOMIC_POLICY_NOTIFICATION_PERIOD_SECS (86_400=24h). Each is_effective
  uses its own.
- **Item 3 (overflow): floor uses saturating_add — clean.** NOTE asymmetry: `effective_at = notified_at
  + PERIOD` (governance_helpers 1413/2525) still uses plain `+` — PRE-EXISTING (not this commit), latent
  overflow if committer timestamp_secs ~u64::MAX. Not practical.
- **Item 4 (const fn removal): clean.** Only callers are match guards in apply_pending_* — no const ctx.
- **Item 5 (test validity): valid, not vacuous.** Tests mirror production formula exactly
  (effective_at = created_at + PERIOD, observed_at = local now) and call the real is_effective.
- **Item 6 (export):** Public-scope export zeroes pending fields (export_import.rs 747/963). Full-scope
  export passes snapshot as-is (845) so `observed_at` DOES ride into the Full signed JCS digest — but
  Full exports are single-creator-signed (no cross-member convergence requirement) and on import the
  exporter's observed_at floor is restored verbatim (lifecycle_helpers 1788), which PRESERVES the
  non-backdatable floor across migration rather than weakening it. Not a defect. observed_at never enters
  an event-log leaf or checkpoint hash (leaf uses pending.effective_at, lines 463/509).

WASM `apply_pending_ceiling_modification` is a documented no-op stub (returns false, doesn't track
pending) — no parity concern; WASM can't initiate ceiling mods through governance. Pre-existing.

preserve_order guard test: `preserve_order` genuinely OFF workspace-wide (no crate enables it); guard
is meaningful. All 5 added tests pass.
