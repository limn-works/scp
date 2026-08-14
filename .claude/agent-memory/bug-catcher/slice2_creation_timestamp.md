# Slice 2 — convergent creation_timestamp_secs (PR #1858, HEAD e935347b5)

CLEAN review (final confirming pass). Three-commit slice (18d8d5a49, 00d7a3be2, e935347b5).

## What it does
Adds `ContextSnapshot.creation_timestamp_secs: u64` (`#[serde(default)]`) so import/restore
re-arm the TTL deadline against the convergent `creation + ttl` (ADR-051 §7.3.1/§9.9.3)
instead of importer-local `now()`. Native + WASM both consume VERBATIM (no importer-now clamp).

## Pipeline verified end-to-end (all wired, no gaps)
- state.rs: field added, `#[serde(default)]`.
- ALL native snapshot builders set it: manager_methods::snapshot_context, messaging_helpers/
  broadcast_helpers/trust_recovery_helpers/ttl_close_helpers::build_snapshot_from_state.
  build_snapshot_for_persist delegates to build_snapshot_from_state (covered).
- Export path: lifecycle.rs:174 export_context_blocks → messaging_helpers::build_snapshot_from_state
  (signed snapshot carries real value). flush path (lifecycle.rs:495) → snapshot_context (covered).
- strip_snapshot_for_public carries it through (non-sensitive convergent metadata).
- import_context (lifecycle_helpers.rs:1806): `creation_timestamp_secs: export.snapshot.creation_timestamp_secs`
  VERBATIM, then dispatch_start_ttl_timer(..., true). restore_context: same, from ctx_snapshot.
- handle_start_ttl_timer (ttl_close.rs): anchor=true → convergent_ttl_deadline_secs(creation, params.ttl).
  duration = ttl_remaining (sleep), deadline_override = creation+ttl (leaf). Convergent regardless of fire time.
- convergent_ttl_deadline_secs: Some(ttl)=>creation.saturating_add(ttl), None=>None. const fn.
- WASM: PerContextState field; create stamps now_secs() ONCE bound to both stored field + ContextCreated leaf;
  import (manager.rs:5930) verbatim from snap; handle_ttl_expiry Some(ttl)=>creation.saturating_add(ttl) /
  None=>now() — NO creation==0 guard (matches native). ttl_seconds copied on import (5861).
- WasmContextExportSnapshot DTO field `#[serde(default)]` (independent DTO, not byte-parity w/ native).

## Trust model (sound)
creation_timestamp_secs verbatim is fail-safe: only consumer is TTL UPPER bound (creation+ttl);
backdating shortens, future-dating bounded by ttl. Contrast pending_* observed_at = window LOWER bound,
RE-PINNED to local now on import (correctly). Authenticated by snapshot sig + exporter_did==creator_did
in validate_export_for_import BEFORE consumption.

## Non-issues confirmed
- Legacy creation==0 → deadline 0+ttl (past) = fail-safe. Timer still sleeps ttl_remaining; leaf stamps 0+ttl.
  state.rs doc "expires immediately" is slightly loose (sleep still runs) but harmless; pre-release no data.
- scp-testing ContextSnapshot literals are all BroadcastContextSnapshot (distinct type) — no missed sites.
- saturating_add everywhere — no overflow panic.
- EXCLUDED per scope: native↔WASM actor_did divergence (slice 4); ±5-min docs.
