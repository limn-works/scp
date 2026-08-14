# ADR-049 PR-3 "single-source TTL deadline from event log" — pruning regression

Branch feat/adr049-pr3-live-timers, `ttl_close_helpers.rs` `convergent_ttl_deadline`.

**Core hazard:** the diff removed the caller `creation_timestamp_secs` scalar as the TTL
create-base and now derives the base from the genesis `ContextCreated` LEAF read from the
event log. But `ContextCreated` is PRUNABLE: `is_structural_event`=true only means "retained
longer," and pure size-based pruning (`compute_prune_boundary` → `map_or(max_boundary=checkpoint_event_count)`
when no time-retention) prunes EVERYTHING before the checkpoint incl. genesis
(`pruned_event_log_export_import_roundtrip` prunes Event0). Pruning runs on an ACTIVE context
via `create_checkpoint` → `prune_before_checkpoint` (trust_recovery_helpers.rs:119, guarded by
`require_active`).

Once genesis is pruned + context never extended (no surviving `TtlExtended` leaf):
- `handle_ttl_expiry` → None → A3 ABORT → keys never destroyed → finite-TTL guarantee silently defeated.
- `execute_extend_ttl`/`reset_ttl_timer` → no-op, no leaf (silent dropped extension).
- `finalize_close` → None → falls back to `clock.now()` → DIVERGENT `ContextClosed` leaf across members.
- import/restore → no arm.
Pre-diff the scalar base was pruning-immune, so all worked. The "re-arms on later restore"
fail-safe comment is WRONG for prune (permanent, not transient hydration failure).
Fix direction: make genesis `ContextCreated` (and deadline-bearing leaves) non-prunable, or
carry the convergent deadline in the checkpoint.

**Secondary:** `extend_ttl_deadline_and_record` reads log via `.ok().flatten().unwrap_or_default()`
— a transient `event_log_entries` Err is swallowed → silent no-op extension while governance
proposal is consumed and Ok(()) returned (per-member divergence). MEDIUM.

**Abort log noise:** `TtlExpiryResult::aborted_no_deadline()` has completed_steps=0 so
`has_failures()`=true → on_ttl_tick (actor/mod.rs:835) logs `error!` "keeping actor alive to
retry the failed step" on every safe abort (promoted/pruned) though nothing is retried. LOW.

**Import asymmetry:** `GenesisBaseTrust::ImportClamp` clamps the genesis base to
min(genesis_ts, import_now) but the `TtlExtended` leaf `new_deadline_unix` (taken as unclamped
`max`) is NOT clamped — a forged extension leaf smuggles a long key-destruction deadline the
base clamp is meant to block. MEDIUM (needs import-validation confirm).
