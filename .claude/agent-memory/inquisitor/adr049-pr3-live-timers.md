---
name: adr049-pr3-live-timers
description: ADR-049 PR-3 TTL timers — the relative-persist root decision I judged UNSOUND was OVERTURNED by commit 150bfccd5 (absolute ttl_deadline_secs); re-review of the fix's premises
metadata:
  type: project
---

Branch `feat/adr049-pr3-live-timers`. Commit chain (all in HEAD 21a93a88e's history):
`5752cd50a` (actor-owned select! Sleep arms + reconcile_timers, A3) →
`1b7924982` (ADR §9 amendment: Class-C scheduling / Class-S terminal split) →
`150bfccd5` (THE FIX: absolute `ttl_deadline_secs` persistence + is_active-gated arm +
convergent bilateral reset; D1/D2/BUG-1) → `50735b908` (SEC-1 fail-closed terminal
persist before teardown + retry key destruction + idempotent leaf) → `21a93a88e`
(create-time terminal-snapshot precheck + real-handle FinalizeClose).

**My prior UNSOUND verdict (persist RELATIVE `ttl_remaining_secs`, restore by partial
re-derivation → extensions silently reverted) HAS BEEN PROPERLY OVERTURNED.** The
overturn is real and lands the exact fix I recommended:
- Snapshot field is now `ContextSnapshot.ttl_deadline_secs: Option<u64>` (ABSOLUTE),
  captured verbatim from `ttl.timer.deadline_unix_secs` (state.rs ~715, build sites
  manager_methods.rs:268 / messaging_helpers.rs:2694). `#[serde(default)]` → legacy None.
- Restore/import read it VERBATIM, `.or_else(|| convergent_ttl_deadline_secs(creation,
  ttl))` fallback only when absent (lifecycle_helpers.rs ~2468). Extension preserved (D2).
- Runtime arms a one-shot `Sleep` via `reconcile_timers` from `deadline_unix_secs`
  (mod.rs). The inert-`Duration` and anchor-bool cargo-cults I flagged are GONE
  (handler sig is now `deadline: Option<u64>`).
- Bilateral reset re-records `old_deadline + additional` (convergent), not local
  `now + dur` (ttl_close_helpers reset_ttl_timer). My prior §7.3.1 QUESTION resolved.
- Terminal `Active→Expired` persists FAIL-CLOSED via `commit_class_s_keep`, OUTSIDE the
  transport timeout (SEC-1), keep-direction (FSM not rolled back on persist fail).
  Applied on BOTH timer path (handle_ttl_expiry) AND FFI/governance close
  (close_context_with_key). Split is principled: scheduling is convergently re-derivable
  (Class-C best-effort), terminal close is resurrection-critical (Class-S).

**Two residual QUESTIONs on the fix's own premises (not UNSOUND):**
1. **Import clamp gap.** Cross-node IMPORT arms on `export.snapshot.ttl_deadline_secs`
   VERBATIM with NO clamp to `creation + ttl`. The careful "backdating only shortens
   (fail-safe)" argument (lifecycle_helpers.rs ~2211) covers `creation_timestamp_secs`
   (bounded above by ttl), but the value actually armed is the UNBOUNDED deadline. A
   creator (exporter==creator is verified) can present a legible params.ttl=1h yet export
   `ttl_deadline_secs = creation + 1yr` to one importer → that replica outlives the
   convergent TTL while honest members expire → legibility/convergence violation. Fix
   re-pins window-COLLAPSING `observed_at` on import but not the window-EXTENDING deadline.
   Suggest `min(ttl_deadline_secs, creation+ttl)` or governance-replay validation.
   Sound for crash-restore (own state); the gap is adversarial import only.
2. **Retry is unbounded-count.** `on_ttl_tick` keeps the terminal actor alive and re-arms
   `ttl_expiry_retry` at a FIXED 5s interval until cleanup+persist complete, then despawns.
   Comment says "bounded backoff" — inaccurate (fixed interval, unbounded count). Right
   fail-closed DIRECTION (never release the slot with un-destroyed keys), but a permanent
   backend outage yields a 5s-spinning terminal zombie for the process lifetime (bounded
   across restart by anti-resurrection dormancy), visible only via `error!` logs — no
   metric / NeedsRepair marker. Suggest exponential backoff + a stuck-terminal gauge.

**Create-terminal precheck (SOUND).** Refuses `CreateContext` only over a DURABLE
TERMINAL snapshot (Expired/Closed/Tombstoned); storage read-fault refuses fail-closed.
Does NOT conflict with legitimate id-reuse: standing contexts re-create over
non-terminal/absent ids (allowed); migration uses ImportContext not CreateContext.
