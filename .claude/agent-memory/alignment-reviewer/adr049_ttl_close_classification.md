---
name: adr049-ttl-close-classification
description: ADR-049 §9 doc-only carve-out splitting governance close (Class S) from TTL auto-close (best-effort, safe-by-re-derivation) — PR #2101, ALIGNED
metadata:
  type: project
---

PR #2101, branch `docs/adr049-ttl-close-classification`, base origin/main 0f26442ac. 3-line net doc diff at ADR-049 §9 (~line 187-188). Splits the "lifecycle close transition" Class-S entry into two: (1) GOVERNANCE/EXPLICIT close = Class S / fail-closed; (2) TTL AUTO-CLOSE = best-effort/coalesced, safe by re-derivation.

VERDICT: ALIGNED, 0 blocking findings, 2 LOW wording observations. Doc accurately describes as-built code (legitimate doc-catches-up reconciliation, not aspirational — artifact-flow clean).

ALL cited symbols verified real on main + behave as claimed:
- `execute_close_context` (governance_helpers.rs:1653) — uses `commit_class_s_keep` (:1685), cancels TTL timer inside the fail-closed closure (`state.ttl.timer.cancel()` :1687). Fail-closed confirmed.
- `tombstone_migrated_context` (governance_helpers.rs:259) — same shape: `commit_class_s_keep` + `state.ttl.timer.cancel()`.
- `GovernanceAction::CloseContext` — real enum variant.
- TTL auto-close handler = `handle_ttl_expiry` (ttl_close_helpers.rs:79) — explicitly Class-C via `class_c_view()`, comment "no Class-S combinator (ADR-049 §9)" (:100), ends with `persist_state_best_effort` (:149). Best-effort confirmed. Leaf timestamp = convergent `deadline_unix_secs`.
- Decision 10 anti-resurrection: supervisor.rs:4133-4145 `snapshot.state != Active` refuses respawn (cites "ADR-049 §10"); ADR §10 line 246 has matching "Anti-resurrection precondition" bullet. Cross-ref "Decision 10" resolves correctly.
- Restore-path convergent-deadline re-arm: `restore_context` (lifecycle_helpers.rs:2377) re-arms via `dispatch_start_ttl_timer(..., anchor_deadline_to_creation=true)` (:2758); `handle_start_ttl_timer` (handlers/ttl_close.rs:134) computes `deadline_override = convergent_ttl_deadline_secs(cell.creation_timestamp_secs, params.ttl.map(as_secs))` — exactly "creation timestamp + params.ttl". Real.

PHANTOM-REF CHECK PASSED: prior draft cited `reconcile_timers` (does NOT exist on main — unmerged PR) and `on_ttl_tick` (exists at actor/mod.rs:633 but is a no-op placeholder). Current diff genericized to "the timer-fired TTL-expiry handler" — cites NO phantom symbols. Clean.

2 LOW observations (non-blocking, did not require change):
1. "atomically clearing the TTL deadline" — `TtlTimer::cancel()` (ttl.rs:1134) only `notify_one()`s the cancel Notify (aborts live task); it does not null `deadline_unix_secs`. Net safety property (stale timer cannot re-fire) still holds via cancel (live) + Decision 10 (crash: closed snapshot not respawned). Wording "cancelling the TTL timer" would be more literal.
2. "re-computes the same past deadline ... idempotently re-fires" — the LEAF deadline is re-derived convergently (exact), but the local sleep uses stale persisted `ttl_remaining_secs` (`remaining_secs()` = `deadline.saturating_sub(now)`, ttl.rs:1149), so re-fire may be delayed by up to that remaining rather than immediate. Doc does NOT claim immediacy ("re-fires the close") so no misalignment; convergence rests on the leaf timestamp not local firing time, consistent with §9.9.3.
