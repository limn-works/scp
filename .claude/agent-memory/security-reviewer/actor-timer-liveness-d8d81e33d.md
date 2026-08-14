---
name: actor-timer-liveness-d8d81e33d
description: Re-review of ADR-049 A3 actor-owned TTL/governance timer refactor (commit d8d81e33d) liveness fixes
metadata:
  type: project
---

# Actor-owned timer refactor (ADR-049 A3) — d8d81e33d liveness re-review

Both prior MEDIUM liveness regressions VERIFIED FIXED. No security/anti-resurrection weakening.

## Fix 1 — TTL expiry timeout (actor/mod.rs on_ttl_tick ~661-712)
- `tokio::time::timeout(HANDLER_TIMEOUT=30s, handle_ttl_expiry)`; on elapse warns + proceeds.
- SOUND because ordering in ttl.rs try_ttl_expiry_cleanup: FSM transition_to(Expired) (sync ArcSwap, ADR-049 Dec-12) + destroy_mls_group + destroy_sender_key ALL run BEFORE first `.await` (transport.delete_published ~L855, event_log.append ~L866). So a hung provider bounded to 30s; confidentiality-critical key destruction ALWAYS completes pre-await. Mirrors sibling command-path handle_ttl_expiry (ttl_close.rs ~L240).
- Timeout-path residual (OBSERVATION, not new, mirrors command path): if timeout fires during append_context_event, then participation-decay + emit_event + in-handler persist_state_best_effort (all AFTER try_ttl_expiry_cleanup in ttl_close_helpers::handle_ttl_expiry) are skipped → ContextExpired Merkle leaf may be missing (same outcome as a plain append failure that already exists). Trailing drain still writes Expired.

## Fix 2 — inbox fairness (actor/mod.rs run() ~289-425)
- MAX_CONSECUTIVE_INBOX=32; biased select; inbox arm guarded `consecutive_inbox < 32`; Arm5 fall-through `std::future::ready(())` guarded `>=32` prevents deadlock when inbox disabled + no timer ready.
- Counter increments ONLY on inbox dispatch; reset to 0 by ANY non-inbox arm (2/3/4/5). Not defeatable: attacker cannot dispatch without incrementing; a READY timer wins biased poll before Arm5 within ≤32 dispatches. 32 is small vs 60s gov cadence / coarse TTL — reasonable. Persist arm same ≤32 bound; coalesced-by-design + exit drain guarantees durability.

## Fix 3 — self-despawn + read_context_state None (supervisor.rs)
- despawn_actor (L4657) removes ONLY in-memory handle under write_lock (sync remove, no await-under-lock); durable snapshot NOT deleted → audit Expired snapshot preserved.
- read_context_state (L8985) None when actor gone (Poisoned if poisoned). Callers only short-circuit on Some(Active|Creating) (standing_context L9089); None and Expired both fall through to create → NO behavioral change. Safe.

## Anti-resurrection INTACT
- respawn_from_snapshot L4334 `if snapshot.state != Active { skip }`; restore_all_contexts same. Expired stays dormant. Trailing drain reads live FSM (build_snapshot_from_state L2692 `state.handle.state()`=Expired) → writes Expired even on timeout path → no resurrection.

## OBSERVATION — create/expire durable-write race (largely pre-existing, self-healing)
- persist_context keyed by context_id, NO generation/CAS/registry guard (messaging_helpers persist_state_best_effort L2533). During slow (≤30s) TTL cleanup the FSM is ALREADY Expired (step-1 sync), so a concurrent STANDING recreate (deterministic id) probes Expired → falls through to create → persists Active, which the dying actor's Expired writes (in-handler write A + post-despawn trailing drain write C) can clobber → live context durably Expired → dormant on next restart. Self-heals: standing pair re-creates on next contact (probe None → create). Non-standing ids not reused → not reachable. New trailing drain adds one post-despawn Expired write widening a pre-existing window. Hardening: serialize durable writes by id (bootstrap_spawn_lock covering persist) or drain-before-despawn.
