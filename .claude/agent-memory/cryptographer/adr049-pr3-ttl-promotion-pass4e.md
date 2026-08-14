---
name: adr049-pr3-ttl-promotion-pass4e
description: ADR-049 PR-3 pass-4e — promotion mutates params.ttl=None as prune-immune disarm authority; convergence SOUND, one durability-lane inconsistency (promote is best-effort while every other governance leaf is fail-closed)
metadata:
  type: project
---

# ADR-049 PR-3 pass-4e TTL/promotion review (branch feat/adr049-pr3-live-timers, HEAD 216ebf420)

Pass-4e reframed the SINGLE-SOURCE TTL-DEADLINE invariant as a PARTITION:
- Fail-dangerous inputs (create BASE = `creation_timestamp_secs + params.ttl`, PROMOTION = `params.ttl == None`) come from the PRUNE-IMMUNE `ContextSnapshot` (creation_ts + context_params).
- Fail-safe input (extensions = `TtlExtended` leaf `new_deadline_unix`) from prunable log.
- `convergent_ttl_deadline(entries, creation_ts, params_ttl)` in ttl_close_helpers.rs (~line 750 on branch). Returns `None` iff params_ttl==None; else max(base, highest TtlExtended). ContextPromoted leaf NO LONGER read for arm decision (deliberate — docstring explicit).

## Verdict: convergence + signed-params SOUND. One MEDIUM/LOW durability inconsistency.

PASS:
- promote_params (mod.rs:156 branch) sets memory_scope=Full + ttl=None. Deterministic, no inputs → convergent. Only call site: execute_promote_context (governance_helpers.rs:2688/2744). Unanimity required. All members apply identically.
- params.ttl NOT part of context_id (caller-supplied String to create_context, not params-derived). Only signature over params = export-time sig over JCS(snapshot) incl context_params, created by exporter==creator over CURRENT snapshot → consistent, no immutable prior manifest. Legibility change (ttl removed) is BY-DESIGN promotion semantics.
- snapshot.context_params = state.handle.params().clone() at every persist site → mutated ttl=None captured. Restore reads ctx_snapshot.context_params.ttl; import reads export.snapshot.context_params.ttl. Durable on success.
- Deadline convergence: base (creation_ts convergent creator-assigned + params.ttl convergent legible) + max(TtlExtended.new_deadline_unix convergent). No per-member-divergent field read.
- A2 reset-leaf: reset_ttl_timer→extend_ttl_deadline_and_record. new_deadline_unix = convergent_ttl_deadline(...).extend(dur). Reset leaf `timestamp` = old_dl (convergent pre-ext deadline), NOT local now. Reader uses new_deadline_unix only. Promoted context (ttl=None) → no-op, no leaf (H2). Convergent.

## FINDING (MEDIUM/LOW, NEW in pass-4e): promotion disarm write is best-effort, not fail-closed
- execute_promote_context routes promote_params via `commit_class_c_best_effort` (BEST-EFFORT persist, swallows error). EVERY other governance leaf doing a security-critical transition uses `commit_class_s_keep` (FAIL-CLOSED) — incl. the close path (governance_helpers.rs:1836) which clears the SAME stale-deadline and whose comment claims to "mirror execute_promote_context" (inaccurate: close is fail-closed, promote is best-effort).
- Backstop EXISTS: the outer governance discharge (governance_helpers.rs ~5355 `discharge.commit_fail_closed`) persists whole state (incl ttl=None) FAIL-CLOSED after dispatch. So on success ttl=None IS durable.
- Residual window (NEW vs pass-4d, which read the durable ContextPromoted leaf): if inner best-effort persist (2b) fails silently AND crash occurs after the fail-closed ContextPromoted leaf append (2c) but before the outer commit_fail_closed (4) → restart reads stale snapshot ttl=Some → re-arms TTL on a permanently-promoted context → keys destroyed at old deadline. The leaf is durable but deliberately ignored. Recoverable: executed_proposals marker also rides the outer persist so proposal is retryable, but a transient re-armed deadline exists. ADR-049 itself says "losing the promotion signal would destroy a permanent one."
- Clean fix: route promote_params through commit_class_s_keep (fail-closed), matching close/suspend and the path it claims to mirror; then ttl=None is durable before the ContextPromoted record leaf is appended. Removes the window; bounded, convergent fix. Inner best-effort persist is then also non-redundant.
