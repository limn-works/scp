---
name: outlet-value-caveat-enforcement-99a290b15
description: §7.3.8 outlet value-caveat runtime enforcement slice (feat/outlet-value-caveat-enforcement @99a290b15) — auth boundary SOUND, 0 findings, 3 obs
metadata:
  type: project
---

# §7.3.8 value-caveat runtime enforcement (feat/outlet-value-caveat-enforcement @99a290b15) -- 2026-07-12 -- SOUND, 0 findings, 3 obs

Enforces §7.3.8 outlet-invocation caveats in the reserve phase, sourced from the INVOCATION UCAN's validated `nb` (prior version wrongly used spending_ucan -> inert; fixed @6eec53290).

**Auth boundary SOUND — cannot widen/omit a delegator-bound caveat:**
- New `TokenNbCaveatResolver` reads leaf `token.payload.nb` directly. Sound ONLY because `verify_edge_attenuation` (validate.rs:1661) runs Step 7b at EVERY chain edge: parent Some + child None (outlet edge) = REJECT (FieldRemoved); parent Some + child Some = `narrow()` (rejects widening/field-removal/origin_kind change). Mint materializes complete effective set into every non-root nb. So a validated leaf's nb IS the narrowed effective set — omission and widening both rejected upstream. A member without direct ceiling authority can't self-issue to drop caveats (Step 7 capability-subset fails without the proof chain).
- All 3 single-shot bridges (pyo3 outlets.rs:528, napi outlets.rs:428, uniffi bridge.rs:12964) resolve `effective_caveats` via `TokenNbCaveatResolver.resolve_caveats(parse_ucan(ucan_token))` — the SAME token `validate_outlet_ucan` validated with TokenNbCaveatResolver (pyo3:380). `ucan_cid = compute_revocation_cid(token.encoded)`, Some iff caveats Some. Threaded bridge -> invoke_outlet_with_economy -> reserve_via_actor -> command -> handler -> reserve_outlet_economy. No caller-supplied JSON caveats; no role_state bypass; spending_ucan `nb` NOT consulted (test reserve_enforces_effective_caveats_param_not_spending_nb).

**Enforcement path (outlets_helpers.rs reserve_outlet_economy:521):**
- Stage 1 `check_invocation_local` (caveats.rs:811) runs FIRST, BEFORE any Class-S consume — fail-closed: input_schema, amount_max_per_call (cost>cap), allowed_adapters (absent/empty=reject), allowed_target_dids (single-shot passes target=None -> populated list rejects = correct fail-closed for same-context). On reject refunds velocity+hard-rate, touches no counter.
- Stage 2 counter consume (`consume_caveat_counters`:1517) is all-or-nothing across 3 kinds (clone-then-insert-on-full-success), Class-S, keyed by ucan_cid. Paid path: folded as LAST mutation in `commit_class_s_keep_compensating` (one fail-closed persist; on CounterExhausted rolls back budget+velocity inline, spending nonce stays consumed = acceptable self-inflicted). Free path: dedicated `commit_class_s_keep`. Both KEEP-on-persist-failure -> success ⟹ counter durably persisted (monotonic: a spent cap never un-consumes behind an acked call).
- CaveatCounters (caveat_counters.rs): saturating arithmetic, rejection leaves record unchanged, rate_window prune saturating_sub cutoff (restart only drops MORE entries, never widens window).

**Monotonic/replay:** void/rollback path (rollback_outlet_economy) reverses velocity/budget/escrow/hard-rate but NOT caveat_counters (test confirms) — over-counts on failure = fail-safe. Class-S snapshot/restore rehydrates counters; public export STRIPS to empty (foreign node fresh accounting, like budget tracker); public snapshot never re-imported into live ctx.

**No leak:** CounterExhausted carries would_be/cap/in_window/window_secs + caller's OWN ucan_cid (a CID hash, from token caller presented). Per-context Class-S + per-cid keyed = no cross-member counter exposure. No key material, no println/dbg.

**Enforcement files:** ONLY pipeline_wiring.rs touched — ADDS `reserve_outlet_economy_enforces_value_caveats` assertion (check_invocation_local + consume_caveat_counters + try_consume + commit_class_s_keep in fn bodies). No existing check weakened.

**OBSERVATIONS (non-blocking):**
1. `effective_caveats: Option<&InvocationCaveats>` and `ucan_cid: Option<&str>` are DECOUPLED params; counter consume gated on `(Some(caveats), Some(cid))`. If a future caller passed caveats=Some, cid=None, counter caveats would silently skip while stateless caveats enforce (partial bypass). All current call sites couple them; hardening = bundle as `Option<(InvocationCaveats, String)>`.
2. Cross-context saga prepare_a (saga.rs:519) passes None/None/Null -> gate inert (documented single-shot scoping). Cross-context outlet invocation does NOT enforce §7.3.8 yet; different capability/UCAN so not a trivial escape, but the caveat is per-delegation-not-per-surface — worth binding when xctx outlet slice lands.
3. Escrow-auth failure (reserve:934) reverses budget/velocity/hard-rate but counter already persisted in combinator stays consumed — fail-safe over-count, intentional (mirrors nonce burn).

23 targeted tests pass (cargo test -p scp-runtime --lib caveat).
