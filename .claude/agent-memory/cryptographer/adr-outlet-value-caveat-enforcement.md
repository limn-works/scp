---
name: adr-outlet-value-caveat-enforcement
description: §7.3.8 value-caveat runtime enforcement slice (feat/outlet-value-caveat-enforcement @99a290b15) — crypto enforcement-soundness review. RESOLVES the prior HIGH from outlet-pr3-capability-redesign.
metadata:
  type: project
---

# §7.3.8 value-caveat runtime enforcement (feat/outlet-value-caveat-enforcement @99a290b15)

RESOLVES the prior HIGH ([[outlet-pr3-capability-redesign]]: post-input caveat enforcement ABSENT/latent). VERDICT: enforcement SOUND. All 6 FOCUS items CONFIRMED. 2 findings: 1 provenance (MEDIUM), 1 latent defense-in-depth (LOW). 23/23 caveat tests pass.

## SOUND (verified)
- **Source unforgeable (F1).** 3 bridges (pyo3 outlets.rs:602, napi outlets.rs:496, uniffi bridge.rs:13041) IDENTICAL: parse the ALREADY-VALIDATED invocation `ucan_token`, `TokenNbCaveatResolver.resolve_caveats` = `token.payload.nb.clone()` (validate.rs:501), `ucan_cid=compute_revocation_cid(token.encoded)`. Signature covers nb; validate.rs:1661 verify_edge_attenuation enforces child nb ≤ parent nb (narrow rejects widen/FieldRemoved) at EVERY edge; outlet edges REQUIRE TokenNbCaveatResolver (NoCaveatResolver → (None,None) OriginKindUnspecified reject) so leaf nb read is the cryptographically-validated narrowed set. NOT spending_ucan (separate §19.5 token, nb:None). Test caveats_sourced_from_invocation_nb_never_from_spending_ucan.
- **Non-rollback (F2).** caveat_counters is owned Class-S HashMap on ClassSState (state.rs), consumed ONLY inside commit_class_s_keep (free path) / commit_class_s_keep_compensating (paid path). snapshot()/restore() round-trip (tested). ContextSnapshot.caveat_counters #[serde(default)]. export_import strip_snapshot_for_public → HashMap::new() (public never re-imported to live). commit KEEP = consumed cap kept on persist failure (tested reserve_counter_consume_is_kept_on_persist_failure max_calls_used=1). NO class_c/coalesce writer.
- **Sync before consume (F3).** check_invocation_local runs in COMMON pre-block (outlets_helpers.rs:681, after action_cost known, before paid/free branch → before ANY Class-S consume). Reject refunds velocity+hard_rate inline, touches no counter. consume_caveat_counters runs inside combinator (paid :816 LAST mutation after nonce; free :890 dedicated commit). Test reserve_sync_check_precedes_counter_consume.
- **rate_window not widenable (F4).** now_secs = deps.clock.now_secs() (supervisor invoke_outlet_with_economy :10376; saga deps.clock) — NOT caller/FFI-supplied. prune uses saturating_sub; restart prunes vs restored wall clock → only drops MORE; timestamps persisted Class-S.
- **amount_max_per_call bound to priced cost (F5).** check_invocation_local(input, action_cost, ...) estimated_cost = action_cost from economy_pre_check (caveats.rs:826 estimated_cost.value() > cap). Counter AmountCumulative also consumes action_cost.value(). Not caller-asserted.
- **narrow() inheritance (F6).** narrow_le_amount/narrow_le_u64 downward, FieldRemoved reject; leaf nb IS materialized narrowed set (spec canonical model, mint folds parent→child).
- consume_caveat_counters all-or-nothing (mutate clone, insert only on full success); per-ucan_cid isolation; CounterExhausted→SCP-OUTLET-6110 Authorization slug. try_consume rejection leaves record unchanged.

## FINDINGS
1. **PROVENANCE MEDIUM.** Spec 07 §7.3.8 (lines 138/143/145, mirrored 208-210) STILL says value-caveat enforcement + CaveatCounterStore "deferred / NOT YET WIRED / type does not exist on current branch." This slice WIRES it. Docs commit 99a290b15 touched only CODE doc comments, not the spec. Artifact-flow (spec leads code) requires updating spec to mark value-caveat family LIVE + reflect ACTUAL shape: owned Class-S caveat_counters map via ADR-049 §9 snapshot, NOT repo-backed CaveatCounterStore under context/{id}/caveat_counters/{ucan_cid} (§7.3.8:145/§17.3). Spec now understates enforcement + misdescribes persistence = phantom provenance.
2. **LATENT LOW / defense-in-depth.** Counter consume gated `if let (Some(caveats), Some(cid))` — (Some(caveats), None) with counter-bearing caveat SILENTLY skips consume while sync check still runs. Violates caveats.rs:429 stated contract ("MUST treat has_counter_bearing_caveat()==true as fail-closed — a cap that cannot be enforced must reject, not silently pass"). UNREACHABLE today (3 bridges mint cid Some iff caveats Some via .map(|_|...)), but invariant is convention at 3 sites not type-enforced. Fix: couple as Option<(InvocationCaveats,String)> OR fail-closed when has_counter_bearing_caveat() && cid.is_none().

## INFORMATIONAL (spec-inherent, NOT slice defect)
- Counters keyed by leaf ucan_cid (spec-faithful §7.3.8:145 + :149 per-delegation binding). Self-minting sibling leaves off a parent bearing max_calls/rate_window → fresh counter per leaf CID = multiplies NON-economic caps. amount_max_cumulative additionally backstopped by per-member SpendingCapability budget (§7.3.8:149); max_calls/rate_window backstopped only by per-invoker hard_rate_limit (Matrix-style) + velocity tracker (both apply every call). Practical impact bounded; spec's per-delegation model, not a deviation.
- Counter consume is ATTEMPT-based (kept across later executor failure) — conservative over-count, never under-count. Sound.
- Cross-context / saga Prepare-A leg threads None caveats + Null input (deferred later slice); counter gate inert there. Correct.
