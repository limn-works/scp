---
name: wasm-consequence-dispatcher-removal
description: Review of cb60846be — deletion of vestigial WASM-only ConsequenceDispatcher trait; convergence coverage preserved by native path
metadata:
  type: project
---

Commit cb60846be (branch chore/cut-wasm-stray-refs, ADR-055 WASM cut) deleted 586 lines from
scp-protocol/src/trust/consequence.rs: the `pub trait ConsequenceDispatcher`, `enforce_triggered` fn,
helpers LeafCtx/mint_leaf/enforce_one_triggered/push_enforced, and `#[cfg(test)] RecordingDispatcher`
+ its 4 ordering/durability mock tests. APPROVE — SOUND, no coverage regression.

**Why:** the trait's only production impl was the deleted WASM bridge (crates/scp-ffi/wasm/ now gone —
only napi/uniffi/src(PyO3) remain). Native runtime never routed through the trait; it has its own
`enforce_triggered_consequences` (scp-runtime governance_logic.rs:187) with the default-no-op
`append_durable_consequence_leaf` overridden only by WASM. So the trait + mock tests were dead in prod.

**How to apply (convergence §9.9.3 verification):**
- Native path is a STRICT SUPERSET of deleted trait logic. process_one_triggered_consequence (gl.rs:216)
  + emit_consequence_triggered/emit_absent_member_enforcement_failed/emit_consequence_enforced_success/
  emit_failure_escalation each gate the durable Merkle leaf on `durable = is_convergent_trigger(&r.trigger)`,
  mint leaf BEFORE the receive-buffer push (H4 ordering), bump checkpoint_events_since.
- The 4 named convergence tests (gl.rs convergence_tests mod) use a REAL MerkleEventLogProvider and assert
  root-delta: velocity/tool_rate → root UNCHANGED (non-convergent, no leaf); warning_count/custom → root
  CHANGES (convergent, leaf minted). Stronger than the deleted mock-trace tests (real Merkle vs recorded calls).
  ConsequenceTriggered ContextEvent always surfaced regardless of durability. All 4 PASS.
- Kept helpers (is_convergent_trigger, convergent_consequence_timestamp, trigger_kind_str,
  consequence_action_type, merge_consequence_events, evaluate_consequence_rules, matches_trigger + data types)
  all still defined in consequence.rs and referenced by native path (governance_logic.rs, governance_helpers.rs,
  governance.rs handler, class_s.rs). Not orphaned.
- `git grep "ConsequenceDispatcher|\benforce_triggered\b"` (excl enforce_triggered_consequences) over
  crates+bindings = EMPTY. No production caller lost. enforce_triggered_consequences untouched + wired.
- gl.rs:19 comment fix (1fd650ed4) = section-header prose only (removed "shared trait" ref). 899b7c890
  scaffold/template = JSDoc + README + HTML-note prose only (in-process-NAPI vs ADR-055 remote-thin-client);
  Context.create/imports/statements untouched. DOC-ONLY confirmed.
- consequence.rs:174,193 `consequence_event_payload` mentions = accurate doc cross-refs on kept helpers,
  not orphaned code (real builder lives in scp-event-log/payload.rs, called by native gl.rs).
- Full suite: 5305 scp-protocol+scp-runtime tests pass (--features scp-runtime/testing).
