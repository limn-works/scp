# ChangeRole Shared Orchestration Review (#1877 slice, feat/changerole-shared-orchestration b800910c7)

CLEAN review, no actionable findings. Unified `orchestrate_change_role<S: ContextStateMut>` in
`crates/scp-protocol/src/context/orchestration/{mod.rs,state_view.rs}`; native + WASM each impl the trait.

Verified byte-identity / correctness:
- Native `append_context_event(RoleAssigned)` (old) == `append_context_event_with_payload(EventPayload::default())`
  (new): both forward to `append_event(..., EventPayload::default(), ...)` (builder.rs:187-223). Identical leaf.
- Native guard reorder (require_active + has_member moved OUTSIDE commit_class_s_keep into the body, vs INSIDE the
  closure before): no behavioral diff. ClassSMut::new is a no-op borrow; persist only runs after f returns Ok.
  On reject: no mutation, no persist, no leaf — same as before. `require_active` only ever returns
  Ok or ContextNotActive (state.rs:1997), so `is_active()==false → inactive_error()=ContextNotActive` is exact.
- Native persist-fail-closed kept atomic: role mutation lives inside `assign_role`'s `commit_class_s_keep`
  (keep direction), `persist_fail_closed()` is a no-op. On persist failure: assign_role returns Err → body `?` →
  no append_leaf, no checkpoint increment. Identical to old `commit_class_s_keep(...)?` short-circuit.
- checkpoint_events_since increment moved into native append_leaf, AFTER append succeeds — same order.
- WASM: require_active_context_mut → require_context_mut switch preserves codes (CTX_2001 not-found,
  CTX_2013 inactive via inactive_error, CTX_2015 member). Broadcast author rotation logic unchanged.
  RoleAssigned leaf appended in dispatch BEFORE GovernanceActionExecuted leaf (manager.rs:3272 dispatch,
  3320 executed). Single dispatch caller (execute_governance_action) — no double-append, all quorum/auto
  paths funnel through it.
- consequence.rs two-leaf-root test correct (RoleAssigned empty + GovernanceActionExecuted shared payload).
- wasm_conformance.rs RoleAssigned removed from the ~40-event "not yet appended by WASM" ignore list (correct,
  WASM now appends it). New replay test pins empty-payload/executor/ordering.

All compiled clean (scp-protocol, scp-runtime, scp-ffi-wasm wasm32). Clippy clean. Tests pass:
orchestration unit (3), wasm cross_impl (16), native cross_impl_change_role + broadcast (3), consequence (31).
