---
name: review-classs-field-granular-view
description: CLEAN review of class_s.rs field-granular best-effort views (ClassCMut/GovernanceClassCMut) — ADR-049 §9 fail-closed structural enforcement
metadata:
  type: project
---

# class_s.rs field-granular ClassCMut/GovernanceClassCMut — CLEAN (no findings)

Worktree classs-guard, branch refactor/classs-type-guard HEAD 643afbb1c (doc-only commit; reviewed FILE as-stands). File: crates/scp-runtime/src/context/actor/class_s.rs (2391 lines, ~1098 prod + tests).

**Why:** ADR-049 §9 Class-S fail-closed invariant — every Class-S mutation must persist fail-closed before ack. This PR replaces whole-`&mut` best-effort views with FIELD-GRANULAR refs so a Class-S `&mut` is uncompilable on the best-effort/compensation path.

**How to apply (verified facts, re-check before relying):**
- `PerContextState` (actor/state.rs:1015): ONLY Class-S fields are `class_s: ClassSState` (1260) and `governance: GovernanceState` (1115, contains nested `class_s`). `ClassCMut::new` (class_s.rs:508) destructures: members/receive_buffer/role_state/checkpoint_events_since as `&mut`, membership+class_s as shared `&`, governance→`GovernanceClassCMut::new`, `..` absorbs rest. Since the only Class-S paths are the 2 named fields (class_s=shared `&`, governance=wrapped), `..` cannot leak a Class-S `&mut`. Sound.
- `GovernanceState` (context/state.rs:1044): ONLY Class-S field is `class_s: GovernanceClassS` (1156). `GovernanceClassCMut::new` (393) binds velocity_tracker/budget_tracker/cooldown_until/economic_policy as `&mut`, next_proposal_seq as shared `&`, `..` absorbs `class_s` (discarded). No `&mut` reach to governance.class_s. Sound.
- Shared `&ClassSState` read-only: only `class_s(&self)->&ClassSState` accessor; no `&`→`&mut` coercion possible because crate-root `#![forbid(unsafe_code)]` (scp-runtime/src/lib.rs:21) rejects the `*const as *mut` escape crate-wide.
- ClassSMut (fail-closed view) unchanged; rest_mut returns whole `&mut PerContextState` — SAFE because its combinators persist fail-closed.
- All 5 ClassSMut-vending combinators persist fail-closed (keep/restore/compensating/keep_compensating/then_append). Constructors `const fn new` crate-internal.
- Gate scripts/check-class-s-fail-closed.sh: byte-identical to origin/main (empty diff) + PASSES exit 0.
- §9.4.3 bearer barrier intact: SagaPreparedState (saga_prepared_state.rs:67) derives NONE of Clone/Debug/Serialize; snapshot via sanctioned mirror. Only derive in class_s.rs = `#[derive(Debug)]` on AppendOutcomeError (bool+ContextError, no bearer).
- Behaviour-neutral: HEAD is comment-only diff. Combinators have NO production caller (only ClassSCell::new wired @actor/mod.rs:237; live handlers still use state_mut escape hatch, 4 sites). All `#[allow(dead_code)]`. No panic/unwrap/expect in prod lines 1-1098 (tests cfg-gated + allow). compiles clean; 26/26 tests pass incl assert_not_impl_any!(ClassSCell: DerefMut).
