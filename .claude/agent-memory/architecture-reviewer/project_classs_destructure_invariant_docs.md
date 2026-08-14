---
name: classs-destructure-invariant-docs
description: ADR-049 §9 ClassCMut destructure SAFETY-INVARIANT comments review — the `..` rest is fail-safe, documentation is the right vehicle for a struct-shape invariant the compiler can't name
metadata:
  type: project
---

Reviewed branch `refactor/classs-type-guard` @ d8207cde2 (worktree classs-guard), file `crates/scp-runtime/src/context/actor/class_s.rs`. Verdict: architecturally sound, APPROVED.

**The load-bearing structural fact:** `ClassCMut::new` / `GovernanceClassCMut::new` destructure the whole `&mut` into field-granular refs with a `..` rest. The `..` is the FAIL-SAFE direction — a future-added Class-S-containing field falls into `..` (unreachable from the view = cannot be mutated). The DANGEROUS direction (binding a Class-S field `&mut`) requires actively NAMING it, which the SAFETY INVARIANT comment forbids. So a new Class-S field does NOT silently defeat airtightness; it just becomes unreachable until someone deliberately wires it.

**Verified by reading:** only two Class-S-containing fields exist — `PerContextState.class_s` (ClassSState, bound shared `&`) and `GovernanceState.class_s` (GovernanceClassS, dropped into GovernanceClassCMut's `..`). All `&mut`-bound fields (members/receive_buffer/role_state/checkpoint_events_since; velocity/budget/cooldown/economic_policy) contain no Class-S substruct. snapshot/restore mirror is total over both.

**Why `ClassSMut` keeps whole `&mut` (rest_mut) but `ClassCMut` can't:** asymmetry is load-bearing and correct — ClassSMut's combinator persists fail-closed so any Class-S reachable through the `&mut` is covered; ClassCMut's combinator (best-effort / compensation arm) does NOT persist fail-closed, so it must hold no whole `&mut`.

**`forbid(unsafe_code)` at scp-runtime/src/lib.rs:21** is the real backstop the GovernanceClassCMut doc cites (a `*const _ as *mut _` escape needs `unsafe`).

**ConsequenceStateSplit migration NOT precluded:** existing `ConsequenceStateSplit.governance: &mut GovernanceState` (governance_logic.rs:130) is exactly the whole-bucket `&mut` this refactor removes; `ClassCSplit` defines the target field-granular shape, matching the other four fields exactly. Migration is correctly deferred.

**Documentation-vs-scope-creep verdict:** the destructure-invariant comments are the RIGHT vehicle, not creep. The invariant ("don't bind a Class-S-containing field `&mut` in this destructure") is a maintainer obligation the type system cannot name (co-descendant modules under context::actor, no pub(in) separation possible). It is sited exactly where a maintainer would edit (the `let PerContextState{..}=` / `let GovernanceState{..}=`). The `..` makes the default fail-safe, so the comment guards only the active-mistake path. Proportionate.

Verified: scanner check-class-s-fail-closed.sh byte-identical + exits 0; 26 unit tests pass; no enforcement files touched; zero external callers (pure dead_code scaffolding); §9 ADR amendment correctly deferred to terminal gate-deletion step.
