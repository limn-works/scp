---
name: classs-cell-combinator-api
description: ClassSCell view-typed combinator API (ADR-049 §9 Class-S fail-closed persist) — review findings on coverage + restore-scope footgun
metadata:
  type: project
---

ClassSCell rework (commit 6352bc46a, branch chore/fuzz-pin-nightly worktree classs-guard) replaced caller-authored inverse-closure rollback with combinator-owned snapshot/restore. File: crates/scp-runtime/src/context/actor/class_s.rs.

**Why:** prior PR1 combinators took `R: FnOnce(&mut PerContextState)` caller rollback — footgun (caller could undo wrong field). The source-text gate `check-class-s-fail-closed.sh` is non-convergent; the type-level goal is to make Class-S fail-closed-persist a compile error to violate (no DerefMut on ClassSCell; privatize Class-S fields in a later PR; `state_mut()` is a temporary escape hatch).

**Surface:** views ClassSMut (class_s_mut/governance_class_s_mut/rest_mut) vs ClassCMut (RESTRICTED — no class_s reach; rest_mut/governance_mut/split_class_c). 5 combinators: commit_class_s_keep (retain-on-fail), _restore (snapshot+restore Class-S), _compensating (async, restore THEN async external undo, gives ClassCMut), _then_append (async, persist-then-append, returns AppendOutcomeError{mutated,err}), commit_best_effort (ClassCMut). ~30 saga/governance/economy sites migrate later.

**How to apply (review verdict NEEDS REVISION):**
- BLOCKING finding: `commit_class_s_restore` snapshots/restores ONLY the Class-S mirror (ClassSState + GovernanceClassS), NOT Class-C. Real sites mutate BOTH classes in one `f` — saga Prepare-A (saga.rs:455-514) calls reserve_tool_economy (governance Class-C velocity/budget/hard_rate_limit) AND xctx_caller_reservations (Class-S). If an author picks `_restore` there, persist-fail leaves the Class-C deductions applied = silent partial rollback. Correct combinator is `_compensating` (manual Class-C undo via rollback_tool_economy through ClassCMut), but nothing forces that choice — same "caller must know what f touched" footgun the rework exists to kill. Fix: either full-PerContextState restore, or loud precondition + debug guard on `_restore`.
- `_keep` name encodes fail-handling not decision criterion — author can't tell it means "monotonic/irreversible mutation that MUST survive persist-fail" (recorded replay nonce). Suggest rename (retain_on_fail / monotonic).
- AppendOutcomeError{mutated,err} is sufficient for commit_b (mutated=false ⇒ durable matches rollback; true ⇒ divergence). `mutated` conflates initial-persist-fail vs repersist-fail but `err` variant distinguishes.
- AsyncFnOnce (edition-2024 async closures) correct + ergonomic for handler authors — lets returned future borrow view + &ActorDeps across await.
- rest_mut() means different things on ClassSMut ("non-Class-S portion") vs ClassCMut (whole &mut) — same name, different contract; nit.

ClassSState snapshot fields: saga_pending, xctx_nonce_dedup, xctx_committed_outputs/invocations, xctx_caller_reservations (state.rs:907). GovernanceClassS restore needs deps.clock to rebuild spending_nonce_tracker (state.rs:1248).
