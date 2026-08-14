---
name: review-classs-type-guard-ec108ea5f
description: Class-S type-guard refactor (ClassCMut/GovernanceClassCMut field-granular views) security review — CLEAN, no findings
metadata:
  type: project
---

# Class-S type-guard refactor (ADR-049 §9) — CLEAN

Branch `refactor/classs-type-guard` HEAD `ec108ea5f` (worktree classs-guard). Substantive file: `crates/scp-runtime/src/context/actor/class_s.rs` (2404 lines). READ-ONLY review. ZERO findings.

**Why:** Behaviour-neutral scaffolding that strengthens ADR-049 §9 Class-S fail-closed invariant from source-text gate toward compile-time enforcement.
**How to apply:** When reviewing further PRs in this refactor chain (PR3 token threading, field privatization, `state_mut` deletion), the airtightness mechanism below is the baseline — verify it is not weakened.

## The mechanism (verified sound + compiles)
- `ClassSCell` owns `PerContextState`; Deref→`&` only, NO DerefMut (static_assertions guard @class_s.rs:1140). Mutation only via combinators.
- Class-S-capable views (`ClassSMut`) → 5 combinators all persist_state_fail_closed: `commit_class_s_keep/_restore/_compensating/_keep_compensating/_then_append`.
- Best-effort `ClassCMut` + `GovernanceClassCMut` (handed to `commit_class_c_best_effort` + compensation closures, NO fail-closed persist) hold ONLY FIELD-GRANULAR refs — `&mut` per Class-C field + SHARED `&ClassSState`/`&membership`/`&next_proposal_seq`. NO whole `&mut PerContextState`/`&mut GovernanceState`/`&mut ClassSState`/`&mut GovernanceClassS` anywhere → a `rest_mut`/`governance_mut` whole-bucket accessor is UNCOMPILABLE (nothing of that type to return).
- KEY SUBTLETY (verified by `cargo check -p scp-runtime` = exit 0): `let PerContextState{class_s, ..} = state` on a `&mut` place yields `class_s: &mut ClassSState` by default binding mode, then mut-to-shared REBORROWED into the `class_s: &'a ClassSState` field at the struct literal. Result stored = genuine shared `&`. No safe `&`→`&mut` coercion exists; only escape (`*const as *mut`) needs `unsafe`, rejected by `#![forbid(unsafe_code)]` @scp-runtime/src/lib.rs:21 (no unsafe in file). Airtight by construction, NOT by field privatization (co-descendant handler modules share `context::actor` so no pub(in) separates them).
- Constructors `ClassSMut/ClassCMut/GovernanceClassCMut::new` all PRIVATE → only this module mints views.

## Verified neutral / clean
- Gate `scripts/check-class-s-fail-closed.sh` BYTE-IDENTICAL to origin/main (diff=0 bytes), PASSES (exit 0).
- mod.rs = pure ownership wrap (ClassSCell::new at construction; handlers still get `&mut` via temporary `state_mut()` escape hatch). All combinators `#[allow(dead_code)]`, exercised only by unit tests.
- saga.rs 154-line diff = ENTIRELY mechanical `state.<field>`→`state.class_s.<field>` relocation of 5 Class-S fields (saga_pending/xctx_nonce_dedup/xctx_committed_outputs/xctx_committed_invocations/xctx_caller_reservations into class_s sub-struct from PR2a). Verified line-by-line via `git diff -w`. No logic/ordering change.
- No panic/unwrap/expect on production path (only #[cfg(test)] under `#[allow(clippy::unwrap_used,…)]`).
- §9.4.3 bearer barrier INTACT: `SagaPreparedState` (saga_prepared_state.rs:67) keeps "No Clone/Debug/Display/Serialize", NOT touched this branch. ClassSState derives nothing. Snapshot/restore via sanctioned mirrors (`SagaPreparedStateSnapshot` Clone+Serialize = intended persistence projection, not live bearer; `NonceDedup::entries`/`from_entries_with_ttl`).
