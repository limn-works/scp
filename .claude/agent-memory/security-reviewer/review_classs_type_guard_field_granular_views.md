---
name: review-classs-type-guard-field-granular-views
description: CLEAN security review of refactor/classs-type-guard (ClassSCell field-granular ClassCMut/GovernanceClassCMut views) — ADR-049 §9 fail-closed Class-S, no &mut path to Class-S on best-effort path
metadata:
  type: project
---

# Class-S type-guard field-granular views — CLEAN (worktree classs-guard, HEAD d8207cde2)

Substantive file: `crates/scp-runtime/src/context/actor/class_s.rs` (2410 lines; 1-1117 production, 1118+ tests). Latest commit comment-only; whole branch introduces ClassSCell machinery (19 files, +3419/-408). NO security findings any category.

**Why airtight (verified against real struct defs):**
- `ClassSCell` owns `PerContextState`; `Deref` only (reads), NO `DerefMut` — `static_assertions::assert_not_impl_any!(ClassSCell: DerefMut)` guards it (class_s.rs:1146). No `&mut cell.field` path.
- Mutation only via combinators handing a *view*. `ClassSMut` (fail-closed persist, may hold whole `&mut` incl `rest_mut`) vs `ClassCMut`/`GovernanceClassCMut` (best-effort/compensation, NO subsequent fail-closed persist).
- `ClassCMut::new` (class_s.rs:517) DESTRUCTURES `&mut PerContextState` ONCE: `class_s` bound as shared `&ClassSState` (read-only via `class_s()` accessor, no `&mut` counterpart), `membership` shared `&`, `governance` wrapped in `GovernanceClassCMut`, four genuine Class-C fields `&mut`. Verified `PerContextState.class_s: ClassSState` and `.governance: GovernanceState` are the only Class-S-containing fields (actor/state.rs:1015).
- `GovernanceClassCMut::new` (class_s.rs:393) destructures `&mut GovernanceState`: binds 4 Class-C fields `&mut`, `next_proposal_seq` shared `&`, and **`class_s: GovernanceClassS` FALLS INTO `..` REST → unreachable**. Verified GovernanceState has exactly one Class-S field `class_s: GovernanceClassS` (state.rs:1156). `..`-rest is the FAIL-SAFE default: a future Class-S-containing field added to either struct is unreachable unless explicitly bound — only an explicit `&mut` binding of a Class-S field would re-open the hole (documented SAFETY INVARIANT comment at both `new`s).
- Result: NO `&mut PerContextState`/`&mut GovernanceState`/`&mut ClassSState`/`&mut GovernanceClassS` exists anywhere in the best-effort views → a `rest_mut`/`governance_mut` whole-bucket accessor is UNCOMPILABLE (nothing of that type to return), and a Class-S mutation on the best-effort/compensation path is a COMPILE error by construction. Independent of field privatization (which is a later PR; fields currently `pub(crate)`, handler modules are co-descendants so vis wouldn't help — destructure is what closes it).
- Shared `&class_s`→`&mut` coercion impossible: only escape = `*const _ as *mut _` cast needs `unsafe`; crate root `#![forbid(unsafe_code)]` (lib.rs:21) rejects crate-wide, can't be locally re-enabled.

**Every ClassSMut-vending combinator persists fail-closed:** `_keep`/`_restore`/`_compensating`/`_keep_compensating`/`_then_append` all call `persist_state_fail_closed`; rollback owned by combinator (snapshot/restore of Class-S sub-structs, not caller closure). `_then_append`'s `after` gets READ-ONLY `&PerContextState` (no class_s_mut nameable). `commit_class_c_best_effort` → `persist_state_best_effort` + ClassCMut (no Class-S mutator).

**Constructors locked:** `ClassSMut::new`/`GovernanceClassCMut::new`/`ClassCMut::new` all module-PRIVATE `const fn new` (only combinators construct views). `ClassSCell::new` pub(crate) (harmless wrapper). `state_mut()` escape hatch is `pub(in crate::context)` — documented temporary, deleted in terminal migration step.

**Behaviour-neutral:** ZERO production callers of any combinator (grep clean) — `#[allow(dead_code)]` scaffolding, exercised only by this module's unit tests. Handlers still mutate via `state_mut()`. NO unwrap/expect/panic/unreachable/todo/unimplemented in production portion (1-1117); panics only in `#[cfg(test)]`.

**Gate:** `scripts/check-class-s-fail-closed.sh` BYTE-IDENTICAL to origin/main (0-line diff) + PASSES (exit 0). View `*_mut()` accessors carry no Class-S MARKER tokens; combinators take closures (markers appear in caller closures, routed through persist boundary later).

**§9.4.3 bearer barrier intact:** `ClassSState`, `GovernanceClassS`, `SagaPreparedState`, `CrossContextToolInvocationPrepared` carry NO Clone/Debug/Serialize/Deserialize derives. Snapshot/restore via sanctioned mirrors (SagaPreparedStateSnapshot, NonceDedup::entries/from_entries_with_ttl, GovernanceClassSSnapshot, NonceTracker snapshot_entries/from_snapshot with clock threaded). New code adds no derive to any bearer type. `spending_nonce_tracker: NonceTracker<Arc<dyn Clock>>` correctly non-Clone (holds clock).

**Compiles clean:** `cargo check -p scp-runtime --tests` Finished, no errors — borrow-checker accepts every destructure + reborrow (the load-bearing mechanism). Tests cover keep/restore/compensating/keep_compensating/then_append (all arms incl durability_diverged true/false) + best_effort split/governance/velocity/budget/policy/receive/role + into_inner.
