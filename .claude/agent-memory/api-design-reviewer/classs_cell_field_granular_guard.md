---
name: classs-cell-field-granular-guard
description: ClassSCell (ADR-049 §9) field-granular Class-S mutation guard — API review APPROVED; design pattern notes for the actor refactor
metadata:
  type: project
---

# ClassSCell / ClassCMut field-granular Class-S guard (ADR-049 §9)

`crates/scp-runtime/src/context/actor/class_s.rs` (`pub(crate)`, internal boundary). Converts the Class-S fail-closed-persist invariant from a source-text scanner (`scripts/check-class-s-fail-closed.sh`) into a compile-time guarantee. Reviewed branch `refactor/classs-type-guard` @643afbb1c — **APPROVED, merge-ready, no API-design changes.**

**Why:** ADR-049 §9 requires Class-S mutations (spending nonce, executed proposals, saga reservations, replay dedup) be persisted fail-closed; a best-effort/coalesced ack would let an actor crash re-open a replay/re-spend window.

**How to apply (the design pattern worth reusing):**
- Misuse resistance BY CONSTRUCTION, not convention: the best-effort/compensation views (`ClassCMut`, `GovernanceClassCMut`) destructure their `&mut` into field-granular refs at construction (a `&mut` per Class-C field + a shared `&` to Class-S). Because no whole-bucket `&mut PerContextState`/`&mut GovernanceState` is held anywhere, a whole-bucket accessor (`rest_mut`/`governance_mut`) is *uncompilable* — nothing of that type to return. Field privatization is NOT relied on (handler + combinator modules are co-descendants of `context::actor`, so `pub(in PATH)` can't separate them).
- The fail-closed view `ClassSMut` MAY hold a whole `&mut` (`rest_mut`) because its combinator persists fail-closed and covers any Class-S field reached. That asymmetry is the load-bearing decision and is correctly documented.
- Rollback strategy encoded in combinator NAME (`_keep`/`_restore`/`_compensating`/`_keep_compensating`/`_then_append`), removing the foot-gun of a caller-supplied rollback closure that undoes the wrong field. Combinator owns the snapshot/restore.
- No `DerefMut` on `ClassSCell` — enforced by `static_assertions::assert_not_impl_any!`. The Class-C views have no `Deref` at all (whole-bucket read removed), so they need no separate DerefMut guard.
- Safe-Rust airtightness backstopped by crate-root `#![forbid(unsafe_code)]` (`scp-runtime/src/lib.rs:21`) — `forbid` (unlike `deny`) can't be locally re-enabled; closes the `*const _ as *mut _` cast escape on the shared `class_s` ref. Note is technically accurate.
- `state_mut` is a TEMPORARY escape hatch deleted in the terminal migration step; sites still on it are expected mid-migration, not defects.

**Doc-honesty check (this was the PR's whole point):** all stale positive `Deref` claims for the Class-C views were removed; every surviving `Deref` mention is either to `ClassSMut`/`ClassSCell` (which genuinely impl it) or phrased as removal. Verified by grep + reading both impls.
