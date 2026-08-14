---
name: review-classs-cell-pr1-scaffolding
description: ClassSCell fail-closed-persist combinator PR1 (worktree classs-guard, commit 5c50015f8) — SOUND/behavior-neutral, zero findings; scaffolding toward retiring the awk Class-S gate via compile-time enforcement
metadata:
  type: project
---

# ClassSCell PR1 scaffolding — SECURITY-CLEAN (worktree classs-guard, HEAD 5c50015f8)

Reviewed 2026-06-20. 2-file diff: new `crates/scp-runtime/src/context/actor/class_s.rs` (591L) + ownership change in `actor/mod.rs`. PR1 = pure scaffolding, no handler migrated. ZERO findings all 4 categories.

**Intent:** Replace the non-convergent awk gate `scripts/check-class-s-fail-closed.sh` with compile-time enforcement. `ClassSCell` owns `PerContextState`, exposes `Deref` (read) but deliberately NO `DerefMut`. Future step privatizes fields so the ONLY mutation path is the persist-on-commit combinators. ContextActor now owns `Option<ClassSCell>` instead of `Option<PerContextState>`.

**Q1 fail-closed-before-ack PRESERVED:** `commit_class_s` (class_s.rs:205-213): `f(&mut state)?` (f-reject short-circuits, no persist) → `persist_state_fail_closed` → Ok arm returns Ok(value), Err arm runs caller rollback + propagates PersistenceFailed. Success path reachable ONLY via persist Ok(()) arm — cannot ack without durable write. Mirrors messaging_helpers.rs:1977 persist_state_fail_closed exactly (that helper returns Ok ONLY on write success, maps any err→PersistenceFailed). `commit_class_s_no_rollback` = empty-rollback specialization (retains in-mem mutation on persist fail = fail-closed DIRECTION e.g. consumed replay nonce, still surfaces err). **Why:** ADR-049 §9 Class-S respawn crash-safety — coalesced ack would let crash roll back a mutation the caller observed closed.

**Q2 state_mut() escape hatch SCOPED TIGHT:** `pub(in crate::context)` (class_s.rs:108) — strictly narrower than struct's own `pub(crate)`. Cannot leak `&mut PerContextState` outside crate::context. `state` field fully private; no DerefMut; new/into_inner move by-value not &mut; combinators lend &mut only to closures in their own bodies, never return it. Grep: ONLY non-test caller of state_mut across scp-runtime is the single dispatch boundary mod.rs:470.

**Q3 behavior-neutral:** dispatch change is pure rename `dispatch_state(&mut state,..)` → `dispatch_state(cell.state_mut(),..)` — same &mut PerContextState as before. outcome.mutated→dirty + take/restore Option discipline + handler sigs untouched. Combinators are `#[allow(dead_code)]`, exercised only by unit tests, inert in prod. `git show --stat` = 2 files only; awk gate NOT in diff → byte-unchanged + still enforcing live sites during migration.

**Q4 no new Option panic:** only state expects are `self.state.take().expect(...)` + deps expect (mod.rs:461-462), BOTH pre-existing (identical in parent 5c50015f8^), BOTH guarded by `self.state.is_none()||...` early-return→skeleton_dispatch at mod.rs:441. Wrapping in ClassSCell doesn't change Option discipline. class_s.rs prod code has no unwrap/expect/panic/index (only #[cfg(test)], allow-listed). No crafted ContextCommand reaches the expect.

**Pattern (positive):** closed-by-construction compile-time enforcement replacing ever-expanding awk denylist = the CLAUDE.md over-engineering guidance done right; keeping awk gate live until full migration is correct fail-safe ordering.
