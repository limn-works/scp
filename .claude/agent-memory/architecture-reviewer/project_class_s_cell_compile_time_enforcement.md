---
name: class-s-cell-compile-time-enforcement
description: ClassSCell refactor — replacing the non-convergent awk Class-S fail-closed gate with compile-time (Deref-no-DerefMut + private fields + combinator) enforcement, ADR-049 §9
metadata:
  type: project
---

ClassSCell (`crates/scp-runtime/src/context/actor/class_s.rs`) is a multi-PR refactor to make ADR-049 §9's Class-S "fail-closed persist after any mutation" invariant a COMPILE error, retiring the non-convergent `scripts/check-class-s-fail-closed.sh` awk scanner (which had 4 black-hat evasions: extern-fn, &mut-alias, ref-mut-destructure, autoref-method).

**Why:** the awk gate is a textbook non-convergent denylist (CLAUDE.md "Guard against non-convergent enforcement" tenet + `.docs/lessons/ast-gate-checks-definition-not-name-resolution.md`). Each new way to alias `&mut PerContextState` = a fresh marker. ~9+ markers accreted.

**Precedent that makes this DEFINITELY the right direction:** ADR-049 §5 (OwnedIdentityDid, lines 96-117) already retired a tree-sitter scanner in favor of type-system + compiler-lint enforcement, with the explicit rationale "a scanner adds no marginal security over the type system; the compiler is the sound, convergent enforcer." ClassSCell is the SAME move for Class-S. When reviewing these PRs, hold them to that §5 standard.

**Design (eventual end state):** private Class-S fields on `PerContextState` (today they are PUBLIC: `pub members`, `pub membership`, `pub role_state` at actor/state.rs:798-807) + Deref-no-DerefMut reads + `&mut PerContextState` vended ONLY inside `commit_class_s`/`commit_class_s_no_rollback`/`commit_best_effort` combinators (each persists by construction). Cross-crate residual (`role_state.ceiling=` / `membership.remove_member()` live in scp-protocol: roles.rs:795, membership.rs:159) to be gated by a `ClassSCommitToken` ZST minted only by the runtime combinator (does NOT exist yet as of PR1).

**PerContextState shape (the key structural fact):** ONE flat struct mixing Class-S fields (membership/members/role_state/governance) and Class-C/structural fields (receive_buffer/merkle_tree/broadcast_context) — fields are a mix of `pub` and `pub(crate)`. Combinator `f: FnOnce(&mut PerContextState)` hands the WHOLE state, so a handler mutating BOTH a Class-S and a Class-C field in one body works and persists fail-closed (over-persisting structural state synchronously is safe — never an authorization break). `commit_best_effort` is the escape for pure-Class-C handlers.

**`check-class-s-fail-closed.sh` is NOT in CLAUDE.md's enforcement-files list** — so retiring it won't need human approval per that list, BUT it also isn't currently protected by it. The two `security_critical_state_is_class_s_or_m_not_coalesced` FIELD round-trip test (§9 enforcement half 1) is SEPARATE and must survive — ClassSCell only replaces the consume-SITE half.

**ADR-049 §9 will need amending when the gate is retired** (artifact-flow: ADR §9.164-168 currently names the awk gate as the enforcement mechanism). Amend the ADR FIRST (flows down), then retire the gate.

PR1 (commit 5c50015f8) = pure scaffolding: combinators + unit tests, `Option<ClassSCell>` in ContextActor, TEMPORARY `state_mut()` escape hatch (vends bare `&mut`) so handlers compile unchanged, fields stay public, awk gate unchanged. Sound foundation. See [[lock_free_read_invariant]] — combinators are SYNC (persist helpers are sync), so no read-path lock concern.
