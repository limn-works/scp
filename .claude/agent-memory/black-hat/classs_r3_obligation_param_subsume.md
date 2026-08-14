---
name: classs-r3-obligation-param-subsume
description: ADR-049 §9 Class-S r3 (commit 71f81dc8d) — obligation-as-REQUIRED-PARAMETER closes BLACK-1a (GROW-without-arming is now E0061 compile error; arm-then-drop panics). Residual = subsume() ALWAYS discards (zero persist); correctness is documented precondition only, 2 prod sites honor it.
metadata:
  type: project
---

# Class-S r3 @ 71f81dc8d — obligation-as-parameter is a REAL structural upgrade; subsume is a discard primitive

File: crates/scp-runtime/src/context/actor/class_s.rs (7240 lines). 4 probes COMPILED+RAN in worktree classs-r3-bh, reverted zero-diff.

## WHAT THE COMMIT FIXED (vs prior BLACK-1a / BLACK-3 waves) — GENUINE
The consequence GROW methods on `ConsequenceRoleStateMut` (suspend_capabilities:1532, suspend_all:1563, demoting system_assign_role:1602) now take `obligation: &mut Option<ClassSCommitToken>` + `context_id: &str` as REQUIRED params and arm internally via `ClassSCommitToken::note_downward_auth` (3265, idempotent: `if did_grow && sink.is_none()`).
- PROBE 3 PROVEN: omitting the obligation is `error[E0061]: this method takes 3 arguments but 1 was supplied`. The old bool-flag "forget the flag" (BLACK-1a/BLACK-3) is now a COMPILE ERROR. Real upgrade from convention→structure.
- PROBE 1 PROVEN: arm via best-effort `class_c_view().consequence_split().role_state.suspend_all(victim,&mut sink,ctx)` then DROP the armed sink → Drop guard PANICS ("dropped without commit"). The drop variant of BLACK-1a is CLOSED (GROW arms the sink itself; dropping it trips the #[must_use] linear guard).
- Shape-fragile compile-witnesses (role_view_grow_resolves_to_trait etc., the BLACK-3 receiver-fragile ones) were DELETED and replaced with an HONEST doc (consequence_split @2421: "GROW is NOT structurally unreachable from a ClassCMut holder ... CALLER DISCIPLINE ... NOT impossibility").

## RESIDUAL #1 (MEDIUM, latent): subsume() ALWAYS DISCARDS the owed persist — zero persist, no panic
- `subsume(mut self, ctx)` @3416 sets `consumed=true` + debug_assert ctx, performs NO persist. PROBE 2 PROVEN: arm a GROW, `token.subsume(ctx)` with NO sibling → SpyPersistence count==0, GROW in memory (suspended_for contains cap), NO panic. A crash here re-grants the suspended capability (≤50ms coalesce window).
- subsume is `pub(crate)`, NO compile/test guard enforces its documented "a sibling token covers the identical persist" precondition. It is a DISCARD primitive whose safety is doc-only.
- The 2 PRODUCTION sites are SOUND (verified by reading):
  - messaging_helpers.rs:2234 (paid-send reconcile): `(Some(sink),true)` paid branch subsumes redundant sink, passes nonce `token` to persist_finalized_send:2345 whose `t.commit` fail-closed-persists ALL in-memory state (covers GROW). Free branch passes obligation through, commits fail-closed:2366. PROBE 4 PROVEN: subsume + sibling commit = EXACTLY ONE persist.
  - governance_helpers.rs:4757 (finalize_governance_action): runs INSIDE caller execute_governance_action's `token.discharge_with` (4920) which persists post-finalize `cell.state` fail-closed once. finalize mutates same `state` via ConsequenceStateSplit::from_state(state). Subsume folds correctly.
- So subsume FOLDS at both live sites, but the PRIMITIVE discards. A NEW consequence caller that arms a GROW then calls subsume without a sibling = silent non-persisted downward-auth GROW. Same residual CLASS as BLACK-1a, new realization vector (subsume vs forget-flag). Single-token silent flip, not conspicuous.

## RESIDUAL #2 (LOW, intrinsic): mem::forget(token) universal
- No production mem::forget on tokens (grep clean). Doc @3199 honestly discloses it as intrinsic/unavoidable (any Drop-linearity is forget-defeatable). Accepted.

## RESIDUAL #3 (LOW, disclosed): alias `use …::ClassSCell as X` evades tripwire
- `class_s_cell_alias` (3864) keys on `type` decl only; doc @3851/3931 disclaims `use … as`. Bounded: ClassSCell.state is PRIVATE → `impl X{self.state.class_s}` only compiles in-module (attacker already editing the file). Same as prior BLACK-4.

## WHAT HOLDS (compile boundary — SOUND)
- ClassSCell !DerefMut (assert_not_impl_any:3501), SharedClassS !DerefMut (3511). No state_mut.
- GROW-without-obligation = E0061 (required param). Token !Clone/!Copy (3588), move-consume commit (no double-commit), #[must_use], Drop-guard debug panic + release metric:3459.
- class_c_parts() raw &mut seam (roles.rs:1238 `&mut self`) reachable ONLY from inside the views (3 callers all already hold &mut role_state); through the cell needs DerefMut (blocked). NOT an independent off-obligation seam.
- Governance-leaf 2-arg `state.role_state.suspend_capabilities/suspend_all` (governance_helpers 809/892/914/4352) are RAW ContextRoleState methods reached via `view.rest_mut()` INSIDE `commit_class_s_keep` (2589: f then unconditional persist_state_fail_closed) — fail-closed, just the combinator path not the token path. supervisor.rs:14904 is #[cfg(test)] (cfg(test) @10689).
- whitelist tripwire (4286) scans `impl ClassSCell` only; GROW methods are on ConsequenceRoleStateMut so not covered — doc honestly scopes it as a non-adversarial honest-contributor speed-bump.

## BOTTOM LINE
Commit a01da94a3/71f81dc8d's obligation-as-parameter is the FIRST wave to make GROW-without-fail-closed a COMPILE ERROR (E0061) rather than a forgettable flag — a real structural win that closes BLACK-1a's drop/forget-flag variants. The one residual the design itself introduces: `subsume` is a discard primitive (always zero-persist) with a doc-only sibling-commit precondition and no mechanical guard. Both prod sites honor it; a future mis-paired subsume is the new latent foot-gun (single-token silent re-grant). mem::forget + alias-use-as are intrinsic/bounded as before.
