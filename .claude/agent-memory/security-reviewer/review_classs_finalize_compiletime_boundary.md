# Class-S compile-time finalization review (branch classs-finalize)

Worktree .claude/worktrees/classs-finalize, HEAD a512ee8e7. STAGED diff review.
ADR-049 §9 Class-S fail-closed persist: migration from source-text scanner
(scripts/check-class-s-fail-closed.sh, DELETED + CI job removed) to compile-time
type-system enforcement.

## VERDICT: compile-time boundary is SOUND. One LOW tripwire-parser gap.

### Why the boundary holds (evidence)
- `ClassSCell` (class_s.rs:1798 impl): no DerefMut (assert_not_impl_any guard @2695),
  `state_mut()` DELETED (zero live callers; all `state_mut` greps are comments/test-names).
  Crate has `#![forbid(unsafe_code)]` (lib.rs:21) → no *const→*mut escape.
- The ONLY source of `&mut PerContextState`/`&mut GovernanceState` is `ClassSMut`
  (class_s.rs:237, `new()` is module-private). `ClassSMut::rest_mut()/class_s_mut()/
  governance_class_s_mut()` are pub(crate) BUT callable only on a view a combinator
  hands you. Every `&mut self.state` in impl ClassSCell wraps into ClassSMut::new
  (persisting combinators) or ClassCMut::new (best-effort/compensation, airtight:
  holds shared `&` to class_s, no whole &mut). begin_class_s/_conditional mint a
  must_use ClassSCommitToken (Drop-guarded) that owes the deferred persist.
- Fields privatized pub(crate)→pub(in crate::context) (state.rs:1294 PerContextState,
  context/state.rs:1257 GovernanceState). pub(in crate::context) is REQUIRED-not-tighter:
  sibling helper modules (tools_helpers/messaging_helpers/lifecycle_logic) legitimately
  name `.class_s.<field>` THROUGH a combinator view (view.rest_mut()). build_snapshot_from_state
  (messaging_helpers.rs:2367) takes `&PerContextState` shared — reads only (.clone/.copied/
  .snapshot_entries), no write. Justified.
- ALL production `.class_s` mutations route through combinators (saga.rs production sites
  all `cell.commit_class_s_*(...|view| view.class_s_mut()...)`; tools_helpers:648/696 inside
  commit_class_s_keep_compensating; lifecycle_helpers:756 begin_class_s_conditional).
  Every direct `.class_s.x.insert/=/clear` on a bare state binding is inside #[cfg(test)]
  (supervisor mod tests 10703-18714; actor/state.rs mod tests 1511-2146; saga mod tests
  2461-5795). Non-test `.class_s` hits outside class_s.rs are READS (Deref).
- Deleted accessors (revoked_spending_ucan_cids_mut, context_id_mut, created_at_mut,
  creation_timestamp_secs_mut) had zero callers — confirmed. revocation set moved to `..`
  rest in GovernanceClassCMut::new so no &mut to it from best-effort view. NO production
  write path to revoked_spending_ucan_cids exists today (feature unwired); all refs are
  init/shared-read/discarded-destructure. When wired it MUST route through a combinator.

### Whitelist tripwire test (class_s_no_persist_mutator_whitelist_is_bounded)
- PASSES (ran it). Sound classification thanks to brace_bounded_body lexer (skips
  string/char/// so a persist-marker in a NEXT method's doc-comment doesn't bleed —
  verified: clear_committed_reservation_idempotent / set_generation_for_test / restore_class_s
  real bodies have NO marker; a naive scanner WOULD misclassify them). KNOWN_SAFE =
  {into_inner, class_c_view, clear_committed_reservation_idempotent, set_generation_for_test,
  restore_class_s}. Persist markers correctly present in all 7 combinators + 2 begin_* (token).
  commit_class_c_best_effort correctly NOT no-persist (names persist_state_best_effort) and
  its view (ClassCMut) is airtight vs Class-S — right.

### LOW finding — tripwire fn-detector is a non-exhaustive prefix allowlist
class_s_no_persist_methods (class_s.rs ~439-446) recognizes ONLY: `fn `, `pub(crate) fn `,
`pub(crate) const fn `, `pub(crate) async fn `, `pub(in crate::context) const fn `,
`pub(in crate::context) fn `. MISSING valid shapes that a future maintainer could use,
which would be SILENTLY SKIPPED (not enumerated → no_persist set doesn't grow → test still
green): `pub(in crate::context) async fn`, bare `async fn`, bare `const fn`, `pub fn`,
`pub async fn`. The empty-guard (assert !fn_starts.is_empty) only catches TOTAL parser
drift, not a single missed method. So a no-persist Class-S mutator added with an
unrecognized header evades the tripwire. NOTE: it does NOT defeat the compile-time boundary
(the method still can't get &mut class_s except via ClassSMut, which persists) — but
clear_committed_reservation_idempotent proves a sanctioned no-persist &mut self method on the
cell CAN exist, so the tripwire is the only guard for that class, and it has a coverage hole.
Fix: replace the prefix-OR with a regex/structural match for any `(pub(...) )?(const |async )*fn `
4-space-indented header, or assert recognized-header-count == total-fn-count.
