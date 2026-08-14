---
name: classs-finalize-findings
description: Adversarial findings on the Class-S fail-closed compile-boundary keystone (branch classs-finalize, class_s.rs) — the "compile error to mutate Class-S" claim is overstated; 4 confirmed bypasses
metadata:
  type: project
---

# Class-S finalize (branch classs-finalize) — confirmed bypasses

Change: retire `scripts/check-class-s-fail-closed.sh` text scanner; replace with
(a) compile boundary (ClassSCell no DerefMut/state_mut + Class-S fields privatized
to `pub(in crate::context)`), (b) `assert_not_impl_any!(ClassSCell: DerefMut)`,
(c) source-text whitelist tripwire `class_s_no_persist_mutator_whitelist_is_bounded`.

File: crates/scp-runtime/src/context/actor/class_s.rs

## Confirmed (compiled + tested in isolated worktree)

1. **HIGH — `pub(in crate::context)` does NOT make Class-S mutation a compile error
   for the modules that matter.** The whole `crate::context` subtree (handlers/*,
   *_helpers.rs, supervisor, lifecycle, messaging, governance) can name and mutate
   `state.class_s.*` and `state.governance.class_s.*` directly. Proved: a free fn in
   `context/actor/handlers/saga.rs` mutating all three field groups with no persist
   COMPILED CLEANLY. The compile-boundary claim only holds CROSS-CRATE / outside
   `crate::context`, not intra-context where the §9 hazard lives.

2. **HIGH — `revoked_spending_ucan_cids` is `pub(crate)`, NOT privatized, and is NOT
   inside `GovernanceClassS`.** Live field at state.rs:1242 on GovernanceState is a
   loose `pub(crate)` field. The claim lists it as a protected Class-S field but it is
   reachable+mutable from anywhere in the scp-runtime crate. (The best-effort views
   correctly leave it to `..`, but that is convention in those specific views, not a
   type-level guarantee for new code.)

3. **MEDIUM-HIGH — tripwire lexer defeat (mechanism c bypass).** The persist-marker
   check is a naive `body.contains("persist_state_fail_closed")` substring test that is
   NOT comment/string-aware (the lexer awareness is only used for brace-depth). A
   no-persist mutator on `impl ClassSCell` whose body has the marker in a COMMENT is
   classified as "persisting" and PASSES the test. Confirmed: exploit B alone → test ok.

4. **MEDIUM — tripwire is blind to non-`impl ClassSCell` mutators.** Parser isolates only
   `\nimpl ClassSCell {\n` .. `\nimpl ClassSCommitToken {\n`. A no-persist Class-S mutator
   as (a) a free fn, or (b) a method on a different impl/newtype, is invisible. Confirmed:
   exploits C1 (free fn) + C2 (BlackhatShadowCell impl) compiled and did not appear in the
   test's Found set.

## What actually holds
- Cross-crate boundary: solid. PerContextState/ClassSState are `pub` but their Class-S
  fields are `pub(in crate::context)`, so other crates can hold the value but not mutate
  Class-S.
- `assert_not_impl_any!(ClassSCell: DerefMut)` + no state_mut: genuinely prevents whole-`&mut`
  via the cell itself.
- Best-effort views (ClassCMut/GovernanceClassCMut) exhaustively destructure, leaving Class-S
  + revoked set to `..` — structurally airtight FOR THOSE VIEWS.
- begin_class_s token is `#[must_use]` + Drop guard (debug_assert + tracing::error) — but
  runtime-only, not compile-enforced.
- Exploit A (no-persist mutator on impl ClassSCell, honest body) DID trip the tripwire.

## Bottom line
The retired scanner was non-convergent, but its replacement is NOT a sound compile boundary
for the intra-context attack surface. It is: cross-crate compile boundary (real but not where
the hazard is) + a tripwire with the SAME class of evasions the scanner had (comment-fake,
out-of-scanned-region) just enumerated differently. Mutation discipline inside crate::context
is still convention + a fooled text test.

## Method note
Staged-but-uncommitted change: `git write-tree` + `git commit-tree -p HEAD` to snapshot the
index, then `git worktree add --detach <commit>` for an isolated exploit worktree.
