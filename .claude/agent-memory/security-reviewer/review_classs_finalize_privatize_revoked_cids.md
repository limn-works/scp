---
name: review-classs-finalize-privatize-revoked-cids
description: ADR-049 §9 Class-S finalize — privatize revoked_spending_ucan_cids/class_s, retire scanner for compile-time boundary + whitelist tripwire. CLEAN.
metadata:
  type: project
---

# Class-S finalize (worktree classs-finalize) — SECURITY CLEAN

ADR-049 §9 compile-time-enforcement finalization. Staged diff: deletes scripts/check-class-s-fail-closed.sh (4354 lines) + its CI job; privatizes Class-S fields to `pub(in crate::context)`; retires text scanner for compile boundary + bounded whitelist tripwire test.

**Why:** the scanner was a non-convergent denylist (grew a pattern per &mut-aliasing spelling). Replaced by the `ClassSCell` type boundary (load-bearing) + `class_s_no_persist_mutator_whitelist_is_bounded` test (backstop).

**How to apply:** the LOAD-BEARING control is the cell's no-whole-`&mut` shape (no DerefMut, no state_mut), NOT the field visibility. `pub(in crate::context)` is defense-in-depth only — sibling handler modules under crate::context can still NAME the fields (that's why 4 prod sites at lifecycle_logic.rs:322, messaging_helpers.rs:267, tools_helpers.rs:648/696 still write `&mut governance.class_s.spending_nonce_tracker` — all reached inside `cell.begin_class_s_conditional`/combinator closures via `view.rest_mut()`, sanctioned persisting path).

## Verified (all 4 review points)
1. revoked_spending_ucan_cids privatized to pub(in crate::context) @state.rs:1250. All grep hits inside crate::context EXCEPT store/context.rs:1759 — that's the `pub` ContextSnapshot DTO field (state.rs:557/:890), a DIFFERENT struct, unaffected. Build CLEAN (`cargo build -p scp-runtime --features testing`).
2. GovernanceClassCMut::new (class_s.rs:586) destructures &mut GovernanceState, names only Class-C fields, leaves BOTH class_s AND revoked_spending_ucan_cids to `..` rest — no &mut. `revoked_spending_ucan_cids_mut` accessor: ZERO callers (grep empty). No `fn state_mut` def exists (only comments).
3. Core boundary intact. ClassSMut (the only view exposing class_s_mut/governance_class_s_mut) has PRIVATE `state` field + private `new`; constructed ONLY by ClassSCell combinators (commit_class_s_keep/_restore/_compensating/_keep_compensating/_then_append/_keep_restore_split + token paths begin_class_s/_conditional). No prod direct write to revoked_spending_ucan_cids (all are .clone() reads). ClassCMut holds shared `&` to class_s only.
4. Tripwire SOUND. strip_comments_and_strings drops `"..."` content + `'...'`; is_method_header strips pub(...)/const/async/unsafe/extern structurally (recognizes pub(in crate::context) fn); parser-drift cross-check recognized==total_method_fns PASSES; persist-marker set {persist_state_fail_closed, persist_state_best_effort, ClassSCommitToken::new} = correct complete sanctioned set. RAW/BYTE-STRING GAP (lexer doesn't special-case r"/r#"/b"/br") is NON-EXPLOITABLE: zero true raw/byte literals in class_s.rs (verified `grep -E '(^|[^A-Za-z0-9_])(r#*"|b"|br#*")'` = empty); and even if present, it only hides a method from the TEST, not the compile boundary (mutator still needs &mut self.state.class_s = impl ClassSCell only). Test passes (44 class_s lib tests green).

No dangling scanner refs (only the ADR's "RETIRED" mention remains; CLAUDE.md enforcement list does not name it).

## Latent (OBSERVATION, not a finding)
strip_comments_and_strings could mis-handle a future raw/byte string with embedded `"`. Defense-in-depth-on-defense-in-depth; the compile boundary is primary. If ever a raw/byte literal is added to class_s.rs, revisit. Not blocking.
