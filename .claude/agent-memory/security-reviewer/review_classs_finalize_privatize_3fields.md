---
name: review-classs-finalize-privatize-3fields
description: ADR-049 §9 Class-S finalize — privatize 3 fields, retire text scanner, compile-time boundary + whitelist tripwire. CLEAN.
metadata:
  type: project
---

# Class-S finalize (branch classs-finalize, staged diff) — CLEAN, no findings

ADR-049 §9 compile-time-enforcement finalization. Deletes `ClassSCell::state_mut`, privatizes 3 Class-S fields to `pub(in crate::context)` (`PerContextState.class_s`, `GovernanceState.class_s`, `GovernanceState.revoked_spending_ucan_cids`), retires `scripts/check-class-s-fail-closed.sh` (4354 lines) + its CI job, replaces with compile-time boundary (no DerefMut/state_mut; best-effort views destructure Class-S to `..` rest) + bounded source-text whitelist tripwire test.

**Why sound for the 3 privatized fields (verified live):**
- All 4 production `&mut ...governance.class_s.spending_nonce_tracker` sites route through `view.rest_mut()` inside a fail-closed/deferred combinator: tools_helpers.rs:648/696 (commit_class_s_keep_compensating), messaging_helpers.rs:267 (begin_class_s_conditional → ClassSCommitToken), lifecycle_logic.rs:322 reached via lifecycle_helpers.rs:760 (begin_class_s_conditional). `rest_mut` is ClassSMut (Class-S-capable) only handed out by persisting combinators.
- `revoked_spending_ucan_cids`: ZERO production `&mut` reach (read-only `&` at validation sites; `revoked_spending_ucan_cids_mut` accessor DELETED, field dropped from GovernanceClassCMut destructure → left to `..`). Populating-on-revocation is future, ADR says no enforcement rewrite needed.
- `state_mut` fully deleted: 0 references. Build clean.
- ClassCMut.class_s field is `&'a ClassSState` (SHARED) — `&mut` binding coerces to `&` on assignment; only read-only accessor. Airtight (pre-existing).

**Privatization non-breaking:** PerContextState is `pub` but a pub struct may have narrower-vis fields; was already `pub(crate)` (external crates couldn't name it). Structs live in `context::state`/`context::actor::state` → `pub(in crate::context)` reaches all consumers (all under crate::context::*). store/context.rs has NO `.class_s` (different concern). No `.class_s` outside context/ in scp-runtime; none in other crates. `cargo build -p scp-runtime` clean.

**Whitelist tripwire (class_s_no_persist_mutator_whitelist_is_bounded):** PASSES. Closed positive allowlist (sound/convergent), not denylist. KNOWN_SAFE={into_inner, class_c_view, commit_class_c_best_effort, clear_committed_reservation_idempotent, set_generation_for_test, restore_class_s} — verified exactly correct vs all 15 impl methods (8 persist fail-closed/token; `new` no self-receiver skipped). PERSIST_MARKERS={persist_state_fail_closed, ClassSCommitToken::new}; best_effort correctly EXCLUDED (doesn't satisfy §9 for Class-S). Lexer `code_only` is char-based (UTF-8 safe for §×→), panic-safe (chars.get().unwrap_or, bounds-checked indexing, ASCII-delimiter byte slices). brace_bounded_body strips comments/strings before brace-match. Macro-invocation + block-comment + parser-drift count cross-checks all fail-LOUD.

**KNOWN RESIDUAL correctly scoped:** ContextRoleState.ceiling/suspended_capabilities dual-use downward-auth pair still reachable via role_state_mut/split_class_c/from_state (whole `&mut ContextRoleState`). VERIFIED all 3 accessors pre-existed on origin/main with IDENTICAL signatures — this PR only edits their DOC comments. NOT introduced/widened. Disclosure actually STRENGTHENED: old docs called it "ADR-accepted Class-C residual"; new docs correctly reclassify as "residual to CLOSE" (the velocity/earned-capacity accepted residual excludes re-granting removed capability, which suspended_capabilities rollback does). role_state_class_c_mut replacement pre-exists. ~122 role_state consumers to migrate (follow-on).

**No security regression** from privatization or scanner retirement: scanner's residual value (catch future no-persist Class-S mutation) is covered by compile boundary + tripwire for the 3 fields; the ceiling/suspended pair gap is the SAME residual the scanner's role-state markers covered, now honestly disclosed as not-yet-substituted (the one place where retiring the scanner loses coverage — but that pair was already a documented residual, and the PR discloses rather than hides it).
