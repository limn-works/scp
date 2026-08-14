---
name: classs-finalize-adr049-s9-review
description: ADR-049 §9 Class-S compile-time-enforcement finalization review (worktree classs-finalize, HEAD a512ee8e7) — ALIGNED faithful record + 1 LOW ADR allowlist-enumeration drift
metadata:
  type: project
---

# ADR-049 §9 Class-S Finalization Review (worktree classs-finalize, HEAD a512ee8e734, 2026-06-23) — ALIGNED, 1 LOW

Staged diff (9 files): ADR-049 §9 amend (+13/-?), ci.yml (-8, deletes class-s-fail-closed job), class_s.rs (+840 combinators+whitelist test), actor/mod.rs + actor/state.rs + context/mod.rs + context/state.rs (comment scrubs + 3 field privatizations), supervisor.rs (comment scrub), scripts/check-class-s-fail-closed.sh DELETED (4354 lines).

**The finalization:** retires the source-text scanner `scripts/check-class-s-fail-closed.sh` (non-convergent denylist that grew a pattern per &mut-aliasing spelling). Replaced by COMPILE-TIME boundary: `ClassSCell` has no `DerefMut` + no `state_mut` escape hatch (deleted) → hands out NO whole `&mut PerContextState`; the 3 Class-S fields privatized to `pub(in crate::context)`; only `&mut` to a Class-S field originates inside a `ClassSCell` combinator (all persist). Backstopped by `#![forbid(unsafe_code)]` (lib.rs:21) + `assert_not_impl_any!(ClassSCell: DerefMut)` (class_s.rs:2687) + a bounded positive-allowlist tripwire TEST.

**ALL claims verified faithful (artifact-flow intact — ADR records end-state, code didn't reshape ADR):**
1. 3 field privatizations all `pub(in crate::context)` in code: PerContextState.class_s (actor/state.rs:1294), GovernanceState.class_s + GovernanceState.revoked_spending_ucan_cids (context/state.rs:1259/1239). ✓
2. Honesty of "no-whole-&mut is LOAD-BEARING, pub(in) is defense-in-depth that does NOT stop sibling handlers": ACCURATE. actor + all *_helpers are co-descendants of crate::context (mod.rs:30-56), so pub(in crate::context) is nameable from sibling handlers — ADR explicitly says so, does not over-claim a compile-error from visibility. ✓
3. Combinators match: 6 Class-S (commit_class_s_keep/_restore/_compensating/_keep_compensating/_then_append/_keep_restore_split) + commit_class_c_best_effort + begin_class_s/_conditional token paths. Token commit/discharge_with both call persist_state_fail_closed. ✓
4. Whitelist test PERSIST_MARKERS = ["persist_state_fail_closed","ClassSCommitToken::new"] — persist_state_best_effort DELIBERATELY excluded (best-effort doesn't satisfy §9 for Class-S, explicit rationale). commit_class_c_best_effort whitelisted by NAME (its ClassCMut view can't reach Class-S). Field round-trip test security_critical_state_is_class_s_or_m_not_coalesced at supervisor.rs:13991. ✓
5. NO stale scanner refs — all 4 remaining `check-class-s-fail-closed.sh` mentions are intentional RETIRED/retired/replacing-retired (ADR:166, class_s.rs:15/156/3043). CLASS_C_GOVERNANCE_LEAVES/CLASS_C_EXCEPTIONS only in ADR retirement note. CLAUDE.md + pretooluse-enforcement-files.sh clean (script was never in enforcement list). ✓
6. Comment scrubs accurate: actor/mod.rs (state_mut deleted, unsubscribe_broadcast now routes MembershipClassCMut::remove_subscriber), supervisor.rs (compile-time boundary), context/mod.rs (trailing-test cutoff prose removed). All `state_mut` repo hits are absence-references in comments, no def/call site. ✓

**LOW (the only finding) — ADR allowlist enumeration is incomplete vs shipped code.** ADR §9 line 166 enumerates KNOWN_SAFE as `{ into_inner, class_c_view, clear_committed_reservation_idempotent, set_generation_for_test, restore_class_s }` = 5 entries. Code `KNOWN_SAFE` (class_s.rs:~3155) = 6 entries — also includes `commit_class_c_best_effort` (verified: its body calls only persist_state_best_effort which is NOT a PERSIST_MARKER, so it genuinely lands in the no-persist set and MUST be whitelisted). ADR's bracketed list omits it → ADR under-enumerates the actual allowlist by one. Not phantom provenance (the ADR isn't claiming something false code-wise), just an incomplete record. Fix: add `commit_class_c_best_effort` to the ADR's bracketed allowlist.

LESSON: when an ADR enumerates an allowlist/set "EXACTLY", diff the ADR's bracketed members against the code constant member-by-member — a "best-effort persist combinator" lands in a no-persist allowlist because best-effort isn't a fail-closed marker, and is easy to drop from the prose enumeration.
