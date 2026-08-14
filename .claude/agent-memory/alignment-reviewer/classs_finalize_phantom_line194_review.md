---
name: classs-finalize-phantom-line194-review
description: ADR-049 §9 Class-S finalize prose pass (worktree classs-finalize, staged @a512ee8e7) — staged surface ALIGNED but phantom §9 line-194 citation NOT fully scrubbed (2 unstaged files, 1 contradicts ADR) → NEEDS DISCUSSION
metadata:
  type: project
---

ADR-049 §9 Class-S compile-time-enforcement finalize, prose-amendment faithfulness review. Worktree /Users/alec/Developer/limn/scp/.claude/worktrees/classs-finalize, branch classs-finalize, STAGED diff @a512ee8e7 (9 files: ADR §9 + class_s.rs +959 + ci.yml -job + DELETE scripts/check-class-s-fail-closed.sh 4354 lines).

VERDICT: NEEDS DISCUSSION. Staged surface is clean; the cross-file phantom-provenance scrub is INCOMPLETE.

What the amendment fixed correctly (STAGED, all PASS):
- ADR §9 "Known residual" bullet (line 166) enumerates all 3 role_state &mut paths (ClassCMut::role_state_mut ~8 callers, ClassCMut::split_class_c→ClassCSplit.role_state, ClassCSplit::from_state) + frames as residual to CLOSE (not accepted) + references the REAL accepted bullet "Coalesced soft anti-spam residual (accepted)" (line 196) not a line number.
- No over-claim: every "compile error"/"airtight"/"cover what the scanner covered" in ADR (153/165-169) and class_s.rs module doc (14-37,28-29,160-169,205-220) scoped to "the THREE privatized fields" (PerContextState.class_s, GovernanceState.class_s, revoked_spending_ucan_cids) WITH matching ContextRoleState-residual disclaimer.
- §9 internally consistent: Known-residual (166) vs accepted-anti-spam (196) agree — suspended_capabilities rollback re-grants a removed cap → NOT accepted. class_s.rs inline role_state_mut doc (1535-46 "Slated for deletion... §9 bypass") + from_state doc (1313-42) consistent.
- Scanner retirement legit: script DELETED (status D), CI job removed from ci.yml, NOT in CLAUDE.md protected-enforcement list; replaced by ClassSCell compile boundary (no DerefMut/no state_mut) + closed positive-allowlist test class_s_no_persist_mutator_whitelist_is_bounded. Aligns with repo "prefer type-system over ever-growing denylist gate" guidance. Surviving script mentions all past-tense historical.

THE DEFECT (2 UNSTAGED sibling files still carry the debunked citation):
- governance_logic.rs:100 — "the documented ADR-049 §9 line-194 ACCEPTED Class-C residual" = HIGH. Two faults: (a) §9 line-194 is PHANTOM (ADR line 194 = clear_poison "Recovery-surface honesty", nothing to do with role_state); (b) "ACCEPTED Class-C residual" DIRECTLY CONTRADICTS staged ADR (166) + class_s.rs (194-198) which say "NOT an accepted Class-C residual... residual to CLOSE." Task item 2 required this to "now agree with the ADR" — it does not.
- tools_helpers.rs:870 — "Best-effort consequence path (ADR-049 §9 line-194)" = MEDIUM. Same wrong line# phantom; no "accepted" assertion so less severe.
- Legit citations NOT to touch: §9 line 144 (saga_pending; ADR 144 = "MLS epoch advance... event log append") at state.rs:960, messaging_helpers.rs:2515, saga_prepared_state.rs:402/409/917, supervisor.rs:14058/14095/14169 — all accurate, distinct from line-194.

ROOT CAUSE / LESSON: ADR section headers are NOT stable line numbers — they shift as the doc is edited. A code comment citing "§9 line-NNN" is fragile phantom provenance BY CONSTRUCTION; here the number went flat-wrong (194 now = clear_poison). The staged class_s.rs already migrated to anchor-style "§9 Known residual"; the 2 stragglers should adopt the same. FIX: re-cite both to the §9 "Known residual — the dual-use ContextRoleState" anchor + drop "ACCEPTED" → "residual to close, best-effort by-design-for-now", and STAGE them with the rest before calling finalize done.

REVIEW-METHOD LESSON: for a "we scrubbed phantom citation X across the repo" claim, grep the WHOLE worktree for X (not just the staged set) and classify each hit: (staged-fixed / unstaged-straggler / legit-different-citation-same-shape). The dangerous straggler is the one that is BOTH wrong-line AND semantically contradicts the artifact it cites. git diff --cached --name-only to see which hits are actually in scope; an untouched-in-working-tree phantom is still a live defect even if "out of the staged set."
