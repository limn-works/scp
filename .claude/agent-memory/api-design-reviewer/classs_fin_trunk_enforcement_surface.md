---
name: classs-fin-trunk-enforcement-surface
description: API review of ADR-049 §9 Class-S enforcement surface (class_s.rs) — combinator family, ClassSCommitToken, field-granular views; verdict APPROVED with non-blocking nits
metadata:
  type: project
---

ADR-049 §9 Class-S enforcement surface (`crates/scp-runtime/src/context/actor/class_s.rs`, branch `classs-fin-trunk`, ~5200 lines). Crate-internal API (`pub(crate)`/`pub(in crate::context)`) used by actor handler/helper authors for every actor mutation.

**Why:** Replaced a non-convergent source-text scanner (`scripts/check-class-s-fail-closed.sh`, deleted, -4354 lines) with a compile-time guarantee: `ClassSCell` has no `DerefMut`/`state_mut`, 3 Class-S fields privatized; mutation only via persisting combinators. Whitelist tripwire test (`class_s_no_persist_mutator_whitelist_is_bounded`) is a bounded positive allowlist (6 entries), not a denylist.

**How to apply:** This is the reference design for the project's "make the wrong thing uncompilable, not gated" doctrine + the Agent-first API tenet (CLAUDE.md line 42). Verdict was APPROVED.

Key facts established (verified, not from memory):
- 7 combinators: `commit_class_s_keep`/`_restore`/`_compensating`/`_keep_compensating`/`_then_append`/`_keep_restore_split` + `commit_class_c_best_effort`. Plus `class_c_view` (non-persisting Class-C), `begin_class_s`/`_conditional` (deferred persist → token).
- Production caller counts: keep=25, restore=9, best_effort=23, class_c_view=171, then_append/compensating=0 (genuinely dead, `#[allow(dead_code)]` HONEST — the only non-class_s.rs matches are comments).
- ClassSCommitToken = `#[must_use]` linear handle, Drop guard debug_assert+tracing::error, parity with EconomyTicket (economy_logic.rs). DELIBERATE asymmetry: token has commit/discharge_with but NO discard/rollback (EconomyTicket has rollback) — keep-direction by design, documented.
- Views are airtight BY CONSTRUCTION via single-destructure-into-disjoint-field-refs: ClassCMut/GovernanceClassCMut/RoleStateClassCMut hold no whole `&mut`, so no `rest_mut`/`gov_mut` can be written. ClassSMut (fail-closed combinators) DOES expose `rest_mut` — sound because the combinator persists fail-closed. The asymmetry is the design's core insight.
- Known residual DISCLOSED not closed: `ContextRoleState.ceiling`/`suspended_capabilities` dual-use Class-S pair still reachable via `ClassCMut::role_state_mut` (slated-for-deletion) + `ClassCSplit::role_state`/`from_state`. RoleStateClassCMut replacement EXISTS but callers not yet migrated. Honestly documented as residual-to-close, NOT ADR-accepted carve-out.

Non-blocking nits found: (1) doc-comment volume is very high (~230-line module header + per-method essays) — risk of doc drift; (2) param-first-arg inconsistency ClassSCommitToken::commit takes `state` vs discharge_with takes `cell` (documented); (3) disjoint-borrow structs (EconomyPreCheckBorrows/CommitBroadcastBorrows/detection_borrows/ClassCSplit) are a coherent recurring pattern, not ad-hoc — each bundles simultaneous disjoint borrows the checker needs; proliferation acceptable.
