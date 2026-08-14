---
name: classs-compile-enforcement-migration-272c4d079
description: ADR-049 §9 Class-S compile-time-enforcement migration (full convergent design — retire text-scanner gate, ClassSCell boundary) — ALIGNED, zero findings
metadata:
  type: project
---

# ADR-049 §9 Class-S Compile-Time Enforcement Migration — ALIGNED, ZERO findings

Worktree `classs-fin-trunk`, HEAD 272c4d079 (merge of origin/main + 207e1811a finalization), 26 commits, 36 files +8789/-8147.

**What shipped = the "Full convergent design" Alec chose** (he rejected "Lighter: keep a slim gate"). Retire the non-convergent text-scanner gate by making a non-fail-closed Class-S mutation a COMPILE error.

**Verified elements (all present, full strength):**
- `ClassSCell` (`crates/scp-runtime/src/context/actor/class_s.rs`, 5210 lines) wraps `PerContextState`: `Deref` only, NO `DerefMut`, NO `state_mut` escape hatch. `assert_not_impl_any!(ClassSCell: DerefMut)` static guard (line ~2758).
- Class-S fields (`PerContextState.class_s`, `GovernanceState.class_s`, `revoked_spending_ucan_cids`) privatized `pub(in crate::context)`; `ClassCMut`/`GovernanceClassCMut` destructure `&mut` into field refs leaving Class-S to `..` rest → hold NO `&mut` to Class-S → mutating it through best-effort path = compile error. Whole-bucket `Deref` on the views was REMOVED so a whole-`&mut` accessor is uncompilable by construction.
- Persist combinators: `commit_class_s_keep`/`_restore`/`_compensating`/`_keep_compensating`/`_then_append`/`_keep_restore_split` (all fail-closed via `persist_state_fail_closed`), `commit_class_c_best_effort` (Class-C), `class_c_view` (non-persisting — relies on run-loop coalescing, no per-site persist injected).
- `ClassSCommitToken` (cross-crate deferred-persist): `#[must_use]`, keep-direction, `commit`/`discharge_with`, Drop guard mirroring `EconomyTicket`. Minted by `begin_class_s`/`begin_class_s_conditional`.
- Whitelist tripwire `class_s_no_persist_mutator_whitelist_is_bounded`: CLOSED positive allowlist (KNOWN_SAFE = exactly 6: into_inner, class_c_view, commit_class_c_best_effort, clear_committed_reservation_idempotent, set_generation_for_test[cfg-test], restore_class_s). `persist_state_best_effort` DELIBERATELY NOT a persist marker (best-effort ≠ §9 for Class-S). Parser-drift count cross-check + macro fail-loud guard + block-comment guard. Convergent inverse of the retired denylist.

**Gate genuinely retired (not slimmed):** `scripts/check-class-s-fail-closed.sh` (4354 lines) DELETED; CI job `class-s-fail-closed` removed from `ci.yml`. Only surviving reference = the ADR sentence documenting retirement.

**state_mut: ZERO whole-state callers/definitions crate-wide** (the only `*_mut` hits are field-granular: role_state_mut/migration_state_mut/lifecycle_state_mut/etc).

**Behavior preservation (focus item 4) — no unauthorized change:** send hot path NOT silently flipped to fail-closed. `finalize_send` (messaging_helpers.rs:2243-2266) uses `begin_class_s_conditional` → PAID branch = deferred FC token, FREE branch = `None` → `persist_state_best_effort` (line 2263, "Class C — not regressed"). Receive cascade = non-persisting class_c_view. Authorized strengthenings (execute_revoke/restore_access best-effort→FC, leave/close structural-FC, gov-marker) route through FC combinators. No persist direction inverted wrong way.

**ADR §9 amendment ACCURATE:** combinator names, token methods, KNOWN_SAFE set (6), "~8 role_state_mut callers" all match code (verified exactly 8). "Known residual" disclosure HONEST & consistent: `ContextRoleState.ceiling`/`suspended_capabilities` still reachable via 8 role_state_mut callers + ClassCSplit; replacement view `role_state_class_c_mut`/`RoleStateClassCMut` ALREADY BUILT+TESTED (closing migration is mechanical follow-on, not orphaned half-work). Disclosed-not-claimed-closed = correct (avoids phantom provenance).

**Coherence:** scp-runtime builds clean (testing features); 44 class_s tests pass incl tripwire, DerefMut static guard, token-Drop-panic, field round-trip `security_critical_state_is_class_s_or_m_not_coalesced`. No todo!/unimplemented!/stub introduced.

**Incidental files (non-issues):** sync/mod.rs = doc-comment rename tracking real create_checkpoint_if_due→_view rename (target queries_helpers.rs:716). key_protocol_verify.rs appears only via origin/main merge (empty under three-dot), not branch work.

LESSON: for a "replace text-scanner gate with compile-time enforcement" review, verify ALL of: (a) gate file + CI job actually DELETED (not slimmed); (b) the escape hatch (`state_mut`) has ZERO whole-state callers — grep and exclude field-granular `*_mut`; (c) the static no-`DerefMut` guard exists AND the views dropped whole-bucket `Deref` (else a DerefMut could re-open it); (d) the replacement test is a CLOSED positive allowlist not a denylist; (e) the hot path's free branch stays best-effort (a coalesced→FC flip = perf regression = unauthorized behavior change); (f) the ADR's disclosed residual has its replacement primitive already in-tree (else it's orphaned half-work, not a scoped follow-on).
