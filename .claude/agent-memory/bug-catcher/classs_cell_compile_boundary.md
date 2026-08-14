---
name: classs-cell-compile-boundary
description: ADR-049 §9 Class-S fail-closed enforcement migrated from text scanner to ClassSCell type boundary + bounded whitelist tripwire test
metadata:
  type: project
---

ADR-049 §9 Class-S fail-closed persist invariant is now enforced by the type system, not the retired `scripts/check-class-s-fail-closed.sh` scanner (deleted on branch `classs-finalize`).

**Mechanism (`crates/scp-runtime/src/context/actor/class_s.rs`):** `ClassSCell` wraps `PerContextState`; `Deref` only (no `DerefMut`, no `state_mut`). Three Class-S fields privatized to `pub(in crate::context)`: `PerContextState.class_s`, `GovernanceState.class_s`, `GovernanceState.revoked_spending_ucan_cids`. Best-effort views (`ClassCMut`/`GovernanceClassCMut`) destructure with `..` so those fields are never bound `&mut`. Only persisting combinators (`commit_class_s_*`, `ClassSCommitToken`) hand out `&mut` to them.

**Tripwire test** `class_s_no_persist_mutator_whitelist_is_bounded`: hand-rolled `#[cfg(test)]` source lexer (`code_only` + `skip_block_comment`/`skip_raw_string`/`skip_quoted_string`, `brace_bounded_body`, `is_method_header`, `body_has_self_receiver`) over `include_str!("class_s.rs")`. Asserts the no-persist self-receiver methods of `impl ClassSCell` == KNOWN_SAFE (6: into_inner, class_c_view, commit_class_c_best_effort, clear_committed_reservation_idempotent, set_generation_for_test, restore_class_s). PERSIST_MARKERS (2): persist_state_fail_closed, ClassSCommitToken::new.

**Verified (Jun 2026):** lexer is char-based (no multi-byte panic), r/b-prefixed idents NOT corrupted (skip_raw_string returns None when not `#`/`"`). Injection-tested: naive no-persist mutator TRIPS; comment/string-only marker spoof TRIPS (code_only strips it). Count cross-check + macro guard + block-comment guard are fail-LOUD. No dangling refs to deleted accessors (context_id_mut/created_at_mut/creation_timestamp_secs_mut/revoked_spending_ucan_cids_mut/state_mut). ci.yml job removal clean (valid YAML, no needs: ref). 42 class_s tests pass.

**KNOWN RESIDUAL (disclosed, not a bug):** `ContextRoleState.ceiling` / `suspended_capabilities` are Class-S downward-auth but NOT behind the boundary — reachable via `ClassCMut::role_state_mut`, `split_class_c`→`ClassCSplit.role_state`, `ClassCSplit::from_state` (whole `&mut ContextRoleState`, no fail-closed persist). Tripwire scans only `impl ClassSCell`, doesn't cover these. ADR-049 also dropped the `CLASS_C_GOVERNANCE_LEAVES` source-text allowlist — downward-leaf classification now prose-only, so a downward leaf tightening via ceiling/suspended_capabilities best-effort is NOT mechanically caught (covered by the same disclosed residual).
