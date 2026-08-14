---
name: review-classs-fin-last-classcmut-narrowing
description: ADR-049 §9 final ClassSCell::state_mut() elimination onto field-granular ClassCMut views — CLEAN, fail-closed invariants intact
metadata:
  type: project
---

# classs-fin-last ClassCMut narrowing review (worktree classs-fin-last, parent f36b09462)

ADR-049 §9 refactor: eliminate the LAST `ClassSCell::state_mut()` production callers by narrowing onto field-granular `ClassCMut` (best-effort) views. **VERDICT: CLEAN — no Class-S fail-closed regression, no new Class-S mutation bypass.**

**Why:** This is the last step before privatizing `PerContextState.class_s` so Class-S mutation becomes a compile error outside the fail-closed combinators.

**How to apply:** Structural facts to reuse when reviewing the FINAL deletion PR (delete `state_mut()` + privatize Class-S field).

## Verified facts (HEAD of branch)
- **Two view types kept separate.** `ClassSMut` (class_s.rs:220) is handed out ONLY by `commit_class_s_*` fail-closed combinators; it has `class_s_mut`/`governance_class_s_mut`/`rest_mut`. `ClassCMut` (class_s.rs:343, best-effort, returned by `class_c_view()` @2316) has NONE of those — its `class_s` field is `&'a ClassSState` (SHARED), `governance` is `GovernanceClassCMut` (leaves `governance.class_s` in `..`). `ClassCMut::class_s()` @1714 returns `&ClassSState` (read). A Class-S `&mut` through ClassCMut is a COMPILE error by construction. `ClassCMut::from_state` (@1254/1385) delegates to `new` (same disjoint destructure), airtight.
- **New ClassCMut accessors all SAFE:** `from_state` (cell-free bridge, delegates to airtight `new`), `commit_broadcast_borrows`→`CommitBroadcastBorrows`{pending_commits,commit_fault,receive_buffer} (3 Class-C), `drain_timed_out_gaps`→owned Vec (Class-C §9.8.5), `MembershipClassCMut::member_dids`→`Iterator<&DID>` (read), `RoleStateClassCMut::member_has_capability`→bool (read). `member_has_capability` is BYTE-IDENTICAL to canonical `ContextRoleState::member_has_capability` (roles.rs:924): suspension-masked, suspended→false. This is the receive-path MessagesWrite gate (suspension = downward-auth Class-S read).
- **Spending-nonce fail-closed (keep-direction) intact on EVERY terminal abort path of send_message/finalize_send.** Token = `Option<ClassSCommitToken>`, `Some` iff paid (nonce-burning) branch (debug_assert @1267). `t.commit` sets `consumed=true` BEFORE persist, persists fail-closed; Drop guard logs+debug_asserts on uncommitted drop. Paths all `.take()` and commit: next_seq None (@1022 discharge), routing Err (@1114), PseudonymRegistryEmpty (@1096), lone-member no-op (@1148 inline `t.commit`), payment-auth Err (@1179), phase2 Err (@1219), finalize TTL-expiry arm (@2075), persist_finalized_send Some-arm (@2233). `commit_send_nonce_token_on_abort`/`discharge_send_abort` route the keep-direction commit. Free send (None token) → best-effort persist (un-regressed).
- **seed_caller_reservation_for_test** is in `#[cfg(test)] mod tests` (mod @2702, helper @3000); routes through `commit_class_s_restore` (fail-closed combinator, same path prod `prepare_a` uses) — NOT a production bypass. Replaces a prior `cell.state_mut()` test escape.
- **deliver_incoming cascade now on `&mut ClassCMut`** (deliver_incoming @1352, deliver_message_and_drain_buffered @2809, handle_deliver_incoming wraps `cell.class_c_view()`). Compile-proof that receive path makes NO Class-S mutation — only sequence/reorder/receive buffers, membership[read], role[read via member_has_capability], routing, split_class_c (Class-C consequence).
- **economy_logic `rollback_economy_ticket_inline` → `_inline_view(&mut GovernanceClassCMut, ...)`** — TIGHTENING: old whole `&mut GovernanceState` could reach `governance.class_s`; new restricted view reverses only velocity/hard_rate_limit/budget (Class-C). Shared by send + join paths.
- **queries_helpers checkpoint helpers** → `ClassCMut` view, sequential per-field borrows; checkpoints Class-C best-effort.
- **ZERO production `state_mut()` callers remain** (grep). `state_mut()` now `#[allow(dead_code)]`, retained for the atomic final-deletion PR.

No findings, all four security focuses pass.
