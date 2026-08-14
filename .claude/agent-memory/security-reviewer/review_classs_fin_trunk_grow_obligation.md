---
name: review-classs-fin-trunk-grow-obligation
description: ADR-049 §9 consequence-GROW fail-closed obligation coupling (subsume) — CLEAN audit, classs-fin-trunk HEAD 71f81dc8d
metadata:
  type: project
---

# §9 consequence-GROW obligation coupling — CLEAN (worktree classs-fin-trunk, HEAD 71f81dc8d, commits a01da94a3 + 71f81dc8d)

ADR-049 §9 downward-auth GROW made structurally fail-closed. CLEAN, zero findings; 1918 scp-runtime lib tests green (testing feature).

**Mechanism:** `ConsequenceRoleStateMut` GROW methods (`suspend_capabilities`/`suspend_all`/demoting `system_assign_role`) now take `obligation: &mut Option<ClassSCommitToken>` + `context_id` as REQUIRED (non-defaultable) params and arm the sink themselves via `ClassSCommitToken::note_downward_auth` on a real mutation. A consequence GROW without an armed obligation is a COMPILE error. Sink threaded enforce_triggered_consequences→process_one_triggered_consequence→dispatch_enforcement_action/emit_failure_escalation→GROW. `suspend_all` arms unconditionally (over-persist=safe direction); `suspend_capabilities` arms iff entry grew; `system_assign_role` arms on Ok.

**5 production sites all discharge fail-closed before ack, correct error precedence (persist_err over deliver/capture_err, original cause preserved):**
1. receive-deliver: handle_deliver_incoming (messaging.rs handler) owns sink, commits after view drops (messaging.rs:374-386).
2. send-finalize: finalize_send (messaging_helpers:2145) — FREE branch sink token IS obligation; PAID branch `subsume(ctx)` then nonce token's commit covers it.
3. tool-settle: handle (tools_helpers:1314) owns sink, commits both Ok+Err arms.
4. periodic-sweep: handle_evaluate_periodic_consequences_actor (governance.rs:829) owns sink, idempotent across loop, commits after view drop.
5. governance-finalize: finalize_governance_action (governance_helpers:4756) subsumes; always runs inside execute_governance_action's `token.discharge_with` (gov_helpers:4920) which performs the single fail-closed persist.

**subsume SOUND:** discharges Drop guard WITHOUT persisting, precondition = sibling token covers identical persist (one persist_state_fail_closed makes WHOLE in-memory state durable). PAID-send: nonce token unconditionally committed in persist_finalized_send Some(t) arm (gov persist covers in-memory GROW). gov-finalize: discharge_with always runs. GROW is in memory BEFORE the covering token commits (straight-line, no early-return/panic between subsume and covering commit). debug_assert_eq ctx matches (sets consumed BEFORE assert to avoid double-panic on unwind). No auth-downgrade rollback window.

**No GROW escapes:** other `suspend_*`/`system_assign_role` callers (gov_helpers:809/892/914/4352/1170, supervisor:14904) are the INHERENT `ContextRoleState::*` or `RoleStateClassCMut::*` (path B), reached only via whole `&mut ContextRoleState` from `ClassSMut::rest_mut`. ClassSMut::new ONLY in commit_class_s_*/begin_class_s/discharge_with combinators (all fail-closed). `RoleStateClassCMut::system_assign_role` (no obligation) used only for member-ADD/grant (upward-safe, best-effort by design); demotion direction reachable-but-unused. class_c_parts raw `&mut` seam pub for cross-crate naming but reachability-gated: needs &mut ContextRoleState, only via ClassSCell (!DerefMut static_assertion + private fields). member_capabilities_mut DELETED (BLACK-1c, zero callers).

**Deleted witnesses non-functional (no regression):** role_view_grow_resolves_to_trait / best_effort_view_has_no_whole_mut_accessor bound a zero-arg &self trait shim; a realistic `&mut self` multi-arg inherent GROW is non-viable at that call site so resolution falls through to shim, witness stays GREEN = false confidence. Proven (commit). Real guarantees (!DerefMut static_assertions + private fields + obligation coupling) remain, stronger.

**Residuals honestly scoped, bounded (not live exploits):** mem::forget (universal Rust escape, in-file-insider), use-as-Alias tripwire evasion (private field is real barrier), class_c_parts pub (reachability-blocked), in-file maintainer adding &mut self GROW to private-field impl (code-review responsibility). All consistent with project "a gate adds ~zero marginal security vs insider who edits it" philosophy.

2nd commit (71f81dc8d) = test-only: note_downward_auth idempotency, paid-send+suspension behavioral, #[cfg(test)] tripwire path-qualified ClassSCell alias. No production code touched.
