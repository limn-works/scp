---
name: wasm-1877-slice1-roles-review
description: #1877 WASM slice1 ContextRoleState convergence — INCOMPLETE at d05e8ad7d, now COMPLETE at dcb3beb25 (deferral markers + eviction fix landed); lists the real seq off-by-one + false-positive traps
metadata:
  type: project
---

# #1877 WASM slice1: adopt shared `ContextRoleState`, converge WASM→native

Branch slice1-roles; worktree `.claude/worktrees/slice1-roles`. Goal: WASM reimplements ONLY async/tokio/platform; SHARE everything sync. Flat WASM reimpl (`members:HashMap<String,MemberEntry>`, `ceiling_strings:HashSet<String>`, `suspended_capabilities`, `creator_did`) replaced by typed `role_state:ContextRoleState` (manager.rs:364).

## Review history
- HEAD `d05e8ad7d`: **INCOMPLETE** — (1) member-removal suspension-clear comment FALSELY claimed native "deliberately LEAVES" = "native parity"; a test asserted `is_none()` under a "native parity" label, certifying divergence as parity. (2) seq base 0-vs-1 unmarked. (3) add-member eviction bug present.
- HEAD `dcb3beb25`: **COMPLETE / convergent.** Commits a56fd0e31 (honesty markers) + dcb3beb25 (eviction fix + tests + markers) resolved all three. Two comment-wording refinements remain (non-blocking).

## Resolved (now correct)
- **Eviction bug FIXED**: `dispatch_add_member` captures `member_was_present`/`seq_was_present` BEFORE insert; rolls back ONLY what this call added (manager.rs ~3917-3936). Test `add_member_existing_member_bad_role_does_not_evict_wasm` (mutation-verified RED/GREEN). Converges to native `execute_add_member` (no rollback, ADR-049 §9 coalesce-window).
- **Removal suspension-clear**: comment manager.rs:4043-4059 reworded — WASM clears suspension on removal; native has NO removal primitive that strips it (NOT deliberate). Marked "KNOWN divergence, native should converge TO WASM, deferred to MembershipState/shared-removal slice." Cross-refs at leave_context + encrypted-join-rollback. The old false "native parity" test framing is gone.
- **Per-action EventType leaf parity**: 3 accurate markers — ModifyCeiling (3703 → CeilingModificationPending/CeilingModified), TransferAdmin (4150 → AdminTransferred), dispatch wrapper (3722). All cite ignored tracker `wasm_native_full_governance_eventtype_parity_pending` (wasm_conformance.rs:2776 — honest intentional panic!, NOT theater). Only RemoveMember's MemberLeft leaf emitted today (verified buffer 4078 + durable 4091).
- **Consequence AssignRole CONVERGED**: WASM `apply_assign_role`→`role_state_system_assign_role`→shared `ContextRoleState::system_assign_role`; failure escalates SuspendAll in SHARED `scp-protocol/src/trust/consequence.rs:1304-1322`. Test `enforce_triggered_assign_role_undefined_role_escalates_to_suspend_all`.
- **Import VERBATIM** (core goal): roundtrip test asserts role+suspension+seq survive (~10870-10943). BLACK-CEIL-01: no per-member recompute.
- `ceiling_strings` field GONE: 4 remaining refs all historical comments; live-path comments reworded to typed `ceiling().contains`.

## REAL residual divergence (deferred, marked) — load-bearing
- **Sequence base off-by-one**: native `MembershipState::next_sequence_number` (membership.rs:199) PRE-increments → first msg seq=**1**. WASM `send_message` POST-increments → first msg seq=**0**. `seq` feeds `encrypt_message` + `MessageSent{sequence_number}` — wire-affecting. Deferred to MembershipState slice.
- **RE-REVIEW at `cde3c1002` (2026-06-24): COMPLETE / convergent.** Final commit `cde3c1002` ("refine sequence-base/field-doc comments") FIXED the two residuals my prior pass flagged: (1) seq marker 2090-2104 now states the off-by-one direction PLAINLY ("native PRE-increments...first seq is 1, this WASM sidecar POST-increments...first seq is 0. This is a real off-by-one in the emitted per-author sequence_number"). (2) field doc reworded. Verdict: COMPLETE.

## Final-pass verification (cde3c1002)
- All 3 marked divergences accurate vs native source: (a) remove-member suspension-clear — native `execute_remove_member` (governance_helpers.rs:1044-1058) strips members/assignments/member_capabilities/access-key/pseudonym but NOT suspended_capabilities; WASM clears it; marked "native should converge TO WASM, deferred to MembershipState/shared-removal slice". (b) seq off-by-one (above). (c) per-action EventType leaf parity (AdminTransferred/CeilingModificationPending/CeilingModified) marked at TransferAdmin(4160)/ModifyCeiling(3713)/dispatch-wrapper(3731), all citing ignored `wasm_native_full_governance_eventtype_parity_pending` (wasm_conformance.rs:2776, honest panic! + #[ignore], enumerates ~40 unappended events).
- Struct converged: PerContextState holds `role_state: ContextRoleState` only; no live `ceiling_strings`/flat `creator_did`/`members`/`suspended_capabilities`. creator_did via `role_state.creator_did`. 4 `ceiling_strings` refs all historical comments. Test asserts old `custom_payments:approve` is GONE.
- Membership-mutation test matrix FULL (13 cells): add succ(10807)+rollback(10719,10648), remove succ(11541,11669)+nonmember(12570), change succ(10490)+reject(10434), join succ(12490,11959)+encrypted-rollback(11844), leave strip(12277)+close(12397)+nonmember(12439), transfer happy(10536)+reject(10597). All assert real props (not theater) — verified add-rollback (5 props, mutation RED/GREEN through prod dispatch) + encrypted-rollback (member/count/role/seq/leaf/buffer all rolled back) + consequence escalate-to-suspend-all (role unchanged + full suspension + 1 durable leaf).
- consequence.rs converged: WasmConsequenceDispatcher delegates apply_suspend_all→shared ContextRoleState::suspend_all (native = .insert REPLACE, verified roles.rs:957), apply_assign_role→system_assign_role; failure escalates SuspendAll in SHARED scp-protocol consequence. Genuinely wired (not dead pub).
- NOTE (separate artifact, out of code scope): crate doc `crates/scp-ffi/wasm/CLAUDE.md` "Runtime Registry" section still lists `WasmContextRuntime { ceiling_strings: HashSet<String>, creator_did: String }` — stale vs converged code. Docs drift, not a code gap; flag if doc-sync is in scope.

## False-positive traps (don't re-raise)
- Cross-family export BYTE parity is explicitly NOT a goal per ADR-050 — do NOT raise WASM-vs-native export byte diffs.
- The 4 `ceiling_strings` refs are intentional HISTORICAL comments, not stale field access.
- `enforce_triggered`/`system_assign_role` live in scp-protocol (shared) — WASM delegates, genuinely wired (not dead pub).
- ignored `wasm_native_full_governance_eventtype_parity_pending` is honest deferral tracking (intentional panic!), NOT `let _=` enforcement theater.
