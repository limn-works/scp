---
name: wasm-1877-slice1-final-review
description: #1877 WASM slice1 ContextRoleState FINAL completeness check at HEAD f8b6e11c1 — COMPLETE/ship-ready w/ one comment-accuracy nit + one out-of-scope stale lesson
metadata:
  type: project
---

#1877 native↔WASM convergence slice 1 (ContextRoleState adoption), FINAL slice. Worktree `.claude/worktrees/slice1-roles`, HEAD `f8b6e11c1` (commit: drop redundant `validate_ceiling_capabilities` + 2 subscribe_broadcast tests + CLAUDE.md doc-sync).

**Verdict: COMPLETE / convergent / ship-ready.** All deferred native-divergences explicitly+accurately marked. crate-doc CLAUDE.md Runtime Registry now matches code. Conformance 57 pass / 1 ignored (leaf-parity marker, legit). wasm clippy clean (`--target wasm32` no `--all-targets`); native clippy clean; ceiling tests 17/17; both subscribe_broadcast tests pass.

**§5.3.1.1 grammar — single enforcement point confirmed across all 3 paths:**
- create: `ContextRoleState::new` → `RoleError::InvalidCeilingCategory` → `ceiling_validation_error` → `SCP-VALID-7000` (manager.rs ~1682-1695). Test `test_wasm_context_create_rejects_malformed_ceiling_entry` asserts BOTH VALID_7000 AND msg "InvalidCeilingCategory" (real, not theater).
- modify: `dispatch_modify_ceiling` relies on `set_ceiling`'s validate-before-mutate → `ceiling_validation_error` → `SCP-VALID-7000` (~3686).
- import: `role_state.ceiling().validate_entries()` → maps to **`SCP-CTX-2032`** (manager.rs ~6873), NOT VALID_7000. Plus deserialize-time `#[serde(try_from)]` reject (also CTX_2032).

**ONE real nit (comment-vs-code, non-blocking):** the block comment ~294-296 AND the `ceiling_validation_error` doc-comment ~308-310 both claim the reject surface is "identical across the create / modify / import paths." FALSE for import — import surfaces `SCP-CTX-2032` (Context class), create/modify surface `SCP-VALID-7000` (Validation class). Grammar IS enforced on all three (correct); reject *code/class* is NOT identical. The import-deserialize test even documents "surfaced as the bridge's deserialize error class (CTX-2032)". Wording was INTRODUCED by this commit (old wording was more careful). Fix = narrow comment to say "identical across create/modify; import surfaces CTX-2032".

**Deferred divergences — all marked accurately:**
- member-removal suspension-CLEAR: WASM clears via `restore_capabilities` on removal; native `execute_remove_member` leaves `suspended_capabilities` dangling. Now CORRECTLY marked "KNOWN native↔WASM divergence where native should converge TO WASM ... deferred to MembershipState/shared-removal slice" (~4040). This FIXES the prior-commit finding (d05e8ad7d) where it was falsely asserted as native parity.
- seq base 0-vs-1: marked as real off-by-one (WASM post-incr base0 → first seq 0; native pre-incr → first seq 1), direction must converge at MembershipState adoption; byte-value out-of-ADR-050-scope but direction in-scope (~2073).
- per-action EventType leaf parity: `#[ignore]`d conformance test `wasm_native_full_governance_eventtype_parity_pending` (wasm_conformance.rs:2776) — uses `panic!` exercising ~40 EventType variants, legit ignore (wiring PR not landed).
- shared `remove_member` primitive: deferred to MembershipState slice, marked.

**Membership-mutation test matrix COMPLETE** (all 6 paths success+reject): join, leave(+last-closes), add_member, remove_member, transfer_admin, subscribe_broadcast (8558 success/idempotent + 8626 non-broadcast-reject). subscribe_broadcast impl matches assertions (members insert, seq seed 0, `subscriber` role, `!members.contains` idempotent guard, CTX_2001 "not a broadcast context" + no-mutation on reject).

**Doc-sync VERIFIED accurate:** CLAUDE.md Runtime Registry now describes `thread_local! MANAGER: RefCell<WasmContextManager>`, `with_manager`, `contexts: HashMap<String,PerContextState>`, `PerContextState{tool_registry,event_log,revoked_tokens,role_state:ContextRoleState}`. All match code. `WasmContextRuntime`=0 refs (gone). `ceiling_strings`/`creator_did` flat fields gone (4 manager.rs hits are historical comments only). `validate_ceiling_capabilities`=0 refs anywhere in tree (clean delete).

**Secondary stale artifact (OUT OF SCOPE for this slice):** `.docs/lessons/wasm-partial-ucan-validation.md` lines 11/13 describe `WasmContextRuntime` w/ flat `ceiling_strings: HashSet<String>` as current ("already has"). Stale vs new design. Evergreen lesson, not normative current-design doc; task scoped doc-sync to crate CLAUDE.md only. Worth a follow-up touch but not a blocker.
