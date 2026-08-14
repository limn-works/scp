---
name: wasm-mls-eviction-docs-polish-c3f7fe48b
description: Final convergence re-attack on WASM gov RemoveMember at c3f7fe48b — delta over prior-clean 66a2c6a5c is comment/doc/test-comment ONLY; zero behavioral change; CLEAN
metadata:
  type: project
---

# WASM gov RemoveMember @ c3f7fe48b — CLEAN (docs-only delta over 66a2c6a5c)

Fact: HEAD c3f7fe48b. Only commit between prior-clean probe (66a2c6a5c, an ancestor) and HEAD is
`c3f7fe48b docs(wasm): clarify self-removal test + WASM-backend relay obligation`.
PROVEN docs/comment-only: stripped all `+/-` non-comment Rust lines from the delta → EMPTY (zero
runtime change). Touches: group.rs test-docstring soften (overclaim removed), scp.ts @returns reword
(per-backend relay obligation: NAPI auto-broadcasts, WASM caller must relay), manager.rs comment
collapse (sender-key-gap prose → 1-line pointer to governance_rotate_sender_key).

**Why:** final convergence check before landing; prior revision (66a2c6a5c) already probed clean.
**How to apply:** this target is DONE/clean; no further black-hat needed unless substantive code changes.

Fresh genuine re-probe of substantive paths (not just trusting prior verdict):
- 12 remove_member unit tests GREEN; full 379 lib GREEN; 2 conformance remove_member GREEN; eviction
  security test (evicted_member_cannot_decrypt_after_removal_and_rotation) GREEN; dup-DID self no-op
  GREEN. Clippy on wasm32-unknown-unknown CLEAN.
- Native oracle re-read (governance_helpers.rs:1231 execute_remove_member): MLS-evict FIRST →
  strip membership/role_state.{members,assignments,member_capabilities}/access_key_store/peer_registry
  → emit MemberLeft buffer → broadcast → post-closure append_context_event(MemberLeft, executor, ts)
  → wrapper GovernanceActionExecuted. WASM mirrors: governance_remove_from_group FIRST (fail-closed-keep
  before ctx.members.remove) → strip members + suspended_capabilities + read_exclusion_list → MemberLeft
  buffer → append_log_event(MemberLeft, executor_did, b"", proposal_created_at) → wrapper Executed.
  Per-DID-state model differs (native role_state/access vs WASM suspended_caps/read_exclusion) but those
  are RUNTIME state, NOT leaf-emitting — only the 2 durable leaves (empty-payload MemberLeft + Executed
  shared-payload) drive tree::root, and both are byte-convergent.
- Fail-closed PROVEN symmetric: WASM only fallible step = governance_remove_from_group (sender-key
  remove/rotate are infallible `()`-returning); on Err member STAYS in ctx.members, zero leaves. Native
  remove_member Err → closure `?` → commit_class_s_keep Err → post-closure MemberLeft append never runs →
  zero leaves. Wrapper rollback removes only executed_proposals entry (retry-safe), never double-strips.
- Conformance KAT still HAND-REPLAY (cross_impl_* replays the 2 appends, does NOT invoke
  execute_remove_member — scp-runtime can't dev-dep scp-ffi-wasm cdylib). Pre-existing structural gap,
  honestly documented in-test; both REAL paths covered by own-crate tests. NOT a regression.
- DoS/weaponize/wrong-leaf re-checked: O(n) bounded member scan no amplification; malformed leaf creds
  skipped via `if let Ok` (leaf scan) or propagated via `?` (own_did → fail-closed keep), no panic/fail-open;
  commit-hex withhold = ADR-034 liveness fork only (evicted still locked at own epoch advance, no
  confidentiality break); dup-non-own-DID one-per-call matches native (shared LOW, not divergence).

VERDICT: no CRIT/HIGH/MED/LOW. Convergence + eviction security CLEAN. Confirms 66a2c6a5c verdict.
