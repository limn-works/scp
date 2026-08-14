---
name: wasm-native-convergence-slice1-final-3e1cc9a6b
description: #1877 WASM↔native convergence slice-1 FINAL gate at HEAD 3e1cc9a6b — ALIGNED within scope; send-seq rollback faithful; prior dispatch_add_member MEDIUM now fixed; quorum concern out-of-scope
metadata:
  type: project
---

# #1877 WASM↔native convergence slice-1 FINAL @ `3e1cc9a6b` (2026-06-24) — ALIGNED within scope

Supersedes [[wasm_native_convergence_slice1_1877_a56fd0e31]] (which was NEEDS-DISCUSSION on the dispatch_add_member MEDIUM). That MEDIUM is now FIXED.

**Read tool serves STALE here — use `git show HEAD:crates/scp-ffi/wasm/src/manager.rs`.** Authoritative source only via git show.

## Final commit (`3e1cc9a6b`)
send_message: reserves+increments per-sender seq (member_sequence_numbers sidecar) BEFORE fallible encrypt (base64 decode CRYPTO_4001 / MLS epoch CRYPTO_4002 / encrypt CRYPTO_4003). Final commit wraps fallible work in a closure; on Err rolls seq back via `saturating_sub(1)` AND removes a fresh-0 entry if `!seq_was_present` (restores pre-send map shape). FAITHFUL to native `MembershipState::rollback_sequence_number` (membership.rs:212 = pure saturating_sub). Native keeps seq in MemberInfo (always present) so never removes; WASM sidecar is lazy → the fresh-0 removal is MORE faithful (member_sequence_numbers IS in export snapshot @6479, so a leaked {sender:0} would be observable). Closure borrow sound: `&mut ctx.crypto` ends before rollback touches `ctx.member_sequence_numbers` (sequential). Mutation-verified test `send_message_failure_does_not_advance_sequence_wasm` (RED=2/GREEN=1). publish_broadcast correctly NOT rolled back (increment followed only by infallible push_event @5685).

## dispatch_add_member MEDIUM — FIXED
@3935: now `member_was_present`/`seq_was_present` novelty-guard; rolls back ONLY what THIS call inserted; never evicts pre-existing member on bad-role re-AddMember. Comment now accurate (explains split-brain it prevents; no longer falsely "mirrors native" unconditionally). join_context @1848 = infallible-by-construction (ceiling-filtered member role), rollback for uniformity only.

## Governance QUORUM concern = OUT-OF-SCOPE for slice-1
`governance_quorum` (@4856 HEAD / @4506 main) uses `total = role_state.members.len()` (live members) as denominator for threshold/majority/unanimity — gates on live members + capability, NOT a frozen signer-set. THE OTHER REVIEWER'S CONCERN IS PRE-EXISTING. Slice diff touched the body ONLY via mechanical field rename `ctx.members.len()` → `ctx.role_state.members.len()` (roster relocated into ContextRoleState by slice-1 adoption). Voting LOGIC byte-identical to origin/main. Governance-engine quorum/voter-eligibility = SEPARATE subsystem, not role-state slice-1 scope. State clearly out-of-scope.

## Deferral markers — ALL present + accurate + honest (direction correct)
- MembershipState/sequence-base: @2075-2087 (off-by-one base: native pre-incr→1, WASM post-incr→0; direction must converge), @7512-7517 (retire sidecar), @5677.
- per-action EventType leaf parity: @4172 (AdminTransferred + GovernanceActionExecuted; points to ignored `wasm_native_full_governance_eventtype_parity_pending`).
- member-removal suspension-clear: @4062-4079 (native execute_remove_member leaves suspended_capabilities; WASM clears via restore_capabilities — native should converge TO WASM; deferred to shared-removal slice).
- shared remove_member: @4072-4079 (ContextRoleState::remove_member primitive in scp-protocol deferred).

## Verdict: ALIGNED within slice scope. Right precedent for rest of #1877 (honest unmarked-vs-marked discipline, mutation-verified tests, faithful native-cite). 0 blocking.
