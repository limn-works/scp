---
name: wasm-mls-eviction-66a2c6a5c
description: ROUND 3 alignment review of fix/wasm-governance-mls-eviction @ 66a2c6a5c — self-removal parity delta; ALIGNED, zero findings
metadata:
  type: project
---

# WASM governance RemoveMember self-removal parity — ROUND 3 @ 66a2c6a5c (branch fix/wasm-governance-mls-eviction, 2026-06-23)

Verdict: **ALIGNED, ZERO findings, ships.** Third pass; extends round-2 [[wasm_mls_eviction_b98c5b1a9]] and round-1 [[wasm_mls_eviction_97c351df9]]. Task #227.

HEAD 66a2c6a5c. Two new commits on top of b98c5b1a9: f761c7d2b (self-removal MLS no-op parity / skip own leaf) → 66a2c6a5c (self-DID short-circuit + dup-leaf parity). Delta since b98c5b1a9 = +579 lines across group.rs / state.rs / manager.rs / wasm_conformance.rs ONLY. TS SDK (scp.ts/wasm.ts) + context.rs UNCHANGED since round-2 → round-2 commit-relay-contract findings stand.

**Why:** the round-1/2 fix made WASM RemoveMember evict from MLS, but self-removal (executor == removed DID) hit `CannotRemoveSelf` from OpenMLS → dispatch failed closed → WASM appended ZERO leaves where native appends TWO → diverged §9.9.3 tree::root + membership set. This delta closes that.

**How to apply:** this branch is reviewed-clean across 3 rounds; if asked to re-review, re-confirm seals survived and re-run the 3 verification commands below.

## What the delta does (all native-parity, byte-verified)
- **Self-DID short-circuit** group.rs:339 `if self.own_did()? == member_did { return Ok(Vec::new()); }` == native provider.rs:1041 `if member_did == self.local_did { return ...default() }`. Returns BEFORE the scan.
- **Own-leaf skip** group.rs:268-271 `if member.index == own_index { continue; }` == native provider.rs:1060. `own_index = g.own_leaf_index()` on RAW OpenMLS MlsGroup (INFALLIBLE — no Result; native wrapper version returns Result). Do NOT hardcode index 0 (Welcome-joiner is non-zero leaf).
- **own_did()** group.rs:204 derives local DID from committer's own-leaf credential — NO stored field (correct for creator leaf 0 AND Welcome-joiner non-zero leaf). WASM analogue of native self.local_did.
- **Dispatch proceeds on empty commit** manager.rs:3515-3569: empty commit still strips ctx.members, cleans suspended_capabilities + read_exclusion_list, buffers MemberLeft, appends durable MemberLeft leaf (executor actor_did + EMPTY payload). Verified == native execute_remove_member (governance_helpers.rs:1044-1098: identical strip+emit+append AFTER crypto no-op).

## Native parity ground truth (verified this round)
- crates/scp-runtime/src/crypto/mls/provider.rs:1041 (self-DID short-circuit) + 1053-1056 (own_index) + 1060 (own-leaf skip) + 1077-1084 (missing-leaf no-op warn+default). Native has BOTH mechanisms → WASM dual-mechanism claim is accurate.
- crates/scp-runtime/src/context/governance_helpers.rs:997-1101 execute_remove_member: calls crypto.remove_member (self-short-circuits) but PROCEEDS to strip membership (1044-1058) + emit MemberLeft (1060-1067) + append durable MemberLeft leaf w/ actor_did (1097-1098). Exactly what WASM self-removal test asserts.

## Duplicate-DID edge case — correctly reasoned
Native short-circuits at 1041 BEFORE the scan, so a 2nd non-own leaf carrying local_did is never resolved/evicted (neither leaf evicted, no epoch advance). WASM matches via the same pre-scan short-circuit. Proven by remove_member_by_did_self_did_does_not_evict_duplicate_leaf (group.rs) + governance_remove_self_did_no_op_in_dup_did_tree (state.rs governance-layer twin).

## Cross-impl conformance (wasm_conformance.rs)
cross_impl_self_removal_leaf_is_empty_and_precedes_executed REPLAYS native's append sequence (NOT co-driving both impls — cdylib can't be dev-dep'd; WASM dispatch asserted separately in WASM crate). Pins: empty-payload MemberLeft + executor actor_did + exactly-1-each leaf counts + MemberLeft-before-GovernanceActionExecuted ordering. Correct split, not a shortcut.

## Sibling gaps — correctly OUT
1. WASM AddMember (manager.rs:3407-3445) does ZERO MLS work + NO durable MemberJoined leaf. fail-to-GRANT direction = SAFE (un-added can't decrypt). → #206 + #1877. Correctly untouched.
2. No commit-relay retry backstop = ADR-034 consequence (WASM no transport); round-2 3-layer relay-contract docs cover caller responsibility (unchanged this delta). → WASM-transport story.

## Non-finding considered
Destroyed-group asymmetry: native self-short-circuits at 1041 even if group destroyed (before with_context); WASM own_did() returns GroupDestroyed when crypto Some-but-group-None. NOT a divergence — that degenerate state shouldn't occur (self-leave destroys whole crypto state → dispatch sees crypto.is_none() → else{Vec::new()}), and failing closed on a genuinely-broken group is SAFE. Not a finding.

## Artifact-flow
No spec/ADR edits; none needed — §9.16.4 (removal=MLS epoch advance) + #1294 (missing-leaf no-op) already normative. Code conforms; nothing flows up. Clean.

## Verification RAN this round (all green)
- `cargo test -p scp-ffi-wasm --lib`: 379 passed (incl all new own_did/self_did/dup_did/dispatch tests)
- `cargo test -p scp-runtime --features testing --test wasm_conformance cross_impl`: 8 passed (incl new self-removal)
- `cargo clippy -p scp-ffi-wasm --target wasm32-unknown-unknown`: clean
- conformance test lives in scp-runtime (NOT scp-core — CLAUDE.md note slightly stale) + needs --features testing

LESSON: a "self-removal parity" delta on an MLS-eviction fix = verify BOTH native mechanisms (pre-scan self-DID short-circuit + in-scan own-leaf skip) are mirrored, BOTH construction paths (create leaf-0 + Welcome non-zero leaf) covered by own_did tests, the dup-DID edge returns BEFORE the scan (else it wrongly evicts the non-own dup), and the empty-commit dispatch still appends the SAME leaf count as a normal removal (zero-leaf fail-closed regression = the divergence being closed). own_leaf_index on RAW OpenMLS group is infallible; on the native wrapper it's Result — don't confuse.
