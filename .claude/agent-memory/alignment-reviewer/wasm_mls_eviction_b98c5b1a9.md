---
name: wasm-mls-eviction-b98c5b1a9
description: ROUND-2 alignment review of WASM governance RemoveMember MLS-eviction security fix at HEAD b98c5b1a9 (3 commits) — ALIGNED, zero findings; follows 97c351df9 round-1
metadata:
  type: project
---

# WASM governance RemoveMember MLS-eviction — ROUND 2 @ b98c5b1a9 (branch fix/wasm-governance-mls-eviction, 2026-06-23) — ALIGNED, ZERO findings

Supersedes/extends [[wasm_mls_eviction_97c351df9]] (round-1 at commit 97c351df9, also ALIGNED). HEAD now b98c5b1a9, 3 commits:
ea0058cde (cryptographically evict) → 97c351df9 (fail-closed ordering + sender-key docs) → b98c5b1a9 (no-op-on-missing-leaf parity + relay-commit docs). Task #227.

**Why:** Closes decryption-after-removal hole — WASM `dispatch_remove_member` previously did ZERO MLS work (removed member kept group key schedule). This round's delta over 97c351df9 = the #1294 missing-leaf NO-OP parity (a governance member with no MLS leaf is removed CLEANLY, empty commit, not an error/keep) + commit-relay contract docs at all 3 layers.

**How to apply:** Treat as the canonical reference for "make WASM match native at a hard crypto boundary native enforces." Verified against native `execute_remove_member` (governance_helpers.rs:997) byte-for-byte.

## What was verified (all CONFIRMED)
- **Ordering** existence-check → MLS-evict FIRST → drop-sender-key → rotate-sender-key → strip governance/per-DID state → buffer event → durable MemberLeft leaf → return commit. Matches native exactly (native also strips role_state/access/routing; WASM strips suspended_capabilities + read_exclusion_list — its analogues).
- **Fail-closed-keep** genuine MLS error (GroupDestroyed / commit-serialize-on-found-leaf) → Err with member STILL present, NO MemberLeft leaf, retry-safe. Test `remove_member_keeps_governance_state_when_mls_eviction_fails` proves it.
- **#1294 missing-leaf no-op** WASM `remove_member_by_did` returns `Ok(Vec::new())` (empty commit) + console.warn for a DID with no MLS leaf — mirrors native `MlsCryptoProvider::remove_member` returning `RemoveMemberOutput::default()` (provider.rs:1077-1084). Governance layer authoritative for membership; crypto layer only manages MLS. Dispatch PROCEEDS to strip + append leaf. Tests `remove_member_with_no_mls_leaf_is_removed_cleanly`, `remove_member_by_did_is_noop_for_non_member`.
- **Durable MemberLeft leaf 3 convergence-critical fields** EMPTY payload (removed DID buffer-only) + EXECUTOR actor_did (committing member, NOT removed member) + convergent `proposal.created_at` (NEVER now()). Appended BEFORE wrapper's GovernanceActionExecuted (matches native execute_remove_member → finalize_governance_action order). Cross-impl KAT `cross_impl_remove_member_leaf_is_empty_and_precedes_executed` (wasm_conformance.rs) compares against MerkleEventLogProvider (the NEW scp_event_log substrate taking explicit timestamp_secs) — the correct convergence target, NOT the legacy InMemoryContextEventLog hash-chain (event_log.rs:97 stamps SystemTime::now() but is NOT the actor-lane convergence target).
- **Spec conformance, NO spec change needed** §7.3.1 (committer-assigned created_at leaf timestamp + committing member as actor + byte-identical preimages) + §9.9.3 (equal-count⇒equal-root requires every leaf field convergent incl timestamp) + §9.16.4 (removal=MLS epoch advance) + §10:200/207 (member removal = MLS Remove Commit + epoch advance, encryption-as-access-control) are ALL pre-existing + normative. Artifact-flow invariant RESPECTED: code conforms to spec.
- **Commit-relay contract** documented at 3 layers (context.rs wasm export doc, internal/wasm.ts, public scp.ts contextExecuteGovernanceAction): WASM has NO internal transport (ADR-034), never auto-broadcasts, caller MUST relay the hex `commit` or MLS group silently forks. Empty commit = broadcast/unencrypted or no-leaf.
- **Security proof test** `evicted_member_cannot_decrypt_after_removal_and_rotation` (state.rs) — 3-member (Alice/Bob/Carol), evicts Bob, proves Bob's stale state CANNOT decrypt post-eviction (new epoch) while Carol CAN. Operative lockout = MLS epoch advance (NOT sender-key rotation).

## Sibling gaps — correctly OUT of scope (and WHERE they belong)
1. **WASM AddMember does NO MLS work** (`dispatch_add_member` manager.rs:3407 only mutates ctx.members + buffer event; no MLS add/Welcome/commit, no durable MemberJoined leaf). Correctly out of scope BECAUSE the asymmetry is right: AddMember-without-MLS merely FAILS TO GRANT (un-added member can't decrypt anyway — never given keys); only RemoveMember-without-MLS is a hole. The MemberJoined-leaf half belongs to #206 (Slice 6: WASM per-action governance leaf parity / event-count); the MLS-add half is a separate convergence item under #1877.
2. **No WASM commit-relay retry backstop** native auto-broadcasts via `try_broadcast_commit_or_enqueue`; WASM returns commit to caller. This is an ADR-034 architectural consequence (no internal transport), NOT a regression — honestly documented at all 3 layers. Belongs to the broader WASM-transport story, not this fix.
3. `dispatch_reset_member` (manager.rs:4169) = counter reset (remove+re-add same role), NOT an MLS membership change → correctly does no MLS work.

## Convergence-program fit (#1877 / #206)
This fix ADDS the WASM MemberLeft leaf (2 durable leaves: MemberLeft + GovernanceActionExecuted), moving WASM TOWARD native's per-action leaf parity — consistent with #206 direction, not against it. KAT pins exactly-1 of each (guards duplicate-append divergence). NO event-count baseline gate broken (expansion, not weakening).

## Cross-impl KAT split rationale (honest)
scp-runtime test crate cannot dev-depend on scp-ffi-wasm cdylib → KAT split: native half in wasm_conformance.rs REPLAYS the 2 appends against MerkleEventLogProvider; WASM half in manager.rs tests drives the real dispatch_remove_member. Both assert identical empty-payload + executor-actor + ordering invariants. Legit (same pattern as prior RoleAssigned KAT, task #223).

## Verification RAN (all green)
- `cargo check --target wasm32-unknown-unknown -p scp-ffi-wasm` clean
- `cargo test -p scp-ffi-wasm --lib` 371 passed / 0 failed (incl all 7 new eviction/leaf/security tests)
- `cargo test -p scp-runtime --features testing --test wasm_conformance cross_impl_remove_member` 1 passed

## LESSONS
- For a "make WASM match native at a crypto boundary" fix, verify the convergence-critical leaf comparison targets the ACTOR-LANE substrate (scp_event_log MerkleEventLogProvider, explicit timestamp_secs), NOT the legacy runtime hash-chain provider (which stamps now() but isn't the convergence target). Don't false-flag the now() in the legacy provider.
- Classify sibling gaps by SECURITY DIRECTION: AddMember-no-MLS = fail-to-grant (safe); RemoveMember-no-MLS = fail-to-revoke (hole). A fix that hardens only the dangerous direction is correctly scoped, not half-done.
- #1294 missing-leaf no-op is the RIGHT parity: a governance member with no MLS leaf must be removed CLEANLY (empty commit), not kept — keeping would diverge from native and orphan governance state. Confirm the no-op vs genuine-error split (missing-leaf=no-op; GroupDestroyed/serialize-fail=Err→fail-closed-keep).
