---
name: wasm-mls-eviction-c3f7fe48b
description: WASM governance MLS-eviction security fix @c3f7fe48b (branch fix/wasm-governance-mls-eviction) — fresh independent crypto re-review, SOUND, APPROVE, no blocking; delta vs 66a2c6a5c is doc/comment-only
metadata:
  type: project
---

# WASM MLS eviction @c3f7fe48b — SOUND, APPROVE, no blocking findings

Branch `fix/wasm-governance-mls-eviction`, HEAD c3f7fe48b. Fresh independent re-review. Delta vs prior-reviewed [@66a2c6a5c](wasm-mls-eviction-66a2c6a5c.md) is DOC/COMMENT-ONLY (verified `git diff 66a2c6a5c..HEAD`): group.rs test-comment clarifies single-member self-DID test does NOT discriminate short-circuit from own-leaf skip (points to `remove_member_by_did_self_did_does_not_evict_duplicate_leaf` as isolating test); manager.rs sender-key comment delegated to `governance_rotate_sender_key`(state.rs) — target exists+carries full explanation, cross-ref accurate; scp.ts doc split into Native(auto-broadcast)/WASM(MUST-relay) backend cases. Zero logic change.

Native parity verified line-by-line this pass: provider.rs:1041 self-DID short-circuit + own-index skip mirrored by WASM group.rs:347 own_did short-circuit + group.rs:270 own-index continue; provider.rs:1077 missing-leaf no-op = WASM group.rs:364 Ok(Vec::new()); execute_remove_member(governance_helpers.rs:1231) MLS-first(1265)+fail-closed-rotate(1284-93)+strip+emit+broadcast+durable MemberLeft empty payload(1348-53 actor_did=CommitMeta executor, ts=proposal.created_at) BEFORE wrapper GovernanceActionExecuted — WASM dispatch_remove_member(manager.rs:3454) byte-identical order incl fail-closed CRYPTO_4011 keep + suspended_capabilities/read_exclusion_list strip + append_log_event(MemberLeft, executor_did, b"", timestamp_secs).

§9.16.4 sender-key: rotate eager-zeroize+OsRng generate; remove drops ZeroizeOnDrop; MLS epoch-advance = operative lockout (no cross-member sender-key distribution, pre-existing gap, orthogonal). timestamp_secs from proposal_created_at(manager.rs:3119-3158) not now(). executor_did = committer.

Tests this pass: 379 wasm lib (incl evicted_member_cannot_decrypt security proof) pass; 57 conformance (`-p scp-runtime --test wasm_conformance --features testing` — lives in scp-runtime NOT scp-core per CLAUDE.md) incl cross_impl_remove_member + cross_impl_self_removal pass; wasm32 clippy clean; NO enforcement files in diff. KATs honestly disclose REPLAY native append (cdylib constraint); non-tautological WASM proof = manager.rs unit driving real execute_governance_action.

Residual NON-blocking pre-existing: WASM commit-relay caller obligation (ADR-034), now doc'd per-backend in scp.ts.
