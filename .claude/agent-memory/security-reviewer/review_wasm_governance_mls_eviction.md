---
name: review-wasm-governance-mls-eviction
description: Security review of fix/wasm-governance-mls-eviction (97c351df9) — WASM RemoveMember now cryptographically evicts from MLS group; CLEAN, zero findings
metadata:
  type: project
---

# WASM governance MLS-eviction security fix — CLEAN (0 findings)

Branch `fix/wasm-governance-mls-eviction` HEAD `97c351df9` (task #227, slice #206). 4 files, +746.

**Why:** Prior WASM `RemoveMember` evicted from governance state but did ZERO MLS work — removed member kept the group key schedule and could still decrypt. This makes WASM mirror native `execute_remove_member` (governance_helpers.rs:997).

**How to apply (verified facts for future re-review):**
- `dispatch_remove_member` (manager.rs ~3451) ordering is FAIL-CLOSED-KEEP: existence check via `contains_key` (no remove) → MLS `governance_remove_from_group(did)?` (the ONLY fallible crypto step) → `governance_remove_sender_key` (infallible) → `governance_rotate_sender_key` (infallible) → THEN `members.remove` + broadcast cleanup + buffer event + durable MemberLeft leaf. If MLS eviction errors, member stays fully in governance+broadcast (proven by `remove_member_keeps_governance_state_when_mls_eviction_fails`).
- Native's post-MLS-removal fault path (`fail_close_remove_member` on sender-key/rotate failure) has NO WASM analog because WASM's sender-key remove/rotate are infallible `()`-returning — correct, not a gap.
- Eviction is COMPLETE: `remove_member` (group.rs) calls `remove_members` + `merge_pending_commit` → epoch advances locally (test asserts epoch+1); `governance_rotate_sender_key` zeroizes old `local_sender_key` in place + regenerates.
- `leaf_index_for_did` (group.rs) is BYTE-PARITY with native `find_leaf_index_by_did` (wrapping_extension.rs:192): same member scan, same `if let Ok(basic) && Ok(scp_cred) && cred.did==target` chain, exact-string DID match, fail-LOUD on no-match (`remove_member_by_did` → RemoveMemberFailed, never silent skip). No wrong-leaf/collision risk.
- Commit hex returned to JS = TLS-serialized MLS Commit (public handshake data, path secrets HPKE-sealed to REMAINING members) — same as native `remove_output.commit_bytes`. NO key-material leak.
- Sender-key non-redistribution on encrypted WASM contexts is PRE-EXISTING + orthogonal: MLS epoch-advance is the operative lockout (evicted member can't derive new-epoch keys), proven by `evicted_member_cannot_decrypt_after_removal_and_rotation` (Bob stale-state fails AEAD on new-epoch ct, Carol still decrypts).
- Post-eviction encode-failure window is UNREACHABLE: `parse_proposal_id_bytes(proposal_id)?` in the success branch can't fail for a tracked proposal — propose path validates the id via same fn BEFORE inserting into pending/resolved_proposals (manager.rs ~4360), and dispatch only runs after the proposal is found there.
- Convergence (MemberLeft leaf): empty payload, actor_did=executor (not removed member), timestamp=convergent proposal.created_at (not local now), appended BEFORE GovernanceActionExecuted — all pinned by `remove_member_appends_empty_member_left_leaf_before_executed_wasm` + native KAT `cross_impl_remove_member_leaf_is_empty_and_precedes_executed`.

**Build/test:** wasm32 lib clippy CLEAN; 367 WASM lib tests pass (incl 6 new security tests); native conformance KAT passes. GOTCHA: `cargo clippy -p scp-ffi-wasm --target wasm32-unknown-unknown --all-targets` FAILS on `scp_identity` unlinked in identity.rs test target — PRE-EXISTING (identity.rs untouched by branch), WASM unit tests run on HOST target not wasm32.
