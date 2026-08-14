---
name: wasm-mls-eviction-97c351df9
description: WASM governance RemoveMember MLS-eviction security fix (branch fix/wasm-governance-mls-eviction @97c351df9) — ALIGNED, zero findings; mirrors native execute_remove_member byte-for-byte
metadata:
  type: project
---

# WASM governance MLS-eviction security fix @ 97c351df9 (branch fix/wasm-governance-mls-eviction, 2026-06-23) — ALIGNED, ZERO findings

Reviewed for task #227. Security fix: WASM `dispatch_remove_member` previously did ZERO MLS work (only stripped governance map + buffer event) → a removed member kept the MLS group key schedule and could still decrypt. Fix makes WASM mirror native `execute_remove_member`.

**Why:** decryption-after-removal hole on the WASM bridge — directly violates the encryption-as-access-control tenet (MLS group keys enforce membership). Distinct from, and more urgent than, the per-action leaf-count parity program (#206).

**How to apply:** this is the canonical example of "make WASM match native" being the RIGHT direction (closing a divergence where WASM skipped a hard security boundary), not entrenching one. Cite when assessing future WASM-vs-native parity fixes.

## Parity verified byte-for-byte against native (governance_helpers.rs:1231 execute_remove_member on the SAME branch — note branch has the POST-unification scp_event_log substrate, trait `append_event` takes explicit `timestamp_secs`, builder.rs:158)
- Ordering: MLS `remove_member` FIRST (hard boundary) → `remove_member_sender_key` → `rotate_sender_key` → strip governance/role/access state → emit buffer event → durable `MemberLeft` leaf. WASM (manager.rs:3450 dispatch_remove_member): existence-check-without-removing → `governance_remove_from_group` (MLS evict) → `governance_remove_sender_key` → `governance_rotate_sender_key` → `members.remove` → `push_event` → `append_log_event(EventType::MemberLeft, executor_did, b"", timestamp_secs)` at 3548.
- FAIL-CLOSED-KEEP: WASM existence-checks WITHOUT removing, defers the governance strip until AFTER MLS eviction succeeds. If crypto errors, returns Err with member STILL present (no decryption-after-removal window; retry-safe). Matches native's `commit_class_s_keep` keep-direction (removal STAYS on persist failure; re-admit is the unsafe direction). Test `remove_member_keeps_governance_state_when_mls_eviction_fails` proves it via REAL crypto (governance member w/ no MLS leaf → RemoveMemberFailed → member kept, no MemberLeft leaf).
- Durable leaf: EMPTY payload (removed DID is buffer-only, never in the durable leaf §9.9.3), `actor_did`=EXECUTOR (committing member, not removed member; ADR-031 §8 / §7.3.1), `timestamp`=convergent `proposal_created_at` (signed proposal.created_at, NEVER local now() — §7.3.1/§9.9.3 equal-count⇒equal-root invariant). Native appends MemberLeft via `append_context_event` (None payload) at governance_helpers.rs:1348.
- Ordering MemberLeft-before-GovernanceActionExecuted: WASM wrapper `execute_governance_action` (manager.rs:3078) calls dispatch (appends MemberLeft inside) THEN appends GovernanceActionExecuted (3219) with SAME proposal_created_at — mirrors native execute_remove_member → finalize_governance_action.
- Cross-impl KAT `cross_impl_remove_member_leaf_is_empty_and_precedes_executed` (wasm_conformance.rs) drives native's REAL appends + pins empty payload + executor actor_did + ordering. WASM half (`remove_member_appends_empty_member_left_leaf_before_executed_wasm`) pins same on the WASM path. Split because scp-runtime test crate can't dev-dep the scp-ffi-wasm cdylib.

## Spec/ADR alignment
- §9.16.4: Removal = MLS group epoch advance excluding the removed member (operative lockout); "removal implies blocking" → sender-key rotation is part of removal. Code comments frame MLS epoch advance as the operative lockout + sender-key rotation as the §9.16 layer — ACCURATE.
- ADR-034 (WASM no scp-runtime dep): respected — WASM uses local OpenMLS (`js` feature) WasmMlsGroup + scp_event_log directly, re-implements rather than imports runtime. `leaf_index_for_did`/`remove_member_by_did` mirror native `find_leaf_index_by_did` (MLS doesn't key tree by DID).
- Artifact-flow: no spec/ADR edits (none needed — §9.16.4/§9.9.3/§7.3.1 already normative; code conforms TO spec). Clean.

## Roadmap fit
- Aligns with the event-log convergence program (finding_runtime_eventlog_not_rfc6962 unification; #1877/#206). Adding the WASM MemberLeft leaf MOVES TOWARD per-action leaf parity, doesn't conflict.

## Honestly-disclosed sibling gaps (NOT this PR's scope — correctly deferred to #206)
1. `dispatch_add_member` (manager.rs:3407) appends NO durable leaf (buffer push_event only) AND does no MLS add_member — the AddMember mirror of this fix. This is the pending #206 per-action leaf-count parity work. NOT the security hole here.
2. WASM has NO cross-member sender-key distribution path for encrypted (non-broadcast) MLS contexts — `encrypt_message` emits only the double-ciphertext, never attaches `local_sender_key`. The rotated key is generated+stored but not redistributed. Code discloses this explicitly + argues (correctly) eviction security holds WITHOUT it: the MLS layer-2 epoch advance is the lockout, independent of sender-key redistribution. Pre-existing, orthogonal to eviction.

## Verification
- `cargo check --target wasm32-unknown-unknown -p scp-ffi-wasm` CLEAN.
- CRYPTO_4011 is a real registered WASM code (also used manager.rs:1935).
- 4 new tests: leaf_index resolve+evict, non-member errors, full security proof (evicted Bob can't decrypt post-eviction / Carol still can), fail-closed-keep.

LESSON: "make WASM match native" is the right direction when WASM was SKIPPING a hard security boundary native enforces — verify by (a) reading native's per-action helper on the SAME branch (substrate may differ from main — this branch has post-unification scp_event_log timestamp-carrying append), (b) confirming the 3 convergence-critical leaf fields match (empty payload / executor actor_did / convergent proposal.created_at not now()), (c) confirming fail-closed ORDER (security boundary before state strip, Err leaves state intact), (d) classifying sibling gaps (AddMember leaf, sender-key redistribution) as separate tracked work, not this PR's debt.
