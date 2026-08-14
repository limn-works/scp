---
name: slice1-roles-wasm-convergence
description: Inquisition verdict on #1877 slice 1 (WASM ContextRoleState adoption / native convergence) — GO, with conditional-rollback divergence to escalate
metadata:
  type: project
---

#1877 slice 1 converges the WASM bridge (`crates/scp-ffi/wasm/src/manager.rs` +
`consequence.rs`) onto the shared `scp_protocol::context::roles::ContextRoleState`,
replacing the flat `MemberEntry`/`ceiling_strings`/`suspended_capabilities`
reimplementation. Verdict: **GO**. Premise (shared type closes role-validation
divergence by construction) HOLDS — verified against current code, not docs.

**Why:** Final design-soundness gate before ship. Interrogated whether deferrals
are honest root-cause boundaries vs sunk-cost, and whether the conditional
add-member rollback matches native's no-corruption outcome.

**How to apply:** When the follow-up slices land (MembershipState adoption,
per-action EventType leaf parity, shared `remove_member` helper), re-check these
three escalation candidates — they are the open seams:

1. **AddMember-on-NEW-member-with-bad-role terminal state DIVERGES.** WASM fully
   rolls back (member absent). Native `execute_add_member`
   (`crates/scp-runtime/.../governance_helpers.rs:940-942`) does NOT roll back the
   `members.insert` on `system_assign_role` error → leaves a dangling member (in
   `members`, no assignment/caps). Reachable natively (no upstream role validation
   before dispatch). WASM is the *cleaner* behavior; the in-code comment's "this
   matches native" is precise about the no-existing-member-corruption property but
   imprecise about the new-member terminal state. Candidate: native should converge
   TO WASM in the shared remove/membership slice.
2. **RemoveMember suspension-clearing DIVERGES (honestly marked).** Native
   `execute_remove_member` strips members/assignments/member_capabilities but
   leaves `suspended_capabilities` dangling. WASM clears it (safer). Deferred to
   shared `ContextRoleState::remove_member` w/ spec-decided canonical policy.
3. **Per-member sequence base 0-vs-1 (honestly marked).** WASM first message seq=0
   (post-increment from 0); native seq=1 (pre-increment). Real off-by-one in
   emitted per-author `sequence_number`; out of ADR-050 export byte-parity scope
   but increment direction must reconcile on MembershipState adoption.

4. **RED-1101 governance quorum is OUT of slice-1 scope (separate engine subsystem).**
   `git log -L` on `governance_quorum` (manager.rs:4856) shows the slice's ONLY change
   was mechanical `ctx.members.len()` → `ctx.role_state.members.len()` (same live-count
   semantics, field renamed). The divergent model — WASM `total/2+1` live-count with NO
   `min_participation_bps`, vs native engines (`scp-protocol/.../governance/majority.rs`)
   frozen `eligible_voter_dids` + `min_participation_bps` floor — predates this slice
   (PR #788, 2026). Adopting ContextRoleState does NOT obligate converging it: quorum's
   INPUT (membership set) is semantically unchanged. Deferring with escalation is honest,
   not scope-dodging. Escalate as a future-slice AC (governance-engine convergence).
   The send-failure sequence rollback (HEAD `3e1cc9a6b`) is exact native parity and
   re-verified sound.

**Verified sound (no finding):**
- `ContextRoleState::system_assign_role` (worktree roles.rs:1731) validates member
  existence + role lookup + `validate_role_definition` ceiling check BEFORE any
  mutation of assignments/member_capabilities → an existing member is left fully
  intact on a rejected re-add. This is what makes the conditional rollback sound.
- ModifyCeiling converges (set_ceiling only, stale member_capabilities, matches
  native `apply_pending_ceiling_modification`).
- TransferAdmin converges (reject-non-member-first, demote all admins, promote
  new_admin, creator_did immutable — matches native `execute_transfer_admin`).
- Export/import restores `role_state` VERBATIM (BLACK-CEIL-01 closed); no recompute.
- Export digest determinism is SOUND: `members`/cap-sets use
  `serde_sorted_set`/`serde_sorted_set_map` codecs. `assignments[*].tokens` Vec is
  non-deterministic (HashSet mint order + random nnc) but explicitly NOT sorted and
  reasoned sound under the verbatim single-signer model (verifier re-serializes
  received bytes, never re-mints). Cross-impl byte-parity explicitly NOT claimed.
- Per-action EventType leaf deferral tracked by real `#[ignore]`'d
  `wasm_native_full_governance_eventtype_parity_pending` (wasm_conformance.rs:2454)
  — NOT phantom provenance.
- `MemberEntry` struct fully removed. Compiles clean (wasm32). 411/411 wasm tests pass.
