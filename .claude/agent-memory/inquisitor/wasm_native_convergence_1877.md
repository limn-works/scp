---
name: wasm-native-convergence-1877
description: #1877 WASM↔native convergence slice — the dispatch_add_member eager-rollback re-add eviction divergence, and which membership-add paths are guarded
metadata:
  type: project
---

#1877 slice 1 makes WASM adopt shared `ContextRoleState` + converge to native across
role/ceiling/suspension/send-gate/membership/encrypted-join/ModifyCeiling/TransferAdmin/export-import.

**Root-cause finding (the one live divergence introduced by the slice):**
`dispatch_add_member` (crates/scp-ffi/wasm/src/manager.rs ~L3886-3897) eagerly rolls back
`members.remove(did)` on `system_assign_role` failure. It is the ONLY membership-add path
WITHOUT a preceding `members.contains` guard:
- `join_context_membership_only` (~L1841) rejects already-joined BEFORE insert.
- `subscribe_broadcast` (~L5524) wraps insert+rollback in `if !members.contains`.
- encrypted-join rollback (~L2362) is a fresh joiner (helper rejected already-joined).
So on `AddMember{existing_member, bad_role}` (reachable — no upstream "already member" guard
on either bridge; both treat AddMember as idempotent re-role upsert), WASM EVICTS a
legitimately-present member, leaving orphaned `assignments`/`member_capabilities` (rollback is
also partial — strips only members+seq). Native `execute_add_member` does NOT roll back
(comment: "member ADD is coalesce-window-rollback acceptable, ADR-049 §9"); member stays.
`system_assign_role` validates role BEFORE mutating (roles.rs ~L1731), so native's prior
assignment survives. **WASM added a rollback native lacks, and it is unsafe on re-add.**
Test `add_member_with_undefined_role_is_rejected_wasm` only covers the FRESH newcomer case.

**Escalate to human (spec decisions, per artifact-flow):**
1. Canonical member-removal suspension policy: native leaves removed member's
   `suspended_capabilities` (no removal primitive — unexamined omission); WASM clears via
   `restore_capabilities`. Slice defers to shared `ContextRoleState::remove_member` +
   spec-decided policy (MembershipState slice). Honest deferral.
2. Should `AddMember` on an already-present member be rejected at validate-time (vs silent
   re-role upsert)? Neither bridge guards it. Resolving this dissolves the eviction edge.

**Honest deferrals (labeled in commits, not mislabeled as parity):**
- ModifyCeiling: WASM applies set_ceiling IMMEDIATELY (single-phase); native stages a
  pending modification w/ CEILING_CHANGE_NOTIFICATION_PERIOD_SECS (two-phase). Commit
  eb276450e converged the inner write (set_ceiling-only, killed an eager-refresh
  un-suspension security bug) but two-phase timing remains deferred. Commit subject
  "converge ModifyCeiling to native" over-claims; body is honest.
- MembershipState / member_sequence_numbers sidecar, per-action EventType leaf parity:
  deferred, marked.

**Latent (pre-slice, comment-only touched):** export version gate `envelope.version <
WASM_EXPORT_VERSION` (=5). Old comment said signatures introduced at v4 → gate would reject
signed v4. Final commit replaced literal "4" with the symbol, papering over the question
rather than resolving whether signed-snapshot-intro-version == current-export-version.
