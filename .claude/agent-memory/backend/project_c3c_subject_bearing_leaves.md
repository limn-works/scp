---
name: project-c3c-subject-bearing-leaves
description: c3c-ts subject-bearing role/membership leaf payloads (native-only); RoleAssigned/MemberJoined/MemberLeft carry affected-member DID; KAT regenerated; FFI/SDK surfacing is next phase
metadata:
  type: project
---

Subject-bearing participation-fact leaves (ADR-011 amendment, .docs/adrs/phase-2.md ~L890-911). Branch `c3c-ts`, pushed `012bba8f5` (base 03d0eca8c). NATIVE-ONLY (WASM removed by a parallel agent in same window — do not add WASM to parity asserts).

**What landed (4 commits):**
- `crates/scp-event-log/src/payload.rs`: added `RoleAssignedPayload { subject_did, role }` + `MembershipChangePayload { subject_did, role_name }` (positional MessagePack, mirrors GovernanceActionExecutedPayload). Added SEPARATE `subject_did: Option<String>` field to `EventPayloadProjection` (KEPT Phase-1 `target_did`). project_payload: RoleAssigned→RoleAssignedPayload, MemberJoined|MemberLeft→MembershipChangePayload, empty→None.
- 6 native emit sites switched empty-payload→subject-bearing via TWO new default trait methods on `ContextEventLogProvider` (builder.rs): `append_membership_change_leaf` + `append_role_assigned_leaf` (added to keep execute_remove_member under clippy 100-line cap AND dedup). Sites: governance_helpers execute_add_member/remove_member/change_role; lifecycle_helpers leave_context+join_context; broadcast_helpers subscribe/unsubscribe. remove_member + leave_context capture role_name BEFORE the membership strip (remove_member returns it as the commit_class_s_keep closure's `T`).
- KAT: test_vectors Vector 32/33 appended seqs 7(RoleAssigned)/8(MemberJoined) at END; old seqs 0-6 byte-identical; new root `0c6f6a09...` (was 39e50b87); event_count 7→9. Mirrored in .docs/specs/25. eventlog_convergence: MemberJoined leaves now carry payload (still converges).
- .docs/specs/07 §7.3.2: governance/access facts key on leaf `target_did`, role/membership on `subject_did` (removed `subject_did==target_did` field/var conflation); attestation bullet flagged as credential-layer exception.

**Whitelist hit:** repo pre-commit hook runs FULL workspace clippy (-D warnings) incl `too_many_lines` (100). Adding ~10 lines to execute_remove_member tripped it → solved by extracting shared trait helpers (NOT by allow).

**NEXT PHASE (not done here):** FFI/SDK surfacing of `projection.subject_did` across the 3 native bridges (PyO3 src/event_log.rs, NAPI, UniFFI all currently read only `.target_did`) + per-bridge parity tests. `participation_service.rs` / participation.rs still attribute via actor_did — they consume the new shape next phase. See [[project-eventlog-committer-assigned-timestamp]].
