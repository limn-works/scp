---
name: slice1-roles-wasm-rolestate
description: WASM bridge ContextRoleState convergence slice (slice1-roles) — 14 adversarial probes through production dispatch all resisted; clean outcome
metadata:
  type: project
---

# slice1-roles: WASM ContextRoleState adoption — CLEAN adversarial outcome

Branch `slice1-roles` (HEAD a56fd0e31). WASM `manager.rs` per-context governance/role
state adopts shared `scp_protocol::context::roles::ContextRoleState`. Probed with 14
throwaway Rust tests run on the NATIVE test target (host SystemTime fallback in
`time.rs` lets governance/propose/send paths run without JS), all through PRODUCTION
dispatch (`dispatch_governance_action`, `propose_governance_action`, `send_message`,
`export_context`/`import_context`). **All 14 resisted — no WASM-specific divergence found.**

## Why it holds (architecture)
- Single shared type `ContextRoleState` in `crates/scp-protocol/src/context/roles.rs`.
  `member_has_capability` checks suspension FIRST then `member_capabilities`. All gates
  delegate to it, so suspension-awareness is uniform.
- Send/publish gate: `send_message`/`publish_broadcast` use positive
  `member_has_capability(did, MessagesWrite)` (suspension-aware) — read-only roles and
  suspended writers both rejected.
- Propose gate: `propose_governance_action` checks `member_has_capability(proposer,
  "governance:propose")` (suspension-aware). Suspended proposer can't auto-execute under
  single_admin.
- TransferAdmin (`dispatch_governance_action_ext`): rejects non-member BEFORE mutation
  (no admin vacancy); demotes ALL admin holders then promotes new; `creator_did` (export
  signer) NEVER touched — export still works after admin relocates.
- AddMember: inserts member, on `system_assign_role` failure (undefined/out-of-ceiling
  role) ROLLS BACK members + member_sequence_numbers (no phantom member/orphan sidecar).
- Encrypted-join (`join_context_encrypted`): on MLS welcome failure, inline-strips
  members/assignments/member_capabilities/suspensions/sequence; leaf deferred to
  post-success — no phantom leaf, no partial membership.
- Export/import: `exporter_did == creator_did` gate, Ed25519 `verify_strict` over
  JCS-canonical snapshot, version gate (rejects <v and >v), ceiling grammar re-validation,
  `CapabilityCeiling` serde `#[serde(try_from=CapabilityCeilingRaw)]` rejects malformed
  ceiling at DESERIALIZE (before signature). role_state restored VERBATIM (the
  BLACK-CEIL-01 fix — no per-member recompute that re-granted a suspended-then-widened cap).
  `crypto: None` on import — member_sequence_numbers sidecar decoupled from AEAD, no GCM
  nonce reuse. member_sequence_numbers is INSIDE the signed snapshot → desync requires
  creator key.

## Documented NATIVE-PARITY behaviors (NOT WASM bugs — out of scope per task)
- ModifyCeiling does `set_ceiling` ONLY; member_capabilities go stale-on-ceiling-change
  (member_has_capability doesn't consult ceiling). Ceiling NARROW does not revoke held
  caps; ceiling WIDEN does not grant unassigned caps (no member-cap refresh). Matches
  native `apply_pending_ceiling_modification`.
- SuspendCapability(write) then ChangeRole member→observer→member LAUNDERS the write
  suspension off: observer doesn't grant write so prune_suspensions_to_role_grants drops
  it; re-promotion grants FRESH write. Observed `has_write=true` after round-trip. This is
  the documented `prune_suspensions_to_role_grants` semantic ("banned voter who becomes
  observer has no vote to suspend"). Native-equivalent — explicitly out of scope.

## Test-only helpers that DON'T match production (per task warning — verified)
- `set_ceiling_and_refresh` / `test_insert_ceiling`: rebuild role defs + re-run
  system_assign_role per member. Production `dispatch_modify_ceiling` does set_ceiling ONLY.
  All my findings probed through real dispatch, not these helpers.
