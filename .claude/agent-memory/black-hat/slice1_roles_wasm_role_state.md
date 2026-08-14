# WASM ContextRoleState slice (slice1-roles, HEAD cde3c1002) — adversarial sweep CLEAN

Target: WASM manager.rs adopting shared `scp_protocol::context::roles::ContextRoleState`,
converging to native. Final pre-ship black-hat sweep. 17 production-path probe tests
written + run through real dispatch (propose_governance_action SingleAdmin auto-execute,
join/leave/send, export_context/import_context). ALL PASSED — no break found.

## Verified SOUND (could not break)
- Membership-mutation atomicity: leave_context, dispatch_remove_member,
  join_context_encrypted-rollback, dispatch_add_member (conditional novelty rollback),
  subscribe_broadcast rollback — all strip members+assignments+member_capabilities+
  suspensions+seq together. No gone-from-members-but-retains-caps, no present-but-uncapable.
- dispatch_remove_member: MLS eviction `governance_remove_from_group().map_err()?` is
  TEXTUALLY BEFORE every state strip. On MLS failure member stays fully present. Structurally
  fail-closed by construction.
- TransferAdmin: reject-before-mutate (non-member guard first); multi-admin demotes ALL via
  system_assign_role; new_admin==existing-admin handled (demote+repromote); creator_did NEVER
  relocated (immutable root). Exactly one admin after.
- send_message / publish_broadcast: positive suspension-aware member_has_capability(MessagesWrite)
  gate. Read-only roles + suspended writers rejected.
- Suspension persists across promotion (prune_suspensions_to_role_grants keeps suspensions
  for caps the new role still grants — member→admin while write-suspended stays denied).
- RestoreAccess does NOT grant caps beyond role (only un-suspends).
- Export/import: Ed25519 verify_strict over JCS-canonical snapshot; verifying key resolved
  from snapshot.creator_did (NOT envelope); exporter_did==creator_did enforced. Tampered
  member_capabilities → sig fail; relocated creator → key-not-found; stripped sig → rejected;
  malformed ceiling → rejected at serde try_from(CapabilityCeilingRaw) deserialize.
  member_sequence_numbers sidecar is INSIDE the signed snapshot (integrity-protected); all
  seq-map access is .get/.entry/.remove (no panicking index) so desync is panic-safe.

## Native-equivalent (OUT OF SCOPE per task; documented, not raised)
- Zero-admin reachable via ChangeRole demoting sole admin to observer — native
  execute_change_role has NO last-admin guard either (governance_helpers.rs).
- ModifyCeiling NARROW does NOT re-derive member_capabilities; members keep caps now
  outside ceiling; member_has_capability checks member_capabilities only, not ceiling.
  Native apply_pending_ceiling_modification does set_ceiling() ONLY — identical. Shared
  protocol property, both sides.

## Known divergences already documented in-code (deferred, not security holes)
- RemoveMember/leave CLEAR suspensions; native leaves them (WASM is safer; convergence to
  shared remove_member primitive deferred to MembershipState slice).
- Per-action EventType leaves (AdminTransferred/CeilingModified) not emitted by WASM yet
  (wasm_native_full_governance_eventtype_parity_pending ignored test).
- send seq POST-increment (base 0) vs native PRE-increment (base 1) — off-by-one, flagged.

## Probe harness notes
- `cargo test -p scp-ffi-wasm --lib` runs in-crate #[cfg(test)] on HOST (cdylib has
  cfg(not(wasm32)) dev-deps). DYLD_LIBRARY_PATH needed.
- Identity registry is thread-local: crate::identity::test_helpers::{cleanup_identity_registry,
  register_identity_with_agent_key}; run export tests --test-threads=1.
- test_insert_member/test_insert_ceiling/test_insert_suspended_capability are real-helper
  shims over shared system_assign_role/set_ceiling — usable but production dispatch
  (propose_governance_action) is the authoritative path; SingleAdmin → required==0 auto-exec.
- SuspendCapability/SuspendAccess need member:ban in ceiling.
