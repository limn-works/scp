# Slice 1 — WASM ContextRoleState adoption + TransferAdmin convergence (HEAD d05e8ad7d)

Branch: wasm/1877-slice1-adopt-context-role-state. Probed 11 exploits through PRODUCTION
dispatch (propose_governance_action / send_message / export_context / import_context). ALL DEFENDED — clean.

## VERDICT: CLEAN. BLACK-CEIL-01 is now FIXED in this slice (supersedes prior HIGH).

Prior memory (slice1_1877_modify_ceiling.md, slice1_f319_verbatim_import.md) flagged BLACK-CEIL-01:
WASM export/import un-suspended a SuspendAccess'd member across a ceiling widen because the
WASM snapshot dropped member_capabilities and recomputed via system_assign_role on import.
THAT IS NOW FIXED HERE:
- export_context (manager.rs ~6377): carries `role_state: ctx.role_state.clone()` VERBATIM
  (members, assignments+tokens, ceiling, role_definitions, member_capabilities, suspended_capabilities).
- import_context (~6788): `let role_state = snap.role_state.clone();` — NO system_assign_role recompute,
  NO ceiling intersection. Matches native lifecycle_helpers::import_context exactly.
- dispatch_modify_ceiling (~3669): set_ceiling ONLY, no refresh — live widen no longer re-grants.
PROVED by BH-5: SuspendAccess → governed ModifyCeiling widen → export → import into fresh manager →
victim STILL suspended (member_has_capability false; suspended set contains messages:write; send blocked).

## TransferAdmin (dispatch_governance_action_ext ~4055) — converges to native execute_transfer_admin:
- reject non-member BEFORE any mutation (CTX_2015)
- demote EVERY admin-role holder → "member", then promote new_admin → "admin" (built-in roles,
  ceiling-intersected so system_assign_role CANNOT fail mid-loop → no zero-admin strand, no rollback needed)
- NEVER touches creator_did (immutable export signer / UCAN root / HMAC identity)
Probed: self-transfer (BH-1, 1 admin), transfer-away-then-export-still-signs (BH-2, creator demoted to
member but still signs export), 2-admins-collapse-to-1 (BH-3), narrow-ceiling-no-strand (BH-11),
suspend-then-promote-to-admin-stays-suspended (BH-4, prune_suspensions_to_role_grants RETAINS the
suspension because admin still grants messages:write). All converge to exactly ONE admin.

## Export/import verify pipeline (deserialize_and_verify_envelope ~6524) — SOUND:
version gate (reject <4 unsigned AND >4); exporter_did==creator_did; non-empty sig; Ed25519 verify_strict
over JCS(snapshot) against key RESOLVED FROM creator_did (#active→#agent, never envelope-supplied);
HMAC self-import belt; CapabilityCeiling try_from=CapabilityCeilingRaw grammar guard at deserialize +
explicit validate_entries belt on import.
Probed: BH-6 forged import (attacker rewrites exporter_did+creator_did) REJECTED; BH-7 tamper a single
assignment role→admin (creator_did untouched) REJECTED by Ed25519; BH-9 malformed ceiling entry
(`***:***:bad\x07`) REJECTED at deserialize.

## Send gate (send_message ~2025): positive messages:write via member_has_capability (suspension-aware).
BH-8 observer (read-only) blocked; BH-4/BH-5 suspended blocked. BH-10 sidecar desync: member in
role_state but absent from member_sequence_numbers → or_insert(0), NO PANIC, no replay (fresh counter).

## GOTCHAS for future probes
- SuspendAccess/SuspendCapability/RevokeAccess/RestoreAccess require `member:ban` in CEILING
  (dispatch_ceiling_capability ~3284). TransferAdmin/ChangeRole/ModifyCeiling/AddMember = None (no ceiling gate; auth at propose time).
- Export envelope + ContextRoleState + RoleAssignment serialize SNAKE_CASE (no rename_all):
  exporter_did, creator_did, role_state, assignments, role_name, member_did, ceiling.capabilities[].
- "member" built-in role grants MessagesRead+MessagesWrite+ToolInvokeAll; built-in roles are ceiling-INTERSECTED.
- Setup via test_insert_ceiling/test_insert_member/test_insert_suspended_capability (set_ceiling_and_refresh
  under the hood — SETUP only); ATTACK via production dispatch. register_identity_with_agent_key() +
  cleanup_identity_registry() for export-sign/verify (thread-local registry shared across managers).
- Demote-then-repromote clears a suspension (prune drops it when intermediate role lacks the cap) — this is
  NATIVE-EQUIVALENT semantics, NOT a WASM finding; do not raise.
