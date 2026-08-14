# WASM #1877 TransferAdmin converge-to-native (d05e8ad7d) -- 2026-06-24 -- CLEAN / no findings

Worktree slice1-roles, HEAD d05e8ad7d. manager.rs only (+145/-47). Read serves STALE
manager.rs here — use `git show HEAD:crates/scp-ffi/wasm/src/manager.rs`.

## What changed
TransferAdmin arm (dispatch_governance_action_ext ~4055) rewritten to byte-match native
execute_transfer_admin (governance_helpers.rs ~1828):
- (a) REJECT non-member new_admin BEFORE any mutation (CTX_2015 member-not-found, what
  map_role_error maps RoleError::MemberNotInContext to);
- (b) collect EVERY "admin"-role holder, demote each to "member" via shared system_assign_role;
- (c) promote new_admin to "admin";
- STOP writing creator_did (prior code unconditionally relocated creator_did onto new_admin
  AND only promoted if already-member → zero-admin vacancy + export-signer hijack onto non-member).
Prior rollback block removed (reject-before-mutate + built-in-role-in-ceiling = infallible).

## Why CLEAN (verified)
- **creator_did immutable is CORRECT, not a gap.** Native UCAN validate.rs:862 verify_root_issuer
  roots delegation chain on context_creator_did (immutable), NOT current admin. revoke.rs:916
  allows revoke by issuer_did OR creator_did. Export sign (6485)/HMAC (6474)/exporter_did (6507)/
  import verify-key resolution (6636) all resolve from snapshot.role_state.creator_did, and import
  enforces exporter_did==creator_did (6611) + verify_strict Ed25519 (6635) before any role_state use.
  operator_did (4714) = tool-register operator = creator (creator-anchored, native-parity, pre-existing).
  mint_role_tokens issues under self.creator_did. Old relocation would have hijacked UCAN root +
  corrupted cross-platform export signing → the fix CLOSES a CRITICAL, introduces nothing.
- **Role IS load-bearing for authz (sound).** propose_governance_action (4805) gates on
  member_has_capability(proposer,"governance:propose"). Shared member_has_capability (roles.rs:1544)
  checks suspension FIRST then role-derived member_capabilities. builtin_admin = all-ceiling-caps
  (incl GovernancePropose/Vote); builtin_member = MessagesRead/Write/ToolInvokeAll only (NO governance).
  So demote→"member" actually REVOKES governance power; promote→"admin" grants it. Real transfer, not label.
- **No execute-time per-member recheck (native parity, execute_governance_action 3460).** Authz at
  PROPOSE time only; proposer demoting self mid-auto-execute is benign (capability captured pre-mutation).
- **Self-transfer safe:** collect-demote-ALL-then-promote order means new_admin (if already admin)
  ends as admin; no zero-admin final state. Matches native order exactly.
- **system_assign_role infallible here (roles.rs:1731):** fails only on non-member (guarded) /
  role-not-found (admin/member always defined) / cap-outside-ceiling (built-ins ceiling-filtered at
  construction). prune_suspensions_to_role_grants on demote = intended consequence cleanup.

## In-scope re-confirmations (unchanged this commit, all SOUND)
- Import verbatim (snap.role_state.clone() 6807) downstream of deserialize_and_verify_envelope (6729);
  §5.3.1.1 validate_entries belt (6815) + serde try_from CapabilityCeilingRaw deserialize gate.
  Closes BLACK-CEIL-01 (no recompute → suspended-then-widened member stays suspended).
- Positive messages:write gate, suspension-aware, both send (2070) and publish/author (5578).
- crypto:None on import (6982) decouples member_sequence_numbers sidecar from any live AEAD key →
  no GCM nonce-reuse vector (debug_assert + tripwire comment for future crypto-populate change).

2 new tests via production propose_governance_action path: member-promo (demote old/promote new/
creator_did unchanged) + non-member reject (no vacancy, no creator_did relocation).
