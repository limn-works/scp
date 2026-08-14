---
name: wasm-1877-slice1-roles-c65552c9e
description: WASM #1877 slice-1 ContextRoleState adoption review — send-auth HIGH CONFIRMED+EXPANDED (observer can send, SuspendAll can't stop it); #1886 closed on all paths; no nonce-reuse; no distinct CRIT
metadata:
  type: project
---

# WASM #1877 slice 1 (c65552c9e) — adopt shared ContextRoleState in PerContextState

Delta over origin/main: 2 WASM files. consequence.rs (apply_assign_role now routes
through `role_state_system_assign_role` = #1886 fix on consequence path; apply_suspend
via suspend_capabilities_typed; apply_suspend_all iterates ceiling∩member_has_capability).
manager.rs deletes flat model, adds `role_state: ContextRoleState` + `member_sequence_numbers: HashMap<String,u64>`.

## CONFIRMED + EXPANDED HIGH (send-auth gap) — the known finding, now with full exploit
- WASM `send_message` (manager.rs:1862-1885) gates ONLY on:
  (1) `suspended_for(sender).contains(MessagesWrite)` AND (2) `role_state.members.contains(sender)`.
  It NEVER calls `member_has_capability(sender, "messages:write")`.
- Native `send_message` (scp-runtime messaging_helpers.rs:930) REQUIRES
  `role.member_has_capability(sender, &MessagesWrite)` (positive role grant) + distinguishes suspended.
- `publish_broadcast` (manager.rs:5181) has the IDENTICAL weak gate (suspended-set only).
- EXPLOIT: builtin `observer` role = MessagesRead only (roles.rs:27). An observer member
  can `send_message` on WASM. SuspendAll/SuspendAccess CANNOT stop them because
  `suspend_all` (roles.rs:1091) only copies the member's ROLE-GRANTED member_capabilities into
  the suspended set — observer never had MessagesWrite, so it's never in the suspended set,
  so the gate passes. Demote-to-observer via import/consequence/governance ChangeRole all
  leave WASM send open.
- PROVEN: 3 probes added to manager.rs test mod (observer send Ok; SuspendAll-then-send Ok;
  broadcast gate is set-membership-only) — ALL PASSED on native test target, then REVERTED.
- NOT a §9.9.3 Merkle divergence: MessageSent is excluded from canonical log (manager.rs:1919-1925).
  Pure authorization-enforcement gap. Fix: add `if !ctx.member_has_capability(sender,"messages:write")`
  before the suspended-set check in BOTH send_message and publish_broadcast (mirror native msg + distinct-suspended msg).

## #1886 (undefined/out-of-ceiling role) — CLOSED ON ALL WASM PATHS
- consequence AssignRole → role_state_system_assign_role → system_assign_role validates
  role_definitions + validate_role_definition(ceiling) (roles.rs:1206). Undefined → Err → false.
- import_context (manager.rs:6473) → system_assign_role per member; undefined role → import Err (6475).
- add_member join (1724) + governance ChangeRole/AddMember already routed through it (tests at 9240/9284).
- role_definitions on import = builtin_roles(ceiling) re-derived locally, NOT from snapshot, so
  importer cannot define an escalated custom role. custom_roles=Vec::new() at import (6450).

## NO nonce-reuse from member_sequence_numbers reset
- sender layer (scp-protocol/crypto/sender_keys/encrypt.rs:58) uses a RANDOM 12-byte OsRng nonce
  per call; (epoch,sequence) are AAD only. leave_context resets seq to 0 + destroys crypto;
  rejoin reseeds seq=0 — but random nonce + fresh sender key on new crypto state = no AES-GCM reuse.
  MLS layer-2 manages its own nonce schedule. RESISTS.

## Export/import role escalation — RESISTS (within signed-snapshot trust model)
- Snapshot Ed25519-signed (pre-existing surface, unchanged by slice). Reconstruction is sound:
  ceiling from ceiling_strings → builtin role_definitions → system_assign_role per member (ceiling-validated)
  → suspensions restored via suspend_capabilities. Dropping a suspension/escalating requires re-signing.

## Benign micro-divergences (NOT exploitable, noted for completeness)
- WASM apply_suspend_all is ADDITIVE (suspend_capabilities extends) vs native suspend_all REPLACES
  (.insert whole set). Differs only if a stale suspension exists on a now-not-granted cap; both gate
  via member_has_capability which requires cap∈member_capabilities, so stale suspension is inert.
- governance propose(4460)/vote(4660,4809)/close(1956) DO use member_has_capability (suspension-aware) — correct, SuspendAccess properly blocks them. Only the message-write path is asymmetric.
- execute_governance_action intentionally has NO per-member re-check (quorum convergence, documented 3178).

## FIX RE-ATTACK @ 3495c2062 (HEAD on spec/wasm-1877-slice1) — CLEAN, the send-auth HIGH is RESOLVED
Fix commit adds the positive suspension-aware `member_has_capability(MessagesWrite)` gate to BOTH `send_message` (~1887, before seq-increment/encrypt at 1920) and `publish_broadcast` (~5240, after is_author). The gate delegates to the SINGLE shared `ContextRoleState::member_has_capability` (roles.rs:1018) which is fail-closed: returns true ONLY if (a) cap ∈ member_capabilities AND (b) cap ∉ suspended_capabilities. 6 fresh black-hat probes written+ran on HOST target (wasm32 lib-test target has 23 pre-existing scp_identity/proptest/zbase32/JsError unlinked errors — documented gotcha, NOT from probes), all PASSED, then REVERTED clean:
- BH1 admin/creator in ceiling-without-write → REJECTED ("does not grant"). NOT fail-open for creator (admin caps = ceiling.clone(), so no write in ceiling = no write).
- BH2 ghost member with assignment to undefined role + EMPTY member_capabilities (hand-crafted dangerous state) → REJECTED. Stale-assignment-without-caps fails closed.
- BH3 suspend_all → REJECTED; then restore_capabilities → send Ok. No permanent lockout, gate is suspension-driven.
- BH4 real production subscribe_broadcast (assigns read-only "subscriber") → publish REJECTED.
- BH4b registered broadcast AUTHOR holding only read-only "observer" role → publish REJECTED by the ROLE gate (passes is_author, fails "author...does not grant messages:write") — isolates the new gate on broadcast path.
- BH5 unknown author → REJECTED.
All member_capabilities-population paths (add_member/subscribe/import/governance ChangeRole/consequence) route exclusively through `system_assign_role` (ceiling+role-def validated) — no path injects MessagesWrite into a read-only member. import_context fix (pass real context_id to ::new) is cosmetic; member_capabilities cleared+rebuilt from signed snapshot via system_assign_role (undefined/out-of-ceiling role → import Err = stronger). apply_suspend_all now delegates to shared suspend_all (REPLACE semantics, byte-identical native) — the old additive-ceiling-iteration divergence GONE. Nonce ordering re-confirmed: gate before seq-increment+encrypt, rejected send burns no nonce/seq. 108 manager tests + 57 wasm_conformance (1 pre-existing ignored gov-EventType-parity, unrelated) GREEN.
ORTHOGONAL (pre-existing, NOT this slice, NOT a regression — present identically on origin/main): WASM `invoke_tool(context_id, tool_id, input)` has NO invoker_did param and does NOT gate on tool_invoke capability, whereas native invoke.rs:255 calls has_tool_invoke_capability. Structural: WASM bridge is single-local-identity (no per-member invoker concept on the local invoke path). Untouched by slice or fix. Note only; not a finding against #1877 slice 1.
VERDICT: send/publish authorization gate is SOUND and fail-closed. No new auth gap exposed by state-convergence on the gated handlers (governance propose/vote/close all gate correctly; execute = intentional quorum convergence).
