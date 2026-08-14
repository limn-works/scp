---
name: slice1-dcb3beb-rolestate-convergence
description: WASM ContextRoleState convergence slice @dcb3beb25 (conditional add-member rollback) — 17 adversarial probes through prod dispatch ALL resisted (CLEAN). Suspension/split-brain/export-import/forgery all hold.
metadata:
  type: project
---

# Slice 1 — WASM ContextRoleState convergence @ HEAD dcb3beb25 — CLEAN (17 probes)

Commit: `dcb3beb25 fix(wasm): conditional add-member rollback (no eviction of existing member)`.
This is the d05e8ad lineage with the BLACK-CEIL-01 fix already in place (export carries
`role_state` VERBATIM via Clone; import restores `snap.role_state.clone()` — NO system_assign_role
recompute, NO ceiling intersection — native parity).

## Verdict: CLEAN. 17 probes through PRODUCTION dispatch, zero bypasses.

### Suspension-bypass-after-widen (the BLACK-CEIL-01 class, via LIVE dispatch not just import)
- PROBE-A: SuspendAccess -> ModifyCeiling widen(+messages:write) -> ChangeRole SAME role -> write NOT regained, send blocked. HOLDS.
- PROBE-B: same via ResetMember (Tier-3). HOLDS.
- Why it holds: ModifyCeiling = set_ceiling ONLY (no role_definitions rebuild). So role grants are STATIC across a widen. system_assign_role (run by ChangeRole/ResetMember) recomputes member_capabilities = the SAME role caps, and prune_suspensions_to_role_grants RETAINS the suspended set (suspended==role caps). Widen cannot leak.
- PROBE-D: suspension on a RETAINED cap (messages:read) survives promote observer->admin. HOLDS.
- PROBE-E: import(suspended) -> LIVE ChangeRole on imported ctx -> still suspended, send blocked. HOLDS.
- PROBE-H (NOT a finding): role round-trip admin->observer->admin DOES re-grant a pruned write suspension. This is NATIVE-PARITY: prune_suspensions_to_role_grants drops the write suspension on demote-to-observer (observer has no write to suspend); promote-back legitimately re-grants. Shared scp-protocol method; native does identical. In-band, convergent.

### Split-brain / rollback (every mutation path + failure branch)
- PROBE-L: AddMember re-add of EXISTING member w/ undefined role -> errors, existing member FULLY intact (role observer, caps, assign, seq 0->0 unchanged). NEW member w/ bad role -> NO partial state. Conditional-rollback fix VERIFIED.
- PROBE-G: RemoveMember of suspended member -> fully clean (no member/caps/assign, send denied).
- PROBE-M: leave clears suspension+role+caps; rejoin = clean "member", NO phantom suspension.
- PROBE-F: TransferAdmin to self -> creator stays admin (no zero-admin strand). built-in member role ceiling-intersected so demote-all loop can't fail mid-way.
- PROBE-O: member in `members` but NO caps/assignment (present-but-uncapable) -> send AND propose both DENY. fail-closed.
- PROBE-N (NOT a finding): capable-ghost (caps+assignment but NOT in members) CAN drive propose (member_has_capability has no membership check); send DENIES (explicit membership check). BUT native propose_governance_action_inner gates IDENTICALLY (member_has_capability only). And it's UNREACHABLE: member_capabilities entries are created ONLY by system_assign_role (requires members.contains first); all removals strip members+assignments+member_capabilities together. caps-imply-membership is a structural invariant native shares. Native-parity + unreachable = not a finding.
- RemoveMember MLS-eviction-fails = fail-closed-KEEP (member stays fully in members; no gone-from-members-but-in-MLS-group hole). Already covered by existing test remove_member_keeps_governance_state_when_mls_eviction_fails.
- join_context_encrypted Welcome-failure rollback strips membership inline (no phantom). Existing test covers.

### Send/publish gate (messages:write)
- send_message + publish_broadcast: membership check FIRST, then suspension-aware member_has_capability(MessagesWrite). Read-only role denied; suspended write denied with distinct message. PROBE-Q: imported (crypto:None) suspended member STILL blocked (suspension gate runs before crypto branch).

### Export/import forgery (signed envelope)
- PROBE-I: TAMPER role_state post-signing (inject ghost admin) -> Ed25519 verify_strict REJECTS (SCP-CTX-2093).
- PROBE-J: exporter_did != creator_did -> REJECT.
- PROBE-K: attacker substitutes unresolvable creator_did -> REJECT (key resolution fails).
- PROBE-P: import-over-existing context_id -> REJECT (no silent overwrite).
- Verify pipeline: size-bound -> deserialize (try_from ceiling grammar reject) -> version gate (<V and >V both reject, unsigned reject) -> exporter==creator -> Ed25519(#active then #agent) over JCS digest -> HMAC self-import. ceiling grammar re-validated at import (defense-in-depth belt).

## GOTCHAS for next session
- Suspend*/Revoke*/Restore* require `member:ban` in the ceiling (dispatch_ceiling_capability gate) — test ceilings MUST include it or you get SCP-PERM-3000 (my probes D/E/H initially failed on this).
- RemoveMember.reason is Option<String> (use None not String::new()).
- WASM unit tests are HOST tests (crate-type cdylib still builds a test harness on darwin). Run: `cargo test -p scp-ffi-wasm --lib --features testing`. Need DYLD_LIBRARY_PATH from python3.12 sysconfig LIBDIR.
- Read tool serves STALE manager.rs; use `sed`/`git show HEAD:` for authoritative content; insert probe tests via python heredoc before the final `}` of mod tests (runs to EOF).
- Helpers: make_bare_per_context_state, manager_with_governed_context(ctx,creator,&[ceiling]), test_insert_member, test_insert_suspended_capability, register_identity_with_agent_key()->(creator_did,...), dispatch_governance_action(ctx,&action,actor,ts) for direct prod dispatch.
