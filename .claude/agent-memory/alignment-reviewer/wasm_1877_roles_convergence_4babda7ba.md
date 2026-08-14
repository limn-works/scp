---
name: wasm-1877-roles-convergence-4babda7ba
description: WASM #1877 ContextRoleState convergence slice review @ 4babda7ba — NEEDS DISCUSSION, 3 HIGH TransferAdmin divergences
metadata:
  type: project
---

# WASM #1877 ContextRoleState Convergence Slice @ `4babda7ba` (2026-06-24) — NEEDS DISCUSSION

Worktree `slice1-roles`, branch off main. Diff `origin/main...HEAD` = consequence.rs (+124/-...) + manager.rs (+2391/-1008). Directive (owner verbatim): "WASM should ONLY reimplement things that depend on async/tokio — when it MUST. Share everything we can, even if it means doing away with recent work." This slice makes WASM adopt shared `scp_protocol::context::roles::ContextRoleState` and converge to native `crates/scp-runtime/src/context/`.

**Why:** #1877 native↔WASM convergence; ADR-034 UPDATED stance (2026-03-21, phase-4.md:1443) — ~92K lines pure-sync scp-protocol now shareable; WASM should only reimplement async/tokio/OpenMLS.
**How to apply:** This is the TEMPLATE slice for the rest of #1877. Fix the TransferAdmin divergences before it's taken as precedent.

## STRUCTURAL CONVERGENCE = CORRECT (the good)
- Deletes flat reimpl: `members: HashMap<String,MemberEntry>`, flat `suspended_capabilities` map, hardcoded role→cap resolver. `MemberEntry` now only in doc-comments describing what was removed.
- Adopts shared `ContextRoleState` (role_state field manager.rs:364). role assignment / ceiling / suspension all route through shared typed code.
- ModifyCeiling (manager.rs:3669-3693): converges to native `set_ceiling`-only (matches `apply_pending_ceiling_modification`); correct reasoning re no eager member_capabilities refresh (avoids re-granting SuspendAccess-suspended member a widened cap).
- ChangeRole (3816-3837): routes through shared `system_assign_role`, rejects undefined/out-of-ceiling roles.
- consequence.rs: `apply_suspend`/`apply_suspend_all` use shared `suspend_capabilities`/`suspend_all`; doc honestly notes prior loop EXTENDED vs native REPLACES (real state divergence closed).
- Join membership rollback (1863-1875): fail-closed, faithful.
- Export signing faithful to §23.16.8: domain `SCP-CONTEXT-EXPORT-V1:` + scope byte + JCS, verify_strict, mandatory sig, strict version gate (SCP-CTX-2094/2093).

## 3 HIGH FINDINGS — TransferAdmin (manager.rs:4055-4111, dispatch_governance_action_ext)
Native canonical = `execute_transfer_admin` governance_helpers.rs:1828-1889.
1. **Mutates creator_did** (4110 `clone_into(&mut ctx.role_state.creator_did)`). Native NEVER touches creator_did. roles.rs:1376 = "DID of the context creator (UCAN root issuer)" = immutable. Overwriting breaks UCAN root-issuer invariant.
2. **Demotes only creator_did, not all admins** (4058,4082). Native collects ALL `role_name=="admin"` assignments and demotes each (gh:1858-1871). WASM demotes one DID, wrong one (creator≠current admin). Multi-admin / post-transfer contexts leave stale admins.
3. **No MemberNotFound guard on new_admin** (4087 `if members.contains(new_admin) && ...` silently no-ops). Native returns `MemberNotFound(new_admin)` (gh:1854-1856). WASM reports success while assigning admin to nobody (zero-admin vacancy possible).

## DIRECTIVE PREMISE CORRECTION (important)
Directive claimed native per-member seq uses `saturating_add` (actor/sequence.rs:134) vs WASM raw `+=1`. INACCURATE: sequence.rs:134 is a DIFFERENT counter (actor RAII send-reservation guard). The per-member counter WASM sidecar mirrors = `MembershipState::next_sequence_number` membership.rs:199-204 which is plain `info.sequence_number += 1`. So raw `+= 1` MATCHES. The REAL gap = **off-by-one starting value**: native increment-then-return → first seq=1; WASM (manager.rs:2092-2093, 5611-5615) read-then-increment → first wire `MessageSent.sequence_number`=0. Lives in EXPLICITLY-DEFERRED MembershipState sidecar (member_sequence_numbers); can't cause GCM nonce reuse on import (crypto:None). Informational/deferred-scope but the deferred slice MUST reconcile 0-vs-1-based or break cross-impl message convergence.

## DEFERRAL = COHERENT
HEAD docs commit (4babda7ba) point 3 explicitly marks `member_sequence_numbers` flat sidecar as interim; shared home = `MembershipState.MemberInfo.sequence_number`; convergence is a deferred slice. Point 4 locks crypto-None-on-import invariant + debug_assert. Clean, not rationalized.

## OTHER OBSERVATION
- WASM export envelope carries `integrity_mac` HMAC (manager.rs:7339-7347) native lacks; documented transitional DiD subsumed by signature, self-import-only. Residual WASM surface vs "share everything" — doc flags possible cleanup.

## GOTCHA
`Read` tool serves STALE on this worktree's manager.rs per prompt — used `git show HEAD:...` dumped to /tmp instead. (Backend memory notes same staleness.) Native governance_helpers.rs / membership.rs / roles.rs read fine via Read.
