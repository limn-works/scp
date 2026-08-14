---
name: remove-member-clears-suspension-139e35aae
description: #1901 ContextRoleState::remove_member clears suspended_capabilities + read_exclusion_list on removal (native↔WASM parity) — security-SOUND, GO
metadata:
  type: project
---

# remove_member clears suspension on removal (139e35aae, #1901)

**VERDICT: GO. Clearing-on-removal is security-sound; defeats no ban/denial mechanism.**

## What changed
- New `ContextRoleState::remove_member(&str)->bool` in scp-protocol/src/context/roles.rs (~1883): drops members/assignments/member_capabilities/suspended_capabilities. `pub(crate)` suspended_capabilities write.
- Native sites converged to it: governance_helpers.rs execute_remove_member (~1308) + lifecycle_helpers.rs leave_context (~327). Both ALSO add `state.access.read_exclusion_list.remove(did)` (was previously NOT dropped natively — net-new, fixes a phantom-read-exclusion leak).
- WASM manager.rs 3 sites (remove_member ~2372, failed-join rollback ~2812, RemoveMember dispatch ~4498): replaced flat strip + restore_capabilities-loop with shared remove_member; read_exclusion_list.remove added at failed-join site (was missing).

## Why it's sound (the core security argument)
- **No re-grant window.** suspended_capabilities only ever DENIES (§5.3.2 step 5). Once a DID holds no role, a suspension is meaningless. Removal is itself a downward-auth transition. A still-in-group member is NEVER affected — removal drops the DID from `members` too, and add_member is the only re-entry.
- **MLS eviction precedes the strip.** execute_remove_member runs remove_member_sender_key + rotate_sender_key + `state.membership.remove_member(did)` BEFORE the role-state teardown, all inside `commit_class_s_keep`. Hard crypto boundary first; bookkeeping after. Removed DID has no group key regardless of role-state contents.
- **read_exclusion_list is NOT a ban denylist.** It is a per-CURRENT-member CEK-wrapping exclusion. RevokeAccess (governance_helpers ~890) requires `state.membership.contains(did)` and inserts into read_exclusion_list for a present member; RestoreReadAccess (~1078) removes it. Enforcement is `!(read_requested && read_excluded)` at restore-guard + CEK wrapping for present members. **execute_add_member (~1148) does NOT consult read_exclusion_list or suspended_capabilities as a re-admission gate** — it does fresh MLS add + fresh role assign + fresh access key. So clearing read_exclusion on removal cannot let a "banned" DID rejoin with read — there is no persistent per-DID ban registry keyed on read_exclusion_list. A ban = MLS eviction + governance re-vote required to re-add. Correct.
- **§9 caller obligation honored.** Both native sites are inside commit_class_s_keep (fail-closed persist). Downward-auth suspension drop persists fail-closed.

## Native↔WASM parity
- Both now clear the same 4 role fields + read_exclusion_list + member_sequence_numbers. WASM read_exclusion_list owned on `ctx` (line 673), not ctx.role_state — cleared inline, correct. §5.9 restore carve-out byte-identical across impls (WASM ~4656, native ~1064). No residual asymmetry.

## Findings: NONE blocking. One observation:
- leave_context drops read_exclusion_list on SELF-leave. If product intent were "a self-leaving member under read-revocation should stay excluded on rejoin," this would matter — but since read_exclusion is per-membership (not durable ban) and re-add is fresh, dropping it on leave is consistent with remove. Sound.
