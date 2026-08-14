---
name: slice1-roles-wasm-sweep
description: WASM ContextRoleState slice (slice1-roles) bug sweep — send_message missing sequence rollback on encrypt failure (native rolls back, WASM doesn't)
metadata:
  type: project
---

# slice1-roles WASM ContextRoleState slice sweep (HEAD f592238ba)

Sweep of crates/scp-ffi/wasm/src/manager.rs + consequence.rs adopting shared `ContextRoleState`.

## FINDING (MEDIUM) — send_message per-sender sequence NOT rolled back on encrypt/base64 failure
- manager.rs `send_message`: `*seq_entry += 1` (~auth line 2092) runs BEFORE the fallible encrypt block (base64 decode ~2096, `encrypt_message` ~2108). On failure `?`/`map_err()?` early-returns WITHOUT restoring the counter → permanent gap in per-sender sequence.
- Native `messaging_helpers::send_message` (scp-runtime) DOES roll back: `rollback_sequence_number(sender_did)` on encrypt_and_send failure (lines 1272-1276), on PseudonymRegistryEmpty (1126-1127), and finalize owns its own rollback. `rollback_sequence_number` uses saturating_sub.
- WASM comment block (auth ~2073-2086) addresses post-vs-pre increment base off-by-one + "increment direction must converge" but is SILENT on the failure-rollback divergence.
- Impact: divergence not data-loss/crash. Sequence feeds AEAD AAD (epoch,seq). Gap tolerated by monotonic receive checks, but WASM and native assign DIFFERENT seq to the same logical next message after a failed send. Per-author byte values out of cross-family parity scope per ADR-050, but reservation/rollback semantics should converge.
- Fix: capture `seq_was_present`/prior value, and on the encrypt/base64 error paths do `*seq_entry`-style rollback (or remove entry if newly inserted) mirroring native saturating_sub.

## VERIFIED CLEAN
- execute_governance_action: rollback only removes executed_proposals marker; dispatch_add_member/remove_member/transfer_admin do their own internal conditional rollback. parse_proposal_id_bytes(?) at execute time unreachable-fail (propose validates id first). RemoveMember leaf ordering (MemberLeft before GovernanceActionExecuted) matches native; strip only after MLS evict succeeds.
- Consequence subject dispatch: WASM passes initiator_did==executor_did==proposer_did (context.rs resolves proposer_did from tracked proposal); native dispatches for proposal.proposer_did + target_did. MATCHES.
- TransferAdmin: reject-before-mutate (member guard), demote-all-admins then promote new; creator_did untouched. Correct.
- ModifyCeiling: set_ceiling only (no role rebuild), gated on ceiling_policy=="governed", fail-closed validate_entries. Matches native apply_pending_ceiling_modification.
- join_context_encrypted: leaf-last ordering correct; rollback strips members/assignments/member_capabilities/suspensions/seq on Welcome failure (pending key NOT restored — documented, acceptable).
- import_context: role_state restored verbatim (no member_capabilities recompute — closes BLACK-CEIL-01); ceiling grammar re-validated; anti-replay ts clamped to now; creation_timestamp_secs verbatim (signed). crypto:None. No panic surfaces — all role accessors get/entry-based.
- publish_broadcast: seq increment followed only by infallible push_event — no rollback needed.
- roles.rs suspend_all/restore_capabilities/prune_suspensions/suspend_capabilities all get_mut/entry — no panic on absent member.

NOTE: import broadcast author key uses generate_sender_key() (fresh random) on import — imported broadcast key won't match subscribers' held key, but documented re-establishment + no nonce reuse (fresh key). Informational only.
