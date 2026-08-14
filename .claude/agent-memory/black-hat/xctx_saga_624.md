---
name: xctx-saga-624
description: Black-hat findings on the §6.2.4 cross-context-tool-invocation saga (branch HEAD 3e2038d84)
metadata:
  type: project
---

# §6.2.4 Cross-Context Tool Invocation Saga — black-hat review

Reviewed at worktree HEAD 3e2038d84 (xctx saga slices 3-6). Change = `git diff origin/main..HEAD`.

## What RESISTS attack (verified sound)
- **Confused-deputy UCAN re-bind**: `validate_ucan_rebind` (saga.rs:589) sets `presenting_agent_did = req.caller_did`; validate_ucan step-5 audience match rejects a proof delegated to a different principal. Test `prepare_b_confused_deputy_audience_mismatch_is_rejected` proves it. `required_cap` built from `target_context_id` but check-4 (`target_context_id == state.context_id`) runs before staging, so cap is bound to B's real ctx.
- **Receipt preimage**: §9.5.1 canonical_hash, length-prefixed VarBytes — splice-resistant. verify_strict (rejects non-canonical S / small-order A). `verify()` REQUIRES caller-supplied authorized key → forged-key receipts fail at a correct consumer.
- **Exactly-once / SagaId idempotency**: `xctx_committed_outputs` (SagaId-keyed, Class-S persisted) re-emits stored receipt+output, never re-invokes; `tool_invoked_event_id` = `ToolInvoked:{saga_id}` deterministic. `commit_a` idempotency witness `xctx_committed_invocations` (persisted).
- **NeedsRepair escrow**: held (not auto-voided) via `hold_external_for_repair`; concurrency slot released. Matches spec.
- **A-side initiation budget**: Prepare-A `reserve_tool_economy` consumes hard_rate_limit + velocity per caller_did → bounds a single caller's initiation/nonce-insertion rate.

## FINDINGS

### HIGH — nonce dedup cache NOT persisted → cross-crash replay / double-execution
- `xctx_nonce_dedup` (NonceDedup) is NOT in `ContextSnapshot` (state.rs ~894-940 lists saga_pending/xctx_committed_outputs/xctx_committed_invocations only). Snapshot builder `messaging_helpers.rs:2062-2126` omits it. Restore → `NonceDedup::new()` (empty).
- After a target-actor crash+restore, a within-TTL (5min) `CrossContextToolInvoke` replays under a FRESH SagaId: empty dedup ⇒ freshness passes; fresh SagaId ⇒ `xctx_committed_outputs` does NOT short-circuit ⇒ tool RE-EXECUTES. Spec's freshness/anti-replay section is defeated across a crash.

### MEDIUM (griefing) — target context reserved WITHOUT target-side authorization
- `start_cross_context_tool_invocation_saga` (supervisor.rs:4749) authorizes ONLY `is_member(caller_context_id, caller_did)` (4773) before `try_reserve_context_set({caller,target})` (4823). No check the caller may invoke against `target_context_id`. Target interface/binding checks run INSIDE Prepare-B, after reservation.
- An attacker member of their OWN caller ctx names a victim `target_context_id`, reserving the victim's saga slot → legit sagas touching the victim get `ActorBusy`. Bounded by attacker's A-side hard_rate_limit but real. Doc-comment's "cannot name/reserve a victim's context" claim is asymmetric (caller-only).
- PROOF: `crates/scp-runtime/tests/blackhat_xctx_target_wedge.rs` (PASSES) — uses the production `try_reserve_context_set` critical section.

### LOW/INFO
- Receipt-signing key (`target_signing_key`) is supplied per-call by the saga initiator; the target actor signs blindly with no Active-Signing-Key check. Sound at protocol layer (consumer verify resolves real key) but trust is pushed entirely to the (future) FFI wiring caller. FFI path `ToolsCommand::InitiateCrossContextToolInvocation` is still NotImplemented (supervisor.rs:4236) — channel-authentication boundary not yet wired.
- No UCAN re-validation/revocation re-check at Commit-B (only Prepare-B). Saga is short + serialized so window is tiny; spec doesn't require it.
