# PR6b0 Typed SagaError §6.2.4 boundary (4e5d5cfc8) -- 2026-06-26 -- ZERO FINDINGS

Diff e406c15c5..4e5d5cfc8. Typed `SagaError` enum (Aborted{reason,code,message}/NeedsRepair{saga_id,message}/Busy{contended_context,message}) + `SagaAbortReason::{RateLimited{retry_after_ms:Option<u64>},Rejected}` replacing FFI message-string classification. `ContextError::RateLimited` gains retry_after_ms:Option<u64>. supervisor.rs concentrated.

ALL 5 lenses CLEAN:
1. message leak: internal reject text (caller_did/tool_reg_id/ctx-hex already authorized to caller). No secret/key/escrow-amount. SagaId=unguessable handle not capability.
2. Busy{contended_context}: NO oracle. try_reserve runs AFTER both authorize-before-reserve gates (caller-membership ~5450 + target-interface ~5477). participant set=EXACTLY {caller_ctx,target_ctx} (saga_participant_context_set:11113). contended is one of those two, both caller-authorized.
3. retry_after_ms: 4 token-bucket hard-limit sites set None; sliding-window Some(secs*1000) saturating. None NEVER->Some(0) (explicit test). Reveals limiter-type only.
4. DOUBLE-CHARGE SOUND. Both pivots key off ctx.reached_needs_repair (bool set INSIDE FSM, never from string): escrow tail run_saga:5682 (hold vs void_external_and_consume) + lift classification. Ok-arm mark_resolved fail: resolve_committed_or_needs_repair sets flag BEFORE Err => NeedsRepair (no retry, escrow held). Err-arm sets flag BEFORE fallible append (journal-fail can't downgrade diverged->clean Aborted). Genuine abort=flag false=>void escrow=>no fund-lock.
5. saga_code_from_message forge-safe+panic-free. find(PREFIX) ASCII => char boundary; slice safe; parse u16 .ok(). Prod messages start "SCP-SAGA-NNNNN:" at offset 0 (untrusted data AFTER) => first-match always genuine, unforgeable. Prefix-less aborts -> GENERIC 13067 (not specific 13050). Forged code is advisory-only: gates nothing.

NO FFI consumer of SagaError yet (mod.rs re-export + supervisor/tests only). CrossContextSagaError = SEPARATE unrelated type. Pure core carrier, no new foreign-boundary info.
