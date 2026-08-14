---
name: adr049-2g-placeholder-deletion
description: ADR-049 Phase 2G Placeholder-variant deletion review @157c421d7 — ALIGNED, 0 findings
metadata:
  type: project
---

# ADR-049 Phase 2G Placeholder Deletion @ `157c421d7` (2026-06-30) — ALIGNED

Branch `chore/2g-delete-placeholder-variants`, diff `origin/main...HEAD` (16 files +280/-486). Deletes all 9 dead actor-mailbox `Placeholder` command variants (8 zero-producer + 1 test-only messaging smoke target migrated to `QueriesCommand::MemberCount`) + de-stales doc-comments.

**Why ALIGNED (0 findings):**
- Master plan `generic-moseying-lightning.md:413` defines 2G = two parts: (a) delete `send_tracker` shim + (b) resolve 9 `Placeholder` variants. This PR does (b) in full (grep `Placeholder {` in scp-runtime/src = 0). Part (a) correctly deferred: diff touches NO `send_tracker` symbol; commit uses NO closing keyword → #18 stays open. Honest scope-split, no false-completion.
- All rewritten doc-comments point at LIVE symbols: `Supervisor::dispatch_{lifecycle,governance,economy,trust_recovery,standing,tools,broadcast}_command`, `spawn_actor_with_state` (:3864), `standing_context`/`StandingCommand::StandingContext` (:4721), `handle_recovery_notify_contact` (trust_recovery.rs:287).
- DEFERRED-commit-11 ADR edits consistent with spec §5.15.8 (`05-contexts.md:1719`: standing-pair creation "not yet wired," no live divergence). ADR correctly DROPPED the pointer to deleted `handlers/standing.rs::reply_not_implemented`; remaining `InitiateStandingPairCreate`/`NotImplemented` mentions all describe symbols as REMOVED (accurate historical prose).
- `lifecycle_control.rs` PersistSync doc correction is factually grounded: Pause/Shutdown arms DO mutate actor-owned Class-C state (`*cell.class_c_view().lifecycle_state_mut()=…`), so old "no state mutation through actor path yet" was FALSE.
- `tools_command_context_id` signature tightened `Option<&str>→&str` (Placeholder was sole None-returning variant) — clean consequence.

**Test-quality reviewer (dispatched by orchestrator) confirmed:** the one flagged concern — two supervisor poison tests (`supervisor.rs:13826`, `:13907`) substitute MUTATING `MessagingCommand::DrainEvents` as smoke-ping (no read-only messaging variant exists) — is HARMLESS + mutation-confirmed. Poisoned site: `dispatch_command` resolves actor by ctx_id via `lookup` BEFORE send; on 3-crash despawn `lookup==None` → `lookup_miss_error` returns ContextPoisoned, DrainEvents body NEVER runs (patched poison branch → test fails, discriminator intact). Recovered site: DrainEvents fire-and-forget (dispatch_via_mailbox returns Ok w/o awaiting reply), last assertion, drains empty buffer nothing reads.

**Reusable pattern:** "N dead + 1 migrated" commit framing describes producer-status split of the SAME N+1 variant set the plan names — verify it's not a scope reduction (it wasn't). For placeholder/stub-deletion PRs, the alignment crux is: (1) every rewritten doc-comment points at a still-live symbol, (2) ADR/spec prose describing deletions says "removed/no-longer-exists" not "pending", (3) any doc "correction" claim is factually grounded in the actual code body (here: read the handler arm to confirm it mutates).
