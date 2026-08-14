---
name: saga122-fault-injection-journal-escrow-vacuous
description: Issue #122 fault-injection saga-journal harness review — Test A escrow-held assertion (voided==0) is VACUOUS because the xctx test tool is free (cost:None) + caller economic_policy=None, so no escrow exists; Tests B/C faithful
metadata:
  type: project
---

# Issue #122 fault-injection saga-journal harness (worktree saga-122, branch feat/122-fault-injection-saga-journal, HEAD c6d271ee5) — NEEDS DISCUSSION (2026-06-30)

Diff `d24b59d33..HEAD`: +717 lines pure `#[cfg(test)]` in `crates/scp-runtime/src/context/supervisor/supervisor.rs`. 3 live tests exercising ADR-049 §3a/§9 + §6.2.4 saga terminal arms. Plan: `~/.claude/plans/saga-122-fault-injection-journal.md`.

## CONFIRMED MISALIGNMENT — Test A escrow-held assertion is vacuous
`xctx_saga_err_arm_commit_exhaustion_needs_repair_escrow_held` asserts `voided==0` (supervisor.rs:16823-16829 + 16916-16921) claiming it proves the §9 "Prepare-A escrow HELD for operator repair, NEVER voided" semantic. It does NOT.

**Why (production trace):** the xctx test harness uses the FREE `calculator-v1` tool (`cost:None`, xctx_target_state ~16416) and the caller context's `economic_policy` is never set (defaults `None`, state.rs:1542). In `reserve_tool_economy` (tools_helpers.rs:791) escrow is gated: `match (economic_policy, payment_adapter) { (Some,Some)=>authorize, _=>None }`. So `ticket.escrow==None`. Then BOTH terminal branches no-op the void counter:
- held branch `hold_external_for_repair` (supervisor.rs:5802 → tools_helpers.rs:305) only voids if `escrow.is_some()`.
- void branch `void_external_and_consume` (supervisor.rs:5810 → tools_helpers.rs:251) calls `adapter.void()` only under `(Some(adapter), Some(escrow))`.
`voided` is structurally pinned at 0 on EVERY terminal → assertion would pass even if prod erroneously took the void branch on NeedsRepair. No positive control in file (only voided.load sites both assert ==0). VoidCountingPaymentAdapter is dead instrumentation here.

**Plan drift:** plan line 29 says "paid-tool xctx"; line 21 "NeedsRepair ⇒ voided==0" — implementation used free tool, making the assertion vacuous (silent semantic downgrade).

**Fix (aligned):** wire a real Prepare-A escrow — set caller `economic_policy=Some(...)`, register tool with non-zero `cost`, present spending UCAN (tools_helpers.rs:625 rejects paid w/o UCAN). THEN void branch would fire adapter.void() so voided==0 distinguishes held vs void. Add positive control: sibling assertion that a non-NeedsRepair void terminal over same harness gives voided==1. If paid escrow infeasible, remove the voided apparatus rather than leave hollow.

## Faithful (aligned) parts
- Test A terminal-classification core IS real: both variants drive live FSM via `start_cross_context_tool_invocation_saga` to SagaError::NeedsRepair; variant 2 proves NeedsRepair append fault doesn't downgrade (reached_needs_repair set BEFORE fallible seq-4 append); durable journal NeedsRepair-vs-Committing assertions distinguishing; metric `scp_saga_repair_needed_total>=1` meaningful. Only `voided==0` is hollow.
- Test B (Ok-arm, ~16634) drives real `resolve_committed_or_needs_repair` (supervisor.rs:6783) via FailingSagaJournal one-shot; asserts NeedsRepair NOT Aborted (double-charge guard), calls==1, durable still Committing. Faithful to §6.2.4 commit-authoritative invariant. `!matches!(Aborted)` is load-bearing.
- Test C (self-heal, ~16682) reopens supervisor#2 over shared durable stores, real `restore_on_startup()` (restores actors w/ Class-S capture, MORE faithful than plan's bare replay_unresolved_sagas), asserts load_unresolved empty + calls==1 (idempotent AlreadyCommitted, tool never re-invoked). Faithful to §2D durable-replay.

GOTCHA pattern: a counting payment adapter asserting voided==0 proves NOTHING unless the harness actually creates an escrow (economic_policy Some + paid tool). Free-tool xctx harnesses (the whole supervisor.rs xctx test family) never create escrow → any voided assertion over them is vacuous. Always demand a positive control (a path where voided==1) before trusting a voided==0 hold assertion.
