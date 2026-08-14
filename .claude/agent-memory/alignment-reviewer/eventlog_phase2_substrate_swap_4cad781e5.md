---
name: eventlog-phase2-substrate-swap-4cad781e5
description: ALIGNED final double-zero confirmation of Phase-2 event-log substrate swap at HEAD 4cad781e5 (one commit past 16a2cd42b notification-window fix); merge-gating
metadata:
  type: project
---

# Phase-2 Event-Log Substrate Swap @ `4cad781e5` — ALIGNED (merge-gating confirmation)

Worktree `agent-aaf1b56ed9b9a3581`. HEAD `4cad781e5` = ONE commit past `16a2cd42b` (which I already reviewed ALIGNED — see [[eventlog-phase2-substrate-swap-final]]). Diff vs origin/main = 99 files, 8210/3036.

**Verdict: ALIGNED. 0 blocking, 0 material. Merge-gating confirmation given.**

**The 5 substrate items (re-confirmed, unchanged from 16a2cd42b):** trait `&str`→`EventType` (Copy); provider onto `scp_event_log::EventLog` (`state.merkle_tree` twin GONE — grep merkle_tree in runtime/src = 0); PyO3/NAPI bridge-local logs deleted; checkpoint+proofs+export-root onto `tree::root` (signed `event_log_merkle_root`); `MessageReceived`/`EquivocationDetected`/`PseudonymAnnounced` appends removed. ADR-051 (clockless) + phase-2 ADR-011 amendment (2-category exclusion taxonomy, 75 variants) govern; code flows DOWN.

**The new commit `4cad781e5` (notification-window fix) — IN-SCOPE, correct.** Corrects a regression from the convergence work: deferred ceiling (§5.3.2) + economic-policy (§19.3) `effective_at = proposal.created_at + PERIOD` is proposer-backdatable (`created_at` signature-bound only vs third parties). Added `observed_at` (local clock at commit-processing) to PendingCeilingModification + PendingEconomicPolicyChange; `is_effective` now `current >= max(effective_at, observed_at + PERIOD)` (was `const fn`, now plain fn — both callers governance_helpers.rs:443/492 same sig, fine). KEY CONVERGENCE CHECK: the APPLIED leaf still carries `pending.effective_at` (convergent, committer-anchored), NOT `observed_at` — verified apply_pending_ceiling_modification:464 + economic equivalent. So `observed_at` is a LOCAL APPLY GATE only, never enters Merkle leaf → §9.9.3 preserved. §19.3 spec literally says "MUST NOT take effect sooner than 24 hours after committed to event log" — local floor IS that enforcement. 4 regression tests (backdated-collapse + honest-converges, both ceiling+economic) + a `serde_json preserve_order` build-guard test. Honest residual ACCEPTED in code comment: governance FREEZE deadline (`freeze_start = max(created_at_a, created_at_b)`) intentionally NOT floored — benign (backdating only ENDS a deadlock earlier, never grants capability, requires TWO colluding signed proposals at same seq). Sound reasoning; freeze is a liveness valve not an authz control.

**No scope-creep into Phase 3+:** grep frontier_root/causal_dag/causal_ref in crates+bindings = 0.

**Pre-existing residual (NOT a finding against this branch):** `store/event_log.rs` + `store/context.rs` carry `// See GitHub issue #636`/`#303` (violates feedback_no_issue_refs_in_code) — but these PREDATE this work (on base), and this branch actually REMOVED `#710` from event_log.rs (`#636, #710` → `#636`). Net reduction. Flag for separate cleanup, not merge-gating here.

GOTCHA: review target = worktree file, not main. The 8210-line diff bulk is substrate-swap mechanical (committer-assigned-timestamp threading through governance/messaging helpers), not scope-creep.
